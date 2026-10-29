import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';

const source = await readFile(new URL('../src/transfer-presentation.ts', import.meta.url), 'utf8');
const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.ES2022, target: ts.ScriptTarget.ES2022 } }).outputText;
const moduleUrl = `data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`;
const { transferPresentation, transferTabSummary, transferCounts } = await import(moduleUrl);

test('known transfer states keep incomplete work out of history', () => {
  assert.equal(transferPresentation('verifying').tab, 'active');
  assert.equal(transferPresentation('verifying').label, 'Checking cloud copy');
  assert.equal(transferPresentation('verifying').tone, 'info');
  assert.equal(transferPresentation('cancelled').tab, 'history');
  assert.match(transferPresentation('cancelled').help, /does not mean the cloud copy completed/);
  assert.equal(transferPresentation('paused').tone, 'neutral');
});

test('unknown and malformed states stay visible in attention without invented success', () => {
  for (const state of [undefined, null, '', '__proto__', 'constructor', 'toString', 'future_server_state', ' completed ']) {
    const result = transferPresentation(state, 'sideways');
    if (state === ' completed ') assert.equal(result.tab, 'history');
    else {
      assert.equal(result.tab, 'attention');
      assert.equal(result.label, 'Status unavailable');
      assert.match(result.help, /Refresh/);
    }
    assert.equal(result.direction, 'unknown');
  }
  assert.equal(transferPresentation('queued', 'download').direction, 'download');
  assert.equal(transferPresentation('queued', 'up').direction, 'upload');
});

test('counts partition every input record once and do not mutate inputs', () => {
  const items = [
    { state: 'queued', direction: 'upload' },
    { state: 'failed', direction: 'download' },
    { state: 'completed', direction: 'download' },
    { state: 'future_state' }
  ];
  const before = structuredClone(items);
  assert.deepEqual(transferCounts(items), { active: 1, attention: 2, history: 1 });
  assert.deepEqual(items, before);
});

test('tab summaries scope empty states to folder sync and keep saved edits separate', () => {
  const history = transferTabSummary('history');
  assert.match(history.description, /folder-sync/);
  assert.match(history.emptyHelp, /Saved edits and recovery records are listed separately/);
  assert.doesNotMatch(history.emptyHelp, /No saved edits/);
});
