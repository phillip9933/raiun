import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';

const source = await readFile(new URL('../src/provider-capabilities.ts', import.meta.url), 'utf8');
const compiled = ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 }
}).outputText;
const { loadProviderSyncData, providerAvailable } = await import(
  `data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`
);

test('disabled provider skips unsupported sync collection requests', async () => {
  const requests = [];
  const result = await loadProviderSyncData(false, true, async action => {
    requests.push(action);
    throw new Error(`unsupported action: ${action}`);
  });

  assert.deepEqual(result, { pairs: [], transfers: [] });
  assert.deepEqual(requests, []);
  assert.equal(providerAvailable(false), false);
});

test('an omitted capability keeps the existing Linux refresh behavior', async () => {
  const requests = [];
  const result = await loadProviderSyncData(undefined, true, async action => {
    requests.push(action);
    return action === 'pairs' ? [{ id: 'pair-1' }] : [{ id: 'transfer-1' }];
  });

  assert.deepEqual(requests, ['pairs', 'transfers']);
  assert.deepEqual(result, {
    pairs: [{ id: 'pair-1' }],
    transfers: [{ id: 'transfer-1' }]
  });
  assert.equal(providerAvailable(undefined), true);
});
