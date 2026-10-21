import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';

const source = await readFile(new URL('../src/offline-snapshot.ts', import.meta.url), 'utf8');
const compiled = ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 }
}).outputText;
const { offlineCopyStoredSizeLabel } = await import(
  `data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`
);

test('offline copy summary reports verified stored bytes without implying file count', () => {
  assert.equal(offlineCopyStoredSizeLabel(431, (n) => `${n} B`), '431 B stored');
  assert.equal(offlineCopyStoredSizeLabel(0, (n) => `${n} B`), '0 B stored');
});

test('invalid offline copy byte totals are omitted', () => {
  assert.equal(offlineCopyStoredSizeLabel(-1, String), null);
  assert.equal(offlineCopyStoredSizeLabel(Number.MAX_SAFE_INTEGER + 1, String), null);
});
