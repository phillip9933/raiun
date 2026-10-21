import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';

const source = await readFile(new URL('../src/windows-compatibility.ts', import.meta.url), 'utf8');
const compiled = ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 }
}).outputText;
const { windowsPortabilityLabel } = await import(
  `data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`
);

test('known portability warnings are advisory and say names remain unchanged', () => {
  assert.equal(
    windowsPortabilityLabel(['reserved_device_name', 'case_collision']),
    'May not work on Windows: uses a Windows reserved device name; differs only by letter case from another item. The existing name is unchanged.'
  );
  assert.equal(
    windowsPortabilityLabel(['component_too_long']),
    'May not work on Windows: exceeds the usual Windows filename component length. The existing name is unchanged.'
  );
});

test('unknown or empty categories do not surface backend text', () => {
  assert.equal(windowsPortabilityLabel(['unsupported_character', 'raw server error']),
    'May not work on Windows: contains a character Windows does not allow. The existing name is unchanged.');
  assert.equal(windowsPortabilityLabel(['raw server error']), null);
  assert.equal(windowsPortabilityLabel([]), null);
});
