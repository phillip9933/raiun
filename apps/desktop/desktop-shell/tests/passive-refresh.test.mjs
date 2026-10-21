import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';

const source = await readFile(new URL('../src/passive-refresh.ts', import.meta.url), 'utf8');
const compiled = ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 }
}).outputText;
const { shouldBlockPassiveRefresh, shouldRunPeriodicPassiveRefresh } = await import(
  `data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`
);

const idle = {
  addOpen: false,
  pickerOpen: false,
  addAccountOpen: false,
  vaultDialogOpen: false,
  nativeDialogBusy: false,
  editingControlFocused: false
};

test('a vault dialog blocks passive refresh after a password input loses focus', () => {
  assert.equal(shouldBlockPassiveRefresh({ ...idle, vaultDialogOpen: true }), true);
});

test('passive refresh remains available when no dialog or input is active', () => {
  assert.equal(shouldBlockPassiveRefresh(idle), false);
});

test('other modal and focused-control blockers remain active', () => {
  assert.equal(shouldBlockPassiveRefresh({ ...idle, pickerOpen: true }), true);
  assert.equal(shouldBlockPassiveRefresh({ ...idle, editingControlFocused: true }), true);
});

test('the periodic timer is blocked by an open vault dialog', () => {
  assert.equal(shouldRunPeriodicPassiveRefresh({ ...idle, vaultDialogOpen: true }, false), false);
});

test('the periodic timer may run during the non-busy account setup wait state', () => {
  assert.equal(shouldRunPeriodicPassiveRefresh({ ...idle, addAccountOpen: true }, true), true);
});
