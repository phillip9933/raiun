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
  vaultAccessOpen: false,
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


test('the first Unlock picker stays refresh-blocked from select to button until closed', async () => {
  const main = await readFile(new URL('../src/main.ts', import.meta.url), 'utf8');
  const start = main.indexOf('function passiveRefreshBlockers() {');
  const end = main.indexOf('async function flushQueuedPassiveStatusRefresh()', start);
  assert.ok(start >= 0 && end > start);
  const snapshot = new Function('state', 'editingControlFocused', `${main.slice(start, end)}; return passiveRefreshBlockers();`);
  const state = { addOpen: false, pickerOpen: false, addAccountOpen: false,
    vaultDialog: null, vaultAccessOpen: true, nativeDialogBusy: false };
  // The queued refresh and periodic timer must remain blocked after focus
  // moves from the Space select onto Cancel/Browse (neither is an input).
  for (const focused of [true, false]) {
    const blockers = snapshot(state, () => focused);
    assert.equal(shouldBlockPassiveRefresh(blockers), true);
    assert.equal(shouldRunPeriodicPassiveRefresh(blockers, false), false);
    assert.equal(shouldRunPeriodicPassiveRefresh({ ...blockers, addAccountOpen: true }, true), false);
  }
  state.vaultAccessOpen = false;
  const closed = snapshot(state, () => false);
  assert.equal(shouldBlockPassiveRefresh(closed), false);
  assert.equal(shouldRunPeriodicPassiveRefresh(closed, false), true);
  assert.equal(shouldRunPeriodicPassiveRefresh({ ...closed, addAccountOpen: true }, true), true);
});
