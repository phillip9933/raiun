import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import ts from 'typescript';

const source = await readFile(new URL('../src/main.ts', import.meta.url), 'utf8');
const tree = ts.createSourceFile('main.ts', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
const wanted = new Set(['clearVaultBrowse', 'confirmAccountAction', 'isCurrentAccount', 'vaultPinContextCurrent', 'handleAction', 'run', 'removeVaultOfflinePin', 'lockVault', 'removePair', 'resolveConflict', 'disconnectSpaceFolderSync', 'nativeVaultAccess', 'vaultAppFeaturesAvailable', 'removeSelectedAccount', 'restoreRemovedAccount']);
const functions = new Map(tree.statements.filter(n => ts.isFunctionDeclaration(n) && n.name && wanted.has(n.name.text)).map(n => [n.name.text, n.getText(tree)]));
assert.equal(functions.size, wanted.size, 'exercise actual production declarations');
const compiled = ts.transpileModule(`${[...functions.values()].join('\n')}\nglobalThis.actions = { ${[...wanted].join(',')} };`, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None }
});
assert.equal((compiled.diagnostics || []).filter(d => d.category === ts.DiagnosticCategory.Error).length, 0);
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
function harness() {
  const dialog = deferred(), calls = [], prompts = [];
  const state = {
    accountEpoch: 7, selectedAccount: 'profile-a', nativeDialogBusy: false, accountSwitching: false,
    status: { connected: true, provider_supported: true, auth_generation: 7 }, agentReachable: true, mutationBusy: 0,
    accountRemovalSupported: true, accounts: [{ id: 'profile-a', label: 'Synthetic profile' }],
    removedAccounts: [{ id: 'profile-old', label: 'Synthetic removed profile', local_data_preserved: true }],
    spaceActionBusy: {}, pairs: [{ id: 'alpha-one', space_id: 'space-a' }, { id: 'alpha-two', space_id: 'space-a' }, { id: 'beta-one', space_id: 'space-b' }],
    error: '', message: '', resolvingConflict: false, conflicts: {}, page: 'folders', vaultGeneration: 11,
    vaultDialog: { generation: 11, pinGeneration: 12, accountEpoch: 7, spaceId: 'space-a', rootPath: '/Synthetic.vault', rootResourceId: 'root-a',
      pins: [{ id: 'pin-a' }], pinBusy: false, pinJob: null, loading: false, unlocked: true, statusUnknown: false, editRetryBusy: false, editRetryJob: null, entries: [], directoryBindings: new Map(), currentDirectoryBinding: null }
  };
  const map = () => new Map();
  const context = {
    state, accountAvatarUi: { clearProfile() {}, cancelPendingExceptEpoch() {} }, discardPairSettingsDraft: (drafts, id) => drafts.delete(id), confirmDialog: (message, options) => { prompts.push({ message, options }); return dialog.promise; },
    render() {}, providerAvailable: x => x !== false, featureAvailable: field => state.status.provider_supported !== false && state.status[field] !== false, spaceName: () => 'R196 Synthetic Space A',
    selectedAccountLabel: () => 'Synthetic profile', lastPath: path => path.split('/').at(-1),
    messageOf: error => String(error.message || error), isStaleAccountRequest: () => false,
    pairExclusionsUi: { open: new Set(), edits: map(), drafts: map(), kinds: map(), errors: map(), busy: map() },
    refresh: async () => { state.status = { ...state.status }; }, syncAccounts: async () => {}, accountSwitchDisabled: () => false, loadConflictPage: async () => {}, isStaleConflictError: () => false,
    forgetVaultOperationsScope() {}, clearVaultPinUi() {}, clearVaultEditRetryUi() {},
    safeVaultExistingOverwriteReason: () => null, safeVaultMountWriteReason: () => null,
    refreshEncryptedRetryLatestStatuses: async () => {},
    request: async (action, payload) => {
      calls.push({ action, payload: structuredClone(payload) });
      if (action === 'status') return { profile_id: 'profile-a', auth_generation: 7 };
      if (action === 'space_disconnect') return { space_id: 'space-a', removed_pair_ids: ['alpha-one', 'alpha-two'] };
      if (action === 'vault_pin_remove') return { removed: true };
      if (action === 'resolve_conflict') return { recovery_path: '/synthetic-recovery' };
      if (action === 'account_remove') return { removed_profile_id: 'profile-a', selected: null, local_data_preserved: true, credentials_revoked: true };
      if (action === 'account_restore') return { restored_profile_id: 'profile-old', selected: 'profile-a', sign_in_required: true };
      return {};
    }
  };
  vm.runInNewContext(compiled.outputText, context, { timeout: 1000 });
  return { ...context.actions, state, calls, prompts, dialog };
}
const cases = [
  ['disconnect', 'space_disconnect', h => h.disconnectSpaceFolderSync('space-a')],
  ['pair remove', 'pair_remove', h => h.removePair('alpha-one')],
  ['conflict', 'resolve_conflict', h => h.resolveConflict({ dataset: { resolveConflict: 'keep_local', pairId: 'alpha-one', path: '/synthetic.txt', localHash: 'hash-a', remoteEtag: 'etag-a' } })],
  ['offline pin', 'vault_pin_remove', h => h.removeVaultOfflinePin('pin-a')],
  ['vault lock', 'vault_lock', h => h.lockVault()],
  ['logout actual handler', 'logout', h => h.handleAction('logout')],
  ['account remove', 'account_remove', h => h.removeSelectedAccount()],
  ['removed account restore', 'account_restore', h => h.restoreRemovedAccount('profile-old')]
];
test('all confirmed actions wait for explicit approval; Cancel emits no RPC and OK emits exactly one', async t => {
  for (const [name, action, start] of cases) await t.test(name, async () => {
    for (const approval of [false, true]) {
      const h = harness(); const pending = start(h);
      assert.equal(h.prompts.length, 1); assert.equal(h.state.nativeDialogBusy, true); assert.equal(h.calls.length, 0);
      assert.equal(h.prompts[0].options.okLabel, 'OK'); assert.equal(h.prompts[0].options.cancelLabel, 'Cancel');
      h.dialog.resolve(approval); await pending;
      assert.equal(h.state.nativeDialogBusy, false);
      assert.equal(h.calls.length, approval ? (action === 'account_remove' ? 2 : 1) : 0);
      if (approval) {
        if (action === 'account_remove') assert.deepEqual(h.calls.map(call => call.action), ['status', action]);
        else assert.equal(h.calls[0].action, action);
      }
    }
  });
});
test('all confirmed actions refuse rejected or nonboolean truthy approvals', async t => {
  for (const [name, , start] of cases) await t.test(name, async () => {
    for (const value of [1, 'yes', {}, []]) {
      const h = harness(), pending = start(h); h.dialog.resolve(value); await pending; assert.equal(h.calls.length, 0);
    }
    const h = harness(), pending = start(h); h.dialog.reject(new Error('synthetic denied dialog')); await pending;
    assert.equal(h.calls.length, 0); assert.match(h.state.error, /Could not show confirmation/); assert.equal(h.state.nativeDialogBusy, false);
  });
});
test('all confirmed actions reject approval after account epoch or profile changes', async t => {
  for (const [name, , start] of cases) await t.test(name, async () => {
    for (const mutate of [h => h.state.accountEpoch++, h => { h.state.selectedAccount = 'profile-b'; }]) {
      const h = harness(), pending = start(h); mutate(h); h.dialog.resolve(true); await pending; assert.equal(h.calls.length, 0);
    }
  });
});
test('one pending prompt blocks a duplicate action and clears busy after cancellation', async () => {
  const h = harness(), first = h.disconnectSpaceFolderSync('space-a');
  await h.removePair('alpha-one'); assert.equal(h.prompts.length, 1); assert.equal(h.calls.length, 0);
  h.dialog.resolve(false); await first; assert.equal(h.state.nativeDialogBusy, false);
  const blocked = harness(); blocked.state.accountSwitching = true; await blocked.removePair('alpha-one'); assert.equal(blocked.prompts.length, 0);
});
test('disconnect rejects changed pair set and changed operational conditions after approval', async () => {
  for (const change of [h => { h.state.pairs = h.state.pairs.filter(p => p.id !== 'alpha-two'); }, h => { h.state.pairs[0].id = 'replacement'; }, h => { h.state.agentReachable = false; }, h => { h.state.status.connected = false; }, h => { h.state.mutationBusy = 1; }]) {
    const h = harness(), pending = h.disconnectSpaceFolderSync('space-a');
    change(h);
    h.dialog.resolve(true); await pending; assert.equal(h.calls.length, 0);
  }
});
test('offline pin and lock reject stale flow and generation before their RPC', async () => {
  for (const start of [h => h.removeVaultOfflinePin('pin-a'), h => h.lockVault()]) {
    for (const change of [h => { h.state.vaultDialog = { ...h.state.vaultDialog }; }, h => { h.state.vaultGeneration++; }]) {
      const h = harness(), pending = start(h); change(h); h.dialog.resolve(true); await pending; assert.equal(h.calls.length, 0);
    }
  }
  const h = harness(), pending = h.removeVaultOfflinePin('pin-a'); h.state.vaultDialog.pinGeneration++; h.dialog.resolve(true); await pending; assert.equal(h.calls.length, 0);
});
test('AST binds imported async dialog and every confirmation site awaits the common helper', () => {
  const calls = []; const globals = [];
  const visit = n => {
    if (ts.isCallExpression(n) && ts.isIdentifier(n.expression)) {
      if (n.expression.text === 'confirmAccountAction') calls.push(n);
      if (n.expression.text === 'confirm') globals.push(n);
    }
    ts.forEachChild(n, visit);
  }; visit(tree);
  assert.equal(calls.length, 8); assert.equal(globals.length, 0);
  for (const call of calls) assert.ok(ts.isAwaitExpression(call.parent), 'each handler must await confirmation');
  const helper = tree.statements.find(n => ts.isFunctionDeclaration(n) && n.name?.text === 'confirmAccountAction');
  const helperCalls = [];
  const scan = n => { if (ts.isCallExpression(n) && ts.isIdentifier(n.expression) && n.expression.text === 'confirmDialog') helperCalls.push(n); ts.forEachChild(n, scan); }; scan(helper);
  assert.equal(helperCalls.length, 1); assert.ok(ts.isAwaitExpression(helperCalls[0].parent));
  assert.ok(tree.statements.some(n => ts.isImportDeclaration(n) && n.moduleSpecifier.text === '@tauri-apps/plugin-dialog' && n.importClause?.namedBindings?.elements?.some(x => x.propertyName?.text === 'confirm' && x.name.text === 'confirmDialog')));
});
