import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import ts from 'typescript';

const source = await readFile(new URL('../src/main.ts', import.meta.url), 'utf8');
const accessibilitySource = await readFile(new URL('../src/vault-dialog-accessibility.ts', import.meta.url), 'utf8');
const accessibilityCompiled = ts.transpileModule(accessibilitySource, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 }
}).outputText;
const { isVaultPasswordValidationError } = await import(
  `data:text/javascript;base64,${Buffer.from(accessibilityCompiled).toString('base64')}`
);
const cleanupSource = await readFile(new URL('../src/vault-lock-state.ts', import.meta.url), 'utf8');
const cleanup = await import(`data:text/javascript;base64,${Buffer.from(ts.transpileModule(cleanupSource, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 }
}).outputText).toString('base64')}`);
const sourceFile = ts.createSourceFile('main.ts', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
const wanted = new Set(['vaultDirectoryRows', 'clearVaultBrowse', 'nativeVaultBrowseAvailable', 'confirmAccountAction', 'forgetSavedVault', 'lockVault', 'unlockVault', 'nativeVaultAccess', 'nativeVaultLockIncomplete', 'nativeVaultLockScope', 'updateNativeVaultLockCleanup', 'reconcileVaultLockStatus', 'checkVaultLockStatus', 'vaultDialog', 'nativeVaultDrivePanel']);
const functions = new Map();
for (const statement of sourceFile.statements) {
  if (ts.isFunctionDeclaration(statement) && statement.name && wanted.has(statement.name.text)) {
    functions.set(statement.name.text, statement.getText(sourceFile));
  }
}
assert.equal(functions.size, wanted.size, 'the exercised production functions must remain directly extractable');

function makeHarness({ nativeMode = false, requestImpl = async () => ({}), unlockImpl = async () => ({ unlocked: true, remembered: false, remembered_status: 'not_saved' }) } = {}) {
  const input = { value: 'synthetic password' };
  const calls = [];
  const state = {
    status: nativeMode ? { vault_access_mode: 'native_read_only' } : {},
    accountEpoch: 7,
    selectedAccount: 'profile-a',
    nativeDialogBusy: false,
    accountSwitching: false,
    vaultGeneration: 11,
    page: 'folders',
    message: '',
    vaultDialog: {
      intent: 'manage', spaceId: 'space-a', rootPath: '/Private.vault', rootResourceId: 'root-a',
      initialized: true, unlocked: true, statusUnknown: false, loading: false,
      rememberOnDevice: true, rememberedStatus: 'known_saved', entries: [{ path: '/secret' }],
      path: '/secret', directoryBindings: new Map(), currentDirectoryBinding: null, vaultMountReady: true, editRetryBusy: false, editRetryJob: null,
      pinBusy: false, pinJob: null, generation: 11, accountEpoch: 7
    }
  };
  const context = {
    state,
    ...cleanup,
    esc: value => String(value), svg: () => '', vaultPasswordErrorAttributes: () => '',
    nativeVaultLockWarnings: new Set(),
    vaultAppFeaturesAvailable: () => !nativeMode,
    app: { querySelector: selector => selector === '#vault-password' ? input : null },
    confirmDialog: async () => true,
    render() {},
    forgetVaultOperationsScope() {},
    clearVaultPinUi() {},
    clearVaultEditRetryUi() {},
    isCurrentAccount: (epoch, profileId = state.selectedAccount) => epoch === state.accountEpoch && profileId === state.selectedAccount,
    isStaleAccountRequest: () => false,
    messageOf: error => error instanceof Error ? error.message : String(error),
    request: async (action, payload) => {
      calls.push({ kind: 'request', action, payload: structuredClone(payload) });
      return requestImpl(action, payload);
    },
    vaultSecretRequest: async payload => {
      calls.push({ kind: 'secret', action: payload.action, payload: structuredClone(payload) });
      return unlockImpl(payload);
    },
    loadVaultPath: async () => {},
    loadVaultPins: async () => {},
    safeRememberedStatus: value => ['known_saved', 'not_saved', 'unknown', 'unavailable'].includes(value) ? value : null,
    safeVaultExistingOverwriteReason: () => null,
    safeVaultMountWriteReason: () => null,
    mountedVaultAccessMessage: () => 'Drive ready.',
    isVaultPasswordValidationError,
    refreshEncryptedRetryLatestStatuses: async () => {}
  };
  const declarations = [...functions.values()].join('\n');
  const compiled = ts.transpileModule(
    `${declarations}\nglobalThis.__vaultActions = { forgetSavedVault, lockVault, unlockVault, reconcileVaultLockStatus, checkVaultLockStatus, vaultDialog };`,
    { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None } }
  ).outputText;
  vm.runInNewContext(compiled, context, { timeout: 1000 });
  return { ...context.__vaultActions, state, input, calls, context };
}

test('forget then lock does not remember a later password unlock unless the user opts in again', async () => {
  const harness = makeHarness({ requestImpl: async action => {
    if (action === 'vault_forget') return { remembered: false, remembered_status: 'not_saved', cleanup: 'complete' };
    if (action === 'vault_lock') return { vault_mount_ready: false, vault_mount_writable: false, vault_mount_existing_file_overwrite: false };
    return {};
  } });
  await harness.forgetSavedVault();
  assert.equal(harness.state.vaultDialog.rememberedStatus, 'not_saved');
  assert.equal(harness.state.vaultDialog.rememberOnDevice, false);

  await harness.lockVault();
  assert.equal(harness.state.vaultDialog.unlocked, false);
  assert.equal(harness.state.vaultDialog.error, '');
  harness.input.value = 'synthetic password';
  await harness.unlockVault(false);
  const firstUnlock = harness.calls.find(call => call.kind === 'secret' && call.action === 'vault_unlock');
  assert.ok(firstUnlock);
  assert.equal(Object.hasOwn(firstUnlock.payload, 'remember'), false);
  assert.equal(harness.state.vaultDialog.unlocked, true);
  assert.equal(harness.state.vaultDialog.error, '');

  harness.state.vaultDialog.unlocked = false;
  harness.state.vaultDialog.rememberOnDevice = true;
  harness.input.value = 'synthetic password';
  await harness.unlockVault(false);
  const unlocks = harness.calls.filter(call => call.kind === 'secret' && call.action === 'vault_unlock');
  assert.equal(unlocks.length, 2);
  assert.equal(unlocks[1].payload.remember, true);
});

test('failed forget does not claim the saved key was forgotten or clear the opt-in state', async () => {
  const harness = makeHarness({ requestImpl: async action => {
    if (action === 'vault_forget') throw new Error('synthetic failure');
    return {};
  } });
  await harness.forgetSavedVault();
  assert.equal(harness.state.vaultDialog.rememberedStatus, 'known_saved');
  assert.equal(harness.state.vaultDialog.rememberOnDevice, true);
  assert.equal(harness.state.vaultDialog.error, 'synthetic failure');
});

test('stale forget completion cannot update a replacement dialog', async () => {
  let resolveForget;
  const harness = makeHarness({ requestImpl: action => action === 'vault_forget'
    ? new Promise(resolve => { resolveForget = resolve; })
    : Promise.resolve({}) });
  const oldFlow = harness.state.vaultDialog;
  const pending = harness.forgetSavedVault();
  assert.equal(oldFlow.loading, true);
  harness.state.vaultDialog = {
    ...oldFlow, rootResourceId: 'root-b', rememberOnDevice: true,
    rememberedStatus: 'known_saved', loading: false, generation: 12
  };
  harness.state.vaultGeneration = 12;
  resolveForget({ remembered: false });
  await pending;
  assert.equal(oldFlow.rememberedStatus, 'known_saved');
  assert.equal(oldFlow.rememberOnDevice, true);
  assert.equal(harness.state.vaultDialog.rootResourceId, 'root-b');
  assert.equal(harness.state.vaultDialog.rememberedStatus, 'known_saved');
  assert.equal(harness.state.vaultDialog.rememberOnDevice, true);
});

test('password is cleared and an integrity failure is associated with the field', async () => {
  const harness = makeHarness({ unlockImpl: async () => { throw new Error('vault integrity token did not verify'); } });
  harness.state.vaultDialog.unlocked = false;
  harness.state.vaultDialog.rememberOnDevice = false;
  harness.input.value = 'synthetic password';
  await harness.unlockVault(false);
  const call = harness.calls.find(item => item.kind === 'secret');
  assert.equal(call.payload.password, 'synthetic password');
  assert.equal(harness.input.value, '');
  assert.equal(harness.state.vaultDialog.error, 'vault integrity token did not verify');
  assert.equal(harness.state.vaultDialog.passwordError, 'vault integrity token did not verify');
});

test('saved-key unlock never reads the password value, still clears the field, and has no field error', async () => {
  const harness = makeHarness({ unlockImpl: async () => { throw new Error('saved key unavailable'); } });
  harness.state.vaultDialog.unlocked = false;
  let cleared = false;
  Object.defineProperty(harness.input, 'value', {
    configurable: true,
    get() { throw new Error('saved-key flow must not read the password field'); },
    set(value) { assert.equal(value, ''); cleared = true; }
  });
  await harness.unlockVault(true);
  const call = harness.calls.find(item => item.kind === 'secret');
  assert.equal(Object.hasOwn(call.payload, 'password'), false);
  assert.equal(call.payload.use_saved, true);
  assert.equal(cleared, true);
  assert.equal(harness.state.vaultDialog.passwordError, '');
  assert.equal(harness.state.vaultDialog.error, 'saved key unavailable');
});

test('transport failure stays a general alert without marking the password invalid', async () => {
  const harness = makeHarness({ unlockImpl: async () => { throw new Error('connection reset by peer'); } });
  harness.state.vaultDialog.unlocked = false;
  harness.state.vaultDialog.rememberOnDevice = false;
  harness.input.value = 'synthetic password';
  await harness.unlockVault(false);
  assert.equal(harness.input.value, '');
  assert.equal(harness.state.vaultDialog.error, 'connection reset by peer');
  assert.equal(harness.state.vaultDialog.passwordError, '');
});

test('native read-only manual/saved/forget/lock workflow never starts app browsing or offline work', async () => {
  const harness = makeHarness({nativeMode:true,
    requestImpl:async action => action === 'vault_forget' ? {remembered:false, remembered_status:'not_saved'} : {vault_mount_ready:false,vault_mount_writable:false},
    unlockImpl:async () => ({unlocked:true,remembered:true,remembered_status:'known_saved',vault_mount_ready:true,vault_mount_writable:false})});
  harness.state.vaultDialog.unlocked=false;
  await harness.unlockVault(false);
  await harness.lockVault();
  await harness.unlockVault(true);
  await harness.forgetSavedVault();
  assert.equal(harness.state.vaultDialog.unlocked,true,'forget keeps the session open');
  await harness.lockVault();
  assert.deepEqual(harness.calls.map(c=>c.action),['vault_unlock','vault_lock','vault_unlock','vault_forget','vault_lock']);
  assert.equal(harness.calls[2].payload.use_saved,true);
  assert.equal(harness.state.vaultDialog.unlocked,false);
  assert.equal(harness.state.vaultDialog.rememberedStatus,'not_saved');
});

test('native mode refuses an unconfirmed unlock without enabling session or drive readiness', async()=>{
  for(const response of [{unlocked:false,vault_mount_ready:true},{vault_mount_ready:true}]){
    const h=makeHarness({nativeMode:true,unlockImpl:async()=>response});h.state.vaultDialog.unlocked=false;
    await h.unlockVault(false);
    assert.equal(h.state.vaultDialog.unlocked,false);assert.equal(h.state.vaultDialog.vaultMountReady,false);
    assert.equal(h.state.vaultDialog.statusUnknown,true);assert.equal(h.state.vaultDialog.vaultMountWritable,false);
    assert.equal(h.input.value,'');assert.match(h.state.vaultDialog.error,/did not confirm/);
    assert.deepEqual(h.calls.map(c=>c.action),['vault_unlock']);
  }
});


test('failed native cleanup stays incomplete after key-only inspection and dialog reopen; explicit retry clears it', async () => {
  let fail = true;
  const h = makeHarness({ nativeMode: true, requestImpl: async action => {
    if (action === 'vault_lock') {
      if (fail) throw new Error('Vault reads stopped, but local cleanup is incomplete; edits and retry state were preserved');
      return { unlocked: false, vault_lock_cleanup_status: 'complete', vault_mount_ready: false };
    }
    return { root_path: '/Private.vault', root_resource_id: 'root-a', initialized: true,
      unlocked: false, vault_mount_ready: false, vault_lock_cleanup_status: 'unknown', remembered_status: 'not_saved' };
  } });
  Object.assign(h.state.status, { profile_id: 'profile-a', server: 'https://example.test', client_id: 'client',
    cloud_root: 'C:\\Synthetic', root_configuration: { recovery_scope_token: 'a'.repeat(64) } });
  await h.lockVault();
  assert.equal(h.state.vaultDialog.unlocked, false);
  assert.equal(h.state.vaultDialog.lockCleanupStatus, 'incomplete');
  assert.match(h.state.message, /Local files may still be accessible/);
  assert.match(h.vaultDialog(), /Lock incomplete/);
  assert.match(h.vaultDialog(), /Retry Lock/);
  assert.doesNotMatch(h.vaultDialog(), /Locked · unlock|data-vault-action="unlock"/);
  assert.deepEqual(h.calls.map(c => c.action), ['vault_lock', 'vault_inspect']);
  const old = h.state.vaultDialog;
  h.state.vaultGeneration++;
  h.state.vaultDialog = { ...old, lockCleanupStatus: 'unknown', error: '', generation: h.state.vaultGeneration };
  await h.reconcileVaultLockStatus(h.state.vaultDialog, h.state.accountEpoch, h.state.vaultGeneration);
  assert.equal(h.state.vaultDialog.lockCleanupStatus, 'incomplete', 'same root warning survives a new dialog');
  assert.match(h.vaultDialog(), /Local files may still be accessible/);
  await h.unlockVault(false);
  assert.equal(h.calls.some(c => c.kind === 'secret'), false, 'cleanup refusal cannot silently unlock again');
  fail = false;
  await h.lockVault();
  assert.equal(h.state.vaultDialog.lockCleanupStatus, 'complete');
  assert.match(h.state.message, /confirmed local cleanup/);
  await h.reconcileVaultLockStatus(h.state.vaultDialog, h.state.accountEpoch, h.state.vaultGeneration);
  assert.equal(h.state.vaultDialog.lockCleanupStatus, 'unknown', 'later key-only metadata is not a new cleanup proof');
});

test('backend incomplete is restored in a fresh renderer; unrelated scope and stale Lock response cannot clear it', async () => {
  const h = makeHarness({ nativeMode: true, requestImpl: async () => ({ root_path: '/Private.vault', root_resource_id: 'root-a', initialized: true,
    unlocked: false, vault_mount_ready: false, vault_lock_cleanup_status: 'incomplete' }) });
  h.state.vaultDialog.lockCleanupStatus = 'unknown';
  await h.reconcileVaultLockStatus(h.state.vaultDialog, h.state.accountEpoch, h.state.vaultGeneration);
  assert.equal(h.state.vaultDialog.lockCleanupStatus, 'incomplete');
  const other = makeHarness({ nativeMode: true, requestImpl: async () => ({ root_path: '/Private.vault', root_resource_id: 'foreign-root', initialized: true, unlocked: false, vault_lock_cleanup_status: 'unknown' }) });
  await other.reconcileVaultLockStatus(other.state.vaultDialog, other.state.accountEpoch, other.state.vaultGeneration);
  assert.equal(other.state.vaultDialog.statusUnknown, true, 'root mismatch cannot rebind cleanup status');
  let finish;
  const stale = makeHarness({ nativeMode: true, requestImpl: () => new Promise(resolve => { finish = resolve; }) });
  const pending = stale.lockVault();
  await new Promise(resolve => setImmediate(resolve));
  const current = { ...stale.state.vaultDialog, lockCleanupStatus: 'incomplete', generation: ++stale.state.vaultGeneration };
  stale.state.vaultDialog = current;
  finish({ unlocked: false, vault_lock_cleanup_status: 'complete' });
  await pending;
  assert.equal(current.lockCleanupStatus, 'incomplete');
  assert.equal(stale.state.message, '');
});
