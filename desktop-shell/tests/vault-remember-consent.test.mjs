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
const sourceFile = ts.createSourceFile('main.ts', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
const wanted = new Set(['confirmAccountAction', 'forgetSavedVault', 'lockVault', 'unlockVault']);
const functions = new Map();
for (const statement of sourceFile.statements) {
  if (ts.isFunctionDeclaration(statement) && statement.name && wanted.has(statement.name.text)) {
    functions.set(statement.name.text, statement.getText(sourceFile));
  }
}
assert.equal(functions.size, wanted.size, 'the exercised production functions must remain directly extractable');

function makeHarness({ requestImpl = async () => ({}), unlockImpl = async () => ({ unlocked: true, remembered: false, remembered_status: 'not_saved' }) } = {}) {
  const input = { value: 'synthetic password' };
  const calls = [];
  const state = {
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
      path: '/secret', vaultMountReady: true, editRetryBusy: false, editRetryJob: null,
      pinBusy: false, pinJob: null, generation: 11, accountEpoch: 7
    }
  };
  const context = {
    state,
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
    `${declarations}\nglobalThis.__vaultActions = { forgetSavedVault, lockVault, unlockVault };`,
    { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None } }
  ).outputText;
  vm.runInNewContext(compiled, context, { timeout: 1000 });
  return { ...context.__vaultActions, state, input, calls };
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
