import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';

const helperSource = await readFile(new URL('../src/windows-recovery.ts', import.meta.url), 'utf8');
const mainSource = await readFile(new URL('../src/main.ts', import.meta.url), 'utf8');
const helperJs = ts.transpileModule(helperSource, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 }
}).outputText;
const helperUrl = `data:text/javascript;base64,${Buffer.from(helperJs).toString('base64')}`;
const controllerSource = await readFile(new URL('../src/windows-recovery-controller.ts', import.meta.url), 'utf8');
const controllerJs = ts.transpileModule(controllerSource, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 }
}).outputText.replace("from './windows-recovery'", `from '${helperUrl}'`);
const { WindowsRecoveryController, eligibleWindowsRecoveryContext, windowsRecoveryContextKey } = await import(
  `data:text/javascript;base64,${Buffer.from(controllerJs).toString('base64')}`
);

const status = {
  profile_id: 'default',
  connected: true,
  auth_generation: 7,
  root_configuration: { valid: true, identity_bound: true, registration_state: 'registered', recovery_scope_token: 'b'.repeat(64) }
};
const identity = { accountEpoch: 4, server: 'https://cloud.example', clientId: 'synthetic', cloudRoot: 'C:\\Raiun' };
const context = {
  accountEpoch: 4,
  profileId: 'default',
  server: identity.server,
  clientId: identity.clientId,
  cloudRoot: identity.cloudRoot,
  authGeneration: 7,
  recoveryScopeToken: 'b'.repeat(64)
};
const response = {
  profile_id: 'default',
  auth_generation: 7,
  recovery_scope_token: 'b'.repeat(64),
  items: [],
  next_after: null,
  read_only: true
};

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

test('eligible context binds account epoch, identity, configured root, and auth generation', () => {
  const result = eligibleWindowsRecoveryContext(true, 'default', status, identity);
  assert.equal(result.eligibility.available, true);
  assert.deepEqual(result.context, context);
  const base = windowsRecoveryContextKey(context);
  for (const changed of [
    { ...context, accountEpoch: 5 },
    { ...context, server: 'https://other.example' },
    { ...context, clientId: 'different' },
    { ...context, cloudRoot: 'D:\\Raiun' },
    { ...context, authGeneration: 8 },
    { ...context, recoveryScopeToken: 'c'.repeat(64) }
  ]) assert.notEqual(windowsRecoveryContextKey(changed), base);
});

test('controller sends the fixed read-only discovery request and accepts only its validated response', async () => {
  const controller = new WindowsRecoveryController();
  const calls = [];
  await controller.load(context, async (action, args) => {
    calls.push({ action, args });
    return response;
  }, () => true);
  assert.deepEqual(calls, [{
    action: 'windows_recovery_list',
    args: {
      profile_id: 'default',
      expected_generation: 7,
      expected_recovery_scope_token: 'b'.repeat(64),
      limit: 50
    }
  }]);
  assert.equal(controller.state.loading, false);
  assert.equal(controller.state.error, '');
  assert.deepEqual(controller.state.page, response);
});

test('changed recovery context clears old view state and discards late list results', async () => {
  const controller = new WindowsRecoveryController();
  const pending = deferred();
  const request = controller.load(context, () => pending.promise, () => true);
  assert.equal(controller.state.loading, true);

  // A fresh agent-instance token invalidates data even when account and path
  // strings are unchanged.
  controller.setContext({ ...context, recoveryScopeToken: 'c'.repeat(64) });
  assert.equal(controller.state.loading, false);
  assert.equal(controller.state.page, null);
  assert.equal(controller.state.error, '');
  pending.resolve(response);
  await request;
  assert.equal(controller.state.page, null);
  assert.equal(controller.state.loading, false);
  assert.equal(controller.state.error, '');
});

test('current-context predicate also fences a response when the caller status changes first', async () => {
  const controller = new WindowsRecoveryController();
  const pending = deferred();
  let current = true;
  const request = controller.load(context, () => pending.promise, () => current);
  current = false;
  pending.resolve(response);
  await request;
  assert.equal(controller.state.page, null);
  assert.equal(controller.state.loading, false);
  assert.equal(controller.state.error, '');
});

test('failed and malformed requests remain an error rather than an empty success', async () => {
  const failed = new WindowsRecoveryController();
  await failed.load(context, async () => { throw new Error('synthetic read failed'); }, () => true);
  assert.equal(failed.state.page, null);
  assert.equal(failed.state.error, 'synthetic read failed');

  const malformed = new WindowsRecoveryController();
  await malformed.load(context, async () => ({ ...response, auth_generation: 8 }), () => true);
  assert.equal(malformed.state.page, null);
  assert.match(malformed.state.error, /invalid or stale/);

  for (const invalidResponse of [
    { ...response, recovery_scope_token: 'c'.repeat(64) },
    Object.fromEntries(Object.entries(response).filter(([key]) => key !== 'recovery_scope_token'))
  ]) {
    const invalid = new WindowsRecoveryController();
    await invalid.load(context, async () => invalidResponse, () => true);
    assert.equal(invalid.state.page, null);
    assert.match(invalid.state.error, /invalid or stale/);
  }
});

test('a failed refresh clears the prior successful page before reporting the failure', async () => {
  const controller = new WindowsRecoveryController();
  await controller.load(context, async () => response, () => true);
  assert.deepEqual(controller.state.page, response);

  await controller.load(context, async () => {
    assert.equal(controller.state.page, null);
    throw new Error('synthetic refresh failure');
  }, () => true);
  assert.equal(controller.state.page, null);
  assert.equal(controller.state.error, 'synthetic refresh failure');
  assert.equal(controller.state.loading, false);
});

test('actual main offline contexts accept only matching selected/status added-profile identity', async () => {
  const main = await readFile(new URL('../src/main.ts', import.meta.url), 'utf8');
  const tree = ts.createSourceFile('main.ts', main, ts.ScriptTarget.Latest, true);
  const names = new Set(['currentWindowsOfflineFolderContext', 'currentWindowsOfflineContext']);
  const selected = tree.statements.filter(node => ts.isFunctionDeclaration(node) && names.has(node.name?.text));
  assert.equal(selected.length, 2);
  const js = ts.transpileModule(selected.map(node => node.getText(tree)).join('\n'), {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 }
  }).outputText;
  const profile = 'profile-' + '1'.repeat(32);
  const state = { selectedAccount: profile, accountEpoch: 4, accountSwitching: false,
    status: { ...status, profile_id: profile, mounted: true, server: identity.server, client_id: identity.clientId, cloud_root: identity.cloudRoot } };
  const binding = () => eligibleWindowsRecoveryContext(true, state.selectedAccount, state.status, { ...identity, accountEpoch: state.accountEpoch });
  const contexts = new Function('state', 'isWindowsAgentStatus', 'eligibleWindowsRecoveryContext', 'windowsRecoveryBinding', 'windowsOfflineFilesUi',
    `${js}; return { folder: currentWindowsOfflineFolderContext, file: currentWindowsOfflineContext };`
  )(state, () => true, eligibleWindowsRecoveryContext, binding, { generation: 9 });
  assert.equal(contexts.folder().profileId, profile);
  assert.equal(contexts.file().profileId, profile);
  assert.equal(contexts.file().accountEpoch, 4);
  state.selectedAccount = 'profile-' + '2'.repeat(32);
  assert.equal(contexts.folder(), null);
  assert.equal(contexts.file(), null);
  state.selectedAccount = profile; state.accountSwitching = true;
  assert.equal(contexts.folder(), null);
  assert.equal(contexts.file(), null);
});

test('protected vault recovery request and completion stay bound to the selected account, drive, vault and UI generation', () => {
  assert.match(mainSource, /expected_generation: scope\.context\.authGeneration/);
  assert.match(mainSource, /expected_recovery_scope_token: scope\.context\.recoveryScopeToken/);
  assert.match(mainSource, /space_id: scope\.spaceId,[\s\S]*root_resource_id: scope\.rootResourceId,[\s\S]*remote_root: scope\.remoteRoot/);
  assert.match(mainSource, /protectedVaultRecoveryScopeIsCurrent\(flow, scope\.key, generation\)/);
  assert.match(mainSource, /state\.vaultGeneration, flow\.spaceId, flow\.rootResourceId, flow\.rootPath/);
  assert.match(mainSource, /context\.accountEpoch, context\.profileId, context\.server, context\.clientId, context\.cloudRoot/);
});
