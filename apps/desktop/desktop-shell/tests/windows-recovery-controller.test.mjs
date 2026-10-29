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

const savedItem = { record_id: 'a'.repeat(32), generation: 9, space_id: 'space-1',
  path: 'Personal/report.txt', bytes: 17, state: 'needs_review', has_remote_baseline: true, retry_requires_review: true };
const savedPage = { ...response, items: [savedItem] };
const applied = { profile_id: 'default', auth_generation: 7, recovery_scope_token: 'b'.repeat(64),
  state: 'verified_applied', retained: true, remote_verified: true, local_completion: 'uncertain', attempts: 1 };
async function readyController() {
  const controller = new WindowsRecoveryController();
  await controller.load(context, async () => savedPage, () => true);
  return controller;
}

test('explicit retry dispatches one exact retained revision and refreshes discovery only after its result', async () => {
  const controller = await readyController(); const calls = [];
  await controller.retry(context, savedItem.record_id, 9, true, async (action, args) => {
    calls.push({ action, args });
    return action === 'windows_recovery_retry' ? applied : savedPage;
  }, async () => true, () => true);
  assert.deepEqual(calls[0], { action: 'windows_recovery_retry', args: {
    profile_id: 'default', expected_generation: 7, expected_recovery_scope_token: 'b'.repeat(64),
    record_id: savedItem.record_id, generation: 9
  } });
  assert.equal(calls.length, 2); assert.equal(calls[1].action, 'windows_recovery_list');
  assert.deepEqual(controller.state.retryResult, applied); assert.deepEqual(controller.state.page, savedPage);
  assert.equal(controller.state.retrying, false);
});

test('cancel, missing capability and unlisted or old revision never mutate or refresh', async () => {
  for (const scenario of [
    { supported: false, id: savedItem.record_id, generation: 9, approve: true },
    { supported: true, id: savedItem.record_id, generation: 9, approve: false },
    { supported: true, id: 'b'.repeat(32), generation: 9, approve: true },
    { supported: true, id: savedItem.record_id, generation: 10, approve: true }
  ]) {
    const c = await readyController(); let requests = 0; let confirmations = 0;
    await c.retry(context, scenario.id, scenario.generation, scenario.supported,
      async () => { requests++; return applied; }, async () => { confirmations++; return scenario.approve; }, () => true);
    assert.equal(requests, 0); assert.equal(confirmations, scenario.supported && !scenario.approve ? 1 : 0);
    assert.deepEqual(c.state.page, savedPage); assert.equal(c.state.retryResult, null);
  }
});

test('context and capability changes while confirmation is open prevent dispatch', async () => {
  for (const changed of [
    { ...context, accountEpoch: 5 }, { ...context, profileId: 'profile-' + '1'.repeat(32) },
    { ...context, server: 'https://other.example' }, { ...context, clientId: 'other' },
    { ...context, cloudRoot: 'D:/other' }, { ...context, authGeneration: 8 },
    { ...context, recoveryScopeToken: 'c'.repeat(64) }, null
  ]) {
    const c = await readyController(); const confirm = deferred(); let calls = 0;
    const pending = c.retry(context, savedItem.record_id, 9, true, async () => { calls++; return applied; }, () => confirm.promise, () => true);
    c.setContext(changed); confirm.resolve(true); await pending;
    assert.equal(calls, 0); assert.equal(c.state.retryResult, null);
  }
  const c = await readyController(); const confirm = deferred(); let capable = true, calls = 0;
  const pending = c.retry(context, savedItem.record_id, 9, true, async () => { calls++; }, () => confirm.promise, () => capable);
  capable = false; confirm.resolve(true); await pending; assert.equal(calls, 0);
});

test('duplicate clicks cannot open another confirmation or overlap retry and refresh', async () => {
  const c = await readyController(); const confirmation = deferred(), mutation = deferred(), refresh = deferred();
  let confirms = 0; const calls = [];
  const request = async action => { calls.push(action); return action === 'windows_recovery_retry' ? mutation.promise : refresh.promise; };
  const retry = () => c.retry(context, savedItem.record_id, 9, true, request, () => { confirms++; return confirmation.promise; }, () => true);
  const first = retry(); await retry(); assert.equal(confirms, 1); assert.equal(calls.length, 0);
  confirmation.resolve(true); await new Promise(resolve => setImmediate(resolve)); await retry();
  assert.deepEqual(calls, ['windows_recovery_retry']);
  mutation.resolve(applied); await new Promise(resolve => setImmediate(resolve)); await retry();
  assert.deepEqual(calls, ['windows_recovery_retry', 'windows_recovery_list']);
  refresh.resolve(savedPage); await first; assert.equal(c.state.retrying, false);
});

test('stale mutation responses never render completion or trigger refresh in a new account', async () => {
  const c = await readyController(); const mutation = deferred(); const calls = [];
  const pending = c.retry(context, savedItem.record_id, 9, true, async action => { calls.push(action); return mutation.promise; }, async () => true, () => true);
  await new Promise(resolve => setImmediate(resolve));
  c.setContext({ ...context, accountEpoch: 5 }); mutation.resolve(applied); await pending;
  assert.deepEqual(calls, ['windows_recovery_retry']); assert.equal(c.state.retryResult, null); assert.equal(c.state.page, null);
});

test('wrong response bindings and failed dispatch leave outcome unconfirmed without automatic retry', async () => {
  for (const patch of [{ profile_id: 'profile-' + '1'.repeat(32) }, { auth_generation: 8 }, { recovery_scope_token: 'c'.repeat(64) }, null]) {
    const c = await readyController(); let calls = 0;
    await c.retry(context, savedItem.record_id, 9, true, async () => {
      calls++; if (!patch) throw new Error('synthetic transport loss'); return { ...applied, ...patch };
    }, async () => true, () => true);
    assert.equal(calls, 1); assert.equal(c.state.retryResult, null); assert.equal(c.state.page, null);
    assert.match(c.state.error, /could not be confirmed/);
  }
});

test('confirmed remote result survives a failed read-only refresh with a separate honest error', async () => {
  const c = await readyController(); let calls = 0;
  await c.retry(context, savedItem.record_id, 9, true, async action => {
    calls++; if (action === 'windows_recovery_retry') return applied; throw new Error('synthetic list failure');
  }, async () => true, () => true);
  assert.equal(calls, 2); assert.deepEqual(c.state.retryResult, applied); assert.equal(c.state.page, null);
  assert.equal(c.state.error, 'synthetic list failure');
});

function mainRetryHarness(controller, confirmation) {
  const tree = ts.createSourceFile('main.ts', mainSource, ts.ScriptTarget.Latest, true);
  const fn = tree.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'retryWindowsSavedEdit');
  assert.ok(fn, 'main must wire the explicit retry');
  const js = ts.transpileModule(fn.getText(tree), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } }).outputText;
  const state = { status: { ...status, windows_recovery_retry_supported: true }, nativeDialogBusy: false, accountSwitching: false,
    accountEpoch: context.accountEpoch, selectedAccount: context.profileId };
  let active = context; const calls = [], dialogs = [];
  const retry = new Function('state', 'isWindowsAgentStatus', 'windowsRecoveryBinding', 'windowsRecoveryContextKey',
    'isCurrentAccount', 'windowsRecoveryController', 'request', 'confirmDialog', 'render',
    `${js}; return retryWindowsSavedEdit;`
  )(state, () => true, () => ({ context: active }), windowsRecoveryContextKey,
    (epoch, profile) => state.accountEpoch === epoch && state.selectedAccount === profile,
    controller, async (action, args) => { calls.push({ action, args }); return action === 'windows_recovery_retry' ? applied : savedPage; },
    async (message, options) => { dialogs.push({ message, options }); return confirmation.promise; }, () => {});
  return { state, retry, calls, dialogs, changeContext: value => { active = value; } };
}

test('main native confirmation cancels safely and rechecks live scope and capability before retry', async () => {
  for (const mode of ['cancel', 'scope_changed', 'capability_removed', 'approved', 'old_agent']) {
    const c = await readyController(), confirmation = deferred(); const h = mainRetryHarness(c, confirmation);
    if (mode === 'old_agent') delete h.state.status.windows_recovery_retry_supported;
    const pending = h.retry(savedItem.record_id, 9);
    if (mode === 'scope_changed') h.changeContext({ ...context, recoveryScopeToken: 'c'.repeat(64) });
    if (mode === 'capability_removed') h.state.status.windows_recovery_retry_supported = false;
    confirmation.resolve(mode !== 'cancel'); await pending;
    assert.equal(h.calls.filter(call => call.action === 'windows_recovery_retry').length, mode === 'approved' ? 1 : 0);
    if (mode !== 'old_agent') {
      assert.match(h.dialogs[0].message, /upload.*only if the cloud baseline is unchanged/);
      assert.match(h.dialogs[0].message, /original saved edit.*remain retained/);
      assert.equal(h.dialogs[0].options.cancelLabel, 'Cancel');
    } else assert.equal(h.dialogs.length, 0);
    assert.equal(h.state.nativeDialogBusy, false);
  }
});

test('nonboolean approval cannot authorize retry and a new account cannot overlap an outstanding mutation', async () => {
  for (const approval of ['yes', 1, {}, undefined]) {
    const c = await readyController(); let calls = 0;
    await c.retry(context, savedItem.record_id, 9, true, async () => { calls++; }, async () => approval, () => true);
    assert.equal(calls, 0);
  }
  const c = await readyController(), pending = deferred(); let mutations = 0;
  const first = c.retry(context, savedItem.record_id, 9, true,
    async () => { mutations++; return pending.promise; }, async () => true, () => true);
  await new Promise(resolve => setImmediate(resolve));
  const next = { ...context, accountEpoch: 5 };
  c.setContext(next); await c.load(next, async () => savedPage, () => true);
  await c.retry(next, savedItem.record_id, 9, true, async () => { mutations++; return applied; }, async () => true, () => true);
  assert.equal(mutations, 1); pending.resolve(applied); await first;
  assert.equal(c.state.retryResult, null);
});

test('a stale confirmation cannot dispatch even if the same identity is restored later', async () => {
  const c = await readyController(), confirmation = deferred(); let calls = 0;
  const pending = c.retry(context, savedItem.record_id, 9, true,
    async () => { calls++; return applied; }, () => confirmation.promise, () => true);
  c.setContext(null); await c.load(context, async () => savedPage, () => true);
  confirmation.resolve(true); await pending; assert.equal(calls, 0);
});

test('actual saved-edits card hides Retry for old agents and disables actions during review', async () => {
  const tree = ts.createSourceFile('main.ts', mainSource, ts.ScriptTarget.Latest, true);
  const fn = tree.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'windowsRecoverySettingsCard');
  const js = ts.transpileModule(fn.getText(tree), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } }).outputText;
  const c = await readyController(), state = { status: { ...status } };
  const card = new Function('state', 'windowsRecoveryBinding', 'windowsRecoveryController', 'esc', 'svg', 'formatBytes', 'windowsRecoveryRetryMessage',
    `${js}; return windowsRecoverySettingsCard;`
  )(state, () => ({ eligibility: { available: true }, context }), c,
    value => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('"', '&quot;'), () => '', value => String(value), () => 'Cloud save verified. Local completion is not confirmed.');
  for (const capability of [undefined, false, 'true', 1]) {
    state.status.windows_recovery_retry_supported = capability;
    assert.doesNotMatch(card(), /data-action="retry-windows-recovery"/);
  }
  state.status.windows_recovery_retry_supported = true;
  assert.match(card(), /data-action="retry-windows-recovery"/);
  c.state.retrying = true;
  assert.match(card(), /data-action="retry-windows-recovery"[^>]* disabled/);
  assert.match(card(), /data-action="load-windows-recovery" disabled/);
  c.state.retrying = false; c.state.retryResult = applied;
  assert.match(card(), /Local completion is not confirmed/);
  assert.match(card(), /Viewing this list does not change the files/);
});
