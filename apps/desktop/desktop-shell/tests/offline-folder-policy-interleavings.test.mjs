import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';
import ts from 'typescript';

const source = await readFile(new URL('../src/main.ts', import.meta.url), 'utf8');
const sourceFile = ts.createSourceFile('main.ts', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
const names = [
  'validOfflineFolderPath',
  'offlineFolderIsCurrent',
  'offlineRequestIsCurrent',
  'offlinePolicyKey',
  'loadOfflineFolderPolicy',
  'setOfflineFolderPolicy',
  'browseRemote',
];
const functions = new Map();
for (const statement of sourceFile.statements) {
  if (ts.isFunctionDeclaration(statement) && statement.name && names.includes(statement.name.text)) {
    functions.set(statement.name.text, statement.getText(sourceFile));
  }
}
for (const name of names) assert.ok(functions.has(name), `main.ts must define ${name}`);

const compiled = ts.transpileModule(
  `${[...functions.values()].join('\n')}\n${names.map(name => `globalThis.${name} = ${name};`).join('\n')}`,
  { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None } },
).outputText;

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

function makeContext(request) {
  const state = {
    accountEpoch: 1,
    pickerGeneration: 1,
    selectedAccount: 'account-a',
    status: { connected: true, offline_cache: { available: true } },
    spaces: [{ id: 'space-a', encrypted: false }],
    spaceId: 'space-a',
    pickerPurpose: 'offline',
    pickerOpen: true,
    pickerPath: '/',
    pickerEntries: [],
    pickerError: '',
    message: '',
  };
  const offlineUi = {
    folderPolicies: new Map(),
    folderPolicyLoading: new Map(),
    folderPolicySaving: new Map(),
    folderListing: null,
    policies: new Map(),
    availabilityStates: new Map(),
    error: '',
  };
  const context = {
    state,
    offlineUi,
    request,
    render() {},
    isCurrentAccount: epoch => epoch === state.accountEpoch,
    isStaleAccountRequest: () => false,
    folderPolicyControlsAvailable: () => true,
    messageOf: error => String(error?.message || error),
    lastPath: path => path.split('/').filter(Boolean).at(-1) || '',
    isWindowsAgentStatus: () => false,
    providerAvailable: () => true,
    console,
    setTimeout,
    clearTimeout,
    Symbol,
    Map,
    Set,
    Promise,
  };
  vm.runInNewContext(compiled, context, { timeout: 1000 });
  return context;
}

test('successful current-folder CloudOnly mutation refreshes its effective policy after browse', async () => {
  const calls = [];
  const context = makeContext(async (action, args) => {
    calls.push([action, args]);
    if (action === 'cache_policy_set') return { space_id: 'space-a', path: '/', policy: 'cloud_only' };
    if (action === 'list') return [];
    if (action === 'cache_policy_get') return { space_id: 'space-a', path: '/', policy: 'cloud_only' };
    throw new Error(`unexpected request ${action}`);
  });
  context.offlineUi.folderListing = { epoch: 1, generation: 1, spaceId: 'space-a', path: '/' };

  await context.setOfflineFolderPolicy('/', '/', 'cloud_only', true);

  assert.deepEqual(calls.map(([action]) => action), ['cache_policy_set', 'list', 'cache_policy_get']);
  assert.equal(context.offlineUi.folderPolicies.get('account-a\0\0space-a\0/'), 'cloud_only');
});

test('an older same-key load cannot clear a newer generation loading token', async () => {
  const pending = [deferred(), deferred()];
  let gets = 0;
  const context = makeContext(async (action) => {
    assert.equal(action, 'cache_policy_get');
    return pending[gets++].promise;
  });
  context.offlineUi.folderListing = { epoch: 1, generation: 1, spaceId: 'space-a', path: '/' };
  const oldLoad = context.loadOfflineFolderPolicy('/', '/', true, 1, 1, 'space-a');
  const key = context.offlinePolicyKey('/');
  const oldToken = context.offlineUi.folderPolicyLoading.get(key);
  assert.ok(oldToken);

  context.state.pickerGeneration = 2;
  context.offlineUi.folderListing = { epoch: 1, generation: 2, spaceId: 'space-a', path: '/' };
  // Simulate the old view being retired before the current view starts a new
  // request for the same account/space/path key.
  context.offlineUi.folderPolicyLoading.delete(key);
  const newLoad = context.loadOfflineFolderPolicy('/', '/', true, 1, 2, 'space-a');
  const newToken = context.offlineUi.folderPolicyLoading.get(key);
  assert.ok(newToken);
  assert.notEqual(newToken, oldToken);

  pending[0].resolve({ space_id: 'space-a', path: '/', policy: 'recent' });
  await oldLoad;
  assert.equal(context.offlineUi.folderPolicyLoading.get(key), newToken);
  assert.equal(context.offlineUi.folderPolicies.has(key), false, 'stale response must not publish its value');

  pending[1].resolve({ space_id: 'space-a', path: '/', policy: 'cloud_only' });
  await newLoad;
  assert.equal(context.offlineUi.folderPolicies.get(key), 'cloud_only');
  assert.equal(context.offlineUi.folderPolicyLoading.has(key), false);
});

test('current-folder controls stay invalid while listing is pending or failed', async () => {
  const listing = deferred();
  const calls = [];
  const context = makeContext(async (action, args) => {
    calls.push([action, args]);
    if (action === 'list') return listing.promise;
    throw new Error(`unexpected request ${action}`);
  });

  assert.equal(context.offlineFolderIsCurrent('/', '/', true, 'space-a'), false);
  const browse = context.browseRemote('/');
  assert.equal(context.offlineFolderIsCurrent('/', '/', true, 'space-a'), false);
  listing.reject(new Error('listing unavailable'));
  await browse;
  assert.equal(context.offlineFolderIsCurrent('/', '/', true, 'space-a'), false);
  assert.deepEqual(calls.map(([action]) => action), ['list']);
});
