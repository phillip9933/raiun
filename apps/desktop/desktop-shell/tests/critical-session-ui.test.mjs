import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import ts from 'typescript';

const main = await readFile(new URL('../src/main.ts', import.meta.url), 'utf8');
const tree = ts.createSourceFile('main.ts', main, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
const declarations = new Map(tree.statements
  .filter(node => ts.isFunctionDeclaration(node) && node.name)
  .map(node => [node.name.text, node]));

function evaluateFunction(name, context) {
  const node = declarations.get(name);
  assert.ok(node, `${name} is declared in main.ts`);
  const source = ts.transpileModule(`${node.getFullText(tree)}\nglobalThis.__tested = ${name};`, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None }
  }).outputText;
  vm.runInNewContext(source, context);
  return context.__tested;
}

test('retained Windows sign-in is distinct from an available offline namespace', () => {
  const isRetainedSignInOnly = evaluateFunction('isRetainedSignInOnly', {});
  assert.equal(isRetainedSignInOnly({ connected: false, offline: true, offline_namespace: false }), true);
  assert.equal(isRetainedSignInOnly({ connected: false, offline: true }), true);
  assert.equal(isRetainedSignInOnly({ connected: false, offline: true, offline_namespace: true }), false);
  assert.equal(isRetainedSignInOnly({ connected: false, offline: false, offline_namespace: false }), false);

  const accountStatusLabel = evaluateFunction('accountStatusLabel', { isRetainedSignInOnly });
  assert.equal(accountStatusLabel({ connected: false, offline: true, offline_namespace: false }), 'Reconnecting sign-in');
  assert.equal(accountStatusLabel({ connected: false, offline: true, offline_namespace: true }), 'Working offline');
  assert.match(main, /cloud files cannot be reached until the server reconnects\./);
  assert.match(main, /offlineNamespace: state\.status\?\.offline_namespace === true/);
  assert.match(main, /const offlineNamespace = state\.status\?\.offline_namespace === true/);
  assert.match(main, /state\.status\?\.mounted && \(connected \|\| state\.status\?\.offline_namespace === true\)/);
});

test('reconnect details remain visible in the notice and Settings and safely escape agent text', () => {
  const escapeHtml = value => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;');
  const details = evaluateFunction('connectionFailureDetails', { esc: escapeHtml });
  assert.equal(details({ connected: false, offline: true, error: 'Connection <failed> & retry' }), '<details class="connection-error-detail"><summary>Connection details</summary><p>Connection &lt;failed&gt; &amp; retry</p></details>');
  assert.equal(details({ connected: false, offline: true }), '');
  assert.equal((main.match(/connectionFailureDetails\(state\.status\)/g) || []).length, 4);
  assert.match(main, /state\.status\?\.refreshing \? 'Checking connection…'/);
  assert.match(main, /state\.status\?\.refreshing \? 'Checking…' : 'Retry connection'/);
});

async function signInHarness({ changeAccountDuringAuth = false } = {}) {
  const state = {
    accountEpoch: 11, selectedAccount: 'profile-a', server: 'https://cloud.example.com', clientId: '',
    error: '', message: '', mutationBusy: 0
  };
  const refreshCalls = [];
  const renderCalls = [];
  const context = {
    state,
    URL,
    app: { querySelector: () => null },
    request: async action => {
      assert.equal(action, 'auth_begin');
      if (changeAccountDuringAuth) {
        state.accountEpoch++;
        state.selectedAccount = 'profile-b';
      }
      throw new Error('authorization endpoint unavailable');
    },
    refresh: async showError => {
      refreshCalls.push(showError);
      state.status = { connected: false, offline: true };
    },
    isCurrentAccount: (epoch, profileId) => epoch === state.accountEpoch && profileId === state.selectedAccount,
    isStaleAccountRequest: () => false,
    messageOf: error => error instanceof Error ? error.message : String(error),
    render: () => renderCalls.push(true)
  };
  const beginSignIn = evaluateFunction('beginSignIn', context);
  await beginSignIn();
  return { state, refreshCalls, renderCalls };
}

test('sign-in failure refreshes authoritative status and keeps the original error visible', async () => {
  const result = await signInHarness();
  assert.deepEqual(result.refreshCalls, [false]);
  assert.deepEqual(result.state.status, { connected: false, offline: true });
  assert.equal(result.state.error, 'authorization endpoint unavailable');
  assert.equal(result.state.mutationBusy, 0);
});

test('sign-in failure does not refresh or surface an error after the selected account changes', async () => {
  const result = await signInHarness({ changeAccountDuringAuth: true });
  assert.deepEqual(result.refreshCalls, []);
  assert.equal(result.state.error, '');
  assert.equal(result.state.selectedAccount, 'profile-b');
  assert.equal(result.state.mutationBusy, 0);
});

test('account removal confirms the selected profile and sends a freshly refreshed auth generation', async () => {
  const state = {
    accountEpoch: 4, selectedAccount: 'profile-a', accountRemovalSupported: true, agentReachable: true,
    accountSwitching: false, mutationBusy: 0, accounts: [{ id: 'profile-a', label: 'Work' }],
    status: { auth_generation: 8 }, error: '', message: ''
  };
  const requests = [];
  const refreshes = [];
  const context = {
    state,
    confirmAccountAction: async text => { assert.match(text, /Remove account “Work”/); assert.match(text, /saved vault-password access will be revoked/); return true; },
    isCurrentAccount: (epoch, profile) => epoch === state.accountEpoch && profile === state.selectedAccount,
    refresh: async () => { refreshes.push(true); state.status = { ...state.status, auth_generation: 8 }; },
    request: async (action, args) => { requests.push({ action, args }); return { removed_profile_id: 'profile-a', selected: null, local_data_preserved: true, credentials_revoked: true }; },
    syncAccounts: async () => {},
    render: () => {},
    messageOf: String,
    isStaleAccountRequest: () => false
  };
  await evaluateFunction('removeSelectedAccount', context)();
  assert.deepEqual(JSON.parse(JSON.stringify(requests)), [{ action: 'account_remove', args: { profile_id: 'profile-a', expected_auth_generation: 8, confirm: true } }]);
  assert.equal(refreshes.length, 1);
  assert.equal(state.message, 'Removed Work. Local files and recovery copies were preserved.');
  assert.equal(state.mutationBusy, 0);
});

test('removing the last account exposes Add/Restore and cannot start sign-in without a profile', async () => {
  const state = {
    accountEpoch: 3, selectedAccount: 'last-profile', accountRemovalSupported: true, agentReachable: true,
    accountSwitching: false, mutationBusy: 0, accountsLoading: false,
    accounts: [{ id: 'last-profile', label: 'Last account' }],
    removedAccounts: [{ id: 'older-profile', label: 'Older account', local_data_preserved: true }],
    status: { auth_generation: 12 }, error: '', message: '', server: 'https://cloud.example.com', clientId: ''
  };
  const removalCalls = [];
  const context = {
    state,
    confirmAccountAction: async () => true,
    isCurrentAccount: (epoch, profile) => epoch === state.accountEpoch && profile === state.selectedAccount,
    refresh: async () => { state.status = { auth_generation: 12 }; },
    request: async (action, args) => {
      removalCalls.push({ action, args });
      return { removed_profile_id: 'last-profile', selected: null, local_data_preserved: true, credentials_revoked: true };
    },
    syncAccounts: async () => {
      state.accountEpoch++;
      state.selectedAccount = '';
      state.accounts = [];
    },
    render: () => {}, messageOf: String, isStaleAccountRequest: () => false
  };
  await evaluateFunction('removeSelectedAccount', context)();
  assert.equal(state.selectedAccount, '');
  assert.equal(evaluateFunction('noAccountsAvailable', { state })(), true);
  const emptyPage = evaluateFunction('noAccountPage', { svg: () => '<svg></svg>' })();
  assert.match(emptyPage, /data-action="open-add-account">Add account/);
  assert.match(emptyPage, /data-page="settings">Open Settings/);
  assert.match(main, /if \(noAccountsAvailable\(\) && state\.page !== 'settings'\) return noAccountPage\(\)/);
  assert.match(main, /<details class="removed-accounts" \$\{noAccounts \? 'open' : ''\}>/);
  assert.match(main, /if \(!profileId\) \{ state\.error = 'Add or restore an account before signing in\.'/);

  const authCalls = [];
  const beginSignIn = evaluateFunction('beginSignIn', {
    state, app: { querySelector: () => null }, request: async (...args) => authCalls.push(args), render: () => {}
  });
  await beginSignIn();
  assert.deepEqual(authCalls, []);
  assert.match(state.error, /Add or restore an account/);
  assert.equal(removalCalls[0].action, 'account_remove');
});

function accountRenameHarness({ switchBeforeSave = false, staleExpectedLabel = false } = {}) {
  const state = {
    accountEpoch: 5, selectedAccount: 'profile-a', agentReachable: true, accountsLoading: false,
    accounts: [{ id: 'profile-a', label: 'Work' }, { id: 'profile-b', label: 'Personal' }],
    mutationBusy: 0, accountSwitching: false, nativeDialogBusy: false, addAccountOpen: false,
    addOpen: false, pickerOpen: false, vaultDialog: null, vaultAccessOpen: false, recoveryLoading: false,
    encryptedEditRecoveryLoading: false, resolvingConflict: false, pickerCreatingFolder: false,
    message: '', error: ''
  };
  const accountRenameUi = { profileId: 'profile-a', accountEpoch: 5, expectedLabel: 'Work', draft: '  Work account  ', editing: true, saving: false, error: '' };
  if (switchBeforeSave) { state.accountEpoch++; state.selectedAccount = 'profile-b'; }
  if (staleExpectedLabel) state.accounts[0].label = 'Renamed elsewhere';
  const calls = [];
  const context = {
    state, accountRenameUi,
    isCurrentAccount: (epoch, profileId) => epoch === state.accountEpoch && profileId === state.selectedAccount,
    accountRenameContextCurrent: () => !!accountRenameUi.profileId && accountRenameUi.accountEpoch === state.accountEpoch && accountRenameUi.profileId === state.selectedAccount,
    accountRenameDraftError: () => '',
    accountRenameCanSave: () => false,
    accountSwitchDisabled: () => state.mutationBusy > 0 || state.accountsLoading || state.accountSwitching,
    request: async (action, args) => {
      calls.push({ action, args });
      return { renamed_profile_id: 'profile-a', label: 'Work account', selected: 'profile-a' };
    },
    syncAccounts: async () => { state.accounts[0] = { id: 'profile-a', label: 'Work account' }; },
    render: () => {}, messageOf: error => String(error), isStaleAccountRequest: () => false
  };
  return { state, accountRenameUi, calls, context };
}

test('account display-name rename targets only the selected profile and refreshes its label', async () => {
  const { state, accountRenameUi, calls, context } = accountRenameHarness();
  await evaluateFunction('saveAccountRename', context)();
  assert.deepEqual(JSON.parse(JSON.stringify(calls)), [{ action: 'account_rename', args: { profile_id: 'profile-a', expected_label: 'Work', label: 'Work account' } }]);
  assert.deepEqual(JSON.parse(JSON.stringify(state.accounts)), [{ id: 'profile-a', label: 'Work account' }, { id: 'profile-b', label: 'Personal' }]);
  assert.equal(accountRenameUi.editing, false);
  assert.equal(state.message, 'Account display name updated.');
  assert.equal(state.mutationBusy, 0);
  assert.match(main, /data-action="edit-account-name"/);
  assert.match(main, /data-action="save-account-name"/);
  assert.match(main, /data-action="cancel-account-name"/);
});

test('display-name rename refuses a stale account selection or expected label and keeps the form on label conflict', async () => {
  const switched = accountRenameHarness({ switchBeforeSave: true });
  await evaluateFunction('saveAccountRename', switched.context)();
  assert.deepEqual(switched.calls, []);

  const staleLabel = accountRenameHarness({ staleExpectedLabel: true });
  await evaluateFunction('saveAccountRename', staleLabel.context)();
  assert.deepEqual(staleLabel.calls, []);
  assert.equal(staleLabel.accountRenameUi.editing, true);
  assert.match(staleLabel.accountRenameUi.error, /name changed/);
});

test('account removal rejects a same-profile reauthentication during the confirmation dialog', async () => {
  const state = {
    accountEpoch: 4, selectedAccount: 'profile-a', accountRemovalSupported: true, agentReachable: true,
    accountSwitching: false, mutationBusy: 0, busy: false, accounts: [{ id: 'profile-a', label: 'Work' }],
    status: { auth_generation: 8 }, error: '', message: ''
  };
  let requestCount = 0;
  const context = {
    state,
    confirmAccountAction: async () => { state.status = { auth_generation: 9 }; return true; },
    isCurrentAccount: (epoch, profile) => epoch === state.accountEpoch && profile === state.selectedAccount,
    refresh: async () => { state.status = { ...state.status }; },
    request: async () => { requestCount++; }, syncAccounts: async () => {}, render: () => {},
    messageOf: String, isStaleAccountRequest: () => false
  };
  await evaluateFunction('removeSelectedAccount', context)();
  assert.equal(requestCount, 0);
  assert.match(state.error, /sign-in changed while confirmation was open/);
  assert.equal(state.mutationBusy, 0);
});

test('account removal emits no RPC if confirmation is followed by a queued or failed refresh', async () => {
  const state = {
    accountEpoch: 4, selectedAccount: 'profile-a', accountRemovalSupported: true, agentReachable: true,
    accountSwitching: false, mutationBusy: 0, busy: false, accounts: [{ id: 'profile-a', label: 'Work' }],
    status: { auth_generation: 3 }, error: '', message: ''
  };
  let requestCount = 0;
  const context = {
    state, confirmAccountAction: async () => true,
    isCurrentAccount: (epoch, profile) => epoch === state.accountEpoch && profile === state.selectedAccount,
    refresh: async () => {}, request: async () => { requestCount++; }, syncAccounts: async () => {}, render: () => {},
    messageOf: String, isStaleAccountRequest: () => false
  };
  await evaluateFunction('removeSelectedAccount', context)();
  assert.equal(requestCount, 0);
  assert.match(state.error, /could not refresh this account’s sign-in status/);
});

test('account removal stops if selection changes while confirmation is open', async () => {
  const state = {
    accountEpoch: 4, selectedAccount: 'profile-a', accountRemovalSupported: true, agentReachable: true,
    accountSwitching: false, mutationBusy: 0, accounts: [{ id: 'profile-a', label: 'Work' }],
    status: { auth_generation: 3 }, error: '', message: ''
  };
  let requestCount = 0;
  const context = {
    state,
    confirmAccountAction: async () => { state.accountEpoch++; state.selectedAccount = 'profile-b'; return true; },
    isCurrentAccount: (epoch, profile) => epoch === state.accountEpoch && profile === state.selectedAccount,
    refresh: async () => {}, request: async () => { requestCount++; }, syncAccounts: async () => {}, render: () => {},
    messageOf: String, isStaleAccountRequest: () => false
  };
  await evaluateFunction('removeSelectedAccount', context)();
  assert.equal(requestCount, 0);
  assert.equal(state.mutationBusy, 0);
});

test('restoring a removed account targets that profile and requires a new sign-in', async () => {
  const state = {
    accountEpoch: 7, selectedAccount: 'active-profile', accountRemovalSupported: true, agentReachable: true,
    accountSwitching: false, mutationBusy: 0, accountsLoading: false, nativeDialogBusy: false, addOpen: false,
    pickerOpen: false, vaultDialog: null, vaultAccessOpen: false, addAccountOpen: false, recoveryLoading: false,
    encryptedEditRecoveryLoading: false, resolvingConflict: false, pickerCreatingFolder: false,
    removedAccounts: [{ id: 'old-profile', label: 'Archive', local_data_preserved: true }], error: '', message: ''
  };
  const requests = [];
  const context = {
    state,
    confirmAccountAction: async text => { assert.match(text, /Restore “Archive”/); return true; },
    isCurrentAccount: (epoch, profile) => epoch === state.accountEpoch && profile === state.selectedAccount,
    accountSwitchDisabled: () => false,
    request: async (action, args) => { requests.push({ action, args }); return { restored_profile_id: 'old-profile', selected: 'active-profile', sign_in_required: true }; },
    syncAccounts: async () => {}, render: () => {}, messageOf: String, isStaleAccountRequest: () => false
  };
  await evaluateFunction('restoreRemovedAccount', context)('old-profile');
  assert.deepEqual(JSON.parse(JSON.stringify(requests)), [{ action: 'account_restore', args: { profile_id: 'old-profile', confirm: true } }]);
  assert.equal(state.message, 'Restored Archive. Sign in to reconnect it.');
  assert.equal(state.mutationBusy, 0);
});
