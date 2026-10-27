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
  assert.match(main, /Cloud files are unavailable until it reconnects\./);
  assert.match(main, /offlineNamespace: state\.status\?\.offline_namespace === true/);
  assert.match(main, /const offlineNamespace = state\.status\?\.offline_namespace === true/);
  assert.match(main, /state\.status\?\.mounted && \(connected \|\| state\.status\?\.offline_namespace === true\)/);
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
