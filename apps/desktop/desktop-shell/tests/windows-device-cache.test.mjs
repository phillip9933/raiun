import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';

const transpile = (source) => ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 }
}).outputText;
const recovery = await readFile(new URL('../src/windows-recovery.ts', import.meta.url), 'utf8');
const recoveryUrl = `data:text/javascript;base64,${Buffer.from(transpile(recovery)).toString('base64')}`;
const source = await readFile(new URL('../src/windows-device-cache.ts', import.meta.url), 'utf8');
const compiled = transpile(source).replace("from './windows-recovery'", `from '${recoveryUrl}'`);
const { validateWindowsDeviceCacheUsage } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`);
const main = await readFile(new URL('../src/main.ts', import.meta.url), 'utf8');
const tree = ts.createSourceFile('main.ts', main, ts.ScriptTarget.Latest, true);
const functionText = (name) => {
  const node = tree.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === name);
  assert.ok(node, name);
  return node.getText(tree);
};
const context = (changes = {}) => ({ profileId: 'profile-' + '1'.repeat(32), accountEpoch: 4,
  authGeneration: 7, recoveryScopeToken: 'b'.repeat(64), flowGeneration: 2,
  server: 'https://synthetic.invalid', clientId: 'test-client', cloudRoot: 'C:\\Raiun', ...changes });
const usage = (changes = {}) => ({ profile_id: context().profileId, auth_generation: 7,
  recovery_scope_token: 'b'.repeat(64), scope: 'device_all_accounts', read_only: true,
  last_observed: true, atomic_snapshot: false, quota_bytes: 1000, used_bytes: 1200,
  pinned_bytes: 300, protected_bytes: 200, over_quota: true, ...changes });
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };
function harness(request) {
  let current = context();
  const ui = { usage: null, contextKey: '', sequence: 0, loading: false, error: '' };
  const text = ['syncWindowsDeviceCacheContext', 'refreshWindowsDeviceCacheUsage', 'windowsDeviceCacheCard'].map(functionText).join('\n');
  const functions = new Function('currentWindowsOfflineContext', 'windowsDeviceCacheUi', 'request', 'render', 'isCurrentAccount',
    'validateWindowsDeviceCacheUsage', 'isStaleAccountRequest', 'messageOf', 'svg', 'esc', 'formatBytes',
    `${transpile(text)}; return { sync: syncWindowsDeviceCacheContext, refresh: refreshWindowsDeviceCacheUsage, card: windowsDeviceCacheCard };`
  )(() => current, ui, request, () => {}, (epoch, profile) => current?.accountEpoch === epoch && current?.profileId === profile,
    validateWindowsDeviceCacheUsage, () => false, String, () => '', String, value => `${value} B`);
  return { ...functions, ui, setContext: value => { current = value; } };
}

test('device-wide usage requires the exact scope and current profile/generation/root token', () => {
  assert.deepEqual(validateWindowsDeviceCacheUsage(usage(), context()), usage());
  for (const invalid of [usage({ scope: 'selected_account' }), usage({ profile_id: 'default' }),
    usage({ auth_generation: 8 }), usage({ recovery_scope_token: 'c'.repeat(64) }),
    usage({ atomic_snapshot: true }), usage({ read_only: false }), usage({ last_observed: false }),
    usage({ quota_bytes: -1 }), usage({ used_bytes: Number.MAX_SAFE_INTEGER + 1 }),
    usage({ protected_bytes: null }), usage({ extra: 1 }), usage({ over_quota: 'true' })]) {
    assert.throws(() => validateWindowsDeviceCacheUsage(invalid, context()));
  }
});

test('actual explicit refresh sends only current scope and discards a reply after selection changes', async () => {
  const calls = [], pending = deferred();
  const view = harness(async (action, args) => { calls.push({ action, args }); return pending.promise; });
  assert.equal(calls.length, 0);
  const loading = view.refresh();
  await view.refresh();
  assert.deepEqual(calls, [{ action: 'windows_device_cache_usage', args: {
    profile_id: context().profileId, expected_generation: 7, expected_recovery_scope_token: 'b'.repeat(64)
  } }]);
  view.setContext(context({ profileId: 'profile-' + '2'.repeat(32) }));
  view.sync(); pending.resolve(usage()); await loading;
  assert.equal(view.ui.usage, null);
  assert.equal(view.ui.loading, false);
  view.setContext(null); view.sync();
  assert.equal(view.card(), '');
});

test('actual Windows card labels shared last-observed totals and offline controls live in their workspace', async () => {
  const view = harness(async () => usage());
  assert.match(view.card(), /Device cache \(all accounts\)/);
  assert.match(view.card(), /not limited to the selected account/);
  assert.match(view.card(), /has not been checked/);
  await view.refresh();
  const html = view.card();
  assert.match(html, /Last observed: 1200 B used of 1000 B/);
  assert.doesNotMatch(html, /data-action="manage-windows-offline-files"/);
  assert.doesNotMatch(html, /data-action="open-offline-files"/);
  assert.match(functionText('offlineWorkspacePage'), /windowsDeviceCacheCard\(\).*windowsOfflineFilesCard\(\).*windowsOfflineFoldersCard\(\)/s);
  const card = functionText('offlineAvailabilityCard');
  assert.match(card, /if \(isWindowsAgentStatus\(state.status\)\) return windowsDeviceCacheCard\(\)/);
  assert.match(card, /state.status\?\.offline_cache/);
});
