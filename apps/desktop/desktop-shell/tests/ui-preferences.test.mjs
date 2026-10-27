import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';

const source = await readFile(new URL('../src/ui-preferences.ts', import.meta.url), 'utf8');
const compiled = ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 }
}).outputText;
const { appearanceStorageKey, themeStorageKey, readAppearance, writeAppearance, mountControlState, ACCENT_COLORS } = await import(
  `data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`
);

function memoryStorage() {
  const entries = new Map();
  return {
    entries,
    getItem(key) { return entries.get(key) ?? null; },
    setItem(key, value) { entries.set(key, String(value)); }
  };
}

test('theme defaults safely when storage is unavailable or has invalid values', () => {
  assert.deepEqual(readAppearance({ getItem() { throw new Error('blocked'); } }, 'before-theme-profile'), { theme: 'system', accent: 'ocean' });
  const storage = memoryStorage();
  storage.setItem(themeStorageKey(), 'auto-dark');
  storage.setItem(appearanceStorageKey('invalid-profile'), JSON.stringify({ theme: 'dark', accent: 'url(javascript:alert(1))' }));
  assert.deepEqual(readAppearance(storage, 'invalid-profile'), { theme: 'system', accent: 'ocean' });
  assert.deepEqual(Object.keys(ACCENT_COLORS).sort(), ['amber', 'ocean', 'rose', 'teal', 'violet']);
});

test('global theme is readable and writable before a profile is selected', () => {
  const storage = memoryStorage();
  assert.deepEqual(readAppearance(storage, ''), { theme: 'system', accent: 'ocean' });
  assert.deepEqual(writeAppearance(storage, '', { theme: 'dark' }), { theme: 'dark', accent: 'ocean' });
  assert.equal(storage.getItem(themeStorageKey()), 'dark');
  assert.deepEqual(readAppearance(storage, ''), { theme: 'dark', accent: 'ocean' });
  assert.deepEqual(readAppearance(storage, 'profile-a'), { theme: 'dark', accent: 'ocean' });
  assert.equal(appearanceStorageKey(''), null);
});

test('account accents remain isolated by the exact profile ID while the theme stays global', () => {
  const storage = memoryStorage();
  writeAppearance(storage, 'Profile-A', { accent: 'violet' });
  writeAppearance(storage, 'profile-a', { accent: 'rose' });

  assert.notEqual(appearanceStorageKey('Profile-A'), appearanceStorageKey('profile-a'));
  assert.deepEqual(readAppearance(storage, 'Profile-A'), { theme: 'dark', accent: 'violet' });
  assert.deepEqual(readAppearance(storage, 'profile-a'), { theme: 'dark', accent: 'rose' });
  writeAppearance(storage, 'profile-a', { theme: 'light' });
  assert.deepEqual(readAppearance(storage, 'Profile-A'), { theme: 'light', accent: 'violet' });
  assert.deepEqual(readAppearance(storage, 'profile-a'), { theme: 'light', accent: 'rose' });
});

test('appearance preferences remain usable in-session when browser storage writes fail', () => {
  const writesBlocked = { getItem() { return null; }, setItem() { throw new Error('quota'); } };
  assert.deepEqual(writeAppearance(writesBlocked, 'fallback-profile', { theme: 'light', accent: 'teal' }), { theme: 'light', accent: 'teal' });
  assert.deepEqual(readAppearance(writesBlocked, 'fallback-profile'), { theme: 'light', accent: 'teal' });
});

test('mount controls reflect capability, connection, busy and current mount state', () => {
  assert.deepEqual(mountControlState(true, true, false, false), { mountDisabled: false, unmountDisabled: true });
  assert.deepEqual(mountControlState(true, true, true, false), { mountDisabled: true, unmountDisabled: false });
  assert.deepEqual(mountControlState(true, false, false, false), { mountDisabled: true, unmountDisabled: true });
  assert.deepEqual(mountControlState(false, true, true, false), { mountDisabled: true, unmountDisabled: true });
  assert.deepEqual(mountControlState(true, true, true, true), { mountDisabled: true, unmountDisabled: true });
});

test('theme is global, account color remains profile-scoped, and existing sign-out is available for retained sessions', async () => {
  const main = await readFile(new URL('../src/main.ts', import.meta.url), 'utf8');
  assert.match(main, /readAppearance\([^\n]*state\.selectedAccount/);
  assert.match(main, /Theme applies to all accounts\. Color marks this account\./);
  assert.match(main, /const canSignOut = state\.agentReachable && \(connected \|\| state\.status\?\.offline === true \|\| state\.status\?\.offline_namespace === true\)/);
  assert.match(main, /if \(isRetainedSignInOnly\(status\)\) return 'Reconnecting sign-in'/);
  assert.match(main, /offlineNamespace: state\.status\?\.offline_namespace === true/);
  assert.match(main, /const offlineNamespace = state\.status\?\.offline_namespace === true/);
  assert.match(main, /state\.status\?\.mounted && \(connected \|\| state\.status\?\.offline_namespace === true\)/);
  assert.match(main, /\$\{canSignOut \? `<button class="button subtle" data-action="logout"[\s\S]*?Sign out<\/button>` : ''\}/);
  assert.match(main, /case 'logout': \{[\s\S]*?confirmAccountAction\([\s\S]*?isCurrentAccount\(epoch, profileId\)[\s\S]*?await run\('logout', \{\}\)/);
  assert.match(main, /async function run\([\s\S]*?catch \(error\) \{ if \(isCurrentAccount\(epoch\) && !isStaleAccountRequest\(error\)\) state\.error = messageOf\(error\); \}/);
  assert.doesNotMatch(main, /data-action="remove-account"/);
});

test('auth_begin failure refreshes the same profile and preserves the original error', async () => {
  const main = await readFile(new URL('../src/main.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('main.ts', main, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const declaration = parsed.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'beginSignIn');
  assert.ok(declaration, 'beginSignIn is declared in the main UI');
  const fn = ts.transpileModule(`${declaration.getFullText(parsed)}\nglobalThis.beginSignIn = beginSignIn;`, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None }
  }).outputText;
  const state = { accountEpoch: 3, selectedAccount: 'account-a', server: 'https://cloud.example.com', clientId: '', error: '', message: '', mutationBusy: 0 };
  const refreshed = [];
  const context = {
    state,
    URL,
    app: { querySelector() { return null; } },
    request: async () => { throw new Error('discovery failed'); },
    isCurrentAccount: (epoch, profileId = state.selectedAccount) => epoch === state.accountEpoch && profileId === state.selectedAccount,
    isStaleAccountRequest: () => false,
    messageOf: error => error.message,
    refresh: async showError => { refreshed.push(showError); state.status = { connected: false }; },
    render() {}
  };
  const { default: vm } = await import('node:vm');
  vm.runInNewContext(fn, context);
  await context.beginSignIn();
  assert.deepEqual(refreshed, [false]);
  assert.equal(state.error, 'discovery failed');
  assert.equal(state.mutationBusy, 0);
});

test('auth_begin failure does not refresh or write an error after the selected profile changes', async () => {
  const main = await readFile(new URL('../src/main.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('main.ts', main, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const declaration = parsed.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'beginSignIn');
  assert.ok(declaration, 'beginSignIn is declared in the main UI');
  const fn = ts.transpileModule(`${declaration.getFullText(parsed)}\nglobalThis.beginSignIn = beginSignIn;`, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None }
  }).outputText;
  const state = { accountEpoch: 3, selectedAccount: 'account-a', server: 'https://cloud.example.com', clientId: '', error: '', message: '', mutationBusy: 0 };
  const refreshed = [];
  const context = {
    state,
    URL,
    app: { querySelector() { return null; } },
    request: async () => { state.selectedAccount = 'account-b'; throw new Error('discovery failed'); },
    isCurrentAccount: (epoch, profileId) => epoch === state.accountEpoch && profileId === state.selectedAccount,
    isStaleAccountRequest: () => false,
    messageOf: error => error.message,
    refresh: async showError => { refreshed.push(showError); },
    render() {}
  };
  const { default: vm } = await import('node:vm');
  vm.runInNewContext(fn, context);
  await context.beginSignIn();
  assert.deepEqual(refreshed, []);
  assert.equal(state.error, '');
  assert.equal(state.mutationBusy, 0);
});

test('backend sign-out rejection remains visible and leaves the selected account state intact', async () => {
  const main = await readFile(new URL('../src/main.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('main.ts', main, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const declaration = parsed.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'run');
  assert.ok(declaration, 'run is declared in the main UI');
  const fn = ts.transpileModule(`${declaration.getFullText(parsed)}\nglobalThis.run = run;`, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None }
  }).outputText;
  const originalStatus = { connected: false, offline: true, offline_namespace: false };
  const state = { accountEpoch: 4, selectedAccount: 'account-a', status: originalStatus, mutationBusy: 0, error: '', message: '' };
  const context = {
    state,
    request: async action => { assert.equal(action, 'logout'); throw new Error('Saved recovery data must be reviewed first.'); },
    isCurrentAccount: (epoch, profileId = state.selectedAccount) => epoch === state.accountEpoch && profileId === state.selectedAccount,
    isStaleAccountRequest: () => false,
    messageOf: error => error.message,
    refresh: async () => { throw new Error('refresh should not run after rejected sign-out'); },
    render() {}
  };
  const { default: vm } = await import('node:vm');
  vm.runInNewContext(fn, context);
  await context.run('logout', {});
  assert.equal(state.error, 'Saved recovery data must be reviewed first.');
  assert.equal(state.selectedAccount, 'account-a');
  assert.equal(state.status, originalStatus);
  assert.equal(state.mutationBusy, 0);
});
