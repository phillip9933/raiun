import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';

const source = await readFile(new URL('../src/network-proxy.ts', import.meta.url), 'utf8');
const compiled = ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 }
}).outputText;
const { parseProxySettings, validateProxyDraft, proxyEditorEnabled } = await import(
  `data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`
);

test('proxy settings accept only the account-scoped backend shape', () => {
  assert.deepEqual(parseProxySettings({ proxy: { mode: 'system' }, account_id: null, revision: 2, apply_requires_reconnect: true }), {
    proxy: { mode: 'system' }, account_id: null, revision: 2, apply_requires_reconnect: true
  });
  assert.throws(() => parseProxySettings({ proxy: { mode: 'direct' }, account_id: null, revision: 0, apply_requires_reconnect: true }));
  assert.throws(() => parseProxySettings({ proxy: { mode: 'bypass' }, account_id: null, revision: 2, apply_requires_reconnect: true }));
});

test('explicit proxy accepts only credential-free HTTP(S) origins', () => {
  assert.deepEqual(validateProxyDraft('explicit', 'https://proxy.example:8443/'), {
    ok: true, config: { mode: 'explicit', url: 'https://proxy.example:8443' }
  });
  for (const value of [
    'ftp://proxy.example',
    'http://user:secret@proxy.example',
    'http://proxy.example/path',
    'http://proxy.example?',
    'http://proxy.example#fragment',
    'http://proxy.example with-space'
  ]) {
    const result = validateProxyDraft('explicit', value);
    assert.equal(result.ok, false);
    assert.equal(JSON.stringify(result).includes('secret'), false);
  }
});

test('proxy changes are disabled while connected, offline, authenticating, or saving', () => {
  const disconnected = { reachable: true, connected: false, offlineNamespace: false, authenticating: false, saving: false };
  assert.equal(proxyEditorEnabled(disconnected), true);
  for (const key of ['connected', 'offlineNamespace', 'authenticating', 'saving']) {
    assert.equal(proxyEditorEnabled({ ...disconnected, [key]: true }), false);
  }
  assert.equal(proxyEditorEnabled({ ...disconnected, reachable: false }), false);
});

test('Windows proxy settings preserve scope fencing and pre-sign-in defaults', () => {
  const reply = { proxy: { mode: 'system' }, account_id: 'account-a', revision: 1, apply_requires_reconnect: true };
  assert.throws(() => parseProxySettings(reply, true));
  const scope_token = 'b'.repeat(64);
  assert.equal(parseProxySettings({ ...reply, scope_token }, true).scope_token, scope_token);
  for (const token of [null, '', 'b'.repeat(63), scope_token + '\n', 'B'.repeat(64)]) {
    assert.throws(() => parseProxySettings({ ...reply, scope_token: token }, true));
  }
  const pending = parseProxySettings({ ...reply, account_id: null, scope_token: null }, true);
  assert.equal(pending.account_id, null);
  assert.equal(pending.scope_token, undefined);
  assert.equal(parseProxySettings(reply).account_id, 'account-a');
});


test('retained Windows credentials require sign-out even when disconnected', () => {
  const idle = { reachable: true, connected: false, offlineNamespace: false, authenticating: false, saving: false };
  assert.equal(proxyEditorEnabled(idle), true);
  assert.equal(proxyEditorEnabled({ ...idle, requiresSignOut: true }), false);
  assert.equal(proxyEditorEnabled({ ...idle, requiresSignOut: false }), true);
});
