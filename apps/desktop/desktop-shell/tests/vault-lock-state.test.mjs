import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';
const source = await readFile(new URL('../src/vault-lock-state.ts', import.meta.url), 'utf8');
const model = await import(`data:text/javascript;base64,${Buffer.from(ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } }).outputText).toString('base64')}`);

test('cleanup failure survives inspect/key changes; only explicit complete Lock clears it', () => {
  const merge = model.mergeVaultLockCleanup;
  assert.equal(merge('unknown', undefined, 'lock_failed'), 'incomplete');
  for (const value of ['unknown', 'complete', undefined]) assert.equal(merge('incomplete', value, 'inspect'), 'incomplete');
  assert.equal(merge('incomplete', 'unknown', 'lock_succeeded'), 'incomplete');
  assert.equal(merge('incomplete', 'complete', 'lock_succeeded'), 'complete');
  assert.equal(merge('complete', 'unknown', 'unlock'), 'unknown');
  assert.equal(merge('complete', 'unknown', 'inspect'), 'unknown');
  assert.equal(merge('unknown', 'complete', 'inspect'), 'unknown');
});
test('warning scope binds account, root token and stable vault identity without aliases', () => {
  const scope = { profileId: 'profile-a', server: 'https://example.test', clientId: 'client', cloudRoot: 'C:\\Synthetic', rootBinding: 'a'.repeat(64), spaceId: 'space', rootResourceId: 'root' };
  const key = model.vaultLockScopeKey(scope);
  assert.ok(key);
  for (const field of Object.keys(scope)) assert.notEqual(model.vaultLockScopeKey({ ...scope, [field]: field === 'rootBinding' ? 'b'.repeat(64) : 'different' }), key);
  assert.equal(model.vaultLockScopeKey({ ...scope, rootBinding: 'a'.repeat(64) + '\n' }), null);
});
test('unknown metadata never says keys cleared; incomplete and key-only locked copy remain distinct', () => {
  assert.match(model.nativeVaultLockMessage('incomplete', false), /may still be accessible/);
  assert.doesNotMatch(model.nativeVaultLockMessage('unknown', false, false), /keys cleared|Locked\./);
  assert.match(model.nativeVaultLockMessage('unknown', false), /Session locked \(keys cleared\)/);
  assert.match(model.nativeVaultLockMessage('unknown', false), /does not confirm.*inaccessible/);
});
