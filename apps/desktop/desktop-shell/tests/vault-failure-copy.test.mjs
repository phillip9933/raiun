import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';

const source = await readFile(new URL('../src/vault-failure-copy.ts', import.meta.url), 'utf8');
const compiled = ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 }
}).outputText;
const { isVaultFailureClass, vaultFailureMessage, vaultEditRetryFailureMessage, vaultEditRetryStatusMessage } = await import(
  `data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`
);

test('known bounded failure classes map to actionable messages without raw server detail', () => {
  for (const category of [
    'transport_unavailable', 'not_found', 'revision_changed',
    'content_mismatch', 'verification_unavailable'
  ]) {
    const message = vaultFailureMessage(category);
    assert.equal(typeof message, 'string');
    assert.match(message, /local copy is retained/i);
    assert.doesNotMatch(message, /https?:|\/|token|secret|password/i);
  }
});

test('unknown values are not displayed as actionable diagnoses', () => {
  assert.equal(isVaultFailureClass('content_mismatch'), true);
  assert.equal(isVaultFailureClass('CloudError: /private/path'), false);
  assert.equal(vaultFailureMessage('server says /Private/path?token=abc'), null);
  assert.equal(vaultFailureMessage({ kind: 'Conflict', message: '/private/path' }), null);
  assert.equal(vaultFailureMessage(null), null);
});

test('encrypted edit retries show only classified offline or authentication guidance', () => {
  assert.match(vaultEditRetryFailureMessage('transport_unavailable'), /connection was lost/i);
  assert.match(vaultEditRetryFailureMessage('authentication_required'), /sign in again/i);
  assert.match(vaultEditRetryFailureMessage('authentication_required'), /saved locally/i);
  for (const value of ['revision_changed', 'server says /private?token=abc', null]) {
    assert.equal(vaultEditRetryFailureMessage(value), null);
  }
  const generic = vaultEditRetryStatusMessage('server says /private?token=abc');
  assert.match(generic, /saved edits remain available/i);
  assert.doesNotMatch(generic, /https?:|\/private|token=abc/i);
});
