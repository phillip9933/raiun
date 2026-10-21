import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';

const source = await readFile(new URL('../src/vault-dialog-accessibility.ts', import.meta.url), 'utf8');
const compiled = ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 }
}).outputText;
const { vaultDialogInitialFocusTarget, vaultDialogTabDestination, vaultDialogCloseBlockedMessage, shouldAnnounceVaultCloseBlocked, vaultPasswordErrorAttributes, isVaultPasswordValidationError } = await import(
  `data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`
);

test('locked vault focuses password after inspection, while loading remains on the dialog', () => {
  assert.equal(vaultDialogInitialFocusTarget({ intent: 'browse', initialized: false, unlocked: false, statusUnknown: false, loading: true }), 'dialog');
  assert.equal(vaultDialogInitialFocusTarget({ intent: 'browse', initialized: true, unlocked: false, statusUnknown: false, loading: false }), 'password');
  assert.equal(vaultDialogInitialFocusTarget({ intent: 'browse', initialized: true, unlocked: false, statusUnknown: true, loading: false }), 'dialog');
  assert.equal(vaultDialogInitialFocusTarget({ intent: 'create', initialized: false, unlocked: false, statusUnknown: false, loading: false }), 'create-name');
});

test('vault dialog traps Tab only at the focusable boundaries', () => {
  assert.equal(vaultDialogTabDestination(0, 4, true), 3);
  assert.equal(vaultDialogTabDestination(3, 4, false), 0);
  assert.equal(vaultDialogTabDestination(1, 4, true), null);
  assert.equal(vaultDialogTabDestination(2, 4, false), null);
  assert.equal(vaultDialogTabDestination(-1, 4, false), 0);
  assert.equal(vaultDialogTabDestination(-1, 4, true), 3);
  assert.equal(vaultDialogTabDestination(-1, 0, false), -1);
});

test('close-block announcements explain active work once until the work state changes', () => {
  const loading = { loading: true, pinBusy: false, pinJob: null, editRetryBusy: false, editRetryJob: null };
  const message = vaultDialogCloseBlockedMessage(loading);
  assert.match(message, /operation to finish before closing/i);
  assert.equal(shouldAnnounceVaultCloseBlocked('', message), true);
  assert.equal(shouldAnnounceVaultCloseBlocked(message, message), false);
  assert.equal(vaultDialogCloseBlockedMessage({ ...loading, loading: false, pinJob: { state: 'running' } }), 'Wait for encrypted offline-copy work to finish before closing.');
  assert.equal(vaultDialogCloseBlockedMessage({ ...loading, loading: false, editRetryJob: { state: 'queued' } }), 'Wait for saved encrypted-file edits to finish before closing.');
  assert.equal(vaultDialogCloseBlockedMessage({ ...loading, loading: false }), '');
});

test('password error relationship is emitted only for an active password error', () => {
  assert.equal(vaultPasswordErrorAttributes(true), 'aria-describedby="vault-password-error" aria-invalid="true"');
  assert.equal(vaultPasswordErrorAttributes(false), '');
  assert.equal(isVaultPasswordValidationError('vault integrity token did not verify'), true);
  assert.equal(isVaultPasswordValidationError('vault password exceeds the 4096-byte limit'), true);
  assert.equal(isVaultPasswordValidationError('connection reset by peer'), false);
  assert.equal(isVaultPasswordValidationError('server rejected the request'), false);
});

test('vault dialog exposes live unlock state and Verify copy announces success without alert urgency', async () => {
  const main = await readFile(new URL('../src/main.ts', import.meta.url), 'utf8');
  assert.match(main, /class="vault-state[^\"]*" role="status" aria-live="polite" aria-atomic="true"/);
  assert.match(main, /copyJob\.status\.state === 'needs_review' \|\| copyJob\.status\.state === 'failed' \? 'alert' : 'status'/);
  assert.match(main, /role="dialog" aria-modal="true" aria-labelledby="vault-title" tabindex="-1"/);
  assert.match(main, /restoreVaultDialogFocus\(\)/);
  assert.match(main, /\.vault-modal'\)\?\.addEventListener\('keydown'/);
  assert.match(main, /event\.key === 'Enter' && !event\.isComposing/);
  assert.match(main, /data-action="verify-copy-operation"/);
  assert.match(main, /data-copy-verify-live/);
});
