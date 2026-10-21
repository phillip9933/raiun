export type VaultDialogFocusState = {
  intent: 'add' | 'manage' | 'browse' | 'create';
  initialized: boolean;
  unlocked: boolean;
  statusUnknown: boolean;
  loading: boolean;
};

export function vaultDialogInitialFocusTarget(state: VaultDialogFocusState): 'password' | 'create-name' | 'dialog' {
  if (state.intent === 'create' && !state.loading) return 'create-name';
  if (state.intent !== 'create' && state.initialized && !state.unlocked && !state.statusUnknown && !state.loading) return 'password';
  return 'dialog';
}

export function vaultDialogTabDestination(activeIndex: number, focusableCount: number, backwards: boolean): number | null {
  if (focusableCount <= 0) return -1;
  if (activeIndex < 0) return backwards ? focusableCount - 1 : 0;
  if (backwards && activeIndex === 0) return focusableCount - 1;
  if (!backwards && activeIndex === focusableCount - 1) return 0;
  return null;
}

export type VaultDialogCloseState = {
  loading: boolean;
  pinBusy: boolean;
  pinJob: unknown;
  editRetryBusy: boolean;
  editRetryJob: { state?: string } | null;
};

export function vaultDialogCloseBlockedMessage(state: VaultDialogCloseState): string {
  if (state.loading) return 'Wait for the encrypted-location operation to finish before closing.';
  if (state.pinBusy || state.pinJob) return 'Wait for encrypted offline-copy work to finish before closing.';
  if (state.editRetryBusy || ['queued', 'running'].includes(state.editRetryJob?.state || '')) {
    return 'Wait for saved encrypted-file edits to finish before closing.';
  }
  return '';
}

export function shouldAnnounceVaultCloseBlocked(previous: string, next: string): boolean {
  return next.length > 0 && previous !== next;
}

export function vaultPasswordErrorAttributes(hasPasswordError: boolean): string {
  return hasPasswordError ? 'aria-describedby="vault-password-error" aria-invalid="true"' : '';
}

export function isVaultPasswordValidationError(message: string): boolean {
  return new Set([
    'vault integrity token did not verify',
    'vault password must not be empty',
    'vault password exceeds the 4096-byte limit',
    'vault password must be valid UTF-8'
  ]).has(message);
}
