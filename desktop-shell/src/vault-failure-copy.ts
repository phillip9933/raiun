export type VaultFailureClass =
  | 'transport_unavailable'
  | 'authentication_required'
  | 'not_found'
  | 'revision_changed'
  | 'content_mismatch'
  | 'verification_unavailable';

const classes = new Set<VaultFailureClass>([
  'transport_unavailable', 'authentication_required', 'not_found', 'revision_changed',
  'content_mismatch', 'verification_unavailable'
]);

const messages: Record<VaultFailureClass, string> = {
  transport_unavailable: 'Connection was lost before the server could confirm this create. The local copy is retained; retry when connected.',
  authentication_required: 'Sign in again before retrying. The local copy is retained.',
  not_found: 'The cloud copy was not found during verification. The local copy is retained; check the destination before retrying.',
  revision_changed: 'The destination changed during verification. The local copy is retained; review it before retrying.',
  content_mismatch: 'The server copy did not match the local file. The local copy is retained; resolve this before retrying.',
  verification_unavailable: 'Raiun could not verify the server copy. The local copy is retained; check the destination before retrying.'
};

const editRetryMessages: Partial<Record<VaultFailureClass, string>> = {
  transport_unavailable: 'The connection was lost before the server could confirm these edits. They remain saved locally; retry when connected.',
  authentication_required: 'Sign in again before retrying these edits. They remain saved locally.'
};

export function vaultFailureMessage(value: unknown): string | null {
  if (!isVaultFailureClass(value)) return null;
  return messages[value as VaultFailureClass];
}

export function vaultEditRetryFailureMessage(value: unknown): string | null {
  if (!isVaultFailureClass(value)) return null;
  return editRetryMessages[value] ?? null;
}

export function vaultEditRetryStatusMessage(value: unknown): string {
  return vaultEditRetryFailureMessage(value) ??
    'The retry stopped before confirmation. Saved edits remain available; check the connection and account before retrying.';
}

export function isVaultFailureClass(value: unknown): value is VaultFailureClass {
  return typeof value === 'string' && classes.has(value as VaultFailureClass);
}
