export type VaultLockCleanupStatus = 'unknown' | 'incomplete' | 'complete';
export type VaultLockCleanupEvent = 'inspect' | 'lock_failed' | 'lock_succeeded' | 'unlock';

export function vaultLockCleanupStatus(value: unknown): VaultLockCleanupStatus {
  return value === 'incomplete' || value === 'complete' ? value : 'unknown';
}

// Only an explicit successful Lock with its cleanup proof clears a failure.
// Inspecting absent keys, unknown state, or even an unsolicited complete value
// is not proof that local plaintext was removed.
export function mergeVaultLockCleanup(previous: unknown, observed: unknown, event: VaultLockCleanupEvent): VaultLockCleanupStatus {
  const before = vaultLockCleanupStatus(previous);
  const next = vaultLockCleanupStatus(observed);
  if (event === 'lock_failed' || next === 'incomplete') return 'incomplete';
  if (event === 'lock_succeeded' && next === 'complete') return 'complete';
  if (before === 'incomplete') return 'incomplete';
  if (event === 'unlock') return 'unknown';
  return 'unknown';
}

export function vaultLockScopeKey(value: {
  profileId: unknown; server: unknown; clientId: unknown; cloudRoot: unknown;
  rootBinding: unknown; spaceId: unknown; rootResourceId: unknown;
}): string | null {
  const parts = [value.profileId, value.server, value.clientId, value.cloudRoot, value.rootBinding, value.spaceId, value.rootResourceId];
  if (!parts.every(part => typeof part === 'string' && part.length > 0 && part.length <= 32000 && !/[\u0000-\u001f\u007f]/.test(part))) return null;
  if (typeof value.rootBinding !== 'string' || value.rootBinding.length !== 64 || /[^0-9a-f]/.test(value.rootBinding)) return null;
  return JSON.stringify(parts);
}

export function nativeVaultLockMessage(status: unknown, unlocked: boolean, statusKnown = true): string {
  if (vaultLockCleanupStatus(status) === 'incomplete') return 'Lock incomplete. Local files may still be accessible. Close apps using this location, then choose Retry Lock. Raiun has not confirmed local cleanup.';
  if (!statusKnown) return 'Encrypted-location state could not be confirmed. Local cleanup has not been confirmed.';
  if (unlocked) return 'This encrypted location is unlocked for read-only access through the Windows drive.';
  if (vaultLockCleanupStatus(status) === 'complete') return 'Locked. Raiun confirmed local cleanup for this location. Copies already read by other apps are not retracted.';
  return 'Session locked (keys cleared). Local cleanup confirmation is unavailable; this does not confirm that local files are inaccessible.';
}
