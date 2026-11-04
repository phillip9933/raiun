export const MIN_CACHE_LIMIT = 256 * 1024 ** 2;
export const MAX_CACHE_LIMIT = 1024 ** 4;
export type CacheLimitUnit = 'MiB' | 'GiB';
export function parseCacheLimit(amount: string, unit: string): number {
  if (!/^\d+(?:\.\d{1,3})?$/.test(amount.trim()) || !['MiB', 'GiB'].includes(unit)) throw new Error('Enter an amount in MiB or GiB.');
  const bytes = Number(amount) * (unit === 'GiB' ? 1024 ** 3 : 1024 ** 2);
  if (!Number.isSafeInteger(bytes) || bytes < MIN_CACHE_LIMIT || bytes > MAX_CACHE_LIMIT) throw new Error('Choose a limit between 256 MiB and 1 TiB.');
  return bytes;
}
export function cacheLimitDraft(bytes: number): { amount: string; unit: CacheLimitUnit } {
  const unit = bytes % (1024 ** 3) === 0 ? 'GiB' : 'MiB';
  return { amount: String(bytes / (unit === 'GiB' ? 1024 ** 3 : 1024 ** 2)), unit };
}
export function formatStorageBytes(bytes: number): string {
  if (!Number.isSafeInteger(bytes) || bytes < 0) return 'Not available';
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let value = bytes / 1024, index = 0;
  while (value >= 1024 && index < units.length - 1) { value /= 1024; index++; }
  return `${value.toFixed(value >= 10 ? 0 : 1)} ${units[index]}`;
}
export function validateCacheLimitReply(value: unknown, expected: { profileId: string; generation: number; windows: boolean; token?: string }, bytes: number): void {
  const v = value as Record<string, unknown> | null;
  if (!v || v.saved !== true || v.eviction_performed !== false || v.profile_id !== expected.profileId || v.auth_generation !== expected.generation || v.quota_bytes !== bytes || v.scope !== (expected.windows ? 'device_all_accounts' : 'account') || (expected.windows && v.recovery_scope_token !== expected.token)) throw new Error('Could not confirm the saved limit. Refresh storage before trying again.');
}
