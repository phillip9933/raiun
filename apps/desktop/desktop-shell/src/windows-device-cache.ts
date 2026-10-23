import { validWindowsProfileId } from './windows-recovery';

export type WindowsDeviceCacheExpectation = {
  profileId: string;
  authGeneration: number;
  recoveryScopeToken: string;
};
export type WindowsDeviceCacheUsage = {
  profile_id: string;
  auth_generation: number;
  recovery_scope_token: string;
  scope: 'device_all_accounts';
  read_only: true;
  last_observed: true;
  atomic_snapshot: false;
  quota_bytes: number;
  used_bytes: number;
  pinned_bytes: number;
  protected_bytes: number;
  over_quota: boolean;
};

/** Device-wide counts, authorized through this exact current account/drive only. */
export function validateWindowsDeviceCacheUsage(value: unknown, expected: WindowsDeviceCacheExpectation): WindowsDeviceCacheUsage {
  const fail = () => { throw new Error('The agent returned invalid or stale device cache usage.'); };
  if (!validWindowsProfileId(expected.profileId) || !Number.isSafeInteger(expected.authGeneration) || expected.authGeneration <= 0 ||
      typeof expected.recoveryScopeToken !== 'string' || expected.recoveryScopeToken.length !== 64 || !/^[0-9a-f]{64}$/.test(expected.recoveryScopeToken)) return fail();
  if (!value || typeof value !== 'object' || Array.isArray(value)) return fail();
  const row = value as Record<string, unknown>;
  const keys = ['profile_id', 'auth_generation', 'recovery_scope_token', 'scope', 'read_only', 'last_observed', 'atomic_snapshot', 'quota_bytes', 'used_bytes', 'pinned_bytes', 'protected_bytes', 'over_quota'].sort();
  if (Object.keys(row).sort().join('\0') !== keys.join('\0') || row.profile_id !== expected.profileId ||
      row.auth_generation !== expected.authGeneration || row.recovery_scope_token !== expected.recoveryScopeToken ||
      row.scope !== 'device_all_accounts' || row.read_only !== true || row.last_observed !== true || row.atomic_snapshot !== false ||
      typeof row.over_quota !== 'boolean') return fail();
  for (const key of ['quota_bytes', 'used_bytes', 'pinned_bytes', 'protected_bytes']) {
    if (!Number.isSafeInteger(row[key]) || (row[key] as number) < 0) return fail();
  }
  return { ...row } as WindowsDeviceCacheUsage;
}
