export type WindowsRecoveryRootStatus = {
  valid?: boolean;
  identity_bound?: boolean;
  registration_state?: string | null;
  recovery_scope_token?: unknown;
};

export type WindowsRecoveryAgentStatus = {
  connected?: boolean;
  windows_recovery_retry_supported?: unknown;
  windows_recovery_cloud_check_supported?: unknown;
  profile_id?: string | null;
  auth_generation?: unknown;
  root_configuration?: WindowsRecoveryRootStatus | null;
};

export type WindowsRecoveryUnavailableReason =
  | 'agent_unreachable'
  | 'wrong_profile'
  | 'account_disconnected'
  | 'root_unavailable'
  | 'invalid_generation';

export type WindowsRecoveryEligibility =
  | { available: true; profileId: string; authGeneration: number; recoveryScopeToken: string }
  | { available: false; reason: WindowsRecoveryUnavailableReason };

export type WindowsRecoveryItem = {
  record_id: string;
  generation: number;
  space_id: string;
  path: string;
  bytes: number;
  state: 'needs_review';
  has_remote_baseline: boolean;
  retry_requires_review: true;
};

export type WindowsRecoveryPage = {
  profile_id: string;
  auth_generation: number;
  recovery_scope_token: string;
  items: WindowsRecoveryItem[];
  next_after: string | null;
  read_only: true;
};

export type WindowsRecoveryPageExpectation = {
  profileId: string;
  authGeneration: number;
  recoveryScopeToken: string;
  seen?: ReadonlySet<string>;
};

/** The eventual RPC caller must send this exact `limit` with `windows_recovery_list`. */
export const WINDOWS_RECOVERY_PAGE_LIMIT = 50;
const AGENT_PAGE_LIMIT = 100;
const AGENT_CURSOR_BYTE_LIMIT = 16_384;
const SPACE_ID_BYTE_LIMIT = 512;
const RELATIVE_PATH_BYTE_LIMIT = 32 * 1024;
const ITEM_KEYS = [
  'record_id', 'generation', 'space_id', 'path', 'bytes', 'state',
  'has_remote_baseline', 'retry_requires_review'
].sort();
const PAGE_KEYS = ['profile_id', 'auth_generation', 'recovery_scope_token', 'items', 'next_after', 'read_only'].sort();

function validRecoveryScopeToken(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function safePositiveInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
}

function safeNonnegativeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function utf8Length(value: string): number {
  return new TextEncoder().encode(value).length;
}

function hasWellFormedSurrogates(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function validSpaceId(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && hasWellFormedSurrogates(value) &&
    utf8Length(value) <= SPACE_ID_BYTE_LIMIT && !/[\u0000-\u001f\u007f-\u009f]/u.test(value);
}

function validRelativePath(value: unknown): value is string {
  if (typeof value !== 'string' || !value || !hasWellFormedSurrogates(value) ||
      utf8Length(value) > RELATIVE_PATH_BYTE_LIMIT || value.startsWith('/') ||
      value.endsWith('/') || value.includes('\\') || /[\u0000-\u001f\u007f-\u009f]/u.test(value)) {
    return false;
  }
  return value.split('/').every(component => component.length > 0 && component !== '.' && component !== '..');
}

function itemKey(recordId: string, generation: number): string {
  return `${recordId}:${generation}`;
}

export function validWindowsProfileId(value: unknown): value is string {
  return typeof value === 'string' && (value === 'default' || (value.length === 40 && /^profile-[0-9a-f]{32}$/.test(value)));
}

/**
 * Keep Windows recovery discovery available as a separate read-only capability;
 * provider_supported remains false while the normal Cloud Files provider is off.
 */
export function windowsRecoveryEligibility(
  agentReachable: boolean,
  selectedProfileId: string | null,
  status: WindowsRecoveryAgentStatus | null
): WindowsRecoveryEligibility {
  if (!agentReachable) return { available: false, reason: 'agent_unreachable' };
  if (!validWindowsProfileId(selectedProfileId) || status?.profile_id !== selectedProfileId) {
    return { available: false, reason: 'wrong_profile' };
  }
  if (status.connected !== true) return { available: false, reason: 'account_disconnected' };
  const root = status.root_configuration;
  if (!root || root.valid !== true || root.identity_bound !== true || root.registration_state !== 'registered') {
    return { available: false, reason: 'root_unavailable' };
  }
  if (typeof root.recovery_scope_token !== 'string' || !/^[0-9a-f]{64}$/.test(root.recovery_scope_token)) {
    return { available: false, reason: 'root_unavailable' };
  }
  if (!safePositiveInteger(status.auth_generation)) return { available: false, reason: 'invalid_generation' };
  return {
    available: true,
    profileId: selectedProfileId,
    authGeneration: status.auth_generation,
    recoveryScopeToken: root.recovery_scope_token
  };
}

/** Validate one exact `windows_recovery_list` response before rendering it. */
export function validateWindowsRecoveryPage(
  value: unknown,
  expectation: WindowsRecoveryPageExpectation
): WindowsRecoveryPage {
  if (!validWindowsProfileId(expectation.profileId) || !safePositiveInteger(expectation.authGeneration) ||
      !validRecoveryScopeToken(expectation.recoveryScopeToken) ||
      WINDOWS_RECOVERY_PAGE_LIMIT > AGENT_PAGE_LIMIT) {
    throw new Error('Windows recovery request context is invalid.');
  }
  if (!isRecord(value) || !hasExactKeys(value, PAGE_KEYS) || value.profile_id !== expectation.profileId ||
      value.auth_generation !== expectation.authGeneration || value.recovery_scope_token !== expectation.recoveryScopeToken ||
      value.read_only !== true ||
      !Array.isArray(value.items) || value.items.length > WINDOWS_RECOVERY_PAGE_LIMIT ||
      value.items.length > AGENT_PAGE_LIMIT) {
    throw new Error('The agent returned an invalid or stale Windows recovery page.');
  }
  if (!(value.next_after === null || (typeof value.next_after === 'string' && value.next_after.length > 0 &&
      hasWellFormedSurrogates(value.next_after) && utf8Length(value.next_after) <= AGENT_CURSOR_BYTE_LIMIT))) {
    throw new Error('The agent returned an invalid Windows recovery cursor.');
  }
  if (value.next_after !== null && value.items.length === 0) {
    throw new Error('The agent returned a Windows recovery cursor without any listed items.');
  }

  const seen = new Set(expectation.seen || []);
  const items: WindowsRecoveryItem[] = [];
  for (const item of value.items) {
    if (!isRecord(item) || !hasExactKeys(item, ITEM_KEYS) ||
        typeof item.record_id !== 'string' || item.record_id.length < 1 || item.record_id.length > 128 ||
        !/^[0-9a-fA-F]+$/.test(item.record_id) || !safePositiveInteger(item.generation) ||
        !validSpaceId(item.space_id) || !validRelativePath(item.path) ||
        !safeNonnegativeInteger(item.bytes) || item.state !== 'needs_review' ||
        typeof item.has_remote_baseline !== 'boolean' || item.retry_requires_review !== true) {
      throw new Error('The agent returned an invalid Windows recovery item.');
    }
    const key = itemKey(item.record_id, item.generation);
    if (seen.has(key)) throw new Error('The agent returned a duplicate Windows recovery item.');
    seen.add(key);
    items.push({
      record_id: item.record_id,
      generation: item.generation,
      space_id: item.space_id,
      path: item.path,
      bytes: item.bytes,
      state: 'needs_review',
      has_remote_baseline: item.has_remote_baseline,
      retry_requires_review: true
    });
  }
  return {
    profile_id: expectation.profileId,
    auth_generation: expectation.authGeneration,
    recovery_scope_token: expectation.recoveryScopeToken,
    items,
    next_after: value.next_after,
    read_only: true
  };
}

export type WindowsRecoveryRetryResult = {
  profile_id: string;
  auth_generation: number;
  recovery_scope_token: string;
  state: 'verified_applied' | 'conflict' | 'outcome_unknown' | 'not_completed';
  retained: true;
  remote_verified: boolean;
  local_completion: 'completed' | 'uncertain' | 'unavailable';
  attempts?: number;
  reason?: string;
};

const RETRY_REASONS = new Set([
  'invalid_record', 'scope_mismatch', 'missing_baseline', 'remote_missing',
  'remote_changed', 'remote_not_writable', 'content_mismatch', 'response_inconsistent'
]);

export function validateWindowsRecoveryRetryResult(
  value: unknown, expectation: WindowsRecoveryPageExpectation
): WindowsRecoveryRetryResult {
  const keys = ['profile_id', 'auth_generation', 'recovery_scope_token', 'state',
    'retained', 'remote_verified', 'local_completion'];
  if (isRecord(value) && value.state === 'verified_applied') keys.push('attempts');
  if (isRecord(value) && value.state === 'conflict') keys.push('reason');
  if (!isRecord(value) || !hasExactKeys(value, keys.sort()) ||
      !validWindowsProfileId(expectation.profileId) || !safePositiveInteger(expectation.authGeneration) ||
      !validRecoveryScopeToken(expectation.recoveryScopeToken) ||
      value.profile_id !== expectation.profileId || value.auth_generation !== expectation.authGeneration ||
      value.recovery_scope_token !== expectation.recoveryScopeToken || value.retained !== true ||
      typeof value.remote_verified !== 'boolean' ||
      (typeof value.local_completion !== 'string' || !['completed', 'uncertain', 'unavailable'].includes(value.local_completion)) ||
      (typeof value.state !== 'string' || !['verified_applied', 'conflict', 'outcome_unknown', 'not_completed'].includes(value.state)) ||
      (value.state === 'verified_applied' && (!safePositiveInteger(value.attempts) || value.attempts > 255)) ||
      (value.state === 'conflict' && (typeof value.reason !== 'string' || !RETRY_REASONS.has(value.reason))) ||
      (value.remote_verified && value.state !== 'verified_applied') ||
      (value.local_completion !== 'unavailable' && (!value.remote_verified || value.state !== 'verified_applied'))) {
    throw new Error('The agent returned an invalid or stale saved-edit retry result.');
  }
  return { ...value } as WindowsRecoveryRetryResult;
}

export function windowsRecoveryRetryMessage(result: WindowsRecoveryRetryResult): string {
  if (result.state === 'verified_applied' && result.remote_verified) {
    return result.local_completion === 'completed'
      ? 'Cloud save verified and local completion confirmed. The original recovery record is retained.'
      : 'Cloud save verified. Local completion is not confirmed; the original recovery record is retained.';
  }
  if (result.state === 'conflict') {
    return 'Retry refused because the saved edit or cloud baseline needs review. The original saved edit is retained.';
  }
  return 'Cloud save is not confirmed. The original saved edit is retained; review it before trying again.';
}

export type WindowsRecoveryCloudCheckResult = {
  profile_id: string;
  auth_generation: number;
  recovery_scope_token: string;
  record_id: string;
  generation: number;
  result: 'matched' | 'missing' | 'different' | 'unavailable';
  bytes: number | null;
  read_only: true;
  cloud_mutated: false;
  local_completion: 'unchanged';
  original_snapshot_retained: true;
};

export function validateWindowsRecoveryCloudCheckResult(
  value: unknown,
  expectation: WindowsRecoveryPageExpectation & { recordId: string; generation: number; bytes: number }
): WindowsRecoveryCloudCheckResult {
  const keys = ['profile_id', 'auth_generation', 'recovery_scope_token', 'record_id', 'generation',
    'result', 'bytes', 'read_only', 'cloud_mutated', 'local_completion', 'original_snapshot_retained'].sort();
  if (!validWindowsProfileId(expectation.profileId) || !safePositiveInteger(expectation.authGeneration) ||
      !validRecoveryScopeToken(expectation.recoveryScopeToken) ||
      !/^[0-9a-fA-F]{1,128}$/.test(expectation.recordId) || !safePositiveInteger(expectation.generation) ||
      !safeNonnegativeInteger(expectation.bytes) || expectation.bytes > 2 ** 40 ||
      !isRecord(value) || !hasExactKeys(value, keys) || value.profile_id !== expectation.profileId ||
      value.auth_generation !== expectation.authGeneration || value.recovery_scope_token !== expectation.recoveryScopeToken ||
      value.record_id !== expectation.recordId || value.generation !== expectation.generation ||
      !['matched', 'missing', 'different', 'unavailable'].includes(value.result as string) ||
      value.read_only !== true || value.cloud_mutated !== false || value.local_completion !== 'unchanged' ||
      value.original_snapshot_retained !== true ||
      (value.result === 'matched' ? value.bytes !== expectation.bytes : value.bytes !== null)) {
    throw new Error('The cloud-copy check could not be confirmed. Refresh saved edits and try again.');
  }
  return { ...value } as WindowsRecoveryCloudCheckResult;
}

export function windowsRecoveryCloudCheckMessage(result: WindowsRecoveryCloudCheckResult): string {
  const retained = 'Your saved copy is kept and Windows sync status is unchanged.';
  switch (result.result) {
    case 'matched': return `The cloud file matches your saved copy. ${retained}`;
    case 'missing': return `The cloud file was not found. ${retained}`;
    case 'different': return `The cloud file differs from your saved copy. ${retained}`;
    case 'unavailable': return `The cloud copy could not be checked. ${retained}`;
  }
}
