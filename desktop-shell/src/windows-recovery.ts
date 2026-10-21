export type WindowsRecoveryRootStatus = {
  valid?: boolean;
  identity_bound?: boolean;
  registration_state?: string | null;
  recovery_scope_token?: unknown;
};

export type WindowsRecoveryAgentStatus = {
  connected?: boolean;
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
  | { available: true; profileId: 'default'; authGeneration: number; recoveryScopeToken: string }
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
  profile_id: 'default';
  auth_generation: number;
  recovery_scope_token: string;
  items: WindowsRecoveryItem[];
  next_after: string | null;
  read_only: true;
};

export type WindowsRecoveryPageExpectation = {
  profileId: 'default';
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
  if (selectedProfileId !== 'default' || status?.profile_id !== 'default') {
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
    profileId: 'default',
    authGeneration: status.auth_generation,
    recoveryScopeToken: root.recovery_scope_token
  };
}

/** Validate one exact `windows_recovery_list` response before rendering it. */
export function validateWindowsRecoveryPage(
  value: unknown,
  expectation: WindowsRecoveryPageExpectation
): WindowsRecoveryPage {
  if (expectation.profileId !== 'default' || !safePositiveInteger(expectation.authGeneration) ||
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
    profile_id: 'default',
    auth_generation: expectation.authGeneration,
    recovery_scope_token: expectation.recoveryScopeToken,
    items,
    next_after: value.next_after,
    read_only: true
  };
}
