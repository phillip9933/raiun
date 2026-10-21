import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';

const source = await readFile(new URL('../src/windows-recovery.ts', import.meta.url), 'utf8');
const compiled = ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 }
}).outputText;
const { validateWindowsRecoveryPage, windowsRecoveryEligibility, WINDOWS_RECOVERY_PAGE_LIMIT } = await import(
  `data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`
);

const status = {
  profile_id: 'default',
  connected: true,
  auth_generation: 7,
  provider_supported: false,
  root_configuration: { valid: true, identity_bound: true, registration_state: 'registered', recovery_scope_token: 'b'.repeat(64) }
};
const item = {
  record_id: 'a'.repeat(32),
  generation: 9,
  space_id: 'space-1',
  path: 'Personal/docs/notes.txt',
  bytes: 17,
  state: 'needs_review',
  has_remote_baseline: true,
  retry_requires_review: true
};
const page = (items = [item], overrides = {}) => ({
  profile_id: 'default',
  auth_generation: 7,
  recovery_scope_token: 'b'.repeat(64),
  items,
  next_after: null,
  read_only: true,
  ...overrides
});
const expectation = { profileId: 'default', authGeneration: 7, recoveryScopeToken: 'b'.repeat(64) };

test('recovery eligibility is separate from the disabled Windows provider capability', () => {
  assert.deepEqual(windowsRecoveryEligibility(true, 'default', status), {
    available: true,
    profileId: 'default',
    authGeneration: 7,
    recoveryScopeToken: 'b'.repeat(64)
  });
});

test('unavailable recovery context is explicit and never converted into an empty page', () => {
  assert.deepEqual(windowsRecoveryEligibility(false, 'default', status), {
    available: false, reason: 'agent_unreachable'
  });
  assert.deepEqual(windowsRecoveryEligibility(true, 'other', status), {
    available: false, reason: 'wrong_profile'
  });
  assert.deepEqual(windowsRecoveryEligibility(true, 'default', { ...status, connected: false }), {
    available: false, reason: 'account_disconnected'
  });
  assert.deepEqual(windowsRecoveryEligibility(true, 'default', {
    ...status, root_configuration: { valid: true, identity_bound: true, registration_state: 'prepared_not_registered' }
  }), { available: false, reason: 'root_unavailable' });
  assert.deepEqual(windowsRecoveryEligibility(true, 'default', { ...status, auth_generation: 0 }), {
    available: false, reason: 'invalid_generation'
  });
  for (const token of [undefined, 'a'.repeat(63), 'A'.repeat(64), 'g'.repeat(64)]) {
    assert.deepEqual(windowsRecoveryEligibility(true, 'default', {
      ...status,
      root_configuration: { ...status.root_configuration, recovery_scope_token: token }
    }), { available: false, reason: 'root_unavailable' });
  }
});

test('valid read-only pages preserve the Windows recovery contract', () => {
  assert.deepEqual(validateWindowsRecoveryPage(page(), expectation), {
    profile_id: 'default',
    auth_generation: 7,
    recovery_scope_token: 'b'.repeat(64),
    items: [item],
    next_after: null,
    read_only: true
  });
  assert.deepEqual(validateWindowsRecoveryPage(page([], { next_after: null }), expectation).items, []);
});

test('rejects stale, wrong-profile, mutable, extra-field, and oversized page responses', () => {
  for (const candidate of [
    page([item], { auth_generation: 8 }),
    page([item], { recovery_scope_token: 'c'.repeat(64) }),
    page([item], { profile_id: 'other' }),
    page([item], { read_only: false }),
    { ...page(), unexpected: true },
    page(Array.from({ length: 51 }, (_, index) => ({ ...item, record_id: index.toString(16).padStart(32, '0') })))
  ]) {
    assert.throws(() => validateWindowsRecoveryPage(candidate, expectation));
  }
  assert.throws(() => validateWindowsRecoveryPage(
    Object.fromEntries(Object.entries(page()).filter(([key]) => key !== 'recovery_scope_token')),
    expectation
  ));
  assert.throws(() => validateWindowsRecoveryPage(page([item], { next_after: 'x'.repeat(16_385) }), expectation));
  assert.throws(() => validateWindowsRecoveryPage(page([], { next_after: 'cursor' }), expectation));
});

test('rejects malformed item fields, unsafe integers, and duplicate record revisions', () => {
  const invalidItems = [
    { ...item, record_id: 'g'.repeat(32) },
    { ...item, record_id: 'a'.repeat(129) },
    { ...item, generation: Number.MAX_SAFE_INTEGER + 1 },
    { ...item, generation: 0 },
    { ...item, bytes: Number.MAX_SAFE_INTEGER + 1 },
    { ...item, bytes: -1 },
    { ...item, state: 'uploaded' },
    { ...item, retry_requires_review: false },
    { ...item, has_remote_baseline: 1 },
    { ...item, path: '/absolute.txt' },
    { ...item, path: 'a/../secret.txt' },
    { ...item, path: 'a\\secret.txt' },
    { ...item, path: 'a//secret.txt' },
    { ...item, path: `a/${'é'.repeat(16_384)}` },
    { ...item, path: `a/\u0001secret.txt` },
    { ...item, extra: 'not in the agent contract' }
  ];
  for (const candidate of invalidItems) {
    assert.throws(() => validateWindowsRecoveryPage(page([candidate]), expectation));
  }
  assert.throws(() => validateWindowsRecoveryPage(page([item, { ...item }]), expectation));
  assert.throws(() => validateWindowsRecoveryPage(page([item]), { ...expectation, seen: new Set([`${item.record_id}:${item.generation}`]) }));
});

test('fixes the page request bound at 50 and rejects a space ID over the journal byte limit', () => {
  assert.equal(WINDOWS_RECOVERY_PAGE_LIMIT, 50);
  assert.throws(() => validateWindowsRecoveryPage(page(Array.from({ length: WINDOWS_RECOVERY_PAGE_LIMIT + 1 }, (_, index) => ({
    ...item, record_id: index.toString(16).padStart(32, '0')
  }))), expectation));
  assert.doesNotThrow(() => validateWindowsRecoveryPage(page([{ ...item, space_id: 'é'.repeat(256) }]), expectation));
  assert.throws(() => validateWindowsRecoveryPage(page([{ ...item, space_id: 'é'.repeat(257) }]), expectation));
});

test('rejects unsafe auth generations', () => {
  assert.throws(() => validateWindowsRecoveryPage(page(), { ...expectation, authGeneration: Number.MAX_SAFE_INTEGER + 1 }));
});
