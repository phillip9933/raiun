import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';

const recoverySource = await readFile(new URL('../src/windows-recovery.ts', import.meta.url), 'utf8');
const recoveryUrl = `data:text/javascript;base64,${Buffer.from(ts.transpileModule(recoverySource, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } }).outputText).toString('base64')}`;
const source = await readFile(new URL('../src/windows-offline-file.ts', import.meta.url), 'utf8');
const compiled = ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 }
}).outputText.replace("from './windows-recovery'", `from '${recoveryUrl}'`);
const {
  WindowsOfflineFileController,
  windowsOfflineFileContextKey,
  validateWindowsFileCacheStatus,
  validateWindowsOfflineJobStatus,
  windowsOfflineJobMessage
} = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`);

const context = (changes = {}) => ({
  profileId: 'default',
  accountEpoch: 4,
  authGeneration: 7,
  recoveryScopeToken: 'b'.repeat(64),
  flowGeneration: 2,
  server: 'https://cloud.example',
  clientId: 'synthetic-client',
  cloudRoot: 'C:\\Raiun',
  ...changes
});
const row = (changes = {}) => ({
  spaceId: 'space-personal',
  rootResourceId: 'root-personal',
  path: '/Documents/example.txt',
  resourceId: 'file-123',
  etag: '"version-4"',
  size: 8192,
  ...changes
});
const cacheStatus = (changes = {}) => ({
  profile_id: 'default',
  auth_generation: 7,
  recovery_scope_token: 'b'.repeat(64),
  read_only: true,
  last_observed: true,
  atomic_snapshot: false,
  policy: 'recent',
  recorded_complete_version: true,
  recorded_bytes: 8192,
  pending_offline_intent: false,
  ...changes
});
const job = (changes = {}) => ({
  job_id: 'a'.repeat(32),
  state: 'running',
  cancel_requested: false,
  recovery_required: false,
  ...changes
});
function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

test('cache status accepts only the exact read-only metadata snapshot for the current context', () => {
  assert.deepEqual(validateWindowsFileCacheStatus(cacheStatus(), context()), cacheStatus());
  assert.equal(validateWindowsFileCacheStatus(cacheStatus({ pending_offline_intent: true }), context()).pending_offline_intent, true);
  for (const invalid of [
    cacheStatus({ auth_generation: 8 }),
    cacheStatus({ recovery_scope_token: 'c'.repeat(64) }),
    cacheStatus({ atomic_snapshot: true }),
    cacheStatus({ read_only: false }),
    cacheStatus({ recorded_bytes: Number.MAX_SAFE_INTEGER + 1 }),
    { ...cacheStatus(), pending_offline_intent: 'true' },
    Object.fromEntries(Object.entries(cacheStatus()).filter(([key]) => key !== 'pending_offline_intent')),
    { ...cacheStatus(), unrecognized: 'field' }
  ]) assert.throws(() => validateWindowsFileCacheStatus(invalid, context()));
  assert.throws(() => validateWindowsFileCacheStatus(cacheStatus(), context({ authGeneration: -1 })));
});

test('selection key binds account, root scope, generation, flow and the full listed file version', () => {
  const base = windowsOfflineFileContextKey(context(), row());
  for (const [nextContext, nextRow] of [
    [context({ accountEpoch: 5 }), row()],
    [context({ authGeneration: 8 }), row()],
    [context({ recoveryScopeToken: 'c'.repeat(64) }), row()],
    [context({ flowGeneration: 3 }), row()],
    [context({ cloudRoot: 'D:\\Raiun' }), row()],
    [context(), row({ spaceId: 'space-other' })],
    [context(), row({ rootResourceId: 'root-other' })],
    [context(), row({ path: '/Documents/other.txt' })],
    [context(), row({ resourceId: 'file-other' })],
    [context(), row({ etag: '"version-5"' })],
    [context(), row({ size: 8193 })]
  ]) assert.notEqual(windowsOfflineFileContextKey(nextContext, nextRow), base);
  for (const invalid of [
    row({ path: '/Documents/../private.txt' }),
    row({ path: '/Documents//example.txt' }),
    row({ path: '/Documents\\example.txt' }),
    row({ size: Number.MAX_SAFE_INTEGER + 1 }),
    row({ etag: '' })
  ]) assert.throws(() => windowsOfflineFileContextKey(context(), invalid));
});

test('job status retains recovery-required state and rejects inconsistent or unknown fields', () => {
  const recovery = job({ state: 'recovery_required', recovery_required: true });
  assert.deepEqual(validateWindowsOfflineJobStatus(recovery), recovery);
  assert.match(windowsOfflineJobMessage(recovery), /needs recovery/i);
  assert.match(windowsOfflineJobMessage(job({ state: 'complete' })), /saved for offline use/i);
  for (const invalid of [
    job({ job_id: 'A'.repeat(32) }),
    job({ state: 'queued' }),
    job({ state: 'recovery_required' }),
    job({ state: 'failed', recovery_required: true }),
    { ...job(), path: '/secret' }
  ]) assert.throws(() => validateWindowsOfflineJobStatus(invalid));
});

test('controller sends the existing cache-status and start request fields and polls/cancels the exact job', async () => {
  const controller = new WindowsOfflineFileController();
  const calls = [];
  const request = async (action, args) => {
    calls.push({ action, args });
    if (action === 'windows_file_cache_status') return cacheStatus();
    if (action === 'windows_offline_file_start') return job();
    if (action === 'windows_offline_file_cancel') return job({ cancel_requested: true });
    return job({ state: 'complete' });
  };
  await controller.loadCacheStatus(context(), row(), request, () => true);
  assert.deepEqual(calls[0], {
    action: 'windows_file_cache_status',
    args: {
      profile_id: 'default', expected_generation: 7, expected_recovery_scope_token: 'b'.repeat(64),
      space_id: 'space-personal', root_resource_id: 'root-personal', path: '/Documents/example.txt',
      resource_id: 'file-123', etag: '"version-4"', size: 8192
    }
  });
  await controller.start(context(), row(), request, () => true);
  assert.equal(calls[1].action, 'windows_offline_file_start');
  assert.equal(calls[1].args.job_id, undefined);
  assert.equal(controller.state.job.job_id, 'a'.repeat(32));
  await controller.pollStatus(context(), row(), request, () => true);
  assert.deepEqual(calls[2], {
    action: 'windows_offline_file_status',
    args: {
      profile_id: 'default', expected_generation: 7,
      expected_recovery_scope_token: 'b'.repeat(64), job_id: 'a'.repeat(32)
    }
  });
  assert.equal(controller.state.job.state, 'complete');
  await controller.cancel(context(), row(), request, () => true);
  assert.equal(calls[3].action, 'windows_offline_file_cancel');
  assert.equal(calls[3].args.job_id, 'a'.repeat(32));
});

test('late file-status response is discarded after the selected version changes', async () => {
  const controller = new WindowsOfflineFileController();
  const pending = deferred();
  const loading = controller.loadCacheStatus(context(), row(), () => pending.promise, () => true);
  controller.setSelection(context(), row({ etag: '"version-5"' }));
  pending.resolve(cacheStatus());
  await loading;
  assert.equal(controller.state.cacheStatus, null);
  assert.equal(controller.state.loading, false);
});

test('external context change fences a response and clears the selection', async () => {
  const controller = new WindowsOfflineFileController();
  const pending = deferred();
  let current = true;
  const loading = controller.loadCacheStatus(context(), row(), () => pending.promise, () => current);
  current = false;
  pending.resolve(cacheStatus());
  await loading;
  assert.equal(controller.state.cacheStatus, null);
  assert.equal(controller.state.loading, false);
  assert.equal(controller.state.error, '');
});

test('ambiguous start failure is reported and cannot submit a duplicate for the same selection', async () => {
  const controller = new WindowsOfflineFileController();
  let calls = 0;
  await controller.start(context(), row(), async () => {
    calls += 1;
    throw new Error('pipe closed');
  }, () => true);
  assert.equal(controller.state.admissionUncertain, true);
  assert.match(controller.state.error, /may have started/i);
  await controller.start(context(), row(), async () => { calls += 1; return job(); }, () => true);
  assert.equal(calls, 1);
  assert.equal(controller.state.admissionUncertain, true);
  controller.setSelection(context({ flowGeneration: 3 }), row());
  assert.equal(controller.state.admissionUncertain, false);
  assert.equal(controller.state.job, null);
});

test('recovery-required result is not downgraded by stale polling or a failed refresh', async () => {
  const controller = new WindowsOfflineFileController();
  const recovery = job({ state: 'recovery_required', recovery_required: true });
  await controller.start(context(), row(), async () => recovery, () => true);
  const pending = deferred();
  const refresh = controller.pollStatus(context(), row(), () => pending.promise, () => true);
  pending.reject(new Error('temporary pipe error'));
  await refresh;
  assert.deepEqual(controller.state.job, recovery);
  assert.match(controller.state.error, /temporary pipe error/);
  assert.match(windowsOfflineJobMessage(controller.state.job), /needs recovery/i);
});

test('same-selection inspection does not overlap an active request', async () => {
  const controller = new WindowsOfflineFileController();
  const pending = deferred();
  let calls = 0;
  const first = controller.loadCacheStatus(context(), row(), async () => {
    calls += 1;
    return pending.promise;
  }, () => true);
  await controller.loadCacheStatus(context(), row(), async () => {
    calls += 1;
    return cacheStatus({ policy: 'always_offline' });
  }, () => true);
  assert.equal(calls, 1);
  pending.resolve(cacheStatus());
  await first;
  assert.equal(controller.state.cacheStatus.policy, 'recent');
  assert.equal(controller.state.error, '');
  assert.equal(controller.state.loading, false);
});

test('poll and cancel during a pending start do not supersede or discard its admitted job', async () => {
  const controller = new WindowsOfflineFileController();
  const pendingStart = deferred();
  const calls = [];
  const startRequest = async (action, args) => {
    calls.push({ action, args });
    return pendingStart.promise;
  };
  const starting = controller.start(context(), row(), startRequest, () => true);
  assert.equal(controller.state.loading, true);
  await controller.pollStatus(context(), row(), async (action, args) => {
    calls.push({ action, args });
    return job();
  }, () => true);
  await controller.cancel(context(), row(), async (action, args) => {
    calls.push({ action, args });
    return job({ cancel_requested: true });
  }, () => true);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].action, 'windows_offline_file_start');

  pendingStart.resolve(job());
  await starting;
  assert.equal(controller.state.loading, false);
  assert.equal(controller.state.admissionUncertain, false);
  assert.equal(controller.state.job.job_id, 'a'.repeat(32));
});

test('added profile file requests remain scoped and discard a same-generation foreign-profile reply', async () => {
  const a = context({ profileId: 'profile-' + '1'.repeat(32) }), b = context({ profileId: 'profile-' + '2'.repeat(32) });
  const controller = new WindowsOfflineFileController();
  const calls = [];
  await controller.loadCacheStatus(a, row(), async (action, args) => {
    calls.push({ action, args }); return cacheStatus({ profile_id: a.profileId });
  }, () => true);
  assert.equal(calls[0].args.profile_id, a.profileId);
  assert.equal(controller.state.cacheStatus.profile_id, a.profileId);
  assert.throws(() => validateWindowsFileCacheStatus(cacheStatus({ profile_id: b.profileId }), a));
  const pending = deferred();
  const loading = controller.loadCacheStatus(a, row(), () => pending.promise, () => true);
  controller.setSelection(b, row());
  pending.resolve(cacheStatus({ profile_id: a.profileId }));
  await loading;
  assert.equal(controller.state.cacheStatus, null);
  assert.notEqual(windowsOfflineFileContextKey(a, row()), windowsOfflineFileContextKey(b, row()));
});
