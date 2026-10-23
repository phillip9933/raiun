import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';

const recoverySource = await readFile(new URL('../src/windows-recovery.ts', import.meta.url), 'utf8');
const recoveryUrl = `data:text/javascript;base64,${Buffer.from(ts.transpileModule(recoverySource, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } }).outputText).toString('base64')}`;
const source = await readFile(new URL('../src/windows-offline-folder.ts', import.meta.url), 'utf8');
const compiled = ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 }
}).outputText.replace("from './windows-recovery'", `from '${recoveryUrl}'`);
const {
  WindowsOfflineFolderController,
  windowsOfflineFolderContextKey,
  validateWindowsOfflineFolderJob
} = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`);

const context = (changes = {}) => ({
  profileId: 'default',
  accountEpoch: 8,
  authGeneration: 12,
  recoveryScopeToken: 'c'.repeat(64),
  flowGeneration: 3,
  server: 'https://cloud.example',
  clientId: 'synthetic-client',
  cloudRoot: 'C:\\Raiun',
  ...changes
});
const row = (changes = {}) => ({
  spaceLabel: 'Personal',
  spaceId: 'personal-space',
  rootResourceId: 'personal-root',
  path: '/Documents',
  resourceId: 'folder-123',
  ...changes
});
const progress = (changes = {}) => ({
  pin_id: 'd'.repeat(64),
  root_resource_id: 'folder-123',
  path: '/Documents',
  state: 'building',
  item_count: 4,
  ready_content_count: 1,
  required_content_count: 3,
  ...changes
});
const prepared = (changes = {}) => ({
  job_id: 'a'.repeat(32),
  state: 'prepared',
  kind: 'folder',
  folder: null,
  cancel_requested: false,
  recovery_required: false,
  ...changes
});
const job = (changes = {}) => ({
  ...prepared({ state: 'running', folder: progress() }),
  ...changes
});
function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

test('folder context validates the exact scope and accepts only root or canonical folder paths', () => {
  const base = windowsOfflineFolderContextKey(context(), row());
  assert.notEqual(windowsOfflineFolderContextKey(context({ flowGeneration: 4 }), row()), base);
  assert.notEqual(windowsOfflineFolderContextKey(context(), row({ resourceId: 'other-folder' })), base);
  assert.doesNotThrow(() => windowsOfflineFolderContextKey(context(), row({ path: '/' })));
  for (const invalid of [
    row({ path: 'relative' }),
    row({ path: '/Documents/' }),
    row({ path: '/Documents/../private' }),
    row({ path: '/Documents//child' }),
    row({ path: '/Documents\\child' }),
    row({ resourceId: '' })
  ]) assert.throws(() => windowsOfflineFolderContextKey(context(), invalid));
});

test('folder job validation bounds progress and binds it to the selected folder', () => {
  assert.deepEqual(validateWindowsOfflineFolderJob(prepared(), row()), prepared());
  assert.deepEqual(validateWindowsOfflineFolderJob(job(), row()), job());
  for (const invalid of [
    prepared({ kind: 'file' }),
    prepared({ state: 'queued' }),
    prepared({ folder: progress({ pin_id: 'A'.repeat(64) }) }),
    job({ folder: progress({ root_resource_id: 'other-folder' }) }),
    job({ folder: progress({ path: '/Other' }) }),
    job({ folder: progress({ item_count: 10_001 }) }),
    job({ folder: progress({ ready_content_count: 4 }) }),
    job({ folder: progress({ required_content_count: 5 }) }),
    job({ folder: progress({ state: 'ready', ready_content_count: 2, required_content_count: 3 }) }),
    job({ state: 'complete', folder: null }),
    job({ state: 'complete', folder: progress() }),
    job({ state: 'recovery_required' }),
    { ...job(), unrecognized: true }
  ]) assert.throws(() => validateWindowsOfflineFolderJob(invalid, row()));
});

test('start prepares and remembers an ID before sending the exact folder request', async () => {
  const controller = new WindowsOfflineFolderController();
  const calls = [];
  const request = async (action, args) => {
    calls.push({ action, args });
    if (action === 'windows_offline_folder_prepare') return prepared();
    return job();
  };
  await controller.start(context(), row(), request, () => true);
  assert.deepEqual(calls.map(({ action }) => action), [
    'windows_offline_folder_prepare', 'windows_offline_folder_start'
  ]);
  assert.deepEqual(calls[0].args, {
    profile_id: 'default', expected_generation: 12, expected_recovery_scope_token: 'c'.repeat(64),
    space_id: 'personal-space', root_resource_id: 'personal-root', path: '/Documents',
    resource_id: 'folder-123'
  });
  assert.deepEqual(calls[1].args, {
    ...calls[0].args, job_id: 'a'.repeat(32)
  });
  assert.equal(controller.state.job.job_id, 'a'.repeat(32));
  assert.equal(controller.state.admissionUncertain, false);
});

test('resume and refresh always prepare first and include only their explicit durable pin IDs', async () => {
  const controller = new WindowsOfflineFolderController();
  const calls = [];
  let preparedId = '';
  const request = async (action, args) => {
    calls.push({ action, args });
    if (action.endsWith('_prepare')) {
      preparedId = calls.length.toString(16).padStart(32, '0');
      return prepared({ job_id: preparedId });
    }
    return job({ job_id: preparedId });
  };
  await controller.resume(context(), row(), 'b'.repeat(64), request, () => true);
  const refreshController = new WindowsOfflineFolderController();
  await refreshController.refresh(context({ flowGeneration: 4 }), row(), 'b'.repeat(64), 'e'.repeat(64), request, () => true);
  assert.deepEqual(calls.map(({ action }) => action), [
    'windows_offline_folder_prepare', 'windows_offline_folder_resume',
    'windows_offline_folder_prepare', 'windows_offline_folder_refresh'
  ]);
  assert.equal(calls[1].args.job_id, '0'.repeat(31) + '1');
  assert.equal(calls[1].args.pin_id, 'b'.repeat(64));
  assert.equal(calls[3].args.pin_id, 'b'.repeat(64));
  assert.equal(calls[3].args.staging_pin_id, 'e'.repeat(64));
  assert.throws(() => controller.resume(context(), row(), 'bad-pin', request, () => true));
});

test('lost start reply keeps its prepared ID for status and cancel without a new prepare or start', async () => {
  const controller = new WindowsOfflineFolderController();
  const calls = [];
  const request = async (action, args) => {
    calls.push({ action, args });
    if (action === 'windows_offline_folder_prepare') return prepared();
    if (action === 'windows_offline_folder_start') throw new Error('pipe closed');
    if (action === 'windows_offline_folder_status') return job();
    return prepared({ state: 'cancelled', cancel_requested: true });
  };
  await controller.start(context(), row(), request, () => true);
  assert.equal(controller.state.admissionUncertain, true);
  assert.equal(controller.state.job.job_id, 'a'.repeat(32));
  assert.match(controller.state.error, /may have started/i);

  await controller.pollStatus(context(), row(), request, () => true);
  assert.equal(controller.state.job.state, 'running');
  await controller.cancel(context(), row(), request, () => true);
  assert.equal(controller.state.job.state, 'cancelled');
  assert.deepEqual(calls.map(({ action }) => action), [
    'windows_offline_folder_prepare', 'windows_offline_folder_start',
    'windows_offline_folder_status', 'windows_offline_folder_cancel'
  ]);
  assert(calls.slice(1).every(({ args }) => args.job_id === 'a'.repeat(32)));
});

test('changing folders in the same account keeps the known running job pollable and cancellable', async () => {
  const controller = new WindowsOfflineFolderController();
  const otherRow = row({ path: '/Photos', resourceId: 'folder-photos' });
  const calls = [];
  const request = async (action, args) => {
    calls.push({ action, args });
    if (action === 'windows_offline_folder_prepare') return prepared();
    if (action === 'windows_offline_folder_start') throw new Error('reply lost');
    if (action === 'windows_offline_folder_status') return job();
    return job({ state: 'cancelled', cancel_requested: true });
  };

  await controller.start(context(), row(), request, () => true);
  assert.equal(controller.state.admissionUncertain, true);
  controller.setSelection(context(), otherRow);
  assert.equal(controller.state.job.job_id, 'a'.repeat(32));
  assert.equal(controller.state.admissionUncertain, true);

  await controller.pollStatus(context(), otherRow, request, () => true);
  assert.equal(controller.state.job.state, 'running');
  await controller.cancel(context(), otherRow, request, () => true);
  assert.equal(controller.state.job.state, 'cancelled');
  assert.deepEqual(calls.map(({ action }) => action), [
    'windows_offline_folder_prepare', 'windows_offline_folder_start',
    'windows_offline_folder_status', 'windows_offline_folder_cancel'
  ]);
  assert(calls.slice(1).every(({ args }) => args.job_id === 'a'.repeat(32)));
});

test('late preparation reply after account change cannot launch a folder job', async () => {
  const controller = new WindowsOfflineFolderController();
  const pending = deferred();
  const calls = [];
  const starting = controller.start(context(), row(), async (action, args) => {
    calls.push({ action, args });
    return pending.promise;
  }, () => true);
  controller.setSelection(context({ accountEpoch: 9 }), row());
  pending.resolve(prepared());
  await starting;
  assert.deepEqual(calls.map(({ action }) => action), ['windows_offline_folder_prepare']);
  assert.equal(controller.state.job, null);
  assert.equal(controller.state.loading, false);
});

test('invalid folder metadata is refused before any RPC is sent', async () => {
  const controller = new WindowsOfflineFolderController();
  let calls = 0;
  await controller.start(context(), row({ path: '/Documents/../private' }), async () => {
    calls += 1;
    return prepared();
  }, () => true);
  assert.equal(calls, 0);
  assert.match(controller.state.error, /folder/i);
});

test('added profile folder prepare/start keeps its scope and cannot start after profile replacement', async () => {
  const a = context({ profileId: 'profile-' + '1'.repeat(32) }), b = context({ profileId: 'profile-' + '2'.repeat(32) });
  const controller = new WindowsOfflineFolderController();
  const calls = [];
  await controller.start(a, row(), async (action, args) => {
    calls.push({ action, args }); return action.endsWith('_prepare') ? prepared() : job();
  }, () => true);
  assert.equal(calls.length, 2);
  assert.ok(calls.every(call => call.args.profile_id === a.profileId));
  const next = new WindowsOfflineFolderController(), pending = deferred();
  const laterCalls = [];
  const loading = next.start(a, row(), async (action) => {
    laterCalls.push(action); return pending.promise;
  }, () => true);
  next.setSelection(b, row());
  pending.resolve(prepared());
  await loading;
  assert.deepEqual(laterCalls, ['windows_offline_folder_prepare']);
  assert.equal(next.state.job, null);
});
