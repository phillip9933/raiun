import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';

const recoverySource = await readFile(new URL('../src/windows-recovery.ts', import.meta.url), 'utf8');
const recoveryUrl = `data:text/javascript;base64,${Buffer.from(ts.transpileModule(recoverySource, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } }).outputText).toString('base64')}`;
const source = await readFile(new URL('../src/windows-offline-folder-panel.ts', import.meta.url), 'utf8');
const controllerSource = await readFile(new URL('../src/windows-offline-folder.ts', import.meta.url), 'utf8');
const viewSource = await readFile(new URL('../src/windows-offline-folder-view.ts', import.meta.url), 'utf8');
const transpile = (text) => ts.transpileModule(text, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 }
}).outputText;
const controllerUrl = `data:text/javascript;base64,${Buffer.from(transpile(controllerSource).replace("from './windows-recovery'", `from '${recoveryUrl}'`)).toString('base64')}`;
const viewUrl = `data:text/javascript;base64,${Buffer.from(transpile(viewSource)).toString('base64')}`;
const compiled = transpile(source)
  .replace("from './windows-offline-folder'", `from '${controllerUrl}'`)
  .replace("from './windows-offline-folder-view'", `from '${viewUrl}'`);
const { WindowsOfflineFolderPanel } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`);

const context = (changes = {}) => ({
  profileId: 'default', accountEpoch: 4, authGeneration: 7,
  recoveryScopeToken: 'c'.repeat(64), flowGeneration: 2,
  server: 'https://synthetic.invalid', clientId: 'fixture', cloudRoot: 'C:\\Raiun', ...changes
});
const savedIntent = (state = 'none', activePinId = null, stagingPinId = null, stagingIsInitial = false) => ({
  state, active_pin_id: activePinId, staging_pin_id: stagingPinId,
  staging_is_initial: stagingIsInitial
});
const row = {
  space_id: 'personal', space_label: 'Personal', root_resource_id: 'personal-root', path: '/Projects', resource_id: 'folder-projects',
  saved_intent: savedIntent()
};
const page = (ctx, changes = {}) => ({
  rows: [row], next_cursor: null, unavailable_rows: 0,
  read_only: true, last_observed: true, atomic_snapshot: false,
  profile_id: ctx.profileId, auth_generation: ctx.authGeneration,
  recovery_scope_token: ctx.recoveryScopeToken, ...changes
});
const prepared = (id = 'a'.repeat(32)) => ({
  job_id: id, state: 'prepared', kind: 'folder', folder: null,
  cancel_requested: false, recovery_required: false
});
const progress = () => ({
  pin_id: 'd'.repeat(64), root_resource_id: 'folder-projects', path: '/Projects',
  state: 'building', item_count: 2, ready_content_count: 0, required_content_count: 2
});
const running = (id = 'a'.repeat(32)) => ({
  ...prepared(id), state: 'running', folder: progress()
});
function deferred() {
  let resolve;
  const promise = new Promise((yes) => { resolve = yes; });
  return { promise, resolve };
}

function makePanel({ getContext = () => context(), request, actionsAvailable = () => true } = {}) {
  return new WindowsOfflineFolderPanel({ getContext, actionsAvailable, request, changed() {} });
}

test('loads only a bounded exact page and rejects forged row/page metadata', async () => {
  const ctx = context();
  const panel = makePanel({ request: async () => page(ctx) });
  await panel.load(true);
  assert.match(panel.render(), /\/Projects/);

  const forged = makePanel({ request: async () => page(ctx, { rows: [{ ...row, extra: 'invented' }] }) });
  await forged.load(true);
  assert.match(forged.render(), /invalid saved-folder row/i);

  const oversized = makePanel({ request: async () => page(ctx, { rows: Array(9).fill(row) }) });
  await oversized.load(true);
  assert.match(oversized.render(), /invalid saved-folder page/i);
});

test('late folder page reply is discarded after the account scope changes', async () => {
  let current = context();
  const pending = deferred();
  const panel = makePanel({ getContext: () => current, request: () => pending.promise });
  const loading = panel.load(true);
  current = context({ authGeneration: 8, recoveryScopeToken: 'e'.repeat(64) });
  panel.syncContext();
  pending.resolve(page(context()));
  await loading;
  assert.doesNotMatch(panel.render(), /\/Projects/);
});

test('page accumulation is capped at 128 known rows without evicting existing handles', async () => {
  const ctx = context();
  const pages = new Map();
  for (let pageIndex = 0; pageIndex < 17; pageIndex += 1) {
    const cursor = pageIndex === 0 ? null : pageIndex.toString(16).padStart(32, '0');
    const rows = Array.from({ length: 8 }, (_, index) => {
      const number = pageIndex * 8 + index;
      return {
        space_id: 'personal', space_label: 'Personal', root_resource_id: 'personal-root',
        path: `/Folder-${number}`, resource_id: `folder-${number}`, saved_intent: savedIntent()
      };
    });
    pages.set(cursor, page(ctx, {
      rows,
      next_cursor: pageIndex < 16 ? (pageIndex + 1).toString(16).padStart(32, '0') : null
    }));
  }
  const panel = makePanel({ request: async (_action, args) => pages.get(args.cursor ?? null) });
  await panel.load(true);
  for (let index = 0; index < 15; index += 1) await panel.load(false);
  assert.equal((panel.render().match(/class="remote-entry/g) ?? []).length, 128);
  await panel.load(false);
  assert.equal((panel.render().match(/class="remote-entry/g) ?? []).length, 128);
  assert.match(panel.render(), /smaller folder branch/i);
});

test('lost start reply keeps its known job ID pollable and cancellable without another start', async () => {
  const ctx = context();
  const calls = [];
  const panel = makePanel({ request: async (action, args) => {
    calls.push({ action, args });
    if (action === 'windows_offline_folders') return page(ctx);
    if (action === 'windows_offline_folder_prepare') return prepared();
    if (action === 'windows_offline_folder_start') throw new Error('reply lost');
    if (action === 'windows_offline_folder_status') return running(args.job_id);
    if (action === 'windows_offline_folder_cancel') return {
      ...running(args.job_id), state: 'cancelled', cancel_requested: true
    };
    throw new Error('unexpected action');
  } });
  await panel.load(true);
  const key = JSON.stringify({
    space_id: 'personal', root_resource_id: 'personal-root',
    path: '/Projects', resource_id: 'folder-projects'
  });
  panel.select(key);
  await panel.run('start');
  assert.match(panel.render(), /reply could not be confirmed/i);
  assert.match(panel.render(), /Check status/);
  assert.match(panel.render(), /Cancel download/);
  await panel.run('poll');
  await panel.run('cancel');
  assert.deepEqual(calls.map(({ action }) => action), [
    'windows_offline_folders', 'windows_offline_folder_prepare',
    'windows_offline_folder_start', 'windows_offline_folder_status', 'windows_offline_folder_cancel'
  ]);
  assert(calls.slice(2).every(({ args }) => args.job_id === 'a'.repeat(32)));
});

test('completed pin roles stay attached to their exact folder when selecting another row', async () => {
  const ctx = context();
  const second = { ...row, path: '/Photos', resource_id: 'folder-photos' };
  let started = false;
  const panel = makePanel({ request: async (action) => {
    if (action === 'windows_offline_folders') {
      return page(ctx, { rows: [row, second], next_cursor: null });
    }
    if (action === 'windows_offline_folder_prepare') return prepared();
    if (action === 'windows_offline_folder_start') {
      started = true;
      return running();
    }
    if (action === 'windows_offline_folder_status') return {
      ...running(), state: 'complete', folder: {
        ...progress(), state: 'ready', ready_content_count: 2
      }
    };
    throw new Error(`unexpected ${action}`);
  } });
  await panel.load(true);
  const key = (entry) => JSON.stringify({
    space_id: entry.space_id, root_resource_id: entry.root_resource_id,
    path: entry.path, resource_id: entry.resource_id
  });
  panel.select(key(row));
  await panel.run('start');
  assert(started);
  await panel.run('poll');

  panel.select(key(second));
  assert.doesNotMatch(panel.render(), /data-action="refresh-windows-offline-folder"/);
  panel.select(key(row));
  assert.match(panel.render(), /data-action="refresh-windows-offline-folder"/);
  assert.match(panel.render(), new RegExp(`data-pin-id="${'d'.repeat(64)}"`));
  assert.match(panel.render(), /data-action="start-windows-offline-folder" disabled/);
});

test('terminal jobs keep known same-folder refresh or resume actions available and prepare first', async () => {
  const key = JSON.stringify({
    space_id: 'personal', root_resource_id: 'personal-root',
    path: '/Projects', resource_id: 'folder-projects'
  });
  for (const { terminalState, action, pinId } of [
    { terminalState: 'complete', action: 'refresh', pinId: 'd'.repeat(64) },
    { terminalState: 'cancelled', action: 'resume', pinId: 'e'.repeat(64) },
    { terminalState: 'failed', action: 'resume', pinId: 'f'.repeat(64) }
  ]) {
    const ctx = context();
    const calls = [];
    let prepareCount = 0;
    const panel = makePanel({ request: async (requestedAction, args) => {
      calls.push({ action: requestedAction, args });
      if (requestedAction === 'windows_offline_folders') return page(ctx);
      if (requestedAction === 'windows_offline_folder_prepare') {
        prepareCount += 1;
        return prepared(prepareCount === 1 ? 'a'.repeat(32) : 'b'.repeat(32));
      }
      if (requestedAction === 'windows_offline_folder_start') return running('a'.repeat(32));
      if (requestedAction === 'windows_offline_folder_status') return {
        ...running('a'.repeat(32)), state: terminalState,
        cancel_requested: terminalState === 'cancelled',
        folder: {
          ...progress(), pin_id: pinId,
          state: terminalState === 'complete' ? 'ready' : 'stale',
          ready_content_count: terminalState === 'complete' ? 2 : 0
        }
      };
      if (requestedAction === `windows_offline_folder_${action}`) return running('b'.repeat(32));
      throw new Error(`unexpected action ${requestedAction}`);
    } });
    await panel.load(true);
    panel.select(key);
    await panel.run('start');
    await panel.run('poll');
    const terminalHtml = panel.render();
    assert.doesNotMatch(terminalHtml, /data-action="poll-windows-offline-folder"/);
    assert.match(terminalHtml, new RegExp(`data-action="${action}-windows-offline-folder"`));
    await panel.run(action);
    assert.deepEqual(calls.map(({ action: name }) => name), [
      'windows_offline_folders', 'windows_offline_folder_prepare',
      'windows_offline_folder_start', 'windows_offline_folder_status',
      'windows_offline_folder_prepare', `windows_offline_folder_${action}`
    ]);
    assert.equal(calls.at(-1).args.pin_id, pinId);
    assert.equal(calls.at(-2).args.space_id, 'personal');
    assert.equal(Object.keys(calls.at(-2).args).filter((name) => [
      'space_id', 'root_resource_id', 'path', 'resource_id', 'space_label'
    ].includes(name)).length, 4);
  }
});


test('requires a safe namespace label while preserving the four-field selection and RPC identity', async () => {
  const ctx = context();
  const calls = [];
  const panel = makePanel({ request: async (action, args) => {
    calls.push({ action, args });
    return action === 'windows_offline_folders' ? page(ctx) : prepared();
  } });
  await panel.load(true);
  const key = JSON.stringify({ space_id: 'personal', root_resource_id: 'personal-root', path: '/Projects', resource_id: 'folder-projects' });
  panel.select(key);
  await panel.run('start');
  assert.deepEqual(calls.at(-2).args, {
    profile_id: 'default', expected_generation: 7, expected_recovery_scope_token: 'c'.repeat(64),
    space_id: 'personal', root_resource_id: 'personal-root', path: '/Projects', resource_id: 'folder-projects'
  });
  assert.equal(Object.keys(JSON.parse(key)).length, 4);
  for (const label of ['', '  ', 'x'.repeat(513), 'Personal\n<script>']) {
    const invalid = makePanel({ request: async () => page(ctx, { rows: [{ ...row, space_label: label }] }) });
    await invalid.load(true);
    assert.match(invalid.render(), /invalid saved-folder row/i);
  }
});

test('fresh role data restores initial resume and active refresh after panel recreation', async () => {
  const ctx = context();
  const cases = [
    {
      action: 'resume', pin: 'd'.repeat(64),
      intent: savedIntent('known', null, 'd'.repeat(64), true)
    },
    {
      action: 'refresh', pin: 'e'.repeat(64), stage: 'f'.repeat(64),
      intent: savedIntent('known', 'e'.repeat(64), 'f'.repeat(64), false)
    }
  ];
  for (const scenario of cases) {
    const calls = [];
    const panel = makePanel({ request: async (action, args) => {
      calls.push({ action, args });
      if (action === 'windows_offline_folders') {
        return page(ctx, { rows: [{ ...row, saved_intent: scenario.intent }] });
      }
      if (action === 'windows_offline_folder_prepare') return prepared();
      if (action === `windows_offline_folder_${scenario.action}`) return running();
      throw new Error(`unexpected ${action}`);
    } });
    await panel.load(true);
    const key = JSON.stringify({
      space_id: 'personal', root_resource_id: 'personal-root',
      path: '/Projects', resource_id: 'folder-projects'
    });
    panel.select(key);
    const html = panel.render();
    assert.match(html, new RegExp(`data-action="${scenario.action}-windows-offline-folder"`));
    assert.match(html, /data-action="start-windows-offline-folder" disabled/);
    await panel.run(scenario.action);
    assert.deepEqual(calls.map(({ action }) => action), [
      'windows_offline_folders', 'windows_offline_folder_prepare',
      `windows_offline_folder_${scenario.action}`
    ]);
    assert.equal(calls[1].args.space_id, 'personal');
    assert.equal(calls[1].args.resource_id, 'folder-projects');
    assert.equal(calls[2].args.pin_id, scenario.pin);
    if (scenario.action === 'refresh') assert.equal(calls[2].args.staging_pin_id, scenario.stage);
  }
});

test('forged, unknown, unavailable, and orphan intent fail closed for mutations', async () => {
  const ctx = context();
  const invalidIntents = [
    null,
    savedIntent('known'),
    savedIntent('known', null, 'D'.repeat(64), true),
    savedIntent('known', 'a'.repeat(64), 'a'.repeat(64), false),
    savedIntent('known', null, 'a'.repeat(64), false),
    savedIntent('unknown', 'a'.repeat(64), null, false),
    savedIntent('recovery_required', 'a'.repeat(64), 'b'.repeat(64), false),
    savedIntent('recovery_required', null, null, false),
    { ...savedIntent(), forged: true }
  ];
  for (const intent of invalidIntents) {
    const badRow = { ...row };
    if (intent === null) delete badRow.saved_intent;
    else badRow.saved_intent = intent;
    const panel = makePanel({ request: async () => page(ctx, { rows: [badRow] }) });
    await panel.load(true);
    assert.match(panel.render(), /invalid saved-folder (?:row|intent)|invalid saved-folder page/i);
  }

  for (const state of ['unknown', 'unavailable', 'recovery_required']) {
    const calls = [];
    const intent = state === 'recovery_required'
      ? savedIntent(state, null, 'b'.repeat(64), false)
      : savedIntent(state);
    const panel = makePanel({ request: async (action, args) => {
      calls.push({ action, args });
      return page(ctx, { rows: [{ ...row, saved_intent: intent }] });
    } });
    await panel.load(true);
    panel.select(JSON.stringify({
      space_id: 'personal', root_resource_id: 'personal-root',
      path: '/Projects', resource_id: 'folder-projects'
    }));
    const html = panel.render();
    assert.match(html, /Existing copies are preserved/);
    assert.match(html, /data-action="start-windows-offline-folder" disabled/);
    assert.doesNotMatch(html, /data-action="resume-windows-offline-folder"/);
    assert.doesNotMatch(html, /data-action="refresh-windows-offline-folder"/);
    await panel.run('start');
    await panel.run('resume');
    await panel.run('refresh');
    assert.deepEqual(calls.map(({ action }) => action), ['windows_offline_folders']);
  }
});

test('a refreshed authoritative page clears an obsolete stage before the next refresh', async () => {
  const ctx = context();
  const active = 'e'.repeat(64);
  const obsoleteStage = 'f'.repeat(64);
  let pageCount = 0;
  const calls = [];
  const panel = makePanel({ request: async (action, args) => {
    calls.push({ action, args });
    if (action === 'windows_offline_folders') {
      pageCount += 1;
      return page(ctx, { rows: [{
        ...row,
        saved_intent: pageCount === 1
          ? savedIntent('known', active, obsoleteStage, false)
          : savedIntent('known', active, null, false)
      }] });
    }
    if (action === 'windows_offline_folder_prepare') return prepared();
    if (action === 'windows_offline_folder_refresh') return running();
    throw new Error(`unexpected ${action}`);
  } });
  await panel.load(true);
  const key = JSON.stringify({
    space_id: 'personal', root_resource_id: 'personal-root',
    path: '/Projects', resource_id: 'folder-projects'
  });
  panel.select(key);
  assert.match(panel.render(), new RegExp(`data-staging-pin-id="${obsoleteStage}"`));
  await panel.load(true);
  assert.doesNotMatch(panel.render(), new RegExp(obsoleteStage));
  await panel.run('refresh');
  const refresh = calls.find(({ action }) => action === 'windows_offline_folder_refresh');
  assert.equal(refresh.args.pin_id, active);
  assert.equal(Object.hasOwn(refresh.args, 'staging_pin_id'), false);
});

test('recovery-required known job blocks direct mutations even after refreshed intent rows', async () => {
  const ctx = context();
  const scenarios = [
    { action: 'start', intent: savedIntent() },
    { action: 'resume', intent: savedIntent('known', null, 'd'.repeat(64), true) },
    { action: 'refresh', intent: savedIntent('known', 'e'.repeat(64), null, false) }
  ];
  for (const scenario of scenarios) {
    const calls = [];
    let pageCount = 0;
    const panel = makePanel({ request: async (action, args) => {
      calls.push({ action, args });
      if (action === 'windows_offline_folders') {
        pageCount += 1;
        return page(ctx, { rows: [{
          ...row,
          saved_intent: pageCount === 1 ? savedIntent() : scenario.intent
        }] });
      }
      if (action === 'windows_offline_folder_prepare') return prepared();
      if (action === 'windows_offline_folder_start') return {
        ...running(), state: 'recovery_required', recovery_required: true
      };
      throw new Error(`unexpected request ${action}`);
    } });
    await panel.load(true);
    const key = JSON.stringify({
      space_id: 'personal', root_resource_id: 'personal-root',
      path: '/Projects', resource_id: 'folder-projects'
    });
    panel.select(key);
    await panel.run('start');
    assert.match(panel.render(), /needs recovery/i);
    await panel.load(true);
    assert.doesNotMatch(panel.render(), /data-action="(?:start|resume|refresh)-windows-offline-folder"/);
    const callsBefore = calls.length;
    await panel.run(scenario.action);
    assert.equal(calls.length, callsBefore, `${scenario.action} must not prepare another job`);
    assert.deepEqual(calls.map(({ action }) => action), [
      'windows_offline_folders', 'windows_offline_folder_prepare', 'windows_offline_folder_start',
      'windows_offline_folders'
    ]);
  }
});
