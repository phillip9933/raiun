import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';

const source = await readFile(new URL('../src/windows-offline-folder-view.ts', import.meta.url), 'utf8');
const compiled = ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 }
}).outputText;
const { renderWindowsOfflineFolderPanel } = await import(
  `data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`
);

const row = (changes = {}) => ({
  spaceLabel: 'Personal', spaceId: 'personal-space', rootResourceId: 'personal-root', path: '/Documents',
  resourceId: 'folder-123', ...changes
});
const props = (changes = {}) => ({
  folderRows: [row()], currentSelection: row(), loading: false, error: '', loaded: true,
  nextCursor: null, unavailableRows: 0, actionsAvailable: true,
  controller: { job: null, loading: false, error: '', admissionUncertain: false },
  canSave: true, canResume: false, canRefresh: false,
  ...changes
});
const runningJob = (changes = {}) => ({
  job_id: 'a'.repeat(32), state: 'running', kind: 'folder', cancel_requested: false,
  recovery_required: false,
  folder: {
    pin_id: 'b'.repeat(64), root_resource_id: 'folder-123', path: '/Documents',
    state: 'building', item_count: 3, ready_content_count: 1, required_content_count: 2
  },
  ...changes
});

test('view exposes accessible folder selection, exact four-field row key, and progress', () => {
  const html = renderWindowsOfflineFolderPanel(props({
    folderRows: [row(), row({ spaceLabel: 'Spaces / Research', spaceId: 'space-research', rootResourceId: 'space-root', path: '/', resourceId: 'space-root' }), row({ path: '/', resourceId: 'personal-root' })],
    knownJobRow: row(), controller: { job: runningJob(), loading: false, error: '', admissionUncertain: false }
  }));
  assert.match(html, /<h2>Folders<\/h2>/);
  assert.match(html, /<svg viewBox="0 0 24 24"[^>]*aria-hidden="true"/);
  assert.match(html, /data-windows-offline-folder-row="\{&quot;space_id&quot;:&quot;personal-space&quot;,&quot;root_resource_id&quot;:&quot;personal-root&quot;,&quot;path&quot;:&quot;\/Documents&quot;,&quot;resource_id&quot;:&quot;folder-123&quot;\}"/);
  assert.match(html, /aria-pressed="true"/);
  assert.match(html, /Personal · Documents/);
  assert.match(html, /Spaces \/ Research · Drive root/);
  assert.match(html, /Personal · Drive root/);
  assert.match(html, /role="status" aria-live="polite"/);
  assert.match(html, /1 of 2 files verified so far/);
  assert.match(html, /data-action="poll-windows-offline-folder"/);
  assert.match(html, /data-action="cancel-windows-offline-folder"/);
  assert.match(html, />Cancel download<\/button>/);
});

test('folder actions use short labels while retaining exact action hooks', () => {
  const initial = renderWindowsOfflineFolderPanel(props({
    canResume: true, resumePinId: 'c'.repeat(64),
    canRefresh: true, refreshActivePinId: 'd'.repeat(64), refreshStagingPinId: 'e'.repeat(64)
  }));
  assert.match(initial, />Keep folder offline<\/button>/);
  assert.match(initial, />Continue download<\/button>/);
  assert.match(initial, />Refresh copy<\/button>/);
  assert.match(initial, /data-action="refresh-windows-offline-folders"[^>]*>Refresh list<\/button>/);
  assert.match(initial, /data-action="more-windows-offline-folders"[^>]*>Load more<\/button>/);
});

test('view escapes listed folder metadata and error text', () => {
  const html = renderWindowsOfflineFolderPanel(props({
    folderRows: [row({ path: '/<img src=x onerror=alert(1)>' })],
    currentSelection: row({ path: '/<img src=x onerror=alert(1)>' }),
    error: '<script>alert("bad")</script>'
  }));
  assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
  assert.match(html, /&lt;script&gt;alert\(&quot;bad&quot;\)&lt;\/script&gt;/);
  assert.doesNotMatch(html, /<script>|<img /);
});

test('provider-unavailable and uncertain states disable new mutations while preserving known-job checks', () => {
  const unavailable = renderWindowsOfflineFolderPanel(props({ actionsAvailable: false, canResume: true, canRefresh: true, resumePinId: 'c'.repeat(64), refreshActivePinId: 'd'.repeat(64) }));
  assert.match(unavailable, /data-action="refresh-windows-offline-folders" disabled/);
  assert.match(unavailable, /data-action="start-windows-offline-folder" disabled/);
  assert.match(unavailable, /data-action="resume-windows-offline-folder"[^>]*disabled/);
  assert.match(unavailable, /data-action="refresh-windows-offline-folder"[^>]*disabled/);

  const uncertain = renderWindowsOfflineFolderPanel(props({
    knownJobRow: row(), controller: { job: runningJob(), loading: false, error: '', admissionUncertain: true }
  }));
  assert.doesNotMatch(uncertain, /data-action="start-windows-offline-folder"/);
  assert.match(uncertain, /request may still be running/i);
  assert.match(uncertain, /data-action="poll-windows-offline-folder"/);
  assert.match(uncertain, /data-action="cancel-windows-offline-folder"/);
});

test('active folder jobs lock list selection and paging without disabling status or cancel', () => {
  const html = renderWindowsOfflineFolderPanel(props({
    nextCursor: 'next-page',
    controller: { job: runningJob(), loading: false, error: '', admissionUncertain: false }
  }));
  assert.match(html, /data-windows-offline-folder-row="[^"]+"[^>]*disabled/);
  assert.match(html, /data-action="refresh-windows-offline-folders" disabled/);
  assert.match(html, /data-action="more-windows-offline-folders" disabled/);
  assert.match(html, /data-action="poll-windows-offline-folder"(?![^>]*disabled)/);
  assert.match(html, /data-action="cancel-windows-offline-folder"(?![^>]*disabled)/);
});

test('a preserved job is not labeled as the newly selected folder', () => {
  const html = renderWindowsOfflineFolderPanel(props({
    currentSelection: row({ path: '/Other', resourceId: 'other-folder' }),
    knownJobRow: row(), controller: { job: runningJob(), loading: false, error: '', admissionUncertain: true }
  }));
  assert.match(html, /<b>Personal · Documents<\/b>/);
  assert.doesNotMatch(html, /<b>Other<\/b>/);
});

test('view keeps errors in an alert and never displays internal job or pin identifiers', () => {
  const html = renderWindowsOfflineFolderPanel(props({
    error: 'The folder changed.',
    controller: { job: runningJob(), loading: false, error: '', admissionUncertain: false }
  }));
  assert.match(html, /role="alert">The folder changed\.<\/div>/);
  assert.doesNotMatch(html, new RegExp('a'.repeat(32)));
  assert.doesNotMatch(html, new RegExp('b'.repeat(64)));
});

test('terminal same-folder status has no poll control and exposes only its known role action', () => {
  const complete = renderWindowsOfflineFolderPanel(props({
    knownJobRow: row(),
    controller: { job: runningJob({ state: 'complete', folder: {
      ...runningJob().folder, state: 'ready', ready_content_count: 2
    } }), loading: false, error: '', admissionUncertain: false },
    canRefresh: true, refreshActivePinId: 'd'.repeat(64)
  }));
  assert.doesNotMatch(complete, /data-action="poll-windows-offline-folder"/);
  assert.match(complete, /data-action="refresh-windows-offline-folder"/);
  assert.doesNotMatch(complete, /data-action="resume-windows-offline-folder"/);

  const failed = renderWindowsOfflineFolderPanel(props({
    knownJobRow: row(),
    controller: { job: runningJob({ state: 'failed', folder: {
      ...runningJob().folder, state: 'stale'
    } }), loading: false, error: '', admissionUncertain: false },
    canResume: true, resumePinId: 'e'.repeat(64)
  }));
  assert.doesNotMatch(failed, /data-action="poll-windows-offline-folder"/);
  assert.match(failed, /data-action="resume-windows-offline-folder"/);
  assert.doesNotMatch(failed, /data-action="refresh-windows-offline-folder"/);
});

test('recovery-required jobs never expose resume or refresh even when roles are known', () => {
  const html = renderWindowsOfflineFolderPanel(props({
    knownJobRow: row(),
    controller: { job: runningJob({ state: 'recovery_required', recovery_required: true }), loading: false, error: '', admissionUncertain: false },
    canResume: true, resumePinId: 'e'.repeat(64),
    canRefresh: true, refreshActivePinId: 'd'.repeat(64)
  }));
  assert.doesNotMatch(html, /data-action="resume-windows-offline-folder"/);
  assert.doesNotMatch(html, /data-action="refresh-windows-offline-folder"/);
  assert.doesNotMatch(html, /data-action="poll-windows-offline-folder"/);
});


test('namespace labels are escaped in row and known job labels', () => {
  const malicious = row({ spaceLabel: 'Spaces / <img src=x onerror=alert(1)>' });
  const html = renderWindowsOfflineFolderPanel(props({
    folderRows: [malicious], currentSelection: malicious, knownJobRow: malicious,
    controller: { job: runningJob(), loading: false, error: '', admissionUncertain: false }
  }));
  assert.match(html, /Spaces \/ &lt;img src=x onerror=alert\(1\)&gt;/);
  assert.doesNotMatch(html, /<img /);
});
