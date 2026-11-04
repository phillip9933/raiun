import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';

const source = await readFile(new URL('../src/pending-write-scope.ts', import.meta.url), 'utf8');
const compiled = ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 }
}).outputText;
const { groupPendingWritesByScope, pendingWritePageIsValid, pendingWriteScopeKey, savedRootDisclosure, togglePendingWriteDisclosure } = await import(
  `data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`
);

const escapeHtml = value => value.replace(/[&<>"']/g, character => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
}[character]));

test('saved edits with the same Space and path but different roots stay in separate groups', () => {
  const rows = [
    { space_id: 'space-a', root_resource_id: 'root-one', path: '/same.txt', write_id: '1' },
    { space_id: 'space-a', root_resource_id: 'root-two', path: '/same.txt', write_id: '2' }
  ];
  const groups = groupPendingWritesByScope(rows);
  assert.equal(groups.size, 2);
  assert.deepEqual([...groups.values()].map(group => group[0].root_resource_id).sort(), ['root-one', 'root-two']);
});

test('older saved-edit records without a root remain visible as an unavailable identity', () => {
  const legacy = { space_id: 'space-a', path: '/same.txt', write_id: 'old', state: 'pending', bytes: 5, created_at_unix: 1 };
  assert.equal(pendingWriteScopeKey(legacy), pendingWriteScopeKey({ ...legacy, root_resource_id: null }));
  assert.match(savedRootDisclosure(null, pendingWriteScopeKey(legacy), 'root-region-0', true, escapeHtml), /Saved root unavailable/);
  assert.equal(groupPendingWritesByScope([legacy]).size, 1);
  const page = pendingWritePageIsValid({ items: [legacy], pending_count: 1, conflict_count: 0 });
  assert.equal(page.items[0].root_resource_id, null);
});

test('saved-edit parser rejects malformed present root IDs instead of silently losing scope', () => {
  const base = { space_id: 'space-a', write_id: '1', path: '/same.txt', state: 'pending', bytes: 5, created_at_unix: 1 };
  assert.throws(() => pendingWritePageIsValid({ items: [{ ...base, root_resource_id: '\u0000root' }], pending_count: 1, conflict_count: 0 }), /invalid saved-edit entry/i);
  assert.throws(() => pendingWritePageIsValid({ items: [{ ...base, root_resource_id: 42 }], pending_count: 1, conflict_count: 0 }), /invalid saved-edit entry/i);
});

test('saved root disclosure uses native button state and escapes root and attribute values', () => {
  const scopeKey = JSON.stringify(['space-a', '<root&one>']);
  const collapsed = savedRootDisclosure('<img src=x onerror="bad">&', scopeKey, 'pending-write-root-region-0', false, escapeHtml);
  assert.match(collapsed, /<button type="button"/);
  assert.match(collapsed, /data-action="toggle-saved-write-root"/);
  assert.match(collapsed, /aria-expanded="false"/);
  assert.match(collapsed, /aria-controls="pending-write-root-region-0"/);
  assert.match(collapsed, /data-scope-key="\[&quot;space-a&quot;,&quot;&lt;root&amp;one&gt;&quot;\]"/);
  assert.match(collapsed, /id="pending-write-root-region-0" hidden><\/div>/);
  assert.doesNotMatch(collapsed, /<img/);

  const expanded = savedRootDisclosure('<img src=x onerror="bad">&', scopeKey, 'pending-write-root-region-0', true, escapeHtml);
  assert.match(expanded, /aria-expanded="true"/);
  assert.match(expanded, /<div class="pending-write-root-region" id="pending-write-root-region-0"><code>&lt;img src=x onerror=&quot;bad&quot;&gt;&amp;<\/code><\/div>/);
  assert.doesNotMatch(expanded, /<details|<summary|<img/);
});

test('saved-root disclosure state is isolated by exact Space and root scope', () => {
  const first = pendingWriteScopeKey({ space_id: 'space-a', root_resource_id: 'root-one' });
  const second = pendingWriteScopeKey({ space_id: 'space-a', root_resource_id: 'root-two' });
  const expanded = new Set();
  const current = new Set([first, second]);
  assert.equal(togglePendingWriteDisclosure(expanded, first, current), true);
  assert.deepEqual([...expanded], [first]);
  assert.equal(togglePendingWriteDisclosure(expanded, second, current), true);
  assert.equal(expanded.size, 2);
  assert.equal(togglePendingWriteDisclosure(expanded, first, current), true);
  assert.deepEqual([...expanded], [second]);
  assert.equal(togglePendingWriteDisclosure(expanded, first, new Set([second])), false);
  assert.deepEqual([...expanded], [second]);

  const firstMarkup = savedRootDisclosure('root-one', first, 'pending-write-root-region-0', true, escapeHtml);
  const secondMarkup = savedRootDisclosure('root-two', second, 'pending-write-root-region-1', true, escapeHtml);
  assert.notEqual(first, second);
  assert.notEqual(firstMarkup.match(/id="([^"]+)"/)?.[1], secondMarkup.match(/id="([^"]+)"/)?.[1]);
  assert.match(firstMarkup, /<code>root-one<\/code>/);
  assert.match(secondMarkup, /<code>root-two<\/code>/);
});

test('saved-edit pages bind export admission to account scope and auth generation', () => {
  const item = { space_id: 'space', root_resource_id: 'root', write_id: '1', path: '/file', state: 'pending', bytes: 4, created_at_unix: 1 };
  const bound = pendingWritePageIsValid({ items: [item], pending_count: 1, conflict_count: 0, auth_generation: 0, account_scope: 'a'.repeat(64) });
  assert.equal(bound.auth_generation, 0);
  assert.equal(bound.account_scope, 'a'.repeat(64));
  const legacy = pendingWritePageIsValid({ items: [item], pending_count: 1, conflict_count: 0 });
  assert.equal(legacy.auth_generation, null);
  assert.equal(legacy.account_scope, null);
  for (const value of [-1, 1.5, '0']) assert.throws(() => pendingWritePageIsValid({ items: [], pending_count: 0, conflict_count: 0, auth_generation: value }));
  for (const value of ['a'.repeat(63), 'A'.repeat(64), 'x'.repeat(64), 7]) assert.throws(() => pendingWritePageIsValid({ items: [], pending_count: 0, conflict_count: 0, account_scope: value }));
});

const { pendingWritePresentation, canRetryLegacyPendingWrites } = await import(
  `data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`
);
const pendingItem = { space_id: 'space-a', root_resource_id: 'root-one', write_id: '1', path: '/file', state: 'pending', bytes: 4, created_at_unix: 1 };
const pendingPage = items => ({ items, pending_count: items.filter(item => item.state === 'pending').length, conflict_count: items.filter(item => item.state === 'conflict').length });

test('new-create states retain distinct local and uncertain labels without claiming completion', () => {
  const states = { staged: 'Saved locally', ready: 'Queued for upload', claimed: 'Uploading', uncertain: 'Outcome uncertain', conflict: 'Needs review' };
  for (const [create_state, label] of Object.entries(states)) {
    const state = ['uncertain', 'conflict'].includes(create_state) ? 'conflict' : 'pending';
    const local_handoff_acknowledged = create_state !== 'staged';
    const page = pendingWritePageIsValid(pendingPage([{ ...pendingItem, state, create_state, local_handoff_acknowledged }]));
    assert.equal(page.items[0].create_state, create_state);
    assert.equal(page.items[0].local_handoff_acknowledged, local_handoff_acknowledged);
    const presentation = pendingWritePresentation(page.items[0]);
    assert.equal(presentation.label, label);
    assert.doesNotMatch(presentation.label, /complete|synced|delivered|uploaded/i);
    if (create_state === 'uncertain') assert.match(presentation.help, /may have reached the cloud.*not be retried automatically/i);
  }
  const unacknowledged = pendingWritePresentation({ ...pendingItem, create_state: 'claimed', local_handoff_acknowledged: false });
  assert.equal(unacknowledged.label, 'Uploading');
  assert.match(unacknowledged.help, /acceptance has not been confirmed/i);
});

test('optional create fields are paired, typed and consistent or reject the whole page', () => {
  const invalid = [
    { create_state: 'ready' }, { local_handoff_acknowledged: false },
    { create_state: null, local_handoff_acknowledged: false },
    { create_state: 'verified', local_handoff_acknowledged: true },
    { create_state: 'future', local_handoff_acknowledged: true },
    { create_state: 1, local_handoff_acknowledged: true },
    { create_state: 'ready', local_handoff_acknowledged: 'false' },
    { create_state: 'ready', local_handoff_acknowledged: null },
    { create_state: 'staged', local_handoff_acknowledged: true },
    { create_state: 'uncertain', local_handoff_acknowledged: true },
    { state: 'conflict', create_state: 'claimed', local_handoff_acknowledged: false },
  ];
  for (const fields of invalid) assert.throws(() => pendingWritePageIsValid(pendingPage([pendingItem, { ...pendingItem, ...fields }])), /invalid saved-edit entry/i, JSON.stringify(fields));
});

test('any visible create suppresses legacy Space retry across mixed roots and Spaces', () => {
  assert.equal(canRetryLegacyPendingWrites([pendingItem], 'space-a'), true);
  assert.equal(canRetryLegacyPendingWrites([{ ...pendingItem, state: 'conflict' }], 'space-a'), false);
  assert.equal(canRetryLegacyPendingWrites([pendingItem], 'other'), false);
  for (const create_state of ['staged', 'ready', 'claimed', 'uncertain', 'conflict']) {
    const create = { ...pendingItem, space_id: 'another-space', root_resource_id: 'root-two', create_state, local_handoff_acknowledged: false };
    assert.equal(canRetryLegacyPendingWrites([pendingItem, create], 'space-a'), false);
    assert.equal(canRetryLegacyPendingWrites([create], 'another-space'), false);
  }
});

test('legacy Windows pages without new fields retain existing labels and retry eligibility', () => {
  const page = pendingWritePageIsValid(pendingPage([pendingItem, { ...pendingItem, write_id: '2', state: 'conflict' }]));
  assert.equal(page.items[0].create_state, undefined);
  assert.equal(page.items[0].local_handoff_acknowledged, undefined);
  assert.equal(pendingWritePresentation(page.items[0]).label, 'Waiting to upload');
  assert.equal(pendingWritePresentation(page.items[1]).label, 'Needs review');
  assert.equal(canRetryLegacyPendingWrites(page.items, 'space-a'), true);
});
