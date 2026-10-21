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
