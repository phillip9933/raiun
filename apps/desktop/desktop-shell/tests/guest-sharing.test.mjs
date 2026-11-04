import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';

const source = await readFile(new URL('../src/guest-sharing.ts', import.meta.url), 'utf8');
const compiled = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } }).outputText;
const api = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`);
const mainSource = await readFile(new URL('../src/main.ts', import.meta.url), 'utf8');

test('guest errors distinguish denied access from unavailable capability', () => {
  assert.equal(api.guestAccessMessage(new Error('HTTP 403 forbidden')), 'Server denied guest access.');
  assert.equal(api.guestAccessMessage(new Error('capability unavailable')), 'Guest invitations are unavailable on this server.');
});

test('guest expiration edits preserve UTC and allow clearing', () => {
  assert.equal(api.guestExpiryValue(''), null);
  assert.equal(api.guestExpiryValue('2027-01-03T10:30'), new Date('2027-01-03T10:30').toISOString());
  assert.equal(api.guestExpiryInput('invalid'), '');
});

test('guest confirmation scope rejects account, page, resource, list-generation, and auth changes', () => {
  const scope = { page: 'guest', category: 'guest', profileId: 'profile-a', accountEpoch: 4, generation: 8, spaceId: 'space-a', path: '/folder/file', itemId: 'item-a', authGeneration: 12 };
  assert.equal(api.guestMutationScopeIsCurrent(scope, { ...scope }), true);
  for (const [key, value] of Object.entries({ page: 'settings', category: 'internal', profileId: 'profile-b', accountEpoch: 5, generation: 9, spaceId: 'space-b', path: '/other', itemId: 'item-b', authGeneration: 13 })) {
    assert.equal(api.guestMutationScopeIsCurrent(scope, { ...scope, [key]: value }), false, `${key} must invalidate a pending confirmation`);
  }
});

test('guest permission renderer escapes server supplied labels and disables busy actions', () => {
  const markup = api.guestAccessMarkup({ profile_id: 'p', auth_generation: 2, available: true, item_id: 'i', roles: [{ id: 'r', name: '<script>' }], guests: [{ id: 'g', email: 'a&b@example.com', roles: ['r'], expiration_date_time: null }] }, true, '', '/docs/a', 'r', '');
  assert.match(markup, /&lt;script&gt;/);
  assert.match(markup, /a&amp;b@example.com/);
  assert.match(markup, /data-guest-role-id="g"[^>]*>/);
  assert.doesNotMatch(markup, /<small>r<\/small>/);
  assert.match(markup, /data-action="guest-revoke"[^>]*disabled/);
});

test('empty permission result escapes its error message', () => {
  const markup = api.guestAccessMarkup(null, false, '<img src=x onerror=alert(1)>', '', '', '');
  assert.match(markup, /&lt;img src=x onerror=alert\(1\)&gt;/);
  assert.doesNotMatch(markup, /<img src=x/);
});

test('unavailable permission result escapes the selected filename', () => {
  const markup = api.guestAccessMarkup({ profile_id: 'p', auth_generation: 2, available: false, item_id: '', roles: [], guests: [] }, false, '', '/docs/<svg onload=alert(1)>', '', '');
  assert.match(markup, /\/docs\/&lt;svg onload=alert\(1\)&gt;/);
  assert.doesNotMatch(markup, /<svg onload=/);
});

test('all renderer dynamic text and input attributes are escaped', () => {
  const markup = api.guestAccessMarkup({ profile_id: 'p', auth_generation: 2, available: true, item_id: 'i', roles: [{ id: 'r', name: 'Read' }], guests: [] }, false, '<b>problem</b>', '/docs/a" autofocus="true', 'r', '" onfocus="alert(1)', 'x" onfocus="alert(1)');
  assert.match(markup, /value="x&amp;quot;|value="x&quot;/);
  assert.match(markup, /&lt;b&gt;problem&lt;\/b&gt;/);
  assert.doesNotMatch(markup, /autofocus="true"/);
  assert.doesNotMatch(markup, /onfocus="alert/);
});

test('inline guest picker is excluded from overlay rendering and modal interaction blocking', () => {
  assert.equal(api.pickerUsesModal(true, 'guest', 'guest'), false);
  assert.equal(api.pickerUsesModal(true, 'offline', 'offline'), false);
  assert.equal(api.pickerUsesModal(true, 'pair', 'folders'), true);
  assert.match(mainSource, /\$\{pickerModalShouldRender\(\) \? pickerModal\(\) : ''\}/);
  assert.match(mainSource, /function pickerModalShouldRender\(\)\s*\{\s*return pickerUsesModal\(state\.pickerOpen, state\.pickerPurpose, state\.page\);\s*\}/);
  assert.match(mainSource, /const pickerModalOpen = pickerModalShouldRender\(\);/);
});

test('received invitation UI and Tauri commands are absent while sender actions remain wired', () => {
  assert.doesNotMatch(mainSource, /guest_(?:review|open|list|save|close)\b|guestReceived|guestInvitationMarkup|guest-invitation-link|Received invitation|single-use link/i);
  assert.match(mainSource, /SharingController/);
  assert.match(mainSource, /sharingWorkspace\.bind\(app\)/);
  assert.match(mainSource, /if \(noAccountsAvailable\(\) && state\.page !== 'settings'\) return noAccountPage\(\);/);
});

test('sharing workspace replaces the old always-visible invitation form', () => {
  assert.match(mainSource, /function guestSharingPage\(\): string \{ return sharingWorkspace\.render\(\); \}/);
  assert.doesNotMatch(mainSource, /data-guest-form|data-guest-category/);
});
