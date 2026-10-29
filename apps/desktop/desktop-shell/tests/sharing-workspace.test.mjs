import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';

const source = await readFile(new URL('../src/sharing-workspace.ts', import.meta.url), 'utf8');
const output = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } }).outputText;
const compiledUrl = `data:text/javascript;base64,${Buffer.from(output).toString('base64')}`;
const { renderSharingWorkspace, sharingActionFromDataset } = await import(compiledUrl);

const capability = (changes = {}) => ({
  server: 'supported', adapter: 'implemented', accountList: true, itemList: true,
  create: true, edit: true, remove: true, copyLink: true,
  expiration: true, password: false, ...changes
});
const list = (changes = {}) => ({
  status: 'ready', rows: [], coverage: { scope: 'account', complete: true, nextPageAvailable: false }, ...changes
});
const methods = () => ({ people: capability(), links: capability(), guests: capability() });
const props = (changes = {}) => ({
  inventory: 'with-me', creationMethod: null, mode: 'list', capability: capability(), methodCapabilities: methods(),
  list: list(), connected: true, busy: false, canStartShare: true,
  ...changes
});
const row = (changes = {}) => ({
  id: 'grant-1', itemName: 'Trip photos', location: 'Personal / Photos', sharedWith: 'alex@example.test',
  role: 'Can view', expiresAt: null, canEdit: true, canRemove: true, canCopyLink: false, ...changes
});

test('default inventory is Shared with me; inventory tabs replace method tabs and creation is separate', () => {
  const html = renderSharingWorkspace(props());
  assert.match(html, /Shared with me/);
  assert.match(html, /Shared by me/);
  assert.match(html, /Public links/);
  assert.match(html, /id="sharing-tab-with-me"[^>]*tabindex="0"/);
  assert.match(html, /id="sharing-tab-by-me"[^>]*tabindex="-1"/);
  assert.doesNotMatch(html, /People &amp; groups|Guest invitations|data-sharing-action="new-share"/);
  assert.match(html, /No shares have been shared with this account yet|Nothing has been shared with this account yet/);
});

test('New share appears only below Shared by me inventory and opens a separate method chooser', () => {
  const withMe = renderSharingWorkspace(props({ inventory: 'with-me' }));
  const publicLinks = renderSharingWorkspace(props({ inventory: 'public-links' }));
  assert.doesNotMatch(withMe, /data-sharing-action="new-share"/);
  assert.doesNotMatch(publicLinks, /data-sharing-action="new-share"/);
  const byMe = renderSharingWorkspace(props({ inventory: 'by-me', mode: 'list' }));
  assert.match(byMe, /data-sharing-action="new-share">New share/);
  assert.ok(byMe.indexOf('data-sharing-action="new-share"') > byMe.indexOf('sharing-list-actions'));
  const choose = renderSharingWorkspace(props({ inventory: 'by-me', mode: 'choose-method', creationMethod: null }));
  assert.match(choose, /Choose how you want to share a file or folder/);
  assert.match(choose, /data-sharing-method="people"/);
  assert.match(choose, /data-sharing-method="links"/);
  assert.match(choose, /data-sharing-method="guests"/);
  assert.doesNotMatch(choose, /sharing-recipient|sharing-role/);
});

test('method choice disables unsupported methods and names the limitation', () => {
  const html = renderSharingWorkspace(props({
    inventory: 'by-me', mode: 'choose-method', creationMethod: null,
    methodCapabilities: { people: capability({ server: 'unsupported' }), links: capability(), guests: capability({ adapter: 'missing' }) }
  }));
  assert.match(html, /data-sharing-method="people"[^>]*disabled/);
  assert.match(html, /This server does not support this sharing method/);
  assert.match(html, /data-sharing-method="guests"[^>]*disabled/);
  assert.match(html, /Raiun does not manage this sharing method yet/);
});

test('Shared with me rows and details are read-only even if mutation flags are present', () => {
  const listing = renderSharingWorkspace(props({ inventory: 'with-me', list: list({ rows: [row()] }) }));
  assert.match(listing, /Trip photos/);
  assert.match(listing, /sharing-table-header-incoming[^>]*><span>Item<\/span><span>Shared by<\/span>/);
  assert.doesNotMatch(listing, /Unknown access|Access source unknown|Expiration|>None</);
  const details = renderSharingWorkspace(props({ inventory: 'with-me', selectedShare: row(), mode: 'details' }));
  assert.match(details, /Shared by/);
  assert.match(details, /Contact the person who shared it/);
  assert.doesNotMatch(details, /data-sharing-action="edit-access"|data-sharing-action="remove-access"|data-sharing-action="copy-link"/);
});

test('incoming details omit unknown or absent access and expiration fields', () => {
  const html = renderSharingWorkspace(props({
    inventory: 'with-me', mode: 'details', selectedShare: row({ role: null, expiresAt: null, accessSource: 'unknown' })
  }));
  assert.match(html, /<dt>Shared by<\/dt>/);
  assert.doesNotMatch(html, /<dt>Access<\/dt>|<dt>Expiration<\/dt>|Unknown access|Access source unknown|<dd>None<\/dd>/);
});

test('outgoing rows retain management actions only when server metadata allows them', () => {
  const html = renderSharingWorkspace(props({ inventory: 'by-me', list: list({ rows: [row()] }) }));
  assert.match(html, /<div class="sharing-table-header"[^>]*><span>Item<\/span><span>Shared with<\/span><span>Access<\/span><span>Expiration<\/span><span>Actions<\/span>/);
  assert.match(html, /Filter this list \(optional\)/);
  assert.doesNotMatch(html, /Direct access/);
  assert.match(html, /Edit access/);
  assert.match(html, /Remove access/);
  const inherited = renderSharingWorkspace(props({ inventory: 'by-me', list: list({ rows: [row({ accessSource: 'inherited' })] }) }));
  assert.doesNotMatch(inherited, /Edit access|Remove access/);
});

test('inventory scope and partial coverage are stated honestly, not as an empty full list', () => {
  const partial = renderSharingWorkspace(props({ inventory: 'by-me', list: list({
    rows: [row()], coverage: { scope: 'account', complete: false, nextPageAvailable: false }
  }) }));
  assert.match(partial, /Partial list of shares available to this account/);
  assert.match(partial, /Trip photos/);
  assert.doesNotMatch(partial, /Nothing has been shared from this account yet/);
  const itemScoped = renderSharingWorkspace(props({ inventory: 'public-links', list: list({
    coverage: { scope: 'item', itemLabel: 'Project notes', complete: true, nextPageAvailable: false }
  }) }));
  assert.match(itemScoped, /Shares for Project notes/);
  assert.doesNotMatch(itemScoped, /Shares available to this account/);
  assert.doesNotMatch(itemScoped, /Choose file or folder/);
});

test('unsupported, unknown, denied, loading, empty, and refresh-failure states remain distinct', () => {
  const unknown = renderSharingWorkspace(props({ inventoryAvailability: { 'with-me': { status: 'unknown', message: 'Incoming inventory is not confirmed.' } } }));
  assert.match(unknown, /Incoming inventory is not confirmed/);
  const unsupported = renderSharingWorkspace(props({ inventoryAvailability: { 'with-me': { status: 'unsupported', message: 'Incoming list unavailable.' } } }));
  assert.match(unsupported, /Incoming list unavailable/);
  const denied = renderSharingWorkspace(props({ list: list({ status: 'denied', message: 'Access denied' }) }));
  assert.match(denied, /Access denied/);
  assert.match(denied, /role="alert"/);
  const loading = renderSharingWorkspace(props({ list: list({ status: 'loading' }) }));
  assert.match(loading, /Loading shares/);
  assert.doesNotMatch(loading, /Nothing has been shared with this account yet/);
  const empty = renderSharingWorkspace(props({ list: list() }));
  assert.match(empty, /Nothing has been shared with this account yet/);
  const refreshError = renderSharingWorkspace(props({ list: list({ status: 'error', message: 'Refresh failed', rows: [row()] }) }));
  assert.match(refreshError, /Trip photos/);
  assert.match(refreshError, /Refresh failed/);
});

test('created link offers explicit copy without embedding its URL and highlights the row', () => {
  const html = renderSharingWorkspace(props({
    inventory: 'public-links', creationMethod: 'links', capability: capability({ copyLink: true }),
    notice: 'Link created.', createdShareId: 'link-4', highlightedShareId: 'link-4',
    list: list({ rows: [row({ id: 'link-4', sharedWith: 'Anyone with the link', canCopyLink: true })] })
  }));
  assert.match(html, /Link created/);
  assert.match(html, /data-sharing-action="copy-link" data-sharing-id="link-4">Copy link/);
  assert.match(html, /sharing-row-highlighted/);
  assert.doesNotMatch(html, /href=/);
});

test('all row content is escaped and secret URL values are never rendered', () => {
  const secretUrl = 'https://cloud.invalid/share/secret-token';
  const hostile = '<img src=x onerror="bad">';
  const html = renderSharingWorkspace(props({
    inventory: 'public-links', list: list({ rows: [row({
      itemName: hostile, location: hostile, sharedWith: hostile, role: hostile, url: secretUrl, canCopyLink: true
    })] })
  }));
  assert.match(html, /&lt;img src=x onerror=&quot;bad&quot;&gt;/);
  assert.doesNotMatch(html, /<img src=x/);
  assert.doesNotMatch(html, /secret-token|href=/);
});

test('unknown source, role, and invitation state remain explicit', () => {
  const html = renderSharingWorkspace(props({
    inventory: 'by-me', mode: 'details', selectedShare: row({ role: null, accessSource: 'unknown', serverState: 'unknown' })
  }));
  assert.match(html, /Unknown access/);
  assert.match(html, /Access source unknown/);
  assert.match(html, /Status unknown/);
  assert.doesNotMatch(html, />Accepted</);
  assert.match(html, /does not delete the file or folder/);
  assert.doesNotMatch(html, /data-sharing-action="remove-access"/);
});

test('public link copy remains available when mutation source is unknown', () => {
  const html = renderSharingWorkspace(props({
    inventory: 'public-links', mode: 'details', capability: capability({ copyLink: true, edit: false, remove: false }),
    selectedShare: row({ id: 'link-8', role: 'Can view', accessSource: 'unknown', canEdit: false, canRemove: false, canCopyLink: true })
  }));
  assert.match(html, /data-sharing-action="copy-link" data-sharing-id="link-8">Copy link/);
  assert.doesNotMatch(html, /data-sharing-action="remove-access"|data-sharing-action="edit-access"/);
});

test('details view shows copy confirmation and errors without enabling incoming mutations', () => {
  const rowData = row({ accessSource: 'unknown', canEdit: false, canRemove: false, canCopyLink: true });
  const success = renderSharingWorkspace(props({
    inventory: 'public-links', mode: 'details', selectedShare: rowData, notice: 'Link copied.'
  }));
  assert.match(success, /Link copied/);
  assert.match(success, /role="status"/);
  const failure = renderSharingWorkspace(props({
    inventory: 'public-links', mode: 'details', selectedShare: rowData,
    list: list({ message: 'Could not copy the link. Try again.' })
  }));
  assert.match(failure, /Could not copy the link\. Try again\./);
  assert.match(failure, /role="alert"/);
  const incoming = renderSharingWorkspace(props({
    inventory: 'with-me', mode: 'details', selectedShare: row({ canCopyLink: true }), notice: 'Read only notice.'
  }));
  assert.match(incoming, /Read only notice/);
  assert.doesNotMatch(incoming, /data-sharing-action="copy-link"|data-sharing-action="remove-access"|data-sharing-action="edit-access"/);
});

test('item chooser remains a separate step after method selection, with guest root and encryption restrictions', () => {
  const method = renderSharingWorkspace(props({ inventory: 'by-me', mode: 'choose-method', creationMethod: null }));
  assert.match(method, /data-sharing-action="choose-method" data-sharing-method="guests"/);
  const html = renderSharingWorkspace(props({
    inventory: 'by-me', creationMethod: 'guests', mode: 'choose-item', spaces: [{ id: 'p', label: 'Personal', encrypted: false }], spaceId: 'p',
    entries: [
      { id: 'root', name: 'Personal', path: '/', isFolder: true },
      { id: 'enc', name: 'Encrypted folder', path: '/Locked', isFolder: true, encrypted: true },
      { id: 'file', name: 'Notes', path: '/Notes.txt', isFolder: false }
    ]
  }));
  assert.match(html, /Space roots cannot be shared with guests/);
  assert.match(html, /Encrypted items cannot be shared here/);
  assert.match(html, /data-sharing-item-id="root"[^>]*disabled/);
  assert.match(html, /data-sharing-item-id="enc"[^>]*disabled/);
  assert.match(html, /data-sharing-action="use-item" disabled/);
});

test('access settings keep server-derived roles and required policy fields', () => {
  const item = { id: 'f1', name: 'Trip photos', location: 'Personal / Photos', path: '/Photos', isFolder: true };
  const base = props({
    inventory: 'by-me', creationMethod: 'links', mode: 'settings', selectedItem: item,
    capability: capability({ password: true }), roles: [{ id: 'viewer', name: 'Can view' }], roleId: 'viewer',
    linkName: 'Family', passwordRequired: true, passwordPresent: false, passwordLengthValid: true, passwordPolicyKnown: true, expirationRequired: true, expiry: ''
  });
  const requiredEmpty = renderSharingWorkspace(base);
  assert.match(requiredEmpty, /id="sharing-password"[^>]*required/);
  assert.match(requiredEmpty, /id="sharing-expiry"[^>]*required/);
  assert.match(requiredEmpty, /data-sharing-action="save-access" disabled/);
  assert.match(requiredEmpty, /Anyone with this link and its password can use the access shown for Trip photos\./);
  assert.equal(requiredEmpty.match(/Anyone with this link and its password can use/g)?.length, 1);
  assert.doesNotMatch(requiredEmpty, /sharing-disclosure|Anyone who obtains this link/);
  const valid = renderSharingWorkspace({ ...base, passwordPresent: true, expiry: '2035-01-01T10:00' });
  assert.match(valid, /data-sharing-action="save-access"[^>]*>Create link/);
  assert.match(valid, /autocomplete="new-password"[^>]*maxlength="72"[^>]*required/);
  assert.match(valid, /Recipients need this password; Raiun does not save it locally/);
  assert.equal(valid.match(/Anyone with this link and its password can use/g)?.length, 1);
  assert.doesNotMatch(valid, /sharing-disclosure|Anyone who obtains this link/);
  assert.doesNotMatch(valid, /value="[^"]*"[^>]*id="sharing-password"|synthetic-only/);
  const disconnected = renderSharingWorkspace({ ...base, connected: false, passwordPresent: true, expiry: '2035-01-01T10:00' });
  assert.match(disconnected, /data-sharing-action="save-access" disabled/);
  const unknown = renderSharingWorkspace({ ...base, passwordPolicyKnown: false, passwordPresent: true, expiry: '2035-01-01T10:00' });
  assert.match(unknown, /password requirements .* unknown/i);
  assert.match(unknown, /data-sharing-action="save-access" disabled/);
});

test('optional unprotected public link renders only its item-specific access disclosure', () => {
  const html = renderSharingWorkspace(props({
    inventory: 'by-me', creationMethod: 'links', mode: 'settings',
    selectedItem: { id: 'f1', name: 'Notes', location: 'Personal', path: '/Notes.txt', isFolder: false },
    capability: capability({ password: true }), roles: [{ id: 'view', name: 'Can view' }], roleId: 'view',
    linkName: 'Notes link', passwordRequired: false, passwordPolicyKnown: true, passwordPresent: false
  }));
  assert.match(html, /Anyone who obtains this link may use it with the access shown for Notes\./);
  assert.equal(html.match(/Anyone who obtains this link may use it with the access shown/g)?.length, 1);
  assert.doesNotMatch(html, /class="sharing-disclosure"/);
});

test('People & groups requires a selected server result and identifies its kind', () => {
  const item = { id: 'f1', name: 'Project brief', location: 'Team / Documents', path: '/Documents/brief.pdf', isFolder: false };
  const html = renderSharingWorkspace(props({
    inventory: 'by-me', creationMethod: 'people', mode: 'settings', selectedItem: item,
    roles: [{ id: 'reader', name: 'Can view' }], roleId: 'reader',
    recipientQuery: 'ops', recipientResults: [{ id: 'group-1', label: 'Operations', kind: 'group', secondary: 'ops@example.test' }],
    recipientSelectedId: 'group-1'
  }));
  assert.match(html, /Person or group/);
  assert.match(html, /Operations/);
  assert.match(html, /Group · ops@example.test/);
  assert.match(html, /This gives Operations Can view access to Project brief/);
  assert.match(html, /data-sharing-action="save-access"[^>]*>Share/);
});

test('edit keeps ordinary recipients and the target fixed', () => {
  const item = { id: 'f1', name: 'Trip photos', location: 'Personal / Photos', path: '/Photos', isFolder: true };
  const html = renderSharingWorkspace(props({
    inventory: 'by-me', creationMethod: 'guests', mode: 'edit', selectedItem: item,
    selectedShare: row({ sharedWith: 'alex@example.test' }), roles: [{ id: 'editor', name: 'Can edit' }], roleId: 'editor'
  }));
  assert.match(html, /alex@example\.test/);
  assert.doesNotMatch(html, /id="sharing-recipient"|data-sharing-action="change-item"/);
  assert.match(html, /data-sharing-action="save-access"[^>]*>Save changes/);
  assert.doesNotMatch(html, /sends an invitation email|Send invitation/);
});

test('link editing exposes only enabled name, access and expiration fields and preserves the existing link/password', () => {
  const item = { id: 'f1', name: 'Trip photos', location: 'Personal / Photos', path: '/Photos', isFolder: true };
  const html = renderSharingWorkspace(props({
    inventory: 'public-links', creationMethod: 'links', mode: 'edit', selectedItem: item,
    selectedShare: row({ id: 'link-2', sharedWith: 'Anyone with the link', role: 'Can view', expiresAt: '2035-01-01T10:00:00Z', canCopyLink: true }),
    roles: [{ id: 'view', name: 'Can view' }, { id: 'edit', name: 'Can edit' }], roleId: 'view',
    linkName: 'Family photos', expiry: '2035-01-01T10:00',
    editableFields: { access: true, expiration: true, name: true }
  }));
  assert.match(html, /<h2 tabindex="-1">Edit share<\/h2>/);
  assert.match(html, /id="sharing-link-name"[^>]*value="Family photos"/);
  assert.match(html, /id="sharing-role"/);
  assert.match(html, /id="sharing-expiry"/);
  assert.match(html, /Its current link and password are kept/);
  assert.match(html, /data-sharing-action="save-access"[^>]*>Save changes/);
  assert.doesNotMatch(html, /id="sharing-password"|data-sharing-action="change-item"/);
});

test('uneditable or unknown link fields stay fixed and cannot be overwritten', () => {
  const html = renderSharingWorkspace(props({
    inventory: 'public-links', creationMethod: 'links', mode: 'edit',
    selectedItem: { id: 'f1', name: 'Report', location: 'Personal', path: '/Report', isFolder: false },
    selectedShare: row({ id: 'link-3', role: null, expiresAt: null, accessSource: 'unknown', canEdit: true, canRemove: false }),
    capability: capability({ edit: true, expiration: false }), roles: [], roleId: '', linkName: 'Existing label',
    editableFields: { access: false, expiration: false, name: false }
  }));
  assert.match(html, /Access level unknown/);
  assert.match(html, /Existing label/);
  assert.match(html, />None<\/b>/);
  assert.doesNotMatch(html, /id="sharing-role"|id="sharing-expiry"|id="sharing-link-name"|id="sharing-password"/);
  assert.match(html, /data-sharing-action="save-access" disabled/);
});

test('unknown mutation outcome blocks another submission and asks for refresh', () => {
  const html = renderSharingWorkspace(props({
    inventory: 'by-me', creationMethod: 'guests', mode: 'settings',
    selectedItem: { id: 'f', name: 'Notes', location: 'Personal', path: '/Notes', isFolder: false },
    roles: [{ id: 'viewer', name: 'Can view' }], roleId: 'viewer', recipient: 'alex@example.test', outcomeUnknown: true,
    validationMessage: 'Could not confirm the result. Refresh before trying again.'
  }));
  assert.match(html, /Could not confirm the result\. Refresh before trying again/);
  assert.equal(html.split('Could not confirm the result. Refresh before trying again').length - 1, 1);
  assert.match(html, /data-sharing-action="refresh"[^>]*>Refresh/);
  assert.match(html, /data-sharing-action="save-access" disabled/);
});

test('action decoder validates inventory, method and row identifiers', () => {
  assert.deepEqual(sharingActionFromDataset({ sharingAction: 'set-inventory', sharingInventory: 'with-me' }), { type: 'set-inventory', inventory: 'with-me' });
  assert.deepEqual(sharingActionFromDataset({ sharingAction: 'choose-method', sharingMethod: 'guests' }), { type: 'choose-method', method: 'guests' });
  assert.deepEqual(sharingActionFromDataset({ sharingAction: 'set-section', sharingSection: 'guests' }), { type: 'set-section', section: 'guests' });
  assert.deepEqual(sharingActionFromDataset({ sharingAction: 'show-details', sharingId: 'grant-2' }), { type: 'show-details', shareId: 'grant-2' });
  assert.equal(sharingActionFromDataset({ sharingAction: 'set-inventory', sharingInventory: 'untrusted' }), null);
  assert.equal(sharingActionFromDataset({ sharingAction: 'choose-method', sharingMethod: 'untrusted' }), null);
  assert.equal(sharingActionFromDataset({ sharingAction: 'remove-access' }), null);
});
