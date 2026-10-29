export type SharingSection = 'people' | 'links' | 'guests';
export type SharingInventory = 'with-me' | 'by-me' | 'public-links';
export type SharingMode = 'list' | 'choose-method' | 'lookup-item' | 'choose-item' | 'settings' | 'details' | 'edit';
export type SharingMethodCapability = {
  server: 'supported' | 'unsupported' | 'unknown';
  adapter: 'implemented' | 'missing';
  accountList: boolean;
  itemList: boolean;
  create: boolean;
  edit: boolean;
  remove: boolean;
  copyLink: boolean;
  expiration: boolean;
  password: boolean;
};
export type SharingCoverage = {
  scope: 'account' | 'item' | 'recently-managed' | null;
  itemLabel?: string;
  complete: boolean;
  nextPageAvailable: boolean;
};
export type SharingRow = {
  id: string;
  itemName: string;
  location: string;
  sharedWith: string;
  role: string | null;
  expiresAt: string | null;
  serverState?: 'pending' | 'accepted' | 'unknown';
  accessSource?: 'direct' | 'inherited' | 'unknown';
  canEdit: boolean;
  canRemove: boolean;
  canCopyLink: boolean;
};
export type SharingList = {
  status: 'idle' | 'loading' | 'ready' | 'error' | 'denied' | 'unavailable';
  rows: readonly SharingRow[];
  coverage: SharingCoverage;
  message?: string;
  refreshing?: boolean;
};
export type SharingSpace = { id: string; label: string; encrypted: boolean };
export type SharingBrowserEntry = { id: string; name: string; path: string; isFolder: boolean; encrypted?: boolean; shareable?: boolean };
export type SharingRole = { id: string; name: string; explanation?: string };
export type SharingRecipientOption = { id: string; label: string; kind: 'person' | 'group'; secondary?: string };
export type SharingItem = { id: string; name: string; location: string; path: string; isFolder: boolean; encrypted?: boolean; shareable?: boolean };
export type SharingAction =
  | { type: 'set-inventory'; inventory: SharingInventory }
  | { type: 'choose-method'; method: SharingSection }
  | { type: 'set-section'; section: SharingSection }
  | { type: 'new-share' }
  | { type: 'choose-item' }
  | { type: 'cancel' }
  | { type: 'continue' }
  | { type: 'change-item' }
  | { type: 'open-folder'; itemId: string }
  | { type: 'open-parent' }
  | { type: 'refresh-items' }
  | { type: 'select-item'; itemId: string }
  | { type: 'choose-recipient'; recipientId: string }
  | { type: 'use-item' }
  | { type: 'view-item-shares' }
  | { type: 'show-details'; shareId: string }
  | { type: 'edit-access'; shareId: string }
  | { type: 'remove-access'; shareId: string }
  | { type: 'copy-link'; shareId: string }
  | { type: 'save-access' }
  | { type: 'refresh' }
  | { type: 'load-more' };

export type SharingWorkspaceProps = {
  inventory?: SharingInventory;
  creationMethod?: SharingSection | null;
  /** Legacy adapter input while the controller migrates from method tabs to inventory tabs. */
  section?: SharingSection;
  mode: SharingMode;
  capability: SharingMethodCapability;
  methodCapabilities?: Partial<Record<SharingSection, SharingMethodCapability>>;
  canStartShare?: boolean;
  inventoryAvailability?: Partial<Record<SharingInventory, { status: 'available' | 'unsupported' | 'unknown'; message?: string }>>;
  list: SharingList;
  connected: boolean;
  busy: boolean;
  query?: string;
  locationFilter?: string;
  locations?: readonly { id: string; label: string }[];
  spaces?: readonly SharingSpace[];
  spaceId?: string;
  currentPath?: string;
  entries?: readonly SharingBrowserEntry[];
  selectedEntryId?: string;
  selectedItem?: SharingItem | null;
  selectedShare?: SharingRow | null;
  editableFields?: { access?: boolean; expiration?: boolean; name?: boolean };
  roles?: readonly SharingRole[];
  roleId?: string;
  recipient?: string;
  linkName?: string;
  expiry?: string;
  passwordRequired?: boolean;
  expirationRequired?: boolean;
  password?: string;
  recipientQuery?: string;
  recipientResults?: readonly SharingRecipientOption[];
  recipientSearchStatus?: 'idle' | 'loading' | 'ready' | 'error';
  recipientSelectedId?: string;
  outcomeUnknown?: boolean;
  createdShareId?: string;
  highlightedShareId?: string;
  validationMessage?: string;
  notice?: string;
};

const sections: readonly { id: SharingSection; label: string; description: string }[] = [
  { id: 'people', label: 'People & groups', description: 'Give people or groups on this server access to a file or folder.' },
  { id: 'links', label: 'Share links', description: 'Create a link to a file or folder. Anyone with the link may gain the access you allow.' },
  { id: 'guests', label: 'Guest invitations', description: 'Invite someone by email to open a file or folder in their browser.' }
];
const inventories: readonly { id: SharingInventory; label: string; description: string }[] = [
  { id: 'with-me', label: 'Shared with me', description: 'Files and folders other people have shared with this account.' },
  { id: 'by-me', label: 'Shared by me', description: 'Access this account has shared with other people.' },
  { id: 'public-links', label: 'Public links', description: 'Links that allow access to files or folders.' }
];
const esc = (value: unknown): string => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]!);
const pluralName: Record<SharingSection, string> = { people: 'people and group shares', links: 'share links', guests: 'guest invitations' };
const methodHeading: Record<SharingSection, string> = { people: 'Share with people', links: 'New share link', guests: 'New guest invitation' };
const finalAction: Record<SharingSection, string> = { people: 'Share', links: 'Create link', guests: 'Send invitation' };
const inventoryFor = (props: SharingWorkspaceProps): SharingInventory => props.inventory || 'with-me';
const methodFor = (props: SharingWorkspaceProps): SharingSection => props.creationMethod || props.section || 'guests';

function capabilityMessage(capability: SharingMethodCapability): string {
  if (capability.server === 'unsupported') return 'This server does not support this sharing method.';
  if (capability.server === 'unknown') return 'Server support for this sharing method has not been confirmed.';
  if (capability.adapter === 'missing') return 'Raiun does not manage this sharing method yet.';
  return 'This sharing method is not available for this account.';
}
function coverageLabel(coverage: SharingCoverage): string {
  if (coverage.scope === 'account') return coverage.complete ? 'Shares available to this account' : 'Partial list of shares available to this account';
  if (coverage.scope === 'item') return `Shares for ${coverage.itemLabel || 'the selected file or folder'}`;
  if (coverage.scope === 'recently-managed') return 'Recently managed items · not a complete account list';
  return 'Shares for a file or folder';
}
function formatExpiry(value: string | null): string {
  if (!value) return 'None';
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return 'Unknown';
  if (date.getTime() <= Date.now()) return `Expired · ${date.toLocaleDateString()}`;
  return date.toLocaleDateString();
}
function sectionHeader(props: SharingWorkspaceProps): string {
  const inventory = inventoryFor(props);
  const selected = inventories.find(item => item.id === inventory)!;
  const tabs = inventories.map(item => {
    const availability = props.inventoryAvailability?.[item.id];
    const unavailable = availability?.status === 'unsupported';
    return `<button type="button" id="sharing-tab-${item.id}" class="sharing-tab ${item.id === inventory ? 'active' : ''}" role="tab" tabindex="${item.id === inventory ? '0' : '-1'}" aria-selected="${item.id === inventory}" aria-controls="sharing-panel" ${unavailable ? `aria-label="${esc(item.label)}. ${esc(availability.message || 'This list is not available.') }"` : ''} data-sharing-action="set-inventory" data-sharing-inventory="${item.id}">${esc(item.label)}</button>`;
  }).join('');
  return `<header class="sharing-heading"><div><div class="eyebrow">SHARING</div><h1>Sharing</h1><p class="lede">Review access to files and folders in this account.</p></div></header><div class="sharing-section-tabs" role="tablist" aria-label="Share inventory">${tabs}</div><section class="sharing-section-intro"><h2>${esc(selected.label)}</h2><p>${esc(selected.description)}</p></section>`;
}
function listToolbar(props: SharingWorkspaceProps): string {
  const locationOptions = (props.locations || []).map(item => `<option value="${esc(item.id)}" ${item.id === props.locationFilter ? 'selected' : ''}>${esc(item.label)}</option>`).join('');
  return `<div class="sharing-list-toolbar"><div class="sharing-search-field"><label for="sharing-search">Filter this list (optional)</label><input id="sharing-search" type="search" autocomplete="off" value="${esc(props.query)}" data-sharing-field="query"></div>${props.locations?.length ? `<div class="sharing-location-field"><label for="sharing-location">Location</label><select id="sharing-location" data-sharing-field="location"><option value="">All locations</option>${locationOptions}</select></div>` : ''}</div>`;
}
function unavailableList(props: SharingWorkspaceProps): string {
  const inventory = inventoryFor(props);
  const availability = props.inventoryAvailability?.[inventory];
  if (availability?.status === 'unsupported' || availability?.status === 'unknown') return `<div class="sharing-state" role="status">${esc(availability.message || (availability.status === 'unknown' ? 'This share list is not available yet.' : 'This share list is not supported.'))}</div>`;
  if (props.list.status === 'denied') return `<div class="sharing-state sharing-state-error" role="alert">${esc(props.list.message || 'You do not have permission to list these shares.')}</div>`;
  if (props.list.status === 'unavailable') return `<div class="sharing-state" role="status">${esc(props.list.message || 'Share listing is unavailable for this scope.')}</div>`;
  if (props.list.status === 'error') return `<div class="sharing-state sharing-state-error" role="alert">${esc(props.list.message || 'Could not load shares. Refresh to try again.')}</div>`;
  if (!props.capability.accountList && !props.capability.itemList && props.list.status !== 'ready') return '<div class="sharing-state" role="status">Raiun cannot list existing shares for this scope yet.</div>';
  if (props.list.status === 'idle' && (props.capability.accountList || (props.capability.itemList && props.list.coverage.scope === 'item'))) return '<div class="sharing-state" role="status">Refresh to load existing shares.</div>';
  return '';
}
function rowMenu(row: SharingRow, capability: SharingMethodCapability): string {
  const mutable = row.accessSource !== 'inherited' && row.accessSource !== 'unknown';
  const actions = `${mutable && row.canEdit && capability.edit ? `<button type="button" data-sharing-action="edit-access" data-sharing-id="${esc(row.id)}">Edit access</button>` : ''}${row.canCopyLink && capability.copyLink ? `<button type="button" data-sharing-action="copy-link" data-sharing-id="${esc(row.id)}">Copy link</button>` : ''}${mutable && row.canRemove && capability.remove ? `<button type="button" class="sharing-danger-action" data-sharing-action="remove-access" data-sharing-id="${esc(row.id)}">Remove access</button>` : ''}`;
  return actions ? `<details class="sharing-row-actions"><summary aria-label="More actions for ${esc(row.itemName)}">More actions</summary><div>${actions}</div></details>` : '';
}
function shareRow(row: SharingRow, capability: SharingMethodCapability, highlightedShareId?: string, readOnly = false, incoming = false): string {
  const status = row.serverState ? `<span class="sharing-status">${row.serverState === 'pending' ? 'Pending' : row.serverState === 'accepted' ? 'Accepted' : 'Status unknown'}</span>` : '';
  const source = row.accessSource === 'inherited' ? '<small>Inherited access</small>' : row.accessSource === 'unknown' ? '<small>Access source unknown</small>' : '';
  const safeRow = readOnly ? { ...row, canEdit: false, canRemove: false, canCopyLink: false } : row;
  const item = `<div class="sharing-item-cell"><span class="sharing-cell-label">Item</span><button type="button" class="sharing-item-link" data-sharing-action="show-details" data-sharing-id="${esc(row.id)}">${esc(row.itemName)}</button><small>${esc(row.location)}</small></div>`;
  const recipient = `<div class="sharing-recipient-cell"><span class="sharing-cell-label">${incoming ? 'Shared by' : 'Shared with'}</span><span>${esc(row.sharedWith)}</span></div>`;
  if (incoming) return `<article class="sharing-row sharing-row-incoming ${row.id === highlightedShareId ? 'sharing-row-highlighted' : ''}">${item}${recipient}</article>`;
  return `<article class="sharing-row ${row.id === highlightedShareId ? 'sharing-row-highlighted' : ''}">${item}${recipient}<div class="sharing-access-cell"><span class="sharing-cell-label">Access</span><span>${esc(row.role || 'Unknown access')}</span>${source}${status}</div><div class="sharing-expiry-cell"><span class="sharing-cell-label">Expiration</span><span>${esc(formatExpiry(row.expiresAt))}</span></div><div class="sharing-actions-cell">${rowMenu(safeRow, capability)}</div></article>`;
}
function listPanel(props: SharingWorkspaceProps): string {
  const { list, capability } = props;
  const inventory = inventoryFor(props);
  const readOnly = inventory === 'with-me';
  const unavailable = unavailableList(props);
  const canRenderRows = capability.adapter === 'implemented' && props.inventoryAvailability?.[inventory]?.status !== 'unsupported' && props.inventoryAvailability?.[inventory]?.status !== 'unknown';
  const emptyCopy = inventory === 'with-me'
    ? 'Nothing has been shared with this account yet.'
    : inventory === 'public-links'
      ? 'No public links yet.'
      : list.coverage.scope === 'recently-managed'
    ? 'No recently managed shares are recorded. This is not a complete account list.'
    : 'Nothing has been shared from this account yet.';
  const content = canRenderRows && list.rows.length
    ? `<div class="sharing-rows" aria-label="${esc(inventories.find(item => item.id === inventory)?.label)}">${inventory === 'with-me' ? '<div class="sharing-table-header sharing-table-header-incoming" aria-hidden="true"><span>Item</span><span>Shared by</span></div>' : '<div class="sharing-table-header" aria-hidden="true"><span>Item</span><span>Shared with</span><span>Access</span><span>Expiration</span><span>Actions</span></div>'}${list.rows.map(row => shareRow(row, capability, props.highlightedShareId, readOnly, readOnly)).join('')}</div>`
    : canRenderRows && list.status === 'ready' && list.coverage.complete && list.coverage.scope
      ? `<div class="sharing-empty" role="status"><b>${esc(emptyCopy)}</b></div>`
      : canRenderRows && list.status === 'ready' && list.coverage.nextPageAvailable
        ? '<div class="sharing-state" role="status">No shares on this page. More results are available.</div>'
        : '';
  const coverage = list.coverage.scope ? `<p class="sharing-coverage">${esc(coverageLabel(list.coverage))}${list.coverage.nextPageAvailable ? ' · More results available' : ''}</p>` : `<p class="sharing-coverage">${esc(coverageLabel(list.coverage))}</p>`;
  const canRefresh = capability.adapter === 'implemented' && capability.server === 'supported' && (capability.accountList || (capability.itemList && list.coverage.scope === 'item'));
  const refresh = canRefresh ? `<button type="button" class="button subtle" data-sharing-action="refresh" ${props.busy || list.refreshing ? 'disabled' : ''}>${list.refreshing ? 'Refreshing…' : 'Refresh'}</button>` : '';
  const loadMore = list.coverage.nextPageAvailable ? `<button type="button" class="button subtle" data-sharing-action="load-more" ${props.busy ? 'disabled' : ''}>Load more shares</button>` : '';
  const loading = list.status === 'loading' ? '<p class="sharing-loading" role="status">Loading shares…</p>' : '';
  const retainedError = (!canRenderRows || ['error', 'denied', 'unavailable'].includes(list.status)) && list.rows.length ? unavailable : '';
  const newShare = inventory === 'by-me' && props.mode === 'list' && (props.canStartShare ?? (props.methodCapabilities ? Object.values(props.methodCapabilities).some(cap => cap?.server === 'supported' && cap.adapter === 'implemented' && cap.create) : capability.server === 'supported' && capability.create))
    ? '<div class="sharing-new-share"><p>Share a file or folder with people, create a link, or invite a guest.</p><button type="button" class="button primary" data-sharing-action="new-share">New share</button></div>' : '';
  return `${listToolbar(props)}${coverage}${loading}${retainedError}${!list.rows.length || !canRenderRows ? unavailable : ''}${content}<div class="sharing-list-actions">${refresh}${loadMore}</div>${newShare}`;
}
function itemChooser(props: SharingWorkspaceProps): string {
  const method = methodFor(props);
  const spaces = (props.spaces || []).map(space => `<option value="${esc(space.id)}" ${space.id === props.spaceId ? 'selected' : ''} ${space.encrypted ? 'disabled' : ''}>${esc(space.label)}${space.encrypted ? ' · encrypted' : ''}</option>`).join('');
  const selectedSpaceEncrypted = (props.spaces || []).find(space => space.id === props.spaceId)?.encrypted === true;
  const entries = (props.entries || []).map(entry => {
    const guestRoot = method === 'guests' && entry.isFolder && (entry.path === '/' || entry.path === '');
    const excluded = entry.encrypted === true || entry.shareable === false || (method === 'guests' && selectedSpaceEncrypted) || guestRoot;
    const selected = entry.id === props.selectedEntryId;
    const select = `<button type="button" class="sharing-select-item" data-sharing-action="select-item" data-sharing-item-id="${esc(entry.id)}" aria-label="${selected ? 'Selected' : 'Choose'} ${entry.isFolder ? 'folder' : 'file'} ${esc(entry.name)}" aria-pressed="${selected}" ${excluded ? 'disabled' : ''}>${selected ? 'Selected' : 'Choose'} ${entry.isFolder ? 'folder' : 'file'}</button>`;
    const open = entry.isFolder ? `<button type="button" class="sharing-open-folder" data-sharing-action="open-folder" data-sharing-item-id="${esc(entry.id)}" aria-label="Open folder ${esc(entry.name)}" ${excluded ? 'disabled' : ''}>Open folder</button>` : '';
    const reason = guestRoot ? 'Space roots cannot be shared with guests.' : entry.encrypted || selectedSpaceEncrypted ? 'Encrypted items cannot be shared here.' : entry.shareable === false ? 'This item is not available to share.' : '';
    return `<div class="sharing-browser-row"><span><b>${esc(entry.name)}</b><small>${esc(entry.path)}${reason ? ` · ${reason}` : ''}</small></span><div>${open}${select}</div></div>`;
  }).join('');
  const selected = props.selectedItem ? `<p class="sharing-selection-summary" role="status">Selected ${props.selectedItem.isFolder ? 'folder' : 'file'}: <b>${esc(props.selectedItem.name)}</b><span>${esc(props.selectedItem.location)}</span></p>` : '';
  const selectedGuestRoot = method === 'guests' && !!props.selectedItem?.isFolder && (props.selectedItem.path === '/' || props.selectedItem.path === '');
  const selectedEligible = !!props.selectedItem && props.selectedItem.shareable !== false && props.selectedItem.encrypted !== true && !selectedGuestRoot;
  const canContinue = selectedEligible && !props.busy;
  const isLookup = props.mode === 'lookup-item';
  const sectionHeading = isLookup ? 'Choose a file or folder' : methodHeading[method];
  return `<section class="sharing-flow"><h2 tabindex="-1">${esc(sectionHeading)}</h2><p>${isLookup ? 'Shares are listed only for this selected file or folder.' : 'Choose a file or folder in an unencrypted location.'}</p><div class="sharing-space-field"><label for="sharing-space">Location</label><select id="sharing-space" data-sharing-field="space" ${props.busy ? 'disabled' : ''}><option value="">Choose a location</option>${spaces}</select><span>${esc((props.spaces || []).find(space => space.id === props.spaceId)?.label || '')}</span></div><div class="sharing-breadcrumb"><span>${esc(props.currentPath || 'Choose a location')}</span><div><button type="button" class="button subtle" data-sharing-action="open-parent">Up one folder</button><button type="button" class="button subtle" data-sharing-action="refresh-items" ${props.busy ? 'disabled' : ''}>Refresh items</button></div></div>${props.list.status === 'loading' ? '<p class="sharing-loading" role="status">Loading files and folders…</p>' : ''}${props.list.status === 'error' || props.list.status === 'denied' ? `<p class="sharing-state-error" role="alert">${esc(props.list.message || 'Could not load this location.')}</p>` : ''}<div class="sharing-browser-list">${entries || (props.list.status === 'ready' ? '<p class="sharing-empty">No files or folders in this location.</p>' : '')}</div>${selected}<div class="sharing-flow-actions"><button type="button" class="button subtle" data-sharing-action="cancel" ${props.busy ? 'disabled' : ''}>Cancel</button><button type="button" class="button primary" data-sharing-action="${isLookup ? 'view-item-shares' : 'use-item'}" ${!canContinue ? 'disabled' : ''}>${isLookup ? 'View shares' : props.selectedItem?.isFolder ? 'Use this folder' : 'Use this file'}</button></div></section>`;
}
function methodChoice(props: SharingWorkspaceProps): string {
  const available = (method: SharingSection) => {
    const cap = props.methodCapabilities?.[method] || (method === methodFor(props) ? props.capability : undefined);
    return !!cap && cap.server === 'supported' && cap.adapter === 'implemented' && cap.create;
  };
  const choices = sections.map(item => `<button type="button" class="sharing-method-choice" data-sharing-action="choose-method" data-sharing-method="${item.id}" aria-pressed="${props.creationMethod === item.id}" ${available(item.id) ? '' : 'disabled'}><b>${esc(item.label)}</b><span>${esc(item.description)}</span>${available(item.id) ? '' : `<small>${esc(capabilityMessage(props.methodCapabilities?.[item.id] || props.capability))}</small>`}</button>`).join('');
  const any = sections.some(item => available(item.id));
  return `<section class="sharing-flow sharing-method-picker"><h2 tabindex="-1">New share</h2><p>Choose how you want to share a file or folder.</p><div class="sharing-method-choices" role="group" aria-label="Sharing method">${choices}</div>${any ? '' : '<p class="sharing-state" role="status">No sharing method is available for this account.</p>'}<div class="sharing-flow-actions"><button type="button" class="button subtle" data-sharing-action="cancel">Cancel</button></div></section>`;
}
function accessForm(props: SharingWorkspaceProps): string {
  const method = methodFor(props);
  const editing = props.mode === 'edit';
  const editable = {
    access: props.editableFields?.access ?? props.capability.edit,
    expiration: props.editableFields?.expiration ?? props.capability.expiration,
    name: props.editableFields?.name ?? (method === 'links' && props.capability.edit)
  };
  const roles = (props.roles || []).map(role => `<option value="${esc(role.id)}" ${role.id === props.roleId ? 'selected' : ''}>${esc(role.name)}</option>`).join('');
  const roleAvailable = !!props.roles?.length;
  const item = props.selectedItem;
  if (!item) return '<div class="sharing-state" role="alert">Choose a file or folder before setting access.</div>';
  if (item.shareable === false || item.encrypted === true || (method === 'guests' && item.isFolder && (item.path === '/' || item.path === ''))) return '<div class="sharing-state" role="status">This item cannot be shared with the selected method.</div>';
  if (props.capability.server !== 'supported' || props.capability.adapter !== 'implemented' || !(props.mode === 'edit' ? props.capability.edit : props.capability.create)) return `<div class="sharing-state" role="status">${esc(capabilityMessage(props.capability))}</div>`;
  const peopleSearch = method === 'people'
    ? `<label for="sharing-recipient">Person or group</label><input id="sharing-recipient" type="search" autocomplete="off" value="${esc(props.recipientQuery ?? props.recipient)}" ${props.busy ? 'disabled' : ''} data-sharing-field="recipient-query">${props.recipientSearchStatus === 'loading' ? '<p class="sharing-loading" role="status">Searching people and groups…</p>' : ''}${props.recipientSearchStatus === 'error' ? '<p class="sharing-state-error" role="alert">Could not search people and groups.</p>' : ''}${props.recipientResults?.length ? `<ul class="sharing-recipient-results" aria-label="People and groups">${props.recipientResults.map(result => `<li><button type="button" data-sharing-action="choose-recipient" data-sharing-recipient-id="${esc(result.id)}" aria-pressed="${props.recipientSelectedId === result.id}" ${props.busy ? 'disabled' : ''}><span>${esc(result.label)}</span><small>${result.kind === 'group' ? 'Group' : 'Person'}${result.secondary ? ` · ${esc(result.secondary)}` : ''}</small></button></li>`).join('')}</ul>` : ''}${props.recipientSelectedId ? `<input type="hidden" value="${esc(props.recipientSelectedId)}" data-sharing-field="recipient-id">` : ''}`
    : '';
  const recipientField = editing && method === 'links'
    ? (editable.name
      ? `<label for="sharing-link-name">Link name</label><input id="sharing-link-name" type="text" required value="${esc(props.linkName)}" ${props.busy ? 'disabled' : ''} data-sharing-field="link-name">`
      : `<div class="sharing-fixed-recipient"><span>Link name</span><b>${esc(props.linkName || props.selectedShare?.itemName || 'Existing link')}</b></div>`)
    : editing
    ? `<div class="sharing-fixed-recipient"><span>Shared with</span><b>${esc(props.selectedShare?.sharedWith || props.recipient || 'Unknown recipient')}</b></div>`
    : method === 'guests'
    ? `<label for="sharing-recipient">Email address</label><input id="sharing-recipient" type="email" required autocomplete="email" value="${esc(props.recipient)}" ${props.busy ? 'disabled' : ''} data-sharing-field="recipient">`
    : method === 'people'
      ? peopleSearch
      : `<label for="sharing-link-name">Link name</label><input id="sharing-link-name" type="text" required value="${esc(props.linkName)}" ${props.busy ? 'disabled' : ''} data-sharing-field="link-name">`;
  const expiration = editing
    ? editable.expiration && props.capability.expiration
      ? `<div class="sharing-field"><label for="sharing-expiry">Expiration${props.expirationRequired ? '' : ' (optional)'}</label><input id="sharing-expiry" type="datetime-local" value="${esc(props.expiry)}" ${props.expirationRequired ? 'required' : ''} ${props.busy ? 'disabled' : ''} data-sharing-field="expiry"></div>`
      : `<div class="sharing-fixed-recipient"><span>Expiration</span><b>${esc(props.selectedShare?.expiresAt ? formatExpiry(props.selectedShare.expiresAt) : 'None')}</b></div>`
    : (props.capability.expiration || props.expirationRequired ? `<div class="sharing-field"><label for="sharing-expiry">Expiration${props.expirationRequired ? '' : ' (optional)'}</label><input id="sharing-expiry" type="datetime-local" value="${esc(props.expiry)}" ${props.expirationRequired ? 'required' : ''} ${props.busy ? 'disabled' : ''} data-sharing-field="expiry"></div>` : '');
  const password = !editing && method === 'links' && (props.capability.password || props.passwordRequired) ? `<div class="sharing-field"><label for="sharing-password">${props.passwordRequired ? 'Password' : 'Password (optional)'}</label><input id="sharing-password" type="password" autocomplete="new-password" value="${esc(props.password)}" ${props.passwordRequired ? 'required' : ''} ${props.busy ? 'disabled' : ''} data-sharing-field="password"></div>` : '';
  const roleSelect = editing && !editable.access
    ? `<div class="sharing-fixed-recipient"><span>Access</span><b>${esc(props.selectedShare?.role || 'Access level unknown')}</b></div>`
    : `<div class="sharing-field"><label for="sharing-role">Access</label><select id="sharing-role" data-sharing-field="role" ${!roleAvailable || props.busy ? 'disabled' : ''}><option value="">${roleAvailable ? 'Choose access' : 'No access roles available'}</option>${roles}</select>${props.roles?.find(role => role.id === props.roleId)?.explanation ? `<small class="sharing-field-hint">${esc(props.roles.find(role => role.id === props.roleId)?.explanation)}</small>` : ''}</div>`;
  const subject = props.mode === 'edit'
    ? (props.selectedShare?.sharedWith || props.recipient || 'the selected recipient')
    : method === 'guests' ? (props.recipient || 'the invited person') : method === 'people' ? ((props.recipientResults || []).find(result => result.id === props.recipientSelectedId)?.label || 'the selected person or group') : 'anyone who obtains this link';
  const role = props.roles?.find(option => option.id === props.roleId)?.name || 'the selected access level';
  const consequence = editing && method === 'links'
    ? `This updates the existing link for ${item.name}. Its current link and password are kept.`
    : editing
    ? `This updates ${subject} access to ${item.name}.`
    : method === 'guests'
    ? `This gives ${subject} ${role} access to ${item.name} and sends an invitation email.`
    : method === 'links'
      ? `Anyone who obtains this link may use it with the access shown for ${item.name}.`
      : `This gives ${subject} ${role} access to ${item.name}.`;
  const requiredFieldsValid = (!props.expirationRequired || (editing && !editable.expiration) || !!props.expiry?.trim()) && (!props.passwordRequired || editing || !!props.password?.trim());
  const recipientValid = editing ? (method !== 'links' || !editable.name || !!props.linkName?.trim()) : (method === 'links' ? !!props.linkName?.trim() : method === 'people' ? !!props.recipientSelectedId : !!props.recipient?.trim());
  const accessValid = editing && !editable.access ? true : roleAvailable && !!props.roleId;
  const hasEditableField = !editing || editable.access || editable.expiration || (method === 'links' && editable.name);
  const canSubmit = props.connected && !props.busy && !props.outcomeUnknown && hasEditableField && accessValid && requiredFieldsValid && recipientValid;
  const validationMessage = props.outcomeUnknown && props.validationMessage?.includes('Could not confirm the result') ? '' : props.validationMessage;
  const unknownOutcome = props.outcomeUnknown ? `<div class="sharing-state-error sharing-unknown-outcome" role="alert"><p>Could not confirm the result. Refresh before trying again.</p><button type="button" class="button subtle" data-sharing-action="refresh" aria-label="Refresh share details" ${props.busy ? 'disabled' : ''}>Refresh</button></div>` : '';
  return `<section class="sharing-flow"><h2 tabindex="-1">${editing ? 'Edit share' : 'Review access'}</h2><div class="sharing-item-summary"><div><b>${esc(item.name)}</b><span>${esc(item.location)}</span></div>${editing ? '' : `<button type="button" class="button subtle" data-sharing-action="change-item" ${props.busy ? 'disabled' : ''}>Change item</button>`}</div><div class="sharing-fields"><div class="sharing-field">${recipientField}</div>${roleSelect}${expiration}${password}</div><p class="sharing-consequence">${esc(consequence)}</p>${unknownOutcome}${validationMessage ? `<p class="sharing-state-error" role="alert">${esc(validationMessage)}</p>` : ''}<p class="sharing-disclosure">${editing ? 'Changes apply to this share only; they do not delete the file or folder.' : method === 'guests' ? 'Sending creates an invitation and emails the recipient.' : method === 'links' ? 'Anyone who obtains this link may use it with the access shown.' : 'Access is managed by this server.'}</p><div class="sharing-flow-actions"><button type="button" class="button subtle" data-sharing-action="cancel" ${props.busy ? 'disabled' : ''}>Cancel</button><button type="button" class="button primary" data-sharing-action="save-access" ${!canSubmit ? 'disabled' : ''}>${props.busy ? 'Working…' : editing ? 'Save changes' : finalAction[method]}</button></div></section>`;
}
function detailPanel(props: SharingWorkspaceProps): string {
  const row = props.selectedShare;
  if (!row) return '<div class="sharing-state" role="alert">This share is no longer available. Refresh the list.</div>';
  const incoming = inventoryFor(props) === 'with-me';
  const errorMessage = props.list.message || props.validationMessage;
  const feedback = `${props.notice ? `<p class="sharing-notice" role="status">${esc(props.notice)}</p>` : ''}${errorMessage ? `<p class="sharing-state-error" role="alert">${esc(errorMessage)}</p>` : ''}`;
  const accessSource = !incoming && row.accessSource === 'inherited' ? '<div><dt>Source</dt><dd>Inherited access</dd></div>' : !incoming && row.accessSource === 'unknown' ? '<div><dt>Source</dt><dd>Access source unknown</dd></div>' : '';
  const status = row.serverState ? `<div><dt>Status</dt><dd>${esc(row.serverState === 'pending' ? 'Pending' : row.serverState === 'accepted' ? 'Accepted' : 'Status unknown')}</dd></div>` : '';
  const access = incoming
    ? (row.role && row.role.toLowerCase() !== 'unknown access' ? `<div><dt>Access</dt><dd>${esc(row.role)}</dd></div>` : '')
    : `<div><dt>Access</dt><dd>${esc(row.role || 'Unknown access')}</dd></div>`;
  const expiration = incoming ? (row.expiresAt ? `<div><dt>Expiration</dt><dd>${esc(formatExpiry(row.expiresAt))}</dd></div>` : '') : `<div><dt>Expiration</dt><dd>${esc(formatExpiry(row.expiresAt))}</dd></div>`;
  const mutable = !incoming && row.accessSource !== 'inherited' && row.accessSource !== 'unknown';
  return `<section class="sharing-flow"><h2 tabindex="-1">Share details</h2>${feedback}<dl class="sharing-details"><div><dt>Item</dt><dd>${esc(row.itemName)}</dd></div><div><dt>Location</dt><dd>${esc(row.location)}</dd></div><div><dt>${incoming ? 'Shared by' : 'Shared with'}</dt><dd>${esc(row.sharedWith)}</dd></div>${access}${accessSource}${expiration}${status}</dl><p class="sharing-disclosure">${incoming ? 'This access was shared with this account. Contact the person who shared it to request a change.' : 'Removing access does not delete the file or folder. It may not remove inherited access or copies already downloaded.'}</p><div class="sharing-flow-actions"><button type="button" class="button subtle" data-sharing-action="cancel">Back to shares</button>${mutable && row.canEdit && props.capability.edit ? `<button type="button" class="button subtle" data-sharing-action="edit-access" data-sharing-id="${esc(row.id)}">Edit access</button>` : ''}${mutable && row.canRemove && props.capability.remove ? `<button type="button" class="sharing-danger-action" data-sharing-action="remove-access" data-sharing-id="${esc(row.id)}">Remove this access</button>` : ''}${!incoming && row.canCopyLink && props.capability.copyLink ? `<button type="button" class="button subtle" data-sharing-action="copy-link" data-sharing-id="${esc(row.id)}">Copy link</button>` : ''}</div></section>`;
}

export function renderSharingWorkspace(props: SharingWorkspaceProps): string {
  const head = sectionHeader(props);
  const copyCreatedLink = methodFor(props) === 'links' && props.createdShareId && props.capability.copyLink
    ? `<button type="button" class="button subtle" data-sharing-action="copy-link" data-sharing-id="${esc(props.createdShareId)}">Copy link</button>` : '';
  const notice = props.notice ? `<div class="sharing-notice" role="status"><span>${esc(props.notice)}</span>${copyCreatedLink}</div>` : '';
  const content = props.mode === 'choose-method'
    ? methodChoice(props)
    : props.mode === 'choose-item' || props.mode === 'lookup-item'
    ? itemChooser(props)
    : props.mode === 'settings' || props.mode === 'edit'
      ? accessForm(props)
      : props.mode === 'details' ? detailPanel(props) : `${notice}${listPanel(props)}`;
  const inventory = inventoryFor(props);
  return `<div class="sharing-workspace">${head}<section class="sharing-panel" id="sharing-panel" role="tabpanel" aria-labelledby="sharing-tab-${inventory}">${content}</section></div>`;
}

export function sharingActionFromDataset(dataset: DOMStringMap): SharingAction | null {
  const action = dataset.sharingAction;
  const shareId = dataset.sharingId;
  const itemId = dataset.sharingItemId;
  switch (action) {
    case 'set-inventory':
      return dataset.sharingInventory === 'with-me' || dataset.sharingInventory === 'by-me' || dataset.sharingInventory === 'public-links'
        ? { type: 'set-inventory', inventory: dataset.sharingInventory } : null;
    case 'choose-method':
      return dataset.sharingMethod === 'people' || dataset.sharingMethod === 'links' || dataset.sharingMethod === 'guests'
        ? { type: 'choose-method', method: dataset.sharingMethod } : null;
    case 'set-section':
      return dataset.sharingSection === 'people' || dataset.sharingSection === 'links' || dataset.sharingSection === 'guests'
        ? { type: 'set-section', section: dataset.sharingSection } : null;
    case 'new-share': case 'choose-item': case 'cancel': case 'continue': case 'change-item': case 'use-item': case 'view-item-shares': case 'save-access': case 'refresh': case 'load-more': case 'open-parent': case 'refresh-items':
      return { type: action };
    case 'open-folder': case 'select-item':
      return itemId ? { type: action, itemId } : null;
    case 'choose-recipient':
      return dataset.sharingRecipientId ? { type: action, recipientId: dataset.sharingRecipientId } : null;
    case 'show-details': case 'edit-access': case 'remove-access': case 'copy-link':
      return shareId ? { type: action, shareId } : null;
    default: return null;
  }
}
