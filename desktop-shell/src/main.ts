import { invoke, isTauri } from '@tauri-apps/api/core';
import { open } from '@tauri-apps/plugin-dialog';
import { listen } from '@tauri-apps/api/event';
import './style.css';

type Status = { connected: boolean; server?: string | null; client_id?: string | null; paused?: boolean; mounted?: boolean; cloud_root?: string | null; error?: string | null; autostart?: boolean | null; recovery_folder?: string | null };
type Space = { id: string; name: string; personal: boolean; writable: boolean; encrypted: boolean };
type SyncMode = 'two_way' | 'upload_only' | 'download_only';
type Pair = { id: string; local_path: string; space_id: string; remote_path: string; mode: SyncMode };
type Conflict = { pair_id: string; path: string; local_hash: string; remote_etag: string };
type ConflictPage = { items: Conflict[]; nextAfter: string | null; opened: boolean; loading: boolean; error: string; recoveryMessage: string };
type RecoveryCopy = { spool_key: string; space_id: string | null; remote_path: string | null; local_data_path: string | null; bytes: number | null; condition: string | null; warnings: string[] };
type RecoveryPage = { items: RecoveryCopy[]; next_after: string | null; scanned_entries: number; warning_count: number; unrecognized_entries: number; truncated: boolean };
type Transfer = { id: number; origin?: string | null; space_id?: string | null; path?: string | null; direction?: string | null; state?: string | null; bytes_total?: number | null; bytes_done?: number | null; error?: string | null; updated_at?: number | null };
type RemoteEntry = { id?: string; path: string; directory: boolean; size?: number; writable?: boolean; encrypted?: boolean };
type Page = 'overview' | 'folders' | 'transfers' | 'settings';

const app = document.querySelector<HTMLDivElement>('#app')!;
const state: { page: Page; status: Status | null; agentReachable: boolean; pairs: Pair[]; transfers: Transfer[]; conflicts: Record<string, ConflictPage>; resolvingConflict: boolean; recoveryPage: RecoveryPage | null; recoveryLoading: boolean; recoveryError: string; spaces: Space[]; spacesServer: string | null; spacesLoading: boolean; spacesError: string; transferFilter: string; busy: boolean; addOpen: boolean; localPath: string; spaceId: string; remotePath: string; mode: SyncMode; pickerOpen: boolean; pickerPath: string; pickerEntries: RemoteEntry[]; pickerError: string; pickerWritable: Record<string, boolean>; message: string; error: string; autostart: boolean | null; server: string; serverEdited: boolean; statusServer: string; clientId: string; clientIdEditedServer: string | null; clientIdServer: string } = {
  page: 'overview', status: null, agentReachable: false, pairs: [], transfers: [], spaces: [], spacesServer: null, spacesLoading: false, spacesError: '', transferFilter: 'active', busy: false, addOpen: false,
  conflicts: {}, resolvingConflict: false, recoveryPage: null, recoveryLoading: false, recoveryError: '', localPath: '', spaceId: '', remotePath: '', mode: 'two_way', pickerOpen: false, pickerPath: '/', pickerEntries: [], pickerError: '', pickerWritable: {}, message: '', error: '', autostart: null, server: '', serverEdited: false, statusServer: '', clientId: '', clientIdEditedServer: null, clientIdServer: ''
};

async function request<T>(action: string, args: Record<string, unknown> = {}): Promise<T> {
  if (!isTauri()) throw new Error('Open Raiun Desktop to connect to the background agent. This browser view is a layout preview.');
  return invoke<T>('request', { message: { action, ...args } });
}
const esc = (value: unknown) => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]!));
const icon = (name: string) => ({
  overview: '<path d="M3 10.5 12 3l9 7.5M5.5 9v11h13V9M9 20v-6h6v6"/>',
  folders: '<path d="M3 7.5h7l2 2h9v9.5H3zM3 7.5V5h7l2 2"/>',
  transfers: '<path d="M7 7h13m0 0-4-4m4 4-4 4M17 17H4m0 0 4-4m-4 4 4 4"/>',
  settings: '<path d="M12 8.5a3.5 3.5 0 1 0 0 7 3.5 3.5 0 0 0 0-7Z"/><path d="m19.4 15 .1.1 1.4 1.1-1.4 2.4-1.7-.7a8.2 8.2 0 0 1-1.5.9l-.3 1.8h-2.8l-.3-1.8a8.2 8.2 0 0 1-1.5-.9l-1.7.7-1.4-2.4 1.4-1.1a7 7 0 0 1 0-1.8l-1.4-1.1 1.4-2.4 1.7.7a8.2 8.2 0 0 1 1.5-.9l.3-1.8h2.8l.3 1.8a8.2 8.2 0 0 1 1.5.9l1.7-.7 1.4 2.4-1.4 1.1a7 7 0 0 1 0 1.8Z"/>',
  cloud: '<path d="M7 18h10a4 4 0 0 0 .5-8A5.5 5.5 0 0 0 7 8.5 4.8 4.8 0 0 0 7 18Z"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  chevron: '<path d="m9 18 6-6-6-6"/>',
  folder: '<path d="M3 7h7l2 2h9v10H3z"/>',
  refresh: '<path d="M20 7v5h-5M4 17v-5h5"/><path d="M5.6 9a7 7 0 0 1 11.8-2L20 12M4 12l2.6 5a7 7 0 0 0 11.8-2"/>',
  pause: '<path d="M8 5v14M16 5v14"/>',
  play: '<path d="m8 5 11 7-11 7z"/>',
  check: '<path d="m5 12 4 4L19 6"/>',
  alert: '<path d="M12 3 2.5 20h19L12 3Z"/><path d="M12 9v4m0 3h.01"/>',
  close: '<path d="m6 6 12 12M18 6 6 18"/>',
  chevronDown: '<path d="m7 10 5 5 5-5"/>',
  lock: '<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
  arrowUp: '<path d="M12 19V5m0 0L6 11m6-6 6 6"/>',
  arrowDown: '<path d="M12 5v14m0 0 6-6m-6 6-6-6"/>',
  dots: '<circle cx="5" cy="12" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/>'
}[name] ?? '<circle cx="12" cy="12" r="8"/>');
const svg = (name: string, cls = '') => `<svg class="icon ${cls}" viewBox="0 0 24 24" aria-hidden="true">${icon(name)}</svg>`;
const spaceName = (id: string) => state.spaces.find(s => s.id === id)?.name ?? (id ? 'OpenCloud location' : 'OpenCloud');

function render() {
  const connected = state.status?.connected === true;
  const reachable = state.agentReachable;
  const nav = [['overview', 'Overview', 'overview'], ['folders', 'Sync folders', 'folders'], ['transfers', 'Transfers', 'transfers'], ['settings', 'Settings', 'settings']] as const;
  app.innerHTML = `
    <div class="shell">
      <aside class="sidebar">
        <div class="brand"><div class="brand-mark">${svg('cloud')}</div><div><strong>raiun</strong><span>DESKTOP</span></div></div>
        <div class="side-label">YOUR CLOUD</div>
        <div class="account-row"><span class="service-mark">${svg('cloud')}</span><span class="account-copy"><b>OpenCloud</b><small>${!reachable ? 'Agent unavailable' : connected ? esc(state.status?.server || 'Connected') : 'Sign-in required'}</small></span><span class="connection-dot ${connected ? 'online' : ''}" title="${connected ? 'Connected' : 'Not connected'}"></span></div>
        <nav aria-label="Main navigation">${nav.map(([key, label, glyph]) => `<button class="nav-item ${state.page === key ? 'selected' : ''}" data-page="${key}">${svg(glyph)}<span>${label}</span>${key === 'transfers' && activeCount() ? `<span class="nav-count">${activeCount()}</span>` : ''}</button>`).join('')}</nav>
        <div class="sidebar-bottom"><div class="agent-status"><span class="status-mark ${connected ? 'online' : 'offline'}">${svg(connected ? 'check' : 'alert')}</span><div><b>${!reachable ? 'Agent unavailable' : !connected ? 'Sign-in needed' : (state.status?.paused ? 'Sync paused' : 'All systems ready')}</b><small>${!reachable ? 'Waiting for Raiun agent' : !connected ? 'Connect your OpenCloud account' : (state.status?.mounted ? 'Cloud drive mounted' : 'Cloud drive not mounted')}</small></div></div><div class="version">RAIUN DESKTOP <span>0.1.0</span></div></div>
      </aside>
      <main class="main-area">
        <header class="topbar"><div class="crumb">${svg('cloud')}<span>OpenCloud</span>${svg('chevron')}<strong>${nav.find(([key]) => key === state.page)?.[1]}</strong></div><div class="top-actions"><button class="icon-button" id="refresh" aria-label="Refresh status" title="Refresh">${svg('refresh')}</button><div class="avatar">R</div></div></header>
        <section class="content">${pageMarkup()}</section>
      </main>
    </div>
    ${(state.error || state.status?.error) ? `<div class="toast error-toast" role="alert"><span>${svg('alert')}</span><div>${esc(state.error || state.status?.error || '')}</div><button data-dismiss-error aria-label="Dismiss">${svg('close')}</button></div>` : ''}
    ${state.message ? `<div class="toast success-toast" role="status"><span>${svg('check')}</span><div>${esc(state.message)}</div><button data-dismiss-message aria-label="Dismiss">${svg('close')}</button></div>` : ''}
    ${state.addOpen ? addModal() : ''}
    ${state.pickerOpen ? pickerModal() : ''}`;
  bind();
}

function pageMarkup(): string {
  if (!state.status) return `<div class="loading-panel"><div class="spinner"></div><p>Checking Raiun agent…</p></div>`;
  if (state.page === 'overview') return overviewPage();
  if (state.page === 'folders') return foldersPage();
  if (state.page === 'transfers') return transfersPage();
  return settingsPage();
}
function overviewPage() {
  const connected = state.status?.connected === true;
  const reachable = state.agentReachable;
  const errors = (state.status?.error ? 1 : 0) + state.transfers.filter(item => ['failed', 'conflict', 'awaiting_authentication'].includes((item.state || '').toLowerCase())).length;
  const running = state.transfers.filter(item => ['queued', 'running', 'retry_wait', 'verifying'].includes((item.state || '').toLowerCase())).length;
  return `<div class="welcome-row"><div><div class="eyebrow">YOUR FILES, IN RHYTHM</div><h1>Good to see you.</h1><p class="lede">Your cloud files and sync folders, together in one place.</p></div><button class="button primary" data-action="add-pair" ${state.status?.connected ? '' : 'disabled'}>${svg('plus')} Add sync folder</button></div>
    ${!reachable ? `<div class="notice-card offline"><div class="notice-icon">${svg('alert')}</div><div class="notice-copy"><b>Raiun agent isn't available</b><p>${esc(state.status?.error || 'Start the Raiun background agent to connect this window to your account. Your settings will appear here once it is running.')}</p></div><button class="button subtle" data-action="refresh">Try again</button></div>` : !connected ? `<div class="notice-card"><div class="notice-icon">${svg('cloud')}</div><div class="notice-copy"><b>Connect your OpenCloud account</b><p>Sign in using your organization’s OpenCloud server. Raiun will open the sign-in page in your browser.</p><div class="signin-server"><input data-server value="${esc(state.server)}" placeholder="https://cloud.example.com" aria-label="OpenCloud server address"/><input data-client-id value="${esc(state.clientId)}" placeholder="Automatic client ID" aria-label="OAuth client ID override (optional)"/><button class="button primary" data-action="sign-in">Sign in ${svg('chevron')}</button></div></div></div>` : ''}
    <div class="section-heading"><div><h2>At a glance</h2><p>A live view from your Raiun agent.</p></div>${connected ? `<span class="live-pill"><i></i> LIVE</span>` : ''}</div>
    <div class="stats-grid"><article class="stat-card"><div class="stat-label">SYNC FOLDERS</div><div class="stat-value">${reachable && connected ? state.pairs.length : '—'}</div><div class="stat-foot">${!reachable ? 'Connect the agent to see folders' : connected ? 'Connected folder pairs' : 'Sign in to load your folders'}</div><span class="stat-icon teal">${svg('folders')}</span></article><article class="stat-card"><div class="stat-label">ACTIVE TRANSFERS</div><div class="stat-value">${reachable && connected ? running : '—'}</div><div class="stat-foot">${!reachable ? 'Connect the agent to see transfers' : connected ? (running ? 'Work in progress' : 'Nothing in progress') : 'Sign in to load transfers'}</div><span class="stat-icon blue">${svg('transfers')}</span></article><article class="stat-card"><div class="stat-label">NEEDS ATTENTION</div><div class="stat-value ${errors ? 'attention-value' : ''}">${reachable && connected ? errors : '—'}</div><div class="stat-foot">${!reachable ? 'Connect the agent to see status' : connected ? (errors ? 'Review items below' : 'No issues reported') : 'Sign in to load status'}</div><span class="stat-icon ${errors ? 'amber' : 'green'}">${svg(errors ? 'alert' : 'check')}</span></article></div>
    <div class="section-heading folders-heading"><div><h2>Your sync folders</h2><p>Each folder stays where you put it.</p></div><button class="text-button" data-page="folders">View all ${svg('chevron')}</button></div>
    ${reachable && connected ? (state.pairs.length ? `<div class="pair-list">${state.pairs.slice(0, 3).map(pair => pairCard(pair)).join('')}</div>` : emptyFolders()) : `<div class="empty-card compact"><span class="empty-icon">${svg(reachable ? 'cloud' : 'folders')}</span><div><b>${reachable ? 'Sign in to load your folder pairs' : 'Waiting for agent connection'}</b><p>${reachable ? 'Your sync folders will appear here when your OpenCloud account connects.' : 'Folder details will show when the agent is reachable.'}</p></div></div>`}
    <div class="cloud-root-card"><div class="cloud-root-icon">${svg('cloud')}</div><div class="root-copy"><b>OpenCloud drive</b><span>${reachable && state.status?.cloud_root ? esc(state.status.cloud_root) : 'Your cloud drive location will appear here'}</span></div><span class="root-badge ${connected && state.status?.mounted ? 'mounted' : ''}">${reachable && state.status?.mounted ? 'Mounted' : 'Not mounted'}</span><button class="icon-button" data-action="open-cloud" ${reachable && connected && state.status?.cloud_root ? '' : 'disabled'} aria-label="Open cloud folder">${svg('chevron')}</button></div>`;
}
function foldersPage() {
  const connected = state.status?.connected === true;
  return `<div class="page-title-row"><div><div class="eyebrow">STAY IN SYNC</div><h1>Sync folders</h1><p class="lede">Choose folders on this computer and where they belong in OpenCloud.</p></div><button class="button primary" data-action="add-pair" ${connected ? '' : 'disabled'}>${svg('plus')} Add sync folder</button></div>
    ${!state.agentReachable ? `<div class="notice-card offline"><div class="notice-icon">${svg('alert')}</div><div class="notice-copy"><b>Connect to the Raiun agent first</b><p>Folder pairs are managed by the background agent. Start it, then refresh this page.</p></div><button class="button subtle" data-action="refresh">Refresh</button></div>` : !connected ? `<div class="notice-card"><div class="notice-icon">${svg('cloud')}</div><div class="notice-copy"><b>Sign in to view sync folders</b><p>Connect your OpenCloud account to load Spaces and folder pairs.</p></div><button class="button primary" data-action="sign-in">Sign in</button></div>` : state.pairs.length ? `<div class="pair-list page-pair-list">${state.pairs.map(folderPairCard).join('')}</div>` : emptyFolders()}`;
}
function folderPairCard(pair: Pair) {
  const panel = state.conflicts[pair.id];
  return `<div class="pair-entry">${pairCard(pair, true)}${panel?.opened ? conflictPanel(pair, panel) : ''}</div>`;
}
function pairCard(pair: Pair, includeReview = false) {
  const title = spaceName(pair.space_id);
  const mode = pair.mode === 'two_way' ? 'Two-way' : pair.mode === 'upload_only' ? 'Upload only' : 'Download only';
  const review = includeReview ? `<button class="small-action quiet" data-review-pair="${esc(pair.id)}">${state.conflicts[pair.id]?.opened ? 'Hide conflicts' : 'Review conflicts'}</button>` : '';
  return `<article class="pair-card"><div class="pair-folder-icon">${svg('folder')}</div><div class="pair-main"><div class="pair-title"><b>${esc(lastPath(pair.local_path))}</b><span class="mode-pill">${mode}</span></div><div class="pair-route"><span class="path-text">${esc(pair.local_path)}</span><span class="route-arrow">${svg('chevron')}</span><span class="remote-label">${svg('cloud')} ${esc(title)}${esc(pair.remote_path)}</span></div></div><div class="pair-actions">${review}<button class="icon-button danger-hover" data-remove-pair="${esc(pair.id)}" title="Remove folder pair" aria-label="Remove ${esc(pair.local_path)}">${svg('dots')}</button></div></article>`;
}
function conflictPanel(pair: Pair, panel: ConflictPage) {
  return `<section class="conflict-panel" aria-label="Conflicts for ${esc(pair.local_path)}"><div class="conflict-heading"><div><h3>Conflicts to review</h3><p>Choose which version to keep. Raiun preserves the displaced version as a recovery copy.</p></div><button class="button subtle conflict-refresh" data-refresh-conflicts="${esc(pair.id)}" ${panel.loading || state.resolvingConflict ? 'disabled' : ''}>${svg('refresh')} Refresh</button></div>
    ${panel.error ? `<div class="conflict-error" role="alert">${svg('alert')}<span>${esc(panel.error)}</span></div>` : ''}
    ${panel.recoveryMessage ? `<div class="conflict-recovery" role="status">${svg('check')}<span>${esc(panel.recoveryMessage)}</span></div>` : ''}
    ${panel.loading && !panel.items.length ? `<div class="conflict-loading"><span class="spinner"></span><span>Checking conflicts…</span></div>` : panel.items.length ? `<div class="conflict-list">${panel.items.map(item => conflictCard(pair, item)).join('')}</div>` : !panel.loading && !panel.error ? `<div class="conflict-empty">No file conflicts found.</div>` : ''}
    ${panel.nextAfter ? `<div class="conflict-more-row"><button class="button subtle" data-more-conflicts="${esc(pair.id)}" ${panel.loading || state.resolvingConflict ? 'disabled' : ''}>${panel.loading ? 'Loading…' : 'Load more conflicts'}</button></div>` : ''}</section>`;
}
function conflictCard(pair: Pair, item: Conflict) {
  const busy = state.resolvingConflict;
  const localDisabled = busy || pair.mode === 'download_only';
  const remoteDisabled = busy || pair.mode === 'upload_only';
  return `<article class="conflict-card"><div class="conflict-file">${svg('alert')}<div><b>${esc(lastPath(item.path))}</b><small>${esc(item.path)}</small></div></div><p class="conflict-description">Local and cloud versions both changed. Pick one to keep.</p><div class="conflict-actions"><button class="button subtle" data-resolve-conflict="keep_local" data-pair-id="${esc(pair.id)}" data-path="${esc(item.path)}" data-local-hash="${esc(item.local_hash)}" data-remote-etag="${esc(item.remote_etag)}" ${localDisabled ? 'disabled' : ''}>Keep local</button><button class="button subtle" data-resolve-conflict="keep_remote" data-pair-id="${esc(pair.id)}" data-path="${esc(item.path)}" data-local-hash="${esc(item.local_hash)}" data-remote-etag="${esc(item.remote_etag)}" ${remoteDisabled ? 'disabled' : ''}>Keep cloud</button></div>${pair.mode === 'download_only' ? '<small class="conflict-mode-note">Keep local is unavailable for download-only pairs.</small>' : pair.mode === 'upload_only' ? '<small class="conflict-mode-note">Keep cloud is unavailable for upload-only pairs.</small>' : ''}</article>`;
}
function emptyFolders() { return `<div class="empty-card"><span class="empty-icon">${svg('folders')}</span><h3>No sync folders yet</h3><p>Add an existing folder and choose its place in OpenCloud. The folder stays on your computer.</p><button class="button primary" data-action="add-pair" ${state.status?.connected ? '' : 'disabled'}>${svg('plus')} Add your first folder</button></div>`; }
function transfersPage() {
  const filters = [['active', 'Active'], ['attention', 'Needs attention'], ['history', 'History']] as const;
  const matching = state.transfers.filter(item => {
    const status = (item.state || '').toLowerCase();
    if (state.transferFilter === 'active') return ['queued', 'running', 'retry_wait', 'verifying', 'paused'].includes(status);
    if (state.transferFilter === 'attention') return ['failed', 'conflict', 'awaiting_authentication'].includes(status);
    return ['completed', 'cancelled'].includes(status);
  });
  return `<div class="page-title-row"><div><div class="eyebrow">ACTIVITY</div><h1>Transfers</h1><p class="lede">See what Raiun is moving and anything that needs your attention.</p></div><button class="button subtle" data-action="refresh">${svg('refresh')} Refresh</button></div>
    <div class="filter-tabs" role="tablist">${filters.map(([key,label]) => `<button class="filter-tab ${state.transferFilter === key ? 'active' : ''}" data-filter="${key}">${label}${key === 'attention' && attentionCount() ? `<span class="tab-badge">${attentionCount()}</span>` : ''}</button>`).join('')}</div>
    ${state.agentReachable && state.status?.connected ? matching.length ? `<div class="transfer-list">${matching.map(transferCard).join('')}</div>` : `<div class="empty-card transfer-empty"><span class="empty-icon">${svg(state.transferFilter === 'attention' ? 'check' : 'transfers')}</span><h3>${state.transferFilter === 'attention' ? 'Nothing needs attention' : state.transferFilter === 'history' ? 'No transfer history yet' : 'No active transfers'}</h3><p>${state.transferFilter === 'active' ? 'New folder sync activity will appear here when the agent reports it.' : state.transferFilter === 'attention' ? 'Raiun has not reported any blocked transfers.' : 'Completed and cancelled transfers will be listed here.'}</p></div>` : !state.agentReachable ? `<div class="notice-card offline"><div class="notice-icon">${svg('alert')}</div><div class="notice-copy"><b>Transfer status is unavailable</b><p>Start the Raiun agent to see transfer activity.</p></div><button class="button subtle" data-action="refresh">Refresh</button></div>` : `<div class="notice-card"><div class="notice-icon">${svg('cloud')}</div><div class="notice-copy"><b>Sign in to see transfer activity</b><p>Connect your OpenCloud account to load transfer status.</p></div><button class="button primary" data-action="sign-in">Sign in</button></div>`}`;
}
function transferCard(item: Transfer) {
  const status = (item.state || 'unknown').toLowerCase();
  const direction = (item.direction || '').toLowerCase();
  const isUpload = direction.includes('upload') || direction === 'up';
  const issue = ['failed', 'conflict', 'awaiting_authentication'].includes(status);
  const statusLabel = status.replaceAll('_', ' ').replace(/\b\w/g, c => c.toUpperCase());
  const subject = item.path || String(item.id) || 'Transfer';
  const origin = item.origin ? item.origin.replaceAll('_', ' ') : 'Sync folder';
  const byteText = item.bytes_total != null && item.bytes_total > 0 && item.bytes_done != null ? `${formatBytes(item.bytes_done)} of ${formatBytes(item.bytes_total)}` : item.bytes_total === 0 && status === 'completed' ? '0 bytes' : '';
  return `<article class="transfer-card"><span class="transfer-direction ${isUpload ? 'up' : 'down'}">${svg(isUpload ? 'arrowUp' : 'arrowDown')}</span><div class="transfer-main"><div class="transfer-title"><b>${esc(lastPath(subject))}</b><span class="transfer-status ${issue ? 'issue' : ''}">${esc(statusLabel)}</span></div><div class="transfer-meta">${esc(origin)} <span>·</span> ${esc(item.space_id ? spaceName(item.space_id) : 'OpenCloud')}${byteText ? `<span>·</span> ${esc(byteText)}` : ''}</div>${item.error ? `<p class="transfer-error">${esc(item.error)}</p>` : ''}</div><div class="transfer-actions">${issue && item.origin === 'folder_pair' ? `<button class="small-action" data-action="sync-now">Rescan folders</button>` : ''}</div></article>`;
}
function settingsPage() {
  const connected = state.status?.connected === true;
  const canInspectRecoveries = state.agentReachable && Boolean(state.status?.recovery_folder);
  const recoveryPage = state.recoveryPage;
  const recoveryItemWarnings = recoveryPage?.items.reduce((count, item) => count + (item.warnings?.length || 0), 0) || 0;
  const recoveryNotice = recoveryPage && (recoveryPage.truncated || recoveryItemWarnings > 0 || recoveryPage.unrecognized_entries > 0)
    ? `<div class="recovery-warning" role="status">${recoveryPage.truncated ? 'The scan was truncated; this list may be incomplete. ' : ''}${recoveryItemWarnings ? `${recoveryItemWarnings} listed item warning(s) need review. ` : ''}${recoveryPage.unrecognized_entries ? `${recoveryPage.unrecognized_entries} entr${recoveryPage.unrecognized_entries === 1 ? 'y was' : 'ies were'} not recognized in this scan.` : ''}</div>`
    : '';
  const recoveryRows = recoveryPage?.items.length
    ? `<div class="recovery-list">${recoveryPage.items.map(recoveryCard).join('')}</div>`
    : recoveryPage
      ? `<div class="recovery-empty">${recoveryPage.warning_count || recoveryPage.unrecognized_entries ? 'No recognized saved copies were listed. Review the scan warnings above.' : 'No saved upload copies found.'}</div>`
      : '';
  return `<div class="page-title-row"><div><div class="eyebrow">PREFERENCES</div><h1>Settings</h1><p class="lede">Manage how Raiun works on this computer.</p></div></div>
    <div class="settings-stack"><section class="settings-card"><div class="settings-heading"><span class="settings-icon">${svg('cloud')}</span><div><h2>OpenCloud account</h2><p>One account connects your cloud drive and sync folders.</p></div></div><div class="settings-row account-settings-row"><div><b>${!state.agentReachable ? 'Agent status' : connected ? 'Connected server' : 'Sign in to OpenCloud'}</b><small>${!state.agentReachable ? 'The Raiun agent is not reachable' : connected ? esc(state.status?.server || 'Your OpenCloud account is connected') : 'Sign in to connect this computer'}</small>${state.agentReachable && !connected ? `<div class="signin-server settings-server"><input data-server value="${esc(state.server)}" placeholder="https://cloud.example.com" aria-label="OpenCloud server address"/><input data-client-id value="${esc(state.clientId)}" placeholder="Automatic client ID" aria-label="OAuth client ID override (optional)"/><button class="button primary" data-action="sign-in">Sign in</button></div>` : ''}</div><button class="button subtle" data-action="refresh">Refresh</button></div></section>
    <section class="settings-card"><div class="settings-heading"><span class="settings-icon">${svg('folder')}</span><div><h2>Cloud drive</h2><p>Your single OpenCloud location in the computer’s file manager.</p></div></div><div class="settings-row"><div><b>Mount status</b><small>${connected && state.status?.cloud_root ? `${state.status.mounted ? 'Mounted at' : 'Configured at'} ${esc(state.status.cloud_root)}` : 'No cloud drive location reported'}</small></div><div class="button-group"><button class="button subtle" data-action="mount" ${connected ? '' : 'disabled'}>Mount</button><button class="button subtle" data-action="unmount" ${connected ? '' : 'disabled'}>Unmount</button></div></div><div class="settings-row"><div><b>Choose location</b><small>Pick the directory Raiun uses for the OpenCloud drive.</small></div><button class="button subtle" data-action="configure-root" ${connected ? '' : 'disabled'}>Choose folder</button></div></section>
    <section class="settings-card"><div class="settings-heading"><span class="settings-icon">${svg('folder')}</span><div><h2>Saved upload copies</h2><p>These local copies support cloud uploads. Some may still be pending or in progress.</p></div></div><div class="settings-row"><div><b>Recovery files</b><small>Review the local and OpenCloud paths. This screen does not upload or delete copies.</small></div><div class="button-group"><button class="button subtle" data-action="open-recovery" ${canInspectRecoveries ? '' : 'disabled'}>Open folder</button><button class="button primary" data-action="load-recoveries" ${canInspectRecoveries && !state.recoveryLoading ? '' : 'disabled'}>${recoveryPage ? 'Refresh list' : 'Inspect saved copies'}</button></div></div>${!state.agentReachable ? `<p class="recovery-hint">The Raiun agent is not reachable.</p>` : !canInspectRecoveries ? `<p class="recovery-hint">Sign in once to associate this computer with a saved account. The list remains available while that account is disconnected.</p>` : ''}${state.recoveryError ? `<div class="recovery-warning" role="alert">${esc(state.recoveryError)}</div>` : ''}${state.recoveryLoading ? `<div class="recovery-loading"><span class="spinner"></span> Checking saved copies…</div>` : ''}${recoveryNotice}${recoveryRows}${recoveryPage?.next_after && !state.recoveryLoading ? `<div class="recovery-more"><button class="button subtle" data-action="more-recoveries">Load more</button></div>` : ''}</section>
    <section class="settings-card"><div class="settings-heading"><span class="settings-icon">${svg('play')}</span><div><h2>Startup</h2><p>Start Raiun when you sign in to this computer.</p></div></div><div class="settings-row"><div><b>Launch at login</b><small>${state.autostart == null ? 'Current setting is not reported by the agent' : state.autostart ? 'Raiun will start at login' : 'Raiun will not start at login'}</small></div><button class="button ${state.autostart ? 'subtle' : 'primary'}" data-action="toggle-autostart" ${connected ? '' : 'disabled'}>${state.autostart ? 'Disable' : 'Enable'}</button></div></section>
    <section class="settings-card"><div class="settings-heading"><span class="settings-icon">${svg('pause')}</span><div><h2>Sync activity</h2><p>Pause background work across your folder pairs.</p></div></div><div class="settings-row"><div><b>${!connected ? 'Sign in to enable sync' : state.status?.paused ? 'Sync is paused' : 'Sync is enabled'}</b><small>The current file may finish first. Opening cloud files can still use the network.</small></div><button class="button subtle" data-action="toggle-pause" ${connected ? '' : 'disabled'}>${state.status?.paused ? 'Resume sync' : 'Pause sync'}</button></div></section></div>`;
}
function recoveryCard(item: RecoveryCopy) {
  const space = item.space_id ? (state.spaces.find(candidate => candidate.id === item.space_id)?.name || item.space_id) : 'OpenCloud location unavailable';
  const remotePath = item.remote_path || 'Remote path unavailable';
  const localPath = item.local_data_path || 'Local data path unavailable';
  const warnings = item.warnings?.length
    ? `<div class="recovery-item-warning">${item.warnings.map(warning => esc(recoveryWarningText(warning))).join(' ')}</div>`
    : '';
  const badge = item.warnings?.length ? 'Needs review' : 'Saved copy';
  return `<article class="recovery-card"><div class="recovery-card-title"><div><b>${esc(remotePath.split('/').filter(Boolean).at(-1) || remotePath)}</b><small>${esc(remotePath)}</small></div><span class="recovery-badge ${item.warnings?.length ? 'warning' : ''}">${badge}</span></div><div class="recovery-meta"><span>${esc(space)}</span><span>${item.bytes == null ? 'Size unavailable' : esc(formatBytes(item.bytes))}</span></div><div class="recovery-local"><span>Local copy</span><code>${esc(localPath)}</code></div>${warnings}</article>`;
}
function recoveryWarningText(warning: string) {
  const messages: Record<string, string> = {
    missing_manifest: 'Recovery details are missing.',
    missing_data: 'The local copy is missing.',
    unsafe_manifest: 'Recovery details could not be opened safely.',
    unsafe_data: 'The local copy could not be opened safely.',
    manifest_too_large: 'Recovery details are too large to inspect.',
    malformed_manifest: 'Recovery details could not be read.',
    manifest_name_mismatch: 'Recovery details do not match this record.',
    invalid_manifest_fields: 'Recovery details are incomplete or invalid.',
    local_path_unavailable: 'The local path could not be determined.'
  };
  return messages[warning] || 'This recovery record needs review.';
}
function addModal() {
  const available = state.spaces.filter(s => !s.encrypted);
  const selected = state.spaces.find(s => s.id === state.spaceId);
  return `<div class="modal-backdrop" data-backdrop="add"><section class="modal" role="dialog" aria-modal="true" aria-labelledby="add-title"><div class="modal-top"><div><div class="eyebrow">NEW CONNECTION</div><h2 id="add-title">Add a sync folder</h2></div><button class="icon-button" data-action="close-add" aria-label="Close">${svg('close')}</button></div><p class="modal-lede">Choose a folder on this computer and the place it belongs in OpenCloud.</p>
    <label class="field-label" for="localPath">Folder on this computer</label><div class="input-with-button"><input id="localPath" value="${esc(state.localPath)}" placeholder="Select an existing folder" readonly /><button class="button subtle" data-action="choose-local">Browse</button></div>
    <label class="field-label" for="spaceSelect">OpenCloud location</label><select id="spaceSelect" ${state.spacesLoading || !state.spaces.length ? 'disabled' : ''}><option value="">${state.spacesLoading ? 'Loading Spaces…' : state.spacesError ? 'Spaces unavailable' : state.spaces.length ? 'Choose a Space' : 'No Spaces available'}</option>${available.map(space => `<option value="${esc(space.id)}" ${state.spaceId === space.id ? 'selected' : ''}>${space.personal ? 'Personal' : 'Space'} · ${esc(space.name)}${space.writable ? '' : ' · read only'}</option>`).join('')}${state.spaces.filter(s => s.encrypted).map(s => `<option value="" disabled>${esc(s.name)} · encrypted and unavailable</option>`).join('')}</select>
    ${state.spacesError ? `<div class="spaces-load-error" role="alert">Could not load Spaces: ${esc(state.spacesError)} <button class="text-button" data-action="refresh-spaces">Try again</button></div>` : ''}
    ${selected ? `<button class="remote-pick-row" data-action="choose-remote"><span class="remote-pick-icon">${svg('folder')}</span><span><small>REMOTE FOLDER</small><b>${esc(selected.name)}${esc(state.remotePath || ' · Choose a folder')}</b></span>${svg('chevron')}</button>` : `<div class="remote-pick-row disabled"><span class="remote-pick-icon">${svg('folder')}</span><span><small>REMOTE FOLDER</small><b>Select a Space first</b></span></div>`}
    <label class="field-label" for="modeSelect">Sync direction</label><select id="modeSelect"><option value="two_way" ${state.mode === 'two_way' ? 'selected' : ''}>Two-way · keep both sides in sync</option><option value="upload_only" ${state.mode === 'upload_only' ? 'selected' : ''}>Upload only · send local changes to OpenCloud</option><option value="download_only" ${state.mode === 'download_only' ? 'selected' : ''}>Download only · receive OpenCloud changes</option></select>
    <div class="helper-note">Removing a folder pair later removes the connection only. It will not delete your local or cloud files.</div><div class="modal-actions"><button class="button subtle" data-action="close-add">Cancel</button><button class="button primary" data-action="save-pair" ${(state.localPath && state.spaceId && state.remotePath) ? '' : 'disabled'}>${svg('plus')} Add folder</button></div></section></div>`;
}
function pickerModal() {
  const currentSpace = state.spaces.find(s => s.id === state.spaceId);
  return `<div class="modal-backdrop" data-backdrop="picker"><section class="modal picker-modal" role="dialog" aria-modal="true" aria-labelledby="picker-title"><div class="modal-top"><div><div class="eyebrow">${esc(currentSpace?.name || 'OPENCloud')}</div><h2 id="picker-title">Choose remote folder</h2></div><button class="icon-button" data-action="close-picker" aria-label="Close">${svg('close')}</button></div><div class="picker-breadcrumb">${svg('cloud')}<span>${esc(currentSpace?.personal ? 'Personal' : currentSpace?.name || 'Space')}</span>${esc(state.pickerPath)}</div>
  ${state.pickerError ? `<div class="picker-error">${svg('alert')} ${esc(state.pickerError)}</div>` : ''}<div class="remote-list">${state.pickerPath !== '/' ? `<button class="remote-entry parent-entry" data-remote-path="${esc(parentPath(state.pickerPath))}">${svg('folder')}<span>..</span>${svg('chevron')}</button>` : ''}${state.pickerEntries.length ? state.pickerEntries.filter(entry => entry.directory).map(entry => entry.encrypted ? `<div class="remote-entry disabled-entry">${svg('lock')}<span>${esc(lastPath(entry.path))} · encrypted</span></div>` : `<button class="remote-entry" data-remote-path="${esc(entry.path)}">${svg('folder')}<span>${esc(lastPath(entry.path))}</span>${svg('chevron')}</button>`).join('') : `<div class="remote-empty">${state.pickerError ? 'Folder listing unavailable.' : 'No folders in this location.'}</div>`}</div><div class="modal-actions"><button class="button subtle" data-action="close-picker">Cancel</button><button class="button primary" data-action="select-remote" ${state.pickerWritable[state.pickerPath] || state.mode === 'download_only' ? '' : 'disabled'}>Use this folder</button></div></section></div>`;
}

function bind() {
  app.querySelectorAll<HTMLElement>('[data-page]').forEach(el => el.addEventListener('click', () => { state.page = el.dataset.page as Page; state.error = ''; render(); }));
  app.querySelector('#refresh')?.addEventListener('click', () => void refresh(true, true));
  app.querySelectorAll<HTMLElement>('[data-action]').forEach(el => el.addEventListener('click', () => void handleAction(el.dataset.action || '', el)));
  app.querySelectorAll<HTMLElement>('[data-filter]').forEach(el => el.addEventListener('click', () => { state.transferFilter = el.dataset.filter || 'active'; render(); }));
  app.querySelectorAll<HTMLElement>('[data-remove-pair]').forEach(el => el.addEventListener('click', () => void removePair(el.dataset.removePair || '')));
  app.querySelectorAll<HTMLElement>('[data-review-pair]').forEach(el => el.addEventListener('click', () => void toggleConflicts(el.dataset.reviewPair || '')));
  app.querySelectorAll<HTMLElement>('[data-refresh-conflicts]').forEach(el => el.addEventListener('click', () => void loadConflictPage(el.dataset.refreshConflicts || '', true)));
  app.querySelectorAll<HTMLElement>('[data-more-conflicts]').forEach(el => el.addEventListener('click', () => void loadConflictPage(el.dataset.moreConflicts || '', false)));
  app.querySelectorAll<HTMLButtonElement>('[data-resolve-conflict]').forEach(el => el.addEventListener('click', () => void resolveConflict(el)));
  app.querySelectorAll<HTMLElement>('[data-retry]').forEach(el => el.addEventListener('click', () => void transferAction('retry', el.dataset.retry || '')));
  app.querySelectorAll<HTMLElement>('[data-cancel]').forEach(el => el.addEventListener('click', () => void transferAction('cancel', el.dataset.cancel || '')));
  app.querySelectorAll<HTMLElement>('[data-remote-path]').forEach(el => el.addEventListener('click', () => { const path = el.dataset.remotePath || '/'; const entry = state.pickerEntries.find(item => item.path === path); if (entry) state.pickerWritable[path] = entry.writable === true && entry.encrypted !== true; void browseRemote(path); }));
  app.querySelector<HTMLElement>('[data-backdrop="add"]')?.addEventListener('click', event => { if (event.target === event.currentTarget) closeAdd(); });
  app.querySelector<HTMLElement>('[data-backdrop="picker"]')?.addEventListener('click', event => { if (event.target === event.currentTarget) state.pickerOpen = false, render(); });
  app.querySelector<HTMLInputElement>('[data-server]')?.addEventListener('input', event => {
    const next = (event.target as HTMLInputElement).value;
    const nextKey = serverKey(next);
    state.server = next;
    state.serverEdited = true;
    if (state.clientIdEditedServer !== nextKey && state.clientIdServer !== nextKey) {
      state.clientId = '';
      state.clientIdServer = nextKey;
    }
    if (nextKey && nextKey === state.statusServer && state.clientIdEditedServer !== nextKey) {
      state.clientId = state.status?.client_id || '';
      state.clientIdServer = nextKey;
    }
    const clientInput = app.querySelector<HTMLInputElement>('[data-client-id]');
    if (clientInput) clientInput.value = state.clientId;
  });
  app.querySelector<HTMLInputElement>('[data-client-id]')?.addEventListener('input', event => {
    state.clientId = (event.target as HTMLInputElement).value;
    state.clientIdEditedServer = serverKey(state.server);
    state.clientIdServer = state.clientIdEditedServer;
  });
  app.querySelector<HTMLSelectElement>('#spaceSelect')?.addEventListener('change', event => { state.spaceId = (event.target as HTMLSelectElement).value; state.remotePath = ''; render(); });
  app.querySelector<HTMLSelectElement>('#modeSelect')?.addEventListener('change', event => { state.mode = (event.target as HTMLSelectElement).value as SyncMode; });
  app.querySelector<HTMLButtonElement>('[data-action="select-remote"]')?.addEventListener('click', () => { state.remotePath = state.pickerPath; state.pickerOpen = false; render(); });
  app.querySelector<HTMLButtonElement>('[data-action="save-pair"]')?.addEventListener('click', () => void savePair());
  app.querySelector<HTMLButtonElement>('[data-dismiss-error]')?.addEventListener('click', () => { state.error = ''; render(); });
  app.querySelector<HTMLButtonElement>('[data-dismiss-message]')?.addEventListener('click', () => { state.message = ''; render(); });
}

async function handleAction(action: string, element?: HTMLElement) {
  switch (action) {
    case 'refresh': await refresh(true, true); break;
    case 'refresh-spaces': await loadSpaces(true); break;
    case 'add-pair': if (!state.status?.connected) return; state.addOpen = true; state.message = ''; state.localPath = ''; state.spaceId = state.spaces.find(space => space.personal && space.writable && !space.encrypted)?.id || ''; state.remotePath = ''; state.mode = 'two_way'; render(); void loadSpaces(); break;
    case 'close-add': closeAdd(); break;
    case 'choose-local': {
      const selected = await open({ directory: true, multiple: false, title: 'Choose a folder to sync' });
      if (typeof selected === 'string') state.localPath = selected;
      render(); break;
    }
    case 'choose-remote': state.pickerOpen = true; state.pickerPath = '/'; state.pickerEntries = []; state.pickerError = ''; state.pickerWritable = { '/': state.spaces.find(space => space.id === state.spaceId)?.writable === true }; render(); await browseRemote('/'); break;
    case 'close-picker': state.pickerOpen = false; render(); break;
    case 'sign-in': await beginSignIn(); break;
    case 'toggle-pause': if (state.status) await run('pause', { paused: !state.status.paused }); break;
    case 'sync-now': await run('sync_now', {}); break;
    case 'mount': await run('mount', {}); break;
    case 'unmount': await run('unmount', {}); break;
    case 'open-cloud': if (state.status?.cloud_root) { try { await invoke('open_cloud_folder'); } catch (error) { state.error = messageOf(error); render(); } } break;
    case 'open-recovery': try { await invoke('open_recovery_folder'); } catch (error) { state.error = messageOf(error); render(); } break;
    case 'load-recoveries': await loadRecoveries(true); break;
    case 'more-recoveries': await loadRecoveries(false); break;
    case 'configure-root': {
      const selected = await open({ directory: true, multiple: false, title: 'Choose OpenCloud drive folder' });
      if (typeof selected === 'string') await run('configure', { cloud_root: selected }); break;
    }
    case 'toggle-autostart': {
      const enabled = state.autostart !== true;
      await run('set_autostart', { enabled });
      if (!state.error) state.autostart = enabled;
      render(); break;
    }
    default: void element;
  }
}
async function loadRecoveries(reset: boolean) {
  if (state.recoveryLoading || !state.agentReachable || !state.status?.recovery_folder) return;
  const recoveryFolder = state.status.recovery_folder;
  const previous = state.recoveryPage;
  const after = reset ? null : previous?.next_after;
  if (!reset && !after) return;
  state.recoveryLoading = true;
  state.recoveryError = '';
  render();
  const args: Record<string, unknown> = { limit: 50 };
  if (after) args.after = after;
  try {
    const page = await request<RecoveryPage>('recoveries', args);
    if (state.status?.recovery_folder !== recoveryFolder) return;
    const priorItems = reset ? [] : (previous?.items || []);
    const seen = new Set(priorItems.map(item => item.spool_key));
    state.recoveryPage = {
      ...page,
      items: [...priorItems, ...page.items.filter(item => !seen.has(item.spool_key))]
    };
  } catch (error) {
    if (state.status?.recovery_folder === recoveryFolder) state.recoveryError = messageOf(error);
  } finally {
    state.recoveryLoading = false;
    render();
  }
}
async function beginSignIn() {
  const input = app.querySelector<HTMLInputElement>('[data-server]');
  const clientInput = app.querySelector<HTMLInputElement>('[data-client-id]');
  if (input) state.server = input.value.trim();
  if (clientInput) state.clientId = clientInput.value.trim();
  const server = state.server.trim().replace(/\/$/, '');
  if (!server) { state.error = 'Enter your OpenCloud server address.'; render(); return; }
  const normalized = /^https?:\/\//i.test(server) ? server : `https://${server}`;
  let parsedServer: URL;
  try { parsedServer = new URL(normalized); } catch { state.error = 'Enter a valid OpenCloud server address.'; render(); return; }
  if (parsedServer.protocol !== 'https:' || !parsedServer.hostname || parsedServer.username || parsedServer.password) { state.error = 'OpenCloud sign-in requires a valid HTTPS server address.'; render(); return; }
  state.server = parsedServer.toString().replace(/\/$/, '');
  state.error = ''; state.message = '';
  try {
    const auth = await request<{ url: string; user_code?: string | null; expires_in?: number | null }>('auth_begin', { server: state.server, client_id: state.clientId });
    if (auth.user_code) {
      const duration = auth.expires_in ? ` · expires in ${Math.ceil(auth.expires_in / 60)} min` : '';
      state.message = `Enter code ${auth.user_code} in the browser to finish sign-in${duration}.`;
    } else state.message = 'Sign-in page opened. Raiun will update when your account connects.';
    await refresh(false);
  } catch (error) { state.error = messageOf(error); }
  render();
}
async function loadSpaces(force = false) {
  if (!state.status?.connected || state.spacesLoading) return;
  const serverKey = state.status.server?.trim() || '__connected__';
  if (!force && state.spacesServer === serverKey) return;
  const serverChanged = state.spacesServer !== serverKey;
  state.spacesServer = serverKey;
  if (serverChanged) {
    state.spaces = [];
    state.spaceId = '';
  }
  state.spacesLoading = true;
  state.spacesError = '';
  render();
  try {
    state.spaces = await request<Space[]>('spaces');
    if (!state.spaces.some(space => space.id === state.spaceId)) {
      state.spaceId = state.spaces.find(space => space.personal && space.writable && !space.encrypted)?.id || '';
    }
  } catch (error) {
    state.spacesError = messageOf(error);
  } finally {
    state.spacesLoading = false;
    render();
  }
}
async function browseRemote(path: string) {
  if (!state.spaceId) return;
  state.pickerPath = path; state.pickerEntries = []; state.pickerError = ''; render();
  try { state.pickerEntries = await request<RemoteEntry[]>('list', { space_id: state.spaceId, path }); }
  catch (error) { state.pickerError = messageOf(error); }
  render();
}
async function savePair() {
  const mode = state.mode;
  const selectedSpace = state.spaces.find(space => space.id === state.spaceId);
  if (selectedSpace && !selectedSpace.writable && mode !== 'download_only') { state.error = 'This Space is read only. Choose Download only or select a writable Space.'; render(); return; }
  const id = crypto.randomUUID();
  await run('pair_add', { id, local_path: state.localPath, space_id: state.spaceId, remote_path: state.remotePath, mode });
  if (!state.error) { state.addOpen = false; state.message = 'Folder pair added.'; await refresh(); }
  render();
}
async function removePair(id: string) {
  if (!confirm('Remove this folder pair? The local and cloud files will stay in place.')) return;
  await run('pair_remove', { id });
  if (!state.error) { state.message = 'Folder pair removed.'; await refresh(); }
  render();
}
async function toggleConflicts(pairId: string) {
  const existing = state.conflicts[pairId];
  if (existing?.opened) {
    existing.opened = false;
    render();
    return;
  }
  state.conflicts[pairId] = existing || { items: [], nextAfter: null, opened: true, loading: false, error: '', recoveryMessage: '' };
  state.conflicts[pairId].opened = true;
  render();
  await loadConflictPage(pairId, true);
}
async function loadConflictPage(pairId: string, reset: boolean) {
  if (!pairId) return;
  const panel = state.conflicts[pairId] || { items: [], nextAfter: null, opened: true, loading: false, error: '', recoveryMessage: '' };
  state.conflicts[pairId] = panel;
  panel.opened = true;
  panel.loading = true;
  panel.error = '';
  if (reset) { panel.items = []; panel.nextAfter = null; }
  render();
  const args: Record<string, unknown> = { pair_id: pairId, limit: 100 };
  if (!reset && panel.nextAfter) args.after = panel.nextAfter;
  try {
    const result = await request<{ items: Conflict[]; next_after: string | null }>('conflicts', args);
    panel.items = reset ? result.items : [...panel.items, ...result.items];
    panel.nextAfter = result.next_after ?? null;
  } catch (error) {
    panel.error = messageOf(error);
  } finally {
    panel.loading = false;
    render();
  }
}
async function resolveConflict(button: HTMLButtonElement) {
  const choice = button.dataset.resolveConflict as 'keep_local' | 'keep_remote' | undefined;
  const pairId = button.dataset.pairId || '';
  const path = button.dataset.path || '';
  const localHash = button.dataset.localHash || '';
  const remoteEtag = button.dataset.remoteEtag || '';
  if (!choice || !pairId || !path || state.resolvingConflict) return;
  const choiceLabel = choice === 'keep_local' ? 'local' : 'cloud';
  const displacedLabel = choice === 'keep_local' ? 'cloud' : 'local';
  if (!confirm(`Keep the ${choiceLabel} version of “${lastPath(path)}”? Raiun will preserve the ${displacedLabel} version as a recovery copy.`)) return;
  state.error = '';
  state.resolvingConflict = true;
  const panel = state.conflicts[pairId];
  if (panel) { panel.error = ''; panel.recoveryMessage = ''; }
  render();
  try {
    const result = await request<{ recovery_path: string }>('resolve_conflict', {
      pair_id: pairId,
      path,
      choice,
      expected_local_hash: localHash,
      expected_remote_etag: remoteEtag
    });
    if (panel) panel.recoveryMessage = `Kept the ${choiceLabel} version. The displaced copy is saved at ${result.recovery_path}.`;
    await loadConflictPage(pairId, true);
  } catch (error) {
    const message = messageOf(error);
    if (isStaleConflictError(message)) {
      state.error = `This conflict changed before your choice could be applied. The list was refreshed; review it again before choosing.`;
      await loadConflictPage(pairId, true);
    } else if (panel) {
      panel.error = message;
    }
  } finally {
    state.resolvingConflict = false;
    render();
  }
}
function isStaleConflictError(message: string) {
  return /stale|changed since|no longer matches|conflict.*changed/i.test(message);
}
async function transferAction(action: 'retry'|'cancel', id: string) {
  await run(action, { id });
  if (!state.error) { state.message = action === 'retry' ? 'Retry requested.' : 'Cancellation requested.'; await refresh(); }
  render();
}
async function run(action: string, args: Record<string, unknown>) {
  state.error = ''; state.message = '';
  try { await request(action, args); await refresh(false); }
  catch (error) { state.error = messageOf(error); }
}
async function refresh(showError = true, forceSpacesRefresh = false) {
  state.busy = true;
  try {
    const priorRecoveryServer = state.status?.recovery_folder || '';
    state.status = await request<Status>('status');
    const recoveryServer = state.status.recovery_folder || '';
    if (priorRecoveryServer !== recoveryServer || !state.status.recovery_folder) {
      state.recoveryPage = null;
      state.recoveryError = '';
    }
    state.agentReachable = true;
    if (typeof state.status.server === 'string' && state.status.server.trim()) {
      const configuredServer = serverKey(state.status.server);
      const currentServer = serverKey(state.server);
      if (!state.serverEdited || currentServer === state.statusServer || currentServer === configuredServer) {
        state.server = state.status.server;
        state.serverEdited = false;
      }
      if (configuredServer !== state.statusServer &&
          state.clientIdEditedServer !== configuredServer &&
          serverKey(state.server) === configuredServer) {
        state.clientId = state.status.client_id || '';
        state.clientIdServer = configuredServer;
      } else if (!state.clientIdServer && !state.clientIdEditedServer &&
                 serverKey(state.server) === configuredServer) {
        state.clientId = state.status.client_id || '';
        state.clientIdServer = configuredServer;
      }
      state.statusServer = configuredServer;
    }
    if (state.status.connected) {
      const [pairs, transfers] = await Promise.all([request<Pair[]>('pairs'), request<Transfer[]>('transfers')]);
      state.pairs = pairs; state.transfers = transfers;
      if (typeof state.status.autostart === 'boolean') state.autostart = state.status.autostart;
      await loadSpaces(forceSpacesRefresh);
    } else {
      state.pairs = []; state.transfers = []; state.spaces = []; state.spacesServer = null; state.spacesError = ''; state.spaceId = '';
    }
    if (!state.status.connected && state.status.error && showError) state.error = state.status.error;
  } catch (error) {
    state.status = { connected: false, error: messageOf(error) };
    state.agentReachable = false;
    state.pairs = []; state.transfers = [];
    state.spaces = []; state.spacesServer = null; state.spacesError = ''; state.spaceId = '';
    state.recoveryPage = null; state.recoveryError = '';
    if (showError) state.error = messageOf(error);
  }
  state.busy = false; render();
}
function closeAdd() { state.addOpen = false; state.pickerOpen = false; state.localPath = ''; state.spaceId = ''; state.remotePath = ''; state.mode = 'two_way'; render(); }
function serverKey(value: string | null | undefined) {
  return (value || '').trim().replace(/\/$/, '').toLowerCase();
}
function messageOf(error: unknown) { return error instanceof Error ? error.message : String(error); }
function lastPath(path: string) { return path.replace(/\\/g, '/').split('/').filter(Boolean).at(-1) || path; }
function parentPath(path: string) { const parts = path.split('/').filter(Boolean); parts.pop(); return parts.length ? `/${parts.join('/')}` : '/'; }
function formatBytes(bytes: number) { if (bytes < 1024) return `${bytes} B`; const units = ['KB','MB','GB','TB']; let value = bytes / 1024; let index = 0; while (value >= 1024 && index < units.length - 1) { value /= 1024; index++; } return `${value.toFixed(value >= 10 ? 0 : 1)} ${units[index]}`; }
function activeCount() { return state.transfers.filter(t => ['queued','running','retry_wait','verifying'].includes((t.state || '').toLowerCase())).length; }
function attentionCount() { return state.transfers.filter(t => ['failed','conflict','awaiting_authentication'].includes((t.state || '').toLowerCase())).length; }

void listen<string>('navigate', event => { if (['folders','transfers'].includes(event.payload)) { state.page = event.payload as Page; render(); } });
render();
void refresh();
setInterval(() => { if (!state.busy && !state.addOpen && !state.pickerOpen && !textInputFocused()) void refresh(false); }, 15_000);
function textInputFocused() {
  return document.activeElement instanceof HTMLInputElement || document.activeElement instanceof HTMLTextAreaElement;
}
