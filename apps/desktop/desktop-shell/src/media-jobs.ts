import { normalizeFolderExclusion, validateFolderExclusions, type FolderExclusion, type FolderExclusionKind } from './folder-settings';

/** Account-scoped photo and video folder records shown alongside sync folders. */
export type MediaJob = {
  id: string; revision: number; account_id: string; source_root: string; space_id: string; destination_root: string;
  destination_root_resource_id: string; filter: 'photos' | 'videos' | 'all';
  organization: 'preserve_relative_path' | 'utc_year_month'; filesystem_mtime_utc: boolean;
  interval_seconds: number; enabled: boolean; exclusions?: FolderExclusion[];
};
type RunStatus = { state: string; uploaded: number; unchanged: number; waiting_for_stability: number; conflicts: number; needs_attention: number; last_error?: string | null };
type JobRow = { job: MediaJob; status: RunStatus | null; queued: boolean; active_account: boolean };
type MediaSettingsEdit = { snapshot: MediaJob; profileKey: string; filter: MediaJob['filter']; organization: MediaJob['organization']; interval_seconds: number; exclusions: FolderExclusion[]; kind: FolderExclusionKind; pattern: string; error: string };
type RecoveryCursor = { origin: string; space_id: string; source_root: string; source_relative_path: string; destination_path: string };
type RecoveryItem = {
  origin: string; space_id: string; source_root: string; source_relative_path: string; destination_path: string;
  upload_verification_available?: boolean; state: string; configuration_revision: number | null; attempt_generation: number | null; source_size: number;
  updated_unix: number | null; staged_copy_present: boolean; staged_copy_size: number | null; stage_generation: number | null;
};
type RecoveryPage = { items: RecoveryItem[]; has_more: boolean; next_cursor: RecoveryCursor | null; account_has_unindexed_stage: boolean };
type RecoveryPanel = {
  jobId: string; revision: number; accountId: string; profileKey: string; viewRevision: number;
  items: RecoveryItem[]; nextCursor: RecoveryCursor | null; hasMore: boolean; loading: boolean; loaded: boolean;
  verifying?: boolean; verificationMessage?: string; error: string; accountHasUnindexedStage: boolean; requestToken: number;
};
type Context = {
  key(): string; connected(): boolean; reachable(): boolean; blocked(): boolean;
  supportsVerifyUpload?(): boolean;
  loadWhileDisconnected?(): boolean;
  supported(): boolean;
  settingsSupported?(): boolean;
  request<T>(action: string, args?: Record<string, unknown>): Promise<T>;
  confirm(message: string): Promise<boolean>; busy(value: boolean): void; render(): void;
};
const trashIcon = '<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h16M9 7V4h6v3m3 0-.8 13H6.8L6 7m4 4v5m4-5v5"/></svg>';
const escape = (value: unknown) => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]!));
function mediaFilterHelp() {
  return '<details class="folder-filter-help"><summary aria-label="How photo and video file types are recognized">i</summary><p>For this folder, Photos and Videos are recognized by file contents rather than filename extensions.</p></details>';
}
const formatRecoveryBytes = (bytes: number) => bytes < 1024 ? `${bytes} B` : `${(bytes / 1024).toFixed(1)} KiB`;
export class MediaJobsView {
  private rows: JobRow[] = [];
  private loading = false;
  private saving = false;
  private loaded = false;
  private error = '';
  private folderCreateError = '';
  private folderCreateErrorKey = '';
  private loadError = '';
  private message = '';
  private revision = 0;
  private recovery: RecoveryPanel | null = null;
  private recoveryRequestToken = 0;
  private edits = new Map<string, MediaSettingsEdit>();
  constructor(private readonly context: Context) {}
  reset() { this.revision++; this.recoveryRequestToken++; this.recovery = null; this.rows = []; this.loading = false; this.loaded = false; this.error = ''; this.folderCreateError = ''; this.folderCreateErrorKey = ''; this.loadError = ''; this.message = ''; this.edits.clear(); }
  folderCreationBusy() { return this.saving; }
  folderCreationError(key: string) { return this.folderCreateErrorKey === key ? this.folderCreateError : ''; }
  clearFolderCreationError(key: string) { if (this.folderCreateErrorKey === key) { this.folderCreateError = ''; this.folderCreateErrorKey = ''; } }
  async refresh() {
    if (this.saving) return;
    if (!this.context.connected() && this.context.loadWhileDisconnected?.() === false) {
      // Windows listing requires a live account. Discard old responses instead
      // of showing its folder-auth error as a media/agent availability problem.
      this.revision++; this.recoveryRequestToken++; this.recovery = null;
      this.rows = []; this.loaded = false; this.loading = false; this.loadError = '';
      this.context.render();
      return;
    }
    if (this.loading || !this.context.reachable() || !this.context.supported()) return;
    const key = this.context.key(); const revision = this.revision;
    this.loading = true;
    try {
      const result = await this.context.request<{jobs: JobRow[]}>('media_jobs');
      if (key !== this.context.key() || revision !== this.revision) return;
      this.rows = result.jobs; this.loaded = true; this.loadError = '';
    } catch (error) {
      if (key === this.context.key() && revision === this.revision) this.loadError = String(error instanceof Error ? error.message : error);
    } finally {
      if (key === this.context.key() && revision === this.revision) { this.loading = false; this.context.render(); }
    }
  }
  spaceIds() { return [...new Set(this.rows.map(row => row.job.space_id))]; }
  statusHtml() {
    if (!this.context.supported()) return '<p class="media-workspace-note">These folder settings are unavailable for this agent.</p>';
    if (this.error || this.loadError) return `<div class="media-warning" role="alert">${escape(this.error || this.loadError)}</div>`;
    if (!this.loaded && this.loading) return '<p class="media-workspace-note" role="status">Loading folder settings…</p>';
    if (!this.loaded && this.context.reachable() && this.context.connected()) return '<p class="media-workspace-note">Folder settings have not loaded yet. Refresh to check.</p>';
    return '';
  }
  rowsForSpace(spaceId: string) {
    if (!this.context.supported()) return '';
    const blocked = this.saving || this.context.blocked() || !this.context.reachable();
    const matching = this.rows.filter(row => row.job.space_id === spaceId);
    return matching.map(row => this.row(row, blocked)).join('');
  }
  html() {
    if (!this.context.supported()) return '';
    const blocked = this.saving || this.context.blocked() || !this.context.reachable();
    const empty = this.loading ? 'Loading folder settings…' : this.loaded ? 'No folders for this account yet.' : !this.context.reachable() ? 'Start the Raiun background agent to load folder settings.' : !this.context.connected() ? 'Sign in to your OpenCloud account to load and manage folder settings.' : 'Refresh to load folder settings.';
    return `<section class="media-backups" aria-label="Folder settings">${this.statusHtml()}<div class="media-job-list">${this.rows.map(row => this.row(row, blocked)).join('') || `<p class="media-empty-result">${empty}</p>`}</div></section>`;
  }
  private row(row: JobRow, blocked: boolean) {
    const {job,status} = row; const active = row.queued || status?.state === 'running';
    const label = !row.active_account ? 'Different signed-in account' : !job.enabled ? 'Paused' : row.queued ? 'Queued' : status?.state?.replaceAll('_',' ') || 'Waiting for first scan';
    const interval = job.interval_seconds === 60 ? 'every minute' : job.interval_seconds === 900 ? 'every 15 minutes' : job.interval_seconds === 3600 ? 'every hour' : job.interval_seconds === 86400 ? 'every day' : `every ${job.interval_seconds} seconds`;
    const organization = job.organization === 'utc_year_month' ? 'Filesystem modified date, UTC year/month' : 'Keep source folders and filenames';
    const filter = job.filter === 'photos' ? 'Photos' : job.filter === 'videos' ? 'Videos' : 'All files';
    const edit = this.edits.get(job.id);
    const inspecting = this.recovery?.jobId === job.id && this.recovery.revision === job.revision && this.recovery.accountId === job.account_id;
    const editDisabled = blocked || active || !row.active_account || !this.context.settingsSupported?.();
    const error = edit?.error ? `<p class="media-settings-error" role="alert">${escape(edit.error)}</p>` : '';
    const settings = edit
      ? `<details class="media-job-settings" open><summary>Folder settings</summary><p>Files stay in this folder on your computer. Includes subfolders; symbolic links are skipped.</p><div class="media-edit-grid"><div class="media-filter-field"><label>Include<select data-media-draft-filter="${escape(job.id)}" ${editDisabled ? 'disabled' : ''}><option value="all" ${edit.filter === 'all' ? 'selected' : ''}>All files</option><option value="photos" ${edit.filter === 'photos' ? 'selected' : ''}>Photos</option><option value="videos" ${edit.filter === 'videos' ? 'selected' : ''}>Videos</option></select></label>${mediaFilterHelp()}</div><label>Organize<select data-media-draft-organization="${escape(job.id)}" ${editDisabled ? 'disabled' : ''}><option value="preserve_relative_path" ${edit.organization === 'preserve_relative_path' ? 'selected' : ''}>Keep source folders</option><option value="utc_year_month" ${edit.organization === 'utc_year_month' ? 'selected' : ''}>Filesystem date, UTC year/month</option></select></label><label>Check for new files<select data-media-draft-interval="${escape(job.id)}" ${editDisabled ? 'disabled' : ''}>${[[60,'Every minute'],[900,'Every 15 minutes'],[3600,'Every hour'],[86400,'Every day']].map(([seconds,label]) => `<option value="${seconds}" ${edit.interval_seconds === seconds ? 'selected' : ''}>${label}</option>`).join('')}</select></label></div><p>Files must remain unchanged across two scans at least ten seconds apart. Files larger than 8 GiB need ordinary folder sync. Existing files are reviewed as conflicts; older cloud versions are not automatically kept.</p>${this.mediaExclusionsMarkup(job.id, edit, editDisabled)}<div class="media-settings-actions"><button class="button subtle" data-media-edit-cancel="${escape(job.id)}" ${this.saving ? 'disabled' : ''}>Cancel</button><button class="button primary" data-media-edit-save="${escape(job.id)}" ${editDisabled || this.saving || Boolean(this.draftValidationError(edit)) ? 'disabled' : ''}>${this.saving ? 'Saving…' : 'Save settings'}</button></div></details>`
      : `<details class="media-job-settings"><summary>Folder settings</summary><p>Include: ${filter}. Includes subfolders; symbolic links are skipped.</p><p>Organize: ${organization}. Check for new files ${interval}.</p><p>Files must remain unchanged across two scans at least ten seconds apart. Files larger than 8 GiB need ordinary folder sync. Existing files are reviewed as conflicts; older cloud versions are not automatically kept.</p>${this.context.settingsSupported?.() ? `<button class="button subtle" data-media-edit-open="${escape(job.id)}" ${editDisabled ? 'disabled' : ''}>Edit settings</button>` : '<p class="media-workspace-note">Editing folder settings is unavailable for this agent.</p>'}</details>`;
    return `<article class="settings-card media-job-card"><div><h3>${escape(job.source_root.split(/[\\/]/).filter(Boolean).at(-1) || job.source_root)}</h3><span class="mode-pill">${escape(label)}</span></div><p><code>${escape(job.source_root)}</code> → <code>${escape(job.destination_root)}</code></p>${error}${settings}
      ${status ? `<p role="status">${status.uploaded} uploaded · ${status.unchanged} already current · ${status.waiting_for_stability} waiting for stable files · ${status.conflicts + status.needs_attention} need attention</p>${status.last_error ? `<p class="exclusion-error">${escape(status.last_error)}</p>` : ''}` : ''}
      <div class="media-job-actions"><button class="button subtle" data-media-toggle="${escape(job.id)}" ${blocked || (!job.enabled && !row.active_account) ? 'disabled' : ''}>${job.enabled ? 'Pause folder' : 'Resume folder'}</button><button class="button subtle" data-media-run="${escape(job.id)}" ${blocked || active || !job.enabled || !row.active_account || !this.context.connected() ? 'disabled' : ''}>Check now</button><button class="button subtle" data-media-remove="${escape(job.id)}" ${blocked || active ? 'disabled' : ''}>Remove settings</button><button class="button subtle" data-media-recovery="${escape(job.id)}" ${blocked || !row.active_account || this.recovery?.loading ? 'disabled' : ''}>${inspecting ? 'Hide retained copies' : 'Inspect retained copies'}</button></div>${inspecting ? this.recoveryHtml(this.recovery!) : ''}</article>`;
  }
  private mediaExclusionsMarkup(jobId: string, edit: MediaSettingsEdit, disabled: boolean) {
    const rows = edit.exclusions.map((rule, index) => `<li><span>${rule.kind === 'file_type' ? 'File type' : 'Path'}</span><code>${escape(rule.pattern)}</code><button class="icon-button danger-hover exclusion-trash" data-media-edit-exclusion-remove="${escape(jobId)}" data-exclusion-index="${index}" aria-label="Remove exclusion ${escape(rule.pattern)}" title="Remove exclusion" ${disabled ? 'disabled' : ''}>${trashIcon}</button></li>`).join('');
    return `<div class="media-exclusion-editor"><b>Exclusions</b><p>Paths are relative to this folder. Paths without a slash match at any depth; paths with a slash start at the folder. Trailing slash means folder only.</p>${rows ? `<ul class="exclusion-path-list">${rows}</ul>` : '<small>No exclusions.</small>'}<div class="exclusion-add"><select data-media-edit-exclusion-kind="${escape(jobId)}" aria-label="Exclusion type" ${disabled ? 'disabled' : ''}><option value="path" ${edit.kind === 'path' ? 'selected' : ''}>Folder or file path</option><option value="file_type" ${edit.kind === 'file_type' ? 'selected' : ''}>File type</option></select><input data-media-edit-exclusion-pattern="${escape(jobId)}" value="${escape(edit.pattern)}" maxlength="255" aria-label="Exclusion pattern" placeholder="${edit.kind === 'file_type' ? '.tmp or .tar.gz' : 'e.g. Archive/**'}" ${disabled ? 'disabled' : ''}/><button class="button subtle" data-media-edit-exclusion-add="${escape(jobId)}" ${disabled || !edit.pattern.trim() ? 'disabled' : ''}>Add exclusion</button></div></div>`;
  }
  private draftValidationError(edit: MediaSettingsEdit) {
    if (edit.pattern.trim()) return 'Add or clear the exclusion pattern before saving.';
    return validateFolderExclusions(edit.exclusions);
  }
  beginSettingsEdit(jobId: string) {
    const row = this.rows.find(value => value.job.id === jobId);
    if (!row || !row.active_account || row.queued || row.status?.state === 'running' || !this.context.settingsSupported?.() || this.saving || this.context.blocked()) return false;
    const snapshot = { ...row.job, exclusions: (row.job.exclusions || []).map(rule => ({ ...rule })) };
    this.edits.set(jobId, { snapshot, profileKey: this.context.key(), filter: snapshot.filter, organization: snapshot.organization, interval_seconds: snapshot.interval_seconds, exclusions: snapshot.exclusions || [], kind: 'path', pattern: '', error: '' });
    this.context.render();
    return true;
  }
  updateSettingsDraft(jobId: string, patch: Partial<Pick<MediaSettingsEdit, 'filter' | 'organization' | 'interval_seconds' | 'kind' | 'pattern'>>) {
    const edit = this.edits.get(jobId);
    if (!edit || this.saving || this.context.blocked()) return false;
    Object.assign(edit, patch);
    return true;
  }
  cancelSettingsEdit(jobId: string) {
    if (this.saving) return false;
    const removed = this.edits.delete(jobId);
    if (removed) this.context.render();
    return removed;
  }
  private async addSettingsExclusion(jobId: string) {
    const edit = this.edits.get(jobId);
    if (!edit || this.saving) return;
    const normalized = normalizeFolderExclusion(edit.kind, edit.pattern);
    if (!normalized.rule) { edit.error = normalized.error || 'Review this exclusion.'; this.context.render(); return; }
    const next = [...edit.exclusions, normalized.rule];
    const error = validateFolderExclusions(next);
    if (error) { edit.error = error; this.context.render(); return; }
    edit.exclusions = next; edit.pattern = ''; edit.error = ''; this.context.render();
  }
  private async removeSettingsExclusion(jobId: string, index: number) {
    const edit = this.edits.get(jobId);
    if (!edit || this.saving || index < 0 || index >= edit.exclusions.length) return;
    edit.exclusions = edit.exclusions.filter((_rule, current) => current !== index); edit.error = ''; this.context.render();
  }
  async saveSettingsEdit(jobId: string) {
    const edit = this.edits.get(jobId);
    if (!edit || this.saving || this.context.blocked() || !this.context.reachable() || !this.context.settingsSupported?.()) return false;
    if (edit.profileKey !== this.context.key()) { edit.error = 'The selected account changed. Cancel and reopen these settings before saving.'; this.context.render(); return false; }
    const validation = this.draftValidationError(edit);
    if (validation) { edit.error = validation; this.context.render(); return false; }
    const snapshot = edit.snapshot;
    const submitted = { ...snapshot, filter: edit.filter, organization: edit.organization, filesystem_mtime_utc: edit.organization === 'utc_year_month', interval_seconds: edit.interval_seconds, exclusions: edit.exclusions.map(rule => ({ ...rule })) };
    const profileKey = edit.profileKey;
    const saved = await this.mutate(async () => {
      if (profileKey !== this.context.key()) throw new Error('The selected account changed. Cancel and reopen these settings before saving.');
      await this.context.request('media_job_set', { job: submitted, expected_revision: snapshot.revision, expected_account_id: snapshot.account_id });
      return 'Folder settings updated.';
    });
    if (profileKey !== this.context.key()) return false;
    if (saved) { this.edits.delete(jobId); this.context.render(); return true; }
    const currentEdit = this.edits.get(jobId);
    if (currentEdit === edit) { edit.error = this.error || 'Settings could not be saved. Refresh and reopen the editor to review the latest version.'; this.context.render(); }
    return false;
  }
  bind(root: HTMLElement) {
    root.querySelectorAll<HTMLButtonElement>('[data-media-edit-open]').forEach(button => button.addEventListener('click', () => this.beginSettingsEdit(button.dataset.mediaEditOpen || '')));
    root.querySelectorAll<HTMLSelectElement>('[data-media-draft-filter]').forEach(select => select.addEventListener('change', () => { const value = select.value; if (value === 'all' || value === 'photos' || value === 'videos') this.updateSettingsDraft(select.dataset.mediaDraftFilter || '', { filter: value }); }));
    root.querySelectorAll<HTMLSelectElement>('[data-media-draft-organization]').forEach(select => select.addEventListener('change', () => { const value = select.value; if (value === 'preserve_relative_path' || value === 'utc_year_month') this.updateSettingsDraft(select.dataset.mediaDraftOrganization || '', { organization: value }); }));
    root.querySelectorAll<HTMLSelectElement>('[data-media-draft-interval]').forEach(select => select.addEventListener('change', () => { const value = Number(select.value); if ([60,900,3600,86400].includes(value)) this.updateSettingsDraft(select.dataset.mediaDraftInterval || '', { interval_seconds: value }); }));
    root.querySelectorAll<HTMLSelectElement>('[data-media-edit-exclusion-kind]').forEach(select => select.addEventListener('change', () => { this.updateSettingsDraft(select.dataset.mediaEditExclusionKind || '', { kind: select.value as FolderExclusionKind }); }));
    root.querySelectorAll<HTMLInputElement>('[data-media-edit-exclusion-pattern]').forEach(input => input.addEventListener('input', () => { const id = input.dataset.mediaEditExclusionPattern || ''; this.updateSettingsDraft(id, { pattern: input.value }); const button = root.querySelector<HTMLButtonElement>(`[data-media-edit-exclusion-add="${CSS.escape(id)}"]`); if (button) button.disabled = !input.value.trim() || this.saving; const save = root.querySelector<HTMLButtonElement>(`[data-media-edit-save="${CSS.escape(id)}"]`); if (save) save.disabled = this.saving || Boolean(input.value.trim()) || !this.edits.get(id) || Boolean(this.draftValidationError(this.edits.get(id)!)); }));
    root.querySelectorAll<HTMLButtonElement>('[data-media-edit-exclusion-add]').forEach(button => button.addEventListener('click', () => void this.addSettingsExclusion(button.dataset.mediaEditExclusionAdd || '')));
    root.querySelectorAll<HTMLButtonElement>('[data-media-edit-exclusion-remove]').forEach(button => button.addEventListener('click', () => { const index = Number(button.dataset.exclusionIndex); if (Number.isInteger(index)) void this.removeSettingsExclusion(button.dataset.mediaEditExclusionRemove || '', index); }));
    root.querySelectorAll<HTMLButtonElement>('[data-media-edit-save]').forEach(button => button.addEventListener('click', () => void this.saveSettingsEdit(button.dataset.mediaEditSave || '')));
    root.querySelectorAll<HTMLButtonElement>('[data-media-edit-cancel]').forEach(button => button.addEventListener('click', () => this.cancelSettingsEdit(button.dataset.mediaEditCancel || '')));
    root.querySelectorAll<HTMLButtonElement>('[data-media-recovery]').forEach(button => button.addEventListener('click', () => {
      const row = this.rows.find(value => value.job.id === button.dataset.mediaRecovery);
      if (!row || !row.active_account || this.context.blocked()) return;
      if (this.recovery?.jobId === row.job.id && this.recovery.revision === row.job.revision && this.recovery.accountId === row.job.account_id) { this.recoveryRequestToken++; this.recovery = null; this.context.render(); }
      else {
        this.recoveryRequestToken++;
        this.recovery = {jobId:row.job.id,revision:row.job.revision,accountId:row.job.account_id,profileKey:this.context.key(),viewRevision:this.revision,items:[],nextCursor:null,hasMore:false,loading:false,loaded:false,error:'',accountHasUnindexedStage:false,requestToken:this.recoveryRequestToken};
        void this.loadRecoveryPage(false);
      }
    }));
    root.querySelectorAll<HTMLButtonElement>('[data-media-verify]').forEach(button => button.addEventListener('click', () => void this.verifyUploadedCopy(Number(button.dataset.mediaVerify))));
    root.querySelector('[data-media-recovery-more]')?.addEventListener('click', () => void this.loadRecoveryPage(true));
    root.querySelectorAll<HTMLButtonElement>('[data-media-toggle],[data-media-run],[data-media-remove]').forEach(button => button.addEventListener('click', () => {
      const id = button.dataset.mediaToggle || button.dataset.mediaRun || button.dataset.mediaRemove;
      const row = this.rows.find(value => value.job.id === id); if (!row) return;
      if (button.dataset.mediaToggle && (row.job.enabled || row.active_account)) void this.mutate(async () => { await this.context.request('media_job_set',{job:{...row.job,enabled:!row.job.enabled},expected_revision:row.job.revision,expected_account_id:row.job.account_id}); return row.job.enabled ? 'Folder paused.' : 'Folder enabled.'; });
      else if (button.dataset.mediaRun && row.active_account) void this.mutate(async () => { await this.context.request('media_job_run',{job_id:id,expected_revision:row.job.revision,expected_account_id:row.job.account_id}); return 'Folder check queued. Watch its status for verified uploads.'; });
      else if (button.dataset.mediaRemove) void this.remove(row);
    }));
  }
  private async remove(row: JobRow) {
    if (this.saving || this.context.blocked() || !this.context.reachable() || !this.context.supported()) return;
    const key = this.context.key();
    const revision = this.revision;
    const { id, account_id, revision: jobRevision } = row.job;
    try {
      if (await this.context.confirm('Remove these folder settings? Local source files, cloud files and recovery copies will stay in place.') !== true) return;
      if (key !== this.context.key() || revision !== this.revision || this.saving || this.context.blocked() || !this.context.reachable() || !this.context.supported()) return;
      const current = this.rows.find(value => value.job.id === id && value.job.account_id === account_id && value.job.revision === jobRevision);
      if (!current || current.queued || current.status?.state === 'running') return;
      await this.mutate(async () => {
        await this.context.request('media_job_remove', { job_id: id, expected_revision: jobRevision, expected_account_id: account_id });
        return 'Folder settings removed. Files remain in place.';
      });
    } catch (error) {
      if (key === this.context.key() && revision === this.revision) { this.error = String(error instanceof Error ? error.message : error); this.context.render(); }
    }
  }
  private recoveryHtml(panel: RecoveryPanel) {
    const rows = panel.items.map((item, index) => {
      const source = `${item.source_root.replace(/[\\/]$/, '')}/${item.source_relative_path}`;
      const revision = item.configuration_revision == null ? 'Legacy or unbound revision' : `Folder settings revision ${item.configuration_revision}`;
      const copy = item.staged_copy_present
        ? `Retained copy present${item.staged_copy_size == null ? '' : ` · ${formatRecoveryBytes(item.staged_copy_size)}`}`
        : 'No verified retained copy found';
      return `<article class="media-recovery-item"><div><b>${escape(item.state.replaceAll('_',' '))}</b><span>${escape(revision)} · ${escape(copy)}</span></div><p><span>Original</span><code>${escape(source)}</code></p><p><span>Destination</span><code>${escape(item.destination_path)}</code></p><small>${formatRecoveryBytes(item.source_size)} source size${item.attempt_generation == null ? '' : ` · attempt ${item.attempt_generation}`}</small>${this.canVerify(panel, item) ? `<button class="button subtle" data-media-verify="${index}" ${panel.verifying || panel.loading || this.context.blocked() || !this.context.connected() ? 'disabled' : ''}>Verify uploaded copy</button>` : ''}</article>`;
    }).join('');
      return `<section class="media-recovery" aria-label="Retained folder copies"><p class="media-recovery-note">Read-only inspection: this shows local recovery metadata and whether a retained copy is present. It does not open, change, upload, or remove retained files.</p>${panel.error ? `<p class="media-recovery-error" role="alert">Could not inspect retained copies: ${escape(panel.error)}</p>` : ''}${panel.accountHasUnindexedStage ? '<p class="media-recovery-warning" role="status">Some local recovery data could not be safely matched to a folder record. Its name and contents are not shown here.</p>' : ''}${panel.loading && !panel.loaded ? '<p role="status">Loading retained-copy details…</p>' : ''}${panel.loaded && panel.items.length === 0 && !panel.accountHasUnindexedStage ? '<p class="media-empty-result">No retained copies or unresolved upload records were found for this folder.</p>' : ''}${panel.verificationMessage ? `<p role="status">${escape(panel.verificationMessage)}</p>` : ''}<p>A remote match does not resume the folder or clear retained recovery.</p>${rows}${panel.loading && panel.loaded ? '<p role="status">Loading next page…</p>' : ''}${panel.hasMore ? `<button class="button subtle" data-media-recovery-more ${panel.loading || panel.verifying ? 'disabled' : ''}>Load next 100</button>` : ''}</section>`;
  }
  private canVerify(panel: RecoveryPanel, item: RecoveryItem) {
    return this.context.supportsVerifyUpload?.() !== false && item.upload_verification_available === true && item.state === 'uncertain'
      && item.configuration_revision === panel.revision && Number.isSafeInteger(item.attempt_generation) && item.attempt_generation! > 0
      && this.rows.some(row => row.job.id === panel.jobId && row.job.revision === panel.revision && row.job.account_id === panel.accountId
        && row.active_account && !row.queued && row.status?.state !== 'running');
  }
  private async verifyUploadedCopy(index: number) {
    const panel = this.recovery; const item = panel?.items[index];
    if (!panel || !item || !this.recoveryIsCurrent(panel) || !this.canVerify(panel, item) || panel.loading || panel.verifying
        || this.context.blocked() || !this.context.connected() || !this.context.reachable() || !this.context.supported()) return;
    panel.verifying = true; panel.verificationMessage = 'Verifying the remote copy; recovery is unchanged…'; this.context.render();
    try {
      const response = await this.context.request<{job_id:string;account_id:string;revision:number;attempt_generation:number;source_relative_path:string;destination_path:string;status:string;recovery_retained:boolean;backup_resumed:boolean}>('media_job_verify_upload', {
        job_id:panel.jobId, expected_account_id:panel.accountId, expected_revision:panel.revision,
        attempt_generation:item.attempt_generation, source_relative_path:item.source_relative_path, destination_path:item.destination_path
      });
      if (!this.recoveryIsCurrent(panel) || !this.canVerify(panel, item)) return;
      if (response.job_id !== panel.jobId || response.account_id !== panel.accountId || response.revision !== panel.revision
          || response.attempt_generation !== item.attempt_generation || response.source_relative_path !== item.source_relative_path
          || response.destination_path !== item.destination_path || response.recovery_retained !== true || response.backup_resumed !== false
          || !['matched','not_matched'].includes(response.status)) throw new Error('Verification response did not match this retained attempt.');
      panel.verificationMessage = response.status === 'matched' ? 'The uploaded copy matches. Backup has not resumed; retained recovery is still kept.' : 'The uploaded copy could not be matched. Retained recovery is unchanged.';
    } catch (error) {
      if (this.recoveryIsCurrent(panel)) panel.verificationMessage = String(error instanceof Error ? error.message : error);
    } finally {
      if (this.recoveryIsCurrent(panel)) { panel.verifying = false; this.context.render(); }
    }
  }
  private recoveryIsCurrent(panel: RecoveryPanel) {
    return this.recovery === panel && panel.profileKey === this.context.key() && panel.viewRevision === this.revision
      && this.rows.some(row => row.job.id === panel.jobId && row.job.revision === panel.revision && row.job.account_id === panel.accountId && row.active_account);
  }
  private async loadRecoveryPage(append: boolean) {
    const panel = this.recovery;
    if (!panel || panel.loading || panel.verifying || !this.recoveryIsCurrent(panel)) return;
    if (append && !panel.hasMore) return;
    const requestToken = ++this.recoveryRequestToken;
    panel.requestToken = requestToken; panel.loading = true; panel.error = '';
    this.context.render();
    try {
      const response = await this.context.request<{job_id:string;account_id:string;revision:number;page:RecoveryPage}>('media_job_recovery', {
        job_id:panel.jobId, expected_revision:panel.revision, expected_account_id:panel.accountId,
        limit:100, cursor:append ? panel.nextCursor : null
      });
      if (!this.recoveryIsCurrent(panel) || panel.requestToken !== requestToken) return;
      if (response.job_id !== panel.jobId || response.account_id !== panel.accountId || response.revision !== panel.revision
          || !response.page || !Array.isArray(response.page.items) || response.page.items.length > 100) throw new Error('Recovery response did not match the selected backup.');
      if (typeof response.page.has_more !== 'boolean' || (response.page.has_more && !response.page.next_cursor)) throw new Error('Recovery page is incomplete.');
      panel.items = append ? [...panel.items, ...response.page.items] : response.page.items;
      panel.hasMore = response.page.has_more === true;
      panel.nextCursor = panel.hasMore ? response.page.next_cursor : null;
      panel.accountHasUnindexedStage = response.page.account_has_unindexed_stage === true;
      panel.loaded = true;
    } catch (error) {
      if (this.recoveryIsCurrent(panel) && panel.requestToken === requestToken) panel.error = String(error instanceof Error ? error.message : error);
    } finally {
      if (this.recoveryIsCurrent(panel) && panel.requestToken === requestToken) { panel.loading = false; this.context.render(); }
    }
  }
  async createFromFolder(input: { source: string; space: string; destination: string; filter: MediaJob['filter']; organization: MediaJob['organization']; interval: string; exclusions?: FolderExclusion[] }, onCreated: () => void) {
    const draft = {...input};
    const key = this.context.key();
    this.clearFolderCreationError(key);
    if (!draft.source || !draft.space || !draft.destination.startsWith('/') || draft.destination === '/') {
      this.folderCreateErrorKey = key;
      this.folderCreateError = 'Choose a source, a location, and an existing destination folder.';
      this.error = this.folderCreateError;
      this.context.render();
      return false;
    }
    if (!this.context.connected() || !this.context.supported()) return false;
    let created = false;
    const succeeded = await this.mutate(async () => {
      const destination = await this.context.request<{id:string;path:string;space_id:string;account_id:string}>('media_destination',{space_id:draft.space,path:draft.destination});
      if (key !== this.context.key()) throw new Error('Account changed before the folder settings were saved.');
      if (destination.space_id !== draft.space || !destination.account_id || !destination.id || !destination.path.startsWith('/')) throw new Error('The selected destination did not match this Space. Choose it again.');
      const job: MediaJob = {id:crypto.randomUUID(),revision:0,account_id:destination.account_id,source_root:draft.source,space_id:draft.space,destination_root:destination.path,destination_root_resource_id:destination.id,filter:draft.filter,organization:draft.organization,filesystem_mtime_utc:draft.organization === 'utc_year_month',interval_seconds:Number(draft.interval),enabled:true,...(draft.exclusions === undefined ? {} : {exclusions:draft.exclusions})};
      await this.context.request('media_job_set',{job,expected_revision:0,expected_account_id:destination.account_id}); return 'Folder settings enabled. Files will be checked for stability before uploading.';
    });
    created = succeeded && key === this.context.key();
    if (created) { this.clearFolderCreationError(key); onCreated(); }
    else if (key === this.context.key() && this.error) { this.folderCreateErrorKey = key; this.folderCreateError = this.error; this.context.render(); }
    return created;
  }
  private async mutate(action: () => Promise<string>): Promise<boolean> {
    if (this.saving || this.context.blocked() || !this.context.reachable()) return false;
    const key = this.context.key(); const revision = this.revision;
    let succeeded = false;
    this.saving = true; this.context.busy(true); this.error = ''; this.message = ''; this.context.render();
    try { const message = await action(); if (key === this.context.key() && revision === this.revision) { this.message = message; succeeded = true; } }
    catch(error) { if (key === this.context.key() && revision === this.revision) this.error = String(error instanceof Error ? error.message : error); }
    finally { this.saving = false; this.context.busy(false); if (key === this.context.key() && revision === this.revision) { await this.refresh(); this.context.render(); } }
    return succeeded;
  }
}
