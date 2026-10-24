/** Account-scoped recurring media backup controls. Preview stays independent. */
export type MediaJob = {
  id: string; revision: number; account_id: string; source_root: string; space_id: string; destination_root: string;
  destination_root_resource_id: string; filter: 'photos' | 'videos' | 'all';
  organization: 'preserve_relative_path' | 'utc_year_month'; filesystem_mtime_utc: boolean;
  interval_seconds: number; enabled: boolean;
};
type RunStatus = { state: string; uploaded: number; unchanged: number; waiting_for_stability: number; conflicts: number; needs_attention: number; last_error?: string | null };
type JobRow = { job: MediaJob; status: RunStatus | null; queued: boolean; active_account: boolean };
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
  supported(): boolean; spaces(): { id: string; name: string; writable: boolean; encrypted: boolean }[];
  request<T>(action: string, args?: Record<string, unknown>): Promise<T>;
  chooseSource(): Promise<string | null>; confirm(message: string): Promise<boolean>; busy(value: boolean): void; render(): void;
};
const escape = (value: unknown) => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]!));
const formatRecoveryBytes = (bytes: number) => bytes < 1024 ? `${bytes} B` : `${(bytes / 1024).toFixed(1)} KiB`;
export class MediaJobsView {
  private rows: JobRow[] = [];
  private loading = false;
  private saving = false;
  private loaded = false;
  private error = '';
  private loadError = '';
  private message = '';
  private revision = 0;
  private recovery: RecoveryPanel | null = null;
  private recoveryRequestToken = 0;
  private draft = this.emptyDraft();
  constructor(private readonly context: Context) {}
  private emptyDraft() { return { source: '', space: '', destination: '', filter: 'photos' as MediaJob['filter'], organization: 'preserve_relative_path' as MediaJob['organization'], interval: '3600' }; }
  reset() { this.revision++; this.recoveryRequestToken++; this.recovery = null; this.rows = []; this.loading = false; this.loaded = false; this.error = ''; this.loadError = ''; this.message = ''; this.draft = this.emptyDraft(); }
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
  html() {
    if (!this.context.supported()) return '';
    const blocked = this.saving || this.context.blocked() || !this.context.reachable();
    const createBlocked = blocked || !this.context.connected();
    const disabled = (value: boolean) => value ? 'disabled' : '';
    const spaces = this.context.spaces().filter(s => s.writable && !s.encrypted);
    const draft = this.draft;
    return `<section class="media-backups" aria-label="Recurring media backups"><div class="section-heading"><div><div class="eyebrow">SOURCE-PRESERVING BACKUP</div><h1>Media backups</h1><p class="lede">Upload photos and videos for the active account. Originals stay on this computer.</p></div><button class="button subtle" data-media-refresh ${disabled(blocked || this.loading)}>Refresh backups</button></div>
      <p class="media-form-note">Backups follow Pause Sync. Uploads count as complete only after their cloud contents are verified. Name conflicts and uncertain uploads need attention; they are not silently overwritten.</p>
      ${this.error || this.loadError ? `<div class="media-warning" role="alert">${escape(this.error || this.loadError)}</div>` : ''}${this.message ? `<p role="status">${escape(this.message)}</p>` : ''}
      <div class="media-job-list">${this.rows.map(row => this.row(row, blocked)).join('') || `<p class="media-empty-result">${this.loading ? 'Loading backups…' : this.loaded ? 'No media backups for this account yet.' : !this.context.reachable() ? 'Start the Raiun background agent to load media backups.' : !this.context.connected() ? 'Sign in to your OpenCloud account to load and manage media backups.' : 'Refresh to load media backups.'}</p>`}</div>
      <form id="media-job-form" class="settings-card media-form"><h3>Add a media backup</h3>
      <div class="media-field"><label for="media-job-source">Source folder</label><div class="input-with-button"><input id="media-job-source" value="${escape(draft.source)}" readonly placeholder="Choose a local folder"/><button type="button" class="button subtle" data-media-source ${disabled(blocked)}>Browse</button></div></div>
      <div class="media-options"><div class="media-field"><label for="media-job-space">OpenCloud location</label><select id="media-job-space" ${disabled(createBlocked)}><option value="">Choose Personal or a Space</option>${spaces.map(s => `<option value="${escape(s.id)}" ${s.id === draft.space ? 'selected' : ''}>${escape(s.name)}</option>`).join('')}</select></div>
      <div class="media-field"><label for="media-job-destination">Existing folder in this location</label><input id="media-job-destination" value="${escape(draft.destination)}" placeholder="/Photos" ${disabled(createBlocked)}/><small>Use a folder below the location root. Encrypted destinations are not supported by media backup yet.</small></div></div>
      <div class="media-options"><div class="media-field"><label for="media-job-filter">Include</label><select id="media-job-filter" ${disabled(blocked)}>${(['photos','videos','all'] as const).map(value => `<option value="${value}" ${draft.filter === value ? 'selected' : ''}>${value === 'all' ? 'All files' : value === 'photos' ? 'Photos' : 'Videos'}</option>`).join('')}</select></div>
      <div class="media-field"><label for="media-job-organization">Destination organization</label><select id="media-job-organization" ${disabled(blocked)}><option value="preserve_relative_path" ${draft.organization === 'preserve_relative_path' ? 'selected' : ''}>Keep folders and filenames</option><option value="utc_year_month" ${draft.organization === 'utc_year_month' ? 'selected' : ''}>Filesystem modified date (UTC year/month)</option></select></div>
      <div class="media-field"><label for="media-job-interval">Check for new files</label><select id="media-job-interval" ${disabled(blocked)}>${[['60','Every minute'],['900','Every 15 minutes'],['3600','Every hour'],['86400','Every day']].map(([value,label]) => `<option value="${value}" ${draft.interval === value ? 'selected' : ''}>${label}</option>`).join('')}</select></div></div>
      <p class="media-form-note">Photos includes recognized images; Videos includes recognized videos. File contents determine the type, not the extension. All files also includes other regular files. Scans include subfolders and skip symbolic links.</p>
      <p class="media-form-note">Date organization uses filesystem modification time, not photo capture time. New files must remain unchanged across two scans at least ten seconds apart. Files larger than 8 GiB need a regular synced folder.</p>
      ${!this.context.connected() ? '<p>Sign in to choose and verify a destination.</p>' : ''}<button type="submit" class="button primary" ${disabled(createBlocked)}>${this.saving ? 'Saving…' : 'Enable backup'}</button></form></section>`;
  }
  private row(row: JobRow, blocked: boolean) {
    const {job,status} = row; const active = row.queued || status?.state === 'running';
    const label = !row.active_account ? 'Different signed-in account' : !job.enabled ? 'Paused' : row.queued ? 'Queued' : status?.state?.replaceAll('_',' ') || 'Waiting for first scan';
    const inspecting = this.recovery?.jobId === job.id && this.recovery.revision === job.revision && this.recovery.accountId === job.account_id;
    return `<article class="settings-card media-job-card"><div><h3>${escape(job.source_root.split(/[\\/]/).filter(Boolean).at(-1) || job.source_root)}</h3><span class="mode-pill">${escape(label)}</span></div><p><code>${escape(job.source_root)}</code> → <code>${escape(job.destination_root)}</code></p>
      <p class="media-form-note">Include: ${job.filter === 'photos' ? 'Photos (recognized image files)' : job.filter === 'videos' ? 'Videos (recognized video files)' : 'All regular files'}. Includes subfolders; symbolic links are skipped.</p>
      ${status ? `<p role="status">${status.uploaded} uploaded · ${status.unchanged} already backed up · ${status.waiting_for_stability} waiting for stable files · ${status.conflicts + status.needs_attention} need attention</p>${status.last_error ? `<p class="exclusion-error">${escape(status.last_error)}</p>` : ''}` : ''}
      <div class="media-job-actions"><button class="button subtle" data-media-toggle="${escape(job.id)}" ${blocked || (!job.enabled && !row.active_account) ? 'disabled' : ''}>${job.enabled ? 'Pause backup' : 'Resume backup'}</button><button class="button subtle" data-media-run="${escape(job.id)}" ${blocked || active || !job.enabled || !row.active_account || !this.context.connected() ? 'disabled' : ''}>Check now</button><button class="button subtle" data-media-remove="${escape(job.id)}" ${blocked || active ? 'disabled' : ''}>Remove backup</button><button class="button subtle" data-media-recovery="${escape(job.id)}" ${blocked || !row.active_account || this.recovery?.loading ? 'disabled' : ''}>${inspecting ? 'Hide retained copies' : 'Inspect retained copies'}</button></div>${inspecting ? this.recoveryHtml(this.recovery!) : ''}</article>`;
  }
  bind(root: HTMLElement) {
    root.querySelector('[data-media-refresh]')?.addEventListener('click', () => void this.refresh());
    root.querySelector('[data-media-source]')?.addEventListener('click', () => void this.choose());
    const fields = {space:'media-job-space',destination:'media-job-destination',filter:'media-job-filter',organization:'media-job-organization',interval:'media-job-interval'};
    for (const [key,id] of Object.entries(fields)) {
      const element = root.querySelector<HTMLInputElement | HTMLSelectElement>(`#${id}`);
      element?.addEventListener('input', () => { Object.assign(this.draft, {[key]:element.value}); });
    }
    root.querySelector('#media-job-form')?.addEventListener('submit', event => { event.preventDefault(); void this.create(); });
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
      if (button.dataset.mediaToggle && (row.job.enabled || row.active_account)) void this.mutate(async () => { await this.context.request('media_job_set',{job:{...row.job,enabled:!row.job.enabled},expected_revision:row.job.revision,expected_account_id:row.job.account_id}); return row.job.enabled ? 'Backup paused.' : 'Backup enabled.'; });
      else if (button.dataset.mediaRun && row.active_account) void this.mutate(async () => { await this.context.request('media_job_run',{job_id:id,expected_revision:row.job.revision,expected_account_id:row.job.account_id}); return 'Backup check queued. Watch its status for verified uploads.'; });
      else if (button.dataset.mediaRemove) void this.remove(row);
    }));
  }
  private async remove(row: JobRow) {
    if (this.saving || this.context.blocked() || !this.context.reachable() || !this.context.supported()) return;
    const key = this.context.key();
    const revision = this.revision;
    const { id, account_id, revision: jobRevision } = row.job;
    try {
      if (await this.context.confirm('Remove this backup schedule? Source files, cloud files and recovery copies will stay in place.') !== true) return;
      if (key !== this.context.key() || revision !== this.revision || this.saving || this.context.blocked() || !this.context.reachable() || !this.context.supported()) return;
      const current = this.rows.find(value => value.job.id === id && value.job.account_id === account_id && value.job.revision === jobRevision);
      if (!current || current.queued || current.status?.state === 'running') return;
      await this.mutate(async () => {
        await this.context.request('media_job_remove', { job_id: id, expected_revision: jobRevision, expected_account_id: account_id });
        return 'Backup schedule removed. Files remain in place.';
      });
    } catch (error) {
      if (key === this.context.key() && revision === this.revision) { this.error = String(error instanceof Error ? error.message : error); this.context.render(); }
    }
  }
  private recoveryHtml(panel: RecoveryPanel) {
    const rows = panel.items.map((item, index) => {
      const source = `${item.source_root.replace(/[\\/]$/, '')}/${item.source_relative_path}`;
      const revision = item.configuration_revision == null ? 'Legacy or unbound revision' : `Backup revision ${item.configuration_revision}`;
      const copy = item.staged_copy_present
        ? `Retained copy present${item.staged_copy_size == null ? '' : ` · ${formatRecoveryBytes(item.staged_copy_size)}`}`
        : 'No verified retained copy found';
      return `<article class="media-recovery-item"><div><b>${escape(item.state.replaceAll('_',' '))}</b><span>${escape(revision)} · ${escape(copy)}</span></div><p><span>Original</span><code>${escape(source)}</code></p><p><span>Destination</span><code>${escape(item.destination_path)}</code></p><small>${formatRecoveryBytes(item.source_size)} source size${item.attempt_generation == null ? '' : ` · attempt ${item.attempt_generation}`}</small>${this.canVerify(panel, item) ? `<button class="button subtle" data-media-verify="${index}" ${panel.verifying || panel.loading || this.context.blocked() || !this.context.connected() ? 'disabled' : ''}>Verify uploaded copy</button>` : ''}</article>`;
    }).join('');
    return `<section class="media-recovery" aria-label="Retained media copies"><p class="media-recovery-note">Read-only inspection: this shows local recovery metadata and whether a retained copy is present. It does not open, change, upload, or remove retained files.</p>${panel.error ? `<p class="media-recovery-error" role="alert">Could not inspect retained copies: ${escape(panel.error)}</p>` : ''}${panel.accountHasUnindexedStage ? '<p class="media-recovery-warning" role="status">Some local recovery data could not be safely matched to a backup record. Its name and contents are not shown here.</p>' : ''}${panel.loading && !panel.loaded ? '<p role="status">Loading retained-copy details…</p>' : ''}${panel.loaded && panel.items.length === 0 && !panel.accountHasUnindexedStage ? '<p class="media-empty-result">No retained copies or unresolved upload records were found for this backup.</p>' : ''}${panel.verificationMessage ? `<p role="status">${escape(panel.verificationMessage)}</p>` : ''}<p>A remote match does not resume backup or clear retained recovery.</p>${rows}${panel.loading && panel.loaded ? '<p role="status">Loading next page…</p>' : ''}${panel.hasMore ? `<button class="button subtle" data-media-recovery-more ${panel.loading || panel.verifying ? 'disabled' : ''}>Load next 100</button>` : ''}</section>`;
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
  private async choose() {
    if (this.saving || this.context.blocked()) return;
    const key = this.context.key();
    await this.mutate(async () => { const source = await this.context.chooseSource(); if (source && key === this.context.key()) this.draft.source = source; return ''; });
  }
  private async create() {
    const draft = {...this.draft};
    const key = this.context.key();
    if (!draft.source || !draft.space || !draft.destination.startsWith('/') || draft.destination === '/') { this.error = 'Choose a source, a location, and an existing destination folder such as /Photos.'; this.context.render(); return; }
    if (!this.context.connected()) return;
    await this.mutate(async () => {
      const destination = await this.context.request<{id:string;path:string;space_id:string;account_id:string}>('media_destination',{space_id:draft.space,path:draft.destination});
      if (key !== this.context.key()) throw new Error('Account changed before the backup was saved.');
      const job: MediaJob = {id:crypto.randomUUID(),revision:0,account_id:destination.account_id,source_root:draft.source,space_id:draft.space,destination_root:destination.path,destination_root_resource_id:destination.id,filter:draft.filter,organization:draft.organization,filesystem_mtime_utc:draft.organization === 'utc_year_month',interval_seconds:Number(draft.interval),enabled:true};
      await this.context.request('media_job_set',{job,expected_revision:0,expected_account_id:destination.account_id}); this.draft = this.emptyDraft(); return 'Backup enabled. Files will be checked for stability before uploading.';
    });
  }
  private async mutate(action: () => Promise<string>) {
    if (this.saving || this.context.blocked() || !this.context.reachable()) return;
    const key = this.context.key(); const revision = this.revision;
    this.saving = true; this.context.busy(true); this.error = ''; this.message = ''; this.context.render();
    try { const message = await action(); if (key === this.context.key() && revision === this.revision) this.message = message; }
    catch(error) { if (key === this.context.key() && revision === this.revision) this.error = String(error instanceof Error ? error.message : error); }
    finally { this.saving = false; this.context.busy(false); if (key === this.context.key() && revision === this.revision) { await this.refresh(); this.context.render(); } }
  }
}
