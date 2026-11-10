import './folder-jobs.css';

export type FolderJobsContext = {
  profileId: string; accountEpoch: number; authGeneration: number;
  connected: boolean; reachable: boolean;
};
type Space = { id: string; name: string; personal: boolean; writable: boolean; encrypted?: boolean };
type JobState = 'prepared' | 'queued' | 'preparing' | 'uploading' | 'complete' | 'cancelled' | 'failed' | 'interrupted';
type FolderJob = {
  job_id: string; kind: 'upload' | 'delete'; state: JobState; space_id: string; remote_path: string;
  files_total: number; folders_total: number; bytes_total: number;
  files_completed: number; folders_completed: number; bytes_completed: number;
  cancel_requested: boolean; error?: string | null; auth_generation: number;
};
type Dependencies = {
  context(): FolderJobsContext | null;
  spaces(): Space[];
  spacesError(): string;
  blocked(): boolean;
  active(): boolean;
  request<T>(action: string, args: Record<string, unknown>): Promise<T>;
  chooseFolder(): Promise<string | null>;
  confirmDelete(message: string): Promise<boolean>;
  busy(value: boolean): void;
  render(): void;
};
const escape = (value: unknown) => String(value ?? '').replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]!));
const text = (value: unknown, limit: number): value is string => typeof value === 'string' && value.length > 0 && value.length <= limit && !/[\u0000-\u001f\u007f-\u009f]/.test(value);
const validPath = (value: string) => text(value, 4096) && value.startsWith('/') && value !== '/' && !value.includes('\\') && value.slice(1).split('/').every(part => part !== '' && part !== '.' && part !== '..');
const activeJob = (job: FolderJob) => ['queued', 'preparing', 'uploading'].includes(job.state);
const cancellable = (job: FolderJob) => job.state === 'prepared' || activeJob(job);
const contextKey = (context: FolderJobsContext) => `${context.accountEpoch}:${context.profileId}:${context.authGeneration}`;
const stateLabel: Record<JobState, string> = { prepared: 'Ready', queued: 'Queued', preparing: 'Preparing', uploading: 'Uploading', complete: 'Complete', cancelled: 'Stopped', failed: 'Failed', interrupted: 'Interrupted' };
const errorMessage = (error: unknown) => error instanceof Error ? error.message : String(error);

function validateJob(value: unknown, context: FolderJobsContext, prepared = false, expected?: Pick<FolderJob, 'job_id' | 'kind' | 'space_id' | 'remote_path'>): FolderJob {
  if (!value || typeof value !== 'object') throw new Error('The folder job could not be confirmed. Refresh its status before trying again.');
  const job = value as Partial<FolderJob>;
  if (!text(job.job_id, 256) || !text(job.space_id, 1024) || typeof job.remote_path !== 'string' || !validPath(job.remote_path) ||
      (job.kind !== 'upload' && job.kind !== 'delete') || !job.state || !Object.hasOwn(stateLabel, job.state) ||
      job.auth_generation !== context.authGeneration || (prepared && job.state !== 'prepared') ||
      ![job.files_total, job.folders_total, job.bytes_total].every(count => Number.isSafeInteger(count) && count! >= 0) ||
      (!prepared && (![job.files_completed, job.folders_completed, job.bytes_completed].every(count => Number.isSafeInteger(count) && count! >= 0) || typeof job.cancel_requested !== 'boolean')) ||
      (job.error != null && typeof job.error !== 'string') ||
      (expected && (job.job_id !== expected.job_id || job.kind !== expected.kind || job.space_id !== expected.space_id || job.remote_path !== expected.remote_path))) {
    throw new Error('The folder job no longer matches this account or folder. Refresh before trying again.');
  }
  return { ...job, files_completed: job.files_completed ?? 0, folders_completed: job.folders_completed ?? 0, bytes_completed: job.bytes_completed ?? 0, cancel_requested: job.cancel_requested ?? false } as FolderJob;
}

/** One-off folder operations. State and responses are bound to one login generation. */
export class FolderJobsView {
  private scope = '';
  private revision = 0;
  private jobs: FolderJob[] = [];
  private loading = false;
  private working = false;
  private loaded = false;
  private error = '';
  private source = '';
  private spaceId = '';
  private uploadPath = '';
  private deletePath = '';
  private deleteOpen = false;
  private timer = 0;
  private admissionUncertain = false;

  constructor(private readonly dependencies: Dependencies) {}

  reset() {
    window.clearTimeout(this.timer);
    this.timer = 0;
    this.scope = '';
    this.revision++;
    this.jobs = [];
    this.loading = false;
    this.working = false;
    this.loaded = false;
    this.error = '';
    this.source = '';
    this.spaceId = '';
    this.uploadPath = '';
    this.deletePath = '';
    this.deleteOpen = false;
    this.admissionUncertain = false;
  }

  leave() { window.clearTimeout(this.timer); this.timer = 0; }

  private context() {
    const context = this.dependencies.context();
    if (!context) {
      if (this.scope) this.reset();
      return null;
    }
    if (contextKey(context) !== this.scope) {
      this.reset();
      this.scope = contextKey(context);
    }
    return context;
  }

  private current(context: FolderJobsContext, revision: number) {
    const current = this.dependencies.context();
    return !!current && contextKey(current) === contextKey(context) && this.revision === revision;
  }

  private args(context: FolderJobsContext, extra: Record<string, unknown> = {}) {
    return { ...extra, expected_auth_generation: context.authGeneration };
  }

  private available(context: FolderJobsContext | null) {
    return !!context && context.reachable && context.connected && !this.working && !this.loading && !this.dependencies.blocked() && !this.admissionUncertain;
  }

  html() {
    const context = this.context();
    if (!context) return '';
    const spaces = this.dependencies.spaces().filter(space => space.writable && !space.encrypted);
    if (!this.spaceId && spaces.length) this.spaceId = spaces.find(space => space.personal)?.id || spaces[0].id;
    const spaceExists = spaces.some(space => space.id === this.spaceId);
    const disabled = !this.available(context);
    const options = spaces.map(space => `<option value="${escape(space.id)}" ${space.id === this.spaceId ? 'selected' : ''}>${escape(space.personal ? 'Personal' : space.name)}</option>`).join('');
    return `<section class="folder-jobs-card" aria-labelledby="folder-jobs-title">
      <div class="folder-jobs-heading"><div><h2 id="folder-jobs-title">Folder transfers <span class="mode-pill">Linux</span></h2><p>Upload a folder once, including subfolders, or delete a whole cloud folder.</p></div><button class="button subtle" data-folder-job-action="refresh" ${this.working || this.loading || !context.reachable || this.dependencies.blocked() ? 'disabled' : ''}>${this.loading ? 'Checking…' : 'Refresh jobs'}</button></div>
      ${!context.connected ? '<p class="helper-note" role="status">Connect this account to upload or delete folders.</p>' : ''}
      ${this.error ? `<p class="folder-jobs-error" role="alert">${escape(this.error)}</p>` : ''}
      ${this.dependencies.spacesError() ? `<p class="folder-jobs-error" role="alert">${escape(this.dependencies.spacesError())}</p>` : ''}
      ${this.admissionUncertain ? '<p class="helper-note" role="status">The last request could not be confirmed. Refresh jobs and review the folder in your cloud drive before starting another operation.</p>' : ''}
      <div class="folder-jobs-form"><label for="folder-job-space">Cloud location</label><select id="folder-job-space" ${disabled ? 'disabled' : ''}><option value="">Choose Personal or a Space</option>${options}</select>
        <label for="folder-job-source">Folder on this computer</label><div class="input-with-button"><input id="folder-job-source" value="${escape(this.source)}" placeholder="Choose a folder to upload" readonly/><button class="button subtle" data-folder-job-action="choose" ${disabled ? 'disabled' : ''}>Browse</button></div>
        <label for="folder-job-upload-path">New cloud folder path</label><input id="folder-job-upload-path" value="${escape(this.uploadPath)}" placeholder="/Holiday photos" maxlength="4096" ${disabled ? 'disabled' : ''}/><small>Enter the full new folder path in the selected location. Existing folders are refused; files are never merged or replaced.</small>
        <div><button class="button primary" data-folder-job-action="upload" ${disabled || !spaceExists || !this.source || !validPath(this.uploadPath) ? 'disabled' : ''}>${this.working ? 'Working…' : 'Upload folder'}</button></div>
      </div>
      <details class="folder-job-delete" ${this.deleteOpen ? 'open' : ''}><summary>Delete a cloud folder</summary><p>This deletes the selected folder and all its cloud contents. Local pending files are preserved; folders with pending changes may be refused.</p><label for="folder-job-delete-path">Existing cloud folder path in the selected location</label><input id="folder-job-delete-path" value="${escape(this.deletePath)}" placeholder="/Folder to delete" maxlength="4096" ${disabled ? 'disabled' : ''}/><button class="button subtle" data-folder-job-action="delete" ${disabled || !spaceExists || !validPath(this.deletePath) ? 'disabled' : ''}>Review deletion…</button></details>
      <div class="folder-jobs-list" aria-label="Folder jobs">${this.jobs.length ? this.jobs.map(job => this.row(job, context)).join('') : `<p class="helper-note">${this.loading ? 'Loading folder jobs…' : this.loaded ? 'No folder jobs in this account session.' : 'Refresh jobs to check this account’s folder activity.'}</p>`}</div>
    </section>`;
  }

  private row(job: FolderJob, context: FolderJobsContext) {
    const space = this.dependencies.spaces().find(value => value.id === job.space_id);
    const location = space?.personal ? 'Personal' : space?.name || 'Space';
    const progress = job.kind === 'upload' ? `${job.files_completed} / ${job.files_total} files · ${job.folders_completed} / ${job.folders_total} folders` : 'Whole cloud folder and its contents';
    const state = job.cancel_requested && cancellable(job) ? 'Stopping' : stateLabel[job.state];
    return `<article class="folder-job-row"><div><b>${job.kind === 'upload' ? 'Upload' : 'Delete'} · ${escape(location)}</b><code>${escape(job.remote_path)}</code><small>${escape(progress)}</small><small>Job ${escape(job.job_id)}</small></div><div class="folder-job-controls"><span role="status">${escape(state)}</span>${cancellable(job) ? `<button class="button subtle" data-folder-job-cancel="${escape(job.job_id)}" ${job.cancel_requested || this.working || this.loading || !context.reachable || this.dependencies.blocked() ? 'disabled' : ''}>Stop</button>` : ''}</div>${job.kind === 'upload' && cancellable(job) ? '<small class="folder-job-note">Stop adding files; files already queued may finish.</small>' : ''}${job.error ? `<p class="folder-jobs-error" role="alert">${escape(job.error)}</p>` : ''}${job.state === 'interrupted' ? '<p class="helper-note">This job was interrupted. Review its cloud folder before starting another operation.</p>' : ''}</article>`;
  }

  bind(root: HTMLElement) {
    root.querySelector<HTMLSelectElement>('#folder-job-space')?.addEventListener('change', event => {
      this.spaceId = (event.target as HTMLSelectElement).value;
      this.dependencies.render();
    });
    const updateButtons = () => {
      const context = this.context();
      const validSpace = this.dependencies.spaces().some(space => space.id === this.spaceId && space.writable && !space.encrypted);
      const upload = root.querySelector<HTMLButtonElement>('[data-folder-job-action="upload"]');
      const remove = root.querySelector<HTMLButtonElement>('[data-folder-job-action="delete"]');
      if (upload) upload.disabled = !this.available(context) || !validSpace || !this.source || !validPath(this.uploadPath);
      if (remove) remove.disabled = !this.available(context) || !validSpace || !validPath(this.deletePath);
    };
    root.querySelector<HTMLInputElement>('#folder-job-upload-path')?.addEventListener('input', event => { this.uploadPath = (event.target as HTMLInputElement).value; updateButtons(); });
    root.querySelector<HTMLInputElement>('#folder-job-delete-path')?.addEventListener('input', event => { this.deletePath = (event.target as HTMLInputElement).value; updateButtons(); });
    root.querySelector<HTMLDetailsElement>('.folder-job-delete')?.addEventListener('toggle', event => { this.deleteOpen = (event.target as HTMLDetailsElement).open; });
    root.querySelectorAll<HTMLElement>('[data-folder-job-action]').forEach(button => button.addEventListener('click', () => {
      const action = button.dataset.folderJobAction;
      if (action === 'refresh') void this.refresh();
      if (action === 'choose') void this.chooseSource();
      if (action === 'upload' || action === 'delete') void this.prepareAndStart(action);
    }));
    root.querySelectorAll<HTMLElement>('[data-folder-job-cancel]').forEach(button => button.addEventListener('click', () => { void this.cancel(button.dataset.folderJobCancel || ''); }));
  }

  async refresh() {
    const context = this.context();
    if (!context || !context.reachable || this.loading || this.working || this.dependencies.blocked()) return;
    const revision = this.revision;
    this.loading = true;
    this.dependencies.render();
    try {
      const response = await this.dependencies.request<unknown>('folder_job_list', this.args(context));
      if (!this.current(context, revision)) return;
      if (!Array.isArray(response)) throw new Error('The folder-job list could not be confirmed.');
      const jobs = response.map(value => validateJob(value, context));
      const ids = new Set(jobs.map(job => job.job_id));
      if (ids.size !== jobs.length) throw new Error('The folder-job list could not be confirmed.');
      for (const job of jobs) {
        const known = this.jobs.find(value => value.job_id === job.job_id);
        if (known) validateJob(job, context, false, known);
      }
      this.jobs = jobs;
      this.loaded = true;
      this.error = '';
      this.admissionUncertain = false;
    } catch (error) {
      if (this.current(context, revision)) this.error = errorMessage(error);
    } finally {
      if (this.current(context, revision)) { this.loading = false; this.dependencies.render(); this.schedulePoll(); }
    }
  }

  private async chooseSource() {
    const context = this.context();
    if (!this.available(context) || !context) return;
    const revision = this.revision;
    this.working = true;
    this.dependencies.render();
    try {
      const source = await this.dependencies.chooseFolder();
      if (!this.current(context, revision) || source == null) return;
      if (!source.startsWith('/') || !text(source, 4096)) throw new Error('Choose an absolute local folder path.');
      this.source = source;
      if (!this.uploadPath) this.uploadPath = `/${source.split('/').filter(Boolean).at(-1) || 'Upload'}`;
      this.error = '';
    } catch (error) {
      if (this.current(context, revision)) this.error = errorMessage(error);
    } finally {
      if (this.current(context, revision)) { this.working = false; this.dependencies.render(); }
    }
  }

  private async prepareAndStart(kind: FolderJob['kind']) {
    const context = this.context();
    if (!this.available(context) || !context) return;
    const space = this.dependencies.spaces().find(value => value.id === this.spaceId && value.writable && !value.encrypted);
    const path = kind === 'upload' ? this.uploadPath : this.deletePath;
    if (!space || !validPath(path) || (kind === 'upload' && !this.source)) return;
    const revision = this.revision;
    this.working = true;
    this.error = '';
    this.dependencies.busy(true);
    this.dependencies.render();
    let startSent = false;
    try {
      const response = await this.dependencies.request<unknown>('folder_job_prepare', this.args(context, { kind, space_id: space.id, remote_path: path, ...(kind === 'upload' ? { source_path: this.source } : {}) }));
      if (!this.current(context, revision)) return;
      const plan = validateJob(response, context, true);
      if (plan.kind !== kind || plan.space_id !== space.id || plan.remote_path !== path) throw new Error('The prepared folder does not match your selection. Refresh before trying again.');
      this.upsert(plan);
      if (kind === 'delete') {
        const approved = await this.dependencies.confirmDelete(`Delete this cloud folder and all its cloud contents?\n\nLocation: ${space.personal ? 'Personal' : space.name}\nFolder: ${plan.remote_path}\n\nLocal pending files are preserved. Folders with pending changes may be refused.`);
        if (!this.current(context, revision) || approved !== true) return;
      }
      if (!this.dependencies.context()?.connected) throw new Error('Reconnect this account before starting the folder job.');
      startSent = true;
      const result = await this.dependencies.request<unknown>('folder_job_start', this.args(context, { job_id: plan.job_id }));
      if (!this.current(context, revision)) return;
      this.upsert(validateJob(result, context, false, plan));
    } catch (error) {
      if (this.current(context, revision)) {
        this.error = errorMessage(error);
        this.admissionUncertain = startSent;
      }
    } finally {
      this.dependencies.busy(false);
      if (this.current(context, revision)) { this.working = false; this.dependencies.render(); this.schedulePoll(); }
    }
  }

  private async cancel(jobId: string) {
    const context = this.context();
    const job = this.jobs.find(value => value.job_id === jobId);
    if (!context || !job || !cancellable(job) || job.cancel_requested || !context.reachable || this.working || this.loading || this.dependencies.blocked()) return;
    const revision = this.revision;
    this.working = true;
    this.error = '';
    this.dependencies.busy(true);
    this.dependencies.render();
    try {
      const result = await this.dependencies.request<unknown>('folder_job_cancel', this.args(context, { job_id: job.job_id }));
      if (!this.current(context, revision)) return;
      this.upsert(validateJob(result, context, false, job));
    } catch (error) {
      if (this.current(context, revision)) this.error = errorMessage(error);
    } finally {
      this.dependencies.busy(false);
      if (this.current(context, revision)) { this.working = false; this.dependencies.render(); this.schedulePoll(); }
    }
  }

  private upsert(job: FolderJob) {
    this.jobs = [job, ...this.jobs.filter(value => value.job_id !== job.job_id)];
    this.loaded = true;
  }

  private schedulePoll() {
    window.clearTimeout(this.timer);
    this.timer = 0;
    if (this.dependencies.active() && this.jobs.some(activeJob)) this.timer = window.setTimeout(() => { void this.poll(); }, 2000);
  }

  private async poll() {
    const context = this.context();
    if (!context || !context.reachable || !this.dependencies.active()) return;
    if (this.working || this.loading || this.dependencies.blocked()) { this.schedulePoll(); return; }
    const revision = this.revision;
    this.loading = true;
    try {
      for (const job of this.jobs.filter(activeJob)) {
        const result = await this.dependencies.request<unknown>('folder_job_status', this.args(context, { job_id: job.job_id }));
        if (!this.current(context, revision)) return;
        this.upsert(validateJob(result, context, false, job));
      }
    } catch (error) {
      if (this.current(context, revision)) this.error = errorMessage(error);
      // A failed status request is not an invitation to resubmit the operation.
    } finally {
      if (this.current(context, revision)) { this.loading = false; this.dependencies.render(); this.schedulePoll(); }
    }
  }
}
