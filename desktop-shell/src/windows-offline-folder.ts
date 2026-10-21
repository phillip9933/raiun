export type WindowsOfflineFolderContext = {
  profileId: 'default';
  accountEpoch: number;
  authGeneration: number;
  recoveryScopeToken: string;
  flowGeneration: number;
  server: string | null;
  clientId: string | null;
  cloudRoot: string | null;
};

/** One exact ordinary directory from the authenticated folder catalog. */
export type WindowsOfflineFolderIntentState =
  | 'none' | 'known' | 'unknown' | 'unavailable' | 'recovery_required';

export type WindowsOfflineFolderSavedIntent = {
  state: WindowsOfflineFolderIntentState;
  activePinId: string | null;
  stagingPinId: string | null;
  stagingIsInitial: boolean;
};

export type WindowsOfflineFolderRow = {
  /** Friendly authenticated namespace label; display-only. */
  spaceLabel: string;
  spaceId: string;
  rootResourceId: string;
  path: string;
  resourceId: string;
  /** Durable cache intent from the latest authenticated page; display/admission hint only. */
  savedIntent?: WindowsOfflineFolderSavedIntent;
};

export type WindowsOfflineFolderProgress = {
  pin_id: string;
  root_resource_id: string;
  path: string;
  state: 'building' | 'ready' | 'stale' | 'unavailable';
  item_count: number;
  ready_content_count: number;
  required_content_count: number;
};

export type WindowsOfflineFolderJobState =
  | 'prepared'
  | 'running'
  | 'complete'
  | 'cancelled'
  | 'failed'
  | 'recovery_required';

export type WindowsOfflineFolderJob = {
  job_id: string;
  state: WindowsOfflineFolderJobState;
  kind: 'folder';
  folder: WindowsOfflineFolderProgress | null;
  cancel_requested: boolean;
  recovery_required: boolean;
};

export type WindowsOfflineFolderControllerState = {
  job: WindowsOfflineFolderJob | null;
  loading: boolean;
  error: string;
  /** A start reply was lost after the reservation ID was received. */
  admissionUncertain: boolean;
};

export type WindowsOfflineFolderRequest = (
  action: string,
  args: Record<string, unknown>
) => Promise<unknown>;

type Fence = { key: string; sequence: number; current: () => boolean };
type Operation = 'start' | 'resume' | 'refresh';

const recoveryTokenPattern = /^[0-9a-f]{64}$/;
const jobIdPattern = /^[0-9a-f]{32}$/;
const pinIdPattern = /^[0-9a-f]{64}$/;
const controlCharacters = /[\u0000-\u001f\u007f-\u009f]/u;
const jobStates = new Set<WindowsOfflineFolderJobState>([
  'prepared', 'running', 'complete', 'cancelled', 'failed', 'recovery_required'
]);
const folderStates = new Set(['building', 'ready', 'stale', 'unavailable']);

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const keys = [...expected].sort();
  return actual.length === keys.length && actual.every((key, index) => key === keys[index]);
}

function validText(value: unknown, maxBytes: number): value is string {
  return typeof value === 'string' && value.trim().length > 0 &&
    new TextEncoder().encode(value).length <= maxBytes && !controlCharacters.test(value);
}

function validContext(context: WindowsOfflineFolderContext): boolean {
  return isRecord(context) && context.profileId === 'default' &&
    Number.isSafeInteger(context.accountEpoch) && context.accountEpoch >= 0 &&
    Number.isSafeInteger(context.authGeneration) && context.authGeneration > 0 &&
    Number.isSafeInteger(context.flowGeneration) && context.flowGeneration >= 0 &&
    typeof context.recoveryScopeToken === 'string' && recoveryTokenPattern.test(context.recoveryScopeToken) &&
    (context.server === null || validText(context.server, 4096)) &&
    (context.clientId === null || validText(context.clientId, 4096)) &&
    (context.cloudRoot === null || validText(context.cloudRoot, 4096));
}

function accountScopeKey(context: WindowsOfflineFolderContext): string {
  if (!validContext(context)) throw new Error('The Windows account scope is unavailable.');
  return JSON.stringify([
    context.profileId, context.accountEpoch, context.authGeneration,
    context.recoveryScopeToken, context.server, context.clientId, context.cloudRoot
  ]);
}

function validFolderPath(path: unknown): path is string {
  return typeof path === 'string' && path.startsWith('/') &&
    (path === '/' || !path.endsWith('/')) && !path.includes('//') && !path.includes('\\') &&
    !controlCharacters.test(path) && new TextEncoder().encode(path).length <= 16 * 1024 &&
    !path.split('/').some((part) => part === '.' || part === '..');
}

function validRow(row: WindowsOfflineFolderRow): boolean {
  return isRecord(row) && validText(row.spaceLabel, 512) && validText(row.spaceId, 512) &&
    validText(row.rootResourceId, 16 * 1024) && validFolderPath(row.path) &&
    validText(row.resourceId, 16 * 1024);
}

export function windowsOfflineFolderContextKey(
  context: WindowsOfflineFolderContext,
  row: WindowsOfflineFolderRow
): string {
  if (!validContext(context) || !validRow(row)) {
    throw new Error('The selected Windows folder is unavailable. Refresh the folder list.');
  }
  return JSON.stringify([
    context.profileId, context.accountEpoch, context.authGeneration,
    context.recoveryScopeToken, context.flowGeneration, context.server,
    context.clientId, context.cloudRoot, row.spaceId, row.rootResourceId,
    row.path, row.resourceId
  ]);
}

function validCount(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0 && (value as number) <= 10_000;
}

function validateFolderProgress(value: unknown): WindowsOfflineFolderProgress {
  if (!isRecord(value) || !exactKeys(value, [
    'pin_id', 'root_resource_id', 'path', 'state', 'item_count',
    'ready_content_count', 'required_content_count'
  ]) || typeof value.pin_id !== 'string' || !pinIdPattern.test(value.pin_id) ||
      !validText(value.root_resource_id, 16 * 1024) || !validFolderPath(value.path) ||
      typeof value.state !== 'string' || !folderStates.has(value.state) ||
      !validCount(value.item_count) || !validCount(value.ready_content_count) ||
      !validCount(value.required_content_count) || value.required_content_count > value.item_count ||
      value.ready_content_count > value.required_content_count ||
      (value.state === 'ready' && value.ready_content_count !== value.required_content_count)) {
    throw new Error('The agent returned invalid saved-folder progress.');
  }
  return value as WindowsOfflineFolderProgress;
}

export function validateWindowsOfflineFolderJob(
  value: unknown,
  expectedFolder?: WindowsOfflineFolderRow
): WindowsOfflineFolderJob {
  if (!isRecord(value) || !exactKeys(value, [
    'job_id', 'state', 'kind', 'folder', 'cancel_requested', 'recovery_required'
  ]) || typeof value.job_id !== 'string' || !jobIdPattern.test(value.job_id) ||
      typeof value.state !== 'string' || !jobStates.has(value.state as WindowsOfflineFolderJobState) ||
      value.kind !== 'folder' || typeof value.cancel_requested !== 'boolean' ||
      typeof value.recovery_required !== 'boolean' ||
      value.recovery_required !== (value.state === 'recovery_required')) {
    throw new Error('The agent returned an invalid offline-folder status.');
  }
  const folder = value.folder === null ? null : validateFolderProgress(value.folder);
  if ((value.state === 'prepared' && folder !== null) ||
      (value.state === 'complete' && (folder === null || folder.state !== 'ready')) ||
      (folder !== null && expectedFolder !== undefined &&
        (folder.root_resource_id !== expectedFolder.resourceId || folder.path !== expectedFolder.path))) {
    throw new Error('The agent returned invalid folder preparation status.');
  }
  return { ...value, folder } as WindowsOfflineFolderJob;
}

function common(context: WindowsOfflineFolderContext): Record<string, unknown> {
  return {
    profile_id: context.profileId,
    expected_generation: context.authGeneration,
    expected_recovery_scope_token: context.recoveryScopeToken
  };
}

function folderFields(row: WindowsOfflineFolderRow): Record<string, unknown> {
  return {
    space_id: row.spaceId,
    root_resource_id: row.rootResourceId,
    path: row.path,
    resource_id: row.resourceId
  };
}

function pin(value: string | null, label: string): string {
  if (typeof value !== 'string' || !pinIdPattern.test(value)) {
    throw new Error(`Select the exact saved folder snapshot to ${label}.`);
  }
  return value;
}

export function windowsOfflineFolderJobMessage(job: WindowsOfflineFolderJob): string {
  switch (job.state) {
    case 'prepared': return 'Folder job is prepared. Start it to continue.';
    case 'running': return job.cancel_requested ? 'Stopping the folder download…' : 'Saving this folder for offline use…';
    case 'complete': return 'This folder is saved for offline use.';
    case 'cancelled': return 'The folder download was cancelled. Any verified files remain saved.';
    case 'failed': return 'The folder download could not finish. Check its status before trying again.';
    case 'recovery_required': return 'This folder download needs recovery. Keep the files and review recovery before retrying.';
  }
}

export class WindowsOfflineFolderController {
  readonly state: WindowsOfflineFolderControllerState = {
    job: null, loading: false, error: '', admissionUncertain: false
  };
  private activeKey: string | null = null;
  private activeScopeKey: string | null = null;
  private jobScopeKey: string | null = null;
  private jobRow: WindowsOfflineFolderRow | null = null;
  get knownJobRow(): WindowsOfflineFolderRow | null { return this.jobRow; }
  private requestSequence = 0;

  setSelection(context: WindowsOfflineFolderContext | null, row: WindowsOfflineFolderRow | null): void {
    if (context === null || row === null) {
      this.clearSelection();
      return;
    }
    const nextKey = windowsOfflineFolderContextKey(context, row);
    const nextScopeKey = accountScopeKey(context);
    if (nextKey === this.activeKey && nextScopeKey === this.activeScopeKey) return;
    const preserveKnownJob = this.jobScopeKey === nextScopeKey && this.state.job !== null &&
      (this.state.admissionUncertain || this.state.job.state === 'running' || this.state.job.state === 'prepared');
    this.activeKey = nextKey;
    this.activeScopeKey = nextScopeKey;
    this.requestSequence += 1;
    this.state.loading = false;
    if (!preserveKnownJob) {
      this.state.job = null;
      this.jobScopeKey = null;
      this.jobRow = null;
      this.state.error = '';
      this.state.admissionUncertain = false;
    }
  }

  clearSelection(): void {
    if (this.activeKey === null && this.state.job === null) return;
    this.activeKey = null;
    this.activeScopeKey = null;
    this.requestSequence += 1;
    this.state.job = null;
    this.jobScopeKey = null;
    this.jobRow = null;
    this.state.loading = false;
    this.state.error = '';
    this.state.admissionUncertain = false;
  }

  start(context: WindowsOfflineFolderContext, row: WindowsOfflineFolderRow, request: WindowsOfflineFolderRequest, current: () => boolean): Promise<void> {
    return this.launch('start', context, row, null, null, request, current);
  }

  resume(context: WindowsOfflineFolderContext, row: WindowsOfflineFolderRow, pinId: string, request: WindowsOfflineFolderRequest, current: () => boolean): Promise<void> {
    return this.launch('resume', context, row, pin(pinId, 'resume'), null, request, current);
  }

  refresh(context: WindowsOfflineFolderContext, row: WindowsOfflineFolderRow, activePinId: string, stagingPinId: string | null, request: WindowsOfflineFolderRequest, current: () => boolean): Promise<void> {
    return this.launch('refresh', context, row, pin(activePinId, 'refresh'), stagingPinId === null ? null : pin(stagingPinId, 'refresh'), request, current);
  }

  async pollStatus(context: WindowsOfflineFolderContext, row: WindowsOfflineFolderRow, request: WindowsOfflineFolderRequest, current: () => boolean): Promise<void> {
    await this.inspect(context, row, request, current, false);
  }

  async cancel(context: WindowsOfflineFolderContext, row: WindowsOfflineFolderRow, request: WindowsOfflineFolderRequest, current: () => boolean): Promise<void> {
    await this.inspect(context, row, request, current, true);
  }

  private async launch(
    operation: Operation,
    context: WindowsOfflineFolderContext,
    row: WindowsOfflineFolderRow,
    activePinId: string | null,
    stagingPinId: string | null,
    request: WindowsOfflineFolderRequest,
    isContextCurrent: () => boolean
  ): Promise<void> {
    if (this.loadingSameSelection(context, row)) return;
    const fence = this.begin(context, row, isContextCurrent);
    if (!fence) return;
    if (this.state.admissionUncertain || (this.state.job !== null &&
        (this.state.job.state === 'running' || this.state.job.state === 'prepared'))) {
      this.state.error = 'A folder job may already be running. Check its status before starting another.';
      return;
    }
    this.state.loading = true;
    this.state.error = '';
    let knownJobId: string | null = null;
    try {
      const preparedValue = await request('windows_offline_folder_prepare', {
        ...common(context), ...folderFields(row)
      });
      const prepared = validateWindowsOfflineFolderJob(preparedValue, row);
      if (prepared.state !== 'prepared' || prepared.folder !== null) {
        throw new Error('The agent did not return a new prepared folder job.');
      }
      knownJobId = prepared.job_id;
      if (!fence.current()) {
        // Keep a known reservation available for status/cancel if only the
        // selected row changed while preparation was in flight.
        if (this.activeScopeKey === accountScopeKey(context)) {
          this.state.job = prepared;
          this.jobScopeKey = accountScopeKey(context);
          this.jobRow = { ...row };
          this.state.admissionUncertain = true;
        }
        return;
      }
      // Retain the known reservation ID before sending a potentially ambiguous start.
      this.state.job = prepared;
      this.jobScopeKey = accountScopeKey(context);
      this.jobRow = { ...row };
      this.state.admissionUncertain = true;
      const action = `windows_offline_folder_${operation}`;
      const args: Record<string, unknown> = {
        ...common(context), ...folderFields(row), job_id: knownJobId
      };
      if (operation === 'resume') args.pin_id = activePinId;
      if (operation === 'refresh') {
        args.pin_id = activePinId;
        if (stagingPinId !== null) args.staging_pin_id = stagingPinId;
      }
      const value = await request(action, args);
      const result = validateWindowsOfflineFolderJob(value, row);
      if (result.job_id !== knownJobId) throw new Error('The agent returned a different folder job.');
      if (fence.current()) {
        this.state.job = result;
        this.jobScopeKey = accountScopeKey(context);
        this.jobRow = { ...row };
        this.state.admissionUncertain = false;
      }
    } catch (error) {
      if (fence.current()) {
        if (knownJobId === null) {
          this.state.error = errorMessage(error, 'Folder job preparation failed. Refresh the folder list and try again.');
        } else {
          this.state.admissionUncertain = true;
          this.state.error = `The folder job may have started, but its reply could not be confirmed. ${errorMessage(error, 'Check this job status before trying again.')}`;
        }
      }
    } finally {
      this.finish(fence, isContextCurrent);
    }
  }

  private async inspect(context: WindowsOfflineFolderContext, row: WindowsOfflineFolderRow, request: WindowsOfflineFolderRequest, isContextCurrent: () => boolean, cancel: boolean): Promise<void> {
    if (this.loadingSameSelection(context, row)) return;
    const fence = this.begin(context, row, isContextCurrent);
    if (!fence) return;
    const job = this.state.job;
    if (job === null) {
      if (fence.current()) this.state.error = 'There is no known folder job to inspect.';
      return;
    }
    this.state.loading = true;
    this.state.error = '';
    try {
      const value = await request(cancel ? 'windows_offline_folder_cancel' : 'windows_offline_folder_status', {
        ...common(context), job_id: job.job_id
      });
      const result = validateWindowsOfflineFolderJob(
        value,
        this.jobScopeKey === accountScopeKey(context) ? (this.jobRow ?? row) : row
      );
      if (result.job_id !== job.job_id) throw new Error('The agent returned a different folder job.');
      if (fence.current()) {
        this.state.job = result;
        if (result.state !== 'prepared') this.state.admissionUncertain = false;
      }
    } catch (error) {
      if (fence.current()) this.state.error = errorMessage(error, cancel
        ? 'The cancellation request could not be confirmed. Check this folder job status.'
        : 'Folder job status could not be refreshed.');
    } finally {
      this.finish(fence, isContextCurrent);
    }
  }

  private loadingSameSelection(context: WindowsOfflineFolderContext, row: WindowsOfflineFolderRow): boolean {
    if (!this.state.loading || this.activeKey === null) return false;
    try { return windowsOfflineFolderContextKey(context, row) === this.activeKey; }
    catch { return false; }
  }

  private begin(context: WindowsOfflineFolderContext, row: WindowsOfflineFolderRow, isContextCurrent: () => boolean): Fence | null {
    let key: string;
    try { key = windowsOfflineFolderContextKey(context, row); }
    catch (error) { this.state.error = errorMessage(error, 'The selected Windows folder is unavailable.'); return null; }
    this.setSelection(context, row);
    if (!isContextCurrent()) { this.clearSelection(); return null; }
    const sequence = ++this.requestSequence;
    return { key, sequence, current: () => this.activeKey === key && this.requestSequence === sequence && isContextCurrent() };
  }

  private finish(fence: Fence, isContextCurrent: () => boolean): void {
    if (this.activeKey !== fence.key || this.requestSequence !== fence.sequence) return;
    if (!isContextCurrent()) this.clearSelection();
    else this.state.loading = false;
  }
}

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof Error && error.message ? error.message : fallback;
}
