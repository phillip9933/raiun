export type WindowsOfflineFileContext = {
  profileId: 'default';
  accountEpoch: number;
  authGeneration: number;
  recoveryScopeToken: string;
  flowGeneration: number;
  server: string | null;
  clientId: string | null;
  cloudRoot: string | null;
};

/** One exact ordinary file version from an already-authenticated listing. */
export type WindowsOfflineFileRow = {
  spaceId: string;
  rootResourceId: string;
  path: string;
  resourceId: string;
  etag: string;
  size: number;
};

export type WindowsFileCacheStatus = {
  profile_id: 'default';
  auth_generation: number;
  recovery_scope_token: string;
  read_only: true;
  last_observed: true;
  atomic_snapshot: false;
  policy: 'recent' | 'always_offline' | 'cloud_only';
  recorded_complete_version: boolean;
  recorded_bytes: number;
  pending_offline_intent: boolean;
};

export type WindowsOfflineJobState =
  | 'running'
  | 'complete'
  | 'cancelled'
  | 'failed'
  | 'recovery_required';

export type WindowsOfflineJobStatus = {
  job_id: string;
  state: WindowsOfflineJobState;
  cancel_requested: boolean;
  recovery_required: boolean;
};

export type WindowsOfflineFileControllerState = {
  cacheStatus: WindowsFileCacheStatus | null;
  job: WindowsOfflineJobStatus | null;
  loading: boolean;
  error: string;
  /** A lost start reply may hide an admitted job; never submit another start in this selection. */
  admissionUncertain: boolean;
};

export type WindowsOfflineFileRequest = (
  action: string,
  args: Record<string, unknown>
) => Promise<unknown>;

type RequestFence = {
  key: string;
  sequence: number;
  isCurrent: () => boolean;
  isContextCurrent: () => boolean;
};

const cachePolicies = new Set(['recent', 'always_offline', 'cloud_only']);
const jobStates = new Set<WindowsOfflineJobState>([
  'running', 'complete', 'cancelled', 'failed', 'recovery_required'
]);
const recoveryTokenPattern = /^[0-9a-f]{64}$/;
const jobIdPattern = /^[0-9a-f]{32}$/;
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f-\u009f]/u;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  return actual.length === sortedExpected.length && actual.every((key, index) => key === sortedExpected[index]);
}

function validText(value: unknown, maxUtf8Bytes: number): value is string {
  return typeof value === 'string' && value.trim().length > 0 &&
    new TextEncoder().encode(value).length <= maxUtf8Bytes && !CONTROL_CHARACTERS.test(value);
}

function validContext(context: WindowsOfflineFileContext): boolean {
  return isRecord(context) && context.profileId === 'default' &&
    Number.isSafeInteger(context.accountEpoch) && context.accountEpoch >= 0 &&
    Number.isSafeInteger(context.authGeneration) && context.authGeneration > 0 &&
    Number.isSafeInteger(context.flowGeneration) && context.flowGeneration >= 0 &&
    typeof context.recoveryScopeToken === 'string' && recoveryTokenPattern.test(context.recoveryScopeToken) &&
    (context.server === null || validText(context.server, 4096)) &&
    (context.clientId === null || validText(context.clientId, 4096)) &&
    (context.cloudRoot === null || validText(context.cloudRoot, 4096));
}

function validRemotePath(path: unknown): path is string {
  return typeof path === 'string' && path.startsWith('/') && !path.endsWith('/') &&
    !path.includes('//') && !path.includes('\\') && !CONTROL_CHARACTERS.test(path) &&
    new TextEncoder().encode(path).length <= 16 * 1024 &&
    !path.split('/').some((component) => component === '.' || component === '..');
}

function validRow(row: WindowsOfflineFileRow): boolean {
  return isRecord(row) && validText(row.spaceId, 512) &&
    validText(row.rootResourceId, 16 * 1024) && validRemotePath(row.path) &&
    validText(row.resourceId, 16 * 1024) && validText(row.etag, 16 * 1024) &&
    Number.isSafeInteger(row.size) && row.size >= 0;
}

export function windowsOfflineFileContextKey(
  context: WindowsOfflineFileContext,
  row: WindowsOfflineFileRow
): string {
  if (!validContext(context) || !validRow(row)) {
    throw new Error('The selected Windows file context is invalid.');
  }
  return JSON.stringify([
    context.profileId,
    context.accountEpoch,
    context.authGeneration,
    context.recoveryScopeToken,
    context.flowGeneration,
    context.server,
    context.clientId,
    context.cloudRoot,
    row.spaceId,
    row.rootResourceId,
    row.path,
    row.resourceId,
    row.etag,
    row.size
  ]);
}

export function validateWindowsFileCacheStatus(
  value: unknown,
  expected: WindowsOfflineFileContext
): WindowsFileCacheStatus {
  if (!validContext(expected) || !isRecord(value) || !hasExactKeys(value, [
    'profile_id', 'auth_generation', 'recovery_scope_token', 'read_only', 'last_observed',
    'atomic_snapshot', 'policy', 'recorded_complete_version', 'recorded_bytes',
    'pending_offline_intent'
  ]) || value.profile_id !== expected.profileId || value.auth_generation !== expected.authGeneration ||
      value.recovery_scope_token !== expected.recoveryScopeToken || value.read_only !== true ||
      value.last_observed !== true || value.atomic_snapshot !== false ||
      typeof value.policy !== 'string' || !cachePolicies.has(value.policy) ||
      typeof value.recorded_complete_version !== 'boolean' ||
      typeof value.pending_offline_intent !== 'boolean' ||
      !Number.isSafeInteger(value.recorded_bytes) || (value.recorded_bytes as number) < 0) {
    throw new Error('The agent returned stale or invalid saved-file status.');
  }
  return value as WindowsFileCacheStatus;
}

export function validateWindowsOfflineJobStatus(value: unknown): WindowsOfflineJobStatus {
  if (!isRecord(value) || !hasExactKeys(value, [
    'job_id', 'state', 'cancel_requested', 'recovery_required'
  ]) || typeof value.job_id !== 'string' || !jobIdPattern.test(value.job_id) ||
      typeof value.state !== 'string' || !jobStates.has(value.state as WindowsOfflineJobState) ||
      typeof value.cancel_requested !== 'boolean' || typeof value.recovery_required !== 'boolean' ||
      value.recovery_required !== (value.state === 'recovery_required')) {
    throw new Error('The agent returned an invalid offline-file job status.');
  }
  return value as WindowsOfflineJobStatus;
}

function commonRequest(context: WindowsOfflineFileContext): Record<string, unknown> {
  return {
    profile_id: context.profileId,
    expected_generation: context.authGeneration,
    expected_recovery_scope_token: context.recoveryScopeToken
  };
}

function rowRequest(row: WindowsOfflineFileRow): Record<string, unknown> {
  return {
    space_id: row.spaceId,
    root_resource_id: row.rootResourceId,
    path: row.path,
    resource_id: row.resourceId,
    etag: row.etag,
    size: row.size
  };
}

export function windowsOfflineJobMessage(status: WindowsOfflineJobStatus): string {
  switch (status.state) {
    case 'running': return status.cancel_requested ? 'Stopping the offline download…' : 'Saving this file for offline use…';
    case 'complete': return 'This file is saved for offline use.';
    case 'cancelled': return 'The offline download was cancelled. The file remains in its current state.';
    case 'failed': return 'The offline download could not finish. Check the file status before trying again.';
    case 'recovery_required': return 'This offline download needs recovery. Keep the file and review saved-file recovery before retrying.';
  }
}

/**
 * Controller for the existing Windows-only file cache and offline-job RPCs.
 * Polling is one status request per call; the caller owns timer cadence and
 * must pass its current context predicate on each tick.
 */
export class WindowsOfflineFileController {
  readonly state: WindowsOfflineFileControllerState = {
    cacheStatus: null,
    job: null,
    loading: false,
    error: '',
    admissionUncertain: false
  };

  private activeKey: string | null = null;
  private requestSequence = 0;

  setSelection(context: WindowsOfflineFileContext | null, row: WindowsOfflineFileRow | null): void {
    if (context === null || row === null) {
      this.clearSelection();
      return;
    }
    const nextKey = windowsOfflineFileContextKey(context, row);
    if (nextKey === this.activeKey) return;
    this.activeKey = nextKey;
    this.requestSequence += 1;
    this.state.cacheStatus = null;
    this.state.job = null;
    this.state.loading = false;
    this.state.error = '';
    this.state.admissionUncertain = false;
  }

  clearSelection(): void {
    if (this.activeKey === null) return;
    this.activeKey = null;
    this.requestSequence += 1;
    this.state.cacheStatus = null;
    this.state.job = null;
    this.state.loading = false;
    this.state.error = '';
    this.state.admissionUncertain = false;
  }

  async loadCacheStatus(
    context: WindowsOfflineFileContext,
    row: WindowsOfflineFileRow,
    request: WindowsOfflineFileRequest,
    isCurrentSelection: () => boolean
  ): Promise<void> {
    if (this.loadingSameSelection(context, row)) return;
    const fence = this.begin(context, row, isCurrentSelection);
    if (!fence) return;
    this.state.loading = true;
    this.state.error = '';
    try {
      const value = await request('windows_file_cache_status', {
        ...commonRequest(context),
        ...rowRequest(row)
      });
      const result = validateWindowsFileCacheStatus(value, context);
      if (fence.isCurrent()) this.state.cacheStatus = result;
    } catch (error) {
      if (fence.isCurrent()) this.state.error = errorMessage(error, 'Saved-file status is unavailable.');
    } finally {
      this.finish(fence);
    }
  }

  async start(
    context: WindowsOfflineFileContext,
    row: WindowsOfflineFileRow,
    request: WindowsOfflineFileRequest,
    isCurrentSelection: () => boolean
  ): Promise<void> {
    if (this.loadingSameSelection(context, row)) return;
    const fence = this.begin(context, row, isCurrentSelection);
    if (!fence) return;
    if (this.state.admissionUncertain || (this.state.job !== null && isActive(this.state.job))) {
      this.state.error = 'An offline job may already be running for this file. Check its status before starting another.';
      return;
    }
    this.state.loading = true;
    this.state.error = '';
    // The start RPC can commit before a transport failure. Keep a visible
    // uncertainty fence so the same selection cannot submit a duplicate.
    this.state.admissionUncertain = true;
    try {
      const value = await request('windows_offline_file_start', {
        ...commonRequest(context),
        ...rowRequest(row)
      });
      const result = validateWindowsOfflineJobStatus(value);
      if (fence.isCurrent()) {
        this.state.job = result;
        this.state.admissionUncertain = false;
      }
    } catch (error) {
      if (fence.isCurrent()) {
        this.state.error = `The offline job may have started, but its reply could not be confirmed. ${errorMessage(error, 'Check the file status before trying again.')}`;
      }
    } finally {
      this.finish(fence);
    }
  }

  /** One safe status poll. A caller may schedule the next poll after this resolves. */
  async pollStatus(
    context: WindowsOfflineFileContext,
    row: WindowsOfflineFileRow,
    request: WindowsOfflineFileRequest,
    isCurrentSelection: () => boolean
  ): Promise<void> {
    await this.inspectJob(context, row, request, isCurrentSelection, false);
  }

  async cancel(
    context: WindowsOfflineFileContext,
    row: WindowsOfflineFileRow,
    request: WindowsOfflineFileRequest,
    isCurrentSelection: () => boolean
  ): Promise<void> {
    await this.inspectJob(context, row, request, isCurrentSelection, true);
  }

  private async inspectJob(
    context: WindowsOfflineFileContext,
    row: WindowsOfflineFileRow,
    request: WindowsOfflineFileRequest,
    isCurrentSelection: () => boolean,
    cancel: boolean
  ): Promise<void> {
    if (this.loadingSameSelection(context, row)) return;
    const fence = this.begin(context, row, isCurrentSelection);
    if (!fence) return;
    const job = this.state.job;
    if (!job) {
      if (fence.isCurrent()) this.state.error = 'There is no confirmed offline job to inspect.';
      return;
    }
    this.state.loading = true;
    this.state.error = '';
    try {
      const action = cancel ? 'windows_offline_file_cancel' : 'windows_offline_file_status';
      const value = await request(action, {
        ...commonRequest(context),
        job_id: job.job_id
      });
      const result = validateWindowsOfflineJobStatus(value);
      if (result.job_id !== job.job_id) throw new Error('The agent returned a different offline job.');
      if (fence.isCurrent()) this.state.job = result;
    } catch (error) {
      if (fence.isCurrent()) this.state.error = errorMessage(error, cancel
        ? 'The cancellation request could not be confirmed. Check this job status.'
        : 'Offline job status could not be refreshed.');
    } finally {
      this.finish(fence);
    }
  }

  private loadingSameSelection(
    context: WindowsOfflineFileContext,
    row: WindowsOfflineFileRow
  ): boolean {
    if (!this.state.loading || this.activeKey === null) return false;
    try {
      return windowsOfflineFileContextKey(context, row) === this.activeKey;
    } catch {
      return false;
    }
  }

  private begin(
    context: WindowsOfflineFileContext,
    row: WindowsOfflineFileRow,
    isCurrentSelection: () => boolean
  ): RequestFence | null {
    let key: string;
    try {
      key = windowsOfflineFileContextKey(context, row);
    } catch (error) {
      this.state.error = errorMessage(error, 'The selected Windows file is unavailable.');
      return null;
    }
    this.setSelection(context, row);
    if (!isCurrentSelection()) {
      this.clearSelection();
      return null;
    }
    const sequence = ++this.requestSequence;
    const isCurrent = () => this.activeKey === key && this.requestSequence === sequence && isCurrentSelection();
    return { key, sequence, isCurrent, isContextCurrent: isCurrentSelection };
  }

  private finish(fence: RequestFence): void {
    if (this.activeKey !== fence.key || this.requestSequence !== fence.sequence) return;
    if (!fence.isContextCurrent()) this.clearSelection();
    else this.state.loading = false;
  }
}

function isActive(job: WindowsOfflineJobStatus): boolean {
  return job.state === 'running';
}

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof Error && error.message ? error.message : fallback;
}
