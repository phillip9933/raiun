import {
  WindowsOfflineFolderController,
  windowsOfflineFolderContextKey,
  type WindowsOfflineFolderContext,
  type WindowsOfflineFolderIntentState,
  type WindowsOfflineFolderRequest,
  type WindowsOfflineFolderRow,
  type WindowsOfflineFolderSavedIntent
} from './windows-offline-folder';
import { renderWindowsOfflineFolderPanel as renderFolderView } from './windows-offline-folder-view';

type Action = 'start' | 'resume' | 'refresh' | 'poll' | 'cancel';
type Options = {
  getContext: () => WindowsOfflineFolderContext | null;
  actionsAvailable: () => boolean;
  request: WindowsOfflineFolderRequest;
  changed: () => void;
  otherJobBusy?: () => boolean;
};

type FolderPage = {
  rows: WindowsOfflineFolderRow[];
  nextCursor: string | null;
  unavailableRows: number;
};

const pageCursorPattern = /^[0-9a-f]{32}$/;
const pinIdPattern = /^[0-9a-f]{64}$/;
const MAX_ROWS = 128;

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, fields: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function scopeKey(context: WindowsOfflineFolderContext): string {
  return JSON.stringify([
    context.profileId, context.accountEpoch, context.authGeneration,
    context.recoveryScopeToken, context.server, context.clientId, context.cloudRoot
  ]);
}

function rowKey(row: WindowsOfflineFolderRow): string {
  return JSON.stringify({
    space_id: row.spaceId, root_resource_id: row.rootResourceId,
    path: row.path, resource_id: row.resourceId
  });
}

function validateSavedIntent(value: unknown): WindowsOfflineFolderSavedIntent {
  if (!record(value) || !exactKeys(value, [
    'state', 'active_pin_id', 'staging_pin_id', 'staging_is_initial'
  ]) || typeof value.state !== 'string' ||
      !new Set<WindowsOfflineFolderIntentState>([
        'none', 'known', 'unknown', 'unavailable', 'recovery_required'
      ]).has(value.state as WindowsOfflineFolderIntentState) ||
      (value.active_pin_id !== null && (typeof value.active_pin_id !== 'string' || !pinIdPattern.test(value.active_pin_id))) ||
      (value.staging_pin_id !== null && (typeof value.staging_pin_id !== 'string' || !pinIdPattern.test(value.staging_pin_id))) ||
      typeof value.staging_is_initial !== 'boolean') {
    throw new Error('The agent returned invalid saved-folder intent. Refresh the list.');
  }
  const state = value.state as WindowsOfflineFolderIntentState;
  const activePinId = value.active_pin_id as string | null;
  const stagingPinId = value.staging_pin_id as string | null;
  const stagingIsInitial = value.staging_is_initial;
  if ((state === 'none' || state === 'unknown' || state === 'unavailable') &&
      (activePinId !== null || stagingPinId !== null || stagingIsInitial)) {
    throw new Error('The agent returned invalid saved-folder intent. Refresh the list.');
  }
  if (state === 'known' && (
    (activePinId === null && (stagingPinId === null || !stagingIsInitial)) ||
    (activePinId !== null && stagingIsInitial) ||
    (activePinId === null && stagingPinId === null) ||
    (activePinId !== null && activePinId === stagingPinId)
  )) {
    throw new Error('The agent returned invalid saved-folder intent. Refresh the list.');
  }
  if (state === 'recovery_required' &&
      (activePinId !== null || stagingPinId === null || stagingIsInitial)) {
    throw new Error('The agent returned invalid saved-folder intent. Refresh the list.');
  }
  return { state, activePinId, stagingPinId, stagingIsInitial };
}

function validatePage(value: unknown, context: WindowsOfflineFolderContext, requestCursor: string | null): FolderPage {
  if (!record(value) || !exactKeys(value, [
    'rows', 'next_cursor', 'unavailable_rows', 'read_only', 'last_observed',
    'atomic_snapshot', 'profile_id', 'auth_generation', 'recovery_scope_token'
  ]) || value.profile_id !== context.profileId || value.auth_generation !== context.authGeneration ||
      value.recovery_scope_token !== context.recoveryScopeToken || value.read_only !== true ||
      value.last_observed !== true || value.atomic_snapshot !== false ||
      !Array.isArray(value.rows) || value.rows.length > 8 ||
      !Number.isSafeInteger(value.unavailable_rows) || (value.unavailable_rows as number) < 0 ||
      (value.unavailable_rows as number) > 100_000 ||
      (value.next_cursor !== null && (typeof value.next_cursor !== 'string' || !pageCursorPattern.test(value.next_cursor))) ||
      (value.next_cursor === requestCursor && requestCursor !== null)) {
    throw new Error('The agent returned an invalid saved-folder page. Refresh the list.');
  }
  if (typeof value.next_cursor === 'string' && requestCursor !== null && value.next_cursor === requestCursor) {
    throw new Error('The agent repeated a saved-folder page cursor. Refresh the list.');
  }
  const rows: WindowsOfflineFolderRow[] = [];
  const seen = new Set<string>();
  for (const candidate of value.rows) {
    if (!record(candidate) || !exactKeys(candidate, ['space_id', 'root_resource_id', 'path', 'resource_id', 'space_label', 'saved_intent']) ||
        typeof candidate.space_label !== 'string' || !candidate.space_label.trim() ||
        new TextEncoder().encode(candidate.space_label).length > 512 || /[\u0000-\u001f\u007f-\u009f]/u.test(candidate.space_label)) {
      throw new Error('The agent returned an invalid saved-folder row. Refresh the list.');
    }
    const row = {
      spaceLabel: candidate.space_label,
      spaceId: candidate.space_id,
      rootResourceId: candidate.root_resource_id,
      path: candidate.path,
      resourceId: candidate.resource_id,
      savedIntent: validateSavedIntent(candidate.saved_intent)
    } as WindowsOfflineFolderRow;
    // Reuse the controller's full canonical path/context validation.
    const key = windowsOfflineFolderContextKey(context, row);
    if (seen.has(key)) throw new Error('The agent returned duplicate saved-folder rows. Refresh the list.');
    seen.add(key);
    rows.push(row);
  }
  return {
    rows,
    nextCursor: value.next_cursor as string | null,
    unavailableRows: value.unavailable_rows as number
  };
}

export class WindowsOfflineFolderPanel {
  readonly controller = new WindowsOfflineFolderController();
  private readonly rows = new Map<string, WindowsOfflineFolderRow>();
  private readonly seenCursors = new Set<string>();
  private context: WindowsOfflineFolderContext | null = null;
  private contextKey: string | null = null;
  private selectedKey: string | null = null;
  private nextCursor: string | null = null;
  private unavailableRows = 0;
  private loaded = false;
  private loading = false;
  private error = '';
  private requestSerial = 0;
  private readonly pinRoles = new Map<string, WindowsOfflineFolderSavedIntent>();
  private jobOperation: Exclude<Action, 'poll' | 'cancel'> | null = null;
  private jobRowKey: string | null = null;

  constructor(private readonly options: Options) {}

  syncContext(): void {
    const next = this.options.getContext();
    const nextKey = next ? scopeKey(next) : null;
    if (nextKey === this.contextKey) {
      this.context = next;
      return;
    }
    this.context = next;
    this.contextKey = nextKey;
    this.requestSerial += 1;
    this.controller.clearSelection();
    this.rows.clear();
    this.seenCursors.clear();
    this.selectedKey = null;
    this.nextCursor = null;
    this.unavailableRows = 0;
    this.loaded = false;
    this.loading = false;
    this.error = '';
    this.pinRoles.clear();
    this.jobOperation = null;
    this.jobRowKey = null;
  }

  async load(reset: boolean): Promise<void> {
    this.syncContext();
    const context = this.context;
    if (!context || !this.options.actionsAvailable() || this.locked() || this.loading) return;
    const cursor = reset ? null : this.nextCursor;
    if (!reset && cursor === null) return;
    if (cursor !== null && this.seenCursors.has(cursor)) {
      this.error = 'This folder page was already loaded. Refresh the list.';
      this.options.changed();
      return;
    }
    const requestId = ++this.requestSerial;
    const capturedScope = scopeKey(context);
    this.loading = true;
    this.error = '';
    this.options.changed();
    try {
      const value = await this.options.request('windows_offline_folders', {
        profile_id: context.profileId,
        expected_generation: context.authGeneration,
        expected_recovery_scope_token: context.recoveryScopeToken,
        ...(cursor === null ? {} : { cursor })
      });
      const page = validatePage(value, context, cursor);
      if (requestId !== this.requestSerial || capturedScope !== this.contextKey || !this.liveContextMatches(capturedScope)) {
        this.syncContext();
        this.options.changed();
        return;
      }
      if (reset) this.seenCursors.clear();
      if (page.nextCursor !== null && this.seenCursors.has(page.nextCursor)) {
        throw new Error('The agent returned a repeated saved-folder page cursor. Refresh the list.');
      }
      const incoming = reset ? new Map<string, WindowsOfflineFolderRow>() : new Map(this.rows);
      for (const row of page.rows) {
        const key = rowKey(row);
        incoming.set(key, row);
      }
      if (incoming.size > MAX_ROWS) throw new Error('Open a smaller folder branch before loading more entries.');
      this.rows.clear();
      for (const [key, row] of incoming) this.rows.set(key, row);
      for (const row of page.rows) {
        // Each accepted page carries the backend's current durable role pair.
        // Replacing this map entry also clears a stale stage after postcommit
        // failure; page data never changes the selected four-field identity.
        this.pinRoles.set(rowKey(row), row.savedIntent!);
      }
      this.nextCursor = page.nextCursor;
      if (cursor !== null) this.seenCursors.add(cursor);
      this.unavailableRows = page.unavailableRows;
      this.loaded = true;
      if (reset && this.selectedKey !== null && !this.rows.has(this.selectedKey)) {
        this.selectedKey = null;
        this.jobOperation = null;
        this.jobRowKey = null;
        this.controller.setSelection(context, null);
      }
      for (const key of this.pinRoles.keys()) {
        if (!this.rows.has(key)) this.pinRoles.delete(key);
      }
    } catch (error) {
      if (requestId === this.requestSerial && capturedScope === this.contextKey && this.liveContextMatches(capturedScope)) {
        this.error = error instanceof Error ? error.message : 'The folder list is unavailable.';
      }
    } finally {
      if (requestId === this.requestSerial && capturedScope === this.contextKey && this.liveContextMatches(capturedScope)) {
        this.loading = false;
        this.options.changed();
      } else if (requestId === this.requestSerial) {
        this.syncContext();
        this.options.changed();
      }
    }
  }

  select(serializedFourFieldRowKey: string): void {
    this.syncContext();
    if (this.locked() || !this.context) return;
    const row = this.rows.get(serializedFourFieldRowKey);
    if (!row && serializedFourFieldRowKey !== '') return;
    if (this.selectedKey !== serializedFourFieldRowKey) {
      this.jobOperation = null;
      this.jobRowKey = null;
    }
    this.selectedKey = row ? serializedFourFieldRowKey : null;
    this.controller.setSelection(this.context, row ?? null);
    this.error = '';
    this.options.changed();
  }

  async run(action: Action): Promise<void> {
    this.syncContext();
    const context = this.context;
    const row = this.selectedKey ? this.rows.get(this.selectedKey) : undefined;
    if (!context || !row || !this.options.actionsAvailable() || this.loading) return;
    const job = this.controller.state.job;
    const activeJob = job && (job.state === 'prepared' || job.state === 'running');
    if (action === 'poll' || action === 'cancel') {
      if (!job || !activeJob) return;
    } else if (this.locked() || this.options.otherJobBusy?.()) {
      return;
    }
    if (action !== 'poll' && action !== 'cancel' && job?.state === 'recovery_required' &&
        this.jobRowKey === this.selectedKey) {
      return;
    }
    const roles = this.selectedKey ? this.pinRoles.get(this.selectedKey) : undefined;
    if (action !== 'poll' && action !== 'cancel') {
      if (!roles || roles.state !== 'none' && roles.state !== 'known') return;
      if (action === 'start' && roles.state !== 'none') return;
      if (action === 'resume' && !(roles.state === 'known' && roles.stagingIsInitial && roles.stagingPinId && !roles.activePinId)) return;
      if (action === 'refresh' && !(roles.state === 'known' && roles.activePinId)) return;
    }
    const capturedScope = this.contextKey;
    const current = () => capturedScope !== null && this.liveContextMatches(capturedScope);
    const operation = action === 'poll' || action === 'cancel' ? this.jobOperation : action;
    if (action !== 'poll' && action !== 'cancel') {
      this.jobOperation = action;
      this.jobRowKey = this.selectedKey;
    }
    this.loading = true;
    this.error = '';
    this.options.changed();
    try {
      if (action === 'start') await this.controller.start(context, row, this.options.request, current);
      else if (action === 'resume') await this.controller.resume(context, row, roles!.stagingPinId!, this.options.request, current);
      else if (action === 'refresh') await this.controller.refresh(context, row, roles!.activePinId!, roles!.stagingPinId, this.options.request, current);
      else if (action === 'poll') await this.controller.pollStatus(context, row, this.options.request, current);
      else await this.controller.cancel(context, row, this.options.request, current);
      if (!current()) return;
      this.error = this.controller.state.error;
      this.capturePins(operation);
    } finally {
      if (current()) {
        this.loading = false;
        this.options.changed();
      } else {
        this.syncContext();
        this.options.changed();
      }
    }
  }

  render(): string {
    this.syncContext();
    const key = this.selectedKey;
    const roles = key ? this.pinRoles.get(key) : undefined;
    const otherBusy = this.options.otherJobBusy?.() ?? false;
    return renderFolderView({
      folderRows: [...this.rows.values()],
      knownJobRow: this.controller.knownJobRow,
      currentSelection: key ? (this.rows.get(key) ?? null) : null,
      loading: this.loading, error: this.error, loaded: this.loaded,
      nextCursor: this.nextCursor, unavailableRows: this.unavailableRows,
      actionsAvailable: Boolean(this.context && this.options.actionsAvailable()),
      intentMessage: key ? intentMessage(roles?.state) : null,
      controller: this.controller.state,
      canSave: Boolean(key && roles?.state === 'none' && !otherBusy),
      canResume: Boolean(key && roles?.state === 'known' && roles.stagingIsInitial && roles.stagingPinId && !roles.activePinId && !otherBusy),
      canRefresh: Boolean(key && roles?.state === 'known' && roles.activePinId && !otherBusy),
      resumePinId: roles?.stagingPinId,
      refreshActivePinId: roles?.activePinId,
      refreshStagingPinId: roles?.stagingPinId
    });
  }

  clear(): void {
    this.context = null;
    this.contextKey = null;
    this.requestSerial += 1;
    this.controller.clearSelection();
    this.rows.clear();
    this.seenCursors.clear();
    this.selectedKey = null;
    this.nextCursor = null;
    this.unavailableRows = 0;
    this.loaded = false;
    this.loading = false;
    this.error = '';
    this.pinRoles.clear();
    this.jobOperation = null;
    this.jobRowKey = null;
    this.options.changed();
  }

  private locked(): boolean {
    const job = this.controller.state.job;
    return this.loading || this.controller.state.loading || this.controller.state.admissionUncertain ||
      job?.state === 'prepared' || job?.state === 'running';
  }

  private liveContextMatches(expectedScope: string): boolean {
    const latest = this.options.getContext();
    return latest !== null && this.contextKey === expectedScope && scopeKey(latest) === expectedScope;
  }

  private capturePins(operation: Exclude<Action, 'poll' | 'cancel'> | null): void {
    const folder = this.controller.state.job?.folder;
    const key = this.jobRowKey;
    if (!folder || !operation || !key) return;
    const roles = this.pinRoles.get(key);
    if (!roles) return;
    if (this.controller.state.job?.state === 'complete' && folder.state === 'ready') {
      roles.state = 'known';
      roles.activePinId = folder.pin_id;
      roles.stagingPinId = null;
      roles.stagingIsInitial = false;
    } else {
      roles.state = 'known';
      if (operation === 'refresh') {
        roles.stagingIsInitial = false;
      } else if (operation === 'start') {
        roles.stagingIsInitial = true;
      }
      roles.stagingPinId = folder.pin_id;
    }
    this.pinRoles.set(key, roles);
  }
}

function intentMessage(state: WindowsOfflineFolderIntentState | undefined): string | null {
  switch (state) {
    case 'unknown': return 'Saved-folder status is unknown. Existing copies are preserved; refresh the folder list before choosing an action.';
    case 'unavailable': return 'Saved-folder status is unavailable. Existing copies are preserved; try loading the folder list again.';
    case 'recovery_required': return 'This saved-folder set needs recovery. Existing copies are preserved; no new folder action is available.';
    default: return null;
  }
}
