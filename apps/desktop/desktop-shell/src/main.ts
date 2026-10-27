/// <reference types="vite/client" />
import { invoke, isTauri } from '@tauri-apps/api/core';
import { getVersion } from '@tauri-apps/api/app';
import { open, confirm as confirmDialog } from '@tauri-apps/plugin-dialog';
import { listen } from '@tauri-apps/api/event';
import './style.css';
import { MediaJobsView } from './media-jobs';
import { mergeVaultLockCleanup, nativeVaultLockMessage, vaultLockScopeKey, type VaultLockCleanupEvent, type VaultLockCleanupStatus } from './vault-lock-state';
import { connectionMode } from './connection-state';
import { shouldBlockPassiveRefresh, shouldRunPeriodicPassiveRefresh } from './passive-refresh';
import { ACCENT_COLORS, mountControlState, readAppearance, writeAppearance, type AccentName, type AppearanceTheme } from './ui-preferences';
import { completeVaultCreate, finishVaultCreateAttempt } from './vault-create';
import { offlineCopyStoredSizeLabel } from './offline-snapshot';
import { isVaultFailureClass, vaultEditRetryStatusMessage, vaultFailureMessage, type VaultFailureClass } from './vault-failure-copy';
import { windowsPortabilityLabel } from './windows-compatibility';
import { loadProviderSyncData, providerAvailable, providerFeatureAvailable } from './provider-capabilities';
import { eligibleWindowsRecoveryContext, WindowsRecoveryController, windowsRecoveryContextKey } from './windows-recovery-controller';
import { WINDOWS_RECOVERY_PAGE_LIMIT } from './windows-recovery';
import { validateWindowsDeviceCacheUsage, type WindowsDeviceCacheUsage } from './windows-device-cache';
import { WindowsOfflineFileController, windowsOfflineFileContextKey, windowsOfflineJobMessage, type WindowsOfflineFileContext, type WindowsOfflineFileRow } from './windows-offline-file';
import { WindowsOfflineFolderPanel } from './windows-offline-folder-panel';
import type { WindowsOfflineFolderContext } from './windows-offline-folder';
import { parseProxySettings, proxyEditorEnabled, validateProxyDraft, type ProxyConfig, type ProxyMode } from './network-proxy';
import { formatTransferRate, parseTransferLimitsReply, parseTransferRateDraft } from './transfer-limits';
import { groupPendingWritesByScope, pendingWritePageIsValid, pendingWriteRootId, savedRootDisclosure, togglePendingWriteDisclosure, type PendingOfflineWrite, type PendingOfflineWritesPage } from './pending-write-scope';
import { claimCopyVerify, copyOperationReviewMessage, copyVerifyContextMatches, copyVerifyRowKey, copyVerifyStartErrorMessage, copyVerifyStatusMessage, isReviewOnlyCopyOperation, releaseCopyVerify, validateCopyVerifyStart, validateCopyVerifyStatus, type CopyVerifyBinding, type CopyVerifyStatus } from './copy-operation-review';
import { copyProducerContextMatches, copyProducerStartErrorMessage, copyProducerStatusMessage, validateCopyProducerStart, validateCopyProducerStatus, type CopyProducerContext, type CopyProducerSourceExpectation, type CopyProducerDestinationExpectation, type CopyProducerStatus } from './copy-producer';
import { isVaultPasswordValidationError, shouldAnnounceVaultCloseBlocked, vaultDialogCloseBlockedMessage, vaultDialogInitialFocusTarget, vaultDialogTabDestination, vaultPasswordErrorAttributes } from './vault-dialog-accessibility';
import raiunLogo from '../src-tauri/icons/raiun.svg';

type OfflineCacheSummary = { available: boolean; quota_bytes: number; used_bytes: number; pinned_bytes: number; protected_bytes: number; over_quota: boolean; unavailable_reason?: string | null };
type Status = { connected: boolean; offline?: boolean; offline_namespace?: boolean; refreshing?: boolean; agent_version?: string | null; server?: string | null; client_id?: string | null; paused?: boolean; paused_space_ids?: string[]; mounted?: boolean; cloud_root?: string | null; error?: string | null; autostart?: boolean | null; recovery_folder?: string | null; encrypted_edit_recovery_available?: boolean; offline_cache?: OfflineCacheSummary | null; profile_id?: string | null; profile_label?: string | null; auth_generation?: number; root_configuration?: { valid: boolean; identity_bound: boolean; registration_state: string | null; recovery_scope_token?: unknown } | null; stopped?: boolean; authenticating?: boolean; provider_supported?: boolean; folder_sync_supported?: boolean; media_jobs_supported?: boolean; vaults_supported?: boolean; vault_access_mode?: 'native_read_only'; account_switch_supported?: boolean; account_setup_requires_sign_in?: boolean; pause_supported?: boolean; bandwidth_limits_supported?: boolean; network_proxy_supported?: boolean; proxy_edit_requires_sign_out?: boolean; session_cleanup_uncertain?: boolean };
type Account = { id: string; label: string; status: Status };
type RemovedAccount = { id: string; label: string; local_data_preserved: true };
type DesktopUpdateStatus = { state: 'idle' | 'current' | 'available' | 'unavailable' | 'downloaded' | 'dismissed' | 'error'; version: string | null; tag: string | null; release_url: string | null; notes: string | null; error: string | null; automatic_checks: boolean; channel: 'stable' | 'beta'; dismissed_tag: string | null; last_check_unix: number | null; key_configured: boolean; downloaded: boolean };
type AccountsResult = { selected: string | null; items: Account[]; account_removal_supported?: boolean; removed_items?: RemovedAccount[] };
type ShellUnlockIntent = { profile_id: string; space_id: string; root_resource_id: string };
type ResolvedUnlockTarget = { resolved: boolean; profile_id: string; space_id: string; root_resource_id: string; root_path: string; display_name: string; pin_id?: string | null; pin_generation?: number | null };
type Space = { id: string; name: string; personal: boolean; writable: boolean; encrypted: boolean };
type SyncMode = 'two_way' | 'upload_only' | 'download_only';
type VaultBinding = { root_path: string; root_resource_id: string };
type Pair = { id: string; local_path: string; space_id: string; remote_path: string; mode: SyncMode; vault?: VaultBinding | null; excluded_paths?: string[] };
type Conflict = { pair_id: string; path: string; local_hash: string; remote_etag: string };
type ConflictPage = { items: Conflict[]; nextAfter: string | null; opened: boolean; loading: boolean; error: string; recoveryMessage: string };
type RecoveryCopy = { spool_key: string; space_id: string | null; remote_path: string | null; local_data_path: string | null; bytes: number | null; condition: string | null; warnings: string[] };
type RecoveryPage = { items: RecoveryCopy[]; next_after: string | null; scanned_entries: number; warning_count: number; unrecognized_entries: number; truncated: boolean };
type EncryptedEditRecoveryItem = { record_id: string | null; bytes: number | null; state: 'building' | 'pending' | 'uncertain' | 'committed' | 'clean' | 'corrupt'; warning: string | null };
type EncryptedEditRecoveryPage = { items: EncryptedEditRecoveryItem[]; next_after: string | null; scanned_entries: number; warning_count: number; truncated: boolean; counts: { building: number; pending: number; uncertain: number; committed: number; clean: number; corrupt: number } };
type Transfer = { id: number; origin?: string | null; space_id?: string | null; path?: string | null; direction?: string | null; state?: string | null; bytes_total?: number | null; bytes_done?: number | null; error?: string | null; updated_at?: number | null };
type RemoteEntry = { id?: string; etag?: string; path: string; directory: boolean; size?: number; writable?: boolean; encrypted?: boolean; windows_portability_warnings?: string[] };
type VaultMountWriteUnavailableReason = 'vault_locked' | 'route_not_installed' | 'route_read_only' | 'drive_not_mounted' | 'private_spool_unavailable' | 'write_backend_unavailable' | 'offline_read_only' | 'offline_existing_file_overwrite_only';
type VaultExistingOverwriteReason = 'vault_locked' | 'route_not_installed' | 'route_read_only' | 'drive_not_mounted' | 'private_spool_unavailable';
type RememberedStatus = 'known_saved' | 'not_saved' | 'unknown' | 'unavailable';
type CachedVaultRoot = { space_id: string; root_resource_id: string; snapshot_available: true; pin_id?: string | null; generation?: number | null };
type CachedVaultRootsPage = { roots: CachedVaultRoot[]; next_after: { space_id: string; root_resource_id: string } | null; truncated: boolean };
type OfflinePolicy = 'recent' | 'always_offline' | 'cloud_only';
type OfflineAvailabilityState = 'ready' | 'stale' | 'unavailable' | null;
type OfflinePinStatus = { job_id: string; space_id: string; path: string; state: 'preparing' | 'building' | 'ready' | 'stale' | 'unavailable' | 'failed' | 'cancelled'; pin_id?: string | null; item_count: number; files_done: number; files_total: number; error?: string | null; cancel_requested: boolean; poll_error?: string; accountEpoch: number };
type PersistedOfflinePin = { pin_id: string; root_resource_id: string; path: string; state: 'building' | 'ready' | 'stale' | 'unavailable'; item_count: number; files_done: number; files_total: number };
type VaultInspect = { vault_lock_cleanup_status?: VaultLockCleanupStatus; root_path: string; root_resource_id: string; root_etag?: string | null; unlocked: boolean; initialized: boolean; writable?: boolean; vault_mount_ready: boolean; vault_mount_writable?: boolean; vault_mount_existing_file_overwrite?: boolean; vault_mount_existing_file_in_place?: boolean; vault_mount_existing_file_overwrite_reason?: VaultExistingOverwriteReason | null; vault_mount_write_unavailable_reason?: VaultMountWriteUnavailableReason | null; remembered_status?: RememberedStatus };
type VaultPinState = 'building' | 'ready' | 'stale';
type VaultPinJobState = 'queued' | 'running' | 'ready' | 'failed' | 'cancelled';
type VaultPin = { id: string; generation: number; state: VaultPinState; item_count: number; byte_len: number };
type VaultPinPage = { items: VaultPin[]; next_after: string | null; truncated: boolean; active_job_id?: string | null };
type VaultPinJob = { job_id: string; state: 'queued' | 'running'; pin_id?: string; cancelRequested?: boolean; items_done?: number; bytes_done?: number };
type VaultPinJobStatus = { job_id: string; state: VaultPinJobState; error?: string | null; pin?: VaultPin | null; items_done?: number; bytes_done?: number };
type VaultEditReconcileStatus = { job_id: string; space_id: string; root_resource_id: string; operation?: string; write_id?: string; operation_revision?: number; retry_generation?: number; automatic: boolean; state: 'queued' | 'running' | 'complete' | 'failed' | 'cancelled'; processed: number; uploaded: number; conflicts: number; remaining: number; error?: string | null; failure_class?: VaultFailureClass | null; cancel_requested: boolean };
type VaultEditLatestResult = { available: boolean; status: VaultEditReconcileStatus | null };
type VaultOperation = { write_id: string; revision: number; retry_generation: number; operation: 'overwrite' | 'create_file' | 'rename_file' | 'delete_file' | 'create_directory' | 'copy_file'; state: 'building' | 'queued' | 'pending' | 'uncertain' | 'conflict'; needs_attention: boolean; attention_reason: 'directory_create_attempt_interrupted' | 'file_create_attempt_interrupted' | 'file_create_recovery_interrupted' | 'copy_file_requires_review' | null; retry_state?: 'attempting' | 'recovery_attempting' | 'recovery_retrying' | null; can_retry_interrupted_create?: boolean; path: string; destination_path?: string | null; bytes: number };
type VaultOperationsPage = { space_id: string; root_resource_id: string; auth_generation: number; items: VaultOperation[]; next_after: string | null; truncated: boolean };
type VaultOperationsScope = { key: string; spaceId: string; rootResourceId: string; authGeneration: number; items: VaultOperation[]; nextAfter: string | null; truncated: boolean; loading: boolean; error: string; accountEpoch: number };
type CopyVerifyJobUi = { key: string; binding: CopyVerifyBinding; jobId: string | null; status: CopyVerifyStatus | null; busy: boolean; cancelBusy: boolean; error: string; generation: number; timer: number };
type VaultDirectoryBinding = { resourceId: string; etag: string };
type VaultDialogState = { lockCleanupStatus: VaultLockCleanupStatus; intent: 'add' | 'manage' | 'browse' | 'create'; spaceId: string; rootPath: string; rootResourceId: string; rootEtag: string; directoryBindings: Map<string, VaultDirectoryBinding>; currentDirectoryBinding: VaultDirectoryBinding | null; offlinePinId?: string; offlinePinGeneration?: number; path: string; entries: RemoteEntry[]; unlocked: boolean; statusUnknown: boolean; initialized: boolean; writable: boolean; offlineUnlockOnly: boolean; vaultMountReady: boolean; vaultMountWritable: boolean | null; vaultMountWriteUnavailableReason: VaultMountWriteUnavailableReason | null; vaultMountExistingFileOverwrite: boolean; vaultMountExistingFileInPlace: boolean; vaultMountExistingFileOverwriteReason: VaultExistingOverwriteReason | null; rememberedStatus: RememberedStatus | null; rememberOnDevice: boolean; pins: VaultPin[]; pinsNextAfter: string | null; pinsTruncated: boolean; pinsLoading: boolean; pinsError: string; pinBusy: boolean; pinJob: VaultPinJob | null; pinGeneration: number; pinPollTimer: number; editRetryBusy: boolean; editRetryError: string; editRetryJob: VaultEditReconcileStatus | null; editRetryGeneration: number; editRetryPollTimer: number; loading: boolean; error: string; passwordError: string; closeBlockedNotice: string; generation: number; accountEpoch: number; pairId?: string };
type CopyProducerSource = { expectation: CopyProducerSourceExpectation; profileId: string; accountEpoch: number; authGeneration: number; rootPath: string; displayName: string; size: number };
type CopyProducerUi = { source: CopyProducerSource | null; generation: number; flowGeneration: number; context: CopyProducerContext | null; destination: CopyProducerDestinationExpectation | null; jobId: string | null; status: CopyProducerStatus | null; busy: boolean; admissionUncertain: boolean; error: string; timer: number; pollError: string };
type MediaFilterValue = 'photos' | 'videos' | 'all';
type MediaOrganizationValue = 'preserve_relative_path' | 'utc_year_month';
type MediaPlanItem = { source_relative_path: string; outcome: string | Record<string, unknown> };
type MediaScanWarning = { relative_path: string | null; kind: string; message: string };
type MediaScanResponse = {
  rows: MediaPlanItem[];
  rows_truncated: boolean;
  totals: { scanned: number; sources: number; planned: number; filtered: number; missing_date: number; collisions: number; rejected: number };
  complete: boolean;
  truncated: boolean;
  warnings: MediaScanWarning[];
  warnings_omitted: number;
};

function safeVaultMountWriteReason(value: unknown): VaultMountWriteUnavailableReason | null {
  return value === 'vault_locked' || value === 'route_not_installed' || value === 'route_read_only' ||
    value === 'drive_not_mounted' || value === 'private_spool_unavailable' || value === 'write_backend_unavailable' || value === 'offline_read_only' || value === 'offline_existing_file_overwrite_only'
    ? value
    : null;
}
function safeVaultExistingOverwriteReason(value: unknown): VaultExistingOverwriteReason | null {
  return value === 'vault_locked' || value === 'route_not_installed' || value === 'route_read_only' || value === 'drive_not_mounted' || value === 'private_spool_unavailable' ? value : null;
}
function safeRememberedStatus(value: unknown): RememberedStatus | null {
  return value === 'known_saved' || value === 'not_saved' || value === 'unknown' || value === 'unavailable' ? value : null;
}
function safeOfflineAvailabilityState(value: unknown): OfflineAvailabilityState {
  if (value === null || value === 'ready' || value === 'stale' || value === 'unavailable') return value;
  throw new Error('The agent returned an unknown offline-copy status.');
}
type Page = 'overview' | 'folders' | 'offline' | 'encrypted' | 'transfers' | 'settings';
type SyncSection = 'folders' | 'media';

const app = document.querySelector<HTMLDivElement>('#app')!;
let appVersionLabel = isTauri() ? 'Loading…' : 'Browser layout preview';
const mediaPreview: { source: string; destinationRoot: string; filter: MediaFilterValue; organization: MediaOrganizationValue; loading: boolean; error: string; result: MediaScanResponse | null; generation: number } = {
  source: '', destinationRoot: '/Personal/Photos', filter: 'photos', organization: 'preserve_relative_path', loading: false, error: '', result: null, generation: 0
};
const offlineUi = { policies: new Map<string, OfflinePolicy>(), availabilityStates: new Map<string, OfflineAvailabilityState>(), policyLoading: new Set<string>(), policySaving: new Set<string>(), folderPolicies: new Map<string, 'recent' | 'cloud_only'>(), folderPolicyLoading: new Map<string, symbol>(), folderPolicySaving: new Map<string, symbol>(), folderListing: null as { epoch: number; generation: number; spaceId: string; path: string } | null, pins: new Map<string, PersistedOfflinePin[]>(), pinsLoading: new Set<string>(), pinsRemoving: new Set<string>(), pin: null as OfflinePinStatus | null, error: '', pollTimer: 0 as number };
const pairExclusionsUi = { open: new Set<string>(), drafts: new Map<string, string>(), errors: new Map<string, string>(), busy: new Set<string>() };
const pendingWritesUi = { authGeneration: null as number | null, accountScope: null as string | null, items: [] as PendingOfflineWrite[], expandedScopes: new Set<string>(), nextAfter: null as string | null, pendingCount: 0, conflictCount: 0, truncated: false, loaded: false, loading: false, refreshQueued: false, error: '', accountEpoch: -1, generation: 0, retryingSpaces: new Set<string>(), exportingWrites: new Set<string>(), reconcileJobs: new Map<string, { job_id: string; space_id: string; accountEpoch: number }>(), retryTimers: new Map<string, number>() };
const encryptedRetryLatestUi = { scopes: [] as { key: string; spaceId: string; rootResourceId: string }[], scopesTruncated: false, discoveryLoading: false, discoveryError: '', statuses: new Map<string, VaultEditLatestResult>(), errors: new Map<string, string>(), loading: new Set<string>(), accountEpoch: -1, generation: 0, timer: 0 as number, running: false };
const windowsRecoveryController = new WindowsRecoveryController();
const windowsOfflineFileController = new WindowsOfflineFileController();
const windowsDeviceCacheUi = { usage: null as WindowsDeviceCacheUsage | null, contextKey: '', sequence: 0, loading: false, error: '' };
type WindowsOfflineFilesPage = { profile_id: string; auth_generation: number; recovery_scope_token: string; items: WindowsOfflineFileRow[]; next_cursor: string | null; unavailable_rows: number; read_only: true; last_observed: true; atomic_snapshot: false };
type ProtectedVaultCaptureItem = { item_token: string; file_name: string; body_length: number };
type ProtectedVaultCapturePage = { schema_version: 1; profile_id: string; auth_generation: number; items: ProtectedVaultCaptureItem[]; next_cursor: string | null; read_only: true };
const windowsOfflineFilesUi = { items: [] as WindowsOfflineFileRow[], nextCursor: null as string | null, unavailableRows: 0, loaded: false, loading: false, error: '', selectedKey: '', generation: 0, contextKey: '', pollTimer: 0 as number };
const protectedVaultRecoveryUi: { contextKey: string; page: ProtectedVaultCapturePage | null; loading: boolean; savingToken: string; error: string; message: string; generation: number } = { contextKey: '', page: null, loading: false, savingToken: '', error: '', message: '', generation: 0 };
let windowsOfflineFolderPollTimer = 0;
const windowsOfflineFoldersPanel = new WindowsOfflineFolderPanel({
  getContext: currentWindowsOfflineFolderContext,
  actionsAvailable: () => !!currentWindowsOfflineFolderContext() && state.agentReachable &&
    state.status?.connected === true && state.status?.mounted === true && !state.accountSwitching,
  request,
  changed: () => render(),
  otherJobBusy: () => windowsOfflineFileController.state.loading ||
    windowsOfflineFileController.state.job?.state === 'running' || windowsOfflineFileController.state.admissionUncertain
});

const vaultOperationsUi = { scopes: new Map<string, VaultOperationsScope>(), lastLoadedAt: 0, generation: 0, loading: false, accountEpoch: -1, rootsTruncated: false };
const copyVerifyUi = { jobs: new Map<string, CopyVerifyJobUi>(), active: new Set<string>(), generation: 0 };
const copyProducerUi: CopyProducerUi = { source: null, generation: 0, flowGeneration: 0, context: null, destination: null, jobId: null, status: null, busy: false, admissionUncertain: false, error: '', timer: 0, pollError: '' };
const proxyUi = { config: { mode: 'system' } as ProxyConfig, revision: 0, accountId: null as string | null, scopeToken: undefined as string | undefined, loadedEpoch: -1, loading: false, saving: false, error: '', draftMode: 'system' as ProxyMode, draftUrl: '', generation: 0 };
const bandwidthUi = { upload: '', download: '', revision: 0, accountId: null as string | null, scopeToken: undefined as string | undefined, loadedEpoch: -1, loading: false, saving: false, error: '', generation: 0 };
const desktopUpdateUi: { status: DesktopUpdateStatus | null; busy: boolean; error: string } = { status: null, busy: false, error: '' };
type InterruptedCreateRetryUi = { key: string; spaceId: string; rootResourceId: string; writeId: string; revision: number; retryGeneration: number; retryState: 'attempting' | 'recovery_attempting' | 'recovery_retrying'; jobId: string; profileId: string; accountEpoch: number; generation: number; busy: boolean; status: VaultEditReconcileStatus | null; error: string };
const interruptedCreateRetryUi: { job: InterruptedCreateRetryUi | null; timer: number; generation: number } = { job: null, timer: 0, generation: 0 };
const cachedVaultRootsUi = { roots: [] as CachedVaultRoot[], nextAfter: null as CachedVaultRootsPage['next_after'], truncated: false, loading: false, error: '', selected: '', generation: 0, accountEpoch: -1 };
const state: { page: Page; syncSection: SyncSection; status: Status | null; statusErrorDismissed: string; agentReachable: boolean; pairs: Pair[]; transfers: Transfer[]; conflicts: Record<string, ConflictPage>; resolvingConflict: boolean; recoveryPage: RecoveryPage | null; recoveryLoading: boolean; recoveryError: string; encryptedEditRecoveryPage: EncryptedEditRecoveryPage | null; encryptedEditRecoveryLoading: boolean; encryptedEditRecoveryError: string; spaces: Space[]; spacesServer: string | null; spacesLoading: boolean; spacesError: string; transferFilter: string; busy: boolean; addOpen: boolean; localPath: string; spaceId: string; remotePath: string; vaultBinding: VaultBinding | null; vaultWritable: boolean; vaultDialog: VaultDialogState | null; vaultGeneration: number; vaultAccessOpen: boolean; vaultAccessSpaceId: string; pickerPurpose: 'pair' | 'encrypted_access' | 'offline'; pickerGeneration: number; mode: SyncMode; pickerOpen: boolean; pickerPath: string; pickerEntries: RemoteEntry[]; pickerError: string; pickerWritable: Record<string, boolean>; pickerFolderName: string; pickerCreatingFolder: boolean; accounts: Account[]; removedAccounts: RemovedAccount[]; accountRemovalSupported: boolean; selectedAccount: string; accountEpoch: number; accountSwitching: boolean; accountsLoading: boolean; accountsError: string; accountSwitchTarget: string; mutationBusy: number; nativeDialogBusy: boolean; addAccountOpen: boolean; addAccountStep: 'details' | 'waiting'; addAccountLabel: string; addAccountRoot: string; addAccountServer: string; addAccountClientId: string; addAccountAuthMessage: string; addAccountAuthStarted: boolean; addAccountError: string; addAccountCreatedId: string; addAccountBusy: boolean; spaceActionBusy: Record<string, 'pause' | 'sync' | 'disconnect'>; message: string; error: string; autostart: boolean | null; server: string; serverEdited: boolean; statusServer: string; clientId: string; clientIdEditedServer: string | null; clientIdServer: string } = {
  page: 'overview', syncSection: 'folders', status: null, statusErrorDismissed: '', agentReachable: false, pairs: [], transfers: [], spaces: [], spacesServer: null, spacesLoading: false, spacesError: '', transferFilter: 'active', busy: false, addOpen: false,
  conflicts: {}, resolvingConflict: false, recoveryPage: null, recoveryLoading: false, recoveryError: '', encryptedEditRecoveryPage: null, encryptedEditRecoveryLoading: false, encryptedEditRecoveryError: '', localPath: '', spaceId: '', remotePath: '', vaultBinding: null, vaultWritable: false, vaultDialog: null, vaultGeneration: 0, vaultAccessOpen: false, vaultAccessSpaceId: '', pickerPurpose: 'pair', pickerGeneration: 0, mode: 'two_way', pickerOpen: false, pickerPath: '/', pickerEntries: [], pickerError: '', pickerWritable: {}, pickerFolderName: '', pickerCreatingFolder: false, accounts: [], removedAccounts: [], accountRemovalSupported: false, selectedAccount: '', accountEpoch: 0, accountSwitching: false, accountsLoading: false, accountsError: '', accountSwitchTarget: '', mutationBusy: 0, nativeDialogBusy: false, addAccountOpen: false, addAccountStep: 'details', addAccountLabel: '', addAccountRoot: '', addAccountServer: '', addAccountClientId: '', addAccountAuthMessage: '', addAccountAuthStarted: false, addAccountError: '', addAccountCreatedId: '', addAccountBusy: false, spaceActionBusy: {}, message: '', error: '', autostart: null, server: '', serverEdited: false, statusServer: '', clientId: '', clientIdEditedServer: null, clientIdServer: ''
};
const mediaJobs = new MediaJobsView({
  key: () => `${state.accountEpoch}:${state.selectedAccount}`,
  connected: () => state.status?.connected === true,
  reachable: () => state.agentReachable,
  supported: () => featureAvailable('media_jobs_supported'),
  supportsVerifyUpload: () => !isWindowsAgentStatus(state.status),
  loadWhileDisconnected: () => !isWindowsAgentStatus(state.status),
  blocked: () => state.mutationBusy > 0 || state.nativeDialogBusy || state.accountSwitching,
  spaces: () => state.spaces,
  request,
  confirm: confirmAccountAction,
  chooseSource: async () => {
    const selected = await open({ directory: true, multiple: false, title: 'Choose media backup source' });
    return typeof selected === 'string' ? selected : null;
  },
  busy: value => { state.mutationBusy = Math.max(0, state.mutationBusy + (value ? 1 : -1)); },
  render
});
let refreshQueued = false;
let passiveStatusRefreshQueued = false;
let accountsSyncPromise: Promise<boolean> | null = null;
let accountSelectionRevision = 0;
let unlockIntentDrain: Promise<void> | null = null;
let unlockIntentDrainRequested = false;
let unlockIntentInitializationReady = false;
const profileIndependentActions = new Set(['accounts', 'account_add', 'account_select', 'account_restore']);
let renderedPage: Page | null = null;
let renderedAccount = '';
let lastRenderedMarkup = '';
type VaultDialogFocusReturn = {
  accountEpoch: number;
  page: Page;
  locator: { kind: 'id'; value: string } | { kind: 'attribute'; name: 'data-vault-pair' | 'data-vault-root' | 'data-action' | 'data-page'; value: string; occurrence: number };
};
let vaultDialogFocusReturn: VaultDialogFocusReturn | null = null;
let renderedVaultDialog: VaultDialogState | null = null;

class StaleAccountRequest extends Error {}
function isCurrentAccount(epoch: number, profileId = state.selectedAccount) { return epoch === state.accountEpoch && profileId === state.selectedAccount; }
function featureAvailable(feature: 'folder_sync_supported' | 'media_jobs_supported' | 'vaults_supported' | 'account_switch_supported' | 'pause_supported') {
  return providerFeatureAvailable(state.status?.provider_supported, state.status?.[feature]);
}
// Renderer-local failures survive dialog close/reopen only for this exact
// selected account, physical-root token and inspected vault. Backend incomplete
// status restores the warning after a renderer restart; unknown never proves cleanup.
const nativeVaultLockWarnings = new Set<string>();
function nativeVaultLockScope(flow: VaultDialogState): string | null {
  if (!nativeVaultAccess() || !isCurrentAccount(flow.accountEpoch)) return null;
  const status = state.status;
  if (!status || status.profile_id !== state.selectedAccount) return null;
  return vaultLockScopeKey({ profileId: state.selectedAccount, server: status.server, clientId: status.client_id,
    cloudRoot: status.cloud_root, rootBinding: status.root_configuration?.recovery_scope_token,
    spaceId: flow.spaceId, rootResourceId: flow.rootResourceId });
}
function updateNativeVaultLockCleanup(flow: VaultDialogState, observed: unknown, event: VaultLockCleanupEvent = 'inspect', expectedScope?: string | null) {
  if (!nativeVaultAccess()) return;
  const scope = nativeVaultLockScope(flow);
  if (expectedScope !== undefined && expectedScope !== scope) {
    flow.statusUnknown = true;
    flow.vaultMountReady = false;
    return;
  }
  const previous = scope && nativeVaultLockWarnings.has(scope) ? 'incomplete' : flow.lockCleanupStatus;
  flow.lockCleanupStatus = mergeVaultLockCleanup(previous, observed, event);
  if (scope && flow.lockCleanupStatus === 'incomplete') nativeVaultLockWarnings.add(scope);
  else if (scope && event === 'lock_succeeded' && flow.lockCleanupStatus === 'complete') nativeVaultLockWarnings.delete(scope);
}
function nativeVaultLockIncomplete(flow: VaultDialogState) { return nativeVaultAccess() && flow.lockCleanupStatus === 'incomplete'; }

function nativeVaultAccess() { return state.status?.vault_access_mode === 'native_read_only'; }
function vaultAppFeaturesAvailable() { return featureAvailable('vaults_supported') && !nativeVaultAccess(); }
function nativeVaultActionAllowed(action: string) {
  return !nativeVaultAccess() || ((!action.startsWith('vault_') && !action.startsWith('encrypted_edit_')) || ['vault_inspect', 'vault_unlock', 'vault_lock', 'vault_forget'].includes(action));
}
function windowsSignInPending() { return isWindowsAgentStatus(state.status) && state.status?.authenticating === true; }

async function request<T>(action: string, args: Record<string, unknown> = {}): Promise<T> {
  if (!nativeVaultActionAllowed(action)) throw new Error('This encrypted-file action is unavailable in native Windows mode.');
  if (!isTauri()) throw new Error('Open Raiun Desktop to connect to the background agent. This browser view is a layout preview.');
  const epoch = state.accountEpoch;
  const profileId = state.selectedAccount;
  const message = { action, ...args, ...(!profileIndependentActions.has(action) && profileId ? { profile_id: profileId } : {}) };
  const result = await invoke<T>('request', { message });
  if (!nativeVaultActionAllowed(action)) throw new StaleAccountRequest();
  if (profileIndependentActions.has(action)) return result;
  if (!isCurrentAccount(epoch, profileId)) throw new StaleAccountRequest();
  return result;
}
async function vaultSecretRequest<T>(message: Record<string, unknown>): Promise<T> {
  if (nativeVaultAccess() && message.action !== 'vault_unlock') throw new Error('This encrypted-file action is unavailable in native Windows mode.');
  if (!featureAvailable('vaults_supported')) throw new Error('Encrypted files are unavailable for this agent.');
  if (!isTauri()) throw new Error('Vault encryption is available in Raiun Desktop, not in the browser preview.');
  const epoch = state.accountEpoch;
  const profileId = state.selectedAccount;
  const result = await invoke<T>('vault_secret', { message: { ...message, profile_id: profileId } });
  if (nativeVaultAccess() && message.action !== 'vault_unlock') throw new StaleAccountRequest();
  if (!isCurrentAccount(epoch, profileId)) throw new StaleAccountRequest();
  return result;
}
function isWindowsAgentStatus(status: Status | null): boolean {
  const windowsWebview = isTauri() && typeof navigator !== 'undefined' && /\bWindows NT\b/i.test(navigator.userAgent);
  return windowsWebview || (status?.profile_label === 'This PC' && status.root_configuration !== undefined);
}
function windowsRecoveryBinding() {
  return eligibleWindowsRecoveryContext(
    state.agentReachable,
    state.selectedAccount || null,
    state.status,
    {
      accountEpoch: state.accountEpoch,
      server: state.status?.server || null,
      clientId: state.status?.client_id || null,
      cloudRoot: state.status?.cloud_root || null
    }
  );
}
/* BEGIN protected vault recovery wire validator */
function validateProtectedVaultCapturePage(value: unknown, expected: { profileId: string; authGeneration: number }): ProtectedVaultCapturePage {
  const exactKeys = (candidate: Record<string, unknown>, keys: string[]) => {
    const actual = Object.keys(candidate).sort();
    const sorted = [...keys].sort();
    return actual.length === sorted.length && actual.every((key, index) => key === sorted[index]);
  };
  const token = (candidate: unknown): candidate is string => typeof candidate === 'string' && /^[0-9a-f]{48}$/.test(candidate);
  const pageKeys = ['schema_version', 'profile_id', 'auth_generation', 'items', 'next_cursor', 'read_only'];
  const itemKeys = ['item_token', 'file_name', 'body_length'];
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Saved vault edits returned an invalid page.');
  const page = value as Record<string, unknown>;
  let encodedLength = 0;
  try { encodedLength = new TextEncoder().encode(JSON.stringify(page)).length; } catch { throw new Error('Saved vault edits returned an invalid page.'); }
  if (!exactKeys(page, pageKeys) || encodedLength > 64 * 1024 || page.schema_version !== 1 ||
      page.profile_id !== expected.profileId || page.auth_generation !== expected.authGeneration ||
      page.read_only !== true || !Array.isArray(page.items) || page.items.length > 100 ||
      !(page.next_cursor === null || token(page.next_cursor))) {
    throw new Error('Saved vault edits returned an invalid or stale page.');
  }
  const seen = new Set<string>();
  const items: ProtectedVaultCaptureItem[] = page.items.map(candidate => {
    if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) throw new Error('Saved vault edits returned an invalid item.');
    const row = candidate as Record<string, unknown>;
    const name = row.file_name;
    if (!exactKeys(row, itemKeys) || !token(row.item_token) || seen.has(row.item_token) ||
        typeof name !== 'string' || !name || name === '.' || name === '..' ||
        new TextEncoder().encode(name).length > 96 || /[\\/\u0000-\u001f\u007f-\u009f]/u.test(name) ||
        typeof row.body_length !== 'number' || !Number.isSafeInteger(row.body_length) || row.body_length < 0) {
      throw new Error('Saved vault edits returned an invalid item.');
    }
    seen.add(row.item_token);
    return { item_token: row.item_token, file_name: name, body_length: row.body_length };
  });
  return { schema_version: 1, profile_id: expected.profileId, auth_generation: expected.authGeneration, items, next_cursor: page.next_cursor as string | null, read_only: true };
}
/* END protected vault recovery wire validator */
function protectedVaultRecoveryScope(flow: VaultDialogState) {
  if (flow.intent === 'create' || !flow.spaceId || !flow.rootResourceId || !flow.rootPath) return null;
  const { context } = windowsRecoveryBinding();
  if (!context || context.accountEpoch !== flow.accountEpoch || !isCurrentAccount(flow.accountEpoch, context.profileId)) return null;
  const key = JSON.stringify([context.accountEpoch, context.profileId, context.server, context.clientId, context.cloudRoot,
    context.authGeneration, context.recoveryScopeToken, state.vaultGeneration, flow.spaceId, flow.rootResourceId, flow.rootPath]);
  return { context, spaceId: flow.spaceId, rootResourceId: flow.rootResourceId, remoteRoot: flow.rootPath, key };
}
function syncProtectedVaultRecoveryScope(key: string) {
  if (protectedVaultRecoveryUi.contextKey === key) return;
  protectedVaultRecoveryUi.contextKey = key;
  protectedVaultRecoveryUi.page = null;
  protectedVaultRecoveryUi.loading = false;
  protectedVaultRecoveryUi.savingToken = '';
  protectedVaultRecoveryUi.error = '';
  protectedVaultRecoveryUi.message = '';
  protectedVaultRecoveryUi.generation++;
}
function protectedVaultRecoveryScopeIsCurrent(flow: VaultDialogState, key: string, generation: number) {
  const current = protectedVaultRecoveryScope(flow);
  return state.vaultDialog === flow && state.vaultGeneration === flow.generation &&
    protectedVaultRecoveryUi.generation === generation && !!current && current.key === key;
}
async function loadProtectedVaultCaptures(reset: boolean) {
  const flow = state.vaultDialog;
  if (!flow || protectedVaultRecoveryUi.loading) return;
  const scope = protectedVaultRecoveryScope(flow);
  if (!scope) {
    protectedVaultRecoveryUi.error = 'Connect the current account and verify its registered Windows drive before checking saved vault edits.';
    render();
    return;
  }
  syncProtectedVaultRecoveryScope(scope.key);
  const after = reset ? null : protectedVaultRecoveryUi.page?.next_cursor || null;
  if (!reset && !after) return;
  if (reset) protectedVaultRecoveryUi.page = null;
  protectedVaultRecoveryUi.loading = true;
  protectedVaultRecoveryUi.error = '';
  protectedVaultRecoveryUi.message = '';
  const generation = protectedVaultRecoveryUi.generation;
  render();
  try {
    const response = await request<unknown>('windows_vault_capture_recovery_list', {
      profile_id: scope.context.profileId,
      expected_generation: scope.context.authGeneration,
      expected_recovery_scope_token: scope.context.recoveryScopeToken,
      space_id: scope.spaceId,
      root_resource_id: scope.rootResourceId,
      remote_root: scope.remoteRoot,
      limit: 50,
      ...(after ? { cursor: after } : {})
    });
    if (!protectedVaultRecoveryScopeIsCurrent(flow, scope.key, generation)) return;
    const page = validateProtectedVaultCapturePage(response, { profileId: scope.context.profileId, authGeneration: scope.context.authGeneration });
    const previous = reset ? [] : protectedVaultRecoveryUi.page?.items || [];
    const tokens = new Set(previous.map(item => item.item_token));
    if (page.items.some(item => tokens.has(item.item_token))) throw new Error('Saved vault edits returned a duplicate item. Refresh the list before continuing.');
    protectedVaultRecoveryUi.page = { ...page, items: [...previous, ...page.items] };
  } catch (error) {
    if (protectedVaultRecoveryScopeIsCurrent(flow, scope.key, generation) && !isStaleAccountRequest(error)) {
      protectedVaultRecoveryUi.error = messageOf(error);
    }
  } finally {
    if (protectedVaultRecoveryScopeIsCurrent(flow, scope.key, generation)) {
      protectedVaultRecoveryUi.loading = false;
      render();
    }
  }
}
async function saveProtectedVaultCaptureCopy(itemToken: string) {
  const flow = state.vaultDialog;
  if (!flow || !itemToken || state.nativeDialogBusy || state.accountSwitching || protectedVaultRecoveryUi.savingToken) return;
  const scope = protectedVaultRecoveryScope(flow);
  const item = protectedVaultRecoveryUi.page?.items.find(row => row.item_token === itemToken);
  if (!scope || protectedVaultRecoveryUi.contextKey !== scope.key || !item) {
    protectedVaultRecoveryUi.error = 'This saved vault edit selection expired. Refresh the list and choose it again.';
    render();
    return;
  }
  const generation = protectedVaultRecoveryUi.generation;
  protectedVaultRecoveryUi.error = '';
  protectedVaultRecoveryUi.message = '';
  protectedVaultRecoveryUi.savingToken = itemToken;
  state.nativeDialogBusy = true;
  render();
  try {
    const result = await invoke<{ cancelled?: boolean; saved?: boolean; body_length?: number }>('save_protected_vault_capture_copy', { request: {
      profileId: scope.context.profileId,
      expectedGeneration: scope.context.authGeneration,
      expectedRecoveryScopeToken: scope.context.recoveryScopeToken,
      spaceId: scope.spaceId,
      rootResourceId: scope.rootResourceId,
      remoteRoot: scope.remoteRoot,
      itemToken,
      expectedBodyLength: item.body_length,
      suggestedName: item.file_name
    } });
    if (!protectedVaultRecoveryScopeIsCurrent(flow, scope.key, generation)) return;
    if (result?.cancelled === true) return;
    if (result?.saved !== true || result.body_length !== item.body_length) {
      throw new Error('Raiun could not confirm the saved plaintext copy. The protected history item remains unchanged.');
    }
    protectedVaultRecoveryUi.message = 'Plaintext copy saved. The protected history item remains stored in Raiun.';
  } catch (error) {
    if (protectedVaultRecoveryScopeIsCurrent(flow, scope.key, generation) && !isStaleAccountRequest(error)) {
      protectedVaultRecoveryUi.error = messageOf(error);
    }
  } finally {
    state.nativeDialogBusy = false;
    if (protectedVaultRecoveryScopeIsCurrent(flow, scope.key, generation)) {
      protectedVaultRecoveryUi.savingToken = '';
      render();
    }
  }
}
function protectedVaultRecoveryPanel(flow: VaultDialogState, busy: boolean) {
  if (flow.intent === 'create' || copyProducerUi.source) return '';
  const scope = protectedVaultRecoveryScope(flow);
  syncProtectedVaultRecoveryScope(scope?.key || '');
  const ui = protectedVaultRecoveryUi;
  const page = ui.page;
  const rows = page?.items.length
    ? `<div class="encrypted-edit-list">${page.items.map(item => `<article class="encrypted-edit-item"><div><b>${esc(item.file_name)}</b><small>${esc(formatBytes(item.body_length))} · saved in protected local history</small></div><button class="small-action" data-vault-capture-save="${esc(item.item_token)}" ${busy || ui.loading || !!ui.savingToken || !scope ? 'disabled' : ''}>${ui.savingToken === item.item_token ? 'Saving…' : 'Save plaintext copy…'}</button></article>`).join('')}</div>`
    : page ? '<div class="recovery-empty" role="status">No completed saved edits were found for this encrypted location.</div>' : '';
  const unavailable = !scope
    ? '<p class="vault-hint" role="status">Connect this account and verify its registered Windows drive to check saved edits.</p>'
    : '';
  return `<section class="vault-pin-panel protected-vault-recovery-panel" aria-label="Saved encrypted-file edits"><div class="vault-pin-heading"><div><b>Saved encrypted-file edits</b><small>Read-only history for this encrypted location</small></div><button class="button subtle" data-vault-capture-refresh ${busy || ui.loading || !scope ? 'disabled' : ''}>${ui.loading ? 'Checking…' : page ? 'Refresh list' : 'Check saved edits'}</button></div><p class="vault-pin-note">Save Copy creates a readable plaintext file on this computer. It does not unlock, upload, retry, or remove the protected history item. Existing files are never replaced; choose a new destination name if needed.</p>${unavailable}${ui.error ? `<div class="vault-error" role="alert">${esc(ui.error)}</div>` : ''}${ui.message ? `<div class="vault-state" role="status">${esc(ui.message)}</div>` : ''}${ui.loading && !page ? '<div class="vault-pin-empty" role="status"><span class="spinner"></span> Checking protected history…</div>' : ''}${rows}${page?.next_cursor ? `<div class="vault-pin-more"><button class="small-action quiet" data-vault-capture-more ${busy || ui.loading || !scope ? 'disabled' : ''}>${ui.loading ? 'Loading…' : 'Load more'}</button></div>` : ''}</section>`;
}
function syncWindowsRecoveryContext() {
  syncWindowsDeviceCacheContext();
  windowsOfflineFoldersPanel.syncContext();
  const binding = isWindowsAgentStatus(state.status) ? windowsRecoveryBinding() : null;
  windowsRecoveryController.setContext(binding?.context || null);
  const context = binding?.context;
  const key = context ? JSON.stringify([context.accountEpoch, context.profileId, context.server, context.clientId, context.cloudRoot, context.authGeneration, context.recoveryScopeToken, state.status?.mounted === true]) : '';
  if (key !== windowsOfflineFilesUi.contextKey) {
    windowsOfflineFilesUi.contextKey = key;
    windowsOfflineFilesUi.generation++;
    windowsOfflineFilesUi.items = [];
    windowsOfflineFilesUi.nextCursor = null;
    windowsOfflineFilesUi.unavailableRows = 0;
    windowsOfflineFilesUi.loaded = false;
    windowsOfflineFilesUi.loading = false;
    windowsOfflineFilesUi.error = '';
    windowsOfflineFilesUi.selectedKey = '';
    windowsOfflineFileController.clearSelection();
    if (windowsOfflineFilesUi.pollTimer) window.clearTimeout(windowsOfflineFilesUi.pollTimer);
    windowsOfflineFilesUi.pollTimer = 0;
  }
}
async function loadWindowsRecoveryList() {
  if (!isWindowsAgentStatus(state.status)) return;
  const binding = windowsRecoveryBinding();
  if (!binding.context) {
    windowsRecoveryController.setContext(null);
    render();
    return;
  }
  const context = binding.context;
  const loading = windowsRecoveryController.load(context, request, () => {
    const current = isWindowsAgentStatus(state.status) ? windowsRecoveryBinding().context : null;
    return !!current && windowsRecoveryContextKey(current) === windowsRecoveryContextKey(context) &&
      isCurrentAccount(context.accountEpoch, context.profileId);
  });
  render();
  await loading;
  const current = isWindowsAgentStatus(state.status) ? windowsRecoveryBinding().context : null;
  if (current && windowsRecoveryContextKey(current) === windowsRecoveryContextKey(context)) render();
}
function currentWindowsOfflineFolderContext(): WindowsOfflineFolderContext | null {
  if (!isWindowsAgentStatus(state.status) || state.accountSwitching) return null;
  // Preserve a known job handle through a transient unreachable agent. Cached
  // identity only maintains the handle; actions still require a live mounted
  // drive and every RPC rechecks native account/root/session authority.
  const binding = eligibleWindowsRecoveryContext(true, state.selectedAccount, state.status, {
    accountEpoch: state.accountEpoch, server: state.status?.server || null,
    clientId: state.status?.client_id || null, cloudRoot: state.status?.cloud_root || null
  });
  return binding.context ? { ...binding.context, flowGeneration: 0 } : null;
}
function windowsOfflineFolderBusy(): boolean {
  const current = windowsOfflineFoldersPanel.controller.state;
  return current.loading || current.admissionUncertain || current.job?.state === 'running' || current.job?.state === 'prepared';
}
function scheduleWindowsOfflineFolderPoll() {
  if (windowsOfflineFolderPollTimer) window.clearTimeout(windowsOfflineFolderPollTimer);
  windowsOfflineFolderPollTimer = 0;
  const job = windowsOfflineFoldersPanel.controller.state.job;
  if (state.page !== 'transfers' || !state.agentReachable || !currentWindowsOfflineFolderContext() ||
      !job || !['running', 'prepared'].includes(job.state)) return;
  windowsOfflineFolderPollTimer = window.setTimeout(() => {
    windowsOfflineFolderPollTimer = 0;
    void runWindowsOfflineFolderAction('poll');
  }, 2000);
}
async function runWindowsOfflineFolderAction(kind: 'start' | 'resume' | 'refresh' | 'poll' | 'cancel') {
  await windowsOfflineFoldersPanel.run(kind);
  scheduleWindowsOfflineFolderPoll();
}
function windowsOfflineFoldersCard(): string {
  return isWindowsAgentStatus(state.status) ? windowsOfflineFoldersPanel.render() : '';
}

function currentWindowsOfflineContext(): WindowsOfflineFileContext | null {
  const { context } = windowsRecoveryBinding();
  if (!isWindowsAgentStatus(state.status) || !context || state.accountSwitching || state.status?.mounted !== true) return null;
  return { ...context, flowGeneration: windowsOfflineFilesUi.generation };
}
function syncWindowsDeviceCacheContext(): WindowsOfflineFileContext | null {
  const context = currentWindowsOfflineContext();
  const key = context ? JSON.stringify([context.accountEpoch, context.profileId, context.server, context.clientId, context.cloudRoot, context.authGeneration, context.recoveryScopeToken]) : '';
  if (key !== windowsDeviceCacheUi.contextKey) {
    windowsDeviceCacheUi.contextKey = key;
    windowsDeviceCacheUi.sequence++;
    windowsDeviceCacheUi.usage = null;
    windowsDeviceCacheUi.loading = false;
    windowsDeviceCacheUi.error = '';
  }
  return context;
}
async function refreshWindowsDeviceCacheUsage() {
  const context = syncWindowsDeviceCacheContext();
  if (!context || windowsDeviceCacheUi.loading) return;
  const key = windowsDeviceCacheUi.contextKey;
  const sequence = ++windowsDeviceCacheUi.sequence;
  windowsDeviceCacheUi.loading = true;
  windowsDeviceCacheUi.usage = null;
  windowsDeviceCacheUi.error = '';
  render();
  const current = () => {
    syncWindowsDeviceCacheContext();
    return key === windowsDeviceCacheUi.contextKey && sequence === windowsDeviceCacheUi.sequence && isCurrentAccount(context.accountEpoch, context.profileId);
  };
  try {
    const value = await request('windows_device_cache_usage', {
      profile_id: context.profileId, expected_generation: context.authGeneration,
      expected_recovery_scope_token: context.recoveryScopeToken
    });
    if (current()) windowsDeviceCacheUi.usage = validateWindowsDeviceCacheUsage(value, context);
  } catch (error) {
    if (current() && !isStaleAccountRequest(error)) windowsDeviceCacheUi.error = messageOf(error);
  } finally {
    if (current()) { windowsDeviceCacheUi.loading = false; render(); }
  }
}
function windowsDeviceCacheCard(): string {
  if (!syncWindowsDeviceCacheContext()) return '';
  const usage = windowsDeviceCacheUi.usage;
  return `<section class="settings-card windows-device-cache-card"><div class="settings-heading"><span class="settings-icon">${svg('download')}</span><div><h2>Device cache (all accounts)</h2><p>Shared by all Raiun accounts on this Windows device. These totals are not limited to the selected account.</p></div></div>${usage ? `<p role="status">Last observed: ${esc(formatBytes(usage.used_bytes))} used of ${esc(formatBytes(usage.quota_bytes))} · ${esc(formatBytes(usage.pinned_bytes))} pinned · ${esc(formatBytes(usage.protected_bytes))} protected.</p>${usage.over_quota ? '<p class="recovery-warning" role="status">The device cache is over its quota.</p>' : ''}` : '<p role="status">Device cache usage has not been checked.</p>'}${windowsDeviceCacheUi.error ? `<p class="recovery-warning" role="alert">${esc(windowsDeviceCacheUi.error)}</p>` : ''}<div class="button-group"><button class="button subtle" data-action="refresh-windows-device-cache" ${windowsDeviceCacheUi.loading ? 'disabled' : ''}>${windowsDeviceCacheUi.loading ? 'Checking…' : usage ? 'Refresh device cache usage' : 'Check device cache usage'}</button></div></section>`;
}
function windowsOfflineContextKey(context: WindowsOfflineFileContext): string {
  return JSON.stringify([context.accountEpoch, context.profileId, context.server, context.clientId, context.cloudRoot, context.authGeneration, context.recoveryScopeToken, context.flowGeneration]);
}
function validateWindowsOfflineFilesPage(value: unknown, expected: WindowsOfflineFileContext): WindowsOfflineFilesPage {
  const page = value as Record<string, unknown> | null;
  const keys = ['profile_id', 'auth_generation', 'recovery_scope_token', 'rows', 'next_cursor', 'unavailable_rows', 'read_only', 'last_observed', 'atomic_snapshot'].sort();
  if (!page || typeof page !== 'object' || Array.isArray(page) || Object.keys(page).sort().join('\0') !== keys.join('\0') ||
      page.profile_id !== expected.profileId || page.auth_generation !== expected.authGeneration || page.recovery_scope_token !== expected.recoveryScopeToken ||
      page.read_only !== true || page.last_observed !== true || page.atomic_snapshot !== false ||
      !Array.isArray(page.rows) || page.rows.length > 8 ||
      !(page.next_cursor === null || (typeof page.next_cursor === 'string' && /^[0-9a-f]{32}$/.test(page.next_cursor))) ||
      !Number.isSafeInteger(page.unavailable_rows) || (page.unavailable_rows as number) < 0) {
    throw new Error('The agent returned an invalid saved-file listing.');
  }
  const itemKeys = ['space_id', 'root_resource_id', 'path', 'resource_id', 'etag', 'size'].sort();
  const items = page.rows.map((value): WindowsOfflineFileRow => {
    const row = value as Record<string, unknown> | null;
    if (!row || typeof row !== 'object' || Array.isArray(row) || Object.keys(row).sort().join('\0') !== itemKeys.join('\0') ||
        typeof row.space_id !== 'string' || !row.space_id || typeof row.root_resource_id !== 'string' || !row.root_resource_id ||
        typeof row.path !== 'string' || typeof row.resource_id !== 'string' || !row.resource_id || typeof row.etag !== 'string' || !row.etag ||
        !Number.isSafeInteger(row.size) || (row.size as number) < 0) throw new Error('The agent returned an invalid saved-file row.');
    const mapped = { spaceId: row.space_id, rootResourceId: row.root_resource_id, path: row.path, resourceId: row.resource_id, etag: row.etag, size: row.size as number };
    windowsOfflineFileContextKey(expected, mapped);
    return mapped;
  });
  return { ...page, items } as unknown as WindowsOfflineFilesPage;
}
async function loadWindowsOfflineFiles(reset: boolean) {
  if (windowsOfflineFilesUi.loading || windowsOfflineFileController.state.loading ||
      windowsOfflineFileController.state.job?.state === 'running' || windowsOfflineFileController.state.admissionUncertain) return;
  const context = currentWindowsOfflineContext();
  if (!context || !state.agentReachable || state.status?.connected !== true) return;
  const currentKey = windowsOfflineContextKey(context);
  if (windowsOfflineFilesUi.contextKey !== JSON.stringify([context.accountEpoch, context.profileId, context.server, context.clientId, context.cloudRoot, context.authGeneration, context.recoveryScopeToken, state.status?.mounted === true])) return;
  if (!reset && (!windowsOfflineFilesUi.loaded || windowsOfflineFilesUi.nextCursor === null)) return;
  const cursor = reset ? null : windowsOfflineFilesUi.nextCursor;
  windowsOfflineFilesUi.generation++;
  const generation = windowsOfflineFilesUi.generation;
  windowsOfflineFilesUi.selectedKey = '';
  windowsOfflineFileController.clearSelection();
  if (windowsOfflineFilesUi.pollTimer) window.clearTimeout(windowsOfflineFilesUi.pollTimer);
  windowsOfflineFilesUi.pollTimer = 0;
  windowsOfflineFilesUi.loading = true;
  windowsOfflineFilesUi.error = '';
  render();
  try {
    const value = await request('windows_offline_files', {
      profile_id: context.profileId,
      expected_generation: context.authGeneration,
      expected_recovery_scope_token: context.recoveryScopeToken,
      ...(cursor ? { cursor } : {})
    });
    const page = validateWindowsOfflineFilesPage(value, context);
    const current = currentWindowsOfflineContext();
    if (!current || generation !== windowsOfflineFilesUi.generation || windowsOfflineContextKey(current) !== currentKey) return;
    windowsOfflineFilesUi.items = page.items;
    windowsOfflineFilesUi.nextCursor = page.next_cursor;
    windowsOfflineFilesUi.unavailableRows = page.unavailable_rows;
    windowsOfflineFilesUi.loaded = true;
  } catch (error) {
    if (generation === windowsOfflineFilesUi.generation) windowsOfflineFilesUi.error = messageOf(error);
  } finally {
    if (generation === windowsOfflineFilesUi.generation) { windowsOfflineFilesUi.loading = false; render(); }
  }
}
function windowsOfflineRowKey(row: WindowsOfflineFileRow): string {
  return JSON.stringify([row.spaceId, row.rootResourceId, row.path, row.resourceId, row.etag, row.size]);
}
function windowsOfflineSelectionCurrent(context: WindowsOfflineFileContext, row: WindowsOfflineFileRow): boolean {
  const current = currentWindowsOfflineContext();
  return !!current && windowsOfflineContextKey(current) === windowsOfflineContextKey(context) &&
    windowsOfflineFilesUi.selectedKey === windowsOfflineRowKey(row) && windowsOfflineFilesUi.items.some(item => windowsOfflineRowKey(item) === windowsOfflineFilesUi.selectedKey);
}
function scheduleWindowsOfflineFilePoll() {
  if (windowsOfflineFilesUi.pollTimer) window.clearTimeout(windowsOfflineFilesUi.pollTimer);
  windowsOfflineFilesUi.pollTimer = 0;
  const context = currentWindowsOfflineContext();
  const row = windowsOfflineFilesUi.items.find(item => windowsOfflineRowKey(item) === windowsOfflineFilesUi.selectedKey);
  if (state.page !== 'transfers' || !context || !row || windowsOfflineFileController.state.job?.state !== 'running') return;
  windowsOfflineFilesUi.pollTimer = window.setTimeout(() => { windowsOfflineFilesUi.pollTimer = 0; void runWindowsOfflineFileAction('poll'); }, 2000);
}
async function runWindowsOfflineFileAction(kind: 'start' | 'poll' | 'cancel') {
  if (kind === 'start' && windowsOfflineFolderBusy()) return;
  const context = currentWindowsOfflineContext();
  const row = windowsOfflineFilesUi.items.find(item => windowsOfflineRowKey(item) === windowsOfflineFilesUi.selectedKey);
  if (!context || !row || !windowsOfflineSelectionCurrent(context, row)) return;
  const isCurrent = () => windowsOfflineSelectionCurrent(context, row);
  const pending = kind === 'start'
    ? windowsOfflineFileController.start(context, row, request, isCurrent)
    : kind === 'cancel'
      ? windowsOfflineFileController.cancel(context, row, request, isCurrent)
      : windowsOfflineFileController.pollStatus(context, row, request, isCurrent);
  if (isCurrent()) render();
  await pending;
  const job = windowsOfflineFileController.state.job;
  if (isCurrent() && job && job.state !== 'running') {
    const refreshed = windowsOfflineFileController.loadCacheStatus(context, row, request, isCurrent);
    render();
    await refreshed;
  }
  if (isCurrent()) render();
  scheduleWindowsOfflineFilePoll();
}
function selectWindowsOfflineFile(key: string) {
  if (windowsOfflineFileController.state.loading || windowsOfflineFileController.state.job?.state === 'running' || windowsOfflineFileController.state.admissionUncertain) return;
  const context = currentWindowsOfflineContext();
  const row = windowsOfflineFilesUi.items.find(item => windowsOfflineRowKey(item) === key);
  if (!context || !row) return;
  if (windowsOfflineFilesUi.pollTimer) window.clearTimeout(windowsOfflineFilesUi.pollTimer);
  windowsOfflineFilesUi.pollTimer = 0;
  windowsOfflineFilesUi.selectedKey = key;
  windowsOfflineFileController.setSelection(context, row);
  const pending = windowsOfflineFileController.loadCacheStatus(context, row, request, () => windowsOfflineSelectionCurrent(context, row));
  render();
  void pending.then(() => { if (windowsOfflineSelectionCurrent(context, row)) render(); });
}
function windowsOfflineFilesCard() {
  if (!isWindowsAgentStatus(state.status)) return '';
  const context = currentWindowsOfflineContext();
  const file = windowsOfflineFilesUi.items.find(item => windowsOfflineRowKey(item) === windowsOfflineFilesUi.selectedKey) || null;
  const controller = windowsOfflineFileController.state;
  const actionsAvailable = !!context && state.agentReachable && state.status?.connected === true && !state.accountSwitching && !windowsOfflineFolderBusy();
  const listLocked = windowsOfflineFilesUi.loading || controller.loading || controller.job?.state === 'running' || controller.admissionUncertain;
  const cache = controller.cacheStatus;
  const job = controller.job;
  const unavailable = !context
    ? state.status?.mounted !== true ? 'Open your Windows drive before using these controls.' : 'Connect this account and set up its Windows drive to choose files.'
    : !state.agentReachable ? 'Raiun is not connected.'
      : state.status?.connected !== true ? 'Connect this account before listing or saving files.' : '';
  return `<section class="settings-card windows-offline-files-card"><div class="settings-heading"><span class="settings-icon">${svg('download')}</span><div><h2>Save individual files offline</h2><p>Choose a file already listed on this drive. Saved status may have changed since this page was loaded.</p></div></div><div class="settings-row"><div><b>Available files</b><small>Files from this account’s Windows drive.</small></div><div class="button-group"><button class="button subtle" data-action="refresh-windows-offline-files" ${!actionsAvailable || listLocked ? 'disabled' : ''}>${windowsOfflineFilesUi.loading ? 'Loading…' : windowsOfflineFilesUi.loaded ? 'Refresh files' : 'Load files'}</button><button class="button subtle" data-action="more-windows-offline-files" ${!actionsAvailable || listLocked || !windowsOfflineFilesUi.nextCursor ? 'disabled' : ''}>Load next page</button></div></div>${unavailable ? `<p class="recovery-hint" role="status">${esc(unavailable)}</p>` : ''}${windowsOfflineFilesUi.error ? `<div class="recovery-warning" role="alert">${esc(windowsOfflineFilesUi.error)}</div>` : ''}${windowsOfflineFilesUi.unavailableRows ? `<p class="recovery-hint" role="status">${windowsOfflineFilesUi.unavailableRows} files could not be shown. Refresh to check again.</p>` : ''}${windowsOfflineFilesUi.loaded ? windowsOfflineFilesUi.items.length ? `<div class="windows-offline-file-list">${windowsOfflineFilesUi.items.map(row => { const key = windowsOfflineRowKey(row); return `<button class="remote-entry ${windowsOfflineFilesUi.selectedKey === key ? 'selected' : ''}" data-windows-offline-row="${esc(key)}" ${listLocked ? 'disabled' : ''}><span>${esc(row.path.split('/').filter(Boolean).at(-1) || row.path)}</span><small>${esc(row.path)} · ${esc(formatBytes(row.size))}</small></button>`; }).join('')}</div>` : '<div class="recovery-empty" role="status">No files were returned in this listing.</div>' : ''}${file ? `<div class="windows-offline-file-detail"><div><b>${esc(file.path)}</b><small>${esc(spaceName(file.spaceId))}</small></div>${cache ? `<p role="status">Last saved status: ${{ recent: 'Automatically cached', always_offline: 'Keep offline', cloud_only: 'Cloud only' }[cache.policy]} · ${cache.recorded_complete_version ? `saved copy recorded (${esc(formatBytes(cache.recorded_bytes))})` : 'no complete saved copy recorded'}.</p>` : '<p role="status">Saved status has not been checked for this file.</p>'}${cache?.pending_offline_intent && !job ? '<p class="recovery-hint" role="status">A saved request to keep this version offline is unfinished. Choose Save this file offline to start a fresh download. Existing recovery data stays preserved.</p>' : ''}${controller.error ? `<div class="recovery-warning" role="alert">${esc(controller.error)}</div>` : ''}${job ? `<p role="status" aria-live="polite">${esc(windowsOfflineJobMessage(job))}</p><div class="button-group"><button class="button subtle" data-action="poll-windows-offline-file" ${controller.loading ? 'disabled' : ''}>Check job</button><button class="button subtle" data-action="cancel-windows-offline-file" ${controller.loading || job.state !== 'running' ? 'disabled' : ''}>Cancel download</button></div>` : `<button class="button primary" data-action="start-windows-offline-file" ${!actionsAvailable || controller.loading || controller.admissionUncertain ? 'disabled' : ''}>${controller.loading ? 'Starting…' : controller.admissionUncertain ? 'Download status unknown' : 'Save this file offline'}</button>`}${controller.admissionUncertain ? '<small role="status">The request may still be running. Reconnect the drive before trying another download.</small>' : ''}</div>` : ''}${windowsOfflineFilesUi.loaded ? '<small class="recovery-hint">Refresh to check for changes. New files appear after you browse their folder.</small>' : ''}</section>`;
}
const esc = (value: unknown) => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]!));
const icon = (name: string) => ({
  overview: '<path d="M3 10.5 12 3l9 7.5M5.5 9v11h13V9M9 20v-6h6v6"/>',
  folders: '<path d="M3 7.5h7l2 2h9v9.5H3zM3 7.5V5h7l2 2"/>',
  transfers: '<path d="M7 7h13m0 0-4-4m4 4-4 4M17 17H4m0 0 4-4m-4 4 4 4"/>',
  media: '<rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="8.5" cy="9" r="1.5"/><path d="m21 15-5-5L5 20"/>',
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
  download: '<path d="M12 3v12m0 0 4-4m-4 4-4-4M5 20h14"/>',
  arrowUp: '<path d="M12 19V5m0 0L6 11m6-6 6 6"/>',
  arrowDown: '<path d="M12 5v14m0 0 6-6m-6 6-6-6"/>',
  dots: '<circle cx="5" cy="12" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/>'
}[name] ?? '<circle cx="12" cy="12" r="8"/>');
const svg = (name: string, cls = '') => `<svg class="icon ${cls}" viewBox="0 0 24 24" aria-hidden="true">${icon(name)}</svg>`;
const spaceName = (id: string) => state.spaces.find(s => s.id === id)?.name ?? (id ? 'OpenCloud location' : 'OpenCloud');

function render() {
  const sameView = renderedPage === state.page && renderedAccount === state.selectedAccount;
  const previousMainScroll = sameView ? app.querySelector<HTMLElement>('.main-area')?.scrollTop ?? 0 : 0;
  const previousSidebarScroll = sameView ? app.querySelector<HTMLElement>('.sidebar')?.scrollTop ?? 0 : 0;
  const previousAccountListScroll = sameView ? app.querySelector<HTMLElement>('.account-list')?.scrollTop ?? 0 : 0;
  const active = document.activeElement;
  const focusedSavedRoot = active instanceof HTMLButtonElement && app.contains(active)
    && active.dataset.action === 'toggle-saved-write-root'
    ? { scopeKey: active.dataset.scopeKey, accountEpoch: state.accountEpoch, profileId: state.selectedAccount }
    : null;
  const priorVaultDialogHadFocus = !!state.vaultDialog && !!app.querySelector('.vault-modal')?.contains(active);
  const focusedCopyControl = active instanceof HTMLElement
    ? active.closest<HTMLElement>('[data-action="verify-copy-operation"], [data-action="check-copy-verification-status"], [data-action="cancel-copy-verification"], [data-copy-verify-live]')
    : null;
  const copyFocus = focusedCopyControl ? {
    action: focusedCopyControl.dataset.action || '',
    live: focusedCopyControl.hasAttribute('data-copy-verify-live'),
    spaceId: focusedCopyControl.dataset.spaceId || focusedCopyControl.dataset.copyVerifySpace || '',
    rootResourceId: focusedCopyControl.dataset.rootResourceId || focusedCopyControl.dataset.copyVerifyRoot || '',
    writeId: focusedCopyControl.dataset.writeId || focusedCopyControl.dataset.copyVerifyWrite || '',
    revision: focusedCopyControl.dataset.revision || focusedCopyControl.dataset.copyVerifyRevision || '',
    authGeneration: focusedCopyControl.dataset.authGeneration || focusedCopyControl.dataset.copyVerifyGeneration || '',
    accountEpoch: state.accountEpoch,
    profileId: state.selectedAccount
  } : null;
  const focusedInput = app.contains(active) && (active instanceof HTMLInputElement || active instanceof HTMLTextAreaElement) && active.id
    ? {
      id: active.id,
      value: active.value,
      start: selectionStart(active),
      end: selectionEnd(active),
      direction: selectionDirection(active)
    }
    : null;
  const stableButtonFocusKeys = ['action', 'page', 'syncSection', 'accountId', 'pairId', 'spaceId', 'writeId', 'rootResourceId', 'vaultPinRemove', 'vaultPinStart'];
  const focusedButton = app.contains(active) && active instanceof HTMLButtonElement
    && (!!active.id || stableButtonFocusKeys.some(key => key in active.dataset))
    ? {
      id: active.id,
      dataset: Object.fromEntries(stableButtonFocusKeys
        .filter(key => key in active.dataset)
        .map(key => [key, active.dataset[key] || ''])),
      accountEpoch: state.accountEpoch,
      profileId: state.selectedAccount
    }
    : null;
  const focusedSelect = app.contains(active) && active instanceof HTMLSelectElement && active.id
    ? { id: active.id, value: active.value }
    : null;
  const connected = state.status?.connected === true;
  const reachable = state.agentReachable;
  const connection = connectionMode(reachable, state.status);
  const retainedSignInOnly = state.status?.offline === true && state.status.offline_namespace !== true;
  const appearance = readAppearance({ getItem: key => window.localStorage.getItem(key) }, state.selectedAccount);
  document.documentElement.dataset.theme = appearance.theme;
  document.documentElement.style.setProperty('--account-accent', ACCENT_COLORS[appearance.accent]);
  const activeAccount = state.accounts.find(account => account.id === state.selectedAccount);
  const targetAccount = state.accounts.find(account => account.id === state.accountSwitchTarget);
  const nav = [['overview', 'Overview', 'overview'], ['folders', 'Sync workspace', 'folders'], ['offline', 'Offline files', 'download'], ['encrypted', 'Encrypted files', 'lock'], ['transfers', 'Transfers', 'transfers'], ['settings', 'Settings', 'settings']] as const;
  const markup = `
    <div class="shell">
      <aside class="sidebar">
        <div class="brand"><img class="brand-logo" src="${raiunLogo}" alt="" /><div><strong>raiun</strong><span>DESKTOP</span></div></div>
        <section class="account-section" aria-label="Accounts">
          <div class="side-label">YOUR ACCOUNTS</div>
          <div class="account-list" role="group" aria-label="OpenCloud accounts">${state.accounts.length ? state.accounts.map(account => {
            const selected = state.selectedAccount === account.id;
            const switching = state.accountSwitchTarget === account.id;
            const connectedAccount = account.status.connected === true;
            return `<button class="account-option ${selected ? 'selected' : ''} ${switching ? 'switching' : ''}" data-account-id="${esc(account.id)}" aria-pressed="${selected}" aria-busy="${switching}" title="${selected ? 'Current account' : `Switch to ${esc(account.label)}`}" ${accountSwitchDisabled() || !featureAvailable('account_switch_supported') ? 'disabled' : ''}><span class="account-option-mark">${svg('cloud')}</span><span class="account-option-copy"><b>${esc(account.label)}</b><small>${switching ? 'Switching…' : esc(accountStatusLabel(account.status))}</small></span><span class="account-option-state ${connectedAccount ? 'connected' : account.status.error ? 'attention' : ''}" aria-hidden="true">${selected ? svg('check') : ''}</span></button>`;
          }).join('') : `<div class="account-list-empty">${state.accountsLoading ? 'Loading accounts…' : 'No accounts found.'}</div>`}</div>
          ${state.accountSwitching && targetAccount ? `<div class="account-switch-feedback" role="status" aria-live="polite">Switching to ${esc(targetAccount.label)}…</div>` : ''}
          <button class="button subtle account-add-button" data-action="open-add-account" ${accountSwitchDisabled() || !featureAvailable('account_switch_supported') ? 'disabled' : ''}>${svg('plus')} Add account</button>
          ${state.accountsError ? `<div class="account-list-error" role="alert">${esc(state.accountsError)}</div>` : ''}
        </section>
        <nav aria-label="Main navigation">${nav.map(([key, label, glyph]) => { const encryptedEdits = state.encryptedEditRecoveryPage?.counts; const encryptedNeedsAttention = encryptedEdits ? encryptedEdits.pending + encryptedEdits.uncertain + encryptedEdits.corrupt : 0; const transferBadge = activeCount() + pendingWritesUi.pendingCount + pendingWritesUi.conflictCount + encryptedNeedsAttention; return `<button class="nav-item ${state.page === key ? 'selected' : ''}" data-page="${key}">${svg(glyph)}<span>${label}</span>${key === 'transfers' && transferBadge ? `<span class="nav-count" title="${activeCount()} active transfers, ${pendingWritesUi.pendingCount + pendingWritesUi.conflictCount} ordinary offline edits, and ${encryptedNeedsAttention} encrypted edits needing review">${transferBadge}</span>` : ''}</button>`; }).join('')}</nav>
        <div class="sidebar-bottom"><button class="agent-status agent-status-toggle" data-action="toggle-pause" ${reachable && connected && featureAvailable('pause_supported') ? '' : 'disabled'} aria-label="${state.status?.paused ? 'Resume sync' : 'Pause sync'}"><span class="status-mark ${connected && providerAvailable(state.status?.provider_supported) ? 'online' : 'offline'}">${svg(connected && providerAvailable(state.status?.provider_supported) ? (state.status?.paused ? 'play' : 'pause') : 'alert')}</span><span class="agent-status-copy"><b>${connection === 'unavailable' ? 'Agent unavailable' : connection === 'offline_reconnecting' ? retainedSignInOnly ? 'Reconnecting sign-in' : 'Working offline' : connection === 'sign_in' ? 'Sign-in needed' : !providerAvailable(state.status?.provider_supported) ? 'Drive unavailable' : !featureAvailable('pause_supported') ? 'Drive connected' : (state.status?.paused ? 'Sync paused' : 'Sync running')}</b><small>${!providerAvailable(state.status?.provider_supported) ? 'Windows drive support is not enabled' : connection === 'unavailable' ? 'Waiting for Raiun agent' : connection === 'offline_reconnecting' ? retainedSignInOnly ? 'Retrying saved sign-in' : 'Reconnecting to server' : connection === 'sign_in' ? 'Connect your OpenCloud account' : !featureAvailable('pause_supported') ? 'Cloud drive available' : (state.status?.paused ? 'Click to resume' : 'Click to pause')}</small></span></button><div class="version">RAIUN DESKTOP <span id="app-version">${esc(appVersionLabel)}</span></div></div>
      </aside>
      <main class="main-area">
        <header class="topbar"><div class="topbar-account ${noAccountsAvailable() ? '' : 'selected-account-accent'}" aria-label="Selected account" aria-live="polite"><b>${noAccountsAvailable() ? 'No account selected' : state.accountSwitching && targetAccount ? `Switching to ${esc(targetAccount.label)}…` : esc(selectedAccountLabel())}</b></div><div class="top-actions"><button class="icon-button" id="refresh" aria-label="Refresh status" title="Refresh">${svg('refresh')}</button></div></header>
        <section class="content">${pageMarkup()}</section>
      </main>
    </div>
    ${desktopUpdateNotification()}
    ${(state.error || (state.status?.error && state.status.error !== state.statusErrorDismissed)) ? `<div class="toast error-toast" role="alert"><span>${svg('alert')}</span><div>${esc(state.error || state.status?.error || '')}</div><button data-dismiss-error aria-label="Dismiss">${svg('close')}</button></div>` : ''}
    ${state.message ? `<div class="toast success-toast" role="status"><span>${svg('check')}</span><div>${esc(state.message)}</div><button data-dismiss-message aria-label="Dismiss">${svg('close')}</button></div>` : ''}
    ${state.addOpen ? addModal() : ''}
    ${state.addAccountOpen ? addAccountModal() : ''}
    ${state.pickerOpen && !(state.page === 'offline' && state.pickerPurpose === 'offline') ? pickerModal() : ''}
    ${state.vaultDialog ? vaultDialog() : ''}
    ${state.vaultAccessOpen && state.page !== 'encrypted' ? encryptedAccessModal() : ''}`;
  if (markup !== lastRenderedMarkup) {
    app.innerHTML = markup;
    lastRenderedMarkup = markup;
    bind();
  }
  if (sameView) {
    const main = app.querySelector<HTMLElement>('.main-area');
    const sidebar = app.querySelector<HTMLElement>('.sidebar');
    const accountList = app.querySelector<HTMLElement>('.account-list');
    if (main) main.scrollTop = previousMainScroll;
    if (sidebar) sidebar.scrollTop = previousSidebarScroll;
    if (accountList) accountList.scrollTop = previousAccountListScroll;
  }
  renderedPage = state.page;
  renderedAccount = state.selectedAccount;
  if (focusedInput) {
    const replacement = document.getElementById(focusedInput.id);
    if (replacement instanceof HTMLInputElement || replacement instanceof HTMLTextAreaElement) {
      replacement.value = focusedInput.value;
      replacement.focus({ preventScroll: true });
      if (focusedInput.start !== null && focusedInput.end !== null) {
        try { replacement.setSelectionRange(focusedInput.start, focusedInput.end, focusedInput.direction || 'none'); } catch { /* Some input types do not support selection ranges. */ }
      }
    }
  }
  if (focusedSelect) {
    const replacement = document.getElementById(focusedSelect.id);
    if (replacement instanceof HTMLSelectElement) {
      if ([...replacement.options].some(option => option.value === focusedSelect.value)) replacement.value = focusedSelect.value;
      replacement.focus({ preventScroll: true });
    }
  }
  if (sameView && focusedButton && focusedButton.accountEpoch === state.accountEpoch && focusedButton.profileId === state.selectedAccount) {
    const replacement = focusedButton.id
      ? document.getElementById(focusedButton.id)
      : [...app.querySelectorAll<HTMLButtonElement>('button')].find(button =>
        Object.entries(focusedButton.dataset).every(([key, value]) => button.dataset[key] === value));
    if (replacement instanceof HTMLButtonElement && !replacement.disabled) replacement.focus({ preventScroll: true });
  }
  if (copyFocus && state.page === 'transfers' && copyFocus.accountEpoch === state.accountEpoch && copyFocus.profileId === state.selectedAccount) {
    const matchesBinding = (element: HTMLElement) =>
      (element.dataset.spaceId || element.dataset.copyVerifySpace || '') === copyFocus.spaceId &&
      (element.dataset.rootResourceId || element.dataset.copyVerifyRoot || '') === copyFocus.rootResourceId &&
      (element.dataset.writeId || element.dataset.copyVerifyWrite || '') === copyFocus.writeId &&
      (element.dataset.revision || element.dataset.copyVerifyRevision || '') === copyFocus.revision &&
      (element.dataset.authGeneration || element.dataset.copyVerifyGeneration || '') === copyFocus.authGeneration;
    const actionReplacement = copyFocus.live ? null : [...app.querySelectorAll<HTMLElement>('[data-action]')]
      .find(element => element.dataset.action === copyFocus.action && matchesBinding(element));
    const replacement = copyFocus.live
      ? [...app.querySelectorAll<HTMLElement>('[data-copy-verify-live]')].find(matchesBinding)
      : actionReplacement && (!(actionReplacement instanceof HTMLButtonElement) || !actionReplacement.disabled)
        ? actionReplacement
        : [...app.querySelectorAll<HTMLElement>('[data-copy-verify-live]')].find(matchesBinding);
    replacement?.focus({ preventScroll: true });
  }
  if (sameView && focusedSavedRoot && state.page === 'transfers'
    && focusedSavedRoot.accountEpoch === state.accountEpoch && focusedSavedRoot.profileId === state.selectedAccount
    && pendingWritesUi.accountEpoch === state.accountEpoch) {
    const replacement = [...app.querySelectorAll<HTMLButtonElement>('button[data-action="toggle-saved-write-root"]')]
      .find(button => button.dataset.scopeKey === focusedSavedRoot.scopeKey);
    replacement?.focus({ preventScroll: true });
  }
  const vaultDialogElement = app.querySelector<HTMLElement>('.vault-modal');
  if (state.vaultDialog) {
    if (renderedVaultDialog !== state.vaultDialog || (priorVaultDialogHadFocus && !vaultDialogElement?.contains(document.activeElement))) {
      renderedVaultDialog = state.vaultDialog;
      const target = vaultDialogInitialFocusTarget(state.vaultDialog);
      const focusTarget = target === 'password'
        ? app.querySelector<HTMLInputElement>('#vault-password')
        : target === 'create-name'
          ? app.querySelector<HTMLInputElement>('#vault-create-name')
          : null;
      (focusTarget && !focusTarget.disabled ? focusTarget : vaultDialogElement)?.focus({ preventScroll: true });
    }
  } else if (renderedVaultDialog) {
    renderedVaultDialog = null;
    restoreVaultDialogFocus();
  }
  scheduleQueuedPassiveStatusRefresh();
}

function captureVaultDialogFocusReturn(element: Element | null): VaultDialogFocusReturn | null {
  if (!(element instanceof HTMLElement)) return null;
  let locator: VaultDialogFocusReturn['locator'] | null = null;
  if (element.id) locator = { kind: 'id', value: element.id };
  else {
    const names = ['data-vault-pair', 'data-vault-root', 'data-action', 'data-page'] as const;
    for (const name of names) {
      const value = element.getAttribute(name);
      if (value === null) continue;
      const matches = [...app.querySelectorAll<HTMLElement>(`[${name}]`)].filter(candidate => candidate.getAttribute(name) === value);
      locator = { kind: 'attribute', name, value, occurrence: Math.max(0, matches.indexOf(element)) };
      break;
    }
  }
  return locator ? { accountEpoch: state.accountEpoch, page: state.page, locator } : null;
}

function restoreVaultDialogFocus() {
  const saved = vaultDialogFocusReturn;
  vaultDialogFocusReturn = null;
  if (!saved || saved.accountEpoch !== state.accountEpoch || saved.page !== state.page) return;
  let target: HTMLElement | null = null;
  const locator = saved.locator;
  if (locator.kind === 'id') target = document.getElementById(locator.value);
  else {
    const name = locator.name;
    const matches = [...app.querySelectorAll<HTMLElement>(`[${name}]`)].filter(candidate => candidate.getAttribute(name) === locator.value);
    target = matches[locator.occurrence] ?? null;
  }
  if (target instanceof HTMLButtonElement && target.disabled) target = null;
  target ??= app.querySelector<HTMLElement>('.main-area');
  if (target) {
    if (target.tabIndex < 0) target.tabIndex = -1;
    target.focus({ preventScroll: true });
  }
}

function selectionStart(element: HTMLInputElement | HTMLTextAreaElement): number | null {
  try { return element.selectionStart; } catch { return null; }
}
function selectionEnd(element: HTMLInputElement | HTMLTextAreaElement): number | null {
  try { return element.selectionEnd; } catch { return null; }
}
function selectionDirection(element: HTMLInputElement | HTMLTextAreaElement): 'forward' | 'backward' | 'none' | null {
  try { return element.selectionDirection; } catch { return null; }
}

function pageMarkup(): string {
  if (!state.status) return `<div class="loading-panel"><div class="spinner"></div><p>Checking Raiun agent…</p></div>`;
  if (noAccountsAvailable() && state.page !== 'settings') return noAccountPage();
  if (state.page === 'overview') return overviewPage();
  if (state.page === 'folders') return syncWorkspacePage();
  if (state.page === 'offline') return offlineWorkspacePage();
  if (state.page === 'encrypted') return encryptedWorkspacePage();
  if (state.page === 'transfers') return transfersPage();
  return settingsPage();
}
function noAccountsAvailable(): boolean {
  return state.accountRemovalSupported && !state.accountsLoading && state.accounts.length === 0 && !state.selectedAccount;
}
function noAccountPage(): string {
  return `<div class="empty-card no-account-card"><span class="empty-icon">${svg('cloud')}</span><div><h3>No OpenCloud account is active</h3><p>Add an account to connect a server, or open Settings to restore a removed account. Restoring requires signing in again.</p><div class="button-group"><button class="button primary" data-action="open-add-account">Add account</button><button class="button subtle" data-page="settings">Open Settings</button></div></div></div>`;
}
function connectionFailureDetails(status: Status | null | undefined): string {
  const detail = typeof status?.error === 'string' ? status.error.trim() : '';
  return detail ? `<details class="connection-error-detail"><summary>Connection details</summary><p>${esc(detail)}</p></details>` : '';
}
function syncWorkspacePage() {
  const unavailable = !state.agentReachable
    ? 'Start the Raiun background agent to load media backups.'
    : !state.status?.connected
      ? 'Sign in to your OpenCloud account to load and manage media backups.'
      : 'Recurring media backups are unavailable for this agent.';
  const content = state.syncSection === 'folders'
    ? foldersPage()
    : `${featureAvailable('media_jobs_supported') ? mediaJobs.html() : `<p class="notice-card">${unavailable}</p>`}${mediaPreviewPage()}`;
  return `<div class="workspace-tabs" role="tablist" aria-label="Sync workspace"><button class="filter-tab ${state.syncSection === 'folders' ? 'active' : ''}" role="tab" aria-selected="${state.syncSection === 'folders'}" data-sync-section="folders">Synced folders</button><button class="filter-tab ${state.syncSection === 'media' ? 'active' : ''}" role="tab" aria-selected="${state.syncSection === 'media'}" data-sync-section="media">Media backups</button></div>${content}`;
}
function mediaPreviewPage() {
  const busy = mediaPreview.loading || state.nativeDialogBusy;
  return `<div class="page-title-row"><div><div class="eyebrow">LOCAL DRY RUN</div><h2>Media preview</h2><p class="lede">Preview photo and video destinations without changing your files.</p></div><button class="button primary" data-action="run-media-preview" ${busy || !mediaPreview.source || !mediaPreview.destinationRoot.trim() ? 'disabled' : ''}>${busy && mediaPreview.loading ? '<span class="spinner"></span> Scanning…' : 'Preview folder'}</button></div>
    <div class="media-disclaimer">${svg('alert')}<div><b>Read-only preview; no file contents are changed.</b><span>Nothing is uploaded, renamed, or deleted. Existing cloud files are not checked for name conflicts.</span></div></div>
    <section class="settings-card media-form"><div class="media-field"><label class="field-label" for="media-source">Source folder on this computer</label><div class="input-with-button"><input id="media-source" value="${esc(mediaPreview.source)}" placeholder="Choose a folder to scan" readonly/><button class="button subtle" data-action="choose-media-source" ${busy ? 'disabled' : ''}>Browse</button></div></div>
    <div class="media-field"><label class="field-label" for="media-destination">Destination folder path</label><input class="media-input" id="media-destination" value="${esc(mediaPreview.destinationRoot)}" placeholder="/Personal/Photos" ${busy ? 'disabled' : ''}/><small>Enter a planned destination such as /Personal/Photos. No cloud connection is needed.</small></div>
    <div class="media-options"><div class="media-field"><label class="field-label" for="media-filter">Include</label><select id="media-filter" ${busy ? 'disabled' : ''}><option value="photos" ${mediaPreview.filter === 'photos' ? 'selected' : ''}>Photos</option><option value="videos" ${mediaPreview.filter === 'videos' ? 'selected' : ''}>Videos</option><option value="all" ${mediaPreview.filter === 'all' ? 'selected' : ''}>All files</option></select></div><div class="media-field"><label class="field-label" for="media-organization">Organize destination</label><select id="media-organization" ${busy ? 'disabled' : ''}><option value="preserve_relative_path" ${mediaPreview.organization === 'preserve_relative_path' ? 'selected' : ''}>Keep source folders and filenames</option><option value="utc_year_month" ${mediaPreview.organization === 'utc_year_month' ? 'selected' : ''}>Group by filesystem modified date (UTC year/month)</option></select></div></div>
    <p class="media-form-note">Photos includes recognized images; Videos includes recognized videos. File contents determine the type, not the extension. All files also includes other regular files. Scans include subfolders and skip symbolic links.</p>
    <p class="media-form-note">${mediaPreview.organization === 'utc_year_month' ? 'Uses filesystem modification time only. No photo or video metadata is read; files without a usable date are marked in the preview.' : 'No date is inferred. Original filenames and source-relative folders are preserved.'}</p></section>
    ${mediaPreview.error ? `<div class="media-warning" role="alert">${svg('alert')}<span>${esc(mediaPreview.error)}</span></div>` : ''}${mediaPreview.result ? mediaResults(mediaPreview.result) : `<div class="empty-card media-empty"><span class="empty-icon">${svg('media')}</span><div><h3>Choose a folder to start</h3><p>This preview is available while you are signed out. It never uploads, renames, or deletes source files.</p></div></div>`}`;
}
function mediaResults(result: MediaScanResponse) {
  const outcomeCounts = result.totals;
  const scanStatus = !result.complete || result.truncated
    ? `<div class="media-warning" role="status">${svg('alert')}<span>Incomplete scan. Review warnings; this preview may omit files.</span></div>`
    : `<div class="media-complete" role="status" aria-label="Scan completed. This is a local path preview only.">${svg('check')}<span>Scan completed. This is a local path preview only.</span></div>`;
  const warnings = result.warnings.length || result.warnings_omitted
    ? `<section class="media-results-section"><div class="section-heading"><div><h2>Scan warnings</h2><p>Skipped or unrecognized entries are listed here.</p></div></div><ul class="media-warning-list">${result.warnings.map(warning => `<li><b>${esc(warning.kind.replaceAll('_', ' '))}</b>${warning.relative_path ? `<code>${esc(warning.relative_path)}</code>` : ''}<span>${esc(warning.message)}</span></li>`).join('')}${result.warnings_omitted ? `<li><b>More warnings</b><span>${result.warnings_omitted} additional warnings omitted.</span></li>` : ''}</ul></section>`
    : '';
  const rows = result.rows.length
    ? `<div class="media-table-wrap"><table class="media-table"><thead><tr><th>Source file</th><th>Preview result</th><th>Destination path</th></tr></thead><tbody>${result.rows.map(mediaPlanRow).join('')}</tbody></table></div>${result.rows_truncated ? `<p class="media-row-limit">Showing the first ${result.rows.length} of ${outcomeCounts.sources} source rows.</p>` : ''}`
    : `<div class="media-empty-result">No source rows to display.</div>`;
  return `<section class="media-results"><div class="media-summary">${mediaStat('Scanned entries', outcomeCounts.scanned)}${mediaStat('Source files', outcomeCounts.sources)}${mediaStat('Planned paths', outcomeCounts.planned)}${mediaStat('Filtered out', outcomeCounts.filtered)}${mediaStat('Needs a date', outcomeCounts.missing_date)}${mediaStat('Collisions', outcomeCounts.collisions)}${mediaStat('Rejected', outcomeCounts.rejected)}</div>${scanStatus}${warnings}<section class="media-results-section"><div class="section-heading"><div><h2>Preview rows</h2><p>Destinations preserve filenames; no remote inventory is checked.</p></div></div>${rows}</section></section>`;
}
function mediaStat(label: string, value: number) { return `<div class="media-stat"><span>${esc(label)}</span><b>${Number.isFinite(value) ? value : 0}</b></div>`; }
function mediaPlanRow(item: MediaPlanItem) {
  const outcome = item.outcome;
  if (typeof outcome === 'string') {
    if (outcome === 'filtered') return `<tr><td><code>${esc(item.source_relative_path)}</code></td><td><span class="media-result-badge muted">Filtered out</span></td><td>—</td></tr>`;
    if (outcome === 'missing_utc_date') return `<tr><td><code>${esc(item.source_relative_path)}</code></td><td><span class="media-result-badge warning">Missing date</span></td><td>—</td></tr>`;
  }
  const detail = outcome && typeof outcome === 'object' ? Object.entries(outcome)[0] : undefined;
  const kind = detail?.[0] || 'unknown';
  const payload = detail?.[1] && typeof detail[1] === 'object' ? detail[1] as Record<string, unknown> : {};
  const destination = typeof payload.destination_path === 'string' ? payload.destination_path : '';
  if (kind === 'planned') return `<tr><td><code>${esc(item.source_relative_path)}</code></td><td><span class="media-result-badge planned">Planned</span></td><td><code>${esc(destination)}</code></td></tr>`;
  if (kind === 'collision') return `<tr><td><code>${esc(item.source_relative_path)}</code></td><td><span class="media-result-badge warning">Collision</span></td><td><code>${esc(destination)}</code></td></tr>`;
  if (kind === 'rejected') return `<tr><td><code>${esc(item.source_relative_path)}</code></td><td><span class="media-result-badge warning">Rejected${payload.reason ? ` · ${esc(String(payload.reason).replaceAll('_', ' '))}` : ''}</span></td><td>—</td></tr>`;
  return `<tr><td><code>${esc(item.source_relative_path)}</code></td><td><span class="media-result-badge muted">${esc(kind.replaceAll('_', ' '))}</span></td><td>${destination ? `<code>${esc(destination)}</code>` : '—'}</td></tr>`;
}
function overviewPage() {
  const connected = state.status?.connected === true;
  const providerEnabled = providerAvailable(state.status?.provider_supported);
  const connection = connectionMode(state.agentReachable, state.status);
  const retainedSignInOnly = state.status?.offline === true && state.status.offline_namespace !== true;
  const signInPending = windowsSignInPending();
  const reachable = state.agentReachable;
  const errors = (state.status?.error ? 1 : 0) + attentionCount();
  const running = state.transfers.filter(item => ['queued', 'running', 'retry_wait', 'verifying'].includes((item.state || '').toLowerCase())).length;
  return `<div class="welcome-row"><div><div class="eyebrow">YOUR FILES, IN RHYTHM</div><h1>Good to see you.</h1><p class="lede">Your cloud files and sync folders, together in one place.</p></div><button class="button primary" data-action="add-pair" ${connected && featureAvailable('folder_sync_supported') ? '' : 'disabled'}>${svg('plus')} Add sync folder</button></div>
    ${connection === 'unavailable' ? `<div class="notice-card offline"><div class="notice-icon">${svg('alert')}</div><div class="notice-copy"><b>Raiun agent isn't available</b><p>${esc(state.status?.error || 'Start the Raiun background agent to connect this window to your account. Your settings will appear here once it is running.')}</p></div><button class="button subtle" data-action="refresh">Try again</button></div>` : connection === 'offline_reconnecting' ? `<div class="notice-card offline"><div class="notice-icon">${svg('cloud')}</div><div class="notice-copy"><b>${state.status?.refreshing ? 'Checking connection…' : retainedSignInOnly ? 'Reconnecting saved sign-in' : 'Working offline — reconnecting to server'}</b><p>${retainedSignInOnly ? 'Raiun still has this account’s sign-in and will retry the server connection. Cloud files are not available until it reconnects.' : 'Your existing offline session is still available. Raiun will retry the connection; you do not need to sign in again.'}</p>${connectionFailureDetails(state.status)}</div><button class="button subtle" data-action="refresh" ${state.status?.refreshing ? 'disabled' : ''}>${state.status?.refreshing ? 'Checking…' : 'Retry connection'}</button></div>` : connection === 'sign_in' ? `<div class="notice-card"><div class="notice-icon">${svg('cloud')}</div><div class="notice-copy"><b>Connect your OpenCloud account</b><p>Sign in using your organization’s OpenCloud server. Raiun will open the sign-in page in your browser.</p>${signInPending ? `<div class="signin-pending" role="status">Raiun is waiting for sign-in to finish in your browser.<button class="button subtle" data-action="cancel-sign-in" ${state.mutationBusy ? 'disabled' : ''}>Cancel sign-in</button></div>` : `<div class="signin-server"><input id="server-address" data-server value="${esc(state.server)}" placeholder="https://cloud.example.com" aria-label="OpenCloud server address"/><input id="client-id" data-client-id value="${esc(state.clientId)}" placeholder="Automatic client ID" aria-label="OAuth client ID override (optional)"/><button class="button primary" data-action="sign-in">Sign in ${svg('chevron')}</button></div>`}</div></div>` : ''}
    <div class="section-heading"><div><h2>At a glance</h2><p>A live view from your Raiun agent.</p></div>${connected ? `<span class="live-pill"><i></i> LIVE</span>` : ''}</div>
    <div class="stats-grid"><article class="stat-card"><div class="stat-label">SYNC FOLDERS</div><div class="stat-value">${reachable && connected && providerEnabled ? state.pairs.length : '—'}</div><div class="stat-foot">${!providerEnabled ? 'Windows drive support is not enabled' : !reachable ? 'Connect the agent to see folders' : connected ? 'Connected folder pairs' : connection === 'offline_reconnecting' ? 'Reconnecting to server' : 'Sign in to load your folders'}</div><span class="stat-icon teal">${svg('folders')}</span></article><article class="stat-card"><div class="stat-label">ACTIVE TRANSFERS</div><div class="stat-value">${reachable && connected && providerEnabled ? running : '—'}</div><div class="stat-foot">${!providerEnabled ? 'Transfer status is unavailable' : !reachable ? 'Connect the agent to see transfers' : connected ? (running ? 'Work in progress' : 'Nothing in progress') : connection === 'offline_reconnecting' ? 'Reconnecting to server' : 'Sign in to load transfers'}</div><span class="stat-icon blue">${svg('transfers')}</span></article><button class="stat-card stat-card-button" data-action="show-attention" ${reachable && (connected || !!state.status?.error) ? '' : 'disabled'} aria-label="Show ${errors} items needing attention"><div class="stat-label">NEEDS ATTENTION</div><div class="stat-value ${errors ? 'attention-value' : ''}">${reachable && (connected || state.status?.error) ? errors : '—'}</div><div class="stat-foot">${!reachable ? 'Connect the agent to see status' : state.status?.error ? 'Open settings to review this issue' : connected ? (errors ? 'Review items below' : 'No issues reported') : connection === 'offline_reconnecting' ? 'Working offline' : 'Sign in to load status'}</div><span class="stat-icon ${errors ? 'amber' : 'green'}">${svg(errors ? 'alert' : 'check')}</span></button></div>
    <div class="section-heading folders-heading"><div><h2>Your sync folders</h2><p>Each folder stays where you put it.</p></div><button class="text-button" data-page="folders">View all ${svg('chevron')}</button></div>
    ${!providerEnabled ? `<div class="notice-card offline"><div class="notice-icon">${svg('alert')}</div><div class="notice-copy"><b>Windows cloud drive is not available</b><p>${connected ? 'Your account is connected. ' : ''}This agent can save the drive folder setup, but it cannot mount or sync files yet.</p></div></div>` : reachable && connected ? (state.pairs.length ? `<div class="pair-list">${state.pairs.slice(0, 3).map(pair => pairCard(pair)).join('')}</div>` : emptyFolders()) : `<div class="empty-card compact"><span class="empty-icon">${svg(reachable ? 'cloud' : 'folders')}</span><div><b>${connection === 'offline_reconnecting' ? 'Working offline' : reachable ? 'Sign in to load your folder pairs' : 'Waiting for agent connection'}</b><p>${connection === 'offline_reconnecting' ? 'Your folder details will refresh when Raiun reconnects.' : reachable ? 'Your sync folders will appear here when your OpenCloud account connects.' : 'Folder details will show when the agent is reachable.'}</p></div></div>`}
    <div class="cloud-root-card"><div class="cloud-root-icon">${svg('cloud')}</div><div class="root-copy"><b>OpenCloud drive</b><span>${reachable && state.status?.cloud_root ? esc(state.status.cloud_root) : 'Your cloud drive location will appear here'}</span></div><span class="root-badge ${reachable && state.status?.mounted ? 'mounted' : ''}">${reachable && state.status?.mounted ? 'Mounted' : !providerEnabled && reachable && state.status?.cloud_root ? 'Configured · disconnected' : 'Not mounted'}</span><button class="icon-button" data-action="open-cloud" ${providerEnabled && reachable && state.status?.mounted && (connected || state.status?.offline_namespace === true) && state.status?.cloud_root ? '' : 'disabled'} aria-label="Open cloud folder">${svg('chevron')}</button></div>${reachable ? `${encryptedAccessCard()}${connected ? offlineAvailabilityCard() : ''}` : ''}`;
}
function offlineAvailabilityCard() {
  if (isWindowsAgentStatus(state.status)) return windowsDeviceCacheCard();
  const cache = state.status?.offline_cache;
  if (!cache) return '';
  const providerEnabled = providerAvailable(state.status?.provider_supported);
  return `<section class="offline-availability-card"><div class="offline-availability-icon">${svg('download')}</div><div class="offline-availability-copy"><b>Offline files</b><span>${!providerEnabled ? 'Offline file access is unavailable because the Windows drive is not enabled.' : cache.available ? 'Choose files or folders to keep available offline. Raiun stores copies on this computer and must stay running to serve them from the drive.' : 'Offline storage is not available for this account yet.'}</span>${cache.available ? `<small>${esc(formatBytes(cache.used_bytes))} used of ${esc(formatBytes(cache.quota_bytes))} · ${esc(formatBytes(cache.pinned_bytes))} pinned</small>` : ''}</div><button class="button ${cache.available ? 'primary' : 'subtle'}" data-page="offline">View offline files</button></section>`;
}
function offlineWorkspacePage() {
  const windows = isWindowsAgentStatus(state.status);
  const providerEnabled = providerAvailable(state.status?.provider_supported);
  const connected = state.status?.connected === true;
  const cache = state.status?.offline_cache;
  const selectedSpace = state.spaces.find(space => space.id === state.spaceId);
  const details = windows
    ? `${windowsDeviceCacheCard()}${windowsOfflineFilesCard()}${windowsOfflineFoldersCard()}`
    : !providerEnabled
      ? `<div class="notice-card offline"><div class="notice-icon">${svg('alert')}</div><div class="notice-copy"><b>Offline file access is unavailable</b><p>This agent does not provide the cloud drive needed for offline copies.</p></div></div>`
      : !connected || !state.pickerOpen || state.pickerPurpose !== 'offline'
        ? `<section class="settings-card"><div class="settings-heading"><span class="settings-icon">${svg('download')}</span><div><h2>Device storage</h2><p>Offline copies use space on this computer. Raiun must stay running to provide them from the mounted drive.</p></div></div>${cache ? `<div class="offline-cache-usage">${esc(formatBytes(cache.used_bytes))} used of ${esc(formatBytes(cache.quota_bytes))} · ${esc(formatBytes(cache.pinned_bytes))} pinned${cache.over_quota ? ' · over the current storage limit' : ''}</div>` : '<p class="recovery-hint">Storage usage is not available for this account.</p>'}<p class="recovery-hint">Connect this account to check saved folders and change offline availability.</p></section>`
        : `<section class="settings-card offline-workspace-browser">${offlinePickerBody(selectedSpace)}</section>`;
  return `<div class="page-title-row"><div><div class="eyebrow">ON THIS DEVICE</div><h1>Offline files</h1><p class="lede">Review device storage and choose the cloud files kept available here.</p></div></div><div class="settings-stack">${details}</div>`;
}
function encryptedAccessCard() {
  const providerEnabled = featureAvailable('vaults_supported');
  return `<section class="encrypted-access-card"><div class="encrypted-access-icon">${svg('lock')}</div><div class="encrypted-access-copy"><b>Encrypted files</b><span>${providerEnabled ? nativeVaultAccess() ? 'Unlock an encrypted Space or folder through the Windows drive. Supported existing-file saves are shown after unlock.' : 'Unlock an encrypted Space or folder to browse it. This does not add a sync folder.' : 'Encrypted browsing is unavailable for this agent.'}</span></div><button class="button primary" data-page="encrypted" ${providerEnabled && state.agentReachable ? '' : 'disabled'}>View encrypted files</button></section>`;
}
function foldersPage() {
  const connected = state.status?.connected === true;
  const providerEnabled = featureAvailable('folder_sync_supported');
  const connection = connectionMode(state.agentReachable, state.status);
  const groups = folderPairGroups();
  return `<div class="page-title-row"><div><div class="eyebrow">STAY IN SYNC</div><h1>Synced Folders</h1><p class="lede">Choose folders on this computer and where they belong in OpenCloud.</p></div><button class="button primary" data-action="add-pair" ${connected && providerEnabled ? '' : 'disabled'}>${svg('plus')} Add sync folder</button></div>
    ${connection === 'unavailable' ? `<div class="notice-card offline"><div class="notice-icon">${svg('alert')}</div><div class="notice-copy"><b>Connect to the Raiun agent first</b><p>Folder pairs are managed by the background agent. Start it, then refresh this page.</p></div><button class="button subtle" data-action="refresh">Refresh</button></div>` : connection === 'offline_reconnecting' ? `<div class="notice-card offline"><div class="notice-icon">${svg('cloud')}</div><div class="notice-copy"><b>${state.status?.refreshing ? 'Checking connection…' : 'Working offline — reconnecting to server'}</b><p>Your existing offline session remains available. Sync settings will refresh when the server connection returns.</p>${connectionFailureDetails(state.status)}</div><button class="button subtle" data-action="refresh" ${state.status?.refreshing ? 'disabled' : ''}>${state.status?.refreshing ? 'Checking…' : 'Retry connection'}</button></div>${groups.length ? `<div class="space-sync-list">${groups.map(group => spacePairGroup(group.spaceId, group.pairs)).join('')}</div>` : ''}` : connection === 'sign_in' ? `<div class="notice-card"><div class="notice-icon">${svg('cloud')}</div><div class="notice-copy"><b>Cloud sync is offline</b><p>Sign in to sync files. You can still review or change which paths are excluded; existing local and cloud files stay in place.</p></div><button class="button primary" data-action="sign-in">Sign in</button></div>${groups.length ? `<div class="space-sync-list">${groups.map(group => spacePairGroup(group.spaceId, group.pairs)).join('')}</div>` : ''}` : groups.length ? `<div class="space-sync-list">${groups.map(group => spacePairGroup(group.spaceId, group.pairs)).join('')}</div>` : emptyFolders()}`;
}
function folderPairGroups(): Array<{ spaceId: string; pairs: Pair[] }> {
  const grouped = new Map<string, Pair[]>();
  for (const pair of state.pairs) {
    const pairs = grouped.get(pair.space_id) || [];
    pairs.push(pair);
    grouped.set(pair.space_id, pairs);
  }
  const orderedSpaceIds = [
    ...state.spaces.filter(space => space.personal && grouped.has(space.id)).map(space => space.id),
    ...state.spaces.filter(space => !space.personal && grouped.has(space.id)).map(space => space.id),
    ...[...grouped.keys()].filter(id => !state.spaces.some(space => space.id === id))
  ];
  return orderedSpaceIds.map(spaceId => ({ spaceId, pairs: grouped.get(spaceId) || [] }));
}
function spacePairGroup(spaceId: string, pairs: Pair[]) {
  const paused = state.status?.paused_space_ids?.includes(spaceId) === true;
  const globalPaused = state.status?.paused === true;
  const busy = state.spaceActionBusy[spaceId];
  const controlsUnavailable = !state.agentReachable || !featureAvailable('folder_sync_supported') || state.status?.connected !== true || state.mutationBusy > 0 || Boolean(busy);
  const syncUnavailable = controlsUnavailable || globalPaused || paused;
  const title = spaceName(spaceId);
  const pauseLabel = busy === 'pause' ? 'Updating…' : paused ? 'Resume folder sync' : 'Pause folder sync';
  const syncLabel = busy === 'sync' ? 'Queueing…' : 'Sync now';
  const syncStateLabel = state.status?.connected !== true ? 'Cloud sync offline' : globalPaused ? 'All folder sync paused' : paused ? 'Folder sync paused' : 'Folder sync enabled';
  const syncReason = !state.agentReachable || state.status?.connected !== true
    ? 'Sign in and connect the agent to sync this Space.'
    : globalPaused
      ? 'Resume global sync before queueing this Space.'
      : paused
        ? 'Resume folder sync for this Space before queueing it.'
        : 'Queue an immediate sync for this Space.';
  return `<section class="space-sync-group" aria-labelledby="space-sync-${esc(spaceId)}"><header class="space-sync-header"><div class="space-sync-title"><span class="space-sync-icon">${svg('cloud')}</span><div><div class="eyebrow">FOLDER SYNC</div><h2 id="space-sync-${esc(spaceId)}">${esc(title)}</h2><span class="space-sync-state ${paused || globalPaused ? 'paused' : ''}">${syncStateLabel}</span></div></div><div class="space-sync-controls"><button class="button subtle" data-action="space-toggle" data-space-id="${esc(spaceId)}" aria-label="${paused ? 'Resume' : 'Pause'} folder sync for ${esc(title)}" title="Pause or resume automatic folder sync for ${esc(title)}" ${controlsUnavailable || !featureAvailable('pause_supported') ? 'disabled' : ''}>${pauseLabel}</button><button class="button primary" data-action="space-sync-now" data-space-id="${esc(spaceId)}" aria-label="Sync ${esc(title)} now" title="${esc(syncReason)}" ${syncUnavailable ? 'disabled' : ''}>${syncLabel}</button><button class="button subtle danger-hover" data-action="space-disconnect" data-space-id="${esc(spaceId)}" aria-label="Disconnect folder sync for ${esc(title)}" title="Remove this Space’s folder-sync connections. Local and cloud files stay in place." ${controlsUnavailable || !pairs.length ? 'disabled' : ''}>${busy === 'disconnect' ? 'Disconnecting…' : 'Disconnect folder sync'}</button></div></header><p class="space-sync-note">Pausing waits for an active folder sync to finish. Mounted drive browsing and writes are unaffected.</p><div class="pair-list page-pair-list">${pairs.map(folderPairCard).join('')}</div></section>`;
}
function folderPairCard(pair: Pair) {
  const panel = state.conflicts[pair.id];
  return `<div class="pair-entry">${pairCard(pair, true)}${panel?.opened ? conflictPanel(pair, panel) : ''}</div>`;
}
function pairCard(pair: Pair, includeReview = false) {
  const title = spaceName(pair.space_id);
  const providerEnabled = featureAvailable('folder_sync_supported');
  const mode = pair.mode === 'two_way' ? 'Two-way' : pair.mode === 'upload_only' ? 'Upload only' : 'Download only';
  const review = includeReview ? `<button class="small-action quiet" data-review-pair="${esc(pair.id)}" ${providerEnabled && state.status?.connected === true ? '' : 'disabled'}>${state.conflicts[pair.id]?.opened ? 'Hide conflicts' : 'Review conflicts'}</button>` : '';
  const vaultAction = pair.vault ? `<button class="small-action quiet vault-manage" data-vault-pair="${esc(pair.id)}">${svg('lock')} Encryption</button>` : '';
  const count = pair.excluded_paths?.length || 0;
  const exclusionButton = `<button class="small-action quiet" data-toggle-exclusions="${esc(pair.id)}" aria-expanded="${pairExclusionsUi.open.has(pair.id)}" ${!providerEnabled || !state.agentReachable || state.mutationBusy > 0 ? 'disabled' : ''}>${pairExclusionsUi.open.has(pair.id) ? 'Hide exclusions' : `Excluded paths${count ? ` (${count})` : ''}`}</button>`;
  const disabled = !providerEnabled || !state.agentReachable || state.mutationBusy > 0 || pairExclusionsUi.busy.has(pair.id);
  return `<article class="pair-card"><div class="pair-folder-icon">${svg(pair.vault ? 'lock' : 'folder')}</div><div class="pair-main"><div class="pair-title"><b>${esc(lastPath(pair.local_path))}</b><span class="mode-pill">${mode}</span>${pair.vault ? '<span class="vault-pill">Encrypted</span>' : ''}</div><div class="pair-route"><span class="path-text">${esc(pair.local_path)}</span><span class="route-arrow">${svg('chevron')}</span><span class="remote-label">${svg(pair.vault ? 'lock' : 'cloud')} ${esc(title)}${pair.vault ? ` · ${esc(pair.vault.root_path)}${pair.remote_path === '/' ? '' : esc(pair.remote_path)}` : esc(pair.remote_path)}</span></div></div><div class="pair-actions">${exclusionButton}${providerEnabled ? vaultAction : ''}${review}<button class="icon-button danger-hover" data-remove-pair="${esc(pair.id)}" title="Remove folder pair" aria-label="Remove ${esc(pair.local_path)}" ${disabled ? 'disabled' : ''}>${svg('dots')}</button></div>${pairExclusionsUi.open.has(pair.id) ? pairExclusionsPanel(pair, disabled) : ''}</article>`;
}
function pairExclusionsPanel(pair: Pair, disabled: boolean) {
  const paths = pair.excluded_paths || [];
  const error = pairExclusionsUi.errors.get(pair.id) || '';
  const draft = pairExclusionsUi.drafts.get(pair.id) || '';
  const rows = paths.length ? `<ul class="exclusion-path-list">${paths.map((path, index) => `<li><code>${esc(path)}</code><button class="small-action quiet" data-remove-exclusion="${esc(pair.id)}" data-exclusion-index="${index}" ${disabled ? 'disabled' : ''}>Resume</button></li>`).join('')}</ul>` : '<p class="exclusion-empty">Nothing is excluded from this folder.</p>';
  return `<section class="pair-exclusions" aria-label="Excluded paths for ${esc(pair.local_path)}"><div><b>Paths that stay out of sync</b><p>Enter a path relative to this local folder. A directory also excludes everything inside it. Excluding a path keeps both copies and does not free disk space.</p></div>${error ? `<div class="exclusion-error" role="alert">${esc(error)}</div>` : ''}${rows}<div class="exclusion-add"><label><span class="sr-only">Path relative to ${esc(lastPath(pair.local_path))}</span><input data-exclusion-input="${esc(pair.id)}" value="${esc(draft)}" placeholder="e.g. Archive or Drafts/notes.txt" maxlength="4096" ${disabled ? 'disabled' : ''}/></label><button class="button subtle" data-add-exclusion="${esc(pair.id)}" ${disabled || !draft.trim() ? 'disabled' : ''}>Stop syncing path</button></div></section>`;
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
function emptyFolders() {
  if (!featureAvailable('folder_sync_supported')) return `<div class="notice-card offline"><div class="notice-icon">${svg('alert')}</div><div class="notice-copy"><b>Windows folder sync is unavailable</b><p>The account is connected, but this Windows agent cannot load or run folder sync yet. No folder list or transfer state is available.</p></div></div>`;
  return `<div class="empty-card"><span class="empty-icon">${svg('folders')}</span><h3>No sync folders yet</h3><p>Add an existing folder and choose its place in OpenCloud. The folder stays on your computer.</p><button class="button primary" data-action="add-pair" ${state.status?.connected ? '' : 'disabled'}>${svg('plus')} Add your first folder</button></div>`;
}
function pendingOfflineWritesSection() {
  const loadedForAccount = pendingWritesUi.accountEpoch === state.accountEpoch;
  const groups = groupPendingWritesByScope(pendingWritesUi.items);
  const rootsBySpace = new Map<string, Set<string | null>>();
  for (const item of pendingWritesUi.items) {
    const roots = rootsBySpace.get(item.space_id) || new Set<string | null>();
    roots.add(pendingWriteRootId(item));
    rootsBySpace.set(item.space_id, roots);
  }
  const renderedRetrySpaces = new Set<string>();
  const rows = [...groups.entries()].map(([scopeKey, items], rowIndex) => {
    const spaceId = items[0].space_id;
    const rootResourceId = pendingWriteRootId(items[0]);
    const rootExpanded = pendingWritesUi.expandedScopes.has(scopeKey);
    const rootRegionId = `pending-write-root-region-${rowIndex}`;
    const label = items.find(item => item.space_label?.trim())?.space_label?.trim() || state.spaces.find(space => space.id === spaceId)?.name || 'OpenCloud Space';
    const pending = items.filter(item => item.state === 'pending').length;
    const conflicts = items.filter(item => item.state === 'conflict').length;
    const globallyPaused = state.status?.paused === true;
    const spacePaused = state.status?.paused_space_ids?.includes(spaceId) === true;
    const pauseReason = globallyPaused ? 'Sync is paused. Resume it to retry uploads.' : spacePaused ? 'Folder sync is paused for this Space. Resume it to retry uploads.' : '';
    const retryDisabled = !state.status?.connected || pendingWritesUi.retryingSpaces.has(spaceId) || !!pauseReason;
    const showRetry = pending > 0 && !renderedRetrySpaces.has(spaceId);
    if (showRetry) renderedRetrySpaces.add(spaceId);
    const retryScope = (rootsBySpace.get(spaceId)?.size ?? 0) > 1
      ? 'Retries pending edits across all saved roots in this Space.'
      : 'Retries pending edits in this Space.';
    return `<section class="pending-write-space"><div class="pending-write-heading"><div><b>${esc(label)}</b>${savedRootDisclosure(rootResourceId, scopeKey, rootRegionId, rootExpanded, esc)}<small>${pending ? `${pending} waiting to upload` : ''}${pending && conflicts ? ' · ' : ''}${conflicts ? `${conflicts} need review` : ''}${pending && !state.status?.connected ? ' · Sign in to retry uploads' : ''}${pending && pauseReason ? ` · ${pauseReason}` : ''}</small></div>${showRetry ? `<button class="button subtle" data-action="retry-pending-writes" data-space-id="${esc(spaceId)}" title="${pauseReason || retryScope}" ${retryDisabled ? 'disabled' : ''}>${pendingWritesUi.retryingSpaces.has(spaceId) ? 'Retrying…' : 'Retry uploads for this Space'}</button>` : ''}</div><div class="pending-write-list">${items.map(item => {
      const exportKey = pendingWriteExportKey(item.space_id, item.write_id);
      const exporting = pendingWritesUi.exportingWrites.has(exportKey);
      const exportButton = pendingWritesUi.authGeneration != null && pendingWritesUi.accountScope && item.root_resource_id && ['pending', 'conflict'].includes(item.state) ? `<button class="small-action pending-write-save" data-action="save-pending-write-copy" data-space-id="${esc(item.space_id)}" data-write-id="${esc(item.write_id)}" data-root-resource-id="${esc(item.root_resource_id || '')}" aria-label="Save a local copy of ${esc(lastPath(item.path))}" title="Save a copy on this PC. The saved edit stays in this list; this action does not upload it." ${exporting || state.nativeDialogBusy || state.accountSwitching ? 'disabled' : ''}>${exporting ? 'Saving…' : 'Save local copy'}</button>` : '';
      return `<article class="pending-write-row"><span class="pending-write-mark ${item.state === 'conflict' ? 'conflict' : ''}">${svg(item.state === 'conflict' ? 'alert' : 'arrowUp')}</span><div class="pending-write-copy"><b>${esc(lastPath(item.path))}</b><small>${esc(item.path)}</small></div><span class="pending-write-state ${item.state}">${item.state === 'conflict' ? 'Needs review' : 'Waiting to upload'}</span><small class="pending-write-bytes">${formatBytes(item.bytes)}</small>${exportButton}</article>`;
    }).join('')}</div></section>`;
  }).join('');
  const total = pendingWritesUi.pendingCount + pendingWritesUi.conflictCount;
  const summary = loadedForAccount ? `<small class="pending-writes-count">${pendingWritesUi.pendingCount} waiting to upload · ${pendingWritesUi.conflictCount} need review</small>` : '';
  return `<section class="pending-writes-card"><div class="pending-writes-heading"><div><h2>Offline edits</h2>${summary}<p>These are retained local edit records. Their status does not confirm a cloud change. Retry uploads checks the cloud version first; changed versions stay for review. Save local copy exports a separate file and leaves the saved edit here.</p></div><button class="button subtle" data-action="refresh-pending-writes" ${pendingWritesUi.loading ? 'disabled' : ''}>${pendingWritesUi.loading ? 'Checking…' : loadedForAccount ? 'Refresh list' : 'Check saved edits'}</button></div>${pendingWritesUi.error ? `<div class="pending-writes-error" role="alert">${esc(pendingWritesUi.error)}</div>` : ''}${pendingWritesUi.loading && !pendingWritesUi.items.length ? `<div class="pending-writes-empty" role="status"><span class="spinner"></span> Checking saved edits…</div>` : !loadedForAccount ? `<div class="pending-writes-empty">Check for local edits waiting to upload.</div>` : total === 0 && !pendingWritesUi.truncated ? `<div class="pending-writes-empty" role="status">No saved edits are waiting to upload or review.</div>` : `${pendingWritesUi.truncated ? '<div class="pending-writes-warning" role="status">The list is limited; load more to see additional saved edits.</div>' : ''}${rows || '<div class="pending-writes-empty">No items on this page.</div>'}${pendingWritesUi.nextAfter ? `<div class="pending-writes-more"><button class="button subtle" data-action="more-pending-writes" ${pendingWritesUi.loading ? 'disabled' : ''}>${pendingWritesUi.loading ? 'Loading…' : 'Load more'}</button></div>` : ''}`}</section>`;
}
function transfersPage() {
  const providerEnabled = featureAvailable('folder_sync_supported');
  const connection = connectionMode(state.agentReachable, state.status);
  const filters = [['active', 'Current & paused'], ['attention', 'Needs attention'], ['history', 'Finished']] as const;
  const matching = state.transfers.filter(item => {
    const status = (item.state || '').toLowerCase();
    if (state.transferFilter === 'active') return ['queued', 'running', 'retry_wait', 'verifying', 'paused'].includes(status);
    if (state.transferFilter === 'attention') return ['failed', 'conflict', 'awaiting_authentication'].includes(status);
    return ['completed', 'cancelled'].includes(status);
  });
  return `<div class="page-title-row"><div><div class="eyebrow">ACTIVITY</div><h1>Transfers</h1><p class="lede">Follow folder-sync activity and review offline files or saved edits for this account.</p></div></div>
    <div class="filter-tabs" role="tablist">${filters.map(([key,label]) => `<button class="filter-tab ${state.transferFilter === key ? 'active' : ''}" data-filter="${key}">${label}${key === 'attention' && attentionCount() ? `<span class="tab-badge">${attentionCount()}</span>` : ''}</button>`).join('')}</div>
    <p class="helper-note">${state.transferFilter === 'active' ? 'Current & paused: queued, transferring, retrying, checking, and paused folder-sync transfers.' : state.transferFilter === 'attention' ? 'Needs attention: failed transfers, conflicts, and transfers waiting for sign-in.' : 'Finished: completed and cancelled folder-sync transfers.'} These tabs filter folder-sync activity only; offline files and saved edits stay visible below.</p>
    ${!isWindowsAgentStatus(state.status) && state.agentReachable ? pendingOfflineWritesSection() : ''}
    ${vaultAppFeaturesAvailable() && state.agentReachable ? encryptedOperationsTransferSection() : ''}
    ${vaultAppFeaturesAvailable() && state.agentReachable ? encryptedRetryLatestSection() : ''}
    ${vaultAppFeaturesAvailable() && state.agentReachable ? encryptedEditsTransferSection() : ''}
    ${!providerEnabled ? `<div class="notice-card offline"><div class="notice-icon">${svg('alert')}</div><div class="notice-copy"><b>Transfer status is unavailable</b><p>Folder-sync transfer reporting is unavailable for this agent. Supported cloud-drive offline controls remain available above.</p></div></div>` : state.agentReachable && state.status?.connected ? matching.length ? `<div class="transfer-list">${matching.map(transferCard).join('')}</div>` : `<div class="empty-card transfer-empty"><span class="empty-icon">${svg(state.transferFilter === 'attention' ? 'check' : 'transfers')}</span><h3>${state.transferFilter === 'attention' ? 'No folder-sync transfers need attention' : state.transferFilter === 'history' ? 'No finished folder-sync transfers yet' : 'No current or paused folder-sync transfers'}</h3><p>${state.transferFilter === 'active' ? 'Queued and running transfers appear here, along with retries, checks, and paused transfers.' : state.transferFilter === 'attention' ? 'No failed transfers, conflicts, or sign-in requests have been reported in this list. Saved edits are shown separately above.' : 'Completed and cancelled transfers appear here with their final status.'}</p></div>` : connection === 'unavailable' ? `<div class="notice-card offline"><div class="notice-icon">${svg('alert')}</div><div class="notice-copy"><b>Transfer status is unavailable</b><p>Start the Raiun agent to see transfer activity.</p></div><button class="button subtle" data-action="refresh">Refresh</button></div>` : connection === 'offline_reconnecting' ? `<div class="notice-card offline"><div class="notice-icon">${svg('cloud')}</div><div class="notice-copy"><b>${state.status?.refreshing ? 'Checking connection…' : 'Working offline — reconnecting to server'}</b><p>Transfer history will refresh when Raiun reconnects.</p>${connectionFailureDetails(state.status)}</div><button class="button subtle" data-action="refresh" ${state.status?.refreshing ? 'disabled' : ''}>${state.status?.refreshing ? 'Checking…' : 'Retry connection'}</button></div>` : `<div class="notice-card"><div class="notice-icon">${svg('cloud')}</div><div class="notice-copy"><b>Sign in to see transfer activity</b><p>Connect your OpenCloud account to load transfer status.</p></div><button class="button primary" data-action="sign-in">Sign in</button></div>`}`;
}
function validateVaultEditLatest(value: unknown, spaceId: string, rootResourceId: string): VaultEditLatestResult {
  if (!value || typeof value !== 'object') throw new Error('The agent returned an invalid encrypted retry status.');
  const result = value as Partial<VaultEditLatestResult>;
  if (typeof result.available !== 'boolean') throw new Error('The agent returned an invalid encrypted retry status.');
  if (!result.available) {
    if (result.status != null) throw new Error('The agent returned an invalid encrypted retry status.');
    return { available: false, status: null };
  }
  const status = result.status;
  if (!status || status.space_id !== spaceId || status.root_resource_id !== rootResourceId ||
      typeof status.job_id !== 'string' || !status.job_id || status.job_id.length > 256 ||
      (status.automatic !== true && status.automatic !== false) || !['queued', 'running', 'complete', 'failed', 'cancelled'].includes(status.state) ||
      ![status.processed, status.uploaded, status.conflicts, status.remaining].every(count => Number.isSafeInteger(count) && count >= 0) ||
      typeof status.cancel_requested !== 'boolean' || !(status.error == null || (typeof status.error === 'string' && status.error.length <= 512)) ||
      !(status.failure_class == null || isVaultFailureClass(status.failure_class))) {
    throw new Error('The agent returned an incomplete or mismatched encrypted retry status.');
  }
  return { available: true, status: status as VaultEditReconcileStatus };
}
function validateUnlockedVaultRoots(value: unknown): { roots: { spaceId: string; rootResourceId: string }[]; truncated: boolean } {
  if (!value || typeof value !== 'object') throw new Error('Active encrypted locations could not be checked.');
  const page = value as { roots?: unknown; truncated?: unknown };
  if (!Array.isArray(page.roots) || page.roots.length > 100 || typeof page.truncated !== 'boolean') throw new Error('Active encrypted locations could not be checked.');
  const roots = new Map<string, { spaceId: string; rootResourceId: string }>();
  for (const value of page.roots) {
    if (!value || typeof value !== 'object') throw new Error('Active encrypted locations could not be checked.');
    const root = value as { space_id?: unknown; root_resource_id?: unknown };
    if (typeof root.space_id !== 'string' || !root.space_id || root.space_id.length > 512 || /[\u0000-\u001f\u007f]/.test(root.space_id) ||
        typeof root.root_resource_id !== 'string' || !root.root_resource_id || root.root_resource_id.length > 512 || /[\u0000-\u001f\u007f]/.test(root.root_resource_id)) {
      throw new Error('Active encrypted locations could not be checked.');
    }
    roots.set(`${root.space_id}\u0000${root.root_resource_id}`, { spaceId: root.space_id, rootResourceId: root.root_resource_id });
  }
  return { roots: [...roots.values()], truncated: page.truncated };
}
function validateVaultOperations(value: unknown, spaceId: string, rootResourceId: string): VaultOperationsPage {
  if (!value || typeof value !== 'object') throw new Error('Saved encrypted operations could not be checked.');
  const page = value as Partial<VaultOperationsPage>;
  if (page.space_id !== spaceId || page.root_resource_id !== rootResourceId || !Number.isSafeInteger(page.auth_generation) || Number(page.auth_generation) < 0 ||
      !Array.isArray(page.items) || page.items.length > 100 || typeof page.truncated !== 'boolean' || !(page.next_after == null || (typeof page.next_after === 'string' && /^[0-9a-fA-F]{32}$/.test(page.next_after)))) {
    throw new Error('Saved encrypted operations could not be checked.');
  }
  const allowedOperations = new Set(['overwrite', 'create_file', 'rename_file', 'delete_file', 'create_directory', 'copy_file']);
  const allowedStates = new Set(['building', 'queued', 'pending', 'uncertain', 'conflict']);
  const allowedRetryStates = new Set(['attempting', 'recovery_attempting', 'recovery_retrying']);
  const items = page.items.map((item: VaultOperation) => {
    if (!item || typeof item !== 'object' || typeof item.write_id !== 'string' || !/^[0-9a-fA-F]{32}$/.test(item.write_id) ||
        !Number.isSafeInteger(item.revision) || item.revision < 0 || !Number.isSafeInteger(item.retry_generation) || item.retry_generation < 0 || !allowedOperations.has(item.operation) || !allowedStates.has(item.state) ||
        typeof item.needs_attention !== 'boolean' ||
        !(item.attention_reason == null || item.attention_reason === 'directory_create_attempt_interrupted' || item.attention_reason === 'file_create_attempt_interrupted' || item.attention_reason === 'file_create_recovery_interrupted' || item.attention_reason === 'copy_file_requires_review') ||
        item.needs_attention !== (item.attention_reason != null) ||
        (item.attention_reason === 'directory_create_attempt_interrupted' && (item.operation !== 'create_directory' || item.state !== 'uncertain')) ||
        ((item.attention_reason === 'file_create_attempt_interrupted' || item.attention_reason === 'file_create_recovery_interrupted') && (item.operation !== 'create_file' || item.state !== 'uncertain')) ||
        (item.attention_reason === 'copy_file_requires_review' && item.operation !== 'copy_file') ||
        !isReviewOnlyCopyOperation(item) ||
        !(item.retry_state == null || allowedRetryStates.has(item.retry_state)) ||
        !(item.can_retry_interrupted_create == null || typeof item.can_retry_interrupted_create === 'boolean') ||
        (item.can_retry_interrupted_create === true && (item.operation !== 'create_file' || item.state !== 'uncertain' || !allowedRetryStates.has(item.retry_state || ''))) ||
        (item.retry_state != null && (item.operation !== 'create_file' || item.state !== 'uncertain')) ||
        typeof item.path !== 'string' || !item.path.startsWith('/') || item.path.length > 4096 || /[\u0000-\u001f\u007f]/.test(item.path) ||
        !Number.isSafeInteger(item.bytes) || item.bytes < 0 ||
        !(item.destination_path == null || (typeof item.destination_path === 'string' && item.destination_path.startsWith('/') && item.destination_path.length <= 4096 && !/[\u0000-\u001f\u007f]/.test(item.destination_path))) ||
        (item.operation === 'rename_file' && typeof item.destination_path !== 'string') || (item.operation !== 'rename_file' && item.destination_path != null)) {
      throw new Error('Saved encrypted operations could not be checked.');
    }
    return item;
  });
  return { space_id: spaceId, root_resource_id: rootResourceId, auth_generation: page.auth_generation as number, items, next_after: page.next_after ?? null, truncated: page.truncated };
}
function clearVaultOperations() {
  vaultOperationsUi.generation++;
  vaultOperationsUi.loading = false;
  vaultOperationsUi.lastLoadedAt = 0;
  vaultOperationsUi.accountEpoch = state.accountEpoch;
  vaultOperationsUi.rootsTruncated = false;
  vaultOperationsUi.scopes.clear();
  clearInterruptedCreateRetryUi();
  clearCopyVerifyUi();
}
function forgetVaultOperationsScope(spaceId: string, rootResourceId: string) {
  vaultOperationsUi.scopes.delete(`${spaceId}\u0000${rootResourceId}`);
  clearCopyVerifyScope(spaceId, rootResourceId);
  if (interruptedCreateRetryUi.job?.spaceId === spaceId && interruptedCreateRetryUi.job.rootResourceId === rootResourceId) clearInterruptedCreateRetryUi();
  vaultOperationsUi.lastLoadedAt = 0;
}
function clearInterruptedCreateRetryUi() {
  interruptedCreateRetryUi.generation++;
  if (interruptedCreateRetryUi.timer) window.clearTimeout(interruptedCreateRetryUi.timer);
  interruptedCreateRetryUi.timer = 0;
  interruptedCreateRetryUi.job = null;
}
function clearCopyVerifyJob(job: CopyVerifyJobUi) {
  if (job.timer) window.clearTimeout(job.timer);
  job.timer = 0;
  copyVerifyUi.active.delete(job.key);
  if (copyVerifyUi.jobs.get(job.key) === job) copyVerifyUi.jobs.delete(job.key);
}
function clearCopyVerifyScope(spaceId: string, rootResourceId: string) {
  for (const job of copyVerifyUi.jobs.values()) {
    if (job.binding.spaceId === spaceId && job.binding.rootResourceId === rootResourceId) clearCopyVerifyJob(job);
  }
}
function clearCopyVerifyUi() {
  copyVerifyUi.generation++;
  for (const job of copyVerifyUi.jobs.values()) if (job.timer) window.clearTimeout(job.timer);
  copyVerifyUi.jobs.clear();
  copyVerifyUi.active.clear();
}
function copyVerifyBindingCurrent(job: CopyVerifyJobUi) {
  if (nativeVaultAccess()) return false;
  if (copyVerifyUi.jobs.get(job.key) !== job || state.page !== 'transfers' || state.accountSwitching ||
      !isCurrentAccount(job.binding.accountEpoch, job.binding.profileId)) return false;
  const scope = vaultOperationsUi.scopes.get(`${job.binding.spaceId}\u0000${job.binding.rootResourceId}`);
  if (!scope || scope.accountEpoch !== job.binding.accountEpoch || scope.authGeneration !== job.binding.authGeneration) return false;
  const currentBinding: CopyVerifyBinding = {
    profileId: state.selectedAccount, accountEpoch: scope.accountEpoch, spaceId: scope.spaceId,
    rootResourceId: scope.rootResourceId, writeId: job.binding.writeId,
    revision: job.binding.revision, authGeneration: scope.authGeneration
  };
  if (!copyVerifyContextMatches(job.binding, currentBinding)) return false;
  if (scope.loading) return true;
  return scope.items.some(item => item.operation === 'copy_file' && item.needs_attention &&
    item.write_id === job.binding.writeId && item.revision === job.binding.revision);
}
function scheduleCopyVerifyPoll(job: CopyVerifyJobUi, delay = 900) {
  if (nativeVaultAccess()) { if (job.timer) window.clearTimeout(job.timer); job.timer = 0; return; }
  if (job.timer) window.clearTimeout(job.timer);
  if (!copyVerifyBindingCurrent(job) || !job.jobId) return;
  job.timer = window.setTimeout(() => { job.timer = 0; void pollCopyVerification(job); }, delay);
}
function copyVerifyActive(job: CopyVerifyJobUi | undefined) {
  return !!job && (job.busy || job.cancelBusy || job.status?.state === 'queued' || job.status?.state === 'running');
}
function discardMissingCopyVerifyJobs(scope: VaultOperationsScope) {
  for (const job of copyVerifyUi.jobs.values()) {
    if (job.binding.spaceId !== scope.spaceId || job.binding.rootResourceId !== scope.rootResourceId) continue;
    if (job.binding.authGeneration !== scope.authGeneration || !scope.items.some(item =>
      item.operation === 'copy_file' && item.needs_attention && item.write_id === job.binding.writeId && item.revision === job.binding.revision)) {
      clearCopyVerifyJob(job);
    }
  }
}
function interruptedCreateRetryMatches(scope: VaultOperationsScope, item: VaultOperation) {
  const job = interruptedCreateRetryUi.job;
  return !!job && job.key === scope.key && job.writeId === item.write_id && job.revision === item.revision && job.retryState === item.retry_state && job.accountEpoch === state.accountEpoch && job.profileId === state.selectedAccount;
}
async function refreshVaultOperations(activeRoots: { spaceId: string; rootResourceId: string }[], force = false, truncated = false) {
  if (nativeVaultAccess()) return;
  if (state.page !== 'transfers' || !state.agentReachable || state.accountSwitching || vaultOperationsUi.loading) return;
  const now = Date.now();
  if (!force && now - vaultOperationsUi.lastLoadedAt < 15000) return;
  const epoch = state.accountEpoch;
  const profileId = state.selectedAccount;
  const generation = ++vaultOperationsUi.generation;
  vaultOperationsUi.loading = true;
  vaultOperationsUi.accountEpoch = epoch;
  vaultOperationsUi.rootsTruncated = truncated || activeRoots.length > 100;
  const currentKeys = new Set(activeRoots.map(scope => `${scope.spaceId}\u0000${scope.rootResourceId}`));
  for (const key of vaultOperationsUi.scopes.keys()) if (!currentKeys.has(key)) vaultOperationsUi.scopes.delete(key);
  const scopes = activeRoots.slice(0, 100).map(scope => {
    const key = `${scope.spaceId}\u0000${scope.rootResourceId}`;
    const existing = vaultOperationsUi.scopes.get(key);
    const model: VaultOperationsScope = existing || { key, ...scope, authGeneration: -1, items: [], nextAfter: null, truncated: false, loading: false, error: '', accountEpoch: epoch };
    // Decoded names are only retained for an exact currently-unlocked scope.
    model.items = [];
    model.nextAfter = null;
    model.truncated = false;
    model.loading = true;
    model.error = '';
    model.accountEpoch = epoch;
    vaultOperationsUi.scopes.set(key, model);
    return model;
  });
  render();
  for (const scope of scopes) {
    try {
      const page = validateVaultOperations(await request<VaultOperationsPage>('vault_operations', {
        space_id: scope.spaceId, root_resource_id: scope.rootResourceId, limit: 50
      }), scope.spaceId, scope.rootResourceId);
      if (!isCurrentAccount(epoch, profileId) || vaultOperationsUi.generation !== generation || state.page !== 'transfers') return;
      if (scope.authGeneration >= 0 && scope.authGeneration !== page.auth_generation) clearCopyVerifyScope(scope.spaceId, scope.rootResourceId);
      scope.authGeneration = page.auth_generation;
      scope.items = page.items;
      scope.nextAfter = page.next_after;
      scope.truncated = page.truncated;
      discardMissingCopyVerifyJobs(scope);
    } catch (error) {
      if (!isCurrentAccount(epoch, profileId) || vaultOperationsUi.generation !== generation || state.page !== 'transfers' || isStaleAccountRequest(error)) return;
      // The agent may have locked this route while the query was in flight. Drop any decoded names.
      scope.items = [];
      scope.nextAfter = null;
      scope.truncated = false;
      scope.error = messageOf(error) || 'Saved encrypted operations could not be checked.';
    } finally {
      if (vaultOperationsUi.generation === generation) scope.loading = false;
    }
  }
  if (!isCurrentAccount(epoch, profileId) || vaultOperationsUi.generation !== generation) return;
  vaultOperationsUi.loading = false;
  vaultOperationsUi.lastLoadedAt = Date.now();
  render();
}
async function loadMoreVaultOperations(element: HTMLElement) {
  if (nativeVaultAccess()) return;
  const spaceId = element.dataset.spaceId || '';
  const rootResourceId = element.dataset.rootResourceId || '';
  const scope = vaultOperationsUi.scopes.get(`${spaceId}\u0000${rootResourceId}`);
  if (!scope?.nextAfter || scope.loading || state.page !== 'transfers' || scope.accountEpoch !== state.accountEpoch) return;
  const epoch = state.accountEpoch;
  const profileId = state.selectedAccount;
  const generation = vaultOperationsUi.generation;
  const cursor = scope.nextAfter;
  scope.loading = true;
  scope.error = '';
  render();
  try {
    const page = validateVaultOperations(await request<VaultOperationsPage>('vault_operations', {
      space_id: spaceId, root_resource_id: rootResourceId, after: cursor, limit: 50
    }), spaceId, rootResourceId);
    if (!isCurrentAccount(epoch, profileId) || vaultOperationsUi.generation !== generation || state.page !== 'transfers' || scope.nextAfter !== cursor) return;
    if (page.auth_generation !== scope.authGeneration) {
      scope.items = []; scope.nextAfter = null; scope.truncated = false;
      scope.error = 'The encrypted location changed while loading operations. Refresh the list before reviewing them.';
      clearCopyVerifyScope(spaceId, rootResourceId);
      return;
    }
    scope.items.push(...page.items);
    scope.nextAfter = page.next_after;
    scope.truncated = page.truncated;
  } catch (error) {
    if (isCurrentAccount(epoch, profileId) && vaultOperationsUi.generation === generation && state.page === 'transfers' && !isStaleAccountRequest(error)) scope.error = messageOf(error);
  } finally {
    if (isCurrentAccount(epoch, profileId) && vaultOperationsUi.generation === generation) { scope.loading = false; render(); }
  }
}
function copyVerifyBindingFromElement(element: HTMLElement): CopyVerifyBinding | null {
  const spaceId = element.dataset.spaceId || '';
  const rootResourceId = element.dataset.rootResourceId || '';
  const writeId = element.dataset.writeId || '';
  const revision = Number(element.dataset.revision);
  const authGeneration = Number(element.dataset.authGeneration);
  const profileId = state.selectedAccount;
  const accountEpoch = state.accountEpoch;
  const scope = vaultOperationsUi.scopes.get(`${spaceId}\u0000${rootResourceId}`);
  const item = scope?.items.find(operation => operation.write_id === writeId && operation.revision === revision);
  if (!profileId || !scope || scope.accountEpoch !== accountEpoch || scope.authGeneration !== authGeneration ||
      !Number.isSafeInteger(revision) || revision < 0 || !Number.isSafeInteger(authGeneration) || authGeneration < 0 ||
      !item || item.operation !== 'copy_file' || !item.needs_attention || !isReviewOnlyCopyOperation(item)) return null;
  return { profileId, accountEpoch, spaceId, rootResourceId, writeId, revision, authGeneration };
}
async function verifyCopyOperation(element: HTMLElement) {
  if (nativeVaultAccess()) return;
  const binding = copyVerifyBindingFromElement(element);
  if (!binding || state.page !== 'transfers' || !state.agentReachable || state.accountSwitching) return;
  const key = copyVerifyRowKey(binding);
  if (!claimCopyVerify(binding, copyVerifyUi.active)) return;
  const job: CopyVerifyJobUi = { key, binding, jobId: null, status: null, busy: true, cancelBusy: false, error: '', generation: ++copyVerifyUi.generation, timer: 0 };
  copyVerifyUi.jobs.set(key, job);
  render();
  try {
    const start = validateCopyVerifyStart(await request<unknown>('vault_copy_verify_start', {
      space_id: binding.spaceId, root_resource_id: binding.rootResourceId, write_id: binding.writeId,
      revision: binding.revision, expected_generation: binding.authGeneration
    }));
    if (!copyVerifyBindingCurrent(job)) { clearCopyVerifyJob(job); return; }
    if (!start.accepted) {
      job.error = copyVerifyStartErrorMessage(start.error);
      releaseCopyVerify(binding, copyVerifyUi.active);
      if (start.error === 'stale_generation' || start.error === 'scope_changed') void refreshEncryptedRetryLatestStatuses(true);
      return;
    }
    job.jobId = start.job_id;
    job.status = { job_id: start.job_id, auth_generation: binding.authGeneration, state: 'queued', cancel_requested: false };
    job.busy = false;
    render();
    scheduleCopyVerifyPoll(job, 400);
  } catch {
    if (!copyVerifyBindingCurrent(job)) { clearCopyVerifyJob(job); return; }
    job.error = 'Raiun could not start copy verification. The saved operation remains for review; refresh before trying again.';
    releaseCopyVerify(binding, copyVerifyUi.active);
  } finally {
    if (copyVerifyUi.jobs.get(job.key) === job) { job.busy = false; render(); }
  }
}
async function pollCopyVerification(job: CopyVerifyJobUi) {
  if (nativeVaultAccess()) return;
  if (!job.jobId || !copyVerifyBindingCurrent(job)) { clearCopyVerifyJob(job); return; }
  try {
    const status = validateCopyVerifyStatus(await request<unknown>('vault_copy_verify_status', {
      space_id: job.binding.spaceId, root_resource_id: job.binding.rootResourceId,
      job_id: job.jobId, expected_generation: job.binding.authGeneration
    }), job.jobId, job.binding.authGeneration);
    if (!copyVerifyBindingCurrent(job)) { clearCopyVerifyJob(job); return; }
    job.status = status;
    job.error = '';
    if (status.state === 'queued' || status.state === 'running') {
      render();
      scheduleCopyVerifyPoll(job, 1000);
      return;
    }
    releaseCopyVerify(job.binding, copyVerifyUi.active);
    if (status.state === 'verified') {
      state.message = copyVerifyStatusMessage(status);
      render();
      void refreshEncryptedRetryLatestStatuses(true);
      return;
    }
    render();
  } catch {
    if (!copyVerifyBindingCurrent(job)) { clearCopyVerifyJob(job); return; }
    // Keep the server job ID so the user can explicitly resume status checks,
    // while allowing the row to leave its active state after a transport error.
    job.status = null;
    job.error = 'Raiun could not check copy verification status. The saved operation remains for review; refresh before checking again.';
    releaseCopyVerify(job.binding, copyVerifyUi.active);
    render();
  }
}
async function checkCopyVerificationStatus(job: CopyVerifyJobUi) {
  if (nativeVaultAccess()) return;
  if (!job.jobId || job.busy || !copyVerifyBindingCurrent(job)) return;
  job.busy = true;
  job.error = '';
  render();
  try { await pollCopyVerification(job); }
  finally {
    if (copyVerifyUi.jobs.get(job.key) === job) { job.busy = false; render(); }
  }
}
async function cancelCopyVerification(job: CopyVerifyJobUi) {
  if (nativeVaultAccess()) return;
  if (!job.jobId || job.cancelBusy || (job.status?.state !== 'queued' && job.status?.state !== 'running') ||
      !copyVerifyBindingCurrent(job)) return;
  job.cancelBusy = true;
  render();
  try {
    const status = validateCopyVerifyStatus(await request<unknown>('vault_copy_verify_cancel', {
      space_id: job.binding.spaceId, root_resource_id: job.binding.rootResourceId,
      job_id: job.jobId, expected_generation: job.binding.authGeneration
    }), job.jobId, job.binding.authGeneration);
    if (!copyVerifyBindingCurrent(job)) { clearCopyVerifyJob(job); return; }
    job.status = status;
    job.error = '';
    if (status.state === 'queued' || status.state === 'running') scheduleCopyVerifyPoll(job, 800);
    else releaseCopyVerify(job.binding, copyVerifyUi.active);
  } catch {
    if (copyVerifyBindingCurrent(job)) job.error = 'Raiun could not stop copy verification. Refresh the operation status before taking another action.';
  } finally {
    if (copyVerifyUi.jobs.get(job.key) === job) { job.cancelBusy = false; render(); }
  }
}

function scheduleInterruptedCreateRetryPoll(job: InterruptedCreateRetryUi, delay = 900) {
  if (nativeVaultAccess()) { if (interruptedCreateRetryUi.timer) window.clearTimeout(interruptedCreateRetryUi.timer); interruptedCreateRetryUi.timer = 0; return; }
  if (interruptedCreateRetryUi.timer) window.clearTimeout(interruptedCreateRetryUi.timer);
  if (state.page !== 'transfers' || interruptedCreateRetryUi.job !== job) return;
  interruptedCreateRetryUi.timer = window.setTimeout(() => {
    interruptedCreateRetryUi.timer = 0;
    void pollInterruptedCreateRetry(job);
  }, delay);
}
function interruptedCreateRetryContextCurrent(job: InterruptedCreateRetryUi) {
  if (nativeVaultAccess()) return false;
  if (interruptedCreateRetryUi.job !== job || job.generation !== interruptedCreateRetryUi.generation || state.page !== 'transfers' ||
      !isCurrentAccount(job.accountEpoch, job.profileId)) return false;
  const scope = vaultOperationsUi.scopes.get(job.key);
  if (!scope) return false;
  const exactRow = scope.items.some(item => item.write_id === job.writeId && item.revision === job.revision &&
    item.retry_generation === job.retryGeneration && item.retry_state === job.retryState);
  const claimedRow = scope.items.some(item => item.write_id === job.writeId && item.revision === job.revision &&
    item.retry_generation === job.retryGeneration + 1 && item.operation === 'create_file' && item.state === 'uncertain');
  const exactJob = job.status?.operation === 'create_file' && job.status.write_id === job.writeId &&
    job.status.operation_revision === job.revision && job.status.retry_generation === job.retryGeneration;
  return exactRow || claimedRow || exactJob;
}
async function retryInterruptedFileCreate(element: HTMLElement) {
  if (nativeVaultAccess()) return;
  const spaceId = element.dataset.spaceId || '';
  const rootResourceId = element.dataset.rootResourceId || '';
  const writeId = element.dataset.writeId || '';
  const revision = Number(element.dataset.revision);
  const retryGeneration = Number(element.dataset.retryGeneration);
  const retryState = element.dataset.retryState;
  const key = `${spaceId}\u0000${rootResourceId}`;
  const scope = vaultOperationsUi.scopes.get(key);
  const item = scope?.items.find(operation => operation.write_id === writeId && operation.revision === revision);
  const latestJob = encryptedRetryLatestUi.statuses.get(key)?.status;
  const latestJobActive = latestJob && ['queued', 'running'].includes(latestJob.state);
  if (!scope || !item || item.operation !== 'create_file' || item.state !== 'uncertain' || !item.can_retry_interrupted_create ||
      !item.retry_state || item.retry_state !== retryState || !['attempting', 'recovery_attempting', 'recovery_retrying'].includes(item.retry_state) ||
      !Number.isSafeInteger(revision) || revision < 1 || !Number.isSafeInteger(retryGeneration) || retryGeneration < 0 || item.retry_generation !== retryGeneration || state.page !== 'transfers' || !state.agentReachable || !state.status?.connected ||
      state.status?.paused || state.status?.paused_space_ids?.includes(spaceId) || state.accountSwitching || latestJobActive) return;
  if (interruptedCreateRetryUi.job && (interruptedCreateRetryUi.job.busy || ['queued', 'running'].includes(interruptedCreateRetryUi.job.status?.state || ''))) return;
  const epoch = state.accountEpoch;
  const profileId = state.selectedAccount;
  const generation = ++interruptedCreateRetryUi.generation;
  const job: InterruptedCreateRetryUi = {
    key, spaceId, rootResourceId, writeId, revision, retryGeneration, retryState: item.retry_state,
    jobId: '', profileId, accountEpoch: epoch, generation, busy: true, status: null, error: ''
  };
  interruptedCreateRetryUi.job = job;
  render();
  try {
    const result = await request<{ accepted: boolean; job_id: string }>('vault_retry_interrupted_file_create', {
      space_id: spaceId, root_resource_id: rootResourceId, write_id: writeId, revision, retry_state: item.retry_state, retry_generation: retryGeneration
    });
    if (!interruptedCreateRetryContextCurrent(job)) return;
    if (result.accepted !== true || typeof result.job_id !== 'string' || !result.job_id || result.job_id.length > 256) {
      throw new Error('Raiun did not confirm the interrupted file retry.');
    }
    job.jobId = result.job_id;
    job.status = { job_id: result.job_id, space_id: spaceId, root_resource_id: rootResourceId, operation: 'create_file', write_id: writeId, operation_revision: revision, retry_generation: retryGeneration, automatic: false, state: 'queued', processed: 0, uploaded: 0, conflicts: 0, remaining: 1, cancel_requested: false };
    render();
    scheduleInterruptedCreateRetryPoll(job, 500);
  } catch (error) {
    if (interruptedCreateRetryContextCurrent(job) && !isStaleAccountRequest(error)) job.error = 'Raiun could not start the verification request. The local copy remains saved; refresh the operation status before trying again.';
  } finally {
    if (interruptedCreateRetryContextCurrent(job)) {
      job.busy = false;
      render();
    }
  }
}
async function pollInterruptedCreateRetry(job: InterruptedCreateRetryUi) {
  if (nativeVaultAccess()) return;
  if (!job.jobId || !interruptedCreateRetryContextCurrent(job)) return;
  try {
    const status = await request<VaultEditReconcileStatus>('vault_reconcile_edits_status', {
      space_id: job.spaceId, root_resource_id: job.rootResourceId, job_id: job.jobId
    });
    if (!interruptedCreateRetryContextCurrent(job)) return;
    if (status.job_id !== job.jobId || status.space_id !== job.spaceId || status.root_resource_id !== job.rootResourceId ||
        status.operation !== 'create_file' || status.write_id !== job.writeId || status.operation_revision !== job.revision ||
        status.retry_generation !== job.retryGeneration ||
        status.automatic !== false || !['queued', 'running', 'complete', 'failed', 'cancelled'].includes(status.state) ||
        (status.failure_class != null && !isVaultFailureClass(status.failure_class)) ||
        ![status.processed, status.uploaded, status.conflicts, status.remaining].every(value => Number.isSafeInteger(value) && value >= 0) ||
        typeof status.cancel_requested !== 'boolean') throw new Error('The agent returned a mismatched interrupted-file retry status.');
    job.status = status;
    if (status.state === 'queued' || status.state === 'running') {
      render();
      scheduleInterruptedCreateRetryPoll(job, 1000);
      return;
    }
    if (status.state === 'complete' && status.uploaded === 1) {
      state.message = 'The interrupted file creation was verified. The local operation has been reconciled.';
    } else if (status.state === 'complete' && status.conflicts > 0) {
      state.message = 'The cloud destination changed. Raiun kept the local file and did not replace the cloud item.';
    } else if (status.state === 'failed') {
      job.error = vaultFailureMessage(status.failure_class) || 'Raiun could not verify the interrupted create. The local file remains saved; check the destination before trying again.';
    } else {
      state.message = 'The explicit retry stopped. Raiun kept the local file; check its current status before trying again.';
    }
    if (interruptedCreateRetryUi.timer) window.clearTimeout(interruptedCreateRetryUi.timer);
    interruptedCreateRetryUi.timer = 0;
    render();
    void refreshEncryptedRetryLatestStatuses(true);
  } catch (error) {
    if (!interruptedCreateRetryContextCurrent(job) || isStaleAccountRequest(error)) return;
    job.error = 'Raiun could not check this retry status. The local copy remains saved; refresh the operation list before trying again.';
    render();
    scheduleInterruptedCreateRetryPoll(job, 2500);
  }
}
function vaultOperationLabel(operation: VaultOperation['operation']) {
  return operation === 'overwrite' ? 'Edit file' : operation === 'create_file' ? 'Create file' : operation === 'rename_file' ? 'Rename file' : operation === 'delete_file' ? 'Delete file' : operation === 'copy_file' ? 'Copy encrypted file' : 'Create folder';
}
function vaultOperationStateLabel(operation: VaultOperation) {
  if (operation.operation === 'copy_file' && operation.needs_attention) return 'Copy needs review';
  if (operation.state === 'building') return 'Preparing locally';
  if (operation.state === 'queued') return operation.operation === 'create_directory' ? 'Folder saved locally · waiting to sync' : 'Saved locally · waiting to sync';
  if (operation.state === 'pending') return operation.operation === 'create_directory' ? 'Folder waiting to sync' : 'Waiting to upload';
  if (operation.needs_attention) return operation.operation === 'create_file' ? 'File creation outcome unknown' : 'Folder creation outcome unknown';
  return operation.state === 'uncertain' ? 'Cloud status uncertain' : 'Needs review';
}
function encryptedOperationsTransferSection() {
  const discoveryError = encryptedRetryLatestUi.discoveryError
    ? `<div class="pending-writes-error" role="alert">${esc(encryptedRetryLatestUi.discoveryError)}</div>`
    : '';
  if (encryptedRetryLatestUi.discoveryLoading && !vaultOperationsUi.scopes.size) return `<section class="pending-writes-card encrypted-operations"><div class="pending-writes-heading"><div><h2>Encrypted file operations</h2><p>Operation names appear only for encrypted locations that are currently unlocked.</p></div></div><div class="pending-writes-empty" role="status">Checking unlocked encrypted locations…</div></section>`;
  const scopes = [...vaultOperationsUi.scopes.values()];
  if (!scopes.length) return `<section class="pending-writes-card encrypted-operations"><div class="pending-writes-heading"><div><h2>Encrypted file operations</h2><p>Operation names appear only while an encrypted location is unlocked.</p></div><button class="button subtle" data-action="refresh-encrypted-operations" ${!state.agentReachable || vaultOperationsUi.loading || encryptedRetryLatestUi.running ? 'disabled' : ''}>Refresh</button></div>${discoveryError || '<div class="pending-writes-empty">Unlock an encrypted location to review its saved operations. Locked locations are not listed here.</div>'}</section>`;
  const rows = scopes.map(scope => {
    const rootSuffix = scope.rootResourceId.length > 8 ? scope.rootResourceId.slice(-8) : scope.rootResourceId;
    const latestJob = encryptedRetryLatestUi.statuses.get(scope.key)?.status;
    const items = scope.items.map(item => {
      const target = item.operation === 'rename_file' && item.destination_path ? `${item.path} → ${item.destination_path}` : item.path;
      const size = ['overwrite', 'create_file'].includes(item.operation) ? ` · ${formatBytes(item.bytes)}` : '';
      const attention = item.attention_reason === 'directory_create_attempt_interrupted'
        ? '<small>Folder creation outcome unknown; files retained. Automatic retry paused for this operation.</small>'
        : item.attention_reason === 'file_create_attempt_interrupted'
          ? '<small>File creation outcome unknown; local copy retained. Automatic retry paused for this operation.</small>'
          : item.attention_reason === 'file_create_recovery_interrupted'
            ? '<small>Raiun stopped while checking this file creation. Its local copy is retained; use the explicit retry only after reviewing the destination.</small>'
            : item.attention_reason === 'copy_file_requires_review'
              ? `<small>${esc(copyOperationReviewMessage())}</small>`
          : '';
      const retryJob = interruptedCreateRetryMatches(scope, item) ? interruptedCreateRetryUi.job : null;
      const retryRunning = retryJob?.busy || retryJob?.status?.state === 'queued' || retryJob?.status?.state === 'running';
      const retryError = retryJob?.error ? `<small role="alert">${esc(retryJob.error)}</small>` : '';
      const retryProgress = retryRunning ? `<small role="status">${retryJob?.status?.state === 'running' ? 'Checking the destination and retrying…' : 'Starting the explicit retry…'}</small>` : '';
      const retryBlockedReason = !state.agentReachable ? 'The Raiun agent is unavailable.'
        : !state.status?.connected ? 'Connect to the server before retrying.'
          : state.status?.paused || state.status?.paused_space_ids?.includes(scope.spaceId) ? 'Resume this account and Space before retrying.'
            : !retryRunning && latestJob && ['queued', 'running'].includes(latestJob.state) ? 'Another encrypted edit operation is already running for this location.'
            : interruptedCreateRetryUi.job && !retryJob ? 'Another encrypted retry is already running.' : '';
      const retryButton = item.can_retry_interrupted_create && item.retry_state
        ? `<button class="button subtle" data-action="retry-interrupted-file-create" data-space-id="${esc(scope.spaceId)}" data-root-resource-id="${esc(scope.rootResourceId)}" data-write-id="${esc(item.write_id)}" data-revision="${item.revision}" data-retry-generation="${item.retry_generation}" data-retry-state="${esc(item.retry_state)}" ${retryRunning || !!retryBlockedReason ? 'disabled' : ''} title="${esc(retryBlockedReason || 'Check the exact destination and retry this interrupted create')}">${retryRunning ? 'Retrying…' : 'Retry file creation'}</button><small>${esc(retryBlockedReason || 'This creates the file only if its cloud destination is still absent. It never replaces an existing item.')}</small>`
        : '';
      const copyBinding: CopyVerifyBinding | null = item.operation === 'copy_file' && item.needs_attention && scope.authGeneration >= 0
        ? { profileId: state.selectedAccount, accountEpoch: scope.accountEpoch, spaceId: scope.spaceId, rootResourceId: scope.rootResourceId, writeId: item.write_id, revision: item.revision, authGeneration: scope.authGeneration }
        : null;
      const copyJob = copyBinding ? copyVerifyUi.jobs.get(copyVerifyRowKey(copyBinding)) : undefined;
      const copyBusy = copyVerifyActive(copyJob);
      const copyBlockedReason = !state.agentReachable ? 'The Raiun agent is unavailable.'
        : state.accountSwitching ? 'Wait for the account switch to finish.' : '';
      const copyVerifyButton = copyBinding
        ? copyJob?.jobId && !copyJob.status
          ? `<button class="button subtle" data-action="check-copy-verification-status" data-space-id="${esc(scope.spaceId)}" data-root-resource-id="${esc(scope.rootResourceId)}" data-write-id="${esc(item.write_id)}" data-revision="${item.revision}" data-auth-generation="${scope.authGeneration}" ${copyBusy || !!copyBlockedReason ? 'disabled' : ''}>${copyBusy ? 'Checking…' : 'Check status'}</button>${copyJob.busy ? `<small role="status" aria-live="polite" tabindex="-1" data-copy-verify-live data-space-id="${esc(scope.spaceId)}" data-root-resource-id="${esc(scope.rootResourceId)}" data-write-id="${esc(item.write_id)}" data-revision="${item.revision}" data-auth-generation="${scope.authGeneration}">Checking verification status…</small>` : ''}${copyJob.error ? `<small role="alert">${esc(copyJob.error)}</small>` : ''}`
          : `<button class="button subtle" data-action="verify-copy-operation" data-space-id="${esc(scope.spaceId)}" data-root-resource-id="${esc(scope.rootResourceId)}" data-write-id="${esc(item.write_id)}" data-revision="${item.revision}" data-auth-generation="${scope.authGeneration}" ${copyBusy || !!copyBlockedReason ? 'disabled' : ''} title="${esc(copyBlockedReason || 'Read-only check of the original source and destination; no copy retry will start')}">${copyBusy ? 'Checking…' : 'Verify copy'}</button>${copyJob?.busy && !copyJob.status ? `<small role="status" aria-live="polite" tabindex="-1" data-copy-verify-live data-space-id="${esc(scope.spaceId)}" data-root-resource-id="${esc(scope.rootResourceId)}" data-write-id="${esc(item.write_id)}" data-revision="${item.revision}" data-auth-generation="${scope.authGeneration}">Starting read-only verification…</small>` : ''}${copyBusy && copyJob?.jobId && !copyJob.status?.cancel_requested && (copyJob.status?.state === 'queued' || copyJob.status?.state === 'running') ? `<button class="small-action quiet" data-action="cancel-copy-verification" data-space-id="${esc(scope.spaceId)}" data-root-resource-id="${esc(scope.rootResourceId)}" data-write-id="${esc(item.write_id)}" data-revision="${item.revision}" data-auth-generation="${scope.authGeneration}" ${copyJob.cancelBusy ? 'disabled' : ''}>${copyJob.cancelBusy ? 'Stopping…' : 'Cancel check'}</button>` : ''}${copyJob?.status ? `<small role="${copyJob.status.state === 'needs_review' || copyJob.status.state === 'failed' ? 'alert' : 'status'}" aria-live="${copyJob.status.state === 'needs_review' || copyJob.status.state === 'failed' ? 'assertive' : 'polite'}" aria-atomic="true" tabindex="-1" data-copy-verify-live data-space-id="${esc(scope.spaceId)}" data-root-resource-id="${esc(scope.rootResourceId)}" data-write-id="${esc(item.write_id)}" data-revision="${item.revision}" data-auth-generation="${scope.authGeneration}">${copyJob.cancelBusy ? 'Stopping copy verification…' : esc(copyVerifyStatusMessage(copyJob.status))}</small>` : ''}${copyJob?.error ? `<small role="alert">${esc(copyJob.error)}</small>` : ''}`
        : '';
      return `<article class="vault-operation-row"><div class="vault-operation-copy"><b>${esc(vaultOperationLabel(item.operation))}</b><small>${esc(target)}</small>${retryButton}${copyVerifyButton}${retryProgress}${retryError}</div><span class="vault-operation-state ${item.state === 'conflict' || item.state === 'uncertain' ? 'warning' : ''}">${esc(vaultOperationStateLabel(item))}${size}${attention}</span></article>`;
    }).join('');
    return `<div class="vault-operation-scope"><div class="vault-operation-scope-heading"><b>${esc(spaceName(scope.spaceId))} · …${esc(rootSuffix)}</b><small>Saved locally; this status does not confirm a cloud change.</small></div>${scope.loading && !scope.items.length ? '<div class="pending-writes-empty" role="status">Checking saved operations…</div>' : scope.error ? `<div class="pending-writes-error" role="alert">${esc(scope.error)}</div>` : items || '<div class="pending-writes-empty">No saved operations for this unlocked location.</div>'}${scope.truncated && scope.nextAfter ? `<div class="recovery-more"><button class="button subtle" data-action="load-more-vault-operations" data-space-id="${esc(scope.spaceId)}" data-root-resource-id="${esc(scope.rootResourceId)}" ${scope.loading ? 'disabled' : ''}>${scope.loading ? 'Loading…' : 'Load more operations'}</button></div>` : ''}</div>`;
  }).join('');
  return `<section class="pending-writes-card encrypted-operations"><div class="pending-writes-heading"><div><h2>Encrypted file operations</h2><p>These local operations are shown only for currently unlocked locations. Upload status is not confirmed until Raiun reports it; new folders stay local until their server identity is verified.</p></div><button class="button subtle" data-action="refresh-encrypted-operations" ${!state.agentReachable || vaultOperationsUi.loading || encryptedRetryLatestUi.running ? 'disabled' : ''}>${vaultOperationsUi.loading || encryptedRetryLatestUi.running ? 'Checking…' : 'Refresh'}</button></div>${discoveryError}${rows}${vaultOperationsUi.rootsTruncated ? '<small class="vault-pin-note">The active-location list reached its limit; some unlocked locations may not be shown.</small>' : ''}</section>`;
}
function scheduleEncryptedRetryLatestPoll(delay = 4000) {
  if (encryptedRetryLatestUi.timer) window.clearTimeout(encryptedRetryLatestUi.timer);
  if (state.page !== 'transfers' || !state.agentReachable) return;
  encryptedRetryLatestUi.timer = window.setTimeout(() => {
    encryptedRetryLatestUi.timer = 0;
    void refreshEncryptedRetryLatestStatuses();
  }, delay);
}
function stopEncryptedRetryLatestPolling() {
  if (encryptedRetryLatestUi.timer) window.clearTimeout(encryptedRetryLatestUi.timer);
  encryptedRetryLatestUi.timer = 0;
  encryptedRetryLatestUi.generation++;
  encryptedRetryLatestUi.running = false;
  encryptedRetryLatestUi.loading.clear();
  clearVaultOperations();
}
function resetEncryptedRetryLatestUi() {
  stopEncryptedRetryLatestPolling();
  encryptedRetryLatestUi.statuses.clear();
  encryptedRetryLatestUi.errors.clear();
  encryptedRetryLatestUi.loading.clear();
  encryptedRetryLatestUi.scopes = [];
  encryptedRetryLatestUi.scopesTruncated = false;
  encryptedRetryLatestUi.discoveryLoading = false;
  encryptedRetryLatestUi.discoveryError = '';
  encryptedRetryLatestUi.accountEpoch = state.accountEpoch;
}
async function refreshEncryptedRetryLatestStatuses(forceOperations = false) {
  if (!vaultAppFeaturesAvailable()) {
    encryptedRetryLatestUi.discoveryError = 'Encrypted retry status is unavailable for this Windows agent.';
    render();
    return;
  }
  if (encryptedRetryLatestUi.running || state.page !== 'transfers' || !state.agentReachable || state.accountSwitching) return;
  const epoch = state.accountEpoch;
  const profileId = state.selectedAccount;
  const generation = ++encryptedRetryLatestUi.generation;
  encryptedRetryLatestUi.running = true;
  encryptedRetryLatestUi.discoveryLoading = true;
  encryptedRetryLatestUi.discoveryError = '';
  render();
  let activeRoots: { spaceId: string; rootResourceId: string }[] = [];
  let activeTruncated = false;
  let activeRootDiscoverySucceeded = false;
  try {
    const active = validateUnlockedVaultRoots(await request('vault_unlocked_roots'));
    activeRoots = active.roots;
    activeTruncated = active.truncated;
    activeRootDiscoverySucceeded = true;
  } catch (error) {
    if (!isCurrentAccount(epoch, profileId) || encryptedRetryLatestUi.generation !== generation || isStaleAccountRequest(error)) return;
    encryptedRetryLatestUi.discoveryError = messageOf(error) || 'Active encrypted locations could not be checked.';
  }
  if (!isCurrentAccount(epoch, profileId) || encryptedRetryLatestUi.generation !== generation || state.page !== 'transfers') return;
  if (activeRootDiscoverySucceeded) await refreshVaultOperations(activeRoots, forceOperations, activeTruncated);
  else clearVaultOperations();
  if (!isCurrentAccount(epoch, profileId) || encryptedRetryLatestUi.generation !== generation || state.page !== 'transfers') return;
  const combinedScopes = new Map<string, { spaceId: string; rootResourceId: string }>();
  for (const scope of [...activeRoots, ...encryptedVaultPairScopes()]) {
    combinedScopes.set(`${scope.spaceId}\u0000${scope.rootResourceId}`, { spaceId: scope.spaceId, rootResourceId: scope.rootResourceId });
  }
  const allScopes = [...combinedScopes.entries()];
  const scopes = allScopes.slice(0, 100).map(([key, scope]) => ({ key, ...scope }));
  encryptedRetryLatestUi.scopes = scopes;
  const configuredScopeCount = new Set(state.pairs.filter(pair => pair.vault?.root_resource_id && pair.space_id).map(pair => `${pair.space_id}\u0000${pair.vault!.root_resource_id}`)).size;
  encryptedRetryLatestUi.scopesTruncated = activeTruncated || configuredScopeCount > 100 || allScopes.length > scopes.length;
  encryptedRetryLatestUi.discoveryLoading = false;
  const visibleKeys = new Set(scopes.map(scope => scope.key));
  for (const key of encryptedRetryLatestUi.statuses.keys()) if (!visibleKeys.has(key)) encryptedRetryLatestUi.statuses.delete(key);
  for (const key of encryptedRetryLatestUi.errors.keys()) if (!visibleKeys.has(key)) encryptedRetryLatestUi.errors.delete(key);
  if (!scopes.length) {
    encryptedRetryLatestUi.running = false;
    render();
    scheduleEncryptedRetryLatestPoll();
    return;
  }
  const updates = Promise.all(scopes.map(async scope => {
    encryptedRetryLatestUi.loading.add(scope.key);
    try {
      const result = validateVaultEditLatest(await request<VaultEditLatestResult>('vault_reconcile_edits_latest', {
        space_id: scope.spaceId, root_resource_id: scope.rootResourceId
      }), scope.spaceId, scope.rootResourceId);
      if (!isCurrentAccount(epoch, profileId) || encryptedRetryLatestUi.generation !== generation || state.page !== 'transfers') return;
      encryptedRetryLatestUi.statuses.set(scope.key, result);
      encryptedRetryLatestUi.errors.delete(scope.key);
    } catch (error) {
      if (!isCurrentAccount(epoch, profileId) || encryptedRetryLatestUi.generation !== generation || state.page !== 'transfers' || isStaleAccountRequest(error)) return;
      encryptedRetryLatestUi.errors.set(scope.key, messageOf(error));
    } finally {
      if (encryptedRetryLatestUi.generation === generation) encryptedRetryLatestUi.loading.delete(scope.key);
    }
  }));
  render();
  await updates;
  if (!isCurrentAccount(epoch, profileId) || encryptedRetryLatestUi.generation !== generation) return;
  encryptedRetryLatestUi.running = false;
  render();
  scheduleEncryptedRetryLatestPoll();
}
async function cancelEncryptedRetryLatest(element: HTMLElement) {
  if (nativeVaultAccess()) return;
  const spaceId = element.dataset.spaceId || '';
  const rootResourceId = element.dataset.rootResourceId || '';
  const jobId = element.dataset.jobId || '';
  const scope = encryptedRetryLatestUi.scopes.find(item => item.spaceId === spaceId && item.rootResourceId === rootResourceId);
  const key = `${spaceId}\u0000${rootResourceId}`;
  const result = encryptedRetryLatestUi.statuses.get(key);
  const job = result?.status;
  if (!scope || !job || job.job_id !== jobId || !['queued', 'running'].includes(job.state) || job.cancel_requested || !state.status?.connected) return;
  const epoch = state.accountEpoch;
  const profileId = state.selectedAccount;
  try {
    const cancelStatus = await request<VaultEditReconcileStatus>('vault_reconcile_edits_cancel', {
      space_id: spaceId, root_resource_id: rootResourceId, job_id: jobId
    });
    const cancelled = validateVaultEditLatest({ available: true, status: cancelStatus }, spaceId, rootResourceId);
    if (!isCurrentAccount(epoch, profileId) || state.page !== 'transfers' || encryptedRetryLatestUi.statuses.get(key)?.status?.job_id !== jobId) return;
    encryptedRetryLatestUi.statuses.set(key, cancelled);
  } catch (error) {
    if (isCurrentAccount(epoch, profileId) && state.page === 'transfers' && !isStaleAccountRequest(error)) encryptedRetryLatestUi.errors.set(key, messageOf(error));
  }
  if (isCurrentAccount(epoch, profileId) && state.page === 'transfers') render();
}
function encryptedVaultPairScopes() {
  const scopes = new Map<string, { spaceId: string; rootResourceId: string }>();
  for (const pair of state.pairs) {
    const rootResourceId = pair.vault?.root_resource_id;
    if (!rootResourceId || !pair.space_id) continue;
    const key = `${pair.space_id}\u0000${rootResourceId}`;
    if (!scopes.has(key)) scopes.set(key, { spaceId: pair.space_id, rootResourceId });
  }
  return [...scopes.entries()].slice(0, 100).map(([key, scope]) => ({ key, ...scope }));
}
function encryptedRetryLatestSection() {
  const scopes = encryptedRetryLatestUi.scopes;
  if (!scopes.length && !encryptedRetryLatestUi.discoveryLoading) return '';
  const rows = scopes.map(scope => {
    const result = encryptedRetryLatestUi.statuses.get(scope.key);
    const error = encryptedRetryLatestUi.errors.get(scope.key);
    const status = result?.status ?? null;
    const busy = !!status && (status.state === 'queued' || status.state === 'running');
    const label = !result
      ? encryptedRetryLatestUi.loading.has(scope.key) ? 'Checking retry status…' : error ? 'Retry status unavailable' : 'No retry status checked yet'
      : !result.available || !status ? 'No retry status from this Raiun session' :
        `${status.automatic ? 'Automatic' : 'Manual'} retry ${status.state === 'queued' ? 'queued' : status.state === 'running' ? 'running' : status.state === 'complete' ? 'finished' : status.state === 'failed' ? 'stopped with an error' : 'cancelled'}`;
    const detail = status
      ? `${status.uploaded} uploaded and verified · ${status.conflicts} need review · ${status.remaining} saved record(s) remain${status.cancel_requested ? ' · stopping after the current operation' : ''}${status.state === 'failed' ? ` · ${vaultEditRetryStatusMessage(status.failure_class)}` : ''}`
      : error ? error : !result?.available
        ? 'Saved edits remain local. Open this encrypted location to retry them explicitly; automatic retries never unlock a vault.'
        : 'Current-process job status is being checked. Saved edits remain available.';
    const pause = state.status?.paused === true || (state.status?.paused_space_ids || []).includes(scope.spaceId);
    const rootSuffix = scope.rootResourceId.length > 8 ? scope.rootResourceId.slice(-8) : scope.rootResourceId;
    return `<article class="encrypted-retry-latest-row"><div><b>${esc(spaceName(scope.spaceId))} · encrypted location …${esc(rootSuffix)}</b><small>${esc(label)} · ${esc(detail)}</small>${busy && pause ? '<small>Sync is paused; no further retry work will start until it resumes.</small>' : ''}</div>${busy ? `<button class="small-action quiet" data-vault-edit-latest-cancel data-space-id="${esc(scope.spaceId)}" data-root-resource-id="${esc(scope.rootResourceId)}" data-job-id="${esc(status!.job_id)}" ${status!.cancel_requested ? 'disabled' : ''}>${status!.cancel_requested ? 'Stopping…' : 'Stop retry'}</button>` : ''}</article>`;
  }).join('');
  const omitted = encryptedRetryLatestUi.scopesTruncated;
  const checking = encryptedRetryLatestUi.discoveryLoading && !scopes.length ? '<div class="pending-writes-empty" role="status">Checking active unlocked encrypted locations…</div>' : '';
  const discoveryError = encryptedRetryLatestUi.discoveryError ? `<div class="pending-writes-error" role="status">${esc(encryptedRetryLatestUi.discoveryError)}</div>` : '';
  return `<section class="pending-writes-card encrypted-retry-latest"><div class="pending-writes-heading"><div><h2>Encrypted upload retries</h2><p>Retries run only after a successful connection cycle for an already-unlocked location, when account and Space sync are not paused; each location has a five-minute backoff. Raiun never unlocks a vault or checks saved keys automatically. Changed cloud versions remain conflicts.</p></div><button class="button subtle" data-action="refresh-encrypted-retry-status" ${encryptedRetryLatestUi.running || !state.agentReachable ? 'disabled' : ''}>${encryptedRetryLatestUi.running ? 'Checking…' : 'Refresh status'}</button></div>${discoveryError}${checking}<div class="encrypted-retry-latest-list">${rows}</div>${omitted ? `<small class="vault-pin-note">The active-location list reached its limit. Showing the first ${scopes.length} encrypted locations.</small>` : ''}<small class="vault-pin-note">Job status is kept only while this Raiun agent is running. After a restart, saved edits remain available for an explicit retry after unlocking.</small></section>`;
}
function encryptedEditsTransferSection() {
  const page = state.encryptedEditRecoveryPage;
  const counts = page?.counts;
  const needsAttention = counts ? counts.pending + counts.uncertain + counts.corrupt : 0;
  const summary = counts
    ? `<small class="pending-writes-count">${counts.building} still being prepared · ${counts.pending} waiting or active · ${counts.uncertain} upload status uncertain · ${counts.committed} upload record(s) · ${counts.corrupt} metadata warning(s)</small>`
    : '';
  const labels: Record<EncryptedEditRecoveryItem['state'], string> = {
    building: 'Local copy is still being prepared', pending: 'Waiting or active', uncertain: 'Status uncertain', committed: 'Upload previously recorded', clean: 'No pending edit recorded', corrupt: 'Needs review'
  };
  const rows = page?.items.length
    ? `<div class="encrypted-edit-list">${page.items.map(item => `<article class="encrypted-edit-item"><div><b>${esc(item.record_id || 'Unrecognized saved copy')}</b><small>${item.bytes == null ? 'Size unavailable' : esc(formatBytes(item.bytes))}</small>${item.warning ? `<small class="encrypted-edit-warning">${esc(item.warning)}</small>` : ''}</div><span class="encrypted-edit-badge ${item.state === 'clean' || item.state === 'committed' ? '' : 'warning'}">${labels[item.state]}</span></article>`).join('')}</div>`
    : page ? `<div class="recovery-empty" role="status" aria-live="polite">${page.scanned_entries === 0 ? 'No saved encrypted-file edits. Nothing to review.' : 'No records on this page.'}</div>` : '';
  const loading = state.encryptedEditRecoveryLoading;
  return `<section class="pending-writes-card encrypted-edits-transfers"><div class="pending-writes-heading"><div><h2>Encrypted file working copies</h2>${summary}<p>Edits to existing encrypted files are saved as readable local working copies. Some may still be active or waiting to upload; local records do not confirm cloud completion. A “Local copy is still being prepared” entry is incomplete and cannot be uploaded or retried yet. Queued create, rename, delete, and folder-creation operations are listed separately; their local status does not confirm cloud completion.</p></div><button class="button subtle" data-action="load-encrypted-edit-recoveries" ${!state.agentReachable || loading ? 'disabled' : ''}>${loading ? 'Checking…' : page ? 'Refresh list' : 'Check saved edits'}</button></div>${state.encryptedEditRecoveryError ? `<div class="pending-writes-error" role="alert">${esc(state.encryptedEditRecoveryError)}</div>` : ''}${loading && !page?.items.length ? `<div class="pending-writes-empty" role="status"><span class="spinner"></span> Checking local encrypted-edit records…</div>` : !page ? `<div class="pending-writes-empty">Check local records to see edits awaiting upload or review.</div>` : `<div class="pending-writes-empty encrypted-edit-transfer-counts" role="status">${needsAttention ? `${needsAttention} record(s) may need attention.` : counts?.building ? `${counts.building} local copy reservation(s) are still being prepared; they are not upload-ready.` : 'No encrypted edits are waiting for review.'} Upload records are not verified against the server.</div>${page.truncated ? '<div class="recovery-warning" role="status">The scan reached its safety limit; this list may be incomplete.</div>' : ''}${rows}${page.next_after && !loading ? `<div class="recovery-more"><button class="button subtle" data-action="more-encrypted-edit-recoveries">Load more</button></div>` : ''}`}</section>`;
}
function transferCard(item: Transfer) {
  const status = (item.state || 'unknown').toLowerCase();
  const direction = (item.direction || '').toLowerCase();
  const isUpload = direction.includes('upload') || direction === 'up';
  const issue = ['failed', 'conflict', 'awaiting_authentication'].includes(status);
  const statusLabel = status.replaceAll('_', ' ').replace(/\b\w/g, c => c.toUpperCase());
  const subject = item.path || String(item.id) || 'Transfer';
  const origin = ['completed', 'cancelled'].includes(status) ? 'This PC' : item.origin ? item.origin.replaceAll('_', ' ') : 'Sync folder';
  const historyAccount = ['completed', 'cancelled'].includes(status) ? ` <span>·</span> ${esc(selectedAccountLabel())}` : '';
  const byteText = item.bytes_total != null && item.bytes_total > 0 && item.bytes_done != null ? `${formatBytes(item.bytes_done)} of ${formatBytes(item.bytes_total)}` : item.bytes_total === 0 && status === 'completed' ? '0 bytes' : '';
  return `<article class="transfer-card"><span class="transfer-direction ${isUpload ? 'up' : 'down'}">${svg(isUpload ? 'arrowUp' : 'arrowDown')}</span><div class="transfer-main"><div class="transfer-title"><b>${esc(lastPath(subject))}</b><span class="transfer-status ${issue ? 'issue' : ''}">${esc(statusLabel)}</span></div><div class="transfer-meta">${esc(origin)}${historyAccount} <span>·</span> ${esc(item.space_id ? spaceName(item.space_id) : 'OpenCloud')}${byteText ? `<span>·</span> ${esc(byteText)}` : ''}</div>${item.error ? `<p class="transfer-error">${esc(item.error)}</p>` : ''}</div><div class="transfer-actions">${issue && item.origin === 'folder_pair' ? `<button class="small-action" data-action="sync-now">Rescan folders</button>` : ''}</div></article>`;
}
async function loadPendingOfflineWrites(reset: boolean) {
  if (isWindowsAgentStatus(state.status) || !providerAvailable(state.status?.provider_supported)) {
    pendingWritesUi.error = 'Saved-edit status is unavailable for this Windows agent. Existing local copies remain in place.';
    render();
    return;
  }
  if (pendingWritesUi.loading) { if (reset) pendingWritesUi.refreshQueued = true; return; }
  if (!state.agentReachable || !state.selectedAccount) {
    pendingWritesUi.error = state.agentReachable ? 'Select an account to check saved edits.' : 'Raiun is not connected. Start it to check saved edits.';
    pendingWritesUi.loaded = false;
    pendingWritesUi.accountEpoch = state.accountEpoch;
    render();
    return;
  }
  if (pendingWritesUi.accountEpoch !== state.accountEpoch) reset = true;
  const epoch = state.accountEpoch;
  const profileId = state.selectedAccount;
  const generation = reset ? ++pendingWritesUi.generation : pendingWritesUi.generation;
  const cursor = reset ? null : pendingWritesUi.nextAfter;
  if (!reset && !cursor) return;
  const previousItems = reset ? [] : pendingWritesUi.items;
  pendingWritesUi.loading = true;
  pendingWritesUi.error = '';
  if (reset) {
    pendingWritesUi.items = [];
    pendingWritesUi.nextAfter = null;
    pendingWritesUi.pendingCount = 0;
    pendingWritesUi.conflictCount = 0;
    pendingWritesUi.truncated = false;
    pendingWritesUi.accountEpoch = epoch;
  }
  render();
  const args: Record<string, unknown> = { limit: 50 };
  if (cursor) args.after = cursor;
  try {
    const raw = await request<unknown>('cache_pending_writes', args);
    if (!isCurrentAccount(epoch, profileId) || generation !== pendingWritesUi.generation) return;
    const page = pendingWritePageIsValid(raw);
    if (!reset && (pendingWritesUi.authGeneration !== page.auth_generation || pendingWritesUi.accountScope !== page.account_scope)) throw new Error('The account changed. Refresh saved edits.');
    pendingWritesUi.authGeneration = page.auth_generation;
    pendingWritesUi.accountScope = page.account_scope;
    const seen = new Set(previousItems.map(item => `${item.space_id}\0${item.write_id}`));
    pendingWritesUi.items = [...previousItems, ...page.items.filter(item => !seen.has(`${item.space_id}\0${item.write_id}`))];
    pendingWritesUi.nextAfter = page.next_after;
    pendingWritesUi.pendingCount = page.pending_count;
    pendingWritesUi.conflictCount = page.conflict_count;
    pendingWritesUi.truncated = page.truncated;
    pendingWritesUi.loaded = true;
    pendingWritesUi.accountEpoch = epoch;
  } catch (error) {
    if (isCurrentAccount(epoch, profileId) && generation === pendingWritesUi.generation && !isStaleAccountRequest(error)) pendingWritesUi.error = messageOf(error);
  } finally {
    if (isCurrentAccount(epoch, profileId) && generation === pendingWritesUi.generation) {
      pendingWritesUi.loading = false;
      render();
      if (pendingWritesUi.refreshQueued) {
        pendingWritesUi.refreshQueued = false;
        void loadPendingOfflineWrites(true);
      }
    }
  }
}
async function retryPendingOfflineWrites(spaceId: string) {
  if (isWindowsAgentStatus(state.status) || !providerAvailable(state.status?.provider_supported)) return;
  const epoch = state.accountEpoch;
  const profileId = state.selectedAccount;
  if (!state.status?.connected || !spaceId || pendingWritesUi.retryingSpaces.has(spaceId)) return;
  if (!pendingWritesUi.items.some(item => item.space_id === spaceId && item.state === 'pending')) return;
  pendingWritesUi.retryingSpaces.add(spaceId);
  pendingWritesUi.error = '';
  render();
  try {
    const started = await request<{ job_id: string; state: 'queued' | 'running' }>('cache_reconcile_writes', { space_id: spaceId });
    if (!isCurrentAccount(epoch, profileId)) return;
    if (typeof started.job_id !== 'string' || !started.job_id || started.job_id.length > 256 || !['queued', 'running'].includes(started.state)) throw new Error('The agent did not confirm the upload retry.');
    const job = { job_id: started.job_id, space_id: spaceId, accountEpoch: epoch };
    pendingWritesUi.reconcileJobs.set(spaceId, job);
    state.message = `Retrying uploads for ${spaceName(spaceId)}. Local copies stay on this PC; changed cloud versions remain for review.`;
    render();
    schedulePendingReconcilePoll(job, 700);
  } catch (error) {
    if (isCurrentAccount(epoch, profileId) && !isStaleAccountRequest(error)) {
      pendingWritesUi.error = messageOf(error);
      pendingWritesUi.retryingSpaces.delete(spaceId);
      render();
    }
  }
}
function pendingWriteExportKey(spaceId: string, writeId: string) { return `${spaceId}\0${writeId}`; }
async function savePendingConflictCopy(spaceId: string, writeId: string, rootResourceId: string) {
  const epoch = state.accountEpoch;
  const profileId = state.selectedAccount;
  const item = pendingWritesUi.items.find(candidate => candidate.space_id === spaceId && candidate.write_id === writeId && candidate.root_resource_id === rootResourceId && ['pending', 'conflict'].includes(candidate.state));
  const key = pendingWriteExportKey(spaceId, writeId);
  const expectedGeneration = pendingWritesUi.authGeneration;
  const expectedAccountScope = pendingWritesUi.accountScope;
  if (expectedGeneration == null || !expectedAccountScope) return;
  if (!item || !rootResourceId || !profileId || pendingWritesUi.accountEpoch !== epoch || pendingWritesUi.exportingWrites.has(key) || state.nativeDialogBusy || state.accountSwitching) return;

  pendingWritesUi.error = '';
  pendingWritesUi.exportingWrites.add(key);
  state.nativeDialogBusy = true;
  render();
  try {
    const result = await invoke<{ cancelled?: boolean; exported?: boolean; space_id?: string; root_resource_id?: string; journal_preserved?: boolean; write_id?: string; path?: string; destination?: string; bytes?: number }>('save_saved_edit_copy', {
      profileId,
      spaceId,
      rootResourceId,
      expectedBinding: [expectedGeneration, expectedAccountScope],
      writeId,
      suggestedName: lastPath(item.path)
    });
    if (!isCurrentAccount(epoch, profileId)) return;
    if (result?.cancelled === true) return;
    if (result?.exported !== true || result.space_id !== spaceId || result.root_resource_id !== rootResourceId || result.journal_preserved !== true || result.write_id !== writeId || result.path !== item.path || result.bytes !== item.bytes || typeof result.destination !== 'string' || !Number.isSafeInteger(result.bytes) || (result.bytes ?? -1) < 0) {
      throw new Error('Raiun did not confirm the local copy. The saved edit remains unchanged.');
    }
    state.message = `Local copy saved to ${result.destination}. The saved edit remains in this list.`;
  } catch (error) {
    if (isCurrentAccount(epoch, profileId) && !isStaleAccountRequest(error)) pendingWritesUi.error = messageOf(error);
  } finally {
    pendingWritesUi.exportingWrites.delete(key);
    state.nativeDialogBusy = false;
    if (isCurrentAccount(epoch, profileId)) {
      render();
    }
  }
}
function schedulePendingReconcilePoll(job: { job_id: string; space_id: string; accountEpoch: number }, delay = 1200) {
  const oldTimer = pendingWritesUi.retryTimers.get(job.space_id);
  if (oldTimer) window.clearTimeout(oldTimer);
  const timer = window.setTimeout(() => {
    pendingWritesUi.retryTimers.delete(job.space_id);
    void pollPendingReconcile(job);
  }, delay);
  pendingWritesUi.retryTimers.set(job.space_id, timer);
}
async function pollPendingReconcile(expected: { job_id: string; space_id: string; accountEpoch: number }) {
  const isJobCurrent = () => isCurrentAccount(expected.accountEpoch) && pendingWritesUi.reconcileJobs.get(expected.space_id)?.job_id === expected.job_id;
  if (!isJobCurrent()) return;
  try {
    const result = await request<{ job_id: string; space_id: string; state: 'queued' | 'running' | 'complete' | 'failed' | 'cancelled'; uploaded: number; conflicts: number; remaining: number; error?: string | null; cancel_requested: boolean }>('cache_reconcile_status', { job_id: expected.job_id });
    if (!isJobCurrent() || result.job_id !== expected.job_id || result.space_id !== expected.space_id) return;
    if (!['queued', 'running', 'complete', 'failed', 'cancelled'].includes(result.state)) throw new Error('The agent returned an unknown upload-retry status.');
    if (result.state === 'queued' || result.state === 'running') {
      schedulePendingReconcilePoll(expected);
      return;
    }
    pendingWritesUi.reconcileJobs.delete(expected.space_id);
    pendingWritesUi.retryingSpaces.delete(expected.space_id);
    if (result.state === 'complete') {
      if (![result.uploaded, result.conflicts, result.remaining].every(value => Number.isSafeInteger(value) && value >= 0)) {
        pendingWritesUi.error = 'The agent finished the retry but returned incomplete counts. Refresh the saved-edit list.';
        render();
        return;
      }
      const { uploaded, conflicts, remaining } = result;
      state.message = `Upload retry finished for ${spaceName(expected.space_id)}: ${uploaded} uploaded, ${conflicts} need review, ${remaining} still waiting. No local copies were removed.`;
      await loadPendingOfflineWrites(true);
    } else if (result.state === 'failed') {
      pendingWritesUi.error = result.error || 'The upload retry could not finish. Local copies were kept.';
    } else {
      state.message = 'The upload retry stopped. Local copies were kept.';
    }
  } catch (error) {
    if (!isJobCurrent() || isStaleAccountRequest(error)) return;
    pendingWritesUi.error = messageOf(error);
    schedulePendingReconcilePoll(expected, 3000);
    render();
  } finally {
    if (isCurrentAccount(expected.accountEpoch) && !pendingWritesUi.reconcileJobs.has(expected.space_id)) render();
  }
}
function networkProxyAvailable() {
  return providerAvailable(state.status?.provider_supported) &&
    (!isWindowsAgentStatus(state.status) || state.status?.network_proxy_supported === true);
}

async function loadNetworkProxySettings(force = false) {
  if (!state.agentReachable || proxyUi.loading) return;
  const epoch = state.accountEpoch;
  if (!networkProxyAvailable()) {
    proxyUi.error = 'Proxy settings are unavailable for this Windows agent.';
    proxyUi.loadedEpoch = epoch;
    render();
    return;
  }
  if (!force && proxyUi.loadedEpoch === epoch) return;
  const generation = ++proxyUi.generation;
  proxyUi.loading = true;
  proxyUi.error = '';
  render();
  try {
    const saved = parseProxySettings(await request<unknown>('network_proxy'), isWindowsAgentStatus(state.status));
    if (!isCurrentAccount(epoch) || generation !== proxyUi.generation) return;
    proxyUi.config = saved.proxy;
    proxyUi.revision = saved.revision;
    proxyUi.accountId = saved.account_id;
    proxyUi.scopeToken = saved.scope_token;
    proxyUi.draftMode = saved.proxy.mode;
    proxyUi.draftUrl = saved.proxy.mode === 'explicit' ? saved.proxy.url : '';
    proxyUi.loadedEpoch = epoch;
  } catch (error) {
    if (isCurrentAccount(epoch) && generation === proxyUi.generation && !isStaleAccountRequest(error)) {
      proxyUi.error = 'Proxy settings could not be loaded from this agent.';
    }
  } finally {
    if (generation === proxyUi.generation) {
      proxyUi.loading = false;
      if (isCurrentAccount(epoch)) render();
    }
  }
}

async function saveNetworkProxySettings() {
  const connection = connectionMode(state.agentReachable, state.status);
  const canEdit = proxyEditorEnabled({
    reachable: state.agentReachable,
    connected: state.status?.connected === true,
    offlineNamespace: state.status?.offline_namespace === true,
    authenticating: state.status?.authenticating === true,
    saving: proxyUi.saving || proxyUi.loading,
    requiresSignOut: isWindowsAgentStatus(state.status) && state.status?.proxy_edit_requires_sign_out === true
  }) && state.mutationBusy === 0 && !state.accountSwitching && proxyUi.loadedEpoch === state.accountEpoch;
  if (!canEdit || proxyUi.loadedEpoch !== state.accountEpoch) return;
  const checked = validateProxyDraft(proxyUi.draftMode, proxyUi.draftUrl);
  if (!checked.ok) {
    proxyUi.error = checked.error;
    render();
    return;
  }
  const epoch = state.accountEpoch;
  const generation = ++proxyUi.generation;
  proxyUi.saving = true;
  state.mutationBusy++;
  proxyUi.error = '';
  render();
  try {
    const saved = parseProxySettings(await request<unknown>('network_proxy_set', {
      proxy: checked.config,
      expected_revision: proxyUi.revision,
      expected_account_id: proxyUi.accountId,
      ...(proxyUi.scopeToken ? { expected_scope_token: proxyUi.scopeToken } : {}),
    }), isWindowsAgentStatus(state.status));
    if (!isCurrentAccount(epoch) || generation !== proxyUi.generation) return;
    proxyUi.config = saved.proxy;
    proxyUi.revision = saved.revision;
    proxyUi.accountId = saved.account_id;
    proxyUi.scopeToken = saved.scope_token;
    proxyUi.draftMode = saved.proxy.mode;
    proxyUi.draftUrl = saved.proxy.mode === 'explicit' ? saved.proxy.url : '';
    state.message = isWindowsAgentStatus(state.status)
      ? 'Proxy setting saved. The next sign-in will use this route.'
      : 'Proxy setting saved. Sign in again to apply it; Raiun did not sign you out.';
  } catch (error) {
    if (isCurrentAccount(epoch) && generation === proxyUi.generation && !isStaleAccountRequest(error)) {
      proxyUi.error = messageOf(error) || 'Proxy settings could not be saved.';
      if (proxyUi.error.toLowerCase().includes('changed')) {
        proxyUi.loadedEpoch = -1;
      }
    }
  } finally {
    state.mutationBusy = Math.max(0, state.mutationBusy - 1);
    if (generation === proxyUi.generation) {
      proxyUi.saving = false;
      if (isCurrentAccount(epoch)) render();
    }
  }
}

function bandwidthLimitsAvailable() {
  return providerAvailable(state.status?.provider_supported) &&
    (!isWindowsAgentStatus(state.status) || state.status?.bandwidth_limits_supported === true);
}

async function loadBandwidthSettings(force = false) {
  if (!state.agentReachable || bandwidthUi.loading) return;
  const epoch = state.accountEpoch;
  if (!bandwidthLimitsAvailable()) {
    bandwidthUi.error = 'Transfer limits are unavailable for this Windows agent.';
    bandwidthUi.loadedEpoch = epoch;
    render();
    return;
  }
  if (!force && bandwidthUi.loadedEpoch === epoch) return;
  const generation = ++bandwidthUi.generation;
  bandwidthUi.loading = true;
  bandwidthUi.error = '';
  render();
  try {
    const saved = parseTransferLimitsReply(await request<unknown>('bandwidth_limits'), isWindowsAgentStatus(state.status));
    if (!isCurrentAccount(epoch) || generation !== bandwidthUi.generation) return;
    bandwidthUi.upload = formatTransferRate(saved.limits.upload_bytes_per_second);
    bandwidthUi.download = formatTransferRate(saved.limits.download_bytes_per_second);
    bandwidthUi.revision = saved.revision;
    bandwidthUi.accountId = saved.account_id;
    bandwidthUi.scopeToken = saved.scope_token;
    bandwidthUi.loadedEpoch = epoch;
  } catch (error) {
    if (isCurrentAccount(epoch) && generation === bandwidthUi.generation && !isStaleAccountRequest(error)) {
      bandwidthUi.error = 'Transfer limits could not be loaded from this agent.';
    }
  } finally {
    if (generation === bandwidthUi.generation) {
      bandwidthUi.loading = false;
      if (isCurrentAccount(epoch)) render();
    }
  }
}

async function saveBandwidthLimits() {
  const canEdit = state.agentReachable && !state.accountSwitching && state.mutationBusy === 0 &&
    !state.status?.authenticating && bandwidthUi.loadedEpoch === state.accountEpoch && Boolean(bandwidthUi.accountId) && !bandwidthUi.saving && !bandwidthUi.loading;
  if (!canEdit) return;
  const upload = parseTransferRateDraft(bandwidthUi.upload);
  const download = parseTransferRateDraft(bandwidthUi.download);
  if (!upload.ok || !download.ok) {
    bandwidthUi.error = !upload.ok ? upload.error : !download.ok ? download.error : 'Transfer limits are invalid.';
    render();
    return;
  }
  const epoch = state.accountEpoch;
  const generation = ++bandwidthUi.generation;
  bandwidthUi.saving = true;
  state.mutationBusy++;
  bandwidthUi.error = '';
  render();
  try {
    const saved = parseTransferLimitsReply(await request<unknown>('bandwidth_limits_set', {
      limits: {
        upload_bytes_per_second: upload.bytesPerSecond,
        download_bytes_per_second: download.bytesPerSecond,
      },
      expected_revision: bandwidthUi.revision,
      expected_account_id: bandwidthUi.accountId,
      ...(bandwidthUi.scopeToken ? { expected_scope_token: bandwidthUi.scopeToken } : {}),
    }), isWindowsAgentStatus(state.status));
    if (!isCurrentAccount(epoch) || generation !== bandwidthUi.generation) return;
    bandwidthUi.upload = formatTransferRate(saved.limits.upload_bytes_per_second);
    bandwidthUi.download = formatTransferRate(saved.limits.download_bytes_per_second);
    bandwidthUi.revision = saved.revision;
    bandwidthUi.accountId = saved.account_id;
    bandwidthUi.scopeToken = saved.scope_token;
    bandwidthUi.loadedEpoch = epoch;
    state.message = saved.apply_immediately
      ? 'Transfer limits saved and applied to this account’s active content transfers.'
      : 'Transfer limits saved for this account; they apply when its next connection starts.';
  } catch (error) {
    if (isCurrentAccount(epoch) && generation === bandwidthUi.generation && !isStaleAccountRequest(error)) {
      bandwidthUi.error = messageOf(error) || 'Transfer limits could not be saved.';
      if (bandwidthUi.error.toLowerCase().includes('changed')) bandwidthUi.loadedEpoch = -1;
    }
  } finally {
    state.mutationBusy = Math.max(0, state.mutationBusy - 1);
    if (generation === bandwidthUi.generation) {
      bandwidthUi.saving = false;
      if (isCurrentAccount(epoch)) render();
    }
  }
}

function bandwidthSettingsCard() {
  const providerEnabled = bandwidthLimitsAvailable();
  const canEdit = providerEnabled && state.agentReachable && !state.accountSwitching && state.mutationBusy === 0 &&
    !state.status?.authenticating && bandwidthUi.loadedEpoch === state.accountEpoch && Boolean(bandwidthUi.accountId) && !bandwidthUi.loading && !bandwidthUi.saving;
  const status = bandwidthUi.loading
    ? '<small role="status">Loading transfer limits…</small>'
    : bandwidthUi.error
      ? `<small class="network-proxy-error" role="alert">${esc(bandwidthUi.error)}${bandwidthUi.loadedEpoch === state.accountEpoch ? '' : ' <button class="text-button" data-action="load-bandwidth-limits">Try again</button>'}</small>`
    : !providerEnabled
      ? '<small>Transfer limits are unavailable for this Windows agent.</small>'
      : bandwidthUi.loadedEpoch !== state.accountEpoch
        ? '<small>Connect to the Raiun agent to view this account’s transfer limits.</small>'
        : bandwidthUi.accountId
          ? `<small>Account-scoped limit${bandwidthUi.accountId ? ` for ${esc(selectedAccountLabel())}` : ''}. Blank means unlimited. Changes apply to active content transfers immediately; sign-in and metadata requests are not limited.</small>`
          : '<small>Sign in to bind transfer limits to an account. Existing transfers keep their current limits.</small>';
  return `<section class="settings-card"><div class="settings-heading"><span class="settings-icon">${svg('refresh')}</span><div><h2>Transfer limits</h2><p>Set separate upload and download ceilings for file contents.</p></div></div><div class="settings-row"><div class="bandwidth-form"><label for="upload-limit-kib">Upload limit <span>KiB/s</span></label><input id="upload-limit-kib" inputmode="decimal" type="number" min="0.001" step="0.001" placeholder="Unlimited" value="${esc(bandwidthUi.upload)}" ${canEdit ? '' : 'disabled'}/><label for="download-limit-kib">Download limit <span>KiB/s</span></label><input id="download-limit-kib" inputmode="decimal" type="number" min="0.001" step="0.001" placeholder="Unlimited" value="${esc(bandwidthUi.download)}" ${canEdit ? '' : 'disabled'}/>${status}</div><button class="button primary" data-action="save-bandwidth-limits" ${canEdit ? '' : 'disabled'}>${bandwidthUi.saving ? 'Saving…' : 'Save limits'}</button></div></section>`;
}

function networkProxySettingsCard(connected: boolean, connection: ReturnType<typeof connectionMode>) {
  const providerEnabled = networkProxyAvailable();
  const active = proxyUi.config.mode === 'system'
    ? 'System proxy'
    : proxyUi.config.mode === 'direct'
      ? 'No proxy'
      : 'Explicit proxy';
  const offlineNamespace = state.status?.offline_namespace === true;
  const canEdit = providerEnabled && proxyEditorEnabled({
    reachable: state.agentReachable,
    connected,
    offlineNamespace,
    authenticating: state.status?.authenticating === true,
    saving: proxyUi.saving || proxyUi.loading,
    requiresSignOut: isWindowsAgentStatus(state.status) && state.status?.proxy_edit_requires_sign_out === true
  }) && state.mutationBusy === 0 && !state.accountSwitching && proxyUi.loadedEpoch === state.accountEpoch;
  const url = proxyUi.draftMode === 'explicit' ? `<label class="field-label" for="network-proxy-url">Proxy address</label><input id="network-proxy-url" class="network-proxy-url" value="${esc(proxyUi.draftUrl)}" placeholder="https://proxy.example.com:8443" autocomplete="off" spellcheck="false" ${canEdit ? '' : 'disabled'}/>` : '';
  const status = proxyUi.loading
    ? '<small role="status">Loading proxy settings…</small>'
    : proxyUi.error
      ? `<small class="network-proxy-error" role="alert">${esc(proxyUi.error)}${proxyUi.loadedEpoch === state.accountEpoch ? '' : ' <button class="text-button" data-action="load-network-proxy">Try again</button>'}</small>`
    : !providerEnabled
      ? '<small>Proxy settings are unavailable for this Windows agent.</small>'
      : proxyUi.loadedEpoch !== state.accountEpoch
        ? '<small>Connect to the Raiun agent to view this account’s proxy setting.</small>'
        : `<small>Current route: ${active}. This setting applies to sign-in, token refresh, and OpenCloud requests.</small>`;
  const restriction = isWindowsAgentStatus(state.status)
    ? (state.status?.proxy_edit_requires_sign_out === true
      ? '<p class="network-proxy-note">Sign out before changing the proxy. Then save the route to use for your next sign-in.</p>'
      : '<p class="network-proxy-note">Save the route to use for your next sign-in.</p>')
    : connected || offlineNamespace
    ? '<p class="network-proxy-note">Disconnect this account before changing its proxy. Raiun will not sign you out; save the setting, then reconnect to apply it.</p>'
    : '<p class="network-proxy-note">Saving does not sign you out. The new route is used the next time you connect.</p>';
  return `<section class="settings-card"><div class="settings-heading"><span class="settings-icon">${svg('cloud')}</span><div><h2>Network proxy</h2><p>Choose the route this account uses for OpenCloud sign-in and file traffic.</p></div></div><div class="settings-row"><div class="network-proxy-form"><label class="field-label" for="network-proxy-mode">Connection route</label><select id="network-proxy-mode" ${canEdit ? '' : 'disabled'}><option value="system" ${proxyUi.draftMode === 'system' ? 'selected' : ''}>Use system proxy settings</option><option value="direct" ${proxyUi.draftMode === 'direct' ? 'selected' : ''}>Connect directly</option><option value="explicit" ${proxyUi.draftMode === 'explicit' ? 'selected' : ''}>Use a proxy address</option></select>${url}${status}${restriction}</div><button class="button primary" data-action="save-network-proxy" ${canEdit && proxyUi.loadedEpoch === state.accountEpoch && state.agentReachable && !proxyUi.loading ? '' : 'disabled'}>${proxyUi.saving ? 'Saving…' : 'Save proxy'}</button></div></section>`;
}

function settingsPage() {
  const noAccounts = noAccountsAvailable();
  const connected = state.status?.connected === true;
  const canSignOut = state.agentReachable && (connected || state.status?.offline === true || state.status?.offline_namespace === true);
  const providerEnabled = providerAvailable(state.status?.provider_supported);
  const mountControls = mountControlState(providerEnabled, connected, state.status?.mounted === true, state.busy || state.mutationBusy > 0 || state.accountSwitching);
  const appearance = readAppearance({ getItem: key => window.localStorage.getItem(key) }, state.selectedAccount);
  const windowsAgent = isWindowsAgentStatus(state.status);
  if (windowsAgent) syncWindowsRecoveryContext();
  const connection = connectionMode(state.agentReachable, state.status);
  const retainedSignInOnly = state.status?.offline === true && state.status.offline_namespace !== true;
  const settingsSignIn = connection === 'sign_in' && !noAccounts
    ? windowsSignInPending()
      ? `<div class="signin-pending" role="status">Raiun is waiting for sign-in to finish in your browser.<button class="button subtle" data-action="cancel-sign-in" ${state.mutationBusy ? 'disabled' : ''}>Cancel sign-in</button></div>`
      : `<div class="signin-server settings-server"><input id="server-address" data-server value="${esc(state.server)}" placeholder="https://cloud.example.com" aria-label="OpenCloud server address"/><input id="client-id" data-client-id value="${esc(state.clientId)}" placeholder="Automatic client ID" aria-label="OAuth client ID override (optional)"/><button class="button primary" data-action="sign-in">Sign in</button></div>`
    : '';
  const canInspectRecoveries = state.agentReachable;
  const canOpenRecoveryFolder = canInspectRecoveries && Boolean(state.status?.recovery_folder);
  const canRemoveSelectedAccount = state.agentReachable && state.accountRemovalSupported && Boolean(state.selectedAccount)
    && Number.isSafeInteger(state.status?.auth_generation) && (state.status?.auth_generation ?? -1) >= 0 && !accountSwitchDisabled();
  const removedAccountSection = state.agentReachable && state.accountRemovalSupported
    ? `<details class="removed-accounts" ${noAccounts ? 'open' : ''}><summary>Removed accounts${state.removedAccounts.length ? ` (${state.removedAccounts.length})` : ''}</summary><p>Removed accounts keep their local files and recovery copies. Restoring an account does not sign it in again.</p>${state.removedAccounts.length ? state.removedAccounts.map(account => `<div class="settings-row removed-account-row"><div><b>${esc(account.label)}</b><small>Local files are preserved.</small></div><button class="button subtle" data-action="restore-removed-account" data-profile-id="${esc(account.id)}" ${accountSwitchDisabled() ? 'disabled' : ''}>Restore</button></div>`).join('') : '<small>No removed accounts.</small>'}</details>`
    : '';
  const recoveryPage = state.recoveryPage;
  const recoveryItemWarnings = recoveryPage?.items.reduce((count, item) => count + (item.warnings?.length || 0), 0) || 0;
  const recoveryNotice = recoveryPage && (recoveryPage.truncated || recoveryItemWarnings > 0 || recoveryPage.unrecognized_entries > 0)
    ? `<div class="recovery-warning" role="status">${recoveryPage.truncated ? 'The scan was truncated; this list may be incomplete. ' : ''}${recoveryItemWarnings ? `${recoveryItemWarnings} listed item warning(s) need review. ` : ''}${recoveryPage.unrecognized_entries ? `${recoveryPage.unrecognized_entries} entr${recoveryPage.unrecognized_entries === 1 ? 'y was' : 'ies were'} not recognized in this scan.` : ''}</div>`
    : '';
  const recoveryRows = recoveryPage?.items.length
    ? `<div class="recovery-list">${recoveryPage.items.map(recoveryCard).join('')}</div>`
    : recoveryPage
      ? `<div class="recovery-empty" role="status" aria-live="polite">${recoveryPage.warning_count || recoveryPage.unrecognized_entries ? 'No recognized saved copies were listed. Review the scan warnings above.' : 'No saved upload copies. Nothing to review.'}</div>`
      : '';
  return `<div class="page-title-row"><div><div class="eyebrow">PREFERENCES</div><h1>Settings</h1><p class="lede">Manage how Raiun works on this computer.</p></div></div>
    <div class="settings-stack"><section class="settings-card"><div class="settings-heading"><span class="settings-icon">${svg('settings')}</span><div><h2>Appearance</h2><p>Theme applies to all accounts. Color marks this account.</p></div></div><div class="settings-row appearance-settings-row"><label for="appearance-theme"><b>Theme</b><small>Use your system setting or choose a theme.</small></label><select id="appearance-theme" aria-label="Theme"><option value="system" ${appearance.theme === 'system' ? 'selected' : ''}>System</option><option value="light" ${appearance.theme === 'light' ? 'selected' : ''}>Light</option><option value="dark" ${appearance.theme === 'dark' ? 'selected' : ''}>Dark</option></select></div><div class="settings-row appearance-settings-row"><label for="appearance-accent"><b>Account color</b><small>${noAccounts ? 'Available when an account is active.' : 'Marks this account in the sidebar and header.'}</small></label><select id="appearance-accent" aria-label="Account color" ${state.selectedAccount ? '' : 'disabled'}><option value="ocean" ${appearance.accent === 'ocean' ? 'selected' : ''}>Ocean</option><option value="teal" ${appearance.accent === 'teal' ? 'selected' : ''}>Teal</option><option value="violet" ${appearance.accent === 'violet' ? 'selected' : ''}>Violet</option><option value="rose" ${appearance.accent === 'rose' ? 'selected' : ''}>Rose</option><option value="amber" ${appearance.accent === 'amber' ? 'selected' : ''}>Amber</option></select></div></section>
    <section class="settings-card"><div class="settings-heading"><span class="settings-icon">${svg('cloud')}</span><div><h2>${noAccounts ? 'No active account' : esc(selectedAccountLabel())}</h2><p>${noAccounts ? 'Add an account or restore one below. Restoring requires a new sign-in.' : `Sign-in and sync folders for this account.${featureAvailable('account_switch_supported') ? ' Other accounts keep syncing in the background.' : ''}`}</p></div></div><div class="settings-row account-settings-row"><div><b>${noAccounts ? 'Account status' : connection === 'unavailable' ? 'Agent status' : connection === 'offline_reconnecting' ? state.status?.refreshing ? 'Checking connection…' : retainedSignInOnly ? 'Reconnecting saved sign-in' : 'Working offline' : connected ? 'Connected server' : 'Sign in to OpenCloud'}</b><small>${noAccounts ? 'No account is selected. Use Add account or restore a removed account below.' : connection === 'unavailable' ? 'The Raiun agent is not reachable' : connection === 'offline_reconnecting' ? retainedSignInOnly ? 'The saved sign-in is available, but cloud files cannot be reached until the server reconnects.' : 'Raiun is reconnecting to the server. Your offline session remains available.' : connected ? esc(state.status?.server || 'This account is connected') : `Sign in to connect ${selectedAccountLabel()}`}</small>${connection === 'offline_reconnecting' ? connectionFailureDetails(state.status) : ''}${settingsSignIn}</div><div class="button-group"><button class="button subtle" data-action="refresh" ${connection === 'offline_reconnecting' && state.status?.refreshing ? 'disabled' : ''}>${connection === 'offline_reconnecting' ? state.status?.refreshing ? 'Checking…' : 'Retry connection' : 'Refresh'}</button>${canSignOut ? `<button class="button subtle" data-action="logout" title="Sign out of ${esc(selectedAccountLabel())}">Sign out</button>` : ''}${canRemoveSelectedAccount ? `<button class="button subtle danger-action" data-action="remove-selected-account">Remove account</button>` : ''}</div></div></section>
    ${removedAccountSection}
    <section class="settings-card"><div class="settings-heading"><span class="settings-icon">${svg('folder')}</span><div><h2>Cloud drive</h2><p>${noAccounts ? 'A drive location will be available after you add or restore and sign in to an account.' : providerEnabled ? 'This account’s OpenCloud location in the computer’s file manager. Save files inside Personal or a writable Space; the top-level folder is read-only.' : 'Windows cloud drive support is not enabled. Choosing a folder saves its setup, but does not mount or sync files.'}</p></div></div><div class="settings-row"><div><b>Mount status</b><small>${noAccounts ? 'No active account' : !providerEnabled ? state.status?.cloud_root ? `Configured but disconnected at ${esc(state.status.cloud_root)}` : 'Windows cloud drive is not mounted' : (connected || connection === 'offline_reconnecting') && state.status?.cloud_root ? `${state.status.mounted ? 'Mounted at' : 'Configured at'} ${esc(state.status.cloud_root)}` : 'No cloud drive location reported for this account'}</small></div><div class="button-group"><button class="button subtle" data-action="mount" ${noAccounts || mountControls.mountDisabled ? 'disabled' : ''}>Mount</button><button class="button subtle" data-action="unmount" ${noAccounts || mountControls.unmountDisabled ? 'disabled' : ''}>Unmount</button></div></div><div class="settings-row"><div><b>Choose location</b><small>Pick this account’s directory for the OpenCloud drive.</small></div><button class="button subtle" data-action="configure-root" ${!noAccounts && state.agentReachable && connected ? '' : 'disabled'}>Choose folder</button></div></section>
    ${networkProxySettingsCard(connected, connection)}
    ${bandwidthSettingsCard()}
    ${desktopUpdatesSettingsCard()}
    <section class="settings-card"><div class="settings-heading"><span class="settings-icon">${svg('lock')}</span><div><h2>Encrypted files</h2><p>${featureAvailable('vaults_supported') ? nativeVaultAccess() ? 'Unlock an encrypted Space or folder through the Windows drive. Supported existing-file saves are shown after unlock.' : 'Unlock an encrypted Space or folder to browse it. This does not add a sync folder; use the Encrypted files workspace.' : 'Encrypted file browsing is unavailable for this agent.'}</p></div></div><div class="settings-row"><div><b>Browse encrypted files</b><small>${nativeVaultAccess() ? 'Choose a Space, then unlock a location in the Windows drive. Save availability depends on the file and current connection. Encrypted offline copies are unavailable here.' : 'Choose a Space, then unlock an encrypted location. Offline edits, when available, apply only to supported operations in this unlocked location.'}</small></div><button class="button primary" data-page="encrypted" ${featureAvailable('vaults_supported') && state.agentReachable ? '' : 'disabled'}>Open Encrypted files</button></div></section>
    ${windowsAgent ? windowsRecoverySettingsCard() : `<section class="settings-card"><div class="settings-heading"><span class="settings-icon">${svg('folder')}</span><div><h2>Saved upload copies</h2><p>Raiun keeps local copies while uploads are pending or in progress.</p></div></div><div class="settings-row"><div><b>Saved copies</b><small>Review the local and OpenCloud paths. Viewing does not restore, upload, or delete files.</small></div><div class="button-group"><button class="button subtle" data-action="open-recovery" ${canOpenRecoveryFolder ? '' : 'disabled'}>Open folder</button><button class="button primary" data-action="load-recoveries" ${canInspectRecoveries && !state.recoveryLoading ? '' : 'disabled'}>${state.recoveryLoading ? 'Checking…' : recoveryPage ? 'Refresh list' : 'View saved copies'}</button></div></div>${!state.agentReachable ? `<p class="recovery-hint">Raiun is not connected.</p>` : !state.status?.recovery_folder ? `<p class="recovery-hint">No upload-copy folder is linked to this account yet. You can still check for saved copies; sign in to associate future copies with this account.</p>` : ''}${state.recoveryError ? `<div class="recovery-warning" role="alert">${esc(state.recoveryError)}</div>` : ''}${state.recoveryLoading ? `<div class="recovery-loading" role="status" aria-live="polite"><span class="spinner"></span> Checking saved copies…</div>` : ''}${recoveryNotice}${recoveryRows}${recoveryPage?.next_after && !state.recoveryLoading ? `<div class="recovery-more"><button class="button subtle" data-action="more-recoveries">Load more</button></div>` : ''}</section>${nativeVaultAccess() ? '' : encryptedEditRecoveryCard()}`}
    <section class="settings-card"><div class="settings-heading"><span class="settings-icon">${svg('play')}</span><div><h2>Startup</h2><p>Start Raiun when you sign in to this computer.</p></div></div><div class="settings-row"><div><b>Launch at login</b><small>${!providerEnabled ? 'Startup setting is unavailable for this Windows agent' : state.autostart == null ? 'Current setting is not reported by the agent' : state.autostart ? 'Raiun will start at login' : 'Raiun will not start at login'}</small></div><button class="button ${state.autostart ? 'subtle' : 'primary'}" data-action="toggle-autostart" ${providerEnabled && connected && typeof state.autostart === 'boolean' ? '' : 'disabled'}>${state.autostart ? 'Disable' : 'Enable'}</button></div></section>
    <section class="settings-card"><div class="settings-heading"><span class="settings-icon">${svg('pause')}</span><div><h2>Sync activity</h2><p>Pause background work across your folder pairs.</p></div></div><div class="settings-row"><div><b>${!featureAvailable('pause_supported') ? 'Windows folder sync is unavailable' : connection === 'offline_reconnecting' ? 'Working offline' : !connected ? 'Sign in to enable sync' : state.status?.paused ? 'Sync is paused' : 'Sync is enabled'}</b><small>${!featureAvailable('pause_supported') ? 'This agent does not support pausing folder sync.' : connection === 'offline_reconnecting' ? 'Raiun will retry the server connection; no new sign-in is needed.' : 'The current file may finish first. Opening cloud files can still use the network.'}</small></div><button class="button subtle" data-action="toggle-pause" ${featureAvailable('pause_supported') && connected ? '' : 'disabled'}>${state.status?.paused ? 'Resume sync' : 'Pause sync'}</button></div></section>
    <section class="settings-card"><div class="settings-heading"><span class="settings-icon">${svg('alert')}</span><div><h2>Diagnostics</h2><p>Export a redacted summary for the selected account with app version, platform, configuration counts, and connection status. It omits account identifiers, folder paths, credentials, and logs.</p></div></div><div class="settings-row"><div><b>Local support report</b><small>Choose a new file location. Existing files are never replaced.</small></div><button class="button subtle" data-action="export-diagnostics" ${!isTauri() || state.nativeDialogBusy ? 'disabled' : ''}>${state.nativeDialogBusy ? 'Preparing…' : 'Export report'}</button></div></section></div>`;
}
function desktopUpdateNotification() {
  const update = desktopUpdateUi.status;
  if (!update || !desktopUpdateNotificationVisible(update)) return '';
  const action = update.state === 'downloaded'
    ? `<button class="button primary" data-action="install-desktop-update" ${desktopUpdateUi.busy ? 'disabled' : ''}>Install update</button>`
    : update.state === 'available' && update.key_configured
      ? `<button class="button primary" data-action="download-desktop-update" ${desktopUpdateUi.busy ? 'disabled' : ''}>Download update</button>`
      : `<button class="button subtle" data-action="open-desktop-release" ${desktopUpdateUi.busy ? 'disabled' : ''}>Open release page</button>`;
  return `<aside class="toast success-toast" role="status" aria-live="polite"><span>${svg('refresh')}</span><div><b>Raiun Desktop ${esc(update.version)} is available.</b>${update.error ? `<small>${esc(update.error)}</small>` : '<small>Choose when to download and install this update.</small>'}</div>${action}<button data-action="later-desktop-update" aria-label="Later" title="Later">${svg('close')}</button></aside>`;
}

function leaveWorkspacePage(nextPage: Page) {
  if (state.page === 'offline' && nextPage !== 'offline') {
    state.pickerGeneration++;
    state.pickerOpen = false;
    state.pickerPurpose = 'pair';
    offlineUi.folderListing = null;
  }
  if (state.page === 'encrypted' && nextPage !== 'encrypted') {
    state.vaultAccessOpen = false;
    state.vaultAccessSpaceId = '';
    cachedVaultRootsUi.generation++;
    cachedVaultRootsUi.loading = false;
  }
}
function navigateToPage(page: Page) {
  if (page === 'offline') { leaveWorkspacePage(page); void openOfflineFiles(); return; }
  if (page === 'encrypted') { leaveWorkspacePage(page); void openEncryptedAccess(); return; }
  leaveWorkspacePage(page);
  state.page = page;
  if (page === 'settings') { void loadNetworkProxySettings(); void loadBandwidthSettings(); }
  if (page === 'transfers') {
    if (!isWindowsAgentStatus(state.status)) void loadPendingOfflineWrites(true);
    if (vaultAppFeaturesAvailable()) { void loadEncryptedEditRecoveries(true); void refreshEncryptedRetryLatestStatuses(); }
  } else stopEncryptedRetryLatestPolling();
  render();
}

function desktopUpdateNotificationVisible(update: DesktopUpdateStatus | null | undefined) {
  return Boolean(update?.tag && update.version && update.dismissed_tag !== update.tag && ['available', 'unavailable', 'downloaded'].includes(update.state));
}

function desktopUpdateManualControls(update: DesktopUpdateStatus | null | undefined, busy: boolean) {
  if (!update?.version || !update.tag || !update.release_url) return '';
  const updateAction = update.state === 'downloaded'
    ? `<button class="button primary" data-action="install-desktop-update" ${busy ? 'disabled' : ''}>${busy ? 'Preparing…' : 'Install update'}</button>`
    : (update.state === 'available' || update.state === 'dismissed') && update.key_configured
      ? `<button class="button primary" data-action="download-desktop-update" ${busy ? 'disabled' : ''}>${busy ? 'Checking and downloading…' : 'Download update'}</button>`
      : `<button class="button subtle" data-action="open-desktop-release" ${busy ? 'disabled' : ''}>Open release page</button>`;
  const stateDetail = update.state === 'unavailable'
    ? 'Automatic installation is not available for this release. The release page has the published downloads.'
    : update.key_configured ? 'The signed update package will be checked before it can be installed.'
      : 'This build has no embedded update verification key. Use the release page for manual downloads.';
  const notes = update.notes ? `<details class="update-notes"><summary>Release notes</summary><pre>${esc(update.notes)}</pre></details>` : '';
  return `<div class="settings-row"><div><b>Version ${esc(update.version)}</b><small>${stateDetail}</small></div><div class="button-group">${updateAction}<button class="button subtle" data-action="later-desktop-update">Later</button></div></div>${notes}`;
}

function desktopUpdatesSettingsCard() {
  const update = desktopUpdateUi.status;
  const stateLabel = !update ? 'Checking update settings…'
    : update.state === 'current' ? 'Raiun Desktop is up to date.'
      : update.state === 'downloaded' ? `Version ${update.version} is downloaded and signature-verified.`
        : update.state === 'available' || update.state === 'unavailable' || update.state === 'dismissed'
          ? `Version ${update.version || ''} is available.` : update.state === 'error'
            ? 'The update check needs attention.' : 'Ready to check for updates.';
  return `<section class="settings-card"><div class="settings-heading"><span class="settings-icon">${svg('refresh')}</span><div><h2>App updates</h2><p>Check GitHub for Raiun Desktop releases. Updates are downloaded only when you choose Download and installed only after you choose Install.</p></div></div><div class="settings-row"><div><b>${esc(stateLabel)}</b><small>${desktopUpdateUi.busy ? 'Checking release and signature…' : update?.error ? esc(update.error) : update?.last_check_unix ? `Last checked ${new Date(update.last_check_unix * 1000).toLocaleString()}` : 'Automatic checks run at most once a day.'}</small></div><div class="button-group"><button class="button subtle" data-action="check-desktop-update" ${desktopUpdateUi.busy ? 'disabled' : ''}>${desktopUpdateUi.busy ? 'Checking…' : 'Check now'}</button></div></div><div class="settings-row"><label for="desktop-update-auto"><b>Automatic checks</b><small>Check once a day while Raiun Desktop is open.</small></label><input id="desktop-update-auto" type="checkbox" ${update?.automatic_checks !== false ? 'checked' : ''} ${desktopUpdateUi.busy ? 'disabled' : ''}/></div><div class="settings-row"><label for="desktop-update-channel"><b>Release channel</b><small>Beta includes preview releases. Stable includes general releases only.</small></label><select id="desktop-update-channel" ${desktopUpdateUi.busy ? 'disabled' : ''}><option value="stable" ${update?.channel === 'stable' ? 'selected' : ''}>Stable</option><option value="beta" ${!update || update.channel === 'beta' ? 'selected' : ''}>Beta</option></select></div>${desktopUpdateManualControls(update, desktopUpdateUi.busy)}${desktopUpdateUi.error ? `<div class="recovery-warning" role="alert">${esc(desktopUpdateUi.error)}</div>` : ''}</section>`;
}

function windowsRecoverySettingsCard() {
  const { eligibility, context } = windowsRecoveryBinding();
  const recovery = windowsRecoveryController.state;
  const reason = !eligibility.available && eligibility.reason === 'agent_unreachable'
    ? 'Raiun is not connected. Saved Windows edits were not checked.'
    : !eligibility.available && eligibility.reason === 'account_disconnected'
      ? 'Connect this Windows account before checking saved edits.'
      : !eligibility.available && eligibility.reason === 'root_unavailable'
        ? state.status?.root_configuration?.registration_state === 'prepared_not_registered'
          ? 'Windows drive support is not enabled for this folder yet. Saved edits remain in place.'
          : 'This Windows drive is not ready to show saved edits yet. Local copies remain in place.'
        : !eligibility.available && eligibility.reason === 'invalid_generation'
          ? 'Refresh the account status before checking saved edits.'
          : !eligibility.available ? 'Select the current Windows account before checking saved edits.' : '';
  const rows = recovery.page?.items.length
    ? `<div class="recovery-list">${recovery.page.items.map(item => `<article class="recovery-card"><div class="recovery-card-title"><div><b>${esc(item.path.split('/').filter(Boolean).at(-1) || item.path)}</b><small>${esc(item.path)}</small></div><span class="recovery-badge warning">Needs review</span></div><div class="recovery-meta"><span>${esc(item.space_id)}</span><span>${esc(formatBytes(item.bytes))}</span></div><small>Saved locally · cloud upload has not been confirmed</small></article>`).join('')}</div>`
    : recovery.page
      ? '<div class="recovery-empty" role="status" aria-live="polite">No saved edits need review in this scan.</div>'
      : '';
  return `<section class="settings-card windows-recovery-card"><div class="settings-heading"><span class="settings-icon">${svg('folder')}</span><div><h2>Saved file edits</h2><p>Local copies of edits to files on this Windows computer. Viewing this list does not change the files.</p></div></div><div class="settings-row"><div><b>Saved edits</b><small>${context ? 'Cloud completion is not confirmed by this list.' : 'Availability depends on the current account and Windows folder.'}</small></div><button class="button primary" data-action="load-windows-recovery" ${!context || recovery.loading ? 'disabled' : ''}>${recovery.loading ? 'Checking…' : recovery.page ? 'Refresh list' : 'Check saved edits'}</button></div>${reason ? `<p class="recovery-hint" role="status">${esc(reason)}</p>` : ''}${recovery.error ? `<div class="recovery-warning" role="alert">${esc(recovery.error)}</div>` : ''}${recovery.loading ? '<div class="recovery-loading" role="status" aria-live="polite"><span class="spinner"></span> Checking local saved edits…</div>' : ''}${rows}${recovery.page?.next_after ? `<div class="recovery-warning" role="status">${recovery.page.items.length} saved edits are shown. More edits are saved locally; this list is incomplete.</div>` : ''}</section>`;
}

function encryptedEditRecoveryCard() {
  if (nativeVaultAccess()) return '';
  const page = state.encryptedEditRecoveryPage;
  const counts = page?.counts;
  const rows = page?.items.length
    ? `<div class="encrypted-edit-list">${page.items.map(item => {
      const labels = { building: 'Local copy is still being prepared', pending: 'Waiting or active', uncertain: 'Status uncertain', committed: 'Upload previously recorded', clean: 'No pending edit recorded', corrupt: 'Needs review' };
      const warning = item.warning ? `<small class="encrypted-edit-warning">${esc(item.warning)}</small>` : '';
      return `<article class="encrypted-edit-item"><div><b>${esc(item.record_id || 'Unrecognized saved copy')}</b><small>${item.bytes == null ? 'Size unavailable' : esc(formatBytes(item.bytes))}</small>${warning}</div><span class="encrypted-edit-badge ${item.state === 'clean' ? '' : 'warning'}">${labels[item.state]}</span></article>`;
    }).join('')}</div>`
    : page ? `<div class="recovery-empty" role="status" aria-live="polite">${page.scanned_entries === 0 ? 'No saved encrypted-file edits. Nothing to review.' : 'No entries on this page.'}</div>` : '';
  const summary = counts ? `<div class="encrypted-edit-summary">${counts.building ? `${counts.building} local copy reservation(s) still being prepared · ` : ''}${counts.pending ? `${counts.pending} needing review · ` : ''}${counts.uncertain ? `${counts.uncertain} uncertain · ` : ''}${counts.committed ? `${counts.committed} upload record(s) · ` : ''}${counts.clean ? `${counts.clean} with no pending edit · ` : ''}${counts.corrupt ? `${counts.corrupt} metadata warning(s)` : ''}</div>` : '';
  return `<section class="settings-card"><div class="settings-heading"><span class="settings-icon">${svg('lock')}</span><div><h2>Saved encrypted-file edits</h2><p>Local working copies of edits to encrypted OpenCloud files. These copies are readable plaintext on this computer.</p></div></div><div class="settings-row"><div><b>Local recovery records</b><small>This list only shows local record status. It does not force an upload, restore, or delete these copies.</small></div><div class="button-group"><button class="button subtle" data-action="open-encrypted-edit-folder" ${state.status?.encrypted_edit_recovery_available ? '' : 'disabled'}>Open folder</button><button class="button primary" data-action="load-encrypted-edit-recoveries" ${state.agentReachable && !state.encryptedEditRecoveryLoading ? '' : 'disabled'}>${state.encryptedEditRecoveryLoading ? 'Checking…' : page ? 'Refresh list' : 'View saved edits'}</button></div></div>${state.encryptedEditRecoveryError ? `<div class="recovery-warning" role="alert">${esc(state.encryptedEditRecoveryError)}</div>` : ''}${state.encryptedEditRecoveryLoading ? `<div class="recovery-loading" role="status" aria-live="polite"><span class="spinner"></span> Checking local recovery records…</div>` : ''}${page?.truncated ? `<div class="recovery-warning" role="status">The scan reached its safety limit; this list may be incomplete.</div>` : ''}${summary}${rows}${page?.next_after && !state.encryptedEditRecoveryLoading ? `<div class="recovery-more"><button class="button subtle" data-action="more-encrypted-edit-recoveries">Load more</button></div>` : ''}</section>`;
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
  const available = nativeVaultAccess() ? state.spaces.filter(space => !space.encrypted) : state.spaces;
  const selected = state.spaces.find(s => s.id === state.spaceId);
  const destinationWritable = selected?.writable === true && (!state.vaultBinding || state.vaultWritable);
  return `<div class="modal-backdrop" data-backdrop="add"><section class="modal" role="dialog" aria-modal="true" aria-labelledby="add-title"><div class="modal-top"><div><div class="eyebrow">NEW CONNECTION</div><h2 id="add-title">Add a sync folder</h2></div><button class="icon-button" data-action="close-add" aria-label="Close">${svg('close')}</button></div><p class="modal-lede">Choose a folder on this computer and the place it belongs in OpenCloud.</p>
    <label class="field-label" for="localPath">Folder on this computer</label><div class="input-with-button"><input id="localPath" value="${esc(state.localPath)}" placeholder="Select an existing folder" readonly /><button class="button subtle" data-action="choose-local">Browse</button></div>
    <label class="field-label" for="spaceSelect">OpenCloud location</label><select id="spaceSelect" ${state.spacesLoading || !state.spaces.length ? 'disabled' : ''}><option value="">${state.spacesLoading ? 'Loading Spaces…' : state.spacesError ? 'Spaces unavailable' : state.spaces.length ? 'Choose a Space' : 'No Spaces available'}</option>${available.map(space => `<option value="${esc(space.id)}" ${state.spaceId === space.id ? 'selected' : ''}>${space.personal ? 'Personal' : 'Space'} · ${esc(space.name)}${space.encrypted ? ' · encrypted' : space.writable ? '' : ' · read only'}</option>`).join('')}</select>
    ${state.spacesError ? `<div class="spaces-load-error" role="alert">Could not load Spaces: ${esc(state.spacesError)} <button class="text-button" data-action="refresh-spaces">Try again</button></div>` : ''}
    ${selected ? `<button class="remote-pick-row" data-action="choose-remote"><span class="remote-pick-icon">${svg(state.vaultBinding ? 'lock' : 'folder')}</span><span><small>${state.vaultBinding ? 'ENCRYPTED FOLDER' : 'REMOTE FOLDER'}</small><b>${esc(selected.name)}${esc(state.vaultBinding ? `${state.vaultBinding.root_path}${state.remotePath === '/' ? '' : state.remotePath}` : state.remotePath || ' · Choose a folder')}</b></span>${svg('chevron')}</button>` : `<div class="remote-pick-row disabled"><span class="remote-pick-icon">${svg('folder')}</span><span><small>REMOTE FOLDER</small><b>Select a Space first</b></span></div>`}
    <label class="field-label" for="modeSelect">Sync direction</label><select id="modeSelect"><option value="two_way" ${state.mode === 'two_way' ? 'selected' : ''} ${destinationWritable ? '' : 'disabled'}>Two-way · keep both sides in sync</option><option value="upload_only" ${state.mode === 'upload_only' ? 'selected' : ''} ${destinationWritable ? '' : 'disabled'}>Upload only · send local changes to OpenCloud</option><option value="download_only" ${state.mode === 'download_only' ? 'selected' : ''}>Download only · receive OpenCloud changes</option></select>${selected && !destinationWritable ? '<small class="vault-hint">This Space or encrypted folder is read only. Choose Download only.</small>' : ''}
    <div class="helper-note">${state.vaultBinding ? 'Your local folder remains plaintext on this computer. Locking the vault stops encrypted sync but does not remove local copies.' : 'Removing a folder pair later removes the connection only. It will not delete your local or cloud files.'}</div><div class="modal-actions"><button class="button subtle" data-action="close-add">Cancel</button><button class="button primary" data-action="save-pair" ${(state.localPath && state.spaceId && state.remotePath) ? '' : 'disabled'}>${svg('plus')} Add folder</button></div></section></div>`;
}
function addAccountModal() {
  const blocked = state.addAccountBusy;
  if (state.status?.account_setup_requires_sign_in === true && state.addAccountStep === 'details') {
    return `<div class="modal-backdrop" data-backdrop="account"><section class="modal account-modal" role="dialog" aria-modal="true" aria-labelledby="account-title"><div class="modal-top"><div><div class="eyebrow">ANOTHER CLOUD ACCOUNT</div><h2 id="account-title">Add an account</h2></div><button class="icon-button" data-action="close-add-account" aria-label="Close" ${blocked ? 'disabled' : ''}>${svg('close')}</button></div><p class="modal-lede">Choose a label now. Next, sign in from Settings and choose this account’s separate Windows drive folder.</p><label class="field-label" for="account-label">Account label</label><input class="account-form-input" id="account-label" value="${esc(state.addAccountLabel)}" placeholder="For example, Work" maxlength="80" ${blocked ? 'disabled' : ''}/>${state.addAccountError ? `<div class="account-setup-error" role="alert">${esc(state.addAccountError)}</div>` : ''}<div class="modal-actions"><button class="button subtle" data-action="close-add-account" ${blocked ? 'disabled' : ''}>Cancel</button><button class="button primary" data-action="save-account" ${blocked || !state.addAccountLabel.trim() ? 'disabled' : ''}>${blocked ? 'Adding…' : 'Add account'}</button></div></section></div>`;
  }
  const connected = state.status?.connected === true;
  const mounted = state.status?.mounted === true;
  const ready = connected && mounted;
  if (state.addAccountStep === 'waiting') {
    const waitingMessage = ready
      ? 'Signed in and drive mounted. This account is ready.'
      : connected
        ? 'Signed in, but the drive is not mounted yet.'
        : state.status?.authenticating
          ? 'Finish sign-in in the browser. Raiun is waiting for the account to connect.'
          : 'Finish sign-in in the browser. Raiun will check the connection here.';
    const statusDetail = connected && !mounted
      ? state.status?.error || 'Raiun could not confirm that this account drive is mounted. Try mounting it again or open Settings.'
      : !connected && state.status?.error
        ? state.status.error
        : '';
    return `<div class="modal-backdrop" data-backdrop="account"><section class="modal account-modal" role="dialog" aria-modal="true" aria-labelledby="account-title"><div class="modal-top"><div><div class="eyebrow">ACCOUNT SETUP · STEP 2 OF 2</div><h2 id="account-title">${ready ? 'Drive ready' : connected ? 'Finish drive setup' : 'Finish sign-in'}</h2></div><button class="icon-button" data-action="close-add-account" aria-label="Close setup" ${blocked ? 'disabled' : ''}>${svg('close')}</button></div><p class="modal-lede">${esc(waitingMessage)} Other accounts continue syncing in the background.</p><div class="account-setup-status ${ready ? 'ready' : connected ? 'warning' : ''}" role="status"><b>${esc(state.addAccountLabel)}</b><span>${esc(state.addAccountServer)}</span>${!connected && state.addAccountAuthMessage ? `<small>${esc(state.addAccountAuthMessage)}</small>` : ''}${statusDetail ? `<p>${esc(statusDetail)}</p>` : ''}${!connected && !state.addAccountAuthMessage && !state.addAccountError ? '<small>Sign-in opens in your browser. Return here when you have approved access.</small>' : ''}</div>${state.addAccountError ? `<div class="account-setup-error" role="alert">${esc(state.addAccountError)}</div>` : ''}<div class="helper-note">Raiun will mount this account’s separate drive after sign-in. Setup is complete only when this page reports that the drive is mounted. You can change sign-in details later in Settings.</div><div class="modal-actions">${ready ? `<button class="button primary" data-action="finish-account-setup">Done</button>` : `${connected ? `<button class="button subtle" data-action="retry-account-mount" ${blocked ? 'disabled' : ''}>${blocked ? 'Checking…' : 'Try mounting drive'}</button>` : `<button class="button primary" data-action="retry-account-signin" ${blocked ? 'disabled' : ''}>${blocked ? 'Opening sign-in…' : state.addAccountAuthStarted ? 'Open sign-in again' : 'Start sign-in'}</button>`}`}<button class="button subtle" data-action="close-add-account" ${blocked ? 'disabled' : ''}>Finish later</button></div></section></div>`;
  }
  const server = normalizeServerAddress(state.addAccountServer);
  const canSubmit = state.addAccountLabel.trim() && state.addAccountRoot && server.ok;
  return `<div class="modal-backdrop" data-backdrop="account"><section class="modal account-modal" role="dialog" aria-modal="true" aria-labelledby="account-title"><div class="modal-top"><div><div class="eyebrow">ANOTHER CLOUD ACCOUNT · STEP 1 OF 2</div><h2 id="account-title">Set up an account</h2></div><button class="icon-button" data-action="close-add-account" aria-label="Close" ${blocked ? 'disabled' : ''}>${svg('close')}</button></div><p class="modal-lede">Add the account details and sign in as one setup. Each account keeps its own drive location, Personal space, and Spaces.</p><label class="field-label" for="account-label">Account label</label><input class="account-form-input" id="account-label" value="${esc(state.addAccountLabel)}" placeholder="For example, Work" maxlength="80" ${blocked ? 'disabled' : ''}/><label class="field-label" for="account-server">OpenCloud server</label><input class="account-form-input" id="account-server" value="${esc(state.addAccountServer)}" placeholder="https://cloud.example.com" autocomplete="url" ${blocked ? 'disabled' : ''}/><label class="field-label" for="account-client-id">OAuth client ID <span class="field-optional">optional</span></label><input class="account-form-input" id="account-client-id" value="${esc(state.addAccountClientId)}" placeholder="Automatic client ID" ${blocked ? 'disabled' : ''}/><label class="field-label" for="account-root">OpenCloud drive folder</label><div class="input-with-button"><input id="account-root" value="${esc(state.addAccountRoot)}" placeholder="Choose a separate folder" readonly/><button class="button subtle" data-action="choose-account-root" ${blocked ? 'disabled' : ''}>Browse</button></div>${state.addAccountError ? `<div class="account-setup-error" role="alert">${esc(state.addAccountError)}</div>` : ''}<div class="helper-note">This folder is dedicated to this account. Raiun will try to mount its drive after sign-in; you can finish later if sign-in or mounting needs attention. Existing accounts keep running.</div><div class="modal-actions"><button class="button subtle" data-action="close-add-account" ${blocked ? 'disabled' : ''}>Cancel</button><button class="button primary" data-action="save-account" ${blocked || !canSubmit ? 'disabled' : ''}>${blocked ? 'Setting up…' : 'Add account & sign in'}</button></div></section></div>`;
}
function pickerModal() {
  const currentSpace = state.spaces.find(s => s.id === state.spaceId);
  const browseOnly = state.pickerPurpose === 'encrypted_access';
  const offlineMode = state.pickerPurpose === 'offline';
  const pickerBody = offlineMode ? offlinePickerBody(currentSpace) : `<div class="picker-breadcrumb">${svg('cloud')}<span>${esc(currentSpace?.personal ? 'Personal' : currentSpace?.name || 'Space')}</span>${esc(state.pickerPath)}</div>${browseOnly ? '<p class="picker-access-note">Open a folder and choose an encrypted folder to unlock. This browse-only flow does not add a sync folder.</p>' : ''}
  ${state.pickerError ? `<div class="picker-error" role="alert">${svg('alert')} ${esc(state.pickerError)}</div>` : ''}${!browseOnly && state.pickerWritable[state.pickerPath] && !currentSpace?.encrypted ? `<div class="picker-create"><input id="picker-folder-name" value="${esc(state.pickerFolderName)}" placeholder="New folder name" aria-label="New folder name" maxlength="255" ${state.pickerCreatingFolder ? 'disabled' : ''}/><button class="button subtle" data-action="create-folder" ${state.pickerCreatingFolder ? 'disabled' : ''}>${state.pickerCreatingFolder ? 'Creating…' : 'Create folder'}</button>${nativeVaultAccess() ? '' : `<button class="button subtle" data-action="create-vault" ${state.pickerCreatingFolder ? 'disabled' : ''}>Create encrypted folder</button>`}</div>` : ''}<div class="remote-list">${state.pickerPath !== '/' && !currentSpace?.encrypted ? `<button class="remote-entry parent-entry" data-remote-path="${esc(parentPath(state.pickerPath))}">${svg('folder')}<span>..</span>${svg('chevron')}</button>` : ''}${state.pickerEntries.length ? state.pickerEntries.filter(entry => entry.directory && !(nativeVaultAccess() && entry.encrypted && !browseOnly)).map(entry => `<button class="remote-entry ${entry.encrypted ? 'vault-entry' : ''}" ${entry.encrypted ? `data-vault-root="${esc(entry.path)}"` : `data-remote-path="${esc(entry.path)}"`}>${svg(entry.encrypted ? 'lock' : 'folder')}<span>${esc(lastPath(entry.path))}${entry.encrypted ? ' · encrypted folder' : ''}${windowsPortabilityNote(entry)}</span>${svg('chevron')}</button>`).join('') : `<div class="remote-empty">${state.pickerError ? 'Folder listing unavailable.' : 'No folders in this location.'}</div>`}</div><div class="modal-actions"><button class="button subtle" data-action="close-picker" ${state.pickerCreatingFolder ? 'disabled' : ''}>Cancel</button>${browseOnly ? '<span class="picker-access-footer">Choose an encrypted folder above</span>' : `<button class="button primary" data-action="select-remote" ${state.pickerCreatingFolder || !(state.pickerWritable[state.pickerPath] || state.mode === 'download_only') ? 'disabled' : ''}>Use this folder</button>`}</div>`;
  return `<div class="modal-backdrop" data-backdrop="picker"><section class="modal picker-modal ${offlineMode ? 'offline-picker-modal' : ''}" role="dialog" aria-modal="true" aria-labelledby="picker-title"><div class="modal-top"><div><div class="eyebrow">${esc(currentSpace?.name || 'OPENCloud')}</div><h2 id="picker-title">${offlineMode ? 'Manage offline files' : browseOnly ? 'Find an encrypted folder' : 'Choose remote folder'}</h2></div><button class="icon-button" data-action="close-picker" aria-label="Close" ${state.pickerCreatingFolder ? 'disabled' : ''}>${svg('close')}</button></div>${pickerBody}</section></div>`;
}
function offlinePickerBody(currentSpace: Space | undefined) {
  const cache = state.status?.offline_cache;
  const options = state.spaces.map(space => `<option value="${esc(space.id)}" ${state.spaceId === space.id ? 'selected' : ''} ${space.encrypted ? 'disabled' : ''}>${space.personal ? 'Personal' : 'Space'} · ${esc(space.name)}${space.encrypted ? ' · encrypted, not available offline yet' : ''}</option>`).join('');
  const pin = offlineUi.pin && offlineUi.pin.accountEpoch === state.accountEpoch && offlineUi.pin.space_id === state.spaceId ? offlineUi.pin : null;
  const pinRunning = !!pin && (pin.state === 'preparing' || pin.state === 'building');
  const pinProgress = pin?.state === 'preparing'
    ? 'Preparing folder contents…'
    : pin?.state === 'stale'
      ? 'Refreshing this snapshot; older verified bytes are retained.'
    : pin?.state === 'unavailable'
      ? 'This copy is not available offline because the cloud location changed.'
    : pin
      ? `${pin.files_done} of ${pin.files_total} files ready${pin.item_count ? ` · ${pin.item_count} items found` : ''}`
      : '';
  const pinCard = pin ? `<div class="offline-pin-status ${pin.state}" role="status" aria-live="polite"><div><b>${pin.state === 'ready' ? 'Folder snapshot verified' : pin.state === 'stale' ? 'Refreshing folder snapshot' : pin.state === 'unavailable' ? 'Folder copy unavailable offline' : pin.state === 'failed' ? 'Could not finish making this folder available offline' : pin.state === 'cancelled' ? 'Offline download cancelled' : pin.cancel_requested ? 'Cancelling offline download…' : 'Making folder available offline'}</b><small>${esc(pin.path)} · ${esc(pinProgress)}</small>${pin.error ? `<small>${esc(pin.error)}</small>` : ''}${pin.poll_error ? `<small>Progress update failed: ${esc(pin.poll_error)}</small>` : ''}</div>${pinRunning && !pin.cancel_requested ? '<button class="button subtle" data-action="cancel-offline-pin">Cancel</button>' : (pin.state === 'ready' || pin.state === 'stale' || pin.state === 'unavailable') && pin.pin_id ? `<button class="button subtle" data-unpin-offline="${esc(pin.pin_id)}">${pin.state === 'stale' ? 'Remove stale snapshot' : pin.state === 'unavailable' ? 'Remove unavailable copy' : 'Stop keeping offline'}</button>` : ''}</div>` : '';
  const canPin = cache?.available === true && currentSpace?.encrypted === false && state.status?.connected === true && !!state.spaceId;
  const pinsKey = offlinePinsKey(state.spaceId);
  const entries = state.pickerEntries.length ? state.pickerEntries.slice(0, 300).map(entry => offlineEntryRow(entry)).join('') : `<div class="remote-empty">${state.pickerError ? 'Folder listing unavailable.' : 'No files or folders in this location.'}</div>`;
  return `<p class="offline-browser-note">Offline copies use storage on this computer. Raiun checks for updates about every five minutes while it is running and connected; refreshes can be delayed while offline. Raiun must stay running to provide copies from the OpenCloud drive when you’re offline.</p>${state.status?.connected !== true ? '<div class="offline-cache-unavailable" role="status">Connect this account to change offline availability.</div>' : ''}<label class="field-label" for="offline-space">OpenCloud Space</label><select id="offline-space" ${state.spacesLoading || !state.spaces.length ? 'disabled' : ''}><option value="">${state.spacesLoading ? 'Loading Spaces…' : state.spacesError ? 'Spaces unavailable' : 'Choose a Space'}</option>${options}</select>${state.spacesError ? `<div class="picker-error" role="alert">${esc(state.spacesError)}</div>` : ''}${cache?.available !== true ? '<div class="offline-cache-unavailable" role="status">Offline storage is not available for this account.</div>' : `<div class="offline-cache-usage">${esc(formatBytes(cache.used_bytes))} used of ${esc(formatBytes(cache.quota_bytes))} · ${esc(formatBytes(cache.pinned_bytes))} pinned${cache.over_quota ? ' · over the current storage limit' : ''}</div>`}${offlineUi.pinsLoading.has(pinsKey) ? '<div class="offline-pin-list-loading" role="status">Checking saved folders…</div>' : ''}${offlineUi.error ? `<div class="picker-error" role="alert">${esc(offlineUi.error)}</div>` : ''}${persistedOfflinePins(currentSpace, pinsKey)}${pinCard}${currentSpace?.encrypted ? '<div class="offline-cache-unavailable" role="status">Encrypted Spaces cannot be cached offline yet. Their encrypted files stay online-only.</div>' : ''}${!currentSpace ? '<div class="remote-empty">Choose an unencrypted Space to manage offline files.</div>' : !currentSpace.encrypted ? `<div class="picker-breadcrumb">${svg('cloud')}<span>${esc(currentSpace.personal ? 'Personal' : currentSpace.name)}</span>${esc(state.pickerPath)}</div><div class="offline-folder-pin"><div><b>Keep this folder offline</b><small>Downloads the files in this folder and its subfolders. Raiun refreshes saved folders periodically while running and connected; changes can be delayed while offline.</small></div><button class="button subtle" data-pin-offline="${esc(state.pickerPath)}" ${!canPin || pinRunning ? 'disabled' : ''}>${pinRunning && pin?.path === state.pickerPath ? 'Preparing…' : 'Make available offline'}</button></div>${folderPolicyCurrentControl(state.pickerPath)}${state.pickerError ? `<div class="picker-error" role="alert">${svg('alert')} ${esc(state.pickerError)}</div>` : ''}<div class="offline-entry-list">${state.pickerPath !== '/' ? `<button class="remote-entry parent-entry" data-remote-path="${esc(parentPath(state.pickerPath))}">${svg('folder')}<span>..</span>${svg('chevron')}</button>` : ''}${entries}</div>${state.pickerEntries.length > 300 ? '<div class="offline-list-limit">Showing the first 300 entries. Open a subfolder to narrow the list.</div>' : ''}` : ''}<p class="offline-policy-note">“Recently used” changes folder cache policy only; it does not remove saved folder copies. Cloud only requires conflicting offline copies or file settings to be cleared first. Unsynced edits and recovery data stay protected.</p>`;
}
function persistedOfflinePins(currentSpace: Space | undefined, pinsKey: string) {
  const pins = offlineUi.pins.get(pinsKey) || [];
  if (!currentSpace || currentSpace.encrypted || pins.length === 0) return '';
  const rows = pins.map(pin => {
    const location = pin.path === '/' ? `${currentSpace.personal ? 'Personal' : 'Space'} root` : pin.path;
    const label = pin.path === '/' ? 'Space root' : lastPath(pin.path);
    const progress = pin.state === 'ready'
      ? `${pin.item_count} items · verified snapshot`
      : pin.state === 'stale'
        ? `${pin.item_count} items · refreshing; older verified bytes are retained`
        : pin.state === 'unavailable'
          ? `${pin.item_count} items · this copy is not available offline because the cloud location changed`
          : `${pin.files_done} of ${pin.files_total} files verified`;
    const key = offlinePinRemovalKey(currentSpace.id, pin.pin_id);
    const removing = offlineUi.pinsRemoving.has(key);
    const button = pin.state === 'stale' ? 'Remove stale snapshot' : pin.state === 'building' ? 'Stop folder download' : pin.state === 'unavailable' ? 'Remove unavailable copy' : 'Stop keeping offline';
    return `<div class="offline-saved-pin ${pin.state}"><span><b>${esc(label)}</b><small>${esc(location)} · ${esc(progress)}</small></span><button class="button subtle" data-unpin-offline="${esc(pin.pin_id)}" ${removing || state.status?.connected !== true ? 'disabled' : ''}>${removing ? 'Removing…' : button}</button></div>`;
  }).join('');
  return `<section class="offline-saved-pins" aria-label="Saved offline folder copies"><div><b>Saved folder copies</b><small>These are in ${esc(currentSpace.personal ? 'Personal' : currentSpace.name)}. You can remove a copy here, including one for the Space root.</small></div>${rows}</section>`;
}
function offlineEntryRow(entry: RemoteEntry) {
  const name = esc(lastPath(entry.path));
  if (entry.encrypted) return `<div class="offline-entry unavailable">${svg('lock')}<span><b>${name}</b><small>Encrypted · not available offline yet</small>${windowsPortabilityNote(entry)}</span></div>`;
  if (entry.directory) {
    const pin = entry.id ? offlineUi.pins.get(offlinePinsKey(state.spaceId))?.find(item => item.root_resource_id === entry.id) : undefined;
    const activeForEntry = offlineUi.pin?.accountEpoch === state.accountEpoch && offlineUi.pin.space_id === state.spaceId && offlineUi.pin.path === entry.path && ['preparing', 'building'].includes(offlineUi.pin.state);
    const pinLabel = pin?.state === 'ready' ? 'Verified offline copy' : pin?.state === 'stale' ? 'Refreshing; older copy retained' : pin?.state === 'unavailable' ? 'Unavailable offline; cloud location changed' : pin ? `${pin.files_done} of ${pin.files_total} files verified` : '';
    const pinControl = pin
      ? `<span class="offline-folder-pin-state" role="status">${esc(pinLabel)}</span>${activeForEntry ? '<span class="offline-saving" role="status">Use Cancel above to stop</span>' : ''}`
      : `<button class="button subtle" data-pin-offline="${esc(entry.path)}" ${state.status?.connected !== true || state.status?.offline_cache?.available !== true || offlineUi.pin?.state === 'preparing' || offlineUi.pin?.state === 'building' ? 'disabled' : ''}>Keep offline</button>`;
    return `<div class="offline-entry"><button class="remote-entry" data-remote-path="${esc(entry.path)}">${svg('folder')}<span>${name}${windowsPortabilityNote(entry)}</span>${svg('chevron')}</button>${folderPolicyRowControls(entry)}${pinControl}</div>`;
  }
  const key = offlinePolicyKey(entry.path);
  const policy = offlineUi.policies.get(key);
  const availabilityState = offlineUi.availabilityStates.get(key);
  const loading = offlineUi.policyLoading.has(key);
  const saving = offlineUi.policySaving.has(key);
  const policyControl = policy
    ? `<div class="offline-policy-control"><label class="offline-policy-select"><span class="sr-only">Offline availability for ${name}</span><select data-offline-policy-path="${esc(entry.path)}" ${saving || state.status?.connected !== true || state.status?.offline_cache?.available !== true ? 'disabled' : ''}><option value="cloud_only" ${policy === 'cloud_only' ? 'selected' : ''}>Cloud only</option><option value="recent" ${policy === 'recent' ? 'selected' : ''}>Recently used</option><option value="always_offline" ${policy === 'always_offline' ? 'selected' : ''}>Always available offline</option></select></label>${policy === 'always_offline' ? `<small class="offline-policy-state ${availabilityState || 'pending'}" role="status">${offlineAvailabilityLabel(availabilityState)}</small><button class="offline-check-status" data-load-offline-policy="${esc(entry.path)}" ${loading || state.status?.connected !== true ? 'disabled' : ''}>${loading ? 'Checking…' : 'Check status'}</button>` : ''}</div>`
    : `<button class="button subtle" data-load-offline-policy="${esc(entry.path)}" ${loading || state.status?.connected !== true || state.status?.offline_cache?.available !== true ? 'disabled' : ''}>${loading ? 'Checking…' : 'Set availability'}</button>`;
  return `<div class="offline-entry file-entry"><span class="offline-file-icon">${svg('media')}</span><span class="offline-entry-name"><b>${name}</b><small>${entry.size == null ? 'File' : esc(formatBytes(entry.size))}</small>${windowsPortabilityNote(entry)}</span>${saving ? '<span class="offline-saving" role="status">Saving and verifying…</span>' : policyControl}</div>`;
}
function folderPolicyControlsAvailable() {
  return !isWindowsAgentStatus(state.status) && providerAvailable(state.status?.provider_supported) && state.status?.offline_cache?.available === true;
}
function folderPolicyCurrentControl(path: string) {
  if (!folderPolicyControlsAvailable()) return '';
  const key = offlinePolicyKey(path);
  const policy = offlineUi.folderPolicies.get(key);
  const loading = offlineUi.folderPolicyLoading.has(key);
  const saving = offlineUi.folderPolicySaving.has(key);
  const disabled = loading || saving || state.status?.connected !== true || !offlineFolderIsCurrent(path, path, true, state.spaceId);
  const status = loading ? 'Checking folder policy…' : policy === 'cloud_only'
    ? 'Effective folder policy: Cloud only. A parent folder setting may apply.'
    : policy === 'recent' ? 'Effective folder policy: Recently used.' : 'Folder policy has not been checked.';
  return `<section class="offline-folder-pin" aria-label="Current folder cache policy"><div><b>Current folder policy</b><small>${esc(status)} Folder policy is separate from saved offline copies.</small></div><div class="offline-policy-control"><button class="button subtle" data-load-folder-policy="${esc(path)}" data-folder-listing-path="${esc(path)}" data-folder-current="true" ${disabled ? 'disabled' : ''}>${loading ? 'Checking…' : 'Check setting'}</button><button class="button subtle" data-set-folder-policy="cloud_only" data-folder-path="${esc(path)}" data-folder-listing-path="${esc(path)}" data-folder-current="true" ${disabled ? 'disabled' : ''}>Cloud only</button><button class="button subtle" data-set-folder-policy="recent" data-folder-path="${esc(path)}" data-folder-listing-path="${esc(path)}" data-folder-current="true" ${disabled ? 'disabled' : ''}>Recently used</button></div></section>`;
}
function folderPolicyRowControls(entry: RemoteEntry) {
  if (!folderPolicyControlsAvailable()) return '';
  const key = offlinePolicyKey(entry.path);
  const policy = offlineUi.folderPolicies.get(key);
  const loading = offlineUi.folderPolicyLoading.has(key);
  const saving = offlineUi.folderPolicySaving.has(key);
  const disabled = loading || saving || state.status?.connected !== true || !offlineFolderIsCurrent(entry.path, state.pickerPath, false, state.spaceId);
  const status = loading ? 'Checking…' : policy === 'cloud_only' ? 'Cloud only' : policy === 'recent' ? 'Recently used' : 'Not checked';
  return `<div class="offline-folder-policy-row" role="group" aria-label="Offline availability for ${esc(entry.path)}"><small role="status">${esc(status)}</small><button class="button subtle" data-load-folder-policy="${esc(entry.path)}" data-folder-listing-path="${esc(state.pickerPath)}" ${disabled ? 'disabled' : ''}>${loading ? 'Checking…' : 'Check policy'}</button><button class="button subtle" data-set-folder-policy="cloud_only" data-folder-path="${esc(entry.path)}" data-folder-listing-path="${esc(state.pickerPath)}" ${disabled ? 'disabled' : ''}>Cloud only</button><button class="button subtle" data-set-folder-policy="recent" data-folder-path="${esc(entry.path)}" data-folder-listing-path="${esc(state.pickerPath)}" ${disabled ? 'disabled' : ''}>Recently used</button></div>`;
}
function windowsPortabilityNote(entry: RemoteEntry) {
  const label = windowsPortabilityLabel(entry.windows_portability_warnings);
  return label ? `<small class="windows-compatibility-note">${esc(label)}</small>` : '';
}
function offlineAvailabilityLabel(availabilityState: OfflineAvailabilityState | undefined) {
  if (availabilityState === 'ready') return 'Verified for offline use';
  if (availabilityState === 'stale') return 'Refreshing; previous verified copy is retained';
  if (availabilityState === 'unavailable') return 'Offline copy unavailable';
  return 'Waiting for a verified offline copy';
}
function offlinePolicyKey(path: string) { return `${state.selectedAccount}\u0000${state.status?.server || ''}\u0000${state.spaceId}\u0000${path}`; }
function offlinePinsKey(spaceId: string) { return `${state.selectedAccount}\u0000${state.status?.server || ''}\u0000${spaceId}`; }
function offlinePinRemovalKey(spaceId: string, pinId: string) { return `${offlinePinsKey(spaceId)}\u0000${pinId}`; }

function encryptedAccessModal(workspace = false) {
  const selected = state.spaces.find(space => space.id === state.vaultAccessSpaceId);
  const connected = state.status?.connected === true;
  const canBrowse = connected && !!selected && !state.spacesLoading;
  const options = state.spaces.map(space => `<option value="${esc(space.id)}" ${state.vaultAccessSpaceId === space.id ? 'selected' : ''}>${space.personal ? 'Personal' : 'Space'} · ${esc(space.name)}${space.encrypted ? ' · encrypted' : space.writable ? '' : ' · read only'}</option>`).join('');
  const cachedOptions = cachedVaultRootsUi.roots.map(root => {
    const key = cachedVaultRootKey(root);
    const suffix = root.root_resource_id.length > 12 ? root.root_resource_id.slice(-8) : root.root_resource_id;
    const snapshotLabel = typeof root.pin_id === 'string' && root.pin_id && Number.isSafeInteger(root.generation) ? ` · verified offline copy · generation ${root.generation}` : ' · saved encrypted location';
    return `<option value="${esc(key)}" ${cachedVaultRootsUi.selected === key ? 'selected' : ''}>${esc(spaceName(root.space_id))}${snapshotLabel} · …${esc(suffix)}</option>`;
  }).join('');
  const cachedContent = copyProducerUi.source
    ? '<div class="vault-hint" role="status">Saved offline locations are read-only. Choose an online encrypted location for the copy destination.</div>'
    : cachedVaultRootsUi.loading && !cachedVaultRootsUi.roots.length
    ? '<div class="recovery-loading" role="status"><span class="spinner"></span> Checking saved encrypted locations…</div>'
    : cachedVaultRootsUi.roots.length
    ? `<label class="field-label" for="cached-encrypted-root">Saved encrypted locations</label><select id="cached-encrypted-root" ${cachedVaultRootsUi.loading ? 'disabled' : ''}>${cachedOptions}</select><small class="vault-hint">Names stay hidden until your password verifies the saved location. Only entries marked “verified offline copy” are complete encrypted snapshots. Offline edits, when available, apply only to supported operations in this unlocked location.</small><div class="cached-vault-actions"><button class="button subtle" data-action="more-cached-vault-roots" ${cachedVaultRootsUi.loading || !cachedVaultRootsUi.nextAfter ? 'disabled' : ''}>${cachedVaultRootsUi.loading ? 'Loading…' : 'Load more'}</button><button class="button primary" data-action="browse-cached-vault-root" ${cachedVaultRootsUi.loading || !cachedVaultRootsUi.selected ? 'disabled' : ''}>Unlock saved location</button></div>${cachedVaultRootsUi.truncated ? '<small class="vault-hint">Only a bounded list of saved locations is shown.</small>' : ''}`
      : `<div class="recovery-empty" role="status">${cachedVaultRootsUi.error ? 'Saved encrypted locations could not be checked.' : state.agentReachable ? 'No saved encrypted locations are available offline.' : 'Raiun is not connected.'}</div>`;
  const onlineContent = connected
    ? `<div class="encrypted-access-divider">Open a location online</div><label class="field-label" for="encrypted-access-space">OpenCloud location</label><select id="encrypted-access-space" ${state.spacesLoading || !state.spaces.length ? 'disabled' : ''}><option value="">${state.spacesLoading ? 'Loading Spaces…' : state.spacesError ? 'Spaces unavailable' : state.spaces.length ? 'Choose a Space' : 'No Spaces available'}</option>${options}</select>${state.spacesError ? `<div class="vault-error" role="alert">${esc(state.spacesError)} <button class="text-button" data-action="retry-encrypted-access-spaces">Try again</button></div>` : ''}<p class="vault-hint">An encrypted Space opens at its root. In a regular Space, browse folders and select an encrypted folder.</p><div class="modal-actions">${workspace ? '' : '<button class="button subtle" data-action="close-encrypted-access">Cancel</button>'}<button class="button primary" data-action="browse-encrypted-space" ${canBrowse ? '' : 'disabled'}>${state.spacesLoading ? 'Loading…' : selected?.encrypted ? 'Unlock Space' : 'Browse Space'}</button></div>`
    : '<div class="vault-hint" role="status">Connect this account to browse cloud locations. Saved encrypted locations may still be available below.</div>';
  const savedLocations = copyProducerUi.source || nativeVaultAccess() ? '' : `<section class="cached-vault-section"><div class="encrypted-access-divider">Saved encrypted locations</div>${cachedVaultRootsUi.error ? `<div class="vault-error" role="alert">${esc(cachedVaultRootsUi.error)} <button class="text-button" data-action="refresh-cached-vault-roots">Try again</button></div>` : ''}${cachedContent}<div class="cached-vault-actions"><button class="button subtle" data-action="refresh-cached-vault-roots" ${cachedVaultRootsUi.loading ? 'disabled' : ''}>Refresh saved locations</button></div></section>`;
  const sections = `${copyProducerUi.source ? '<button class="button subtle" data-action="cancel-vault-copy">Cancel copy</button>' : ''}${savedLocations}${onlineContent}`;
  const passwordHelp = `<details class="workspace-help"><summary>How remembered passwords work</summary><p>Your vault password is not saved unless you choose “Remember on this device.” When you opt in and the unlock succeeds, Raiun stores the password in the operating system’s protected credential store for this account and vault.</p><p>Locking a vault does not remove a saved password. Use “Forget saved key” in the unlock window to remove it. Saved encrypted snapshots are read-only while offline; other operations depend on the connected drive and supported features.</p></details>`;
  if (workspace) return `<div class="page-title-row"><div><div class="eyebrow">END-TO-END ENCRYPTION</div><h1>Encrypted files</h1><p class="lede">Unlock an encrypted Space or folder. This does not add a sync folder.</p></div></div><div class="settings-stack encrypted-workspace"><section class="settings-card">${sections}</section>${passwordHelp}</div>`;
  return `<div class="modal-backdrop" data-backdrop="encrypted-access"><section class="modal encrypted-access-modal" role="dialog" aria-modal="true" aria-labelledby="encrypted-access-title"><div class="modal-top"><div><div class="eyebrow">END-TO-END ENCRYPTION</div><h2 id="encrypted-access-title">${copyProducerUi.source ? 'Choose copy destination' : 'Unlock encrypted files'}</h2></div><button class="icon-button" data-action="close-encrypted-access" aria-label="Close">${svg('close')}</button></div><p class="modal-lede">${copyProducerUi.source ? `Choose another online encrypted location for ${esc(copyProducerUi.source.displayName)}. Raiun keeps the original file in place.` : 'Unlock this location to open its files from your OpenCloud drive. You do not need to set up a synced folder.'}</p>${sections}</section></div>`;
}
function encryptedWorkspacePage() { return encryptedAccessModal(true); }

function mountedVaultAccessMessage(
  writable: boolean | null,
  reason: VaultMountWriteUnavailableReason | null,
  routeReady: boolean,
  existingFileOverwrite = false,
  existingFileReason: VaultExistingOverwriteReason | null = null,
) {
  if (writable) return 'Encrypted files are available for reading and editing through the mounted OpenCloud drive.';
  if (existingFileOverwrite) return 'The mounted drive can queue supported file edits, file creation/rename/deletion, and folder creation while offline. A queued folder can contain files and folders. A queued-folder rename is limited to a never-attempted subtree of at most 64 operations and 64 MiB of file data; restart, child creation, and reconciliation passed in the R28 VM gate. Remote folder deletion is unsupported, though an empty never-attempted queued folder can be canceled locally when it has no open handles or dependent operations. Retry uploads after reconnecting.';
  if (writable === null && !reason) return 'Mounted-drive write availability could not be confirmed.';
  if (reason === 'offline_read_only' || reason === 'offline_existing_file_overwrite_only') {
    if (existingFileReason === 'drive_not_mounted') return 'The verified snapshot is open read-only. Mount the OpenCloud drive and enable private edit storage to use supported offline file and folder operations.';
    if (existingFileReason === 'private_spool_unavailable') return 'The verified snapshot is open read-only because private edit storage is unavailable. Supported offline file and folder operations are unavailable until it is ready.';
    return 'This verified encrypted snapshot is open read-only. Offline edits are unavailable until private edit storage and the mounted drive are ready.';
  }
  switch (reason) {
    case 'drive_not_mounted':
      return 'The OpenCloud drive is not mounted. Mount it in Settings to access this location there.';
    case 'route_read_only':
      return 'This location is available read-only through the mounted OpenCloud drive. Encrypted writes are not enabled for this route.';
    case 'private_spool_unavailable':
      return 'This location is available read-only through the mounted drive. Local encrypted-edit storage is not ready for writes.';
    case 'write_backend_unavailable':
      return 'This location is available read-only through the mounted drive. Encrypted writes are not available for this location.';
    case 'vault_locked':
      return 'This encrypted location is locked. Unlock it to make it available through the drive.';
    case 'route_not_installed':
      return 'This location is not available through the mounted drive yet.';
    default:
      return routeReady
        ? 'Mounted-drive writing is not available for this location.'
        : 'This location is not available through the mounted drive yet.';
}
}

function vaultOfflinePinPanel(flow: VaultDialogState) {
  if (nativeVaultAccess()) return '';
  if (!flow.unlocked || flow.statusUnknown || flow.intent === 'create') return '';
  const canStart = state.status?.connected === true && !flow.offlineUnlockOnly && !flow.loading && !flow.pinBusy && !flow.pinJob && !flow.pinsLoading;
  const rows = flow.pins.map(pin => {
    const jobMatchesPin = flow.pinJob?.pin_id === pin.id;
    const status = pin.state === 'ready' ? 'Verified snapshot available offline' : pin.state === 'stale' ? 'Snapshot needs refresh' : jobMatchesPin ? 'Snapshot is being prepared' : 'Snapshot setup was interrupted; this generation is not ready';
    const ready = pin.state === 'ready';
    const busy = flow.pinBusy || jobMatchesPin;
    const storedSize = offlineCopyStoredSizeLabel(pin.byte_len, formatBytes);
    return `<article class="vault-pin-row ${ready ? 'ready' : pin.state === 'stale' ? 'stale' : 'building'}"><div class="vault-pin-copy"><b>${ready ? 'Verified offline copy' : 'Encrypted offline copy'}</b><small>${status}${storedSize ? ` · ${storedSize}` : ''}</small></div><div class="vault-pin-actions"><button class="small-action" data-vault-pin-start="${esc(pin.id)}" ${!canStart || busy ? 'disabled' : ''}>${pin.state === 'building' || pin.state === 'stale' ? 'Try again' : 'Refresh'}</button><button class="small-action quiet" data-vault-pin-remove="${esc(pin.id)}" ${flow.pinBusy || !!flow.pinJob ? 'disabled' : ''}>Remove</button></div></article>`;
  }).join('');
  const job = flow.pinJob ? `<div class="vault-pin-progress" role="status"><div><b>${flow.pinJob.cancelRequested ? 'Stopping offline-copy setup…' : flow.pinJob.state === 'queued' ? 'Offline-copy setup queued' : 'Preparing offline copy…'}</b><small>Raiun is preparing and verifying this encrypted snapshot. The copy is not ready until verification finishes.</small></div><button class="small-action quiet" data-vault-pin-cancel ${flow.pinBusy || flow.pinJob.cancelRequested ? 'disabled' : ''}>${flow.pinJob.cancelRequested ? 'Stopping…' : 'Cancel'}</button></div>` : '';
  const empty = flow.pinsLoading && !flow.pins.length
    ? '<div class="vault-pin-empty" role="status"><span class="spinner"></span> Checking encrypted offline copies…</div>'
    : !flow.pinsLoading && !flow.pins.length
      ? '<div class="vault-pin-empty">No encrypted offline copy is saved for this location.</div>'
      : '';
  const start = !flow.pins.length
    ? `<button class="button subtle" data-vault-pin-start ${!canStart ? 'disabled' : ''}>${flow.pinBusy ? 'Starting…' : 'Keep available offline'}</button>`
    : '';
  const offlineNote = flow.offlineUnlockOnly
    ? flow.vaultMountExistingFileOverwrite
      ? '<small class="vault-pin-note">This saved snapshot is open offline. The mounted drive can queue supported file edits, file creation/rename/deletion, and folder creation; changes stay local until retry. A queued-folder rename is limited to a never-attempted subtree of at most 64 operations and 64 MiB of file data; restart, child creation, and reconciliation passed in the R28 VM gate. Remote folder deletion is unsupported, though an empty never-attempted queued folder can be canceled locally when it has no open handles or dependent operations.</small>'
      : '<small class="vault-pin-note">This location is open from its saved snapshot. It is read-only until the mounted drive and private edit storage are ready. Connect to refresh it.</small>'
    : !state.status?.connected
      ? '<small class="vault-pin-note">Connect this account to create or refresh an encrypted offline copy. Supported offline edits require an unlocked location, a mounted drive, and private edit storage.</small>'
      : '<small class="vault-pin-note">Raiun saves encrypted content on this device. You must unlock the vault to read it. Supported offline file and folder operations require the mounted drive and private edit storage to be ready. Saved copies are checked for refresh about once an hour while connected and unlocked; timing can be delayed while offline or busy.</small>';
  return `<section class="vault-pin-panel"><div class="vault-pin-heading"><div><b>Keep available offline</b><small>Encrypted snapshot for this location</small></div>${start}</div>${flow.pinsError ? `<div class="vault-error" role="alert">${esc(flow.pinsError)} <button class="text-button" data-vault-pin-refresh-list>Try again</button></div>` : ''}${flow.pinsLoading && flow.pins.length ? '<small class="vault-pin-note" role="status">Refreshing saved-copy status…</small>' : ''}${job}${flow.pinJob ? '<small class="vault-pin-note">Cancel or wait for snapshot work to finish before closing or locking this location.</small>' : ''}${empty}${rows}${flow.pinsNextAfter ? `<div class="vault-pin-more"><button class="small-action quiet" data-vault-pin-more ${flow.pinsLoading ? 'disabled' : ''}>${flow.pinsLoading ? 'Loading…' : 'Load more encrypted copies'}</button></div>` : ''}${flow.pinsTruncated ? '<small class="vault-pin-note">The list is limited; load more to see additional saved copies.</small>' : ''}${offlineNote}</section>`;
}

function nativeExistingFileSaveMessage() {
  return 'Supported files up to 512 KiB can be saved in place through the Windows drive while connected. Use an app that writes directly into the existing file. Editors that replace files, new files, rename/move/delete and offline edits are not supported here. Existing read-only files remain read-only.';
}

function nativeVaultDrivePanel(flow: VaultDialogState, busy: boolean) {
  const ready = !flow.statusUnknown && flow.unlocked && !nativeVaultLockIncomplete(flow) && flow.vaultMountReady && state.status?.mounted === true && state.status?.connected === true;
  const existingFileSaves = ready && flow.vaultMountExistingFileInPlace;
  return `<section class="vault-native-read-only"><b>${existingFileSaves ? 'Windows drive access · supported file saves' : 'Read-only Windows drive access'}</b><p>${nativeVaultLockIncomplete(flow) ? esc(nativeVaultLockMessage(flow.lockCleanupStatus, flow.unlocked)) : existingFileSaves ? nativeExistingFileSaveMessage() : ready ? 'Open the OpenCloud drive and navigate to this encrypted location to read its files. Files cannot be edited here.' : 'The encrypted location is unlocked, but native drive access has not been confirmed. Close and reopen this dialog to check drive access.'}</p><button class="button primary" data-vault-action="open-native" ${busy || !ready ? 'disabled' : ''}>Open OpenCloud drive</button><small>In-app browsing and encrypted offline copies are unavailable. Locking denies new reads; it cannot retract copies already read by other apps.</small></section>`;
}
async function openNativeVaultDrive() {
  const flow = state.vaultDialog;
  if (!nativeVaultAccess() || !featureAvailable('vaults_supported') || !flow || nativeVaultLockIncomplete(flow) || !flow.unlocked || flow.statusUnknown || !flow.vaultMountReady || flow.loading || state.status?.mounted !== true || state.status.connected !== true || !isCurrentAccount(flow.accountEpoch) || state.vaultGeneration !== flow.generation || state.accountSwitching) return;
  await openAccountFolder('open_cloud_folder');
}
function vaultDialog() {
  const flow = state.vaultDialog!;
  const passwordErrorActive = !!flow.passwordError && flow.error === flow.passwordError;
  const busy = flow.loading || state.accountSwitching || state.accountEpoch !== flow.accountEpoch || state.vaultGeneration !== flow.generation;
  const copyChoosingDestination = !nativeVaultAccess() && !!copyProducerUi.source && !copyProducerUi.jobId;
  const copyActive = !nativeVaultAccess() && (copyProducerUi.status?.state === 'queued' || copyProducerUi.status?.state === 'running');
  const pinWorkPending = flow.pinBusy || !!flow.pinJob;
  const editRetryRunning = !!flow.editRetryJob && (flow.editRetryJob.state === 'queued' || flow.editRetryJob.state === 'running');
  const vaultWorkPending = pinWorkPending || flow.editRetryBusy || editRetryRunning;
  const closeDisabled = busy || vaultWorkPending || (copyChoosingDestination && copyProducerUi.busy);
  if (!closeDisabled) flow.closeBlockedNotice = '';
  const title = flow.intent === 'create' ? 'Create encrypted folder' : flow.intent === 'manage' ? 'Encrypted folder' : flow.intent === 'browse' ? 'Unlock encrypted files' : 'Choose encrypted folder';
  const directoryRows = !nativeVaultAccess() && flow.unlocked && !flow.statusUnknown
    ? `<div class="vault-directory-list">${flow.path !== '/' ? `<button class="vault-directory-row" data-vault-path="${esc(parentPath(flow.path))}" ${copyProducerUi.admissionUncertain ? 'disabled' : ''}>${svg('folder')}<span>..</span>${svg('chevron')}</button>` : ''}${flow.entries.filter(entry => entry.directory).map(entry => `<button class="vault-directory-row" data-vault-path="${esc(entry.path)}" ${copyProducerUi.admissionUncertain ? 'disabled' : ''}>${svg('folder')}<span>${esc(lastPath(entry.path))}</span>${svg('chevron')}</button>`).join('') || `<div class="vault-empty">No folders in this encrypted location.</div>`}${copyChoosingDestination ? '' : flow.entries.filter(entry => !entry.directory).map(entry => `<div class="vault-file-row"><span class="vault-file-name">${svg('media')}<b>${esc(lastPath(entry.path))}</b><small>${entry.size == null ? 'File' : esc(formatBytes(entry.size))}</small></span>${canStartVaultCopyFrom(flow, entry) ? `<button class="small-action" data-copy-source-index="${flow.entries.indexOf(entry)}" aria-label="Copy ${esc(lastPath(entry.path))} to another encrypted location">Copy to…</button>` : ''}</div>`).join('')}</div>` : '';
  const createForm = flow.intent === 'create'
    ? `<label class="field-label" for="vault-create-name">Folder name</label><input class="vault-input" id="vault-create-name" value="${esc(state.pickerFolderName)}" placeholder="For example, Private" maxlength="240" ${busy ? 'disabled' : ''}/><small class="vault-hint">Raiun adds the .vault suffix when needed. Folder creation can be partially completed by the server; if an error appears, check the remote location before retrying.</small><label class="field-label" for="vault-create-password">Vault password</label><input class="vault-input" id="vault-create-password" type="password" autocomplete="new-password" ${busy ? 'disabled' : ''}/><label class="field-label" for="vault-create-confirm">Confirm password</label><input class="vault-input" id="vault-create-confirm" type="password" autocomplete="new-password" ${busy ? 'disabled' : ''}/>`
    : !flow.unlocked && flow.initialized && !flow.statusUnknown && !nativeVaultLockIncomplete(flow)
      ? `<label class="field-label" for="vault-password">Vault password</label><input class="vault-input" id="vault-password" type="password" autocomplete="current-password" ${vaultPasswordErrorAttributes(passwordErrorActive)} ${busy ? 'disabled' : ''}/><label class="remember-vault-choice"><input id="vault-remember" type="checkbox" ${flow.rememberOnDevice ? 'checked' : ''} ${busy || flow.rememberedStatus === 'unavailable' ? 'disabled' : ''}/><span>Remember on this device</span></label><small class="vault-hint">${flow.rememberedStatus === 'unavailable' ? 'Secure storage is unavailable, so this password cannot be remembered.' : 'Your vault password is not saved unless you choose “Remember on this device.”'}</small>`
      : '';
  const rememberedNoteText = flow.statusUnknown || flow.rememberedStatus === null
    ? ''
    : flow.rememberedStatus === 'known_saved'
      ? 'Raiun confirmed a saved key during this session. It may have changed; using it checks the key before unlocking.'
      : flow.rememberedStatus === 'not_saved'
        ? 'No key is saved on this device.'
        : flow.rememberedStatus === 'unknown'
          ? 'Saved-key status has not been checked this session. Choose “Unlock with saved key” to check it.'
          : 'Secure storage is unavailable. Password unlock still works, but saved-key use and saving are unavailable.';
  const rememberedNote = rememberedNoteText
    ? `<small class="vault-hint" role="status" aria-live="polite" aria-atomic="true" aria-label="${esc(rememberedNoteText)}">${esc(rememberedNoteText)}</small>`
    : '';
  const useButton = !nativeVaultAccess() && flow.intent === 'add' && flow.initialized && flow.unlocked && !flow.statusUnknown
    ? `<button class="button primary" data-vault-action="use" ${busy || vaultWorkPending ? 'disabled' : ''}>Use this folder</button>`
    : '';
  const mountedAvailability = nativeVaultAccess() ? `${nativeVaultLockMessage(flow.lockCleanupStatus, flow.unlocked, !flow.statusUnknown)}${!flow.statusUnknown && flow.unlocked && flow.vaultMountReady && flow.vaultMountExistingFileInPlace && state.status?.mounted === true && state.status?.connected === true ? ` ${nativeExistingFileSaveMessage()}` : ''}` : flow.statusUnknown
    ? 'Encrypted-location status could not be confirmed. Retry the check before unlocking or browsing.'
    : flow.loading
      ? 'Checking encrypted-location access…'
      : !flow.unlocked
        ? 'Unlock this location before opening its files through the mounted drive.'
      : mountedVaultAccessMessage(
        flow.vaultMountWritable,
        flow.vaultMountWriteUnavailableReason,
        flow.vaultMountReady,
        flow.vaultMountExistingFileOverwrite,
        flow.vaultMountExistingFileOverwriteReason,
      );
  const lockButton = (flow.intent === 'manage' || flow.intent === 'browse') && (flow.unlocked || nativeVaultLockIncomplete(flow)) && !flow.statusUnknown
    ? `<button class="button subtle" data-vault-action="lock" ${busy || vaultWorkPending || copyActive ? 'disabled' : ''}>${nativeVaultLockIncomplete(flow) ? 'Retry Lock' : 'Lock now'}</button>`
    : '';
  const statusButton = flow.statusUnknown || nativeVaultLockIncomplete(flow) || (nativeVaultAccess() && !flow.unlocked && flow.lockCleanupStatus === 'unknown')
    ? `<button class="button primary" data-vault-action="check-status" ${busy ? 'disabled' : ''}>${busy ? 'Checking…' : flow.statusUnknown ? 'Retry check' : 'Check status'}</button>`
    : '';
  const unlockButton = (flow.intent === 'manage' || flow.intent === 'browse' || flow.intent === 'add') && flow.initialized && !flow.unlocked && !flow.statusUnknown && !nativeVaultLockIncomplete(flow)
    ? `<button class="button primary" data-vault-action="unlock" ${busy ? 'disabled' : ''}>${busy ? 'Unlocking…' : flow.offlineUnlockOnly ? 'Unlock offline snapshot' : 'Unlock vault'}</button>`
    : '';
  const savedUnlockButton = (flow.intent === 'manage' || flow.intent === 'browse' || flow.intent === 'add') && flow.initialized && !flow.unlocked && !flow.statusUnknown && (flow.rememberedStatus === 'known_saved' || flow.rememberedStatus === 'unknown') && !nativeVaultLockIncomplete(flow)
    ? `<button class="button primary" data-vault-action="unlock-saved" ${busy ? 'disabled' : ''}>${busy ? 'Unlocking…' : 'Unlock with saved key'}</button>`
    : '';
  const forgetButton = !flow.offlineUnlockOnly && !!flow.rootResourceId && !flow.statusUnknown && flow.rememberedStatus !== 'not_saved'
    ? `<button class="button subtle" data-vault-action="forget" ${busy ? 'disabled' : ''}>Forget saved key</button>`
    : '';
  const rootDisplay = flow.unlocked && !flow.statusUnknown
    ? flow.rootPath
    : `Encrypted location · Space ${flow.spaceId} · …${flow.rootResourceId.length > 8 ? flow.rootResourceId.slice(-8) : flow.rootResourceId}`;
  const opaqueOfflineLabel = flow.offlineUnlockOnly
    ? `${flow.offlinePinId ? `Verified offline copy · generation ${flow.offlinePinGeneration ?? 'unknown'}` : 'Saved encrypted location'} · Space ${flow.spaceId} · …${flow.rootResourceId.length > 8 ? flow.rootResourceId.slice(-8) : flow.rootResourceId}`
    : flow.rootPath;
  const lockState = nativeVaultLockIncomplete(flow) ? nativeVaultLockMessage(flow.lockCleanupStatus, flow.unlocked, !flow.statusUnknown) : flow.statusUnknown
    ? 'Encrypted-location metadata could not be confirmed. Retry before unlocking.'
    : nativeVaultAccess() && !flow.unlocked
      ? nativeVaultLockMessage(flow.lockCleanupStatus, false)
    : flow.unlocked
      ? flow.offlineUnlockOnly ? flow.offlinePinId ? flow.vaultMountExistingFileOverwrite ? 'Unlocked from verified snapshot · supported offline edits are enabled' : 'Unlocked from a verified encrypted snapshot · read-only' : 'Unlocked from saved encrypted location; complete offline copy not confirmed · limited offline access' : 'Unlocked for this account'
      : flow.initialized
        ? flow.offlineUnlockOnly ? flow.offlinePinId ? 'Verified encrypted offline copy · unlock to browse names' : 'Saved encrypted location · offline snapshot availability not confirmed' : flow.intent === 'browse' ? 'Locked · unlock to browse encrypted names' : 'Locked · unlock to resume sync and browse names'
        : 'No usable integrity token was found. This folder cannot be unlocked.';
  const browseExplanation = nativeVaultAccess() ? 'Unlock this location to read its files through the Windows drive. Supported file saves are shown after unlocking. Encrypted offline copies and in-app file browsing are unavailable in this mode.' : flow.intent === 'browse'
    ? flow.offlineUnlockOnly
      ? flow.offlinePinId
        ? 'Enter the vault password, or use a saved key, to verify this complete encrypted snapshot. Offline access is read-only; no files are uploaded or changed.'
        : 'Enter the vault password, or use a saved key, to check this saved encrypted location. A complete offline copy is not confirmed. Offline access is read-only; no files are uploaded or changed.'
    : 'Unlock this location to open its files through your OpenCloud drive. No synced folder is added.'
    : 'Remote names and contents are encrypted. The selected local folder remains plaintext on this computer. Locking may wait for active encrypted reads, folder sync, and offline-copy work to stop. It cannot retract bytes already read or copied by other apps, or encrypt/remove local sync copies. When this location is available through the mounted drive, locking denies further reads.';
  const liveLockState = flow.loading && nativeVaultLockIncomplete(flow) ? 'Checking local cleanup…' : flow.loading ? flow.initialized && !flow.unlocked ? 'Unlocking encrypted location…' : 'Checking encrypted-location access…' : lockState;
  const copyPanel = !nativeVaultAccess() && copyProducerUi.source
    ? `<section class="copy-producer-panel" role="group" aria-label="Copy encrypted file"><b>${copyActive ? 'Copying encrypted file' : copyProducerUi.jobId ? 'Copy result' : copyChoosingDestination ? 'Choose a destination folder' : 'Choose where to copy this file'}</b><small>${esc(copyProducerUi.source.expectation.path)} · ${esc(formatBytes(copyProducerUi.source.size))}</small>${copyProducerUi.status ? `<span role="status" aria-live="polite">${esc(copyProducerStatusMessage(copyProducerUi.status))}</span>` : copyChoosingDestination ? '<span role="status">Choose another unlocked writable encrypted location. Raiun keeps the original file in place.</span>' : ''}${copyProducerUi.error ? `<span role="alert">${esc(copyProducerUi.error)}</span>` : ''}${copyProducerUi.pollError ? `<span role="alert">${esc(copyProducerUi.pollError)}</span>` : ''}${copyProducerUi.jobId && (!copyActive || !!copyProducerUi.pollError) ? `<button class="small-action" data-action="copy-producer-check" ${copyProducerUi.busy ? 'disabled' : ''}>${copyActive ? 'Retry status check' : 'Check copy status'}</button>` : ''}${copyActive ? `<button class="small-action" data-action="copy-producer-cancel" ${copyProducerUi.busy ? 'disabled' : ''}>${copyProducerUi.busy ? 'Checking…' : 'Cancel copy'}</button>` : ''}${!copyActive ? `<button class="small-action" data-action="copy-producer-close">${copyProducerUi.admissionUncertain ? 'Close copy flow' : copyProducerUi.jobId ? 'Close copy status' : 'Cancel copy'}</button>` : ''}</section>`
    : '';
  const protectedRecoveryPanel = typeof protectedVaultRecoveryPanel === 'function' ? protectedVaultRecoveryPanel(flow, busy) : '';
  const destinationAction = copyChoosingDestination && copyProducerUi.admissionUncertain
    ? '<div class="vault-hint" role="alert">Raiun could not confirm whether the copy was accepted. Do not start it again yet. Check the destination and pending operations, then close this copy flow before deciding what to do next.</div>'
    : copyChoosingDestination && flow.unlocked && !flow.statusUnknown && canUseVaultCopyDestination(flow)
    ? `<div class="copy-destination-actions"><small>Copy as <b>${esc(lastPath(copyProducerUi.source!.expectation.path))}</b> into <code>${esc(flow.path)}</code>.</small><button class="button primary" data-vault-action="copy-use-destination" ${busy || copyProducerUi.busy ? 'disabled' : ''}>${copyProducerUi.busy ? 'Starting…' : 'Copy to this folder'}</button></div>`
    : copyChoosingDestination && flow.unlocked && !flow.statusUnknown
      ? `<div class="vault-hint" role="status">${flow.writable ? 'A stable folder version is unavailable here, or this is the source location. Choose a different folder.' : 'This location is read-only. Choose an unlocked writable encrypted location.'}</div>`
      : '';
  return `<div class="modal-backdrop" data-backdrop="vault"><section class="modal vault-modal" role="dialog" aria-modal="true" aria-labelledby="vault-title" tabindex="-1"><div class="modal-top"><div><div class="eyebrow">END-TO-END ENCRYPTION</div><h2 id="vault-title">${copyChoosingDestination ? 'Choose copy destination' : title}</h2></div><button class="icon-button" data-vault-action="close" aria-label="Close" ${closeDisabled || copyActive ? 'disabled' : ''}>${svg('close')}</button></div><p class="modal-lede">${copyChoosingDestination ? 'Choose an unlocked writable encrypted folder. Raiun creates a new file there and keeps the original in place.' : browseExplanation}</p><div class="vault-root">${svg('lock')}<code>${esc(flow.offlineUnlockOnly ? opaqueOfflineLabel : rootDisplay)}</code></div>${flow.error ? `<div class="vault-error" ${passwordErrorActive ? 'id="vault-password-error" ' : ''}role="alert">${svg('alert')}<span>${esc(flow.error)}</span></div>` : ''}${flow.closeBlockedNotice ? `<div class="vault-state" role="status" aria-live="polite" aria-atomic="true">${esc(flow.closeBlockedNotice)}</div>` : ''}${flow.intent !== 'create'? `<div class="vault-state ${flow.unlocked && !flow.statusUnknown ? 'unlocked' : ''}" role="status" aria-live="polite" aria-atomic="true">${liveLockState}</div>` : ''}${createForm}${rememberedNote}${flow.unlocked && !flow.statusUnknown ? nativeVaultAccess() ? nativeVaultDrivePanel(flow, busy) : `<div class="vault-browse-label">${copyChoosingDestination ? 'Destination folder' : 'Folders inside this encrypted location'} <code>${esc(flow.path)}</code></div>${flow.loading ? '<div class="vault-empty" role="status"><span class="spinner"></span> Loading encrypted folder…</div>' : directoryRows}${destinationAction}${copyPanel}${!copyChoosingDestination ? `${vaultOfflinePinPanel(flow)}${vaultEditRetryPanel(flow)}` : ''}` : copyPanel}${protectedRecoveryPanel}<div class="helper-note">Your vault password is not saved unless you choose “Remember on this device.” After an opted-in successful unlock, Raiun stores the password in the operating system’s protected credential store for this account and vault. Locking the vault does not remove it; use “Forget saved key” separately. If a vault password is lost, its encrypted cloud contents cannot be recovered by Raiun.</div>${flow.intent !== 'create' ? `<div class="helper-note">${esc(mountedAvailability)}</div>` : ''}<div class="modal-actions"><button class="button subtle" data-vault-action="close" ${closeDisabled || copyActive ? 'disabled' : ''}>Close</button>${unlockButton}${savedUnlockButton}${lockButton}${flow.offlineUnlockOnly ? '' : forgetButton}${statusButton}${useButton}${!nativeVaultAccess() && flow.intent === 'create' ? `<button class="button primary" data-vault-action="create" ${busy ? 'disabled' : ''}>${busy ? 'Creating…' : 'Create vault'}</button>` : ''}</div></section></div>`;
}

function bind() {
  mediaJobs.bind(app);
  app.querySelectorAll<HTMLElement>('[data-page]').forEach(el => el.addEventListener('click', () => navigateToPage(el.dataset.page as Page)));
  app.querySelectorAll<HTMLElement>('[data-sync-section]').forEach(el => el.addEventListener('click', () => {
    const section = el.dataset.syncSection;
    if (section !== 'folders' && section !== 'media') return;
    state.page = 'folders';
    state.syncSection = section;
    render();
    if (section === 'media') void mediaJobs.refresh();
  }));
  app.querySelector('#refresh')?.addEventListener('click', () => void refresh(true, true));
  app.querySelectorAll<HTMLButtonElement>('[data-account-id]').forEach(el => el.addEventListener('click', () => { if (el.dataset.accountId) void switchAccount(el.dataset.accountId); }));
  app.querySelectorAll<HTMLElement>('[data-action]').forEach(el => el.addEventListener('click', () => void handleAction(el.dataset.action || '', el)));
  app.querySelector<HTMLSelectElement>('#network-proxy-mode')?.addEventListener('change', event => {
    proxyUi.draftMode = (event.target as HTMLSelectElement).value as ProxyMode;
    render();
  });
  app.querySelector<HTMLSelectElement>('#appearance-theme')?.addEventListener('change', event => {
    const theme = (event.target as HTMLSelectElement).value as AppearanceTheme;
    const next = writeAppearance({ getItem: key => window.localStorage.getItem(key), setItem: (key, value) => window.localStorage.setItem(key, value) }, state.selectedAccount, { theme });
    document.documentElement.dataset.theme = next.theme;
    render();
  });
  app.querySelector<HTMLSelectElement>('#appearance-accent')?.addEventListener('change', event => {
    const accent = (event.target as HTMLSelectElement).value as AccentName;
    writeAppearance({ getItem: key => window.localStorage.getItem(key), setItem: (key, value) => window.localStorage.setItem(key, value) }, state.selectedAccount, { accent });
    render();
  });
  app.querySelector<HTMLInputElement>('#network-proxy-url')?.addEventListener('input', event => {
    proxyUi.draftUrl = (event.target as HTMLInputElement).value;
  });
  app.querySelector<HTMLInputElement>('#upload-limit-kib')?.addEventListener('input', event => {
    bandwidthUi.upload = (event.target as HTMLInputElement).value;
  });
  app.querySelector<HTMLInputElement>('#download-limit-kib')?.addEventListener('input', event => {
    bandwidthUi.download = (event.target as HTMLInputElement).value;
  });
  app.querySelector<HTMLInputElement>('#desktop-update-auto')?.addEventListener('change', event => {
    void saveDesktopUpdatePreferences((event.target as HTMLInputElement).checked, desktopUpdateUi.status?.channel || 'beta');
  });
  app.querySelector<HTMLSelectElement>('#desktop-update-channel')?.addEventListener('change', event => {
    void saveDesktopUpdatePreferences(desktopUpdateUi.status?.automatic_checks !== false, (event.target as HTMLSelectElement).value as 'stable' | 'beta');
  });
  app.querySelectorAll<HTMLElement>('[data-vault-edit-latest-cancel]').forEach(el => el.addEventListener('click', () => void cancelEncryptedRetryLatest(el)));
  app.querySelectorAll<HTMLElement>('[data-filter]').forEach(el => el.addEventListener('click', () => { state.transferFilter = el.dataset.filter || 'active'; render(); }));
  app.querySelectorAll<HTMLElement>('[data-remove-pair]').forEach(el => el.addEventListener('click', () => void removePair(el.dataset.removePair || '')));
  app.querySelectorAll<HTMLElement>('[data-toggle-exclusions]').forEach(el => el.addEventListener('click', () => togglePairExclusions(el.dataset.toggleExclusions || '')));
  app.querySelectorAll<HTMLInputElement>('[data-exclusion-input]').forEach(el => el.addEventListener('input', () => { const id = el.dataset.exclusionInput || ''; pairExclusionsUi.drafts.set(id, el.value); const button = app.querySelector<HTMLButtonElement>(`[data-add-exclusion="${CSS.escape(id)}"]`); if (button) button.disabled = !el.value.trim() || state.mutationBusy > 0 || pairExclusionsUi.busy.has(id); }));
  app.querySelectorAll<HTMLButtonElement>('[data-add-exclusion]').forEach(el => el.addEventListener('click', () => void addPairExclusion(el.dataset.addExclusion || '')));
  app.querySelectorAll<HTMLButtonElement>('[data-remove-exclusion]').forEach(el => el.addEventListener('click', () => { const index = Number(el.dataset.exclusionIndex); if (el.dataset.removeExclusion && Number.isInteger(index)) void removePairExclusion(el.dataset.removeExclusion, index); }));
  app.querySelectorAll<HTMLElement>('[data-review-pair]').forEach(el => el.addEventListener('click', () => void toggleConflicts(el.dataset.reviewPair || '')));
  app.querySelectorAll<HTMLElement>('[data-refresh-conflicts]').forEach(el => el.addEventListener('click', () => void loadConflictPage(el.dataset.refreshConflicts || '', true)));
  app.querySelectorAll<HTMLElement>('[data-more-conflicts]').forEach(el => el.addEventListener('click', () => void loadConflictPage(el.dataset.moreConflicts || '', false)));
  app.querySelectorAll<HTMLButtonElement>('[data-resolve-conflict]').forEach(el => el.addEventListener('click', () => void resolveConflict(el)));
  app.querySelectorAll<HTMLElement>('[data-retry]').forEach(el => el.addEventListener('click', () => void transferAction('retry', el.dataset.retry || '')));
  app.querySelectorAll<HTMLElement>('[data-cancel]').forEach(el => el.addEventListener('click', () => void transferAction('cancel', el.dataset.cancel || '')));
  app.querySelectorAll<HTMLElement>('[data-remote-path]').forEach(el => el.addEventListener('click', () => { const path = el.dataset.remotePath || '/'; const entry = state.pickerEntries.find(item => item.path === path); if (entry) state.pickerWritable[path] = entry.writable === true && entry.encrypted !== true; void browseRemote(path); }));
  app.querySelectorAll<HTMLElement>('[data-load-offline-policy]').forEach(el => el.addEventListener('click', () => void loadOfflinePolicy(el.dataset.loadOfflinePolicy || '')));
  app.querySelectorAll<HTMLElement>('[data-load-folder-policy]').forEach(el => el.addEventListener('click', () => {
    const path = el.dataset.loadFolderPolicy || '';
    const listingPath = el.dataset.folderListingPath || '';
    void loadOfflineFolderPolicy(path, listingPath, el.dataset.folderCurrent === 'true');
  }));
  app.querySelectorAll<HTMLElement>('[data-set-folder-policy]').forEach(el => el.addEventListener('click', () => {
    const policy = el.dataset.setFolderPolicy;
    if (policy !== 'recent' && policy !== 'cloud_only') return;
    void setOfflineFolderPolicy(el.dataset.folderPath || '', el.dataset.folderListingPath || '', policy, el.dataset.folderCurrent === 'true');
  }));
  app.querySelectorAll<HTMLElement>('[data-windows-offline-row]').forEach(el => el.addEventListener('click', () => selectWindowsOfflineFile(el.dataset.windowsOfflineRow || '')));
  app.querySelectorAll<HTMLElement>('[data-windows-offline-folder-row]').forEach(el => el.addEventListener('click', () => windowsOfflineFoldersPanel.select(el.dataset.windowsOfflineFolderRow || '')));
  app.querySelectorAll<HTMLSelectElement>('[data-offline-policy-path]').forEach(el => el.addEventListener('change', () => void setOfflinePolicy(el.dataset.offlinePolicyPath || '', el.value as OfflinePolicy)));
  app.querySelectorAll<HTMLElement>('[data-pin-offline]').forEach(el => el.addEventListener('click', () => void startOfflinePin(el.dataset.pinOffline || '')));
  app.querySelectorAll<HTMLElement>('[data-unpin-offline]').forEach(el => el.addEventListener('click', () => void stopOfflinePin(el.dataset.unpinOffline || '')));
  app.querySelector<HTMLSelectElement>('#offline-space')?.addEventListener('change', event => {
    const spaceId = (event.target as HTMLSelectElement).value;
    if (!state.spaces.some(space => space.id === spaceId && !space.encrypted)) return;
    state.spaceId = spaceId;
    state.pickerPath = '/';
    state.pickerGeneration++;
    offlineUi.error = '';
    state.pickerEntries = [];
    void loadOfflinePins(spaceId);
    void browseRemote('/');
  });
  app.querySelector<HTMLElement>('[data-action="cancel-offline-pin"]')?.addEventListener('click', () => void cancelOfflinePin());
  app.querySelectorAll<HTMLElement>('[data-vault-root]').forEach(el => el.addEventListener('click', () => {
    const rootPath = el.dataset.vaultRoot || '/';
    const entry = state.pickerEntries.find(candidate => candidate.path === rootPath);
    const rootWritable = entry?.writable ?? state.pickerWritable[state.pickerPath] ?? false;
    if (copyProducerUi.source) state.pickerOpen = false;
    void openVaultFlow(state.pickerPurpose === 'encrypted_access' ? 'browse' : 'add', state.spaceId, rootPath, undefined, rootWritable);
  }));
  app.querySelectorAll<HTMLElement>('[data-vault-pair]').forEach(el => {
    el.addEventListener('click', () => {
      const pair = state.pairs.find(item => item.id === el.dataset.vaultPair);
      if (pair?.vault) void openVaultFlow('manage', pair.space_id, pair.vault.root_path, pair.id);
    });
  });
  app.querySelectorAll<HTMLElement>('[data-vault-path]').forEach(el => el.addEventListener('click', () => {
    const flow = state.vaultDialog;
    if (flow) {
      const path = el.dataset.vaultPath || '/';
      if (copyProducerUi.source && !copyProducerUi.jobId) {
        if (copyProducerUi.busy || copyProducerUi.admissionUncertain) return;
        copyProducerUi.flowGeneration++;
        copyProducerUi.destination = null;
        copyProducerUi.context = null;
      }
      const child = flow.entries.find(entry => entry.directory && entry.path === path);
      if (child?.id && isStrongVaultEtag(child.etag)) {
        flow.directoryBindings.set(path, { resourceId: child.id, etag: child.etag });
      }
      void loadVaultPath(flow, path);
    }
  }));
  app.querySelectorAll<HTMLButtonElement>('[data-copy-source-index]').forEach(el => el.addEventListener('click', () => {
    const index = Number(el.dataset.copySourceIndex);
    if (Number.isSafeInteger(index) && index >= 0) void beginVaultCopy(index);
  }));
  app.querySelectorAll<HTMLElement>('[data-vault-action]').forEach(el => el.addEventListener('click', () => {
    const action = el.dataset.vaultAction;
    if (action === 'close') closeVaultDialog();
    else if (action === 'unlock') void unlockVault(false);
    else if (action === 'unlock-saved') void unlockVault(true);
    else if (action === 'lock') void lockVault();
    else if (action === 'forget') void forgetSavedVault();
    else if (action === 'check-status') void checkVaultLockStatus();
    else if (action === 'open-native') void openNativeVaultDrive();
    else if (action === 'use') useVaultFolder();
    else if (action === 'create') void createEncryptedVault();
    else if (action === 'copy-use-destination') void startVaultCopyToCurrentFolder();
  }));
  app.querySelector<HTMLButtonElement>('[data-vault-capture-refresh]')?.addEventListener('click', () => void loadProtectedVaultCaptures(true));
  app.querySelector<HTMLButtonElement>('[data-vault-capture-more]')?.addEventListener('click', () => void loadProtectedVaultCaptures(false));
  app.querySelectorAll<HTMLButtonElement>('[data-vault-capture-save]').forEach(el => el.addEventListener('click', () => void saveProtectedVaultCaptureCopy(el.dataset.vaultCaptureSave || '')));
  app.querySelectorAll<HTMLButtonElement>('[data-vault-pin-start]').forEach(el => el.addEventListener('click', () => void startVaultOfflinePin(el.dataset.vaultPinStart || undefined)));
  app.querySelector<HTMLButtonElement>('[data-vault-pin-cancel]')?.addEventListener('click', () => void cancelVaultOfflinePin());
  app.querySelectorAll<HTMLButtonElement>('[data-vault-pin-remove]').forEach(el => el.addEventListener('click', () => void removeVaultOfflinePin(el.dataset.vaultPinRemove || '')));
  app.querySelector<HTMLButtonElement>('[data-vault-edit-retry]')?.addEventListener('click', () => void startVaultEditRetry());
  app.querySelector<HTMLButtonElement>('[data-vault-edit-retry-cancel]')?.addEventListener('click', () => void cancelVaultEditRetry());
  app.querySelector<HTMLButtonElement>('[data-vault-pin-refresh-list]')?.addEventListener('click', () => { const flow = state.vaultDialog; if (flow) void loadVaultPins(flow, true); });
  app.querySelector<HTMLButtonElement>('[data-vault-pin-more]')?.addEventListener('click', () => { const flow = state.vaultDialog; if (flow) void loadVaultPins(flow, false); });
  app.querySelector<HTMLElement>('.vault-modal')?.addEventListener('keydown', event => {
    const dialog = event.currentTarget as HTMLElement;
    if (event.key === 'Escape' && !event.isComposing) {
      event.preventDefault();
      closeVaultDialog();
      return;
    }
    if (event.key !== 'Tab') return;
    const focusable = [...dialog.querySelectorAll<HTMLElement>('button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), a[href], [tabindex]:not([tabindex="-1"])')]
      .filter(element => element.tabIndex >= 0 && element.getClientRects().length > 0);
    const destination = vaultDialogTabDestination(focusable.indexOf(document.activeElement as HTMLElement), focusable.length, event.shiftKey);
    if (destination === null) return;
    event.preventDefault();
    if (destination < 0) dialog.focus({ preventScroll: true });
    else focusable[destination]?.focus({ preventScroll: true });
  });
  app.querySelector<HTMLElement>('[data-backdrop="vault"]')?.addEventListener('click', event => {
    if (event.target === event.currentTarget && !state.vaultDialog?.loading && !state.vaultDialog?.pinBusy && !state.vaultDialog?.pinJob && !state.vaultDialog?.editRetryBusy && !['queued', 'running'].includes(state.vaultDialog?.editRetryJob?.state || '')) closeVaultDialog();
  });
  app.querySelector<HTMLElement>('[data-backdrop="encrypted-access"]')?.addEventListener('click', event => { if (event.target === event.currentTarget) closeEncryptedAccess(); });
  app.querySelector<HTMLElement>('[data-backdrop="add"]')?.addEventListener('click', event => { if (event.target === event.currentTarget) closeAdd(); });
  app.querySelector<HTMLElement>('[data-backdrop="picker"]')?.addEventListener('click', event => { if (event.target === event.currentTarget && !state.pickerCreatingFolder) { state.pickerGeneration++; state.pickerOpen = false; state.pickerPurpose = 'pair'; render(); } });
  app.querySelector<HTMLElement>('[data-backdrop="account"]')?.addEventListener('click', event => { if (event.target === event.currentTarget && !state.addAccountBusy) closeAccountSetup(); });
  app.querySelector<HTMLInputElement>('#account-label')?.addEventListener('input', event => { state.addAccountLabel = (event.target as HTMLInputElement).value; updateAddAccountSubmit(); });
  app.querySelector<HTMLInputElement>('#account-server')?.addEventListener('input', event => { state.addAccountServer = (event.target as HTMLInputElement).value; updateAddAccountSubmit(); });
  app.querySelector<HTMLInputElement>('#account-client-id')?.addEventListener('input', event => { state.addAccountClientId = (event.target as HTMLInputElement).value; });
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
  app.querySelector<HTMLInputElement>('#picker-folder-name')?.addEventListener('input', event => { state.pickerFolderName = (event.target as HTMLInputElement).value; });
  app.querySelector<HTMLInputElement>('#vault-create-name')?.addEventListener('input', event => { state.pickerFolderName = (event.target as HTMLInputElement).value; });
  app.querySelector<HTMLInputElement>('#vault-remember')?.addEventListener('change', event => {
    if (state.vaultDialog) state.vaultDialog.rememberOnDevice = (event.target as HTMLInputElement).checked;
  });
  app.querySelector<HTMLInputElement>('#vault-password')?.addEventListener('keydown', event => {
    if (event.key === 'Enter' && !event.isComposing) {
      event.preventDefault();
      void unlockVault(false);
    }
  });
  app.querySelector<HTMLInputElement>('#media-destination')?.addEventListener('input', event => {
    mediaPreview.destinationRoot = (event.target as HTMLInputElement).value;
    invalidateMediaPreview();
    render();
  });
  app.querySelector<HTMLSelectElement>('#media-filter')?.addEventListener('change', event => {
    mediaPreview.filter = (event.target as HTMLSelectElement).value as MediaFilterValue;
    invalidateMediaPreview();
    render();
  });
  app.querySelector<HTMLSelectElement>('#media-organization')?.addEventListener('change', event => {
    mediaPreview.organization = (event.target as HTMLSelectElement).value as MediaOrganizationValue;
    invalidateMediaPreview();
    render();
  });
  app.querySelector<HTMLSelectElement>('#spaceSelect')?.addEventListener('change', event => {
    state.spaceId = (event.target as HTMLSelectElement).value;
    state.remotePath = '';
    state.vaultBinding = null;
    state.vaultWritable = false;
    const selected = state.spaces.find(space => space.id === state.spaceId);
    if (selected && !selected.writable) state.mode = 'download_only';
    render();
  });
  app.querySelector<HTMLSelectElement>('#encrypted-access-space')?.addEventListener('change', event => {
    state.vaultAccessSpaceId = (event.target as HTMLSelectElement).value;
    const selected = state.spaces.find(space => space.id === state.vaultAccessSpaceId);
    const button = app.querySelector<HTMLButtonElement>('[data-action="browse-encrypted-space"]');
    if (button) {
      button.disabled = !state.status?.connected || !selected || state.spacesLoading;
      button.textContent = selected?.encrypted ? 'Unlock Space' : 'Browse Space';
    }
  });
  app.querySelector<HTMLSelectElement>('#cached-encrypted-root')?.addEventListener('change', event => {
    cachedVaultRootsUi.selected = (event.target as HTMLSelectElement).value;
    const button = app.querySelector<HTMLButtonElement>('[data-action="browse-cached-vault-root"]');
    if (button) button.disabled = cachedVaultRootsUi.loading || !cachedVaultRootsUi.roots.some(root => cachedVaultRootKey(root) === cachedVaultRootsUi.selected);
  });
  app.querySelector<HTMLSelectElement>('#modeSelect')?.addEventListener('change', event => { state.mode = (event.target as HTMLSelectElement).value as SyncMode; });
  app.querySelector<HTMLButtonElement>('[data-action="select-remote"]')?.addEventListener('click', () => {
    state.remotePath = state.pickerPath;
    state.vaultBinding = null;
    state.vaultWritable = false;
    if (!state.pickerWritable[state.pickerPath]) state.mode = 'download_only';
    state.pickerOpen = false;
    render();
  });
  app.querySelector<HTMLButtonElement>('[data-action="save-pair"]')?.addEventListener('click', () => void savePair());
  app.querySelector<HTMLButtonElement>('[data-dismiss-error]')?.addEventListener('click', () => { state.statusErrorDismissed = state.status?.error || ''; state.error = ''; render(); });
  app.querySelector<HTMLButtonElement>('[data-dismiss-message]')?.addEventListener('click', () => { state.message = ''; render(); });
}

async function confirmAccountAction(message: string): Promise<boolean> {
  if (state.nativeDialogBusy || state.accountSwitching) return false;
  const epoch = state.accountEpoch;
  const profileId = state.selectedAccount;
  state.nativeDialogBusy = true;
  render();
  try {
    // The dialog plugin replaces window.confirm with a Promise-returning API.
    // Only a resolved, explicit approval can authorize the pending action.
    const approved = await confirmDialog(message, { title: 'Raiun Desktop', okLabel: 'OK', cancelLabel: 'Cancel' });
    return approved === true && isCurrentAccount(epoch, profileId);
  } catch (error) {
    if (isCurrentAccount(epoch, profileId)) state.error = `Could not show confirmation: ${messageOf(error)}`;
    return false;
  } finally {
    state.nativeDialogBusy = false;
    render();
  }
}
async function removeSelectedAccount() {
  const epoch = state.accountEpoch;
  const profileId = state.selectedAccount;
  const account = state.accounts.find(item => item.id === profileId);
  if (!profileId || !account || !state.accountRemovalSupported || !state.agentReachable || state.accountSwitching || state.mutationBusy > 0) return;
  const reviewedAuthGeneration = state.status?.auth_generation;
  if (!Number.isSafeInteger(reviewedAuthGeneration) || (reviewedAuthGeneration ?? -1) < 0) {
    state.error = 'Raiun could not confirm the current sign-in. Refresh and try again.';
    render();
    return;
  }
  const confirmed = await confirmAccountAction(`Remove account “${account.label}”? Raiun will sign out and revoke access. Local files and saved recovery copies stay on this computer. Any saved vault-password access will be revoked; you will need each vault password again. You can restore the account later, but you will need to sign in again.`);
  if (!confirmed || !isCurrentAccount(epoch, profileId) || !state.accountRemovalSupported || !state.agentReachable || !state.accounts.some(item => item.id === profileId)) return;
  state.error = '';
  const priorStatus = state.status;
  await refresh(false);
  if (!isCurrentAccount(epoch, profileId) || !state.accountRemovalSupported || !state.agentReachable || state.busy || state.status === priorStatus ||
      (state.status?.profile_id != null && state.status.profile_id !== profileId) || !state.accounts.some(item => item.id === profileId)) {
    if (isCurrentAccount(epoch, profileId)) {
      state.error = 'Raiun could not refresh this account’s sign-in status. Refresh and try again.';
      render();
    }
    return;
  }
  const authGeneration = state.status?.auth_generation;
  if (!Number.isSafeInteger(authGeneration) || (authGeneration ?? -1) < 0 || authGeneration !== reviewedAuthGeneration) {
    state.error = 'This account’s sign-in changed while confirmation was open. Review removal again.';
    render();
    return;
  }
  state.mutationBusy++;
  state.error = '';
  state.message = '';
  render();
  try {
    const result = await request<{ removed_profile_id: string; selected: string | null; local_data_preserved: boolean; credentials_revoked: boolean }>(
      'account_remove', { profile_id: profileId, expected_auth_generation: authGeneration, confirm: true });
    if (!isCurrentAccount(epoch, profileId)) return;
    if (result.removed_profile_id !== profileId || result.local_data_preserved !== true || result.credentials_revoked !== true) {
      throw new Error('Raiun did not confirm that this account was safely removed. Refresh the account list.');
    }
    await syncAccounts();
    state.message = `Removed ${account.label}. Local files and recovery copies were preserved.`;
  } catch (error) {
    if (isCurrentAccount(epoch, profileId) && !isStaleAccountRequest(error)) {
      const detail = messageOf(error);
      await syncAccounts();
      if (isCurrentAccount(epoch, profileId)) {
        await refresh(false);
        state.error = detail;
      }
    }
  } finally {
    state.mutationBusy = Math.max(0, state.mutationBusy - 1);
    render();
  }
}
async function restoreRemovedAccount(profileId: string) {
  const epoch = state.accountEpoch;
  const selectedProfileId = state.selectedAccount;
  const account = state.removedAccounts.find(item => item.id === profileId);
  if (!account || !profileId || !state.accountRemovalSupported || !state.agentReachable || accountSwitchDisabled()) return;
  const confirmed = await confirmAccountAction(`Restore “${account.label}” to the account list? Its local files stay where they are. Raiun will not sign in automatically; you will need to sign in again.`);
  if (!confirmed || !isCurrentAccount(epoch, selectedProfileId) || !state.accountRemovalSupported || !state.agentReachable || !state.removedAccounts.some(item => item.id === profileId)) return;
  state.mutationBusy++;
  state.error = '';
  state.message = '';
  render();
  try {
    const result = await request<{ restored_profile_id: string; selected: string | null; sign_in_required: boolean }>(
      'account_restore', { profile_id: profileId, confirm: true });
    if (!isCurrentAccount(epoch, selectedProfileId)) return;
    if (result.restored_profile_id !== profileId || result.sign_in_required !== true) {
      throw new Error('Raiun did not confirm that the account was restored without signing in. Refresh the account list.');
    }
    await syncAccounts();
    if (isCurrentAccount(epoch, selectedProfileId)) state.message = `Restored ${account.label}. Sign in to reconnect it.`;
  } catch (error) {
    if (isCurrentAccount(epoch, selectedProfileId) && !isStaleAccountRequest(error)) state.error = messageOf(error);
  } finally {
    state.mutationBusy = Math.max(0, state.mutationBusy - 1);
    render();
  }
}
async function handleAction(action: string, element?: HTMLElement) {
  switch (action) {
    case 'refresh': await refresh(true, true); break;
    case 'load-network-proxy': await loadNetworkProxySettings(true); break;
    case 'save-network-proxy': if (networkProxyAvailable()) await saveNetworkProxySettings(); break;
    case 'load-bandwidth-limits': await loadBandwidthSettings(true); break;
    case 'save-bandwidth-limits': if (bandwidthLimitsAvailable()) await saveBandwidthLimits(); break;
    case 'show-attention':
      if (state.status?.error) state.page = 'settings';
      else { state.page = 'transfers'; state.transferFilter = 'attention'; }
      render();
      if (state.page === 'transfers') { void loadPendingOfflineWrites(true); void loadEncryptedEditRecoveries(true); }
      break;
    case 'choose-media-source': {
      state.nativeDialogBusy = true;
      render();
      try {
        const selected = await open({ directory: true, multiple: false, title: 'Choose a folder for local media preview' });
        if (typeof selected === 'string') {
          mediaPreview.source = selected;
          invalidateMediaPreview();
        }
      } catch (error) { mediaPreview.error = messageOf(error); }
      finally { state.nativeDialogBusy = false; render(); }
      break;
    }
    case 'run-media-preview': await runMediaPreview(); break;
    case 'refresh-spaces': await loadSpaces(true); break;
    case 'open-add-account': if (!featureAvailable('account_switch_supported')) return; state.addAccountOpen = true; state.addAccountStep = 'details'; state.addAccountLabel = ''; state.addAccountRoot = ''; state.addAccountServer = ''; state.addAccountClientId = ''; state.addAccountAuthMessage = ''; state.addAccountAuthStarted = false; state.addAccountError = ''; state.addAccountCreatedId = ''; state.accountsError = ''; render(); break;
    case 'open-encrypted-access': if (featureAvailable('vaults_supported')) await openEncryptedAccess(); break;
    case 'refresh-windows-device-cache': await refreshWindowsDeviceCacheUsage(); break;
    case 'open-offline-files': if (providerAvailable(state.status?.provider_supported)) await openOfflineFiles(); break;
    case 'refresh-pending-writes': await loadPendingOfflineWrites(true); break;
    case 'refresh-windows-offline-folders': await windowsOfflineFoldersPanel.load(true); break;
    case 'more-windows-offline-folders': await windowsOfflineFoldersPanel.load(false); break;
    case 'start-windows-offline-folder': await runWindowsOfflineFolderAction('start'); break;
    case 'resume-windows-offline-folder': await runWindowsOfflineFolderAction('resume'); break;
    case 'refresh-windows-offline-folder': await runWindowsOfflineFolderAction('refresh'); break;
    case 'poll-windows-offline-folder': await runWindowsOfflineFolderAction('poll'); break;
    case 'cancel-windows-offline-folder': await runWindowsOfflineFolderAction('cancel'); break;
    case 'refresh-windows-offline-files': await loadWindowsOfflineFiles(true); break;
    case 'more-windows-offline-files': await loadWindowsOfflineFiles(false); break;
    case 'start-windows-offline-file': await runWindowsOfflineFileAction('start'); break;
    case 'poll-windows-offline-file': await runWindowsOfflineFileAction('poll'); break;
    case 'cancel-windows-offline-file': await runWindowsOfflineFileAction('cancel'); break;
    case 'toggle-saved-write-root': {
      const scopeKey = element?.dataset.scopeKey;
      if (!scopeKey || !pendingWritesUi.loaded || pendingWritesUi.accountEpoch !== state.accountEpoch) return;
      const currentScopeKeys = new Set(groupPendingWritesByScope(pendingWritesUi.items).keys());
      if (togglePendingWriteDisclosure(pendingWritesUi.expandedScopes, scopeKey, currentScopeKeys)) render();
      break;
    }
    case 'refresh-encrypted-retry-status': await refreshEncryptedRetryLatestStatuses(); break;
    case 'refresh-encrypted-operations': await refreshEncryptedRetryLatestStatuses(true); break;
    case 'load-more-vault-operations': if (element) await loadMoreVaultOperations(element); break;
    case 'retry-interrupted-file-create': if (element) await retryInterruptedFileCreate(element); break;
    case 'verify-copy-operation': if (element) await verifyCopyOperation(element); break;
    case 'check-copy-verification-status': {
      const binding = element ? copyVerifyBindingFromElement(element) : null;
      const job = binding ? copyVerifyUi.jobs.get(copyVerifyRowKey(binding)) : undefined;
      if (job) await checkCopyVerificationStatus(job);
      break;
    }
    case 'cancel-copy-verification': {
      const binding = element ? copyVerifyBindingFromElement(element) : null;
      const job = binding ? copyVerifyUi.jobs.get(copyVerifyRowKey(binding)) : undefined;
      if (job) await cancelCopyVerification(job);
      break;
    }
    case 'copy-producer-check': await pollCopyProducer(); break;
    case 'copy-producer-cancel': await cancelVaultCopy(); break;
    case 'copy-producer-close': cancelCopyProducerWizard(); break;
    case 'cancel-vault-copy': cancelCopyProducerWizard(); break;
    case 'more-pending-writes': await loadPendingOfflineWrites(false); break;
    case 'retry-pending-writes': if (element?.dataset.spaceId) await retryPendingOfflineWrites(element.dataset.spaceId); break;
    case 'save-pending-write-copy': if (element?.dataset.spaceId && element.dataset.writeId && element.dataset.rootResourceId) await savePendingConflictCopy(element.dataset.spaceId, element.dataset.writeId, element.dataset.rootResourceId); break;
    case 'close-encrypted-access': closeEncryptedAccess(); break;
    case 'retry-encrypted-access-spaces': await loadSpaces(true); break;
    case 'refresh-cached-vault-roots': await loadCachedVaultRoots(true); break;
    case 'more-cached-vault-roots': await loadCachedVaultRoots(false); break;
    case 'browse-cached-vault-root': await openCachedVaultRoot(element); break;
    case 'browse-encrypted-space': await browseEncryptedSpace(); break;
    case 'close-add-account': if (!state.addAccountBusy) closeAccountSetup(); break;
    case 'retry-account-signin': await retryAccountSignIn(); break;
    case 'retry-account-mount': await retryAccountMount(); break;
    case 'finish-account-setup': if (state.status?.connected && state.status.mounted) { state.message = `${selectedAccountLabel()} is signed in and its drive is mounted.`; closeAccountSetup(); } break;
    case 'choose-account-root': {
      if (state.status?.account_setup_requires_sign_in === true) return;
      const epoch = state.accountEpoch;
      state.nativeDialogBusy = true;
      render();
      try {
        const selected = await open({ directory: true, multiple: false, title: 'Choose a separate folder for this account' });
        if (isCurrentAccount(epoch) && typeof selected === 'string') state.addAccountRoot = selected;
      } catch (error) { if (isCurrentAccount(epoch)) state.error = messageOf(error); }
      finally { state.nativeDialogBusy = false; render(); }
      break;
    }
    case 'save-account': await addAccount(); break;
    case 'add-pair': if (!featureAvailable('folder_sync_supported') || !state.status?.connected) return; state.pickerGeneration++; state.pickerPurpose = 'pair'; state.vaultAccessOpen = false; state.addOpen = true; state.message = ''; state.localPath = ''; state.spaceId = state.spaces.find(space => space.personal && space.writable && !space.encrypted)?.id || ''; state.remotePath = ''; state.vaultBinding = null; state.vaultWritable = false; state.mode = 'two_way'; render(); void loadSpaces(); break;
    case 'close-add': closeAdd(); break;
    case 'choose-local': {
      const epoch = state.accountEpoch;
      state.nativeDialogBusy = true;
      render();
      try {
        const selected = await open({ directory: true, multiple: false, title: 'Choose a folder to sync' });
        if (isCurrentAccount(epoch) && typeof selected === 'string') state.localPath = selected;
      } catch (error) { if (isCurrentAccount(epoch)) state.error = messageOf(error); }
      finally { state.nativeDialogBusy = false; render(); }
      break;
    }
    case 'choose-remote': {
      const space = state.spaces.find(candidate => candidate.id === state.spaceId);
      if (!space) break;
      if (space.encrypted) { await openVaultFlow('add', space.id, '/'); break; }
      state.pickerPurpose = 'pair'; state.pickerOpen = true; state.pickerPath = '/'; state.pickerEntries = []; state.pickerError = ''; state.pickerWritable = { '/': space.writable === true }; render(); await browseRemote('/'); break;
    }
    case 'create-folder': await createRemoteFolder(); break;
    case 'create-vault': {
      const space = state.spaces.find(candidate => candidate.id === state.spaceId);
      if (space?.writable && !space.encrypted) await openVaultFlow('create', space.id, state.pickerPath);
      break;
    }
    case 'close-picker': if (!state.pickerCreatingFolder) { state.pickerGeneration++; state.pickerOpen = false; state.pickerPurpose = 'pair'; render(); } break;
    case 'sign-in': await beginSignIn(); break;
    case 'cancel-sign-in': await cancelSignIn(); break;
    case 'logout': {
      const epoch = state.accountEpoch;
      const profileId = state.selectedAccount;
      if (await confirmAccountAction(`Sign out of ${selectedAccountLabel()}? Its local files stay on this computer, while this account’s cloud drive stops mounting.`) && isCurrentAccount(epoch, profileId)) await run('logout', {});
      break;
    }
    case 'remove-selected-account': await removeSelectedAccount(); break;
    case 'restore-removed-account': if (element?.dataset.profileId) await restoreRemovedAccount(element.dataset.profileId); break;
    case 'toggle-pause': if (featureAvailable('pause_supported') && state.status) await run('pause', { paused: !state.status.paused }); break;
    case 'space-toggle': if (element?.dataset.spaceId) await toggleSpacePause(element.dataset.spaceId); break;
    case 'space-sync-now': if (element?.dataset.spaceId) await queueSpaceSync(element.dataset.spaceId); break;
    case 'space-disconnect': if (element?.dataset.spaceId) await disconnectSpaceFolderSync(element.dataset.spaceId); break;
    case 'sync-now': if (featureAvailable('folder_sync_supported')) await run('sync_now', {}); break;
    case 'mount': if (providerAvailable(state.status?.provider_supported)) await run('mount', {}); break;
    case 'unmount': if (providerAvailable(state.status?.provider_supported)) await run('unmount', {}); break;
    case 'open-cloud': if (state.status?.cloud_root) await openAccountFolder('open_cloud_folder'); break;
    case 'open-recovery': await openAccountFolder('open_recovery_folder'); break;
    case 'load-recoveries': await loadRecoveries(true); break;
    case 'more-recoveries': await loadRecoveries(false); break;
    case 'load-windows-recovery': await loadWindowsRecoveryList(); break;
    case 'load-encrypted-edit-recoveries': await loadEncryptedEditRecoveries(true); break;
    case 'more-encrypted-edit-recoveries': await loadEncryptedEditRecoveries(false); break;
    case 'open-encrypted-edit-folder': await openEncryptedEditRecoveryFolder(); break;
    case 'export-diagnostics': {
      if (state.nativeDialogBusy || !isTauri()) break;
      const profileId = state.selectedAccount;
      const epoch = state.accountEpoch;
      if (!profileId) break;
      state.nativeDialogBusy = true;
      state.error = '';
      render();
      try {
        const result = await invoke<{ cancelled?: boolean }>('export_diagnostics', { profileId });
        if (!result.cancelled && isCurrentAccount(epoch, profileId)) state.message = 'Redacted diagnostics report saved.';
      } catch (error) {
        if (isCurrentAccount(epoch, profileId)) state.error = messageOf(error);
      } finally {
        state.nativeDialogBusy = false;
        render();
      }
      break;
    }
    case 'configure-root': {
      const epoch = state.accountEpoch;
      state.nativeDialogBusy = true;
      render();
      try {
        const selected = await open({ directory: true, multiple: false, title: 'Choose OpenCloud drive folder' });
        if (isCurrentAccount(epoch) && typeof selected === 'string') await run('configure', { cloud_root: selected });
      } catch (error) { if (isCurrentAccount(epoch)) state.error = messageOf(error); }
      finally { state.nativeDialogBusy = false; render(); }
      break;
    }
    case 'toggle-autostart': {
      if (!providerAvailable(state.status?.provider_supported) || typeof state.autostart !== 'boolean') return;
      const epoch = state.accountEpoch;
      const enabled = state.autostart !== true;
      await run('set_autostart', { enabled });
      if (isCurrentAccount(epoch)) { if (!state.error) state.autostart = enabled; render(); } break;
    }
    case 'check-desktop-update': await refreshDesktopUpdate(true); break;
    case 'download-desktop-update': await downloadDesktopUpdate(); break;
    case 'install-desktop-update': await installDesktopUpdate(); break;
    case 'later-desktop-update': await laterDesktopUpdate(); break;
    case 'open-desktop-release': await openDesktopRelease(); break;
    default: void element;
  }
}
function invalidateMediaPreview() {
  mediaPreview.generation++;
  mediaPreview.result = null;
  mediaPreview.error = '';
}

async function runMediaPreview() {
  if (mediaPreview.loading) return;
  const source = mediaPreview.source.trim();
  const destinationRoot = mediaPreview.destinationRoot.trim();
  if (!source || !destinationRoot) {
    mediaPreview.error = 'Choose a local source folder and enter a destination folder path.';
    render();
    return;
  }
  if (!isTauri()) {
    mediaPreview.error = 'Media preview is available in Raiun Desktop, not in the browser layout preview.';
    render();
    return;
  }
  const generation = ++mediaPreview.generation;
  const organization = mediaPreview.organization;
  mediaPreview.loading = true;
  mediaPreview.error = '';
  mediaPreview.result = null;
  render();
  try {
    const result = await invoke<MediaScanResponse>('preview_media_scan', {
      source,
      destinationRoot,
      filter: mediaPreview.filter,
      organization,
      filesystemMtimeUtc: organization === 'utc_year_month'
    });
    if (generation === mediaPreview.generation) mediaPreview.result = result;
  } catch (error) {
    if (generation === mediaPreview.generation) mediaPreview.error = messageOf(error);
  } finally {
    if (generation === mediaPreview.generation) {
      mediaPreview.loading = false;
      render();
    }
  }
}

async function openAccountFolder(command: 'open_cloud_folder' | 'open_recovery_folder') {
  const epoch = state.accountEpoch;
  const selectedProfileId = state.selectedAccount || null;
  state.mutationBusy++;
  render();
  try {
    await invoke(command, { profileId: selectedProfileId });
  } catch (error) {
    if (isCurrentAccount(epoch)) state.error = messageOf(error);
  } finally {
    state.mutationBusy = Math.max(0, state.mutationBusy - 1);
    if (isCurrentAccount(epoch)) render();
  }
}
async function openEncryptedEditRecoveryFolder() {
  if (nativeVaultAccess()) return;
  const epoch = state.accountEpoch;
  const profileId = state.selectedAccount || null;
  state.mutationBusy++;
  render();
  try {
    await invoke('open_encrypted_edit_recovery_folder', { profileId });
  } catch (error) {
    if (isCurrentAccount(epoch)) state.encryptedEditRecoveryError = messageOf(error);
  } finally {
    state.mutationBusy = Math.max(0, state.mutationBusy - 1);
    if (isCurrentAccount(epoch)) render();
  }
}
async function loadEncryptedEditRecoveries(reset: boolean) {
  if (!vaultAppFeaturesAvailable()) {
    state.encryptedEditRecoveryError = 'Encrypted recovery listing is unavailable for this Windows agent. Existing recovery data remains in place.';
    render();
    return;
  }
  if (state.encryptedEditRecoveryLoading) return;
  if (!state.agentReachable) {
    state.encryptedEditRecoveryError = 'Raiun is not connected. Start it, then try again.';
    render();
    return;
  }
  const epoch = state.accountEpoch;
  const profileId = state.selectedAccount;
  const previous = state.encryptedEditRecoveryPage;
  const after = reset ? null : previous?.next_after;
  if (!reset && !after) return;
  state.encryptedEditRecoveryLoading = true;
  state.encryptedEditRecoveryError = '';
  render();
  const args: Record<string, unknown> = { limit: 50 };
  if (after) args.after = after;
  try {
    const page = validateEncryptedEditRecoveryPage(await request<EncryptedEditRecoveryPage>('encrypted_edit_recoveries', args));
    if (!isCurrentAccount(epoch, profileId)) return;
    const priorItems = reset ? [] : previous?.items || [];
    const seen = new Set(priorItems.map(item => item.record_id || 'unrecognized'));
    state.encryptedEditRecoveryPage = {
      ...page,
      items: [...priorItems, ...page.items.filter(item => !item.record_id || !seen.has(item.record_id))]
    };
  } catch (error) {
    if (isCurrentAccount(epoch, profileId) && !isStaleAccountRequest(error)) state.encryptedEditRecoveryError = messageOf(error);
  } finally {
    if (isCurrentAccount(epoch, profileId)) {
      state.encryptedEditRecoveryLoading = false;
      render();
    }
  }
}
function validateEncryptedEditRecoveryPage(value: EncryptedEditRecoveryPage): EncryptedEditRecoveryPage {
  const count = (candidate: unknown) => Number.isSafeInteger(candidate) && (candidate as number) >= 0;
  const states = new Set<EncryptedEditRecoveryItem['state']>(['building', 'pending', 'uncertain', 'committed', 'clean', 'corrupt']);
  if (!value || !Array.isArray(value.items) || !value.counts ||
      !count(value.scanned_entries) || !count(value.warning_count) || typeof value.truncated !== 'boolean' ||
      !(value.next_after == null || (typeof value.next_after === 'string' && value.next_after.length <= 20 && /^(0|[1-9][0-9]*)$/.test(value.next_after))) ||
      !['building', 'pending', 'uncertain', 'committed', 'clean', 'corrupt'].every(key => count(value.counts[key as keyof typeof value.counts]))) {
    throw new Error('The agent returned an invalid encrypted-edit status list.');
  }
  for (const item of value.items) {
    if (!item || !(item.record_id == null || (typeof item.record_id === 'string' && item.record_id.length <= 128)) ||
        !(item.bytes == null || count(item.bytes)) || !states.has(item.state) ||
        !(item.warning == null || (typeof item.warning === 'string' && item.warning.length <= 512))) {
      throw new Error('The agent returned an invalid encrypted-edit status entry.');
    }
  }
  return value;
}
async function loadRecoveries(reset: boolean) {
  if (isWindowsAgentStatus(state.status) || !providerAvailable(state.status?.provider_supported)) {
    state.recoveryError = 'Saved-copy listing is unavailable for this Windows agent. Existing recovery data remains in place.';
    render();
    return;
  }
  if (state.recoveryLoading) return;
  if (!state.agentReachable) {
    state.recoveryError = 'Raiun is not connected. Start it, then try again.';
    render();
    return;
  }
  const epoch = state.accountEpoch;
  const recoveryFolder = state.status?.recovery_folder || null;
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
    if (!isCurrentAccount(epoch)) return;
    if ((state.status?.recovery_folder || null) !== recoveryFolder) return;
    const priorItems = reset ? [] : (previous?.items || []);
    const seen = new Set(priorItems.map(item => item.spool_key));
    state.recoveryPage = {
      ...page,
      items: [...priorItems, ...page.items.filter(item => !seen.has(item.spool_key))]
    };
  } catch (error) {
    if (isCurrentAccount(epoch) && !isStaleAccountRequest(error) && (state.status?.recovery_folder || null) === recoveryFolder) state.recoveryError = messageOf(error);
  } finally {
    if (isCurrentAccount(epoch)) { state.recoveryLoading = false; render(); }
  }
}
async function beginSignIn() {
  const epoch = state.accountEpoch;
  const profileId = state.selectedAccount;
  if (!profileId) { state.error = 'Add or restore an account before signing in.'; render(); return; }
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
  state.mutationBusy++;
  render();
  try {
    const auth = await request<{ url: string; user_code?: string | null; expires_in?: number | null }>('auth_begin', { server: state.server, client_id: state.clientId });
    if (auth.user_code) {
      const duration = auth.expires_in ? ` · expires in ${Math.ceil(auth.expires_in / 60)} min` : '';
      state.message = `Enter code ${auth.user_code} in the browser to finish sign-in${duration}.`;
    } else state.message = 'Sign-in page opened. Raiun will update when your account connects.';
    if (isCurrentAccount(epoch, profileId)) await refresh(false);
  } catch (error) {
    if (isCurrentAccount(epoch, profileId) && !isStaleAccountRequest(error)) {
      const originalError = messageOf(error);
      await refresh(false);
      if (isCurrentAccount(epoch, profileId)) state.error = originalError;
    }
  }
  finally { state.mutationBusy = Math.max(0, state.mutationBusy - 1); if (isCurrentAccount(epoch, profileId)) render(); }
}
async function cancelSignIn() {
  if (!windowsSignInPending() || state.mutationBusy) return;
  const epoch = state.accountEpoch;
  state.error = '';
  state.mutationBusy++;
  render();
  try {
    const result = await request<{ cancelled: boolean; cleanup_uncertain?: boolean }>('auth_cancel');
    if (isCurrentAccount(epoch)) await refresh(false);
    if (isCurrentAccount(epoch) && result.cleanup_uncertain) state.error = 'Sign-in was cancelled, but Raiun could not confirm removal of its saved session from Windows protected storage.';
  } catch (error) {
    if (isCurrentAccount(epoch) && !isStaleAccountRequest(error)) state.error = messageOf(error);
  } finally {
    state.mutationBusy = Math.max(0, state.mutationBusy - 1);
    if (isCurrentAccount(epoch)) render();
  }
}
async function loadSpaces(force = false) {
  if (!featureAvailable('folder_sync_supported') && !featureAvailable('media_jobs_supported') && !featureAvailable('vaults_supported')) return;
  if (!state.status?.connected || state.spacesLoading) return;
  const epoch = state.accountEpoch;
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
    const spaces = await request<Space[]>('spaces');
    if (!isCurrentAccount(epoch)) return;
    state.spaces = spaces;
    if (!state.spaces.some(space => space.id === state.spaceId)) {
      state.spaceId = state.spaces.find(space => space.personal && space.writable && !space.encrypted)?.id || '';
    }
  } catch (error) {
    if (!isCurrentAccount(epoch) || isStaleAccountRequest(error)) return;
    state.spacesError = messageOf(error);
  } finally {
    if (isCurrentAccount(epoch)) { state.spacesLoading = false; render(); }
  }
}
async function openEncryptedAccess() {
  if (accountSwitchDisabled() && state.page !== 'encrypted') return;
  state.page = 'encrypted';
  if (!featureAvailable('vaults_supported') || !state.agentReachable) {
    state.vaultAccessOpen = false;
    render();
    return;
  }
  const epoch = state.accountEpoch;
  state.pickerGeneration++;
  state.pickerOpen = false;
  state.vaultAccessOpen = true;
  state.vaultAccessSpaceId = '';
  cachedVaultRootsUi.generation++;
  cachedVaultRootsUi.roots = [];
  cachedVaultRootsUi.nextAfter = null;
  cachedVaultRootsUi.truncated = false;
  cachedVaultRootsUi.error = '';
  cachedVaultRootsUi.selected = '';
  cachedVaultRootsUi.accountEpoch = epoch;
  state.spacesError = '';
  render();
  await Promise.all([
    state.status?.connected === true ? loadSpaces(true) : Promise.resolve(),
    copyProducerUi.source || nativeVaultAccess() ? Promise.resolve() : loadCachedVaultRoots(true)
  ]);
  if (!isCurrentAccount(epoch) || !state.vaultAccessOpen) return;
}
function closeEncryptedAccess() {
  if (copyProducerUi.source && !copyProducerUi.jobId) resetCopyProducerFlow();
  state.vaultAccessOpen = false;
  state.vaultAccessSpaceId = '';
  state.pickerGeneration++;
  cachedVaultRootsUi.generation++;
  cachedVaultRootsUi.loading = false;
  cachedVaultRootsUi.selected = '';
  render();
}
function cachedVaultRootKey(root: CachedVaultRoot) { return JSON.stringify([root.space_id, root.root_resource_id]); }
async function loadCachedVaultRoots(reset: boolean) {
  if (!vaultAppFeaturesAvailable()) return;
  if (!state.vaultAccessOpen || cachedVaultRootsUi.loading) return;
  if (cachedVaultRootsUi.accountEpoch !== state.accountEpoch) reset = true;
  const epoch = state.accountEpoch;
  const profileId = state.selectedAccount;
  const generation = reset ? ++cachedVaultRootsUi.generation : cachedVaultRootsUi.generation;
  const cursor = reset ? null : cachedVaultRootsUi.nextAfter;
  if (!reset && !cursor) return;
  const previous = reset ? [] : cachedVaultRootsUi.roots;
  cachedVaultRootsUi.loading = true;
  cachedVaultRootsUi.error = '';
  if (reset) {
    cachedVaultRootsUi.roots = [];
    cachedVaultRootsUi.nextAfter = null;
    cachedVaultRootsUi.truncated = false;
    cachedVaultRootsUi.accountEpoch = epoch;
  }
  render();
  const args: Record<string, unknown> = { limit: 50 };
  if (cursor) args.after = cursor;
  try {
    const page = await request<CachedVaultRootsPage>('vault_cached_roots', args);
    if (!isCurrentAccount(epoch, profileId) || !state.vaultAccessOpen || generation !== cachedVaultRootsUi.generation) return;
    if (!Array.isArray(page.roots)) throw new Error('The agent returned an invalid saved encrypted-location list.');
    const roots = page.roots.filter(root => root && typeof root.space_id === 'string' && root.space_id.length > 0 && root.space_id.length <= 1024 && typeof root.root_resource_id === 'string' && root.root_resource_id.length > 0 && root.root_resource_id.length <= 1024 && root.snapshot_available === true && ((root.pin_id == null && root.generation == null) || (typeof root.pin_id === 'string' && root.pin_id.length > 0 && root.pin_id.length <= 512 && Number.isSafeInteger(root.generation) && (root.generation ?? -1) >= 0)));
    if (roots.length !== page.roots.length) throw new Error('The agent returned an invalid saved encrypted-location entry.');
    const seen = new Set(previous.map(cachedVaultRootKey));
    cachedVaultRootsUi.roots = [...previous, ...roots.filter(root => !seen.has(cachedVaultRootKey(root)))];
    cachedVaultRootsUi.nextAfter = page.next_after && typeof page.next_after.space_id === 'string' && typeof page.next_after.root_resource_id === 'string' ? page.next_after : null;
    cachedVaultRootsUi.truncated = page.truncated === true;
    cachedVaultRootsUi.selected = cachedVaultRootsUi.roots.some(root => cachedVaultRootKey(root) === cachedVaultRootsUi.selected)
      ? cachedVaultRootsUi.selected
      : cachedVaultRootsUi.roots[0] ? cachedVaultRootKey(cachedVaultRootsUi.roots[0]) : '';
  } catch (error) {
    if (isCurrentAccount(epoch, profileId) && state.vaultAccessOpen && generation === cachedVaultRootsUi.generation && !isStaleAccountRequest(error)) cachedVaultRootsUi.error = messageOf(error);
  } finally {
    if (isCurrentAccount(epoch, profileId) && state.vaultAccessOpen && generation === cachedVaultRootsUi.generation) {
      cachedVaultRootsUi.loading = false;
      render();
    }
  }
}
async function openCachedVaultRoot(opener?: HTMLElement) {
  if (nativeVaultAccess()) return;
  if (!state.vaultAccessOpen || cachedVaultRootsUi.loading || state.accountSwitching || state.mutationBusy > 0 || state.nativeDialogBusy) return;
  const root = cachedVaultRootsUi.roots.find(item => cachedVaultRootKey(item) === cachedVaultRootsUi.selected);
  if (!root) return;
  if (opener) vaultDialogFocusReturn = captureVaultDialogFocusReturn(opener);
  if (state.page !== 'encrypted') closeEncryptedAccess();
  await openVaultFlow('browse', root.space_id, '', undefined, false, root.root_resource_id, true, root.pin_id || undefined, Number.isSafeInteger(root.generation) ? root.generation! : undefined);
}
async function browseEncryptedSpace() {
  if (!state.vaultAccessOpen || state.spacesLoading || state.status?.connected !== true) return;
  const epoch = state.accountEpoch;
  const space = state.spaces.find(candidate => candidate.id === state.vaultAccessSpaceId);
  if (!space) return;
  const workspace = state.page === 'encrypted';
  if (!workspace) state.vaultAccessOpen = false;
  state.vaultAccessSpaceId = '';
  cachedVaultRootsUi.generation++;
  cachedVaultRootsUi.loading = false;
  state.spaceId = space.id;
  state.pickerPurpose = 'encrypted_access';
  state.pickerPath = '/';
  state.pickerEntries = [];
  state.pickerError = '';
  state.pickerWritable = { '/': space.writable === true };
  if (space.encrypted) {
    await openVaultFlow('browse', space.id, '/');
    return;
  }
  state.pickerOpen = true;
  render();
  await browseRemote('/');
  if (!isCurrentAccount(epoch)) return;
}
async function browseRemote(path: string) {
  if (!state.spaceId) return;
  const epoch = state.accountEpoch;
  const generation = ++state.pickerGeneration;
  const spaceId = state.spaceId;
  const purpose = state.pickerPurpose;
  let listingLoaded = false;
  if (purpose === 'offline') offlineUi.folderListing = null;
  state.pickerPath = path; state.pickerEntries = []; state.pickerError = ''; render();
  try {
    const entries = await request<RemoteEntry[]>('list', { space_id: spaceId, path });
    if (!isCurrentAccount(epoch) || state.pickerGeneration !== generation || state.spaceId !== spaceId || state.pickerPurpose !== purpose || !state.pickerOpen || state.pickerPath !== path) return;
    state.pickerEntries = entries;
    listingLoaded = true;
    if (purpose === 'offline') {
      offlineUi.folderListing = { epoch, generation, spaceId, path };
      offlineUi.folderPolicies.delete(offlinePolicyKey(path));
      for (const entry of entries) if (entry.directory && !entry.encrypted) offlineUi.folderPolicies.delete(offlinePolicyKey(entry.path));
    }
  } catch (error) {
    if (!isCurrentAccount(epoch) || isStaleAccountRequest(error) || state.pickerGeneration !== generation || state.spaceId !== spaceId || state.pickerPurpose !== purpose || !state.pickerOpen || state.pickerPath !== path) return;
    state.pickerError = messageOf(error);
  }
  if (isCurrentAccount(epoch) && state.pickerGeneration === generation && state.spaceId === spaceId && state.pickerPurpose === purpose && state.pickerOpen && state.pickerPath === path) {
    render();
    if (listingLoaded && purpose === 'offline' && !state.spaces.find(space => space.id === spaceId)?.encrypted) {
      void loadOfflineFolderPolicy(path, path, true, epoch, generation, spaceId);
    }
  }
}
async function openOfflineFiles() {
  if (accountSwitchDisabled() && state.page !== 'offline') return;
  state.page = 'offline';
  if (isWindowsAgentStatus(state.status)) {
    state.pickerGeneration++;
    state.pickerOpen = false;
    state.pickerPurpose = 'pair';
    render();
    void refreshWindowsDeviceCacheUsage();
    return;
  }
  if (!providerAvailable(state.status?.provider_supported) || state.status?.connected !== true) {
    state.pickerGeneration++;
    state.pickerOpen = false;
    state.pickerPurpose = 'pair';
    render();
    return;
  }
  const epoch = state.accountEpoch;
  state.pickerGeneration++;
  state.pickerPurpose = 'offline';
  state.pickerOpen = true;
  state.pickerPath = '/';
  state.pickerEntries = [];
  state.pickerError = '';
  state.spaceId = '';
  offlineUi.error = '';
  render();
  await loadSpaces(true);
  if (!isCurrentAccount(epoch) || !state.pickerOpen || state.pickerPurpose !== 'offline') return;
  if (!state.spaceId) state.spaceId = state.spaces.find(space => !space.encrypted)?.id || '';
  if (state.spaceId && !state.spaces.find(space => space.id === state.spaceId)?.encrypted) {
    void loadOfflinePins(state.spaceId);
    await browseRemote('/');
  }
  else render();
  if (offlineUi.pin?.accountEpoch === epoch && ['preparing', 'building'].includes(offlineUi.pin.state)) scheduleOfflinePinPoll(0);
}
async function loadOfflinePins(spaceId: string) {
  const epoch = state.accountEpoch;
  const key = offlinePinsKey(spaceId);
  if (offlineUi.pinsLoading.has(key) || state.pickerPurpose !== 'offline' || !state.pickerOpen || !spaceId) return;
  offlineUi.pinsLoading.add(key);
  render();
  try {
    const result = await request<PersistedOfflinePin[]>('cache_pins', { space_id: spaceId });
    if (!isCurrentAccount(epoch) || state.pickerPurpose !== 'offline' || !state.pickerOpen || state.spaceId !== spaceId) return;
    offlineUi.pins.set(key, result.filter(pin => typeof pin.pin_id === 'string' && typeof pin.root_resource_id === 'string' && typeof pin.path === 'string' && (pin.state === 'building' || pin.state === 'ready' || pin.state === 'stale' || pin.state === 'unavailable')));
  } catch (error) {
    if (isCurrentAccount(epoch) && state.pickerPurpose === 'offline' && state.pickerOpen && state.spaceId === spaceId && !isStaleAccountRequest(error)) offlineUi.error = messageOf(error);
  } finally {
    offlineUi.pinsLoading.delete(key);
    if (isCurrentAccount(epoch) && state.pickerPurpose === 'offline' && state.pickerOpen && state.spaceId === spaceId) render();
  }
}
function offlineRequestIsCurrent(epoch: number, generation: number, spaceId: string, path?: string) {
  return isCurrentAccount(epoch) && state.pickerOpen && state.pickerPurpose === 'offline' &&
    state.pickerGeneration === generation && state.spaceId === spaceId && (path === undefined || state.pickerPath === path);
}
function offlineFileIsCurrent(spaceId: string, path: string) {
  const entry = state.pickerEntries.find(item => item.path === path);
  return !!entry && !entry.directory && !entry.encrypted && state.spaceId === spaceId;
}
function validOfflineFolderPath(path: string) {
  return path === '/' || (path.length <= 4096 && path.startsWith('/') && !path.includes('\\') &&
    !/[\u0000-\u001f\u007f]/.test(path) && path.slice(1).split('/').every(part => !!part && part !== '.' && part !== '..'));
}
function offlineFolderIsCurrent(path: string, listingPath: string, currentFolder: boolean, spaceId: string) {
  const listing = offlineUi.folderListing;
  if (!listing || listing.epoch !== state.accountEpoch || listing.generation !== state.pickerGeneration || listing.spaceId !== spaceId || listing.path !== listingPath) return false;
  if (!validOfflineFolderPath(path) || !validOfflineFolderPath(listingPath) || state.pickerPath !== listingPath || state.spaceId !== spaceId ||
      !state.spaces.some(space => space.id === spaceId && !space.encrypted)) return false;
  if (currentFolder) return path === listingPath;
  return state.pickerEntries.some(entry => entry.path === path && entry.directory && !entry.encrypted);
}
async function loadOfflineFolderPolicy(path: string, listingPath: string, currentFolder = false, epoch = state.accountEpoch, generation = state.pickerGeneration, spaceId = state.spaceId) {
  if (!folderPolicyControlsAvailable() || state.pickerPurpose !== 'offline' || !state.pickerOpen || state.status?.connected !== true ||
      !offlineFolderIsCurrent(path, listingPath, currentFolder, spaceId)) return;
  const key = offlinePolicyKey(path);
  if (offlineUi.folderPolicyLoading.has(key) || offlineUi.folderPolicySaving.has(key)) return;
  offlineUi.error = '';
  const requestToken = Symbol();
  offlineUi.folderPolicyLoading.set(key, requestToken);
  render();
  try {
    const result = await request<{ space_id: string; path: string; policy: unknown }>('cache_policy_get', { space_id: spaceId, path });
    if (!offlineRequestIsCurrent(epoch, generation, spaceId, listingPath) || !offlineFolderIsCurrent(path, listingPath, currentFolder, spaceId)) return;
    if (result.space_id !== spaceId || result.path !== path || (result.policy !== 'recent' && result.policy !== 'cloud_only')) {
      throw new Error('The agent returned an invalid folder cache policy.');
    }
    offlineUi.folderPolicies.set(key, result.policy);
  } catch (error) {
    if (offlineRequestIsCurrent(epoch, generation, spaceId, listingPath) && offlineFolderIsCurrent(path, listingPath, currentFolder, spaceId) && !isStaleAccountRequest(error)) {
      offlineUi.error = messageOf(error);
    }
  } finally {
    if (offlineUi.folderPolicyLoading.get(key) === requestToken) offlineUi.folderPolicyLoading.delete(key);
    if (isCurrentAccount(epoch) && state.pickerOpen && state.pickerPurpose === 'offline' && state.spaceId === spaceId && state.pickerPath === listingPath) render();
  }
}
async function setOfflineFolderPolicy(path: string, listingPath: string, policy: 'recent' | 'cloud_only', currentFolder: boolean) {
  const spaceId = state.spaceId;
  const epoch = state.accountEpoch;
  const generation = state.pickerGeneration;
  if ((policy !== 'recent' && policy !== 'cloud_only') || !folderPolicyControlsAvailable() || state.pickerPurpose !== 'offline' ||
      !state.pickerOpen || state.status?.connected !== true || !offlineFolderIsCurrent(path, listingPath, currentFolder, spaceId)) return;
  const key = offlinePolicyKey(path);
  if (offlineUi.folderPolicySaving.has(key) || offlineUi.folderPolicyLoading.has(key)) return;
  const requestToken = Symbol();
  offlineUi.folderPolicySaving.set(key, requestToken);
  offlineUi.error = '';
  render();
  try {
    const result = await request<{ space_id: string; path: string; policy: unknown }>('cache_policy_set', { space_id: spaceId, path, policy });
    if (!offlineRequestIsCurrent(epoch, generation, spaceId, listingPath) || !offlineFolderIsCurrent(path, listingPath, currentFolder, spaceId)) return;
    if (result.space_id !== spaceId || result.path !== path ||
        (result.policy !== 'recent' && result.policy !== 'cloud_only') || (policy === 'cloud_only' && result.policy !== 'cloud_only')) {
      throw new Error('The agent did not confirm this folder cache policy.');
    }
    offlineUi.folderPolicies.set(key, result.policy);
    state.message = result.policy === 'cloud_only'
      ? policy === 'recent'
        ? `${path === '/' ? 'This folder' : lastPath(path)} remains Cloud only because an inherited folder setting applies. Saved offline copies remain separate.`
        : `${path === '/' ? 'This folder' : lastPath(path)} is Cloud only. Removable cached copies were cleared.`
      : `${path === '/' ? 'This folder' : lastPath(path)} is set to Recently used. Saved offline copies remain separate.`;
    offlineUi.policies.clear();
    offlineUi.availabilityStates.clear();
    offlineUi.folderPolicies.clear();
    await browseRemote(listingPath);
  } catch (error) {
    if (offlineRequestIsCurrent(epoch, generation, spaceId, listingPath) && offlineFolderIsCurrent(path, listingPath, currentFolder, spaceId) && !isStaleAccountRequest(error)) {
      offlineUi.error = messageOf(error);
    }
  } finally {
    const ownedRequest = offlineUi.folderPolicySaving.get(key) === requestToken;
    if (ownedRequest) offlineUi.folderPolicySaving.delete(key);
    if (isCurrentAccount(epoch) && state.pickerOpen && state.pickerPurpose === 'offline' && state.spaceId === spaceId && state.pickerPath === listingPath) {
      render();
      // The browse's automatic read was blocked by this save token. Read
      // effective state only after releasing our own token, in the fresh view.
      if (ownedRequest && offlineFolderIsCurrent(path, listingPath, currentFolder, spaceId)) {
        await loadOfflineFolderPolicy(path, listingPath, currentFolder);
      }
    }
  }
}
async function loadOfflinePolicy(path: string) {
  const spaceId = state.spaceId;
  const epoch = state.accountEpoch;
  const generation = state.pickerGeneration;
  if (state.pickerPurpose !== 'offline' || !state.pickerOpen || state.status?.connected !== true || !state.status?.offline_cache?.available || !offlineFileIsCurrent(spaceId, path)) return;
  const key = offlinePolicyKey(path);
  if (offlineUi.policyLoading.has(key) || offlineUi.policySaving.has(key)) return;
  offlineUi.error = '';
  offlineUi.policyLoading.add(key);
  render();
  try {
    const result = await request<{ space_id: string; path: string; policy: OfflinePolicy; availability_state: unknown }>('cache_policy_get', { space_id: spaceId, path });
    if (offlineRequestIsCurrent(epoch, generation, spaceId) && state.pickerEntries.some(entry => entry.path === path && !entry.directory && !entry.encrypted)) {
      if (['recent', 'always_offline', 'cloud_only'].includes(result.policy)) offlineUi.policies.set(key, result.policy);
      else throw new Error('The agent returned an unknown offline availability setting.');
      const availabilityState = safeOfflineAvailabilityState(result.availability_state);
      offlineUi.availabilityStates.set(key, result.policy === 'always_offline' ? availabilityState : null);
    }
  } catch (error) {
    if (offlineRequestIsCurrent(epoch, generation, spaceId) && !isStaleAccountRequest(error)) offlineUi.error = messageOf(error);
  } finally {
    offlineUi.policyLoading.delete(key);
    if (offlineRequestIsCurrent(epoch, generation, spaceId)) render();
  }
}
async function setOfflinePolicy(path: string, policy: OfflinePolicy) {
  const spaceId = state.spaceId;
  const epoch = state.accountEpoch;
  const generation = state.pickerGeneration;
  if (!['recent', 'always_offline', 'cloud_only'].includes(policy) || state.pickerPurpose !== 'offline' || state.status?.connected !== true || !state.status?.offline_cache?.available || !offlineFileIsCurrent(spaceId, path)) return;
  const key = offlinePolicyKey(path);
  if (offlineUi.policySaving.has(key)) return;
  offlineUi.policySaving.add(key);
  offlineUi.error = '';
  render();
  try {
    const result = await request<{ space_id: string; path: string; policy: OfflinePolicy; availability_state: unknown }>('cache_policy_set', { space_id: spaceId, path, policy });
    if (offlineRequestIsCurrent(epoch, generation, spaceId) && state.pickerEntries.some(entry => entry.path === path && !entry.directory && !entry.encrypted)) {
      if (result.space_id !== spaceId || result.path !== path || result.policy !== policy) throw new Error('The agent did not confirm this offline availability setting.');
      const availabilityState = safeOfflineAvailabilityState(result.availability_state);
      offlineUi.policies.set(key, policy);
      offlineUi.availabilityStates.set(key, policy === 'always_offline' ? availabilityState : null);
      state.message = policy === 'always_offline'
        ? `${lastPath(path)} is set to always available offline. ${offlineAvailabilityLabel(availabilityState)}.`
        : policy === 'cloud_only' ? `${lastPath(path)} is set to Cloud only. Protected copies are kept.` : `${lastPath(path)} is set to Recently used.`;
      await refresh(false);
    }
  } catch (error) {
    if (offlineRequestIsCurrent(epoch, generation, spaceId) && !isStaleAccountRequest(error)) offlineUi.error = messageOf(error);
  } finally {
    offlineUi.policySaving.delete(key);
    if (offlineRequestIsCurrent(epoch, generation, spaceId)) render();
  }
}
async function startOfflinePin(path: string) {
  const spaceId = state.spaceId;
  const epoch = state.accountEpoch;
  const generation = state.pickerGeneration;
  const entry = path === '/' ? null : state.pickerEntries.find(item => item.path === path);
  if (state.pickerPurpose !== 'offline' || !state.pickerOpen || state.status?.connected !== true || !state.status?.offline_cache?.available || !spaceId || state.spaces.find(space => space.id === spaceId)?.encrypted || (path !== '/' && (!entry || entry.encrypted || !entry.directory)) || offlineUi.pin && ['preparing', 'building'].includes(offlineUi.pin.state)) return;
  offlineUi.error = '';
  try {
    const started = await request<Omit<OfflinePinStatus, 'accountEpoch'>>('cache_pin_start', { space_id: spaceId, path });
    if (!offlineRequestIsCurrent(epoch, generation, spaceId) || started.space_id !== spaceId || started.path !== path) return;
    offlineUi.pin = { ...started, accountEpoch: epoch };
    render();
    if (['preparing', 'building'].includes(started.state)) scheduleOfflinePinPoll(250);
    else {
      if (started.state === 'ready' || started.state === 'stale' || started.state === 'unavailable') await loadOfflinePins(spaceId);
      await refresh(false);
    }
  } catch (error) {
    if (offlineRequestIsCurrent(epoch, generation, spaceId) && !isStaleAccountRequest(error)) {
      offlineUi.error = messageOf(error);
      render();
    }
  }
}
function scheduleOfflinePinPoll(delay = 1200) {
  if (offlineUi.pollTimer) window.clearTimeout(offlineUi.pollTimer);
  const pin = offlineUi.pin;
  if (!pin || !['preparing', 'building'].includes(pin.state)) { offlineUi.pollTimer = 0; return; }
  offlineUi.pollTimer = window.setTimeout(() => { offlineUi.pollTimer = 0; void pollOfflinePin(pin); }, delay);
}
async function pollOfflinePin(expected: OfflinePinStatus) {
  if (offlineUi.pin?.job_id !== expected.job_id || !isCurrentAccount(expected.accountEpoch)) return;
  try {
    const result = await request<Omit<OfflinePinStatus, 'accountEpoch'>>('cache_pin_status', { space_id: expected.space_id, job_id: expected.job_id });
    if (offlineUi.pin?.job_id !== expected.job_id || !isCurrentAccount(expected.accountEpoch) || result.space_id !== expected.space_id || result.job_id !== expected.job_id) return;
    offlineUi.pin = { ...result, accountEpoch: expected.accountEpoch };
    if (state.pickerOpen && state.pickerPurpose === 'offline' && state.spaceId === result.space_id) render();
    if (['preparing', 'building'].includes(result.state)) scheduleOfflinePinPoll(1200);
    else if (result.state === 'ready' || result.state === 'stale' || result.state === 'unavailable') {
      state.message = result.state === 'stale'
        ? `${lastPath(result.path || '/') || 'Folder'} offline snapshot is refreshing; previously verified bytes are retained.`
        : result.state === 'unavailable'
          ? `${lastPath(result.path || '/') || 'Folder'} is unavailable offline because its cloud location changed.`
          : `${lastPath(result.path || '/') || 'Folder'} snapshot is verified for offline use.`;
      if (state.pickerOpen && state.pickerPurpose === 'offline' && state.spaceId === result.space_id) await loadOfflinePins(result.space_id);
      await refresh(false);
    }
  } catch (error) {
    if (offlineUi.pin?.job_id !== expected.job_id || !isCurrentAccount(expected.accountEpoch)) return;
    offlineUi.pin = { ...expected, poll_error: messageOf(error) };
    if (state.pickerOpen && state.pickerPurpose === 'offline') render();
    scheduleOfflinePinPoll(3000);
  }
}
async function stopOfflinePin(pinId: string) {
  const spaceId = state.spaceId;
  const epoch = state.accountEpoch;
  const pinsKey = offlinePinsKey(spaceId);
  const pin = offlineUi.pins.get(pinsKey)?.find(item => item.pin_id === pinId);
  const visibleEntry = pin && state.pickerEntries.find(entry => entry.directory && entry.id === pin.root_resource_id);
  const activePin = offlineUi.pin?.accountEpoch === epoch && offlineUi.pin.space_id === spaceId && offlineUi.pin.pin_id === pinId ? offlineUi.pin : null;
  if (!pin || state.pickerPurpose !== 'offline' || !state.pickerOpen || state.status?.connected !== true) return;
  const key = offlinePinRemovalKey(spaceId, pinId);
  if (offlineUi.pinsRemoving.has(key)) return;
  offlineUi.pinsRemoving.add(key);
  offlineUi.error = '';
  render();
  try {
    const result = await request<{ pin_id: string; cancelled: boolean }>('cache_pin_cancel', { space_id: spaceId, pin_id: pinId });
    if (!isCurrentAccount(epoch) || state.spaceId !== spaceId || state.pickerPurpose !== 'offline' || !state.pickerOpen) return;
    if (result.pin_id !== pinId || result.cancelled !== true) throw new Error('The agent did not confirm removing this offline folder.');
    offlineUi.pins.set(pinsKey, offlineUi.pins.get(pinsKey)?.filter(item => item.pin_id !== pinId) || []);
    if (offlineUi.pin?.pin_id === pinId) offlineUi.pin = null;
    const target = visibleEntry?.path || activePin?.path;
    state.message = `Raiun stopped keeping ${target ? lastPath(target) : 'the saved folder snapshot'} offline. Recently used files may remain cached.`;
    await refresh(false);
  } catch (error) {
    if (isCurrentAccount(epoch) && state.spaceId === spaceId && state.pickerPurpose === 'offline' && state.pickerOpen && !isStaleAccountRequest(error)) offlineUi.error = messageOf(error);
  } finally {
    offlineUi.pinsRemoving.delete(key);
    if (isCurrentAccount(epoch) && state.pickerPurpose === 'offline' && state.pickerOpen && state.spaceId === spaceId) render();
  }
}
async function cancelOfflinePin() {
  const pin = offlineUi.pin;
  if (!pin || !['preparing', 'building'].includes(pin.state) || pin.cancel_requested) return;
  const epoch = state.accountEpoch;
  offlineUi.pin = { ...pin, cancel_requested: true };
  render();
  try {
    await request<{ cancel_requested: boolean }>('cache_pin_cancel', { space_id: pin.space_id, job_id: pin.job_id });
    if (offlineUi.pin?.job_id === pin.job_id && isCurrentAccount(epoch)) scheduleOfflinePinPoll(200);
  } catch (error) {
    if (offlineUi.pin?.job_id === pin.job_id && isCurrentAccount(epoch) && !isStaleAccountRequest(error)) {
      offlineUi.pin = { ...pin, poll_error: messageOf(error) };
      offlineUi.error = messageOf(error);
      render();
    }
  }
}
function clearOfflineUi() {
  if (offlineUi.pollTimer) window.clearTimeout(offlineUi.pollTimer);
  offlineUi.pollTimer = 0;
  offlineUi.policies.clear();
  offlineUi.availabilityStates.clear();
  offlineUi.policyLoading.clear();
  offlineUi.policySaving.clear();
  offlineUi.folderPolicies.clear();
  offlineUi.folderPolicyLoading.clear();
  offlineUi.folderPolicySaving.clear();
  offlineUi.folderListing = null;
  offlineUi.pins.clear();
  offlineUi.pinsLoading.clear();
  offlineUi.pinsRemoving.clear();
  offlineUi.pin = null;
  offlineUi.error = '';
}
function clearPendingOfflineWrites() {
  pendingWritesUi.retryTimers.forEach(timer => window.clearTimeout(timer));
  pendingWritesUi.retryTimers.clear();
  pendingWritesUi.reconcileJobs.clear();
  pendingWritesUi.generation++;
  pendingWritesUi.items = [];
  pendingWritesUi.nextAfter = null;
  pendingWritesUi.pendingCount = 0;
  pendingWritesUi.conflictCount = 0;
  pendingWritesUi.truncated = false;
  pendingWritesUi.loaded = false;
  pendingWritesUi.loading = false;
  pendingWritesUi.refreshQueued = false;
  pendingWritesUi.error = '';
  pendingWritesUi.accountEpoch = -1;
  pendingWritesUi.authGeneration = null;
  pendingWritesUi.accountScope = null;
  pendingWritesUi.expandedScopes.clear();
  pendingWritesUi.retryingSpaces.clear();
  pendingWritesUi.exportingWrites.clear();
}
async function openVaultFlow(intent: VaultDialogState['intent'], spaceId: string, rootPath: string, pairId?: string, rootWritable?: boolean, rootResourceId?: string, offlineUnlockOnly = false, offlinePinId?: string, offlinePinGeneration?: number) {
  if (nativeVaultAccess() && (intent === 'create' || intent === 'add' || offlineUnlockOnly)) return;
  if (!state.vaultDialog && !vaultDialogFocusReturn) vaultDialogFocusReturn = captureVaultDialogFocusReturn(document.activeElement);
  const accountEpoch = state.accountEpoch;
  const generation = ++state.vaultGeneration;
  const selectedSpaceWritable = state.spaces.find(space => space.id === spaceId)?.writable === true;
  const flow: VaultDialogState = {
    lockCleanupStatus: 'unknown', intent, spaceId, rootPath, rootResourceId: rootResourceId || '', rootEtag: '', directoryBindings: new Map(), currentDirectoryBinding: null, offlinePinId, offlinePinGeneration, path: '/', entries: [],
    unlocked: false, statusUnknown: false, initialized: offlineUnlockOnly, writable: !nativeVaultAccess() && !offlineUnlockOnly && selectedSpaceWritable && (rootWritable ?? true), offlineUnlockOnly, vaultMountReady: false, vaultMountWritable: offlineUnlockOnly ? false : null, vaultMountWriteUnavailableReason: offlineUnlockOnly ? 'offline_read_only' : null, vaultMountExistingFileOverwrite: false, vaultMountExistingFileInPlace: false, vaultMountExistingFileOverwriteReason: offlineUnlockOnly ? 'vault_locked' : null, rememberedStatus: offlineUnlockOnly ? 'unknown' : null, rememberOnDevice: false, pins: [], pinsNextAfter: null, pinsTruncated: false, pinsLoading: false, pinsError: '', pinBusy: false, pinJob: null, pinGeneration: 0, pinPollTimer: 0, editRetryBusy: false, editRetryError: '', editRetryJob: null, editRetryGeneration: 0, editRetryPollTimer: 0, loading: intent !== 'create' && !offlineUnlockOnly, error: '', passwordError: '', closeBlockedNotice: '', generation, accountEpoch, pairId
  };
  state.vaultDialog = flow;
  render();
  if (intent === 'create' || offlineUnlockOnly) { render(); return; }
  try {
    const inspected = await request<VaultInspect>('vault_inspect', { space_id: spaceId, root_path: rootPath });
    if (!isCurrentAccount(accountEpoch) || state.vaultDialog !== flow || state.vaultGeneration !== generation) return;
    if (rootResourceId && inspected.root_resource_id !== rootResourceId) {
      throw new Error('The encrypted root changed while Raiun was checking it. Open the location from the drive again.');
    }
    flow.rootPath = inspected.root_path;
    flow.rootResourceId = inspected.root_resource_id;
    flow.rootEtag = typeof inspected.root_etag === 'string' && isStrongVaultEtag(inspected.root_etag) ? inspected.root_etag : '';
    if (flow.rootResourceId && flow.rootEtag) {
      flow.directoryBindings.set('/', { resourceId: flow.rootResourceId, etag: flow.rootEtag });
      flow.currentDirectoryBinding = { resourceId: flow.rootResourceId, etag: flow.rootEtag };
    }
    flow.unlocked = inspected.unlocked;
    flow.initialized = inspected.initialized;
    flow.vaultMountReady = inspected.vault_mount_ready === true;
    flow.vaultMountWritable = typeof inspected.vault_mount_writable === 'boolean' ? inspected.vault_mount_writable : null;
    flow.vaultMountExistingFileOverwrite = inspected.vault_mount_existing_file_overwrite === true;
    flow.vaultMountExistingFileInPlace = nativeVaultAccess() && !flow.offlineUnlockOnly && flow.unlocked && flow.vaultMountReady && inspected.vault_mount_existing_file_in_place === true;
    flow.vaultMountExistingFileOverwriteReason = safeVaultExistingOverwriteReason(inspected.vault_mount_existing_file_overwrite_reason);
    flow.vaultMountWriteUnavailableReason = safeVaultMountWriteReason(inspected.vault_mount_write_unavailable_reason);
    flow.rememberedStatus = safeRememberedStatus(inspected.remembered_status);
    updateNativeVaultLockCleanup(flow, inspected.vault_lock_cleanup_status, inspected.unlocked ? 'unlock' : 'inspect');
    if (typeof inspected.writable === 'boolean') flow.writable = !nativeVaultAccess() && selectedSpaceWritable && inspected.writable;
    flow.loading = false;
    if (flow.unlocked && !nativeVaultAccess()) {
      if (!nativeVaultAccess()) await loadVaultPath(flow, '/');
      if (!nativeVaultAccess() && isCurrentAccount(accountEpoch) && state.vaultDialog === flow && flow.unlocked && !flow.statusUnknown) await loadVaultPins(flow, true);
    }
    else render();
  } catch (error) {
    if (isCurrentAccount(accountEpoch) && state.vaultDialog === flow && !isStaleAccountRequest(error)) {
      flow.error = messageOf(error);
      flow.statusUnknown = true;
      flow.loading = false;
      render();
    }
  }
}
async function loadVaultPath(flow: VaultDialogState, path: string) {
  if (nativeVaultAccess()) return;
  const accountEpoch = flow.accountEpoch;
  const generation = flow.generation;
  if (!flow.unlocked || !flow.rootResourceId || flow.loading) return;
  flow.loading = true;
  flow.error = '';
  flow.path = path;
  flow.currentDirectoryBinding = flow.directoryBindings.get(path) || (path === '/' && flow.rootEtag
    ? { resourceId: flow.rootResourceId, etag: flow.rootEtag }
    : null);
  render();
  try {
    const entries = await request<RemoteEntry[]>('vault_list', {
      space_id: flow.spaceId, root_path: flow.rootPath,
      root_resource_id: flow.rootResourceId, path,
      ...(flow.offlineUnlockOnly ? { offline: true } : {})
    });
    if (!isCurrentAccount(accountEpoch) || state.vaultDialog !== flow || state.vaultGeneration !== generation) return;
    flow.entries = entries;
    if (!flow.directoryBindings.has('/') && flow.rootResourceId && isStrongVaultEtag(flow.rootEtag)) {
      flow.directoryBindings.set('/', { resourceId: flow.rootResourceId, etag: flow.rootEtag });
    }
  } catch (error) {
    if (!isCurrentAccount(accountEpoch) || state.vaultDialog !== flow || isStaleAccountRequest(error)) return;
    flow.error = messageOf(error);
  } finally {
    if (isCurrentAccount(accountEpoch) && state.vaultDialog === flow && state.vaultGeneration === generation) {
      flow.loading = false;
      render();
    }
  }
}
function isStrongVaultEtag(value: unknown): value is string {
  return typeof value === 'string' && value.length >= 2 && value.length <= 4096 &&
    value.startsWith('"') && value.endsWith('"') && !value.startsWith('W/') && !/[\u0000-\u001f\u007f]/.test(value);
}
function copyProducerFeatureAvailable() {
  return isTauri() && !isWindowsAgentStatus(state.status) && providerAvailable(state.status?.provider_supported) && state.agentReachable;
}
function copyProducerPaused(spaceId: string) {
  return state.status?.paused === true || (state.status?.paused_space_ids || []).includes(spaceId);
}
function canStartVaultCopyFrom(flow: VaultDialogState, entry: RemoteEntry) {
  if (nativeVaultAccess()) return false;
  return copyProducerFeatureAvailable() && !copyProducerUi.source && flow.unlocked && !flow.statusUnknown &&
    !flow.offlineUnlockOnly && !flow.loading && !!flow.rootResourceId && !entry.directory && !!entry.id &&
    isStrongVaultEtag(entry.etag) && state.status?.connected === true && !copyProducerPaused(flow.spaceId) &&
    Number.isSafeInteger(state.status.auth_generation) && (state.status.auth_generation ?? -1) >= 0 &&
    !state.accountSwitching && !flow.pinBusy && !flow.pinJob && !flow.editRetryBusy &&
    !(flow.editRetryJob && ['queued', 'running'].includes(flow.editRetryJob.state));
}
function canUseVaultCopyDestination(flow: VaultDialogState) {
  if (nativeVaultAccess()) return false;
  const source = copyProducerUi.source;
  const binding = flow.currentDirectoryBinding;
  return !!source && !copyProducerUi.admissionUncertain && copyProducerFeatureAvailable() && state.status?.connected === true &&
    !copyProducerPaused(flow.spaceId) && !copyProducerPaused(source.expectation.spaceId) &&
    !state.accountSwitching && flow.unlocked && !flow.statusUnknown &&
    !flow.offlineUnlockOnly && flow.writable && !flow.loading && !!flow.rootResourceId && !!binding &&
    !!binding.resourceId && isStrongVaultEtag(binding.etag) &&
    !(source.expectation.spaceId === flow.spaceId && source.expectation.rootResourceId === flow.rootResourceId) &&
    isCurrentAccount(source.accountEpoch, source.profileId) && source.authGeneration === state.status.auth_generation;
}
function currentCopyProducerContext(context: CopyProducerContext) {
  if (nativeVaultAccess()) return false;
  const source = copyProducerUi.source;
  const destination = copyProducerUi.destination;
  return !!source && !!destination && !!copyProducerUi.context && copyProducerContextMatches(context, copyProducerUi.context) &&
    context.flowGeneration === copyProducerUi.flowGeneration && context.profileId === state.selectedAccount &&
    context.accountEpoch === state.accountEpoch && context.authGeneration === state.status?.auth_generation &&
    source.profileId === context.profileId && source.accountEpoch === context.accountEpoch &&
    source.authGeneration === context.authGeneration &&
    source.expectation.spaceId === context.source.spaceId && source.expectation.rootResourceId === context.source.rootResourceId &&
    source.expectation.resourceId === context.source.resourceId && source.expectation.version === context.source.version &&
    source.expectation.path === context.source.path &&
    destination.spaceId === context.destination.spaceId && destination.rootResourceId === context.destination.rootResourceId &&
    destination.parentResourceId === context.destination.parentResourceId && destination.parentVersion === context.destination.parentVersion &&
    destination.targetPath === context.destination.targetPath && state.status?.connected === true &&
    !copyProducerPaused(context.source.spaceId) && !copyProducerPaused(context.destination.spaceId);
}
function clearCopyProducerTimer() {
  if (copyProducerUi.timer) window.clearTimeout(copyProducerUi.timer);
  copyProducerUi.timer = 0;
}
function resetCopyProducerFlow() {
  clearCopyProducerTimer();
  copyProducerUi.generation++;
  copyProducerUi.flowGeneration++;
  copyProducerUi.source = null;
  copyProducerUi.context = null;
  copyProducerUi.destination = null;
  copyProducerUi.jobId = null;
  copyProducerUi.status = null;
  copyProducerUi.busy = false;
  copyProducerUi.error = '';
  copyProducerUi.pollError = '';
  copyProducerUi.admissionUncertain = false;
}
async function beginVaultCopy(entryIndex: number) {
  if (nativeVaultAccess()) return;
  const flow = state.vaultDialog;
  const entry = flow?.entries[entryIndex];
  if (!flow || !entry || !canStartVaultCopyFrom(flow, entry) || !entry.id || !isStrongVaultEtag(entry.etag)) return;
  const generation = ++copyProducerUi.generation;
  copyProducerUi.flowGeneration++;
  copyProducerUi.source = {
    expectation: { spaceId: flow.spaceId, rootResourceId: flow.rootResourceId, resourceId: entry.id, version: entry.etag, path: entry.path },
    profileId: state.selectedAccount,
    accountEpoch: state.accountEpoch,
    authGeneration: state.status!.auth_generation!,
    rootPath: flow.rootPath,
    displayName: lastPath(entry.path),
    size: Number.isSafeInteger(entry.size) && (entry.size ?? -1) >= 0 ? entry.size! : 0
  };
  copyProducerUi.context = null;
  copyProducerUi.destination = null;
  copyProducerUi.jobId = null;
  copyProducerUi.status = null;
  copyProducerUi.busy = false;
  copyProducerUi.error = '';
  copyProducerUi.pollError = '';
  copyProducerUi.admissionUncertain = false;
  state.vaultGeneration++;
  clearVaultPinUi(flow);
  state.vaultDialog = null;
  render();
  if (copyProducerUi.generation !== generation || !copyProducerUi.source) return;
  await openEncryptedAccess();
  if (copyProducerUi.generation !== generation || !copyProducerUi.source) return;
  render();
}
function copyProducerContextFor(source: CopyProducerSource, destination: CopyProducerDestinationExpectation): CopyProducerContext {
  return {
    profileId: source.profileId,
    accountEpoch: source.accountEpoch,
    authGeneration: source.authGeneration,
    flowGeneration: copyProducerUi.flowGeneration,
    source: source.expectation,
    destination
  };
}
function combineVaultPath(parent: string, name: string) {
  const base = parent === '/' ? '' : parent.replace(/\/$/, '');
  return `${base}/${name}`;
}
async function startVaultCopyToCurrentFolder() {
  if (nativeVaultAccess()) return;
  const flow = state.vaultDialog;
  const source = copyProducerUi.source;
  if (!flow || !source || copyProducerUi.admissionUncertain || copyProducerUi.busy || !canUseVaultCopyDestination(flow) || !flow.currentDirectoryBinding) return;
  const destination: CopyProducerDestinationExpectation = {
    spaceId: flow.spaceId,
    rootResourceId: flow.rootResourceId,
    parentResourceId: flow.currentDirectoryBinding.resourceId,
    parentVersion: flow.currentDirectoryBinding.etag,
    targetPath: combineVaultPath(flow.path, lastPath(source.expectation.path))
  };
  const context = copyProducerContextFor(source, destination);
  copyProducerUi.destination = destination;
  copyProducerUi.context = context;
  copyProducerUi.busy = true;
  copyProducerUi.error = '';
  copyProducerUi.pollError = '';
  const generation = copyProducerUi.generation;
  render();
  try {
    const start = validateCopyProducerStart(await request<unknown>('vault_copy_start', {
      space_id: destination.spaceId,
      root_resource_id: destination.rootResourceId,
      expected_generation: context.authGeneration,
      source_space_id: source.expectation.spaceId,
      source_root_resource_id: source.expectation.rootResourceId,
      source_path: source.expectation.path,
      source_resource_id: source.expectation.resourceId,
      source_etag: source.expectation.version,
      destination_path: destination.targetPath,
      destination_parent_resource_id: destination.parentResourceId,
      destination_parent_etag: destination.parentVersion
    }));
    if (generation !== copyProducerUi.generation || !currentCopyProducerContext(context)) return;
    if (!start.accepted) {
      copyProducerUi.error = copyProducerStartErrorMessage(start.error);
      copyProducerUi.destination = null;
      copyProducerUi.context = null;
      render();
      return;
    }
    copyProducerUi.jobId = start.job_id;
    copyProducerUi.status = { job_id: start.job_id, auth_generation: context.authGeneration, state: 'queued', cancel_requested: false };
    render();
    scheduleCopyProducerPoll(context, 500);
  } catch {
    if (generation === copyProducerUi.generation && currentCopyProducerContext(context)) {
      copyProducerUi.admissionUncertain = true;
      copyProducerUi.error = 'Raiun could not confirm whether this copy was accepted. Check the destination and pending operations before starting another copy.';
    }
  } finally {
    if (generation === copyProducerUi.generation) {
      copyProducerUi.busy = false;
      render();
    }
  }
}
function scheduleCopyProducerPoll(context: CopyProducerContext, delay: number) {
  clearCopyProducerTimer();
  if (nativeVaultAccess()) return;
  copyProducerUi.timer = window.setTimeout(() => { void pollCopyProducer(context); }, delay);
}
async function pollCopyProducer(context = copyProducerUi.context) {
  if (nativeVaultAccess()) return;
  const jobId = copyProducerUi.jobId;
  if (!context || !jobId || !currentCopyProducerContext(context)) return;
  clearCopyProducerTimer();
  const generation = copyProducerUi.generation;
  copyProducerUi.busy = true;
  copyProducerUi.pollError = '';
  render();
  try {
    const status = validateCopyProducerStatus(await request<unknown>('vault_copy_status', {
      space_id: context.destination.spaceId,
      root_resource_id: context.destination.rootResourceId,
      job_id: jobId,
      expected_generation: context.authGeneration
    }), jobId, context.authGeneration);
    if (generation !== copyProducerUi.generation || !currentCopyProducerContext(context)) return;
    copyProducerUi.status = status;
    if (status.state === 'queued' || status.state === 'running') scheduleCopyProducerPoll(context, 1000);
  } catch {
    if (generation === copyProducerUi.generation && currentCopyProducerContext(context)) {
      copyProducerUi.pollError = 'Raiun could not check this copy. Check status before taking another action.';
    }
  } finally {
    if (generation === copyProducerUi.generation) {
      copyProducerUi.busy = false;
      render();
    }
  }
}
async function cancelVaultCopy() {
  if (nativeVaultAccess()) return;
  const context = copyProducerUi.context;
  const jobId = copyProducerUi.jobId;
  if (!context || !jobId || !currentCopyProducerContext(context) || copyProducerUi.busy) return;
  copyProducerUi.busy = true;
  clearCopyProducerTimer();
  render();
  try {
    const status = validateCopyProducerStatus(await request<unknown>('vault_copy_cancel', {
      space_id: context.destination.spaceId,
      root_resource_id: context.destination.rootResourceId,
      job_id: jobId,
      expected_generation: context.authGeneration
    }), jobId, context.authGeneration);
    if (currentCopyProducerContext(context)) {
      copyProducerUi.status = status;
      if (status.state === 'queued' || status.state === 'running') scheduleCopyProducerPoll(context, 1000);
    }
  } catch {
    if (currentCopyProducerContext(context)) copyProducerUi.pollError = 'Raiun could not confirm that this copy stopped. Check its status before taking another action.';
  } finally {
    copyProducerUi.busy = false;
    render();
  }
}
function cancelCopyProducerWizard() {
  if (copyProducerUi.status?.state === 'queued' || copyProducerUi.status?.state === 'running') {
    void cancelVaultCopy();
    return;
  }
  resetCopyProducerFlow();
  state.vaultAccessOpen = false;
  state.vaultAccessSpaceId = '';
  render();
}
function invalidateCopyProducerForVaultTransition() {
  if (!copyProducerUi.source) return;
  resetCopyProducerFlow();
  state.message = 'The copy selection was cleared because an encrypted location changed lock state. Select the file again after both locations are unlocked.';
}
function invalidateCopyProducerIfUnavailable() {
  const source = copyProducerUi.source;
  if (!source) return;
  const destination = copyProducerUi.destination;
  if (state.accountEpoch !== source.accountEpoch || state.selectedAccount !== source.profileId ||
      state.status?.auth_generation !== source.authGeneration || state.status?.connected !== true ||
      copyProducerPaused(source.expectation.spaceId) || (destination && copyProducerPaused(destination.spaceId))) {
    invalidateCopyProducerForVaultTransition();
  }
}
function isVaultPinState(value: unknown): value is VaultPinState {
  return value === 'building' || value === 'ready' || value === 'stale';
}
function isVaultPinJobState(value: unknown): value is VaultPinJobState {
  return value === 'queued' || value === 'running' || value === 'ready' || value === 'failed' || value === 'cancelled';
}
function parseVaultPin(value: unknown): VaultPin | null {
  if (!value || typeof value !== 'object') return null;
  const pin = value as Partial<VaultPin>;
  if (typeof pin.id !== 'string' || !pin.id || pin.id.length > 512 || !Number.isSafeInteger(pin.generation) || (pin.generation ?? -1) < 0 || !isVaultPinState(pin.state) || !Number.isSafeInteger(pin.item_count) || (pin.item_count ?? -1) < 0 || !Number.isSafeInteger(pin.byte_len) || (pin.byte_len ?? -1) < 0) return null;
  return pin as VaultPin;
}
function vaultPinContextCurrent(flow: VaultDialogState, generation: number) {
  return isCurrentAccount(flow.accountEpoch) && state.vaultDialog === flow && state.vaultGeneration === flow.generation &&
    flow.pinGeneration === generation && flow.unlocked && !flow.statusUnknown && !!flow.rootResourceId;
}
function vaultEditRetryContextCurrent(flow: VaultDialogState, generation: number) {
  return isCurrentAccount(flow.accountEpoch) && state.vaultDialog === flow && state.vaultGeneration === flow.generation &&
    flow.editRetryGeneration === generation && flow.unlocked && !flow.statusUnknown && !!flow.rootResourceId;
}
function clearVaultEditRetryUi(flow: VaultDialogState) {
  if (flow.editRetryPollTimer) window.clearTimeout(flow.editRetryPollTimer);
  flow.editRetryPollTimer = 0;
  flow.editRetryGeneration++;
  flow.editRetryBusy = false;
  flow.editRetryError = '';
  flow.editRetryJob = null;
}
function vaultEditRetryAllowed(flow: VaultDialogState) {
  if (nativeVaultAccess()) return false;
  return flow.unlocked && !flow.statusUnknown && !flow.offlineUnlockOnly && !!flow.rootResourceId &&
    state.status?.connected === true && state.status.paused !== true && !(state.status.paused_space_ids || []).includes(flow.spaceId) &&
    !flow.loading && !flow.pinBusy && !flow.pinJob && !flow.pinsLoading && !flow.editRetryBusy &&
    (!flow.editRetryJob || !['queued', 'running'].includes(flow.editRetryJob.state));
}
function vaultEditRetryPanel(flow: VaultDialogState) {
  if (nativeVaultAccess()) return '';
  if (!flow.unlocked || flow.statusUnknown || !flow.initialized || !flow.rootResourceId) return '';
  const active = flow.editRetryJob && (flow.editRetryJob.state === 'queued' || flow.editRetryJob.state === 'running');
  const canRetry = vaultEditRetryAllowed(flow);
  const status = flow.editRetryJob
    ? `<div class="vault-edit-retry-status" role="status"><b>${flow.editRetryJob.state === 'queued' ? 'Upload retry queued' : flow.editRetryJob.state === 'running' ? 'Checking saved edits' : flow.editRetryJob.state === 'complete' ? 'Retry finished' : flow.editRetryJob.state === 'cancelled' ? 'Retry stopped' : 'Retry needs attention'}</b><small>${flow.editRetryJob.uploaded} uploaded and verified · ${flow.editRetryJob.conflicts} need review · ${flow.editRetryJob.remaining} saved record(s) remain${flow.editRetryJob.cancel_requested ? ' · stopping after the current operation' : ''}</small></div>`
    : '';
  const pauseText = state.status?.paused === true
    ? 'Resume account sync before retrying.'
    : (state.status?.paused_space_ids || []).includes(flow.spaceId)
      ? 'Resume this Space’s folder sync before retrying.'
      : !state.status?.connected
        ? 'Connect this account to retry saved edits.'
        : '';
  const recoveryCounts = state.encryptedEditRecoveryPage?.counts;
  const recentSummary = recoveryCounts
    ? `<small class="vault-edit-retry-note">Saved-edit review currently lists ${recoveryCounts.pending + recoveryCounts.uncertain} pending or uncertain record(s) and ${recoveryCounts.corrupt} metadata warning(s) across this account. The retry itself is limited to this unlocked location.</small>`
    : '<small class="vault-edit-retry-note">Raiun checks saved edits for this exact encrypted location. Refresh “Saved encrypted-file edits” in Settings for the account-wide local record list.</small>';
  return `<section class="vault-pin-panel vault-edit-retry-panel"><div class="vault-pin-heading"><div><b>Saved encrypted-file edits</b><small>Retry existing-file edits for this unlocked location</small></div><button class="button subtle" data-vault-edit-retry ${canRetry ? '' : 'disabled'}>${flow.editRetryBusy ? 'Starting…' : active ? 'Retry running' : 'Retry uploads'}</button></div><small class="vault-edit-retry-note">After a successful connection cycle, Raiun may also retry this exact location automatically while it stays unlocked and unpaused, with a five-minute backoff. Reconnection never unlocks a vault or checks saved keys. Both automatic and explicit retries check the original remote identity and version. Changed versions remain conflicts; nothing is rebased. Confirmed uploads require successful remote readback. Unresolved records stay saved. Offline changes to cached encrypted locations can queue existing-file edits, regular-file create/rename/delete, and folder creation. A queued folder can contain new files and folders while it remains unlocked. A queued-folder rename is limited to a never-attempted subtree of at most 64 operations and 64 MiB of file data; restart, child creation, and reconciliation passed in the R28 VM gate. Other folder renames and remote folder deletion are unsupported; an empty never-attempted queued folder can be canceled locally when it has no open handles or dependent operations.</small>${pauseText ? `<small class="vault-edit-retry-note" role="status">${esc(pauseText)}</small>` : ''}${flow.editRetryError ? `<div class="vault-error" role="alert">${esc(flow.editRetryError)}</div>` : ''}${status}${active ? `<div class="vault-pin-progress"><div><small>Keep this dialog open while Raiun checks the exact unlocked location.</small></div><button class="small-action quiet" data-vault-edit-retry-cancel ${flow.editRetryBusy || flow.editRetryJob?.cancel_requested ? 'disabled' : ''}>${flow.editRetryJob?.cancel_requested ? 'Stopping…' : 'Cancel'}</button></div>` : ''}${recentSummary}</section>`;
}
function scheduleVaultEditRetryPoll(flow: VaultDialogState, jobId: string, generation: number, delay = 1000) {
  if (flow.editRetryPollTimer) window.clearTimeout(flow.editRetryPollTimer);
  flow.editRetryPollTimer = window.setTimeout(() => {
    flow.editRetryPollTimer = 0;
    void pollVaultEditRetry(flow, jobId, generation);
  }, delay);
}
async function startVaultEditRetry() {
  if (nativeVaultAccess()) return;
  const flow = state.vaultDialog;
  if (!flow || !vaultEditRetryAllowed(flow)) return;
  const epoch = flow.accountEpoch;
  const profileId = state.selectedAccount;
  const generation = ++flow.editRetryGeneration;
  flow.editRetryBusy = true;
  flow.editRetryError = '';
  render();
  try {
    const result = await request<{ accepted: boolean; job_id: string }>('vault_reconcile_edits_start', { space_id: flow.spaceId, root_resource_id: flow.rootResourceId });
    if (!isCurrentAccount(epoch, profileId) || !vaultEditRetryContextCurrent(flow, generation)) return;
    if (result.accepted !== true || typeof result.job_id !== 'string' || !result.job_id || result.job_id.length > 256) throw new Error('Raiun did not confirm the encrypted edit retry.');
    flow.editRetryJob = { job_id: result.job_id, space_id: flow.spaceId, root_resource_id: flow.rootResourceId, automatic: false, state: 'queued', cancel_requested: false, processed: 0, uploaded: 0, conflicts: 0, remaining: 0 };
    render();
    scheduleVaultEditRetryPoll(flow, result.job_id, generation, 500);
  } catch (error) {
    if (isCurrentAccount(epoch, profileId) && vaultEditRetryContextCurrent(flow, generation) && !isStaleAccountRequest(error)) flow.editRetryError = messageOf(error);
  } finally {
    if (isCurrentAccount(epoch, profileId) && vaultEditRetryContextCurrent(flow, generation)) {
      flow.editRetryBusy = false;
      render();
    }
  }
}
async function pollVaultEditRetry(flow: VaultDialogState, jobId: string, generation: number) {
  if (nativeVaultAccess()) return;
  const expected = flow.editRetryJob;
  if (!expected || expected.job_id !== jobId || !vaultEditRetryContextCurrent(flow, generation)) return;
  try {
    const status = await request<VaultEditReconcileStatus>('vault_reconcile_edits_status', { space_id: flow.spaceId, root_resource_id: flow.rootResourceId, job_id: jobId });
    if (!vaultEditRetryContextCurrent(flow, generation) || flow.editRetryJob?.job_id !== jobId) return;
    if (status.job_id !== jobId || status.space_id !== flow.spaceId || status.root_resource_id !== flow.rootResourceId || !['queued', 'running', 'complete', 'failed', 'cancelled'].includes(status.state) || ![status.processed, status.uploaded, status.conflicts, status.remaining].every(value => Number.isSafeInteger(value) && value >= 0) || typeof status.cancel_requested !== 'boolean' || !(status.failure_class == null || isVaultFailureClass(status.failure_class))) {
      throw new Error('The agent returned an incomplete or mismatched encrypted edit status.');
    }
    flow.editRetryJob = { ...status, error: status.error || undefined };
    if (status.state === 'queued' || status.state === 'running') {
      render();
      scheduleVaultEditRetryPoll(flow, jobId, generation, 1300);
      return;
    }
    if (flow.editRetryPollTimer) window.clearTimeout(flow.editRetryPollTimer);
    flow.editRetryPollTimer = 0;
    if (status.state === 'complete') {
      state.message = `Encrypted edit retry finished: ${status.uploaded} uploaded and verified, ${status.conflicts} need review, ${status.remaining} saved record(s) remain (including conflicts). Confirmed uploads may be retired; unresolved records stay saved.`;
      if (state.encryptedEditRecoveryPage) void loadEncryptedEditRecoveries(true);
    } else if (status.state === 'failed') {
      flow.editRetryError = vaultEditRetryStatusMessage(status.failure_class);
    } else {
      state.message = `Encrypted edit retry stopped: ${status.uploaded} uploaded and verified, ${status.conflicts} need review, ${status.remaining} saved record(s) remain. Confirmed uploads may be retired; unresolved records stay saved.`;
    }
  } catch (error) {
    if (!vaultEditRetryContextCurrent(flow, generation) || isStaleAccountRequest(error)) return;
    flow.editRetryError = messageOf(error);
    scheduleVaultEditRetryPoll(flow, jobId, generation, 3000);
  }
  if (vaultEditRetryContextCurrent(flow, generation)) render();
}
async function cancelVaultEditRetry() {
  if (nativeVaultAccess()) return;
  const flow = state.vaultDialog;
  const job = flow?.editRetryJob;
  if (!flow || !job || !['queued', 'running'].includes(job.state) || flow.editRetryBusy || !flow.unlocked || flow.statusUnknown) return;
  const epoch = flow.accountEpoch;
  const profileId = state.selectedAccount;
  const generation = flow.editRetryGeneration;
  flow.editRetryBusy = true;
  render();
  try {
    const result = await request<VaultEditReconcileStatus>('vault_reconcile_edits_cancel', { space_id: flow.spaceId, root_resource_id: flow.rootResourceId, job_id: job.job_id });
    if (!isCurrentAccount(epoch, profileId) || !vaultEditRetryContextCurrent(flow, generation) || flow.editRetryJob?.job_id !== job.job_id) return;
    if (result.job_id !== job.job_id || result.space_id !== flow.spaceId || result.root_resource_id !== flow.rootResourceId || typeof result.cancel_requested !== 'boolean') throw new Error('Raiun did not confirm cancellation for this encrypted location.');
    flow.editRetryJob = { ...flow.editRetryJob, cancel_requested: result.cancel_requested };
  } catch (error) {
    if (isCurrentAccount(epoch, profileId) && vaultEditRetryContextCurrent(flow, generation) && !isStaleAccountRequest(error)) flow.editRetryError = messageOf(error);
  } finally {
    if (isCurrentAccount(epoch, profileId) && vaultEditRetryContextCurrent(flow, generation)) {
      flow.editRetryBusy = false;
      render();
    }
  }
}
function clearVaultPinUi(flow: VaultDialogState) {
  if (flow.pinPollTimer) window.clearTimeout(flow.pinPollTimer);
  flow.pinPollTimer = 0;
  flow.pinGeneration++;
  flow.pins = [];
  flow.pinsNextAfter = null;
  flow.pinsTruncated = false;
  flow.pinsLoading = false;
  flow.pinsError = '';
  flow.pinBusy = false;
  flow.pinJob = null;
  clearVaultEditRetryUi(flow);
}
async function loadVaultPins(flow: VaultDialogState, reset: boolean) {
  if (nativeVaultAccess()) return;
  if (!flow.unlocked || flow.statusUnknown || !flow.rootResourceId || flow.pinsLoading) return;
  const generation = flow.pinGeneration;
  const epoch = flow.accountEpoch;
  const profileId = state.selectedAccount;
  const cursor = reset ? null : flow.pinsNextAfter;
  if (!reset && !cursor) return;
  const previous = flow.pins;
  flow.pinsLoading = true;
  flow.pinsError = '';
  if (reset) {
    flow.pinsNextAfter = null;
    flow.pinsTruncated = false;
  }
  render();
  const args: Record<string, unknown> = { space_id: flow.spaceId, root_resource_id: flow.rootResourceId, limit: 50 };
  if (cursor) args.after = cursor;
  try {
    const page = await request<VaultPinPage>('vault_pins', args);
    if (!isCurrentAccount(epoch, profileId) || !vaultPinContextCurrent(flow, generation)) return;
    if (!Array.isArray(page.items)) throw new Error('The agent returned an invalid encrypted offline-copy list.');
    const pins = page.items.map(parseVaultPin);
    if (pins.some(pin => pin === null)) throw new Error('The agent returned an invalid encrypted offline-copy entry.');
    const merged = reset ? [] : [...previous];
    for (const pin of pins as VaultPin[]) {
      // Copy-on-write refreshes retain prior generations. Keep each one so a
      // newer Building/Stale generation never hides an earlier Ready copy.
      const oldIndex = merged.findIndex(old => old.id === pin.id && old.generation === pin.generation);
      if (oldIndex < 0) merged.push(pin);
      else if (pin.generation >= merged[oldIndex].generation) merged[oldIndex] = pin;
    }
    flow.pins = merged;
    flow.pinsNextAfter = page.next_after && typeof page.next_after === 'string' ? page.next_after : null;
    flow.pinsTruncated = page.truncated === true;
    if (typeof page.active_job_id === 'string' && page.active_job_id.length > 0 && page.active_job_id.length <= 256) {
      if (!flow.pinJob || flow.pinJob.job_id === page.active_job_id) {
        flow.pinJob = { ...(flow.pinJob || {}), job_id: page.active_job_id, state: 'running' };
        scheduleVaultPinPoll(flow, page.active_job_id, generation, 300);
      }
    }
  } catch (error) {
    if (isCurrentAccount(epoch, profileId) && vaultPinContextCurrent(flow, generation) && !isStaleAccountRequest(error)) flow.pinsError = messageOf(error);
  } finally {
    if (isCurrentAccount(epoch, profileId) && vaultPinContextCurrent(flow, generation)) {
      flow.pinsLoading = false;
      render();
    }
  }
}
function scheduleVaultPinPoll(flow: VaultDialogState, jobId: string, generation: number, delay = 1000) {
  if (flow.pinPollTimer) window.clearTimeout(flow.pinPollTimer);
  flow.pinPollTimer = window.setTimeout(() => {
    flow.pinPollTimer = 0;
    void pollVaultPin(flow, jobId, generation);
  }, delay);
}
async function pollVaultPin(flow: VaultDialogState, jobId: string, generation: number) {
  if (nativeVaultAccess()) return;
  if (!vaultPinContextCurrent(flow, generation) || flow.pinJob?.job_id !== jobId) return;
  try {
    const status = await request<VaultPinJobStatus>('vault_pin_status', { space_id: flow.spaceId, root_resource_id: flow.rootResourceId, job_id: jobId });
    if (!vaultPinContextCurrent(flow, generation) || flow.pinJob?.job_id !== jobId) return;
    if (status.job_id !== jobId || !isVaultPinJobState(status.state)) throw new Error('The agent returned an unknown encrypted offline-copy status.');
    const count = status.items_done;
    const bytes = status.bytes_done;
    if ((count != null && (!Number.isSafeInteger(count) || count < 0)) || (bytes != null && (!Number.isSafeInteger(bytes) || bytes < 0))) throw new Error('The agent returned invalid encrypted offline-copy progress.');
    const reportedPin = status.pin ? parseVaultPin(status.pin) : null;
    flow.pinJob = {
      ...flow.pinJob,
      state: status.state === 'queued' ? 'queued' : 'running',
      ...(reportedPin?.id ? { pin_id: reportedPin.id } : {}),
      items_done: count,
      bytes_done: bytes
    };
    if (status.state === 'queued' || status.state === 'running') {
      render();
      scheduleVaultPinPoll(flow, jobId, generation, 1500);
      return;
    }
    const completedPin = reportedPin;
    const expectedPinId = flow.pinJob.pin_id;
    if (status.state === 'ready') {
      if (!completedPin || completedPin.state !== 'ready' || (expectedPinId && completedPin.id !== expectedPinId)) {
        flow.pinJob = null;
        flow.pinsError = 'Raiun did not confirm a complete encrypted offline copy. No ready state was shown.';
        render();
        return;
      }
      flow.pinJob = null;
      const index = flow.pins.findIndex(pin => pin.id === completedPin.id && pin.generation === completedPin.generation);
      if (index < 0) flow.pins = [...flow.pins, completedPin];
      else if (completedPin.generation >= flow.pins[index].generation) flow.pins[index] = completedPin;
      flow.pinsError = '';
      const storedSize = offlineCopyStoredSizeLabel(completedPin.byte_len, formatBytes);
      state.message = `Encrypted offline copy ready${storedSize ? ` · ${storedSize}` : ''}. The copy is read-only while offline.`;
      void loadVaultPins(flow, true);
    } else if (status.state === 'failed') {
      flow.pinJob = null;
      flow.pinsError = status.error || 'The encrypted offline copy could not be prepared. Existing verified copies were kept.';
      void loadVaultPins(flow, true);
    } else {
      flow.pinJob = null;
      state.message = 'Encrypted offline-copy setup was cancelled. Any earlier verified copy remains unchanged.';
      void loadVaultPins(flow, true);
    }
  } catch (error) {
    if (!vaultPinContextCurrent(flow, generation) || isStaleAccountRequest(error)) return;
    flow.pinsError = messageOf(error);
    render();
    scheduleVaultPinPoll(flow, jobId, generation, 3000);
  }
  if (vaultPinContextCurrent(flow, generation)) render();
}
async function startVaultOfflinePin(pinId?: string) {
  if (nativeVaultAccess()) return;
  const flow = state.vaultDialog;
  if (!flow || !flow.unlocked || flow.statusUnknown || flow.loading || flow.pinBusy || flow.pinJob || flow.offlineUnlockOnly || state.status?.connected !== true || !flow.rootResourceId) return;
  if (pinId && !flow.pins.some(pin => pin.id === pinId)) return;
  const generation = ++flow.pinGeneration;
  if (flow.pinPollTimer) window.clearTimeout(flow.pinPollTimer);
  flow.pinPollTimer = 0;
  const epoch = flow.accountEpoch;
  const profileId = state.selectedAccount;
  flow.pinBusy = true;
  flow.pinsError = '';
  render();
  try {
    const result = await request<{ accepted: boolean; job_id: string }>('vault_pin_start', {
      space_id: flow.spaceId, root_path: flow.rootPath, root_resource_id: flow.rootResourceId,
      ...(pinId ? { pin_id: pinId } : {})
    });
    if (!isCurrentAccount(epoch, profileId) || !vaultPinContextCurrent(flow, generation)) return;
    if (result.accepted !== true || typeof result.job_id !== 'string' || !result.job_id || result.job_id.length > 256) throw new Error('Raiun did not confirm encrypted offline-copy setup.');
    flow.pinJob = { job_id: result.job_id, state: 'queued', ...(pinId ? { pin_id: pinId } : {}) };
    flow.pinBusy = false;
    render();
    scheduleVaultPinPoll(flow, result.job_id, generation, 500);
  } catch (error) {
    if (isCurrentAccount(epoch, profileId) && vaultPinContextCurrent(flow, generation) && !isStaleAccountRequest(error)) flow.pinsError = messageOf(error);
  } finally {
    if (isCurrentAccount(epoch, profileId) && vaultPinContextCurrent(flow, generation)) {
      flow.pinBusy = false;
      render();
    }
  }
}
async function cancelVaultOfflinePin() {
  if (nativeVaultAccess()) return;
  const flow = state.vaultDialog;
  if (!flow?.pinJob || flow.pinBusy || !flow.unlocked || flow.statusUnknown) return;
  const job = flow.pinJob;
  const generation = flow.pinGeneration;
  const epoch = flow.accountEpoch;
  const profileId = state.selectedAccount;
  flow.pinBusy = true;
  render();
  try {
    const result = await request<{ cancelled: boolean }>('vault_pin_cancel', { space_id: flow.spaceId, root_resource_id: flow.rootResourceId, job_id: job.job_id });
    if (!isCurrentAccount(epoch, profileId) || !vaultPinContextCurrent(flow, generation) || flow.pinJob?.job_id !== job.job_id) return;
    if (result.cancelled !== true) throw new Error('Raiun did not confirm cancellation.');
    flow.pinJob.cancelRequested = true;
  } catch (error) {
    if (isCurrentAccount(epoch, profileId) && vaultPinContextCurrent(flow, generation) && !isStaleAccountRequest(error)) flow.pinsError = messageOf(error);
  } finally {
    if (isCurrentAccount(epoch, profileId) && vaultPinContextCurrent(flow, generation)) {
      flow.pinBusy = false;
      render();
    }
  }
}
async function removeVaultOfflinePin(pinId: string) {
  if (nativeVaultAccess()) return;
  const flow = state.vaultDialog;
  if (!flow || !pinId || flow.pinBusy || !flow.unlocked || flow.statusUnknown || flow.pinJob?.pin_id === pinId || !flow.pins.some(pin => pin.id === pinId)) return;
  const generation = flow.pinGeneration;
  const epoch = flow.accountEpoch;
  const profileId = state.selectedAccount;
  if (!await confirmAccountAction('Remove this encrypted offline copy from this device? Cloud files and other cached data are unchanged.') || !isCurrentAccount(epoch, profileId) || !vaultPinContextCurrent(flow, generation) || flow.pinBusy || flow.pinJob?.pin_id === pinId || !flow.pins.some(pin => pin.id === pinId)) return;
  flow.pinBusy = true;
  flow.pinsError = '';
  render();
  try {
    const result = await request<{ removed: boolean }>('vault_pin_remove', { space_id: flow.spaceId, root_resource_id: flow.rootResourceId, pin_id: pinId });
    if (!isCurrentAccount(epoch, profileId) || !vaultPinContextCurrent(flow, generation)) return;
    if (result.removed !== true) throw new Error('Raiun did not confirm removal of the encrypted offline-copy reference.');
    flow.pins = flow.pins.filter(pin => pin.id !== pinId);
    state.message = 'Encrypted offline copy removed from this device. Cloud files and other cached data were left unchanged.';
  } catch (error) {
    if (isCurrentAccount(epoch, profileId) && vaultPinContextCurrent(flow, generation) && !isStaleAccountRequest(error)) flow.pinsError = messageOf(error);
  } finally {
    if (isCurrentAccount(epoch, profileId) && vaultPinContextCurrent(flow, generation)) {
      flow.pinBusy = false;
      render();
    }
  }
}
function closeVaultDialog() {
  const current = state.vaultDialog;
  if (copyProducerUi.source && copyProducerUi.busy) return;
  if (copyProducerUi.status?.state === 'queued' || copyProducerUi.status?.state === 'running') return;
  if (current) {
    const blockedMessage = vaultDialogCloseBlockedMessage({
      ...current,
      loading: current.loading || state.accountSwitching || state.accountEpoch !== current.accountEpoch || state.vaultGeneration !== current.generation
    });
    if (blockedMessage) {
      if (shouldAnnounceVaultCloseBlocked(current.closeBlockedNotice, blockedMessage)) {
        current.closeBlockedNotice = blockedMessage;
        render();
      }
      return;
    }
  }
  state.vaultGeneration++;
  if (state.vaultDialog) clearVaultPinUi(state.vaultDialog);
  state.vaultDialog = null;
  if (copyProducerUi.source) resetCopyProducerFlow();
  render();
}
async function unlockVault(useSaved = false) {
  const flow = state.vaultDialog;
  const input = app.querySelector<HTMLInputElement>('#vault-password');
  if (!flow || nativeVaultLockIncomplete(flow) || flow.loading || !flow.initialized || (!useSaved && !input)) return;
  if (typeof copyProducerUi !== 'undefined' && copyProducerUi.source) invalidateCopyProducerForVaultTransition();
  let password = useSaved ? '' : input?.value || '';
  if (input) input.value = '';
  flow.passwordError = '';
  if (!useSaved && !password) { flow.error = 'Enter the vault password.'; flow.passwordError = flow.error; render(); return; }
  flow.loading = true;
  flow.error = '';
  const accountEpoch = flow.accountEpoch;
  const generation = flow.generation;
  render();
  let unlockNotice = '';
  try {
    const action = flow.offlineUnlockOnly ? 'vault_unlock_offline' : 'vault_unlock';
    const unlocked = await (async () => {
      try {
        return await vaultSecretRequest<{ unlocked?: boolean; offline?: boolean; root_path?: string; root_resource_id?: string; pin_id?: string | null; generation?: number | null; space_name?: string; vault_mount_ready?: boolean; vault_mount_writable?: boolean; vault_mount_existing_file_overwrite?: boolean; vault_mount_existing_file_in_place?: boolean; vault_mount_existing_file_overwrite_reason?: VaultExistingOverwriteReason | null; vault_mount_write_unavailable_reason?: VaultMountWriteUnavailableReason | null; remembered?: boolean; remembered_status?: RememberedStatus; remember_error?: 'secure_store_unavailable' | null }>({
      action, space_id: flow.spaceId,
      ...(!flow.offlineUnlockOnly ? { root_path: flow.rootPath } : {}),
      root_resource_id: flow.rootResourceId,
      ...(flow.offlineUnlockOnly && flow.offlinePinId ? { pin_id: flow.offlinePinId } : {}),
      ...(flow.offlineUnlockOnly && flow.offlinePinId && Number.isSafeInteger(flow.offlinePinGeneration) ? { expected_generation: flow.offlinePinGeneration } : {}),
          ...(useSaved ? { use_saved: true } : { password, ...(flow.rememberOnDevice ? { remember: true } : {}) })
        });
      } catch (error) {
        if (!useSaved) {
          const failure = messageOf(error);
          if (isVaultPasswordValidationError(failure)) flow.passwordError = failure;
        }
        throw error;
      }
    })();
    if (!isCurrentAccount(accountEpoch) || state.vaultDialog !== flow || state.vaultGeneration !== generation) return;
    if (nativeVaultAccess() && unlocked.unlocked !== true) {
      flow.unlocked = false;
      flow.statusUnknown = true;
      flow.vaultMountReady = false;
      flow.vaultMountWritable = false;
      flow.vaultMountExistingFileOverwrite = false;
      flow.vaultMountExistingFileInPlace = false;
      flow.entries = [];
      throw new Error('The agent did not confirm this vault unlock. Check status before continuing.');
    }
    if (flow.offlineUnlockOnly && (unlocked.unlocked !== true || unlocked.offline !== true || typeof unlocked.root_path !== 'string' || !unlocked.root_path.startsWith('/') || unlocked.root_resource_id !== flow.rootResourceId || unlocked.vault_mount_writable !== false || typeof unlocked.vault_mount_existing_file_overwrite !== 'boolean' || (unlocked.vault_mount_existing_file_overwrite && unlocked.vault_mount_existing_file_overwrite_reason != null) || (!unlocked.vault_mount_existing_file_overwrite && unlocked.vault_mount_existing_file_overwrite_reason != null && !safeVaultExistingOverwriteReason(unlocked.vault_mount_existing_file_overwrite_reason)) || (flow.offlinePinId ? unlocked.pin_id !== flow.offlinePinId || unlocked.generation !== flow.offlinePinGeneration : unlocked.pin_id != null || unlocked.generation != null))) {
      throw new Error('The saved encrypted location could not be verified for offline access.');
    }
    if (flow.offlineUnlockOnly) flow.rootPath = unlocked.root_path!;
    flow.unlocked = true;
    flow.vaultMountReady = unlocked.vault_mount_ready === true;
    updateNativeVaultLockCleanup(flow, undefined, 'unlock');
    flow.vaultMountWritable = typeof unlocked.vault_mount_writable === 'boolean' ? unlocked.vault_mount_writable : null;
    flow.vaultMountExistingFileOverwrite = unlocked.vault_mount_existing_file_overwrite === true;
    flow.vaultMountExistingFileInPlace = nativeVaultAccess() && !flow.offlineUnlockOnly && flow.unlocked && flow.vaultMountReady && unlocked.vault_mount_existing_file_in_place === true;
    flow.vaultMountExistingFileOverwriteReason = safeVaultExistingOverwriteReason(unlocked.vault_mount_existing_file_overwrite_reason);
    flow.vaultMountWriteUnavailableReason = safeVaultMountWriteReason(unlocked.vault_mount_write_unavailable_reason);
    flow.rememberedStatus = safeRememberedStatus(unlocked.remembered_status) ?? flow.rememberedStatus;
    if (unlocked.remember_error === 'secure_store_unavailable') {
      flow.rememberedStatus = 'unavailable';
      unlockNotice = 'The vault unlocked, but secure storage is unavailable. The password was not saved.';
    } else if (!useSaved && flow.rememberOnDevice && unlocked.remembered !== true) {
      unlockNotice = 'The vault unlocked, but no saved key was confirmed. Check the saved-key status before relying on it.';
    }
    flow.loading = false;
    if (!nativeVaultAccess()) await loadVaultPath(flow, '/');
    if (!nativeVaultAccess() && isCurrentAccount(accountEpoch) && state.vaultDialog === flow && flow.unlocked && !flow.statusUnknown) await loadVaultPins(flow, true);
    if (unlockNotice && isCurrentAccount(accountEpoch) && state.vaultDialog === flow && state.vaultGeneration === generation) {
      flow.error = flow.error ? `${flow.error} ${unlockNotice}` : unlockNotice;
    }
    if (flow.intent === 'manage') state.message = 'Encrypted folder unlocked. Local files remain plaintext on this computer.';
    else if (flow.intent === 'browse') state.message = `${flow.offlineUnlockOnly ? flow.offlinePinId ? 'Encrypted files unlocked from the verified offline snapshot.' : 'Encrypted files unlocked from saved location metadata; a complete offline snapshot was not confirmed.' : 'Encrypted files unlocked.'} ${(nativeVaultAccess() && !flow.statusUnknown && flow.unlocked && flow.vaultMountReady && flow.vaultMountExistingFileInPlace && state.status?.mounted === true && state.status?.connected === true ? nativeExistingFileSaveMessage() : mountedVaultAccessMessage(flow.vaultMountWritable, flow.vaultMountWriteUnavailableReason, flow.vaultMountReady))} No sync folder was added.`;
  } catch (error) {
    if (isCurrentAccount(accountEpoch) && state.vaultDialog === flow && !isStaleAccountRequest(error)) {
      flow.error = messageOf(error);
      if (useSaved && !flow.offlineUnlockOnly) {
        try {
          const inspected = await request<VaultInspect>('vault_inspect', { space_id: flow.spaceId, root_path: flow.rootPath });
          if (isCurrentAccount(accountEpoch) && state.vaultDialog === flow && state.vaultGeneration === generation) {
            flow.rememberedStatus = safeRememberedStatus(inspected.remembered_status) ?? flow.rememberedStatus;
          }
        } catch { /* Preserve the original unlock failure when status refresh also fails. */ }
      }
    }
  } finally {
    // JS strings cannot be reliably zeroized; drop the transient reference and
    // always leave the DOM field empty on every result path.
    password = '';
    if (isCurrentAccount(accountEpoch) && state.vaultDialog === flow && state.vaultGeneration === generation) {
      flow.loading = false;
      render();
      if (vaultAppFeaturesAvailable() && state.page === 'transfers' && flow.unlocked) void refreshEncryptedRetryLatestStatuses(true);
    }
  }
}
async function forgetSavedVault() {
  const flow = state.vaultDialog;
  if (!flow || flow.loading || flow.statusUnknown || !flow.rootResourceId) return;
  flow.loading = true;
  flow.error = '';
  const accountEpoch = flow.accountEpoch;
  const generation = flow.generation;
  render();
  try {
    await request<{ remembered: false }>('vault_forget', {
      space_id: flow.spaceId,
      root_resource_id: flow.rootResourceId
    });
    if (!isCurrentAccount(accountEpoch) || state.vaultDialog !== flow || state.vaultGeneration !== generation) return;
    flow.rememberedStatus = 'not_saved';
    flow.rememberOnDevice = false;
    state.message = nativeVaultAccess() ? `Saved vault key forgotten. ${nativeVaultLockMessage(flow.lockCleanupStatus, flow.unlocked, !flow.statusUnknown)}` : flow.unlocked
      ? 'Saved vault key forgotten. The vault remains unlocked until you lock it.'
      : 'Saved vault key forgotten. The vault remains locked.';
  } catch (error) {
    if (isCurrentAccount(accountEpoch) && state.vaultDialog === flow && state.vaultGeneration === generation && !isStaleAccountRequest(error)) {
      flow.error = messageOf(error);
    }
  } finally {
    if (isCurrentAccount(accountEpoch) && state.vaultDialog === flow && state.vaultGeneration === generation) {
      flow.loading = false;
      render();
    }
  }
}
async function createEncryptedVault() {
  if (nativeVaultAccess()) return;
  const flow = state.vaultDialog;
  const nameInput = app.querySelector<HTMLInputElement>('#vault-create-name');
  const passwordInput = app.querySelector<HTMLInputElement>('#vault-create-password');
  const confirmInput = app.querySelector<HTMLInputElement>('#vault-create-confirm');
  if (!flow || flow.intent !== 'create' || flow.loading || !nameInput || !passwordInput || !confirmInput) return;
  const rawName = nameInput.value.trim();
  const name = rawName.toLocaleLowerCase().endsWith('.vault') ? rawName : `${rawName}.vault`;
  let password = passwordInput.value;
  let confirmation = confirmInput.value;
  passwordInput.value = '';
  confirmInput.value = '';
  if (!rawName || rawName === '.' || rawName === '..' || /[/\\\u0000-\u001f\u007f]/.test(name)) {
    password = ''; confirmation = '';
    flow.error = 'Enter a folder name without slashes or control characters.';
    render();
    return;
  }
  if (!password || password !== confirmation) {
    password = ''; confirmation = '';
    flow.error = 'Enter the same nonempty password in both fields.';
    render();
    return;
  }
  flow.loading = true;
  flow.error = '';
  const accountEpoch = flow.accountEpoch;
  const generation = flow.generation;
  render();
  try {
    const created = await vaultSecretRequest<VaultInspect>({
      action: 'vault_create', space_id: flow.spaceId, parent_path: flow.rootPath, name, password
    });
    if (!isCurrentAccount(accountEpoch) || state.vaultDialog !== flow || state.vaultGeneration !== generation) return;
    completeVaultCreate(
      state,
      created,
      mountedVaultAccessMessage(typeof created.vault_mount_writable === 'boolean' ? created.vault_mount_writable : null, safeVaultMountWriteReason(created.vault_mount_write_unavailable_reason), created.vault_mount_ready === true),
      render
    );
  } catch (error) {
    if (isCurrentAccount(accountEpoch) && state.vaultDialog === flow && !isStaleAccountRequest(error)) {
      flow.error = `${messageOf(error)} If the server created the folder before failing, check that location before retrying.`;
    }
  } finally {
    password = ''; confirmation = '';
    if (isCurrentAccount(accountEpoch) && state.vaultDialog === flow && state.vaultGeneration === generation) {
      finishVaultCreateAttempt(flow, render);
    }
  }
}
async function lockVault() {
  const flow = state.vaultDialog;
  if (!flow || flow.loading || (!flow.unlocked && !nativeVaultLockIncomplete(flow)) || flow.editRetryBusy || (flow.editRetryJob && ['queued', 'running'].includes(flow.editRetryJob.state))) return;
  const accountEpoch = flow.accountEpoch;
  const profileId = state.selectedAccount;
  const generation = flow.generation;
  if (!await confirmAccountAction(nativeVaultAccess() ? 'Lock this encrypted location? If local cleanup cannot finish, files may remain accessible. Close apps using this location before retrying. Locking cannot retract copies already read by other apps.' : 'Lock this encrypted folder? Locking may wait for active encrypted reads, folder sync, offline-copy work, or upload retry to stop. It cannot retract bytes already read or copied by other apps, or encrypt/remove local sync copies. When this location is available through the mounted drive, locking denies further reads.') || !isCurrentAccount(accountEpoch, profileId) || state.vaultDialog !== flow || state.vaultGeneration !== generation || flow.loading || (!flow.unlocked && !nativeVaultLockIncomplete(flow)) || flow.editRetryBusy || (flow.editRetryJob && ['queued', 'running'].includes(flow.editRetryJob.state))) return;
  if (typeof copyProducerUi !== 'undefined' && copyProducerUi.source) invalidateCopyProducerForVaultTransition();
  const lockScope = nativeVaultAccess() ? nativeVaultLockScope(flow) : null;
  flow.loading = true;
  if (nativeVaultAccess()) state.message = '';
  flow.error = '';
  flow.statusUnknown = true;
  flow.entries = [];
  flow.path = '/';
  flow.vaultMountReady = false;
  forgetVaultOperationsScope(flow.spaceId, flow.rootResourceId);
  clearVaultPinUi(flow);
  render();
  try {
    const locked = await request<{ vault_lock_cleanup_status?: VaultLockCleanupStatus; vault_mount_ready?: boolean; vault_mount_writable?: boolean; vault_mount_existing_file_overwrite?: boolean; vault_mount_existing_file_in_place?: boolean; vault_mount_existing_file_overwrite_reason?: VaultExistingOverwriteReason | null; vault_mount_write_unavailable_reason?: VaultMountWriteUnavailableReason | null }>('vault_lock', { space_id: flow.spaceId, root_path: flow.rootPath, root_resource_id: flow.rootResourceId });
    if (!isCurrentAccount(accountEpoch) || state.vaultDialog !== flow || state.vaultGeneration !== generation) return;
    flow.unlocked = false;
    flow.statusUnknown = false;
    if (nativeVaultAccess()) updateNativeVaultLockCleanup(flow, locked.vault_lock_cleanup_status, 'lock_succeeded', lockScope);
    flow.vaultMountReady = locked.vault_mount_ready === true;
    flow.vaultMountWritable = typeof locked.vault_mount_writable === 'boolean' ? locked.vault_mount_writable : null;
    flow.vaultMountExistingFileOverwrite = locked.vault_mount_existing_file_overwrite === true;
    flow.vaultMountExistingFileInPlace = nativeVaultAccess() && !flow.offlineUnlockOnly && flow.unlocked && flow.vaultMountReady && locked.vault_mount_existing_file_in_place === true;
    flow.vaultMountExistingFileOverwriteReason = safeVaultExistingOverwriteReason(locked.vault_mount_existing_file_overwrite_reason);
    flow.vaultMountWriteUnavailableReason = safeVaultMountWriteReason(locked.vault_mount_write_unavailable_reason);
    flow.entries = [];
    flow.path = '/';
    state.message = nativeVaultAccess() ? nativeVaultLockMessage(flow.lockCleanupStatus, false, !flow.statusUnknown) : 'Encrypted location locked. Local files remain plaintext on this computer.';
  } catch (error) {
    if (isCurrentAccount(accountEpoch) && state.vaultDialog === flow && state.vaultGeneration === generation && !isStaleAccountRequest(error)) {
      if (nativeVaultAccess()) updateNativeVaultLockCleanup(flow, 'incomplete', 'lock_failed', lockScope);
      if (nativeVaultAccess()) state.message = nativeVaultLockMessage('incomplete', false);
      flow.error = messageOf(error);
      await reconcileVaultLockStatus(flow, accountEpoch, generation);
    }
  } finally {
    if (isCurrentAccount(accountEpoch) && state.vaultDialog === flow && state.vaultGeneration === generation) {
      flow.loading = false;
      render();
      if (vaultAppFeaturesAvailable() && state.page === 'transfers') void refreshEncryptedRetryLatestStatuses(true);
    }
  }
}
async function checkVaultLockStatus() {
  const flow = state.vaultDialog;
  if (!flow || flow.loading || (!flow.statusUnknown && !nativeVaultLockIncomplete(flow) && !(nativeVaultAccess() && !flow.unlocked && flow.lockCleanupStatus === 'unknown'))) return;
  flow.loading = true;
  flow.error = '';
  render();
  await reconcileVaultLockStatus(flow, flow.accountEpoch, flow.generation);
  if (isCurrentAccount(flow.accountEpoch) && state.vaultDialog === flow && state.vaultGeneration === flow.generation) {
    flow.loading = false;
    render();
  }
}
async function reconcileVaultLockStatus(flow: VaultDialogState, accountEpoch: number, generation: number) {
  try {
    const inspected = await request<VaultInspect>('vault_inspect', { space_id: flow.spaceId, root_path: flow.rootPath });
    if (!isCurrentAccount(accountEpoch) || state.vaultDialog !== flow || state.vaultGeneration !== generation) return;
    if (nativeVaultAccess() && inspected.root_resource_id !== flow.rootResourceId) throw new Error('The encrypted root changed during lock inspection.');
    flow.rootPath = inspected.root_path;
    flow.rootResourceId = inspected.root_resource_id;
    flow.initialized = inspected.initialized;
    flow.unlocked = inspected.unlocked;
    flow.statusUnknown = false;
    flow.vaultMountReady = inspected.vault_mount_ready === true;
    flow.vaultMountWritable = typeof inspected.vault_mount_writable === 'boolean' ? inspected.vault_mount_writable : null;
    flow.vaultMountExistingFileOverwrite = inspected.vault_mount_existing_file_overwrite === true;
    flow.vaultMountExistingFileInPlace = nativeVaultAccess() && !flow.offlineUnlockOnly && flow.unlocked && flow.vaultMountReady && inspected.vault_mount_existing_file_in_place === true;
    flow.vaultMountExistingFileOverwriteReason = safeVaultExistingOverwriteReason(inspected.vault_mount_existing_file_overwrite_reason);
    flow.vaultMountWriteUnavailableReason = safeVaultMountWriteReason(inspected.vault_mount_write_unavailable_reason);
    flow.rememberedStatus = safeRememberedStatus(inspected.remembered_status);
    updateNativeVaultLockCleanup(flow, inspected.vault_lock_cleanup_status, inspected.unlocked ? 'unlock' : 'inspect');
    flow.entries = [];
    flow.path = '/';
    flow.loading = false;
    if (flow.unlocked) {
      const lockError = flow.error;
      if (!nativeVaultAccess()) await loadVaultPath(flow, '/');
      if (isCurrentAccount(accountEpoch) && state.vaultDialog === flow && state.vaultGeneration === generation && !flow.error) {
        flow.error = lockError;
      }
      if (!nativeVaultAccess() && isCurrentAccount(accountEpoch) && state.vaultDialog === flow && state.vaultGeneration === generation) await loadVaultPins(flow, true);
      if (nativeVaultAccess()) render();
    } else {
      clearVaultPinUi(flow);
      render();
    }
  } catch {
    if (!isCurrentAccount(accountEpoch) || state.vaultDialog !== flow || state.vaultGeneration !== generation) return;
    flow.statusUnknown = true;
    flow.unlocked = false;
    flow.entries = [];
    flow.path = '/';
    flow.vaultMountReady = false;
    flow.loading = false;
    flow.error = 'Could not confirm the vault lock state. Check the connection, then check status before browsing.';
    render();
  }
}
function useVaultFolder() {
  if (nativeVaultAccess()) return;
  const flow = state.vaultDialog;
  if (!flow || flow.intent !== 'add' || !flow.initialized || !flow.rootResourceId || flow.loading || flow.pinBusy || flow.pinJob || flow.editRetryBusy || (flow.editRetryJob && ['queued', 'running'].includes(flow.editRetryJob.state))) return;
  state.spaceId = flow.spaceId;
  state.vaultBinding = { root_path: flow.rootPath, root_resource_id: flow.rootResourceId };
  state.vaultWritable = flow.writable;
  if (!flow.writable) state.mode = 'download_only';
  state.remotePath = flow.path;
  clearVaultPinUi(flow);
  state.vaultGeneration++;
  state.vaultDialog = null;
  state.pickerOpen = false;
  render();
}
async function createRemoteFolder() {
  if (state.pickerCreatingFolder) return;
  const epoch = state.accountEpoch;
  const space = state.spaces.find(candidate => candidate.id === state.spaceId);
  const name = state.pickerFolderName.trim();
  if (!space || !space.writable || space.encrypted || !state.pickerWritable[state.pickerPath]) {
    state.pickerError = 'This location is read only. Choose a writable folder.';
    render();
    return;
  }
  if (!name || name === '.' || name === '..' || /[/\\\u0000-\u001f\u007f]/.test(name)) {
    state.pickerError = 'Enter a folder name without slashes or control characters.';
    render();
    return;
  }
  state.pickerError = '';
  state.pickerCreatingFolder = true;
  render();
  try {
    await request<RemoteEntry>('create_folder', { space_id: space.id, parent_path: state.pickerPath, name });
    state.pickerFolderName = '';
    await browseRemote(state.pickerPath);
  } catch (error) {
    if (isCurrentAccount(epoch) && !isStaleAccountRequest(error)) state.pickerError = messageOf(error);
  } finally {
    if (isCurrentAccount(epoch)) { state.pickerCreatingFolder = false; render(); }
  }
}
async function savePair() {
  if (!featureAvailable('folder_sync_supported')) return;
  const epoch = state.accountEpoch;
  const mode = state.mode;
  const selectedSpace = state.spaces.find(space => space.id === state.spaceId);
  if (nativeVaultAccess() && (selectedSpace?.encrypted || state.vaultBinding)) { state.error = 'Encrypted locations are available through the read-only Windows drive, not sync folders.'; render(); return; }
  const destinationWritable = selectedSpace?.writable === true && (!state.vaultBinding || state.vaultWritable);
  if (!destinationWritable && mode !== 'download_only') { state.error = 'This Space or encrypted folder is read only. Choose Download only or select a writable location.'; render(); return; }
  const id = crypto.randomUUID();
  await run('pair_add', { id, local_path: state.localPath, space_id: state.spaceId, remote_path: state.remotePath, mode, vault: state.vaultBinding });
  if (!isCurrentAccount(epoch)) return;
  if (!state.error) { state.addOpen = false; state.message = 'Folder pair added.'; await refresh(); }
  render();
}
async function removePair(id: string) {
  if (!featureAvailable('folder_sync_supported')) return;
  const epoch = state.accountEpoch;
  const profileId = state.selectedAccount;
  if (!await confirmAccountAction('Remove this folder pair? The local and cloud files will stay in place.') || !isCurrentAccount(epoch, profileId) || !featureAvailable('folder_sync_supported') || !state.pairs.some(pair => pair.id === id)) return;
  await run('pair_remove', { id });
  if (!isCurrentAccount(epoch)) return;
  if (!state.error) { pairExclusionsUi.open.delete(id); pairExclusionsUi.drafts.delete(id); pairExclusionsUi.errors.delete(id); state.message = 'Folder pair removed.'; await refresh(); }
  render();
}
function togglePairExclusions(pairId: string) {
  if (!state.agentReachable || state.mutationBusy > 0) return;
  pairExclusionsUi.errors.delete(pairId);
  if (pairExclusionsUi.open.has(pairId)) pairExclusionsUi.open.delete(pairId);
  else pairExclusionsUi.open.add(pairId);
  render();
}
function validatePairExclusion(path: string, existing: string[]): string | null {
  const bytes = new TextEncoder().encode(path).length;
  if (!path || bytes > 4096) return 'Enter a path of at most 4 KiB.';
  if (path.startsWith('/') || path.endsWith('/') || path.includes('\\') || /[\u0000-\u001f\u007f]/.test(path)) return 'Use a relative path with forward slashes and no control characters.';
  const parts = path.split('/');
  if (parts.some(part => !part || part === '.' || part === '..')) return 'Use a path without empty, “.”, or “..” components.';
  if (existing.includes(path)) return 'That path is already excluded.';
  if (existing.length >= 256) return 'This folder already has the maximum of 256 excluded paths.';
  const total = existing.reduce((sum, item) => sum + new TextEncoder().encode(item).length, 0) + bytes;
  if (total > 32 * 1024) return 'The combined excluded paths cannot exceed 32 KiB.';
  return null;
}
async function setPairExclusions(pairId: string, paths: string[]) {
  if (!state.agentReachable || state.mutationBusy > 0 || pairExclusionsUi.busy.has(pairId)) return;
  const pair = state.pairs.find(item => item.id === pairId);
  if (!pair) return;
  const epoch = state.accountEpoch;
  const profileId = state.selectedAccount;
  pairExclusionsUi.busy.add(pairId);
  state.mutationBusy++;
  pairExclusionsUi.errors.delete(pairId);
  state.message = '';
  render();
  try {
    await request('pair_exclusions_set', { id: pairId, excluded_paths: paths });
    if (!isCurrentAccount(epoch, profileId)) return;
    pairExclusionsUi.drafts.delete(pairId);
    state.message = paths.length
      ? `Sync exclusions updated. Existing local and cloud files remain in place.`
      : 'All paths in this folder are included in sync again.';
    await refresh(false);
  } catch (error) {
    if (isCurrentAccount(epoch, profileId) && !isStaleAccountRequest(error)) pairExclusionsUi.errors.set(pairId, messageOf(error));
  } finally {
    state.mutationBusy = Math.max(0, state.mutationBusy - 1);
    if (isCurrentAccount(epoch, profileId)) pairExclusionsUi.busy.delete(pairId);
    render();
  }
}
async function addPairExclusion(pairId: string) {
  const pair = state.pairs.find(item => item.id === pairId);
  if (!pair || !state.agentReachable || state.mutationBusy > 0) return;
  const path = pairExclusionsUi.drafts.get(pairId) || '';
  const paths = pair.excluded_paths || [];
  const error = validatePairExclusion(path, paths);
  if (error) { pairExclusionsUi.errors.set(pairId, error); render(); return; }
  await setPairExclusions(pairId, [...paths, path]);
}
async function removePairExclusion(pairId: string, index: number) {
  const pair = state.pairs.find(item => item.id === pairId);
  const paths = pair?.excluded_paths || [];
  if (!pair || !state.agentReachable || state.mutationBusy > 0 || index < 0 || index >= paths.length) return;
  await setPairExclusions(pairId, paths.filter((_, current) => current !== index));
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
  const epoch = state.accountEpoch;
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
    if (!isCurrentAccount(epoch)) return;
    panel.items = reset ? result.items : [...panel.items, ...result.items];
    panel.nextAfter = result.next_after ?? null;
  } catch (error) {
    if (!isCurrentAccount(epoch) || isStaleAccountRequest(error)) return;
    panel.error = messageOf(error);
  } finally {
    if (isCurrentAccount(epoch)) { panel.loading = false; render(); }
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
  const epoch = state.accountEpoch;
  const profileId = state.selectedAccount;
  if (!await confirmAccountAction(`Keep the ${choiceLabel} version of “${lastPath(path)}”? Raiun will preserve the ${displacedLabel} version as a recovery copy.`) || !isCurrentAccount(epoch, profileId) || state.resolvingConflict) return;
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
    if (!isCurrentAccount(epoch)) return;
    if (panel) panel.recoveryMessage = `Kept the ${choiceLabel} version. The displaced copy is saved at ${result.recovery_path}.`;
    await loadConflictPage(pairId, true);
  } catch (error) {
    if (!isCurrentAccount(epoch) || isStaleAccountRequest(error)) return;
    const message = messageOf(error);
    if (isStaleConflictError(message)) {
      state.error = `This conflict changed before your choice could be applied. The list was refreshed; review it again before choosing.`;
      await loadConflictPage(pairId, true);
    } else if (panel) {
      panel.error = message;
    }
  } finally {
    if (isCurrentAccount(epoch)) { state.resolvingConflict = false; render(); }
  }
}
function isStaleConflictError(message: string) {
  return /stale|changed since|no longer matches|conflict.*changed/i.test(message);
}
async function transferAction(action: 'retry'|'cancel', id: string) {
  if (!featureAvailable('folder_sync_supported')) return;
  const epoch = state.accountEpoch;
  await run(action, { id });
  if (!isCurrentAccount(epoch)) return;
  if (!state.error) { state.message = action === 'retry' ? 'Retry requested.' : 'Cancellation requested.'; await refresh(); }
  render();
}
async function run(action: string, args: Record<string, unknown>) {
  const epoch = state.accountEpoch;
  state.mutationBusy++;
  state.error = ''; state.message = '';
  render();
  try { await request(action, args); if (isCurrentAccount(epoch)) await refresh(false); }
  catch (error) { if (isCurrentAccount(epoch) && !isStaleAccountRequest(error)) state.error = messageOf(error); }
  finally { state.mutationBusy = Math.max(0, state.mutationBusy - 1); render(); }
}
function isStaleAccountRequest(error: unknown) { return error instanceof StaleAccountRequest; }
async function toggleSpacePause(spaceId: string) {
  if (!featureAvailable('folder_sync_supported') || !featureAvailable('pause_supported') || !state.agentReachable || state.status?.connected !== true || state.mutationBusy > 0 || state.spaceActionBusy[spaceId]) return;
  const epoch = state.accountEpoch;
  const paused = state.status.paused_space_ids?.includes(spaceId) !== true;
  state.spaceActionBusy[spaceId] = 'pause';
  state.mutationBusy++;
  state.error = ''; state.message = '';
  render();
  try {
    const result = await request<{ space_id: string; paused: boolean; paused_space_ids: string[] }>('space_pause', { space_id: spaceId, paused });
    if (!isCurrentAccount(epoch)) return;
    if (state.status) state.status.paused_space_ids = result.paused_space_ids;
    state.message = `Folder sync ${result.paused ? 'paused' : 'resumed'} for ${spaceName(spaceId)}.`;
    await refresh(false);
  } catch (error) {
    if (isCurrentAccount(epoch) && !isStaleAccountRequest(error)) state.error = messageOf(error);
  } finally {
    state.mutationBusy = Math.max(0, state.mutationBusy - 1);
    if (isCurrentAccount(epoch)) delete state.spaceActionBusy[spaceId];
    render();
  }
}
async function queueSpaceSync(spaceId: string) {
  const globallyPaused = state.status?.paused === true;
  const spacePaused = state.status?.paused_space_ids?.includes(spaceId) === true;
  if (!featureAvailable('folder_sync_supported') || !state.agentReachable || state.status?.connected !== true || globallyPaused || spacePaused || state.mutationBusy > 0 || state.spaceActionBusy[spaceId]) return;
  const epoch = state.accountEpoch;
  state.spaceActionBusy[spaceId] = 'sync';
  state.mutationBusy++;
  state.error = ''; state.message = '';
  render();
  try {
    const result = await request<{ accepted: boolean; space_id: string }>('space_sync_now', { space_id: spaceId });
    if (!isCurrentAccount(epoch)) return;
    if (!result.accepted) throw new Error('The agent did not accept the folder sync request.');
    state.message = `Folder sync queued for ${spaceName(spaceId)}. Check Transfers for progress; queued does not mean completed.`;
    await refresh(false);
  } catch (error) {
    if (isCurrentAccount(epoch) && !isStaleAccountRequest(error)) state.error = messageOf(error);
  } finally {
    state.mutationBusy = Math.max(0, state.mutationBusy - 1);
    if (isCurrentAccount(epoch)) delete state.spaceActionBusy[spaceId];
    render();
  }
}
async function disconnectSpaceFolderSync(spaceId: string) {
  if (!featureAvailable('folder_sync_supported') || !state.agentReachable || state.status?.connected !== true || state.mutationBusy > 0 || state.spaceActionBusy[spaceId]) return;
  const pairs = state.pairs.filter(pair => pair.space_id === spaceId);
  if (!pairs.length) return;
  const title = spaceName(spaceId);
  const epoch = state.accountEpoch;
  const profileId = state.selectedAccount;
  const pairIds = pairs.map(pair => pair.id).sort();
  if (!await confirmAccountAction(`Disconnect folder sync for ${title}? This removes all folder-sync connections for this Space. Local files and cloud files stay in place. Account and cloud-drive browsing, and media backups, remain connected.`) || !isCurrentAccount(epoch, profileId)) return;
  const currentPairIds = state.pairs.filter(pair => pair.space_id === spaceId).map(pair => pair.id).sort();
  if (!featureAvailable('folder_sync_supported') || !state.agentReachable || state.status?.connected !== true || state.mutationBusy > 0 || state.spaceActionBusy[spaceId] || currentPairIds.length !== pairIds.length || currentPairIds.some((id, index) => id !== pairIds[index])) return;
  state.spaceActionBusy[spaceId] = 'disconnect';
  state.mutationBusy++;
  state.error = ''; state.message = '';
  render();
  try {
    const result = await request<{ space_id: string; removed_pair_ids: string[] }>('space_disconnect', { space_id: spaceId });
    if (!isCurrentAccount(epoch, profileId)) return;
    if (result.space_id !== spaceId || !Array.isArray(result.removed_pair_ids) || result.removed_pair_ids.some(id => typeof id !== 'string' || !id)) {
      throw new Error('The agent returned an invalid folder-sync disconnect result. Refresh the folder list to check its status.');
    }
    for (const id of result.removed_pair_ids) {
      pairExclusionsUi.open.delete(id);
      pairExclusionsUi.drafts.delete(id);
      pairExclusionsUi.errors.delete(id);
      pairExclusionsUi.busy.delete(id);
    }
    state.message = `Folder sync disconnected for ${title}. Local and cloud files stay in place; account browsing and media backups remain connected.`;
    await refresh(false);
  } catch (error) {
    if (isCurrentAccount(epoch, profileId) && !isStaleAccountRequest(error)) {
      state.error = messageOf(error);
      // The request may have committed before a transport failure. Re-read the authoritative folder list.
      await refresh(false);
    }
  } finally {
    state.mutationBusy = Math.max(0, state.mutationBusy - 1);
    if (isCurrentAccount(epoch, profileId)) delete state.spaceActionBusy[spaceId];
    render();
  }
}
function accountStatusLabel(status: Status) {
  if (status.stopped) return 'Stopped';
  if (status.connected) return status.paused ? 'Paused' : 'Connected';
  if (isRetainedSignInOnly(status)) return 'Reconnecting sign-in';
  if (status.offline_namespace) return 'Working offline';
  if (!status.connected) return status.error ? 'Needs attention' : 'Sign-in needed';
  return 'Sign-in needed';
}
function isRetainedSignInOnly(status: Status | null | undefined): boolean {
  return status?.offline === true && status.offline_namespace !== true;
}
function selectedAccountLabel() { return state.accounts.find(account => account.id === state.selectedAccount)?.label || state.status?.profile_label || 'OpenCloud'; }
function accountSwitchDisabled() {
  const pickerModalOpen = state.pickerOpen && !(state.page === 'offline' && state.pickerPurpose === 'offline');
  const encryptedAccessModalOpen = state.vaultAccessOpen && state.page !== 'encrypted';
  return state.accountsLoading || state.accountSwitching || state.mutationBusy > 0 || state.nativeDialogBusy || state.addOpen || pickerModalOpen || state.vaultDialog !== null || encryptedAccessModalOpen || state.addAccountOpen || state.recoveryLoading || state.encryptedEditRecoveryLoading || state.resolvingConflict || state.pickerCreatingFolder;
}
function activateAccount(profileId: string) {
  if (profileId === state.selectedAccount) return false;
  if (copyProducerUi.source) resetCopyProducerFlow();
  mediaJobs.reset();
  pairExclusionsUi.open.clear();
  pairExclusionsUi.drafts.clear();
  pairExclusionsUi.errors.clear();
  pairExclusionsUi.busy.clear();
  resetEncryptedRetryLatestUi();
  clearOfflineUi();
  clearPendingOfflineWrites();
  cachedVaultRootsUi.generation++;
  cachedVaultRootsUi.roots = [];
  cachedVaultRootsUi.nextAfter = null;
  cachedVaultRootsUi.truncated = false;
  cachedVaultRootsUi.loading = false;
  cachedVaultRootsUi.error = '';
  cachedVaultRootsUi.selected = '';
  cachedVaultRootsUi.accountEpoch = -1;
  proxyUi.generation++;
  proxyUi.config = { mode: 'system' };
  proxyUi.revision = 0;
  proxyUi.accountId = null;
  proxyUi.scopeToken = undefined;
  proxyUi.loadedEpoch = -1;
  proxyUi.loading = false;
  proxyUi.saving = false;
  proxyUi.error = '';
  proxyUi.draftMode = 'system';
  proxyUi.draftUrl = '';
  bandwidthUi.generation++;
  bandwidthUi.upload = '';
  bandwidthUi.download = '';
  bandwidthUi.revision = 0;
  bandwidthUi.accountId = null;
  bandwidthUi.scopeToken = undefined;
  bandwidthUi.loadedEpoch = -1;
  bandwidthUi.loading = false;
  bandwidthUi.saving = false;
  bandwidthUi.error = '';
  state.accountEpoch++;
  windowsRecoveryController.setContext(null);
  windowsOfflineFoldersPanel.clear();
  if (windowsOfflineFolderPollTimer) window.clearTimeout(windowsOfflineFolderPollTimer);
  windowsOfflineFolderPollTimer = 0;
  windowsOfflineFilesUi.contextKey = '';
  windowsOfflineFilesUi.generation++;
  windowsOfflineFilesUi.items = [];
  windowsOfflineFilesUi.nextCursor = null;
  windowsOfflineFilesUi.loaded = false;
  windowsOfflineFilesUi.loading = false;
  windowsOfflineFilesUi.selectedKey = '';
  windowsOfflineFileController.clearSelection();
  if (windowsOfflineFilesUi.pollTimer) window.clearTimeout(windowsOfflineFilesUi.pollTimer);
  windowsOfflineFilesUi.pollTimer = 0;
  state.selectedAccount = profileId;
  state.status = null;
  state.spaceActionBusy = {};
  state.statusErrorDismissed = '';
  state.agentReachable = false;
  state.pairs = [];
  state.transfers = [];
  state.conflicts = {};
  state.resolvingConflict = false;
  state.recoveryPage = null;
  state.recoveryLoading = false;
  state.recoveryError = '';
  state.encryptedEditRecoveryPage = null;
  state.encryptedEditRecoveryLoading = false;
  state.encryptedEditRecoveryError = '';
  state.spaces = [];
  state.spacesServer = null;
  state.spacesLoading = false;
  state.spacesError = '';
  state.spaceId = '';
  state.remotePath = '';
  state.vaultGeneration++;
  if (state.vaultDialog) clearVaultPinUi(state.vaultDialog);
  state.vaultDialog = null;
  state.vaultAccessOpen = false;
  state.vaultAccessSpaceId = '';
  state.pickerPurpose = 'pair';
  state.pickerGeneration++;
  state.vaultBinding = null;
  state.vaultWritable = false;
  state.pickerOpen = false;
  state.pickerPath = '/';
  state.pickerEntries = [];
  state.pickerError = '';
  state.pickerWritable = {};
  state.pickerFolderName = '';
  state.pickerCreatingFolder = false;
  state.addOpen = false;
  state.addAccountOpen = false;
  state.addAccountLabel = '';
  state.addAccountRoot = '';
  state.localPath = '';
  state.mode = 'two_way';
  state.autostart = null;
  state.server = '';
  state.serverEdited = false;
  state.statusServer = '';
  state.clientId = '';
  state.clientIdEditedServer = null;
  state.clientIdServer = '';
  state.transferFilter = 'active';
  state.error = '';
  state.message = '';
  state.busy = false;
  refreshQueued = false;
  render();
  return true;
}
let accountsSyncQueued = false;
async function syncAccounts(): Promise<boolean> {
  if (accountsSyncPromise) {
    accountsSyncQueued = true;
    return accountsSyncPromise;
  }

  const run = (async () => {
    let anyChanged = false;
    do {
      accountsSyncQueued = false;
      const selectionRevision = accountSelectionRevision;
      state.accountsLoading = true;
      state.accountsError = '';
      render();
      let changed = false;
      try {
        const result = await request<AccountsResult>('accounts');
        state.accounts = result.items || [];
        state.removedAccounts = result.removed_items || [];
        state.accountRemovalSupported = result.account_removal_supported === true;
        if (selectionRevision === accountSelectionRevision) {
          changed = activateAccount(result.selected || '');
        } else {
          // The result may have been captured before a newer account_select.
          // Discard its selection and fetch again before allowing callers to
          // proceed with the new profile.
          accountsSyncQueued = true;
        }
      } catch (error) {
        if (!isStaleAccountRequest(error)) state.accountsError = messageOf(error);
      } finally {
        state.accountsLoading = false;
        render();
      }
      anyChanged ||= changed;
      if (changed) await refresh(false, true);
    } while (accountsSyncQueued);
    return anyChanged;
  })();
  accountsSyncPromise = run;
  try {
    return await run;
  } finally {
    if (accountsSyncPromise === run) accountsSyncPromise = null;
  }
}
async function syncAccountsForSelection(profileId: string): Promise<void> {
  for (let attempt = 0; attempt < 3; attempt++) {
    await syncAccounts();
    if (state.selectedAccount === profileId) return;
  }
  throw new Error('Raiun could not confirm the selected account. Refresh and try again.');
}
async function switchAccount(profileId: string) {
  if (!featureAvailable('account_switch_supported') || !profileId || profileId === state.selectedAccount || accountSwitchDisabled()) return;
  const targetLabel = state.accounts.find(account => account.id === profileId)?.label || 'account';
  state.accountSwitching = true;
  state.accountSwitchTarget = profileId;
  state.mutationBusy++;
  state.error = '';
  state.message = '';
  render();
  try {
    accountSelectionRevision++;
    await request('account_select', { profile_id: profileId });
    await syncAccountsForSelection(profileId);
    state.message = `Switched to ${targetLabel}.`;
  } catch (error) {
    if (!isStaleAccountRequest(error)) state.error = messageOf(error);
  } finally {
    state.accountSwitching = false;
    state.accountSwitchTarget = '';
    state.mutationBusy = Math.max(0, state.mutationBusy - 1);
    render();
    if (state.page === 'offline') void openOfflineFiles();
    if (state.page === 'encrypted') void openEncryptedAccess();
  }
}
function normalizeServerAddress(value: string): { ok: true; server: string } | { ok: false; error: string } {
  const server = value.trim().replace(/\/$/, '');
  if (!server) return { ok: false, error: 'Enter your OpenCloud server address.' };
  const normalized = /^https?:\/\//i.test(server) ? server : `https://${server}`;
  try {
    const parsed = new URL(normalized);
    if (parsed.protocol !== 'https:' || !parsed.hostname || parsed.username || parsed.password) return { ok: false, error: 'OpenCloud sign-in requires a valid HTTPS server address.' };
    return { ok: true, server: parsed.toString().replace(/\/$/, '') };
  } catch { return { ok: false, error: 'Enter a valid OpenCloud server address.' }; }
}
function updateAddAccountSubmit() {
  const submit = app.querySelector<HTMLButtonElement>('[data-action="save-account"]');
  const server = normalizeServerAddress(state.addAccountServer);
  if (submit) submit.disabled = state.addAccountBusy || !state.addAccountLabel.trim() || (state.status?.account_setup_requires_sign_in !== true && (!state.addAccountRoot || !server.ok));
}
function closeAccountSetup() {
  state.addAccountOpen = false;
  state.addAccountStep = 'details';
  state.addAccountLabel = '';
  state.addAccountRoot = '';
  state.addAccountServer = '';
  state.addAccountClientId = '';
  state.addAccountAuthMessage = '';
  state.addAccountAuthStarted = false;
  state.addAccountError = '';
  state.addAccountCreatedId = '';
  render();
}
async function beginNewAccountSignIn() {
  if (!featureAvailable('account_switch_supported')) return;
  const normalized = normalizeServerAddress(state.addAccountServer);
  if (!normalized.ok) throw new Error(normalized.error);
  state.addAccountServer = normalized.server;
  state.server = normalized.server;
  state.clientId = state.addAccountClientId.trim();
  const auth = await request<{ url: string; user_code?: string | null; expires_in?: number | null }>('auth_begin', { server: normalized.server, client_id: state.clientId });
  state.addAccountAuthStarted = true;
  const duration = auth.expires_in ? ` · expires in ${Math.ceil(auth.expires_in / 60)} min` : '';
  state.addAccountAuthMessage = auth.user_code
    ? `Enter code ${auth.user_code} in the browser${duration}.`
    : 'Sign-in page opened. Approve access in your browser, then return here.';
}
async function addAccount() {
  if (!featureAvailable('account_switch_supported')) return;
  if (state.addAccountBusy) return;
  const label = state.addAccountLabel.trim();
  const signInFirst = state.status?.account_setup_requires_sign_in === true;
  const cloudRoot = state.addAccountRoot.trim();
  const normalized = normalizeServerAddress(state.addAccountServer);
  if (!label || (!signInFirst && (!cloudRoot || !normalized.ok))) {
    state.addAccountError = signInFirst ? 'Enter an account label.' : !normalized.ok ? normalized.error : 'Enter an account label and choose its separate drive folder.';
    render();
    return;
  }
  if (!signInFirst && normalized.ok) state.addAccountServer = normalized.server;
  state.addAccountBusy = true;
  state.mutationBusy++;
  state.addAccountError = '';
  render();
  try {
    let profileId = state.addAccountCreatedId;
    if (!profileId) {
      const created = await request<{ id: string }>('account_add', signInFirst ? { label } : { label, cloud_root: cloudRoot });
      profileId = created.id;
      state.addAccountCreatedId = profileId;
    }
    accountSelectionRevision++;
    await request('account_select', { profile_id: profileId });
    state.page = 'settings';
    await syncAccountsForSelection(profileId);
    if (signInFirst) {
      const epoch = state.accountEpoch;
      await refresh(false, true);
      if (!isCurrentAccount(epoch, profileId)) return;
      closeAccountSetup();
      state.message = 'Account added. Sign in from Settings, then choose this account’s Windows drive folder.';
      return;
    }
    state.addAccountOpen = true;
    state.addAccountStep = 'waiting';
    state.addAccountLabel = label;
    state.addAccountRoot = cloudRoot;
    if (normalized.ok) state.addAccountServer = normalized.server;
    state.addAccountClientId = state.addAccountClientId.trim();
    await refresh(false, true);
    await beginNewAccountSignIn();
    await refresh(false, true);
  } catch (error) {
    if (!isStaleAccountRequest(error)) state.addAccountError = messageOf(error);
  } finally {
    state.addAccountBusy = false;
    state.mutationBusy = Math.max(0, state.mutationBusy - 1);
    render();
  }
}
async function retryAccountSignIn() {
  if (!featureAvailable('account_switch_supported')) return;
  if (state.addAccountBusy || !state.addAccountCreatedId || state.addAccountStep !== 'waiting') return;
  state.addAccountBusy = true;
  state.mutationBusy++;
  state.addAccountError = '';
  state.addAccountAuthMessage = '';
  render();
  try {
    await beginNewAccountSignIn();
    await refresh(false, true);
  } catch (error) {
    if (!isStaleAccountRequest(error)) state.addAccountError = messageOf(error);
  } finally {
    state.addAccountBusy = false;
    state.mutationBusy = Math.max(0, state.mutationBusy - 1);
    render();
  }
}
async function retryAccountMount() {
  if (!featureAvailable('account_switch_supported')) return;
  if (state.addAccountBusy || state.status?.connected !== true || state.status.mounted === true) return;
  const epoch = state.accountEpoch;
  state.addAccountBusy = true;
  state.mutationBusy++;
  state.addAccountError = '';
  render();
  try {
    await request('mount');
    await refresh(true, true);
    if (isCurrentAccount(epoch) && state.status?.connected && !state.status.mounted) state.addAccountError = state.status.error || 'The drive is still not mounted. Check Settings for more details.';
  } catch (error) {
    if (isCurrentAccount(epoch) && !isStaleAccountRequest(error)) state.addAccountError = messageOf(error);
  } finally {
    state.addAccountBusy = false;
    state.mutationBusy = Math.max(0, state.mutationBusy - 1);
    render();
  }
}
function validShellUnlockIntent(value: unknown): value is ShellUnlockIntent {
  if (!value || typeof value !== 'object') return false;
  const intent = value as Partial<ShellUnlockIntent>;
  const profileValid = intent.profile_id === 'default' || /^profile-[a-f0-9]{32}$/.test(intent.profile_id || '');
  const validHint = (hint: unknown) => typeof hint === 'string' && hint.length > 0 && new TextEncoder().encode(hint).length <= 1024 && !/[\u0000-\u001f\u007f]/.test(hint);
  return profileValid && validHint(intent.space_id) && validHint(intent.root_resource_id);
}
function validResolvedVaultRoot(path: unknown) {
  return typeof path === 'string' && path.startsWith('/') && new TextEncoder().encode(path).length <= 4096 && !/[\u0000-\u001f\u007f]/.test(path) && !path.split('/').some(component => component === '.' || component === '..');
}
async function findOfflineUnlockCandidate(intent: ShellUnlockIntent): Promise<CachedVaultRoot | null> {
  if (nativeVaultAccess()) return null;
  let cursor: CachedVaultRootsPage['next_after'] = null;
  const candidates: CachedVaultRoot[] = [];
  for (let pageIndex = 0; pageIndex < 10; pageIndex++) {
    const page: CachedVaultRootsPage = await request<CachedVaultRootsPage>('vault_cached_roots', { limit: 100, ...(cursor ? { after: cursor } : {}) });
    if (!Array.isArray(page.roots)) throw new Error('Raiun returned an invalid encrypted offline-location list.');
    for (const root of page.roots) {
      if (!root || typeof root.space_id !== 'string' || !root.space_id || new TextEncoder().encode(root.space_id).length > 1024 || typeof root.root_resource_id !== 'string' || !root.root_resource_id || new TextEncoder().encode(root.root_resource_id).length > 1024 || root.snapshot_available !== true || !((root.pin_id == null && root.generation == null) || (typeof root.pin_id === 'string' && !!root.pin_id && root.pin_id.length <= 512 && Number.isSafeInteger(root.generation) && (root.generation ?? -1) >= 0))) {
        throw new Error('Raiun returned an invalid encrypted offline-location entry.');
      }
      if (root.space_id === intent.space_id && root.root_resource_id === intent.root_resource_id && root.snapshot_available === true) {
        candidates.push(root);
      }
    }
    if (!page.next_after) break;
    if (pageIndex === 9) throw new Error('There are too many saved encrypted locations to verify this link. Open Raiun and choose the location from the list.');
    if (typeof page.next_after.space_id !== 'string' || !page.next_after.space_id || new TextEncoder().encode(page.next_after.space_id).length > 1024 || typeof page.next_after.root_resource_id !== 'string' || !page.next_after.root_resource_id || new TextEncoder().encode(page.next_after.root_resource_id).length > 1024) {
      throw new Error('Raiun returned an invalid encrypted offline-location cursor.');
    }
    cursor = page.next_after;
  }
  if (candidates.length > 1) throw new Error('Several saved encrypted copies match this location. Open Raiun and choose the exact saved copy.');
  return candidates[0] || null;
}
async function openShellUnlockIntent(value: unknown) {
  if (!validShellUnlockIntent(value)) {
    state.error = 'This Raiun unlock link is invalid or out of date.';
    render();
    return;
  }
  const intent = value;
  if (accountSwitchDisabled()) {
    state.error = 'Close the current dialog or finish the current action before opening this encrypted location.';
    render();
    return;
  }
  if (!state.accounts.some(account => account.id === intent.profile_id)) {
    state.error = 'This link points to an account that is not configured in Raiun. Choose the account first, then open the link again.';
    render();
    return;
  }
  if (state.selectedAccount !== intent.profile_id) {
    await switchAccount(intent.profile_id);
    if (state.selectedAccount !== intent.profile_id) return;
  }
  const epoch = state.accountEpoch;
  const profileId = state.selectedAccount;
  state.page = 'overview';
  render();
  try {
    if (state.status?.connected !== true) {
      const cached = await findOfflineUnlockCandidate(intent);
      if (!isCurrentAccount(epoch, profileId)) return;
      if (!cached) throw new Error('This encrypted location is not saved for offline access. Connect this account and try the link again.');
      if (cached.pin_id && (!Number.isSafeInteger(cached.generation) || (cached.generation ?? -1) < 0)) {
        throw new Error('The saved encrypted copy does not have a verified generation. Open Raiun and check its status.');
      }
      await openVaultFlow('browse', intent.space_id, '', undefined, undefined, intent.root_resource_id, true, cached.pin_id || undefined, Number.isSafeInteger(cached.generation) ? cached.generation! : undefined);
      if (isCurrentAccount(epoch, profileId) && state.vaultDialog && !state.vaultDialog.statusUnknown) state.message = 'Encrypted files are locked. Enter the vault password to open this saved copy.';
      return;
    }

    const target = await request<ResolvedUnlockTarget>('vault_resolve_unlock_target', {
      space_id: intent.space_id,
      root_resource_id: intent.root_resource_id,
    });
    if (!isCurrentAccount(epoch, profileId)) return;
    if (target.resolved !== true || target.profile_id !== profileId || target.space_id !== intent.space_id || target.root_resource_id !== intent.root_resource_id || !validResolvedVaultRoot(target.root_path)) {
      throw new Error('Raiun could not verify that encrypted location. Browse to it from the drive and try again.');
    }
    await openVaultFlow('browse', target.space_id, target.root_path, undefined, undefined, target.root_resource_id);
    if (isCurrentAccount(epoch, profileId) && state.vaultDialog && !state.vaultDialog.statusUnknown) state.message = 'Encrypted files are locked. Enter the vault password to open this location.';
  } catch (error) {
    if (isCurrentAccount(epoch, profileId) && !isStaleAccountRequest(error)) {
      state.error = messageOf(error);
      render();
    }
  }
}
async function consumeShellUnlockIntent() {
  if (!isTauri() || !unlockIntentInitializationReady) return;
  unlockIntentDrainRequested = true;
  if (unlockIntentDrain) return unlockIntentDrain;
  const run = (async () => {
    let handled = 0;
    while (unlockIntentDrainRequested && handled < 4) {
      unlockIntentDrainRequested = false;
      const intent = await invoke<ShellUnlockIntent | null>('take_shell_unlock_intent');
      if (!intent) continue;
      handled++;
      await openShellUnlockIntent(intent);
    }
  })();
  unlockIntentDrain = run;
  try {
    await run;
  } catch (error) {
    state.error = `Could not open the encrypted location link: ${messageOf(error)}`;
    render();
  } finally {
    if (unlockIntentDrain === run) unlockIntentDrain = null;
  }
}
async function refreshDesktopUpdate(manual: boolean) {
  if (!isTauri() || desktopUpdateUi.busy) return;
  desktopUpdateUi.busy = true;
  desktopUpdateUi.error = '';
  render();
  try {
    desktopUpdateUi.status = await invoke<DesktopUpdateStatus>('check_desktop_update', { manual });
  } catch (error) {
    desktopUpdateUi.error = `Could not check for Raiun Desktop updates: ${messageOf(error)}`;
  } finally {
    desktopUpdateUi.busy = false;
    render();
  }
}

async function saveDesktopUpdatePreferences(automaticChecks: boolean, channel: 'stable' | 'beta') {
  if (!isTauri()) return;
  const channelChanged = desktopUpdateUi.status?.channel != null && desktopUpdateUi.status.channel !== channel;
  let saved = false;
  try {
    desktopUpdateUi.status = await invoke<DesktopUpdateStatus>('set_desktop_update_preferences', { automaticChecks, channel });
    desktopUpdateUi.error = '';
    saved = true;
  } catch (error) {
    desktopUpdateUi.error = `Could not save update preferences: ${messageOf(error)}`;
  }
  if (saved && channelChanged) await refreshDesktopUpdate(true);
  else render();
}

async function downloadDesktopUpdate() {
  if (!isTauri() || desktopUpdateUi.busy) return;
  desktopUpdateUi.busy = true;
  desktopUpdateUi.error = '';
  render();
  try {
    const expectedTag = desktopUpdateUi.status?.tag;
    if (!expectedTag) throw new Error('No selected release is available to download. Check for updates again.');
    desktopUpdateUi.status = await invoke<DesktopUpdateStatus>('download_desktop_update', { expectedTag });
    if (desktopUpdateUi.status.error) desktopUpdateUi.error = desktopUpdateUi.status.error;
  } catch (error) {
    desktopUpdateUi.error = `Could not download a verified Desktop update: ${messageOf(error)}`;
  } finally {
    desktopUpdateUi.busy = false;
    render();
  }
}

async function installDesktopUpdate() {
  if (!isTauri() || desktopUpdateUi.busy) return;
  desktopUpdateUi.busy = true;
  desktopUpdateUi.error = '';
  render();
  try {
    await invoke('install_desktop_update');
    if (navigator.platform.toLowerCase().includes('linux')) {
      desktopUpdateUi.error = 'The update was installed. Raiun Desktop is restarting.';
    }
  } catch (error) {
    desktopUpdateUi.error = `Could not safely install the update: ${messageOf(error)}`;
  } finally {
    desktopUpdateUi.busy = false;
    render();
  }
}

async function laterDesktopUpdate() {
  const tag = desktopUpdateUi.status?.tag;
  if (!isTauri() || !tag) return;
  try {
    desktopUpdateUi.status = await invoke<DesktopUpdateStatus>('dismiss_desktop_update', { tag });
    desktopUpdateUi.error = '';
  } catch (error) {
    desktopUpdateUi.error = `Could not save this update reminder: ${messageOf(error)}`;
  }
  render();
}

async function openDesktopRelease() {
  const tag = desktopUpdateUi.status?.tag;
  if (!isTauri() || !tag) return;
  try {
    await invoke('open_desktop_release', { tag });
  } catch (error) {
    desktopUpdateUi.error = `Could not open the Desktop release page: ${messageOf(error)}`;
    render();
  }
}

async function initialize() {
  if (isTauri()) {
    try {
      await listen('raiun:unlock-intent', () => { void consumeShellUnlockIntent(); });
    } catch (error) {
      state.error = `Could not receive encrypted location links: ${messageOf(error)}`;
      render();
    }
  }
  const accountChanged = await syncAccounts();
  if (!accountChanged) await refresh(false);
  if (isTauri()) {
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible') void refreshDesktopUpdate(false);
    });
    void refreshDesktopUpdate(false);
    try {
      const destination = await invoke<string | null>('take_shell_navigation');
      if (destination === 'folders' || destination === 'transfers') {
        state.page = destination;
        render();
        if (destination === 'transfers') { if (!isWindowsAgentStatus(state.status)) void loadPendingOfflineWrites(true); if (vaultAppFeaturesAvailable()) { void loadEncryptedEditRecoveries(true); void refreshEncryptedRetryLatestStatuses(); } }
      }
    } catch (error) {
      state.error = `Could not check for pending tray navigation: ${messageOf(error)}`;
      render();
    }
    try {
      const shellError = await invoke<string | null>('take_shell_error');
      if (shellError?.trim()) {
        state.error = `Raiun tray action failed: ${shellError.trim()}`;
        render();
      }
    } catch (error) {
      state.error = `Could not check for a pending tray error: ${messageOf(error)}`;
      render();
    }
    unlockIntentInitializationReady = true;
    await consumeShellUnlockIntent();
  }
}
async function refresh(showError = true, forceSpacesRefresh = false) {
  if (state.busy) { refreshQueued = true; return; }
  const epoch = state.accountEpoch;
  const profileId = state.selectedAccount;
  state.busy = true;
  try {
    const priorRecoveryServer = state.status?.recovery_folder || '';
    state.status = await request<Status>('status');
    invalidateCopyProducerIfUnavailable();
    state.accounts = state.accounts.map(account => account.id === profileId
      ? { ...account, status: state.status! }
      : account);
    if (state.status.error !== state.statusErrorDismissed) state.statusErrorDismissed = '';
    const recoveryServer = state.status.recovery_folder || '';
    if (priorRecoveryServer !== recoveryServer) {
      state.recoveryPage = null;
      state.recoveryError = '';
    }
    state.agentReachable = true;
    syncWindowsRecoveryContext();
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
    const syncData = await loadProviderSyncData<Pair, Transfer>(
      state.status.provider_supported,
      state.status.connected,
      action => request(action),
      state.status.folder_sync_supported,
      !isWindowsAgentStatus(state.status),
    );
    state.pairs = syncData.pairs;
    state.transfers = syncData.transfers;
    if (providerAvailable(state.status.provider_supported) && state.status.connected) {
      if (typeof state.status.autostart === 'boolean') state.autostart = state.status.autostart;
      await loadSpaces(forceSpacesRefresh);
    } else {
      state.spaces = []; state.spacesServer = null; state.spacesError = ''; state.spaceId = '';
    }
    if (!state.status.connected && state.status.error && showError) state.error = state.status.error;
  } catch (error) {
    if (isCurrentAccount(epoch) && !isStaleAccountRequest(error)) {
      state.status = { connected: false, error: messageOf(error) };
      if (copyProducerUi.source) invalidateCopyProducerForVaultTransition();
      state.agentReachable = false;
      syncWindowsRecoveryContext();
      clearVaultOperations();
      state.pairs = []; state.transfers = [];
      state.spaces = []; state.spacesServer = null; state.spacesError = ''; state.spaceId = '';
      state.recoveryPage = null; state.recoveryError = '';
      if (showError) state.error = messageOf(error);
    }
  }
  if (isCurrentAccount(epoch)) {
    state.busy = false; render();
    if (state.page === 'settings') void loadNetworkProxySettings();
    if (state.page === 'settings') void loadBandwidthSettings();
    if (state.page === 'folders' && state.syncSection === 'media') void mediaJobs.refresh();
    if (state.page === 'transfers' && state.status?.connected) scheduleEncryptedRetryLatestPoll(250);
    if (refreshQueued) { refreshQueued = false; void refresh(false); }
  }
}
function closeAdd() { state.addOpen = false; state.pickerGeneration++; state.pickerPurpose = 'pair'; state.pickerOpen = false; state.localPath = ''; state.spaceId = ''; state.remotePath = ''; state.vaultBinding = null; state.vaultWritable = false; state.vaultGeneration++; state.vaultDialog = null; state.mode = 'two_way'; render(); }
function serverKey(value: string | null | undefined) {
  return (value || '').trim().replace(/\/$/, '').toLowerCase();
}
function messageOf(error: unknown) { return isStaleAccountRequest(error) ? '' : error instanceof Error ? error.message : String(error); }
function lastPath(path: string) { return path.replace(/\\/g, '/').split('/').filter(Boolean).at(-1) || path; }
function parentPath(path: string) { const parts = path.split('/').filter(Boolean); parts.pop(); return parts.length ? `/${parts.join('/')}` : '/'; }
function formatBytes(bytes: number) { if (bytes < 1024) return `${bytes} B`; const units = ['KB','MB','GB','TB']; let value = bytes / 1024; let index = 0; while (value >= 1024 && index < units.length - 1) { value /= 1024; index++; } return `${value.toFixed(value >= 10 ? 0 : 1)} ${units[index]}`; }
function activeCount() { return state.transfers.filter(t => ['queued','running','retry_wait','verifying'].includes((t.state || '').toLowerCase())).length; }
function attentionCount() { return state.transfers.filter(t => ['failed','conflict','awaiting_authentication'].includes((t.state || '').toLowerCase())).length; }

void listen<string>('navigate', event => { if (['folders','transfers'].includes(event.payload)) navigateToPage(event.payload as Page); });
void listen<{ source?: string; action?: string }>('raiun:status-changed', async event => {
  const passiveTrayPoll = event.payload?.source === 'tray' && !event.payload.action;
  if (passiveTrayPoll && passiveRefreshBlocked()) {
    passiveStatusRefreshQueued = true;
    return;
  }
  passiveStatusRefreshQueued = false;
  const changed = await syncAccounts();
  if (!changed) await refresh(false);
});
void listen<unknown>('raiun:tray-error', event => {
  const payload = event.payload;
  if (typeof payload === 'string' && payload.trim()) {
    state.error = `Raiun tray action failed: ${payload.trim()}`;
  } else if (payload && typeof payload === 'object' && 'action' in payload && payload.action === 'sync') {
    state.error = 'The sync request from the tray failed. Check the Raiun connection and retry from Transfers.';
  } else {
    state.error = 'A Raiun tray action failed. Check the agent status and try again.';
  }
  render();
});
render();
if (isTauri()) {
  void getVersion().then(version => {
    appVersionLabel = version;
    const versionElement = document.querySelector<HTMLElement>('#app-version');
    if (versionElement) versionElement.textContent = version;
  }).catch(() => {
    appVersionLabel = 'Version unavailable';
    const versionElement = document.querySelector<HTMLElement>('#app-version');
    if (versionElement) versionElement.textContent = 'Version unavailable';
  });
}
void initialize();
setInterval(() => { if (isTauri()) void refreshDesktopUpdate(false); }, 60 * 60 * 1000);
setInterval(() => { const waitingForAccountSetup = state.addAccountOpen && state.addAccountStep === 'waiting' && !state.addAccountBusy; if (shouldRunPeriodicPassiveRefresh(passiveRefreshBlockers(), waitingForAccountSetup)) { void syncAccounts().then(changed => { if (!changed) void refresh(false); }); } }, 15_000);
function editingControlFocused() {
  return document.activeElement instanceof HTMLInputElement || document.activeElement instanceof HTMLTextAreaElement || document.activeElement instanceof HTMLSelectElement;
}
function passiveRefreshBlocked() {
  return shouldBlockPassiveRefresh(passiveRefreshBlockers());
}
function passiveRefreshBlockers() {
  return {
    addOpen: state.addOpen,
    pickerOpen: state.pickerOpen,
    addAccountOpen: state.addAccountOpen,
    vaultDialogOpen: state.vaultDialog !== null,
    vaultAccessOpen: state.vaultAccessOpen,
    nativeDialogBusy: state.nativeDialogBusy,
    editingControlFocused: editingControlFocused()
  };
}
async function flushQueuedPassiveStatusRefresh() {
  if (!passiveStatusRefreshQueued || passiveRefreshBlocked()) return;
  passiveStatusRefreshQueued = false;
  try {
    const changed = await syncAccounts();
    if (!changed) await refresh(false);
  } catch (error) {
    state.error = messageOf(error);
    render();
  }
}
function scheduleQueuedPassiveStatusRefresh() {
  if (!passiveStatusRefreshQueued) return;
  window.setTimeout(() => { void flushQueuedPassiveStatusRefresh(); }, 0);
}
app.addEventListener('focusout', () => {
  scheduleQueuedPassiveStatusRefresh();
});
