//! Windows control plane and account-bound Cloud Files runtime. The provider
//! and verified save path are enabled in the next non-test candidate after
//! isolated native save/recovery/lifecycle acceptance. Package acceptance and
//! publication remain separate; other feature gates are independent.

#[path = "auth.rs"]
mod auth;

#[path = "root_manifest.rs"]
mod root_manifest;
#[path = "vault_custody.rs"]
mod vault_custody;
// Historical protected retention only; no upload or cleanup authority.
#[allow(dead_code)]
#[path = "vault_edit_capture.rs"]
mod vault_edit_capture;
#[path = "vault_edit_disposition.rs"]
mod vault_edit_disposition;
#[allow(dead_code)]
#[path = "vault_edit_retention.rs"]
mod vault_edit_retention;
#[path = "vault_edit_upload.rs"]
mod vault_edit_upload;
#[path = "windows_vault_capture_recovery.rs"]
mod windows_vault_capture_recovery;
#[path = "windows_vault_credentials.rs"]
mod windows_vault_credentials;
#[path = "windows_vault_custody.rs"]
mod windows_vault_custody;
// Dormant in normal activation; only an explicit per-Agent native fixture
// starts this fresh-only consumer. No history/startup dispatch.
#[allow(dead_code)]
#[path = "windows_vault_close_worker.rs"]
mod windows_vault_close_worker;

#[path = "windows_vault_cleanup_holds.rs"]
mod windows_vault_cleanup_holds;

#[path = "windows_proxy.rs"]
mod windows_proxy;

#[path = "windows_bandwidth.rs"]
mod windows_bandwidth;

#[path = "windows_cache_status.rs"]
mod windows_cache_status;

#[path = "windows_offline_jobs.rs"]
mod windows_offline_jobs;

#[path = "windows_folder_requests.rs"]
mod windows_folder_requests;
#[path = "windows_folder_sync.rs"]
mod windows_folder_sync;
#[path = "windows_media_requests.rs"]
mod windows_media_requests;
#[path = "windows_vault_browse.rs"]
mod windows_vault_browse;
#[path = "windows_vault_requests.rs"]
mod windows_vault_requests;

#[path = "windows_profile_registry.rs"]
mod windows_profile_registry;
#[path = "windows_profiles.rs"]
mod windows_profiles;

type ProtectedCapturePage = (
    Vec<windows_vault_custody::RecoveryCaptureMetadata>,
    Option<String>,
);

// Focused native broker acceptance passed. Enable candidate account routing;
// Folder/media source receipts bind the exact authenticated scope and source identity.
const WINDOWS_ACCOUNTS_ENABLED: bool = !cfg!(test);
const WINDOWS_FOLDER_SYNC_ENABLED: bool = !cfg!(test);
// Non-test candidate enables verified worker paths; exact package acceptance is separate.
const WINDOWS_MEDIA_METADATA_ENABLED: bool = !cfg!(test);
// Candidate unlock/read/lock and normal reconnection passed native acceptance.
// Test builds keep public capability exposure disabled; direct fixtures cover
// the same guarded implementation. Installed-package acceptance is separate.
const WINDOWS_VAULT_SESSIONS_ENABLED: bool = !cfg!(test);
const WINDOWS_REFRESH_LEAD_SECONDS: u64 = 30;
include!("windows_vault_session_control.rs");
include!("windows_vault_edit_upload.rs");

use clap::{Parser, Subcommand};
use raiun_cloudfiles_windows::{
    configured_roots_overlap, pin_configured_root, pin_registered_configured_root,
};
use raiun_control::{read_json_value, write_json_line};
use raiun_control_windows::{DpapiSessionStore, NamedPipeListener, connect_current_user};
use raiun_core::backend::{CloudBackend, CloudSpace};
use raiun_opencloud::{OpenCloudClient, RangeReadContext};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const PROVIDER_UNAVAILABLE: &str = "This operation is not available in this Windows beta.";

fn windows_startup_executable() -> Result<PathBuf, String> {
    std::env::current_exe()
        .map_err(|_| "The installed app path is unavailable".to_owned())?
        .parent()
        .map(|directory| directory.join("raiun-desktop-shell.exe"))
        .ok_or_else(|| "The installed app path is unavailable".to_owned())
}

const MAX_SESSION_BYTES: usize = 65_536;
const MAX_ROOT_CONFIG_BYTES: usize = 16 * 1024;
// The 9219 isolated native save + lifecycle checks passed. Non-test candidates
// now use the real provider/save path; exact-package acceptance is still required.
// Ordinary unit tests remain kernel-inactive. Ignored isolated-VM fixtures opt
// in per instance, exercising the same guarded production operations explicitly.
const WINDOWS_PROVIDER_ACTIVATION_ENABLED: bool = !cfg!(test);
const WINDOWS_INITIAL_SAVE_DISPATCH_ENABLED: bool = !cfg!(test);

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Serve,
    Request { message: String },
}

trait SessionStore: Send + Sync {
    /// Production stores declare their trusted profile before any restore or mutation.
    fn bound_profile(&self) -> Option<&str> {
        None
    }
    /// Persist the protected session blob without granting startup restore
    /// authority. The active pointer is published only after the auth worker
    /// wins the same state lock used by cancellation and logout.
    fn save_pending(&self, scope: &str, session: &auth::Session) -> Result<(), String>;
    fn publish_active(&self, scope: &str, session: &auth::Session) -> Result<(), String>;
    fn load_active(&self, expected_scope: &str) -> Result<Option<auth::Session>, String>;
    fn revoke_active(&self) -> Result<Option<(String, String, String)>, String>;
    fn remove(&self, scope: &str, server: &str, client_id: &str) -> Result<(), String>;
    fn save_root_config(
        &self,
        scope: &str,
        server: &str,
        client_id: &str,
        bytes: &[u8],
    ) -> Result<(), String>;
    fn load_root_config(
        &self,
        scope: &str,
        server: &str,
        client_id: &str,
    ) -> Result<Option<Vec<u8>>, String>;
    fn remove_root_config(&self, scope: &str, server: &str, client_id: &str) -> Result<(), String>;
    fn load_bandwidth_settings(
        &self,
        _profile: &str,
        _scope: &[u8],
    ) -> Result<Option<Vec<u8>>, String> {
        Err("Bandwidth storage is unavailable".into())
    }
    fn compare_exchange_bandwidth_settings(
        &self,
        _profile: &str,
        _scope: &[u8],
        _old: Option<&[u8]>,
        _next: &[u8],
    ) -> Result<(), String> {
        Err("Bandwidth storage is unavailable".into())
    }
    fn load_proxy_settings(&self, _profile: &str) -> Result<Option<Vec<u8>>, String> {
        Err("Proxy storage is unavailable".into())
    }
    fn compare_exchange_proxy_settings(
        &self,
        _profile: &str,
        _old: Option<&[u8]>,
        _next: &[u8],
    ) -> Result<(), String> {
        Err("Proxy storage is unavailable".into())
    }
    fn load_vault_credentials(
        &self,
        _profile: &str,
    ) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, String> {
        Err("Protected vault credentials are unavailable".into())
    }
    fn compare_exchange_vault_credentials(
        &self,
        _profile: &str,
        _old: Option<&[u8]>,
        _next: &[u8],
    ) -> Result<(), String> {
        Err("Protected vault credentials are unavailable".into())
    }
    fn load_vault_custody(
        &self,
        _scope: &[u8],
    ) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, String> {
        Err("Protected vault history is unavailable".into())
    }
    fn compare_exchange_vault_custody(
        &self,
        _scope: &[u8],
        _old: Option<&[u8]>,
        _next: &[u8],
    ) -> Result<(), String> {
        Err("Protected vault history is unavailable".into())
    }
    fn load_vault_existing_edit_capture(
        &self,
        _binding: &[u8],
    ) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, String> {
        Err("Protected vault capture is unavailable".into())
    }
    fn put_new_vault_existing_edit_capture(
        &self,
        _binding: &[u8],
        _record: &[u8],
    ) -> Result<(), String> {
        Err("Protected vault capture is unavailable".into())
    }
    fn load_vault_completed_history_segment(
        &self,
        _binding: &[u8],
    ) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, String> {
        Err("Protected completed vault history is unavailable".into())
    }
    fn put_new_vault_completed_history_segment(
        &self,
        _binding: &[u8],
        _record: &[u8],
    ) -> Result<(), String> {
        Err("Protected completed vault history is unavailable".into())
    }
    fn before_publish(&self) {}
}

struct BandwidthStore<'a> {
    store: &'a dyn SessionStore,
    profile: &'a str,
}
impl windows_bandwidth::Store for BandwidthStore<'_> {
    fn load(&self, scope: &[u8]) -> Result<Option<Vec<u8>>, String> {
        self.store.load_bandwidth_settings(self.profile, scope)
    }
    fn compare_exchange(
        &self,
        scope: &[u8],
        old: Option<&[u8]>,
        next: &[u8],
    ) -> Result<(), String> {
        self.store
            .compare_exchange_bandwidth_settings(self.profile, scope, old, next)
    }
}
struct VaultCredentialStore<'a> {
    store: &'a dyn SessionStore,
    profile: &'a str,
}
impl windows_vault_credentials::Store for VaultCredentialStore<'_> {
    fn load(&self, profile: &str) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, String> {
        if profile != self.profile {
            return Err("Vault credential profile changed".into());
        }
        self.store.load_vault_credentials(profile)
    }
    fn compare_exchange(
        &self,
        profile: &str,
        old: Option<&[u8]>,
        next: &[u8],
    ) -> Result<(), String> {
        if profile != self.profile {
            return Err("Vault credential profile changed".into());
        }
        self.store
            .compare_exchange_vault_credentials(profile, old, next)
    }
}

struct ProxyStore<'a> {
    store: &'a dyn SessionStore,
    profile: &'a str,
}
impl windows_proxy::Store for ProxyStore<'_> {
    fn load(&self) -> Result<Option<Vec<u8>>, String> {
        self.store.load_proxy_settings(self.profile)
    }
    fn compare_exchange(&self, old: Option<&[u8]>, next: &[u8]) -> Result<(), String> {
        self.store
            .compare_exchange_proxy_settings(self.profile, old, next)
    }
}

fn budget_client(
    client: Arc<OpenCloudClient>,
    session: &auth::Session,
    profile: &str,
    account: &str,
    generation: u64,
    provider: &ProviderManager,
    store: &dyn SessionStore,
) -> Result<(Arc<OpenCloudClient>, windows_bandwidth::Scope), String> {
    if generation == 0 || provider.authorized_generation.load(Ordering::Acquire) != generation {
        return Err("The account changed before bandwidth admission".into());
    }
    let scope = windows_bandwidth::Scope::new(
        profile,
        &session.server,
        &session.client_id,
        session.expected_issuer.as_deref(),
        account,
    )?;
    provider.proxy.bind_verified(
        profile,
        scope.bytes(),
        &session.proxy,
        generation,
        &ProxyStore { store, profile },
    )?;
    let budget = provider.bandwidth.bind(
        scope.clone(),
        generation,
        &BandwidthStore { store, profile },
    )?;
    if provider.authorized_generation.load(Ordering::Acquire) != generation {
        // authorize_generation already cancels the retired generation; a stale
        // completion must not pause a newer controller.
        return Err("The account changed during bandwidth admission".into());
    }
    let client = Arc::try_unwrap(client)
        .map_err(|_| "The account client was already published")?
        .with_transfer_budget(budget);
    Ok((Arc::new(client), scope))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RootConfiguration {
    profile_scope: String,
    server: String,
    client_id: String,
    issuer: Option<String>,
    path: String,
    volume_serial: u32,
    file_index: u64,
    registration_ownership: Option<RegistrationOwnership>,
    valid: bool,
}

/// Durable proof binding a Cloud Files registration to the account's verified
/// Personal drive and this exact local root. The state records whether the
/// OS registration was actually confirmed; it is not inferred from the
/// existence of this configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RegistrationOwnership {
    state: String,
    account_id: String,
    personal_drive_id: String,
    personal_root_resource_id: Option<String>,
    volume_serial: u32,
    file_index: u64,
}

#[derive(Default)]
struct AccountState {
    session: Option<auth::Session>,
    root_configuration: Option<RootConfiguration>,
    online_authenticated: bool,
    logout_pending: bool,
    needs_refresh: bool,
    refreshing: bool,
    refresh_retry_at: u64,
    authenticating: bool,
    active_generation: u64,
    error: Option<String>,
    session_cleanup_uncertain: bool,
    retiring: bool,
}

struct WindowsRecoveryContext {
    session: auth::Session,
    agent_generation: u64,
    configuration: RootConfiguration,
    local_root_identity: raiun_cloudfiles_windows::ConfiguredRootIdentity,
    _root_lease: raiun_cloudfiles_windows::ConfiguredRootLease,
    client: Arc<OpenCloudClient>,
    provider_scope: raiun_cloudfiles_windows::ProviderScope,
    spaces: Vec<CloudSpace>,
    context: RangeReadContext,
    recovery_provider: raiun_cloudfiles_windows::DurableEditRecoveryProvider,
}

type SharedSourceAdmissions = Arc<Mutex<Arc<windows_profile_registry::Registry>>>;

struct WindowsAgent {
    source_admissions: Option<SharedSourceAdmissions>,
    vault_sessions: Arc<raiun_vault::session::VaultSessionCoordinator>,
    profile_scope: String,
    session_store: Arc<dyn SessionStore>,
    state: Arc<Mutex<AccountState>>,
    generation: Arc<AtomicU64>,
    provider: Arc<ProviderManager>,
    auth_thread: Mutex<Option<JoinHandle<()>>>,
    refresh_thread: Mutex<Option<JoinHandle<()>>>,
    fresh_close_worker: Mutex<Option<windows_vault_close_worker::FreshCloseWorker>>,
    folder_lifecycle: Mutex<()>,
    vault_credential_operation: Mutex<()>,
    protected_recovery_tokens: Mutex<windows_vault_capture_recovery::Tokens>,
    #[cfg(all(test, debug_assertions))]
    synthetic_vault_completion_writer_probe: bool,
}

struct ProtectedRecoveryContext {
    generation: u64,
    session: auth::Session,
    configuration: RootConfiguration,
    binding: ActiveProviderBinding,
    context_token: String,
}

#[derive(Clone)]
struct FolderPauseSnapshot {
    generation: u64,
    paused: bool,
    paused_space_ids: Vec<String>,
}

/// Own the native Cloud Files connection on one dedicated thread. The native
/// connection contains OS handles and callback lifetime state, so it never
/// crosses a Rust thread boundary. All auth/session transitions synchronously
/// request a revoke-and-disconnect before replacing credentials.
struct ProviderManager {
    proxy: windows_proxy::Service,
    bandwidth: windows_bandwidth::Service,
    commands: std::sync::mpsc::SyncSender<ProviderCommand>,
    connected: Arc<AtomicBool>,
    authorized_generation: Arc<AtomicU64>,
    recovery_cursor_nonce: Option<[u8; 32]>,
    offline_jobs: Arc<windows_offline_jobs::OfflineJobs>,
    worker: Mutex<Option<JoinHandle<()>>>,
    fresh_close_source: Mutex<Option<FreshClosePublication>>,
    existing_save_owner: Mutex<Weak<WindowsAgent>>,
    existing_save_admission: AtomicBool,
    folder_generation: Arc<AtomicU64>,
    folder_revocation: Arc<Mutex<Option<raiun_engine::SyncRevocationHandle>>>,
    folder_error: Arc<Mutex<Option<String>>>,
    folder_pause: Arc<Mutex<Option<FolderPauseSnapshot>>>,
    // Per-instance native-test capability; absent from production binaries and
    // never controlled by environment, IPC, configuration, or another agent.
    #[cfg(all(test, debug_assertions))]
    lifecycle_test_activation: AtomicBool,
    #[cfg(all(test, debug_assertions))]
    initial_save_test_activation: Arc<AtomicBool>,
    #[cfg(all(test, debug_assertions))]
    initial_save_test_observation: Arc<Mutex<Option<String>>>,
    #[cfg(all(test, debug_assertions))]
    disconnect_test_calls: AtomicU64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ActiveProviderBinding {
    generation: u64,
    path: PathBuf,
    identity: raiun_cloudfiles_windows::ConfiguredRootIdentity,
    personal_space_id: String,
    personal_root_resource_id: String,
}

// Immutable source admission metadata; not a restored publication capability.
struct FreshClosePublication {
    source: windows_vault_close_worker::VaultClosePublisherSource,
    binding: Option<ActiveProviderBinding>,
    original_active: Option<Arc<AtomicBool>>,
}
impl FreshClosePublication {
    #[cfg(all(test, debug_assertions))]
    fn private(source: windows_vault_close_worker::VaultClosePublisherSource) -> Self {
        Self {
            source,
            binding: None,
            original_active: None,
        }
    }
    fn cancel(&self) {
        self.source.cancel();
    }
    fn publisher(
        &self,
        generation: u64,
    ) -> Option<windows_vault_close_worker::VaultClosePublisher> {
        if self
            .binding
            .as_ref()
            .is_some_and(|binding| binding.generation != generation)
        {
            return None;
        }
        self.source.publisher(generation)
    }
    fn marker(&self, binding: &ActiveProviderBinding) -> Option<Arc<AtomicBool>> {
        if self.binding.as_ref() != Some(binding) {
            return None;
        }
        let active = self.source.existing_file_save_marker(binding.generation)?;
        self.original_active
            .as_ref()
            .filter(|original| Arc::ptr_eq(original, &active))?;
        Some(active)
    }
}

// The atomic gate is finite admission serialization, never a mutex held through
// a worker join or native command. Failure cancels only this exact source.
struct ExistingSaveWorkerAdmission {
    owner: Arc<WindowsAgent>,
    binding: ActiveProviderBinding,
    original_active: Option<Arc<AtomicBool>>,
    connection_current: bool,
    committed: bool,
}
impl Drop for ExistingSaveWorkerAdmission {
    fn drop(&mut self) {
        if !self.committed
            && let Some(active) = self.original_active.as_ref()
        {
            self.owner
                .abort_existing_file_save_admission(&self.binding, active);
        }
        self.owner
            .provider
            .existing_save_admission
            .store(false, Ordering::Release);
    }
}

// Pure admission check used before any native parent-population operation.
fn vault_worker_binding_current(
    generation: u64,
    requested: &ActiveProviderBinding,
    active: Option<&ActiveProviderBinding>,
) -> bool {
    requested.generation != 0 && generation == requested.generation && active == Some(requested)
}

struct VerifiedVaultBackend {
    backend: Arc<raiun_cloudfiles_windows::OpenCloudPlaceholderBackend>,
    custody: Arc<windows_vault_custody::WindowsVaultCustody>,
}

// Owner-thread only: the opaque native fence never enters a command or response.
struct PendingNativeVaultCleanup {
    binding: ActiveProviderBinding,
    expected_backend: Arc<raiun_cloudfiles_windows::OpenCloudPlaceholderBackend>,
    route: Arc<raiun_cloudfiles_windows::vault_routes::VerifiedVaultRoute>,
    fence: raiun_cloudfiles_windows::VaultCleanupFence,
}

type PendingVaultCleanupTicket = windows_vault_cleanup_holds::PendingCleanupTicket;

enum ProviderCommand {
    InstallFolders {
        setup: Box<windows_folder_sync::Setup>,
        response: std::sync::mpsc::SyncSender<Result<(), String>>,
    },
    FolderRequest {
        generation: u64,
        request: windows_folder_requests::FolderRequest,
        response: std::sync::mpsc::SyncSender<Result<Value, String>>,
    },
    PrepareOfflineFolder {
        binding: ActiveProviderBinding,
        response: std::sync::mpsc::SyncSender<Result<Value, String>>,
    },
    ListOfflineFolders {
        binding: ActiveProviderBinding,
        cursor: Option<String>,
        cancellation: raiun_cloudfiles_windows::CancellationToken,
        response: std::sync::mpsc::SyncSender<Result<Value, String>>,
    },
    StartOfflineFolder {
        binding: ActiveProviderBinding,
        request: windows_cache_status::FolderJobRequest,
        response: std::sync::mpsc::SyncSender<Result<Value, String>>,
    },
    ListOfflineFiles {
        binding: ActiveProviderBinding,
        cursor: Option<String>,
        cancellation: raiun_cloudfiles_windows::CancellationToken,
        response: std::sync::mpsc::SyncSender<Result<Value, String>>,
    },
    StartOfflineFile {
        binding: ActiveProviderBinding,
        row: windows_cache_status::CacheStatusRow,
        response: std::sync::mpsc::SyncSender<Result<Value, String>>,
    },
    SetDeviceCacheQuota {
        binding: ActiveProviderBinding,
        quota_bytes: u64,
        response: std::sync::mpsc::SyncSender<Result<Value, String>>,
    },
    DeviceCacheUsage {
        binding: ActiveProviderBinding,
        response: std::sync::mpsc::SyncSender<Result<Value, String>>,
    },
    FileCacheStatus {
        binding: ActiveProviderBinding,
        row: windows_cache_status::CacheStatusRow,
        response:
            std::sync::mpsc::SyncSender<Result<raiun_cloudfiles_windows::FileCacheStatus, String>>,
    },
    RefreshVaultParent {
        binding: ActiveProviderBinding,
        space_id: String,
        root_resource_id: String,
        root_path: String,
        response: std::sync::mpsc::SyncSender<Result<(), String>>,
    },
    BeginLockVaultRoute {
        binding: ActiveProviderBinding,
        space_id: String,
        root_resource_id: String,
        root_path: String,
        response: std::sync::mpsc::SyncSender<Result<PendingVaultCleanupTicket, String>>,
    },
    FinishLockVaultRoute {
        binding: ActiveProviderBinding,
        ticket: PendingVaultCleanupTicket,
        response: std::sync::mpsc::SyncSender<Result<(), String>>,
    },
    AbortLockVaultRoute {
        binding: ActiveProviderBinding,
        ticket: PendingVaultCleanupTicket,
        response: std::sync::mpsc::SyncSender<Result<(), String>>,
    },
    InspectVaultBackend {
        binding: ActiveProviderBinding,
        response: std::sync::mpsc::SyncSender<Result<VerifiedVaultBackend, String>>,
    },
    ListProtectedVaultCaptures {
        binding: ActiveProviderBinding,
        scope: windows_vault_capture_recovery::RecoveryScope,
        after_capture_id: Option<String>,
        limit: usize,
        response: std::sync::mpsc::SyncSender<Result<ProtectedCapturePage, String>>,
    },
    SaveProtectedVaultCaptureCopy {
        binding: ActiveProviderBinding,
        scope: windows_vault_capture_recovery::RecoveryScope,
        capture_id: String,
        destination: PathBuf,
        response: std::sync::mpsc::SyncSender<
            Result<windows_vault_capture_recovery::CopyReceipt, String>,
        >,
    },
    CompleteVaultUpload {
        writable_bytes: bool,
        binding: ActiveProviderBinding,
        expected_backend: Arc<raiun_cloudfiles_windows::OpenCloudPlaceholderBackend>,
        upload: raiun_cloudfiles_windows::FreshVaultUpload,
        store: Box<dyn raiun_cloudfiles_windows::VaultLocalCompletionStore>,
        response: std::sync::mpsc::SyncSender<Result<(), String>>,
    },
    VaultCleanupDiagnostics {
        binding: ActiveProviderBinding,
        response: std::sync::mpsc::SyncSender<Result<Value, String>>,
    },
    VaultLockCleanupStatus {
        binding: ActiveProviderBinding,
        space_id: String,
        root_resource_id: String,
        root_path: String,
        response: std::sync::mpsc::SyncSender<Result<bool, String>>,
    },
    InspectConnection {
        binding: ActiveProviderBinding,
        response: std::sync::mpsc::SyncSender<Result<bool, String>>,
    },
    Connect {
        path: PathBuf,
        generation: u64,
        expected_identity: raiun_cloudfiles_windows::ConfiguredRootIdentity,
        already_registered: bool,
        personal_space_id: String,
        personal_root_resource_id: String,
        backend: Arc<raiun_cloudfiles_windows::OpenCloudPlaceholderBackend>,
        recovery: Arc<dyn raiun_cloudfiles_windows::EditRecoveryProvider>,
        custody_account: Vec<u8>,
        custody_store: Arc<dyn SessionStore>,
        fresh_close_publisher: Option<windows_vault_close_worker::VaultClosePublisher>,
        response: std::sync::mpsc::SyncSender<Result<(), String>>,
    },
    DispatchRecovery {
        agent_generation: u64,
        recovery: Arc<dyn raiun_cloudfiles_windows::PreparedEditRecovery>,
        record_id: String,
        record_generation: u64,
        remote: Arc<dyn raiun_cloudfiles_windows::RecoveryRemote>,
        response: std::sync::mpsc::SyncSender<
            Result<raiun_cloudfiles_windows::ReconciliationOutcome, String>,
        >,
    },
    #[cfg(all(test, debug_assertions))]
    RevokeBackendForTest(std::sync::mpsc::SyncSender<Result<(), String>>),
    #[cfg(test)]
    DirectoryObservation(std::sync::mpsc::SyncSender<Result<NativeCallbackObservation, String>>),
    #[cfg(test)]
    ReadOnlyPlaceholderObservation {
        path: NativeRestartProbePath,
        response: std::sync::mpsc::SyncSender<Result<NativeReadOnlyObservation, String>>,
    },
    #[cfg(test)]
    HydrateNativeReadFixtureForTest {
        fixture: NativeReadFixturePath,
        response: std::sync::mpsc::SyncSender<Result<i32, String>>,
    },
    #[cfg(test)]
    VaultFilePendingForTest {
        identity: [u8; 16],
        response: std::sync::mpsc::SyncSender<Result<bool, String>>,
    },
    #[cfg(test)]
    VaultCleanupFixture {
        binding: ActiveProviderBinding,
        forget_receipt: Option<[u8; 16]>,
        response: std::sync::mpsc::SyncSender<Result<bool, String>>,
    },
    #[cfg(test)]
    CloseObservation(std::sync::mpsc::SyncSender<Result<NativeCloseObservation, String>>),
    Disconnect(std::sync::mpsc::SyncSender<Result<(), String>>),
    Stop(std::sync::mpsc::SyncSender<Result<(), String>>),
}

#[cfg(test)]
type NativeCallbackObservation = (
    (usize, usize, usize, usize, usize),
    (usize, usize, usize, i32),
    Result<(u32, u32, u32, u64), String>,
    Result<i32, String>,
    Result<(u32, u32, u32, u64), String>,
);

#[cfg(test)]
type NativeCloseObservation = (usize, usize, usize, usize, usize, i32, usize, usize);

#[cfg(test)]
type NativeReadOnlyObservation = (
    (usize, usize, usize, usize, usize),
    (usize, usize, usize, i32),
    Result<(u32, u32, u32, u64), String>,
);

#[cfg(test)]
type NativeDifferentialObservation = (
    NativeReadOnlyObservation,
    (usize, usize, usize),
    (usize, usize, usize, usize, usize, usize),
);

#[cfg(test)]
#[derive(Clone, Copy)]
enum NativeReadFixturePath {
    Personal,
    ProjectsSpace,
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum NativeRestartProbePath {
    PersonalNativeRead,
    ProjectsNativeRead,
    RecoveryDocument,
    RecoveryReadOnlyProbe,
    VaultCapturedFile,
}

impl ProviderManager {
    fn new() -> Self {
        let (commands, receiver) = std::sync::mpsc::sync_channel(4);
        let connected = Arc::new(AtomicBool::new(false));
        let worker_connected = Arc::clone(&connected);
        let authorized_generation = Arc::new(AtomicU64::new(1));
        let worker_generation = Arc::clone(&authorized_generation);
        let initial_save_activation =
            Arc::new(AtomicBool::new(WINDOWS_INITIAL_SAVE_DISPATCH_ENABLED));
        let worker_initial_save_activation = Arc::clone(&initial_save_activation);
        #[cfg(all(test, debug_assertions))]
        let initial_save_test_observation = Arc::new(Mutex::new(None::<String>));
        #[cfg(all(test, debug_assertions))]
        let worker_initial_save_test_observation = Arc::clone(&initial_save_test_observation);
        let offline_jobs = Arc::new(windows_offline_jobs::OfflineJobs::default());
        let worker_jobs = Arc::clone(&offline_jobs);
        let folder_generation = Arc::new(AtomicU64::new(0));
        let worker_folder_generation = Arc::clone(&folder_generation);
        let folder_revocation = Arc::new(Mutex::new(None::<raiun_engine::SyncRevocationHandle>));
        let worker_folder_revocation = Arc::clone(&folder_revocation);
        let folder_error = Arc::new(Mutex::new(None));
        let worker_folder_error = Arc::clone(&folder_error);
        let folder_pause = Arc::new(Mutex::new(None::<FolderPauseSnapshot>));
        let worker_folder_pause = Arc::clone(&folder_pause);
        let worker = thread::Builder::new()
            .name("raiun-windows-cloud-files".into())
            .spawn(move || {
                let mut connection: Option<raiun_cloudfiles_windows::ConfiguredRootConnection> =
                    None;
                let mut backend: Option<Arc<raiun_cloudfiles_windows::OpenCloudPlaceholderBackend>> =
                    None;
                let mut vault_custody: Option<Arc<windows_vault_custody::WindowsVaultCustody>> = None;
                let mut retired_vaults: Vec<Arc<raiun_cloudfiles_windows::vault_routes::VerifiedVaultRoute>> = Vec::new();
                let mut active_binding: Option<ActiveProviderBinding> = None;
                let mut last_vault_cleanup_error: Option<raiun_cloudfiles_windows::Error> = None;
                let mut folders: Option<windows_folder_sync::Runtime> = None;
                let mut cleanup_holds = windows_vault_cleanup_holds::PendingCleanupHolds::<PendingNativeVaultCleanup>::new();
                let mut pending_command = None;
                loop {
                    let command = match pending_command.take().map_or_else(
                        || receiver.recv_timeout(Duration::from_millis(250)), Ok,
                    ) {
                        Ok(command) => Some(command),
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => None,
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                    };
                    // Sweep on every command and the existing bounded idle tick.
                    cleanup_holds.sweep(Instant::now());
                    if active_binding.as_ref().is_some_and(|binding| worker_generation.load(Ordering::Acquire) != binding.generation) {
                        cleanup_holds.clear();
                    }
                    let handled_command = command.is_some();
                    if let Some(command) = command {
                    match command {
                        ProviderCommand::InstallFolders { setup, response } => {
                            let generation = setup.generation;
                            let result = (|| {
                                if worker_generation.load(Ordering::Acquire) != generation { return Err("The account changed before folder setup".into()); }
                                if folders.as_ref().is_some_and(|runtime| runtime.generation == generation) { return Ok(()); }
                                let runtime = windows_folder_sync::Runtime::open(*setup, &worker_generation)?;
                                let (paused, paused_space_ids) = runtime.pause_snapshot()?;
                                let mut cancellation = worker_folder_revocation.lock().map_err(|_| "Folder cancellation is unavailable")?;
                                if worker_generation.load(Ordering::Acquire) != generation { return Err("The account changed during folder setup".into()); }
                                let mut pause_status = worker_folder_pause.lock().map_err(|_| "Folder status unavailable")?;
                                if let Some(previous) = cancellation.take() { previous.revoke(); }
                                *cancellation = Some(runtime.revocation_handle());
                                *pause_status = Some(FolderPauseSnapshot { generation, paused, paused_space_ids });
                                folders = Some(runtime);
                                worker_folder_generation.store(generation, Ordering::Release);
                                Ok(())
                            })();
                            let _ = response.send(result);
                        }
                        ProviderCommand::FolderRequest { generation, request, response } => {
                            let Some(runtime) = folders.as_mut().filter(|runtime| runtime.generation == generation && worker_generation.load(Ordering::Acquire) == generation) else {
                                let _ = response.send(Err("The account changed before folder work".into())); continue;
                            };
                            if let windows_folder_requests::FolderRequest::Sync { space_id } = request {
                                match runtime.prepare_sync(space_id.as_deref(), &worker_generation) {
                                    Ok((revision, pairs)) => {
                                        // Acceptance is queued work, never a claim of completion.
                                        let accepted = space_id.as_ref().map_or_else(|| json!({}), |id| json!({"accepted":true,"space_id":id}));
                                        let _ = response.send(Ok(accepted));
                                        let result = runtime.run_sync(revision, pairs, &worker_generation);
                                        if let Ok(mut error) = worker_folder_error.lock() { *error = result.err(); }
                                    }
                                    Err(error) => { let _ = response.send(Err(error)); }
                                }
                            } else if let windows_folder_requests::FolderRequest::Media(windows_media_requests::MediaRequest::Run { job_id, expected_revision, expected_account_id }) = request {
                                match runtime.prepare_media_run(&job_id, expected_revision, &expected_account_id, &worker_generation) {
                                    Ok((revision, job, pin)) => {
                                        let accepted = json!({"accepted":true,"queued":true,"job_id":job.id.clone(),"revision":job.revision});
                                        let _ = response.send(Ok(accepted));
                                        let result = runtime.run_media_job(revision, job, pin, &worker_generation);
                                        if let Ok(mut error) = worker_folder_error.lock() { *error = result.err(); }
                                    }
                                    Err(error) => { let _ = response.send(Err(error)); }
                                }
                            } else {
                                let changes_pause = matches!(&request, windows_folder_requests::FolderRequest::Pause { .. } | windows_folder_requests::FolderRequest::SpacePause { .. });
                                let result = runtime.handle(request, &worker_generation);
                                if result.is_ok() && changes_pause {
                                    // Snapshot publication shares the install/revocation lock.
                                    if let Ok(_cancellation) = worker_folder_revocation.lock() {
                                        if worker_generation.load(Ordering::Acquire) == generation && worker_folder_generation.load(Ordering::Acquire) == generation {
                                            if let Ok(mut snapshot) = worker_folder_pause.lock() {
                                                *snapshot = runtime.pause_snapshot().ok().map(|(paused, paused_space_ids)| FolderPauseSnapshot { generation, paused, paused_space_ids });
                                            }
                                        }
                                    }
                                }
                                let _ = response.send(result);
                            }
                        }
                        ProviderCommand::ListOfflineFolders { binding, cursor, cancellation, response } => {
                            let mut result = windows_cache_status::inspect_worker_folder_page(
                                worker_generation.load(Ordering::Acquire), &binding,
                                active_binding.as_ref(), connection.is_some(), backend.as_deref(), cursor.as_deref(), &cancellation);
                            if worker_generation.load(Ordering::Acquire) != binding.generation {
                                result = Err("The account changed during folder inspection".to_owned());
                            }
                            let _ = response.send(result);
                        }
                        ProviderCommand::PrepareOfflineFolder { binding, response } => {
                            let result = if binding.generation == 0
                                || worker_generation.load(Ordering::Acquire) != binding.generation
                                || active_binding.as_ref() != Some(&binding) || connection.is_none()
                                || backend.as_ref().is_none_or(|backend| backend.is_revoked())
                            {
                                Err("The Windows drive changed; refresh the folder list".to_owned())
                            } else {
                                worker_jobs.prepare_folder(binding, &worker_generation)
                            };
                            let _ = response.send(result);
                        }
                        ProviderCommand::StartOfflineFolder { binding, request, response } => {
                            let result = if binding.generation == 0
                                || worker_generation.load(Ordering::Acquire) != binding.generation
                                || active_binding.as_ref() != Some(&binding) || connection.is_none()
                            {
                                Err("The Windows drive changed; refresh the folder list".to_owned())
                            } else {
                                backend.as_ref().filter(|b| !b.is_revoked())
                                    .ok_or_else(|| "The Windows drive is disconnected".to_owned())
                                    .and_then(|backend| {
                                        let backend = Arc::clone(backend);
                                        let job_binding = binding.clone();
                                        let job_id = request.job_id().to_owned();
                                        worker_jobs.start_folder_with_id(binding, &worker_generation, &job_id, move |cancellation, progress| {
                                            let root = pin_registered_configured_root(&job_binding.path, job_binding.identity)
                                                .map_err(|_| raiun_cloudfiles_windows::BackendError::Unavailable)?;
                                            if root.identity() != job_binding.identity {
                                                return Err(raiun_cloudfiles_windows::BackendError::Unavailable.into());
                                            }
                                            request.run(&backend, cancellation, progress)
                                        })
                                    })
                            };
                            let _ = response.send(result);
                        }
                        ProviderCommand::ListOfflineFiles { binding, cursor, cancellation, response } => {
                            let mut result = windows_cache_status::inspect_worker_file_page(
                                worker_generation.load(Ordering::Acquire), &binding,
                                active_binding.as_ref(), connection.is_some(), backend.as_deref(), cursor.as_deref(), &cancellation);
                            if worker_generation.load(Ordering::Acquire) != binding.generation {
                                result = Err("The account changed during file inspection".to_owned());
                            }
                            let _ = response.send(result);
                        }
                        ProviderCommand::StartOfflineFile { binding, row, response } => {
                            let result = windows_cache_status::inspect_worker_cache_status(
                                worker_generation.load(Ordering::Acquire), &binding,
                                active_binding.as_ref(), connection.is_some(), backend.as_deref(), &row)
                                .and_then(|_| {
                                    let backend = Arc::clone(backend.as_ref().ok_or("The Windows drive is disconnected")?);
                                    let job_binding = binding.clone();
                                    worker_jobs.start(binding, &worker_generation, move |cancellation| {
                                        let root = pin_registered_configured_root(&job_binding.path, job_binding.identity)
                                            .map_err(|_| raiun_cloudfiles_windows::BackendError::Unavailable)?;
                                        if root.identity() != job_binding.identity {
                                            return Err(raiun_cloudfiles_windows::BackendError::Unavailable.into());
                                        }
                                        backend.download_file_offline_for_binding(&row.expectation(), cancellation).map(|_| ())
                                    })
                                });
                            let _ = response.send(result);
                        }
                        ProviderCommand::SetDeviceCacheQuota { binding, quota_bytes, response } => {
                            let result = windows_cache_status::inspect_worker_device_cache_usage(
                                worker_generation.load(Ordering::Acquire), &binding,
                                active_binding.as_ref(), connection.is_some(), backend.as_deref())
                                .and_then(|_| {
                                    backend.as_ref().ok_or("The Windows drive is disconnected")?
                                        .set_device_cache_quota(quota_bytes)
                                        .map_err(|_| "Could not save the device cache limit")?;
                                    Ok(json!({"scope":"device_all_accounts","saved":true,
                                        "eviction_performed":false,"quota_bytes":quota_bytes}))
                                });
                            let _ = response.send(result);
                        }
                        ProviderCommand::DeviceCacheUsage { binding, response } => {
                            let mut result = windows_cache_status::inspect_worker_device_cache_usage(
                                worker_generation.load(Ordering::Acquire), &binding,
                                active_binding.as_ref(), connection.is_some(), backend.as_deref());
                            if worker_generation.load(Ordering::Acquire) != binding.generation {
                                result = Err("The account changed during cache inspection".into());
                            }
                            let _ = response.send(result);
                        }
                        ProviderCommand::FileCacheStatus { binding, row, response } => {
                            let mut result = windows_cache_status::inspect_worker_cache_status(
                                worker_generation.load(Ordering::Acquire), &binding,
                                active_binding.as_ref(), connection.is_some(), backend.as_deref(), &row);
                            if worker_generation.load(Ordering::Acquire) != binding.generation {
                                result = Err("The account changed during Windows drive inspection".into());
                            }
                            let _ = response.send(result);
                        }
                        ProviderCommand::RefreshVaultParent { binding, space_id, root_resource_id, root_path, response } => {
                            let mut result = (|| {
                                if !vault_worker_binding_current(worker_generation.load(Ordering::Acquire), &binding, active_binding.as_ref())
                                    || !retired_vaults.is_empty() || vault_custody.is_none()
                                    || !connection.as_ref().is_some_and(|connection| connection.can_admit_vault_session())
                                    || backend.as_ref().is_none_or(|backend| backend.is_revoked()) {
                                    return Err("The Windows drive changed before vault enumeration".to_owned());
                                }
                                let backend = backend.as_ref().ok_or("The Windows drive is unavailable")?;
                                let connection = connection.as_ref().ok_or("The Windows drive is unavailable")?;
                                backend.refresh_vault_parent_population(connection, binding.identity, &space_id, &root_resource_id, &root_path)
                                    .map_err(|_| "Could not refresh the verified vault parent".to_owned())
                            })();
                            if worker_generation.load(Ordering::Acquire) != binding.generation {
                                result = Err("The account changed during vault enumeration".into());
                            }
                            let _ = response.send(result);
                        }
                        ProviderCommand::BeginLockVaultRoute { binding, space_id, root_resource_id, root_path, response } => {
                            let result = (|| {
                                if !vault_worker_binding_current(worker_generation.load(Ordering::Acquire), &binding, active_binding.as_ref()) || connection.is_none() {
                                    return Err("The Windows drive changed before vault cleanup".to_owned());
                                }
                                // Reserve finite hold capacity and reject duplicate scope BEFORE native work.
                                if !cleanup_holds.has_capacity() || cleanup_holds.any(|hold| hold.binding == binding
                                    && hold.route.space_id() == space_id && hold.route.root_resource_id() == root_resource_id
                                    && hold.route.root_path() == root_path) {
                                    return Err("Vault cleanup is already pending or capacity is unavailable".to_owned());
                                }
                                let expected_backend = backend.as_ref().ok_or("The Windows drive is unavailable")?;
                                let index = match retired_vaults.iter().position(|route| route.space_id() == space_id
                                    && route.root_resource_id() == root_resource_id && route.root_path() == root_path) {
                                    Some(index) => index,
                                    None => {
                                        let route = expected_backend.retire_vault_route(&space_id, &root_resource_id, &root_path)
                                            .map_err(|_| "Could not retain this vault for cleanup")?
                                            .ok_or("This vault has no active route")?;
                                        retired_vaults.push(route);
                                        retired_vaults.len() - 1
                                    }
                                };
                                let route = Arc::clone(&retired_vaults[index]);
                                route.revoke_hydration().map_err(|_| "Vault hydration could not fully drain")?;
                                let fence = connection.as_ref().ok_or("The Windows drive is unavailable")?
                                    .begin_cleanup_retired_vault_route(&route).map_err(|error| {
                                        last_vault_cleanup_error = Some(error);
                                        "Vault reads stopped, but local cleanup is incomplete; edits and retry state were preserved"
                                    })?;
                                if !vault_worker_binding_current(worker_generation.load(Ordering::Acquire), &binding, active_binding.as_ref()) {
                                    return Err("The account changed during vault cleanup".to_owned());
                                }
                                cleanup_holds.insert(PendingNativeVaultCleanup { binding, expected_backend: Arc::clone(expected_backend), route, fence }, Instant::now())
                                    .map_err(|_hold| "Vault cleanup hold capacity is unavailable".to_owned())
                            })();
                            // Failed response drops the only ticket weak ref. Release native
                            // references immediately, retaining the retired route as incomplete.
                            if let Err(failed) = response.send(result) {
                                if let Ok(ticket) = failed.0 { cleanup_holds.abort(ticket); }
                            }
                        }
                        ProviderCommand::FinishLockVaultRoute { binding, ticket, response } => {
                            let result = (|| {
                                let hold = cleanup_holds.take(ticket, Instant::now()).ok_or("Vault cleanup hold expired or was abandoned")?;
                                if hold.binding != binding
                                    || !vault_worker_binding_current(worker_generation.load(Ordering::Acquire), &binding, active_binding.as_ref())
                                    || backend.as_ref().is_none_or(|current| !Arc::ptr_eq(current, &hold.expected_backend))
                                    || !retired_vaults.iter().any(|route| Arc::ptr_eq(route, &hold.route)) {
                                    return Err("The Windows drive changed before vault cleanup finished".to_owned());
                                }
                                connection.as_ref().ok_or("The Windows drive is unavailable")?
                                    .finish_vault_cleanup(hold.fence).map_err(|error| {
                                        last_vault_cleanup_error = Some(error);
                                        "Vault keys are locked, but local cleanup is incomplete"
                                    })?;
                                if !vault_worker_binding_current(worker_generation.load(Ordering::Acquire), &binding, active_binding.as_ref()) {
                                    return Err("The account changed during vault cleanup".to_owned());
                                }
                                retired_vaults.retain(|route| !Arc::ptr_eq(route, &hold.route));
                                Ok(())
                            })();
                            let _ = response.send(result);
                        }
                        ProviderCommand::AbortLockVaultRoute { binding, ticket, response } => {
                            // Ticket consumption releases holds even on a stale caller binding;
                            // abort never removes a retired route or reports cleanup complete.
                            let current = vault_worker_binding_current(worker_generation.load(Ordering::Acquire), &binding, active_binding.as_ref());
                            let aborted = cleanup_holds.abort(ticket);
                            let _ = response.send(if current && aborted { Ok(()) } else { Err("Vault cleanup hold is no longer current".to_owned()) });
                        }
                        ProviderCommand::InspectVaultBackend { binding, response } => {
                            let result = if binding.generation == 0
                                || worker_generation.load(Ordering::Acquire) != binding.generation {
                                Err("The account changed before Windows drive inspection".to_owned())
                            } else if connection.is_none() || !retired_vaults.is_empty() {
                                Err("The Windows drive is not connected".to_owned())
                            } else if !connection.as_ref().is_some_and(|connection| connection.can_admit_vault_session()) {
                                Err("The retained drive needs verified vault cleanup before unlock".to_owned())
                            } else if active_binding.as_ref() == Some(&binding) {
                                backend.as_ref().filter(|backend| !backend.is_revoked())
                                    .cloned().ok_or_else(|| "The Windows drive is waiting for confirmed disconnect".to_owned())
                                    .and_then(|backend| {
                                        let custody = vault_custody.as_ref().cloned()
                                            .ok_or("The retained drive has no verified vault history".to_owned())?;
                                        Ok(VerifiedVaultBackend { backend, custody })
                                    })
                            } else {
                                Err("A different Windows drive connection is already active".to_owned())
                            };
                            let _ = response.send(result);
                        }
                        ProviderCommand::ListProtectedVaultCaptures {
                            binding,
                            scope,
                            after_capture_id,
                            limit,
                            response,
                        } => {
                            // Read-only history discovery is tied to the current
                            // root owner. Retired vault cleanup state is not a
                            // gate here: it grants no authority and does not
                            // prevent local protected-history inspection.
                            let result = (|| {
                                if !vault_worker_binding_current(
                                    worker_generation.load(Ordering::Acquire),
                                    &binding,
                                    active_binding.as_ref(),
                                ) || connection.is_none()
                                {
                                    return Err("The account or Windows drive changed".to_owned());
                                }
                                let custody = vault_custody
                                    .as_ref()
                                    .ok_or("Protected vault history is unavailable")?;
                                let owner = backend
                                    .as_ref()
                                    .filter(|backend| !backend.is_revoked())
                                    .ok_or("The connected account root is unavailable")?
                                    .scope();
                                let page = windows_vault_capture_recovery::page_from_custody(
                                    custody,
                                    owner,
                                    &scope,
                                    after_capture_id.as_deref(),
                                    limit,
                                )?;
                                if !vault_worker_binding_current(
                                    worker_generation.load(Ordering::Acquire),
                                    &binding,
                                    active_binding.as_ref(),
                                ) {
                                    return Err("The account or Windows drive changed".to_owned());
                                }
                                Ok(page)
                            })();
                            let _ = response.send(result);
                        }
                        ProviderCommand::SaveProtectedVaultCaptureCopy {
                            binding,
                            scope,
                            capture_id,
                            destination,
                            response,
                        } => {
                            let result = (|| {
                                if !vault_worker_binding_current(
                                    worker_generation.load(Ordering::Acquire),
                                    &binding,
                                    active_binding.as_ref(),
                                ) || connection.is_none()
                                {
                                    return Err("The account or Windows drive changed".to_owned());
                                }
                                let custody = vault_custody
                                    .as_ref()
                                    .ok_or("Protected vault history is unavailable")?;
                                let owner = backend
                                    .as_ref()
                                    .filter(|backend| !backend.is_revoked())
                                    .ok_or("The connected account root is unavailable")?
                                    .scope();
                                let receipt = windows_vault_capture_recovery::save_copy(
                                    custody,
                                    owner,
                                    &scope,
                                    &capture_id,
                                    windows_vault_capture_recovery::SaveCopyDestination {
                                        root_path: &binding.path,
                                        root_identity: binding.identity,
                                        destination: &destination,
                                    },
                                    || {
                                        vault_worker_binding_current(
                                            worker_generation.load(Ordering::Acquire),
                                            &binding,
                                            active_binding.as_ref(),
                                        ) && connection.is_some()
                                    },
                                )?;
                                if !vault_worker_binding_current(
                                    worker_generation.load(Ordering::Acquire),
                                    &binding,
                                    active_binding.as_ref(),
                                ) {
                                    return Err("The account changed; inspect the chosen destination".to_owned());
                                }
                                Ok(receipt)
                            })();
                            let _ = response.send(result);
                        }
                        ProviderCommand::CompleteVaultUpload { writable_bytes, binding, expected_backend, upload, mut store, response } => {
                            // The HTTP caller hands over an owned fresh capability. Only
                            // this native owner thread may complete the already-live file.
                            // Storage callbacks perform local protected CAS only; never
                            // account/coordinator lookup or HTTP under publication fences.
                            let result = (|| {
                                if !vault_worker_binding_current(worker_generation.load(Ordering::Acquire), &binding, active_binding.as_ref())
                                    || !retired_vaults.is_empty()
                                    || backend.as_ref().is_none_or(|current| !Arc::ptr_eq(current, &expected_backend) || current.is_revoked())
                                    || upload.root() != binding.identity
                                {
                                    return Err("The Windows drive changed before local save completion".to_owned());
                                }
                                let active = connection.as_ref().ok_or("The Windows drive is not connected")?;
                                let completed = if writable_bytes {
                                    active.complete_writable_vault_upload(upload, store.as_mut())
                                } else {
                                    active.complete_vault_upload(upload, store.as_mut())
                                };
                                completed.map_err(|error| {
                                        #[cfg(all(test, debug_assertions))]
                                        eprintln!("synthetic_vault_local_completion_refused error={error:?}");
                                        #[cfg(not(all(test, debug_assertions)))]
                                        let _ = error;
                                        "The cloud save is verified, but local completion needs recovery review".to_owned()
                                    })?;
                                if !vault_worker_binding_current(worker_generation.load(Ordering::Acquire), &binding, active_binding.as_ref()) {
                                    return Err("The account changed during local save completion".to_owned());
                                }
                                Ok(())
                            })();
                            let _ = response.send(result);
                        }
                        ProviderCommand::VaultCleanupDiagnostics { binding, response } => {
                            let result = if !vault_worker_binding_current(worker_generation.load(Ordering::Acquire), &binding, active_binding.as_ref()) {
                                Err("The Windows drive changed before support inspection".to_owned())
                            } else if let Some(active) = connection.as_ref() {
                                let observation = active.vault_cleanup_diagnostics();
                                Ok(json!({
                                    "modified_closes": observation.modified_closes,
                                    "unverifiable_closes": observation.unverifiable_closes,
                                    "journaled_closes": observation.journaled_closes,
                                    "close_callbacks": observation.close_callbacks,
                                    "close_pool_refusals": observation.close_pool_refusals,
                                    "deleted_closes": observation.deleted_closes,
                                    "last_close_stage": observation.last_close_stage,
                                    "last_close_hresult": observation.last_close_hresult,
                                    "inventory_complete": observation.inventory_complete,
                                    "last_cleanup_error": last_vault_cleanup_error.map(|error| format!("{error:?}")),
                                }))
                            } else { Err("The Windows drive is not connected".to_owned()) };
                            let result = if worker_generation.load(Ordering::Acquire) == binding.generation { result }
                                else { Err("The Windows drive changed during support inspection".to_owned()) };
                            let _ = response.send(result);
                        }
                        ProviderCommand::VaultLockCleanupStatus { binding, space_id, root_resource_id, root_path, response } => {
                            let result = if !vault_worker_binding_current(worker_generation.load(Ordering::Acquire), &binding, active_binding.as_ref()) || connection.is_none() {
                                Err("The Windows drive changed before cleanup inspection".to_owned())
                            } else {
                                // Absence is unknown, never proof of complete cleanup.
                                connection.as_ref().ok_or_else(|| "The Windows drive is unavailable".to_owned()).and_then(|active| {
                                    let footprint = active.writable_vault_cleanup_incomplete().map_err(|_| "Current vault cleanup status is unavailable".to_owned())?;
                                    Ok(footprint || retired_vaults.iter().any(|route| route.space_id() == space_id && route.root_resource_id() == root_resource_id && route.root_path() == root_path))
                                })
                            };
                            let result = if worker_generation.load(Ordering::Acquire) == binding.generation { result }
                                else { Err("The Windows drive changed during cleanup inspection".to_owned()) };
                            let _ = response.send(result);
                        }
                        ProviderCommand::InspectConnection { binding, response } => {
                            let result = if worker_generation.load(Ordering::Acquire) != binding.generation {
                                Err("The account changed before Windows drive inspection".to_owned())
                            } else if connection.is_none() {
                                Ok(false)
                            } else if active_binding.as_ref() == Some(&binding) {
                                if backend.as_ref().is_some_and(|backend| !backend.is_revoked()) {
                                    Ok(true)
                                } else {
                                    Err("The Windows drive is waiting for confirmed disconnect".to_owned())
                                }
                            } else {
                                Err("A different Windows drive connection is already active".to_owned())
                            };
                            let _ = response.send(result);
                        }
                        ProviderCommand::Connect {
                            path,
                            generation,
                            expected_identity,
                            already_registered,
                            personal_space_id,
                            personal_root_resource_id,
                            backend: next_backend,
                            recovery,
                            custody_account,
                            custody_store,
                            fresh_close_publisher,
                            response,
                        } => {
                            let candidate_binding = ActiveProviderBinding {
                                generation,
                                path: path.clone(),
                                identity: expected_identity,
                                personal_space_id: personal_space_id.clone(),
                                personal_root_resource_id: personal_root_resource_id.clone(),
                            };
                            let candidate_backend = Arc::clone(&next_backend);
                            let result = if worker_generation.load(Ordering::Acquire) != generation {
                                Err("The account changed before the Windows drive could connect".to_owned())
                            } else if connection.is_some() {
                                Err("A Windows drive connection is already active".to_owned())
                            } else {
                                let lease = if already_registered {
                                    raiun_cloudfiles_windows::pin_registered_configured_root(
                                        &path,
                                        expected_identity,
                                    )
                                } else {
                                    raiun_cloudfiles_windows::pin_configured_root(&path)
                                }
                                .map_err(|_| "Could not verify the exact configured Windows drive folder".to_owned())
                                .and_then(|lease| {
                                    if lease.identity() != expected_identity {
                                        return Err("The configured Windows drive folder identity changed".into());
                                    }
                                    let composite_root_identity = next_backend
                                        .register_composite_root_for(
                                            &personal_space_id,
                                            &personal_root_resource_id,
                                        )
                                        .map_err(|_| "The verified Personal/Spaces namespace changed before connection".to_owned())?;
                                    // Missing/corrupt historical metadata must never be initialized
                                    // as empty. Ordinary drive connectivity remains independent;
                                    // vault unlock requires a successfully prepared service below.
                                    let custody = raiun_cloudfiles_windows::prepare_vault_custody_root(
                                        &lease, next_backend.as_ref(), composite_root_identity,
                                    ).ok().and_then(|context| {
                                        match fresh_close_publisher {
                                            Some(publisher) => windows_vault_custody::WindowsVaultCustody::prepare_with_fresh_close_publisher(
                                                custody_store, &custody_account, &context, Some(publisher),
                                            ),
                                            None => windows_vault_custody::WindowsVaultCustody::prepare(
                                                custody_store, &custody_account, &context,
                                            ),
                                        }.ok()
                                    });
                                    let prepared = raiun_cloudfiles_windows::prepare_configured_root_runtime(
                                        lease,
                                        Arc::clone(&next_backend),
                                        composite_root_identity,
                                        recovery,
                                    )
                                    .map_err(|_| "Durable recovery checks failed; the Windows drive was not connected".to_owned())?;
                                    let prepared = if let Some(history) = custody.as_ref() {
                                        raiun_cloudfiles_windows::attach_vault_published_history(
                                            prepared, Arc::clone(history) as Arc<dyn raiun_cloudfiles_windows::vault_custody::VaultPublishedHistorySource>,
                                        ).map_err(|_| "Could not bind protected vault history".to_owned())?
                                    } else { prepared };
                                    raiun_cloudfiles_windows::connect_configured_root(prepared)
                                        .map(|active| (active, custody))
                                        .map_err(|_| "Could not connect the Windows Cloud Files drive".to_owned())
                                });
                                match lease {
                                    Ok((active, custody))
                                        if worker_generation.load(Ordering::Acquire) == generation =>
                                    {
                                        last_vault_cleanup_error = None;
                                        active_binding = Some(candidate_binding.clone());
                                        vault_custody = custody;
                                        connection = Some(active);
                                        backend = Some(next_backend);
                                        worker_connected.store(true, Ordering::Release);
                                        Ok(())
                                    }
                                    Ok((mut active, _custody)) => {
                                        next_backend.revoke();
                                        if active.disconnect_in_place().is_err() {
                                            connection = Some(active);
                                            backend = Some(next_backend);
                                            worker_connected.store(true, Ordering::Release);
                                            Err("The account changed during connect and Windows has not confirmed disconnect".into())
                                        } else {
                                            Err("The account changed while the Windows drive was connecting".into())
                                        }
                                    }
                                    Err(error) => {
                                        next_backend.revoke();
                                        Err(error)
                                    }
                                }
                            };
                            if result.is_err() {
                                candidate_backend.revoke();
                            }
                            let _ = response.send(result);
                        }
                        ProviderCommand::DispatchRecovery {
                            agent_generation,
                            recovery,
                            record_id,
                            record_generation,
                            remote,
                            response,
                        } => {
                            let result = if worker_generation.load(Ordering::Acquire)
                                != agent_generation
                            {
                                Err("The account changed before recovery could start".to_owned())
                            } else {
                                recovery
                                    .dispatch_recovered_edit(
                                        &record_id,
                                        record_generation,
                                        remote.as_ref(),
                                        raiun_cloudfiles_windows::ExplicitRecoveryApproval::user_reviewed(),
                                    )
                                    .map_err(|_error| {
                                        #[cfg(test)]
                                        eprintln!("windows_recovery_dispatch_error={_error:?}");
                                        "Could not safely complete the selected recovery attempt".to_owned()
                                    })
                            };
                            let _ = response.send(result);
                        }
                        #[cfg(all(test, debug_assertions))]
                        ProviderCommand::RevokeBackendForTest(response) => {
                            cleanup_holds.clear();
                            let result = backend.as_ref().map(|backend| backend.revoke())
                                .ok_or_else(|| "No active backend to revoke".to_owned());
                            let _ = response.send(result);
                        }
                        #[cfg(test)]
                        ProviderCommand::DirectoryObservation(response) => {
                            let result = connection
                                .as_ref()
                                .map(|active| {
                                    let path = [
                                        "Spaces",
                                        "Projects",
                                        "RecoveryRoot",
                                        "document.bin",
                                    ];
                                    let before = active
                                        .placeholder_observation(&path)
                                        .map_err(|_| "placeholder state unavailable".to_owned());
                                    let explicit = active
                                        .hydrate_test_placeholder(&path)
                                        .map_err(|_| "explicit hydration failed".to_owned());
                                    (
                                        active.directory_observation(),
                                        active.fetch_observation(),
                                        before,
                                        explicit,
                                        active
                                            .placeholder_observation(&path)
                                            .map_err(|_| "post-hydration state unavailable".to_owned()),
                                    )
                                })
                                .ok_or_else(|| "Windows Cloud Files connection is not active".to_owned());
                            let _ = response.send(result);
                        }
                        #[cfg(test)]
                        ProviderCommand::VaultFilePendingForTest { identity, response } => {
                            let result = connection.as_ref().ok_or_else(|| "Windows Cloud Files connection is not active".to_owned())
                                .and_then(|active| active.vault_file_pending_for_test(&identity)
                                    .map_err(|_| "Vault file pending state is unavailable".to_owned()));
                            let _ = response.send(result);
                        }
                        #[cfg(test)]
                        ProviderCommand::ReadOnlyPlaceholderObservation { path, response } => {
                            let result = connection
                                .as_ref()
                                .ok_or_else(|| "Windows Cloud Files connection is not active".to_owned())
                                .map(|active| {
                                    let components = match path {
                                        NativeRestartProbePath::PersonalNativeRead => {
                                            &["Personal", "native-read.bin"][..]
                                        }
                                        NativeRestartProbePath::ProjectsNativeRead => {
                                            &["Spaces", "Projects", "native-read.bin"][..]
                                        }
                                        NativeRestartProbePath::RecoveryDocument => {
                                            &["Spaces", "Projects", "RecoveryRoot", "document.bin"][..]
                                        }
                                        NativeRestartProbePath::RecoveryReadOnlyProbe => {
                                            &["Spaces", "Projects", "RecoveryRoot", "read-probe.bin"][..]
                                        }
                                        NativeRestartProbePath::VaultCapturedFile => {
                                            &["Personal", "Travel.vault", "1"][..]
                                        }
                                    };
                                    (
                                        active.directory_observation(),
                                        active.fetch_observation(),
                                        active
                                            .placeholder_observation(components)
                                            .map_err(|_| "placeholder state unavailable".to_owned()),
                                    )
                                });
                            let _ = response.send(result);
                        }
                        #[cfg(test)]
                        ProviderCommand::HydrateNativeReadFixtureForTest { fixture, response } => {
                            let result = connection
                                .as_ref()
                                .ok_or_else(|| "Windows Cloud Files connection is not active".to_owned())
                                .and_then(|active| {
                                    let path: &[&str] = match fixture {
                                        NativeReadFixturePath::Personal => {
                                            &["Personal", "native-read.bin"]
                                        }
                                        NativeReadFixturePath::ProjectsSpace => {
                                            &["Spaces", "Projects", "native-read.bin"]
                                        }
                                    };
                                    active
                                        .hydrate_test_placeholder(path)
                                        .map_err(|_| "native read fixture hydration failed".to_owned())
                                });
                            let _ = response.send(result);
                        }
                        #[cfg(test)]
                        ProviderCommand::VaultCleanupFixture { binding, forget_receipt, response } => {
                            let result = (|| {
                                if !vault_worker_binding_current(worker_generation.load(Ordering::Acquire), &binding, active_binding.as_ref()) {
                                    return Err("The Windows drive changed before the synthetic cleanup observation".to_owned());
                                }
                                let active = connection.as_ref().ok_or("The Windows drive is not connected")?;
                                if let Some(identity) = forget_receipt {
                                    active.forget_writable_cleanup_receipt_for_integration(identity)
                                        .map_err(|_| "Could not drop the matching volatile synthetic receipt".to_owned())?;
                                    Ok(false)
                                } else {
                                    active.placeholder_on_disk_empty_for_integration(&["Personal", "Travel.vault", "1"])
                                        .map_err(|_| "Could not inspect synthetic native on-disk ranges".to_owned())
                                }
                            })();
                            let _ = response.send(result);
                        }
                        #[cfg(test)]
                        ProviderCommand::CloseObservation(response) => {
                            let result = connection
                                .as_ref()
                                .map(|active| active.close_observation_for_integration())
                                .ok_or_else(|| "Windows Cloud Files connection is not active".to_owned());
                            let _ = response.send(result);
                        }
                        ProviderCommand::Disconnect(response) => {
                            cleanup_holds.clear();
                            if let Ok(mut handle) = worker_folder_revocation.lock() { if let Some(handle) = handle.take() { handle.revoke(); } }
                            drop(folders.take());
                            worker_folder_generation.store(0, Ordering::Release);
                            if let Ok(mut snapshot) = worker_folder_pause.lock() { *snapshot = None; }
                            if let Ok(mut error) = worker_folder_error.lock() { *error = None; }
                            worker_jobs.cancel_all();
                            let result = disconnect_provider_connection(
                                &mut retired_vaults,
                                &mut connection,
                                &mut backend,
                                &worker_connected,
                            );
                            if connection.is_none() {
                                active_binding = None;
                                vault_custody = None;
                            }
                            let _ = response.send(result);
                        }
                        ProviderCommand::Stop(response) => {
                            cleanup_holds.clear();
                            if let Ok(mut handle) = worker_folder_revocation.lock() { if let Some(handle) = handle.take() { handle.revoke(); } }
                            drop(folders.take());
                            worker_folder_generation.store(0, Ordering::Release);
                            if let Ok(mut snapshot) = worker_folder_pause.lock() { *snapshot = None; }
                            if let Ok(mut error) = worker_folder_error.lock() { *error = None; }
                            worker_jobs.cancel_all();
                            let result = disconnect_provider_connection(
                                &mut retired_vaults,
                                &mut connection,
                                &mut backend,
                                &worker_connected,
                            );
                            let stopped = result.is_ok();
                            let _ = response.send(result);
                            if stopped { break; }
                        }
                    }
                    }
                    let mut dispatched_initial = false;
                    if worker_initial_save_activation.load(Ordering::Acquire) {
                        // Fresh initial-save work retains priority; never scan recovery here.
                        let result = dispatch_one_initial_edit(
                            connection.as_ref(), backend.as_ref(), active_binding.as_ref(),
                            &worker_generation);
                        dispatched_initial = !matches!(&result, Ok(None));
                        #[cfg(all(test, debug_assertions))]
                        if dispatched_initial {
                            if let Ok(mut observation) = worker_initial_save_test_observation.lock() {
                                *observation = Some(match &result {
                                    Err(message) => format!("error: {message}"),
                                    Ok(Some(raiun_cloudfiles_windows::ReconciliationOutcome::VerifiedApplied { .. })) => "verified_applied".into(),
                                    Ok(Some(raiun_cloudfiles_windows::ReconciliationOutcome::Conflict(_))) => "conflict".into(),
                                    Ok(Some(raiun_cloudfiles_windows::ReconciliationOutcome::Ambiguous)) => "ambiguous".into(),
                                    Ok(Some(raiun_cloudfiles_windows::ReconciliationOutcome::Deferred)) => "deferred".into(),
                                    Ok(None) => unreachable!("empty dispatch is not observed"),
                                });
                            }
                        }
                    }
                    if !handled_command && !dispatched_initial {
                        // Pick up commands arriving during initial-save inspection first.
                        match receiver.try_recv() {
                            Ok(command) => { pending_command = Some(command); continue; }
                            Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
                            Err(std::sync::mpsc::TryRecvError::Empty) => {}
                        }
                        if let Some(runtime) = folders.as_mut() {
                            // A read-only metadata request may install this worker.
                            // Disabled features must also suppress background work.
                            let ordinary = if WINDOWS_FOLDER_SYNC_ENABLED {
                                runtime.periodic_tick(&worker_generation)
                            } else {
                                None
                            };
                            if let Some(result) = ordinary {
                                if let Ok(mut error) = worker_folder_error.lock() { *error = result.err(); }
                            } else if WINDOWS_MEDIA_METADATA_ENABLED {
                                if let Some(result) = runtime.periodic_media_tick(&worker_generation) {
                                    if let Ok(mut error) = worker_folder_error.lock() { *error = result.err(); }
                                }
                            }
                        }
                    }
                }
                cleanup_holds.clear();
                worker_jobs.cancel_all();
                if disconnect_provider_connection(
                    &mut retired_vaults,
                    &mut connection,
                    &mut backend,
                    &worker_connected,
                ).is_err() {
                    // The command owner is gone, so no retry can be serviced.
                    // Preserve native callback/root ownership until process exit
                    // rather than dropping it after failed cleanup. Bindings
                    // have been revoked; this never reports a successful lock.
                    if let Some(active) = connection.take() { std::mem::forget(active); }
                    if let Some(active) = backend.take() { std::mem::forget(active); }
                    std::mem::forget(retired_vaults);
                }
            })
            .expect("start Windows Cloud Files ownership thread");
        Self {
            proxy: windows_proxy::Service::default(),
            bandwidth: windows_bandwidth::Service::default(),
            commands,
            connected,
            authorized_generation,
            folder_generation,
            folder_revocation,
            folder_error,
            folder_pause,
            offline_jobs,
            recovery_cursor_nonce: {
                let mut nonce = [0; 32];
                getrandom::fill(&mut nonce).ok().map(|_| nonce)
            },
            worker: Mutex::new(Some(worker)),
            fresh_close_source: Mutex::new(None),
            existing_save_owner: Mutex::new(Weak::new()),
            existing_save_admission: AtomicBool::new(false),
            #[cfg(all(test, debug_assertions))]
            lifecycle_test_activation: AtomicBool::new(false),
            #[cfg(all(test, debug_assertions))]
            initial_save_test_activation: initial_save_activation,
            #[cfg(all(test, debug_assertions))]
            initial_save_test_observation,
            #[cfg(all(test, debug_assertions))]
            disconnect_test_calls: AtomicU64::new(0),
        }
    }

    #[allow(dead_code)]
    #[allow(clippy::too_many_arguments)]
    fn connect(
        &self,
        path: PathBuf,
        generation: u64,
        expected_identity: raiun_cloudfiles_windows::ConfiguredRootIdentity,
        already_registered: bool,
        personal_space_id: String,
        personal_root_resource_id: String,
        backend: Arc<raiun_cloudfiles_windows::OpenCloudPlaceholderBackend>,
        recovery: Arc<dyn raiun_cloudfiles_windows::EditRecoveryProvider>,
        custody_account: Vec<u8>,
        custody_store: Arc<dyn SessionStore>,
    ) -> Result<(), String> {
        let fresh_close_publisher = self
            .fresh_close_source
            .lock()
            .map_err(|_| "Fresh vault close publication is unavailable")?
            .as_ref()
            .and_then(|source| source.publisher(generation));
        let (response, result) = std::sync::mpsc::sync_channel(1);
        self.commands
            .send(ProviderCommand::Connect {
                path,
                generation,
                expected_identity,
                already_registered,
                personal_space_id,
                personal_root_resource_id,
                backend,
                recovery,
                custody_account,
                custody_store,
                fresh_close_publisher,
                response,
            })
            .map_err(|_| "Windows Cloud Files connection manager is unavailable")?;
        result
            .recv()
            .map_err(|_| "Windows Cloud Files connection manager stopped unexpectedly")?
    }

    fn refresh_vault_parent(
        &self,
        binding: ActiveProviderBinding,
        space_id: String,
        root_resource_id: String,
        root_path: String,
    ) -> Result<(), String> {
        let (response, result) = std::sync::mpsc::sync_channel(1);
        self.commands
            .send(ProviderCommand::RefreshVaultParent {
                binding,
                space_id,
                root_resource_id,
                root_path,
                response,
            })
            .map_err(|_| "Windows Cloud Files connection manager is unavailable")?;
        result
            .recv()
            .map_err(|_| "Windows Cloud Files connection manager stopped")?
    }

    fn begin_lock_vault_route(
        &self,
        binding: ActiveProviderBinding,
        space_id: String,
        root_resource_id: String,
        root_path: String,
    ) -> Result<PendingVaultCleanupTicket, String> {
        let (response, result) = std::sync::mpsc::sync_channel(1);
        self.commands
            .send(ProviderCommand::BeginLockVaultRoute {
                binding,
                space_id,
                root_resource_id,
                root_path,
                response,
            })
            .map_err(|_| "Windows Cloud Files connection manager is unavailable")?;
        result
            .recv()
            .map_err(|_| "Windows Cloud Files connection manager stopped")?
    }

    fn finish_lock_vault_route(
        &self,
        binding: ActiveProviderBinding,
        ticket: PendingVaultCleanupTicket,
    ) -> Result<(), String> {
        let (response, result) = std::sync::mpsc::sync_channel(1);
        self.commands
            .send(ProviderCommand::FinishLockVaultRoute {
                binding,
                ticket,
                response,
            })
            .map_err(|_| "Windows Cloud Files connection manager is unavailable")?;
        result
            .recv()
            .map_err(|_| "Windows Cloud Files connection manager stopped")?
    }

    fn abort_lock_vault_route(
        &self,
        binding: ActiveProviderBinding,
        ticket: PendingVaultCleanupTicket,
    ) -> Result<(), String> {
        let (response, result) = std::sync::mpsc::sync_channel(1);
        self.commands
            .send(ProviderCommand::AbortLockVaultRoute {
                binding,
                ticket,
                response,
            })
            .map_err(|_| "Windows Cloud Files connection manager is unavailable")?;
        result
            .recv()
            .map_err(|_| "Windows Cloud Files connection manager stopped")?
    }

    #[cfg(test)]
    fn vault_cleanup_fixture(
        &self,
        binding: ActiveProviderBinding,
        forget_receipt: Option<[u8; 16]>,
    ) -> Result<bool, String> {
        let (response, result) = std::sync::mpsc::sync_channel(1);
        self.commands
            .send(ProviderCommand::VaultCleanupFixture {
                binding,
                forget_receipt,
                response,
            })
            .map_err(|_| "Windows Cloud Files connection manager is unavailable")?;
        result
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| "Synthetic cleanup observation timed out")?
    }

    fn verified_vault_backend(
        &self,
        binding: ActiveProviderBinding,
    ) -> Result<VerifiedVaultBackend, String> {
        let (response, result) = std::sync::mpsc::sync_channel(1);
        self.commands
            .send(ProviderCommand::InspectVaultBackend { binding, response })
            .map_err(|_| "Windows Cloud Files connection manager is unavailable")?;
        result
            .recv()
            .map_err(|_| "Windows Cloud Files connection manager stopped unexpectedly")?
    }

    fn list_protected_vault_captures(
        &self,
        binding: ActiveProviderBinding,
        scope: windows_vault_capture_recovery::RecoveryScope,
        after_capture_id: Option<String>,
        limit: usize,
    ) -> Result<ProtectedCapturePage, String> {
        let (response, result) = std::sync::mpsc::sync_channel(1);
        self.commands
            .send(ProviderCommand::ListProtectedVaultCaptures {
                binding,
                scope,
                after_capture_id,
                limit,
                response,
            })
            .map_err(|_| "Windows Cloud Files connection manager is unavailable")?;
        result
            .recv_timeout(Duration::from_secs(30))
            .map_err(|_| "Protected vault history did not respond within its bound".to_owned())?
    }

    fn save_protected_vault_capture_copy(
        &self,
        binding: ActiveProviderBinding,
        scope: windows_vault_capture_recovery::RecoveryScope,
        capture_id: String,
        destination: PathBuf,
    ) -> Result<windows_vault_capture_recovery::CopyReceipt, String> {
        let (response, result) = std::sync::mpsc::sync_channel(1);
        self.commands
            .send(ProviderCommand::SaveProtectedVaultCaptureCopy {
                binding,
                scope,
                capture_id,
                destination,
                response,
            })
            .map_err(|_| "Windows Cloud Files connection manager is unavailable")?;
        result.recv_timeout(Duration::from_secs(30)).map_err(|_| {
            "Save Copy did not respond within its bound; inspect the chosen destination".to_owned()
        })?
    }

    fn complete_vault_upload(
        &self,
        binding: ActiveProviderBinding,
        expected_backend: Arc<raiun_cloudfiles_windows::OpenCloudPlaceholderBackend>,
        upload: raiun_cloudfiles_windows::FreshVaultUpload,
        store: Box<dyn raiun_cloudfiles_windows::VaultLocalCompletionStore>,
    ) -> Result<(), String> {
        self.complete_vault_upload_mode(binding, expected_backend, upload, store, false)
    }

    fn complete_writable_vault_upload(
        &self,
        binding: ActiveProviderBinding,
        expected_backend: Arc<raiun_cloudfiles_windows::OpenCloudPlaceholderBackend>,
        upload: raiun_cloudfiles_windows::FreshVaultUpload,
        store: Box<dyn raiun_cloudfiles_windows::VaultLocalCompletionStore>,
    ) -> Result<(), String> {
        self.complete_vault_upload_mode(binding, expected_backend, upload, store, true)
    }

    fn complete_vault_upload_mode(
        &self,
        binding: ActiveProviderBinding,
        expected_backend: Arc<raiun_cloudfiles_windows::OpenCloudPlaceholderBackend>,
        upload: raiun_cloudfiles_windows::FreshVaultUpload,
        store: Box<dyn raiun_cloudfiles_windows::VaultLocalCompletionStore>,
        writable_bytes: bool,
    ) -> Result<(), String> {
        let (response, result) = std::sync::mpsc::sync_channel(1);
        self.commands
            .send(ProviderCommand::CompleteVaultUpload {
                writable_bytes,
                binding,
                expected_backend,
                upload,
                store,
                response,
            })
            .map_err(|_| "Windows Cloud Files connection manager is unavailable")?;
        result
            .recv()
            .map_err(|_| "Windows Cloud Files connection manager stopped during save completion")?
    }

    #[cfg(test)]
    fn vault_file_pending_for_test(&self, identity: [u8; 16]) -> Result<bool, String> {
        let (response, result) = std::sync::mpsc::sync_channel(1);
        self.commands
            .send(ProviderCommand::VaultFilePendingForTest { identity, response })
            .map_err(|_| "Windows provider manager is unavailable")?;
        result
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| "Vault pending inspection did not complete within its bound".to_owned())?
    }

    fn vault_cleanup_diagnostics(&self, binding: ActiveProviderBinding) -> Result<Value, String> {
        let (response, result) = std::sync::mpsc::sync_channel(1);
        self.commands
            .try_send(ProviderCommand::VaultCleanupDiagnostics { binding, response })
            .map_err(|_| "Windows support inspection is unavailable")?;
        result
            .recv_timeout(Duration::from_secs(2))
            .map_err(|_| "Windows support inspection was unavailable within its bound".to_owned())?
    }

    // true = exact pending cleanup; false = unknown, never complete.
    fn vault_lock_cleanup_status(
        &self,
        binding: ActiveProviderBinding,
        space_id: String,
        root_resource_id: String,
        root_path: String,
    ) -> Result<bool, String> {
        let (response, result) = std::sync::mpsc::sync_channel(1);
        self.commands
            .try_send(ProviderCommand::VaultLockCleanupStatus {
                binding,
                space_id,
                root_resource_id,
                root_path,
                response,
            })
            .map_err(|_| "Windows cleanup inspection is unavailable")?;
        result
            .recv_timeout(Duration::from_secs(2))
            .map_err(|_| "Windows cleanup inspection was unavailable within its bound".to_owned())?
    }

    fn connection_matches(&self, binding: ActiveProviderBinding) -> Result<bool, String> {
        let (response, result) = std::sync::mpsc::sync_channel(1);
        self.commands
            .send(ProviderCommand::InspectConnection { binding, response })
            .map_err(|_| "Windows Cloud Files connection manager is unavailable")?;
        result
            .recv()
            .map_err(|_| "Windows Cloud Files connection manager stopped unexpectedly")?
    }

    fn existing_vault_save_worker_marker(
        &self,
        binding: &ActiveProviderBinding,
    ) -> Result<Option<Arc<AtomicBool>>, String> {
        if !self.connection_matches(binding.clone())? {
            return Ok(None);
        }
        let marker = self
            .fresh_close_source
            .lock()
            .map_err(|_| "Existing-file save admission unavailable")?
            .as_ref()
            .and_then(|source| source.marker(binding));
        if self.authorized_generation.load(Ordering::Acquire) != binding.generation
            || !self.connection_matches(binding.clone())?
        {
            return Ok(None);
        }
        Ok(marker.filter(|active| active.load(Ordering::Acquire)))
    }

    fn prepare_existing_file_save_worker(
        self: &Arc<Self>,
        binding: &ActiveProviderBinding,
        state: &Arc<Mutex<AccountState>>,
        store: &Arc<dyn SessionStore>,
        connection_current: bool,
    ) -> Result<Option<ExistingSaveWorkerAdmission>, String> {
        let owner = self
            .existing_save_owner
            .lock()
            .map_err(|_| "Existing-file save owner unavailable")?
            .upgrade();
        let Some(owner) = owner else {
            return Ok(None);
        };
        if !Arc::ptr_eq(&owner.provider, self)
            || !Arc::ptr_eq(&owner.state, state)
            || !Arc::ptr_eq(&owner.session_store, store)
        {
            return Err("Existing-file save owner does not match this drive".into());
        }
        self.existing_save_admission
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| "Existing-file save admission is already in progress")?;
        let mut admission = ExistingSaveWorkerAdmission {
            owner: Arc::clone(&owner),
            binding: binding.clone(),
            original_active: None,
            connection_current: false,
            committed: false,
        };
        let existing = self
            .fresh_close_source
            .lock()
            .map_err(|_| "Existing-file save admission unavailable")?
            .as_ref()
            .and_then(|source| source.marker(binding));
        admission.original_active = existing.clone();
        owner.check_existing_file_save_account(binding)?;
        if connection_current && let Some(active) = existing {
            admission.original_active = Some(active);
            admission.connection_current = true;
            return Ok(Some(admission));
        }
        // Cancel first, take ownership, then join with no source/worker/auth/
        // provider mutex held. The consumer keeps its ORIGINAL active Arc.
        owner.stop_fresh_close_worker()?;
        admission.original_active = None;
        if self.connected.load(Ordering::Acquire) {
            // Any retained old native connection must drain before a fresh
            // source is installed; an exact-binding mismatch is not absence.
            self.disconnect()?;
        }
        owner.check_existing_file_save_account(binding)?;
        let worker = windows_vault_close_worker::FreshCloseWorker::start_for_existing_file_saves(
            Arc::downgrade(&owner),
            Arc::clone(&self.authorized_generation),
            binding.generation,
        )?;
        let source = worker.source();
        let active = source
            .existing_file_save_marker(binding.generation)
            .ok_or("Existing-file save worker changed during admission")?;
        owner.check_existing_file_save_account(binding)?;
        {
            let mut slot = owner
                .fresh_close_worker
                .lock()
                .map_err(|_| "Existing-file save worker unavailable")?;
            let mut publication = self
                .fresh_close_source
                .lock()
                .map_err(|_| "Existing-file save source unavailable")?;
            if slot.is_some()
                || publication.is_some()
                || self.connected.load(Ordering::Acquire)
                || self.authorized_generation.load(Ordering::Acquire) != binding.generation
                || !active.load(Ordering::Acquire)
            {
                return Err("The drive changed during existing-file save admission".into());
            }
            *publication = Some(FreshClosePublication {
                source,
                binding: Some(binding.clone()),
                original_active: Some(Arc::clone(&active)),
            });
            *slot = Some(worker);
        }
        admission.original_active = Some(active);
        Ok(Some(admission))
    }

    fn cancel_fresh_close(&self) {
        let source = self
            .fresh_close_source
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(source) = source {
            source.cancel();
        }
    }

    fn revoke_folders(&self) {
        // Serialize cancellation publication with InstallFolders. No database
        // owner or token lock crosses threads or is held through networking.
        if let Ok(mut handle) = self.folder_revocation.lock() {
            if let Some(handle) = handle.take() {
                handle.revoke();
            }
        }
        self.folder_generation.store(0, Ordering::Release);
        if let Ok(mut snapshot) = self.folder_pause.lock() {
            *snapshot = None;
        }
    }

    fn pause_snapshot(&self, generation: u64, online: bool) -> Option<FolderPauseSnapshot> {
        self.folder_pause
            .lock()
            .ok()
            .and_then(|snapshot| snapshot.clone())
            .filter(|snapshot| {
                online
                    && snapshot.generation == generation
                    && self.authorized_generation.load(Ordering::Acquire) == generation
                    && self.folder_generation.load(Ordering::Acquire) == generation
            })
    }

    fn install_folders(&self, setup: windows_folder_sync::Setup) -> Result<(), String> {
        let (response, result) = std::sync::mpsc::sync_channel(1);
        self.commands
            .send(ProviderCommand::InstallFolders {
                setup: Box::new(setup),
                response,
            })
            .map_err(|_| "Windows folder worker is unavailable")?;
        result.recv().map_err(|_| "Windows folder worker stopped")?
    }

    fn folder_request(
        &self,
        generation: u64,
        request: windows_folder_requests::FolderRequest,
    ) -> Result<Value, String> {
        let (response, result) = std::sync::mpsc::sync_channel(1);
        self.commands
            .send(ProviderCommand::FolderRequest {
                generation,
                request,
                response,
            })
            .map_err(|_| "Windows folder worker is unavailable")?;
        result.recv().map_err(|_| "Windows folder worker stopped")?
    }

    fn disconnect(&self) -> Result<(), String> {
        #[cfg(all(test, debug_assertions))]
        self.disconnect_test_calls.fetch_add(1, Ordering::SeqCst);
        self.cancel_fresh_close();
        self.bandwidth.suspend();
        self.revoke_folders();
        let (response, result) = std::sync::mpsc::sync_channel(1);
        self.commands
            .send(ProviderCommand::Disconnect(response))
            .map_err(|_| "Windows Cloud Files connection manager is unavailable")?;
        result
            .recv()
            .map_err(|_| "Windows Cloud Files connection manager stopped unexpectedly")?
    }

    fn dispatch_recovery(
        &self,
        agent_generation: u64,
        recovery: Arc<dyn raiun_cloudfiles_windows::PreparedEditRecovery>,
        record_id: String,
        record_generation: u64,
        remote: Arc<dyn raiun_cloudfiles_windows::RecoveryRemote>,
    ) -> Result<raiun_cloudfiles_windows::ReconciliationOutcome, String> {
        let (response, result) = std::sync::mpsc::sync_channel(1);
        self.commands
            .send(ProviderCommand::DispatchRecovery {
                agent_generation,
                recovery,
                record_id,
                record_generation,
                remote,
                response,
            })
            .map_err(|_| "Windows recovery manager is unavailable")?;
        result
            .recv()
            .map_err(|_| "Windows recovery manager stopped unexpectedly")?
    }

    #[cfg(all(test, debug_assertions))]
    fn revoke_backend_for_test(&self) -> Result<(), String> {
        let (response, result) = std::sync::mpsc::sync_channel(1);
        self.commands
            .send(ProviderCommand::RevokeBackendForTest(response))
            .map_err(|_| "Windows Cloud Files connection manager is unavailable")?;
        result
            .recv()
            .map_err(|_| "Windows Cloud Files connection manager stopped unexpectedly")?
    }

    #[cfg(test)]
    fn directory_observation(&self) -> Result<NativeCallbackObservation, String> {
        let (response, result) = std::sync::mpsc::sync_channel(1);
        self.commands
            .send(ProviderCommand::DirectoryObservation(response))
            .map_err(|_| "Windows Cloud Files connection manager is unavailable")?;
        result
            .recv()
            .map_err(|_| "Windows Cloud Files connection manager stopped unexpectedly")?
    }

    #[cfg(test)]
    fn read_only_placeholder_observation(
        &self,
        path: NativeRestartProbePath,
    ) -> Result<NativeReadOnlyObservation, String> {
        let (response, result) = std::sync::mpsc::sync_channel(1);
        self.commands
            .send(ProviderCommand::ReadOnlyPlaceholderObservation { path, response })
            .map_err(|_| "Windows Cloud Files connection manager is unavailable")?;
        result
            .recv()
            .map_err(|_| "Windows Cloud Files connection manager stopped unexpectedly")?
    }

    #[cfg(test)]
    fn hydrate_native_read_fixture_for_test(
        &self,
        fixture: NativeReadFixturePath,
    ) -> Result<i32, String> {
        let (response, result) = std::sync::mpsc::sync_channel(1);
        self.commands
            .send(ProviderCommand::HydrateNativeReadFixtureForTest { fixture, response })
            .map_err(|_| "Windows Cloud Files connection manager is unavailable")?;
        result
            .recv()
            .map_err(|_| "Windows Cloud Files connection manager stopped unexpectedly")?
    }

    #[cfg(test)]
    fn close_observation(&self) -> Result<NativeCloseObservation, String> {
        let (response, result) = std::sync::mpsc::sync_channel(1);
        self.commands
            .send(ProviderCommand::CloseObservation(response))
            .map_err(|_| "Windows Cloud Files connection manager is unavailable")?;
        result
            .recv()
            .map_err(|_| "Windows Cloud Files connection manager stopped unexpectedly")?
    }

    #[cfg(test)]
    fn close_failure_observation(&self) -> Result<NativeCloseObservation, String> {
        let (response, result) = std::sync::mpsc::sync_channel(1);
        self.commands
            .send(ProviderCommand::CloseObservation(response))
            .map_err(|_| "Windows Cloud Files connection manager is unavailable")?;
        result
            .recv_timeout(Duration::from_millis(250))
            .map_err(|_| "Close callback diagnostic unavailable within its bound".to_owned())?
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Acquire)
    }

    fn activation_enabled(&self) -> bool {
        let enabled = WINDOWS_PROVIDER_ACTIVATION_ENABLED;
        #[cfg(all(test, debug_assertions))]
        let enabled = enabled || self.lifecycle_test_activation.load(Ordering::Acquire);
        enabled
    }

    fn authorize_generation(&self, generation: u64) {
        self.cancel_fresh_close();
        self.bandwidth.authorize_generation(generation);
        // InstallFolders checks/publishes under this same lock. Revocation and
        // the generation change must be atomic against that publication.
        let mut handle = self
            .folder_revocation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(handle) = handle.take() {
            handle.revoke();
        }
        self.folder_generation.store(0, Ordering::Release);
        if let Ok(mut snapshot) = self.folder_pause.lock() {
            *snapshot = None;
        }
        self.offline_jobs
            .cancel_and_authorize(&self.authorized_generation, generation);
    }

    fn recovery_cursor_context(
        &self,
        scope: &raiun_cloudfiles_windows::ProviderScope,
        root: raiun_cloudfiles_windows::ConfiguredRootIdentity,
        generation: u64,
    ) -> Result<String, String> {
        self.recovery_scope_fingerprint(
            scope.profile_id(),
            scope.server_origin(),
            scope.account_id(),
            root,
            generation,
        )
    }

    fn recovery_scope_fingerprint(
        &self,
        profile: &str,
        origin: &str,
        account: &str,
        root: raiun_cloudfiles_windows::ConfiguredRootIdentity,
        generation: u64,
    ) -> Result<String, String> {
        use sha2::Digest;
        let nonce = self
            .recovery_cursor_nonce
            .as_ref()
            .ok_or("Saved edit pagination could not establish a fresh session")?;
        let bytes = serde_json::to_vec(&(
            "raiun-windows-recovery-cursor-v1",
            nonce,
            profile,
            origin,
            account,
            root.volume_serial,
            root.file_index,
            generation,
        ))
        .map_err(|_| "Saved edit pagination context is unavailable")?;
        Ok(format!("{:x}", sha2::Sha256::digest(bytes)))
    }

    fn configuration_recovery_scope_token(
        &self,
        configuration: &RootConfiguration,
        generation: u64,
    ) -> Result<String, String> {
        let owner = configuration
            .registration_ownership
            .as_ref()
            .ok_or("The Windows drive has no verified recovery identity")?;
        let origin = url::Url::parse(&configuration.server)
            .map_err(|_| "The Windows drive server is invalid")?
            .origin()
            .ascii_serialization();
        self.recovery_scope_fingerprint(
            &configuration.profile_scope,
            &origin,
            &owner.account_id,
            raiun_cloudfiles_windows::ConfiguredRootIdentity {
                volume_serial: configuration.volume_serial,
                file_index: configuration.file_index,
            },
            generation,
        )
    }
}

fn disconnect_provider_connection(
    retired_vaults: &mut Vec<Arc<raiun_cloudfiles_windows::vault_routes::VerifiedVaultRoute>>,
    connection: &mut Option<raiun_cloudfiles_windows::ConfiguredRootConnection>,
    backend: &mut Option<Arc<raiun_cloudfiles_windows::OpenCloudPlaceholderBackend>>,
    connected: &AtomicBool,
) -> Result<(), String> {
    if let Some(active_backend) = backend.as_ref() {
        // Retain every route before revocation can fail. Native cleanup must
        // never lose the catalogue that owns previously published plaintext.
        retired_vaults.extend(
            active_backend
                .retire_vault_routes()
                .map_err(|_| "Could not retain vault cleanup state")?,
        );
        active_backend.revoke();
    }
    if !retired_vaults.is_empty() {
        // Revoke ALL routes before any fallible cleanup. A failure in the first
        // file must not leave another route's prepared objects able to publish.
        let mut revoke_failed = false;
        for route in retired_vaults.iter() {
            revoke_failed |= route.revoke_hydration().is_err();
        }
        if revoke_failed {
            return Err(
                "Vault hydration was revoked incompletely; retry state was preserved".into(),
            );
        }
        let active = connection
            .as_ref()
            .ok_or("Vault cleanup needs its retained Windows drive")?;
        for route in retired_vaults.iter() {
            active.cleanup_retired_vault_route(route)
                .map_err(|_| "Vault hydration was revoked, but local cleanup is incomplete; edits and retry state were preserved")?;
        }
        retired_vaults.clear();
    }
    let Some(active_connection) = connection.as_mut() else {
        connected.store(false, Ordering::Release);
        backend.take();
        return Ok(());
    };
    match active_connection.disconnect_in_place() {
        Ok(()) => {
            connection.take();
            backend.take();
            connected.store(false, Ordering::Release);
            Ok(())
        }
        Err(_) => {
            // The native connection remains owned by this manager. Its
            // backend has been revoked, so callbacks fail closed until a
            // later explicit disconnect retry succeeds.
            connected.store(true, Ordering::Release);
            Err("Windows Cloud Files callbacks were revoked, but disconnect did not complete cleanly".into())
        }
    }
}

impl Drop for ProviderManager {
    fn drop(&mut self) {
        self.cancel_fresh_close();
        self.bandwidth.suspend();
        self.revoke_folders();
        let (response, result) = std::sync::mpsc::sync_channel(1);
        let sent = self.commands.send(ProviderCommand::Stop(response)).is_ok();
        let stopped = sent && matches!(result.recv(), Ok(Ok(())));
        // Taking the handle still detaches on refusal; dropping commands next
        // closes the channel so the worker preserves failed cleanup ownership.
        if let Ok(mut worker) = self.worker.lock()
            && let Some(worker) = worker.take()
            && stopped
        {
            let _ = worker.join();
        }
    }
}

fn valid_runtime_profile(profile: &str) -> bool {
    profile == "default"
        || profile.strip_prefix("profile-").is_some_and(|suffix| {
            suffix.len() == 32
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

impl WindowsAgent {
    fn attach_existing_file_save_owner(self: &Arc<Self>) -> Result<(), String> {
        let mut owner = self
            .provider
            .existing_save_owner
            .lock()
            .map_err(|_| "Existing-file save owner unavailable")?;
        if let Some(current) = owner.upgrade()
            && !Arc::ptr_eq(&current, self)
        {
            return Err("A different existing-file save owner is attached".into());
        }
        *owner = Arc::downgrade(self);
        Ok(())
    }

    fn check_existing_file_save_account(
        &self,
        binding: &ActiveProviderBinding,
    ) -> Result<(), String> {
        let state = self.state.lock().map_err(|_| "Account state unavailable")?;
        let configuration = state
            .root_configuration
            .as_ref()
            .ok_or("Choose a drive before enabling existing-file saves")?;
        let session = state
            .session
            .as_ref()
            .ok_or("Connect the account before enabling existing-file saves")?;
        let owner = configuration
            .registration_ownership
            .as_ref()
            .ok_or("The drive owner is unverified")?;
        if !state.online_authenticated
            || state.authenticating
            || state.refreshing
            || state.logout_pending
            || state.needs_refresh
            || state.session_cleanup_uncertain
            || binding.generation == 0
            || self.generation.load(Ordering::Acquire) != binding.generation
            || session.expires_at <= unix_time_now().saturating_add(30)
            || state.active_generation != binding.generation
            || self.provider.authorized_generation.load(Ordering::Acquire) != binding.generation
            || !configuration.valid
            || configuration.profile_scope != self.profile_scope
            || configuration.server != session.server
            || configuration.client_id != session.client_id
            || Path::new(&configuration.path) != binding.path.as_path()
            || configuration.volume_serial != binding.identity.volume_serial
            || configuration.file_index != binding.identity.file_index
            || owner.personal_drive_id != binding.personal_space_id
            || owner.personal_root_resource_id.as_deref()
                != Some(binding.personal_root_resource_id.as_str())
        {
            return Err("The account or root changed before existing-file save admission".into());
        }
        Ok(())
    }

    fn abort_existing_file_save_admission(
        &self,
        binding: &ActiveProviderBinding,
        active: &Arc<AtomicBool>,
    ) {
        let worker = {
            let mut slot = self
                .fresh_close_worker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut source = self
                .provider
                .fresh_close_source
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let exact_source = source.as_ref().is_some_and(|source| {
                source.binding.as_ref() == Some(binding)
                    && source
                        .original_active
                        .as_ref()
                        .is_some_and(|original| Arc::ptr_eq(original, active))
            });
            let cancelled_exact_worker = source.is_none()
                && slot.as_ref().is_some_and(|worker| {
                    worker.owns_existing_file_save_marker(binding.generation, active)
                });
            if exact_source || cancelled_exact_worker {
                active.store(false, Ordering::Release);
                if let Some(source) = source.take() {
                    source.cancel();
                }
                slot.take()
            } else {
                None
            }
        };
        if let Some(worker) = worker {
            let _ = worker.stop();
        }
    }

    // Not present in normal production activation or IPC/configuration. Call
    // after authenticating the fixture's generation and before provider install.
    #[cfg(all(test, debug_assertions))]
    fn start_fresh_close_worker_for_test(self: &Arc<Self>) -> Result<(), String> {
        let mut slot = self
            .fresh_close_worker
            .lock()
            .map_err(|_| "Fresh vault close worker ownership is unavailable")?;
        if slot.is_some() {
            return Err("Fresh vault close worker is already owned".into());
        }
        let mut source = self
            .provider
            .fresh_close_source
            .lock()
            .map_err(|_| "Fresh vault close publication is unavailable")?;
        if source.is_some() || self.provider.connected.load(Ordering::Acquire) {
            return Err("Start fresh vault close publication before provider installation".into());
        }
        let worker = windows_vault_close_worker::FreshCloseWorker::start(
            Arc::downgrade(self),
            Arc::clone(&self.provider.authorized_generation),
        )?;
        *source = Some(FreshClosePublication::private(worker.source()));
        *slot = Some(worker);
        Ok(())
    }

    // Not present in normal production activation or IPC/configuration. Call
    // after authenticating the fixture's generation and before provider install.
    #[cfg(all(test, debug_assertions))]
    fn start_fresh_close_worker_with_writable_completion_for_test(
        self: &Arc<Self>,
    ) -> Result<(), String> {
        let mut slot = self
            .fresh_close_worker
            .lock()
            .map_err(|_| "Fresh vault close worker ownership is unavailable")?;
        if slot.is_some() {
            return Err("Fresh vault close worker is already owned".into());
        }
        let mut source = self
            .provider
            .fresh_close_source
            .lock()
            .map_err(|_| "Fresh vault close publication is unavailable")?;
        if source.is_some() || self.provider.connected.load(Ordering::Acquire) {
            return Err("Start fresh vault close publication before provider installation".into());
        }
        let worker =
            windows_vault_close_worker::FreshCloseWorker::start_with_writable_completion_for_test(
                Arc::downgrade(self),
                Arc::clone(&self.provider.authorized_generation),
            )?;
        *source = Some(FreshClosePublication::private(worker.source()));
        *slot = Some(worker);
        Ok(())
    }

    #[cfg(all(test, debug_assertions))]
    fn fresh_close_observation_for_test(
        &self,
    ) -> Result<windows_vault_close_worker::FreshCloseObservation, String> {
        self.fresh_close_worker
            .lock()
            .map_err(|_| "Fresh close worker unavailable")?
            .as_ref()
            .ok_or("Fresh close worker is absent")?
            .observation()
    }

    fn stop_fresh_close_worker(&self) -> Result<(), String> {
        self.provider.cancel_fresh_close();
        let worker = self
            .fresh_close_worker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        // Release the ownership mutex before an in-flight guarded HTTP call
        // finishes or the consumer's last Agent Arc drops.
        if let Some(worker) = worker {
            worker.stop()?;
        }
        Ok(())
    }
    fn new(session_store: impl SessionStore + 'static) -> Self {
        Self::new_for_profile("default", session_store)
            .expect("default runtime and session store must match")
    }

    fn new_for_profile(
        profile: &str,
        session_store: impl SessionStore + 'static,
    ) -> Result<Self, String> {
        Self::new_for_profile_with_sources(profile, session_store, None)
    }

    fn new_for_profile_with_sources(
        profile: &str,
        session_store: impl SessionStore + 'static,
        source_admissions: Option<SharedSourceAdmissions>,
    ) -> Result<Self, String> {
        Self::new_for_profile_with_services(
            profile,
            session_store,
            source_admissions,
            Arc::new(raiun_vault::session::VaultSessionCoordinator::new()),
        )
    }

    fn new_for_profile_with_services(
        profile: &str,
        session_store: impl SessionStore + 'static,
        source_admissions: Option<SharedSourceAdmissions>,
        vault_sessions: Arc<raiun_vault::session::VaultSessionCoordinator>,
    ) -> Result<Self, String> {
        if !valid_runtime_profile(profile) {
            return Err("Invalid Windows runtime profile".into());
        }
        if session_store
            .bound_profile()
            .is_some_and(|bound| bound != profile)
        {
            return Err("Windows runtime and session store profiles differ".into());
        }
        let agent = Self {
            source_admissions,
            vault_sessions,
            profile_scope: profile.into(),
            session_store: Arc::new(session_store),
            // Signed-out status and lifecycle fences must share the initial
            // generation; otherwise a new account cannot be retired safely.
            state: Arc::new(Mutex::new(AccountState {
                active_generation: 1,
                ..AccountState::default()
            })),
            generation: Arc::new(AtomicU64::new(1)),
            provider: Arc::new(ProviderManager::new()),
            auth_thread: Mutex::new(None),
            refresh_thread: Mutex::new(None),
            fresh_close_worker: Mutex::new(None),
            folder_lifecycle: Mutex::new(()),
            vault_credential_operation: Mutex::new(()),
            protected_recovery_tokens: Mutex::new(windows_vault_capture_recovery::Tokens::default()),
            #[cfg(all(test, debug_assertions))]
            synthetic_vault_completion_writer_probe: true,
        };
        agent.restore_active_session();
        Ok(agent)
    }

    fn restore_active_session(&self) {
        let restored = self.session_store.load_active(self.profile_scope.as_str());
        let (session, error, cleanup_uncertain) = match restored {
            Ok(Some(session)) if session.refresh_token.is_some() => (Some(session), None, false),
            Ok(Some(session)) => {
                let revoked = self.session_store.revoke_active();
                let mut cleanup_uncertain = revoked.is_err();
                if let Ok(Some((scope, server, client_id))) = revoked {
                    cleanup_uncertain |= self
                        .session_store
                        .remove(&scope, &server, &client_id)
                        .is_err();
                }
                // Even if pointer revocation failed, remove the exact expired
                // blob so a surviving pointer cannot restore it next launch.
                cleanup_uncertain |= self
                    .session_store
                    .remove(
                        self.profile_scope.as_str(),
                        &session.server,
                        &session.client_id,
                    )
                    .is_err();
                (
                    None,
                    Some("Saved Windows session has expired; sign in again".into()),
                    cleanup_uncertain,
                )
            }
            Ok(None) => (None, None, false),
            Err(error) => (None, Some(error), false),
        };
        let root_configuration = session.as_ref().and_then(|session| {
            load_root_configuration(&self.session_store, &self.profile_scope, session)
                .ok()
                .flatten()
        });
        if let Ok(mut state) = self.state.lock() {
            state.session = session;
            state.root_configuration = root_configuration;
            state.online_authenticated = false;
            state.needs_refresh = state.session.is_some();
            state.refreshing = false;
            state.refresh_retry_at = 0;
            state.error = error;
            state.session_cleanup_uncertain = cleanup_uncertain;
        }
    }

    fn guest_sharing(&self, value: &Value) -> Result<Value, String> {
        let request = crate::guest_sharing_wire::Request::parse(value)?;
        if request.profile_id != self.profile_scope {
            return Err("The selected account does not own this request".into());
        }
        // The account-state lease serializes sign-out, refresh and replacement
        // with this explicitly confirmed operation. No credentials enter IPC.
        let state = self
            .state
            .lock()
            .map_err(|_| "Account state is unavailable")?;
        if state.retiring
            || state.logout_pending
            || state.authenticating
            || state.refreshing
            || !state.online_authenticated
            || state.active_generation != request.expected_auth_generation
            || self.generation.load(Ordering::Acquire) != request.expected_auth_generation
        {
            return Err("The account changed; refresh guest access before continuing".into());
        }
        let session = state
            .session
            .as_ref()
            .filter(|s| s.expires_at > unix_time_now())
            .ok_or("Reconnect this account to manage guest access")?;
        let client = OpenCloudClient::new_for_guest_sharing(
            &session.server,
            session.access_token.clone(),
            &session.proxy,
        )
        .map_err(|_| "Could not prepare guest access")?;
        request.execute(&client)
    }

    fn sharing(&self, value: &Value) -> Result<Value, String> {
        let request = crate::sharing_wire::Request::parse(value)?;
        if request.profile_id != self.profile_scope {
            return Err("The selected account does not own this request".into());
        }
        // The account-state lease serializes sign-out, refresh and replacement
        // with this explicitly confirmed operation. No credentials enter IPC.
        let state = self
            .state
            .lock()
            .map_err(|_| "Account state is unavailable")?;
        if state.retiring
            || state.logout_pending
            || state.authenticating
            || state.refreshing
            || !state.online_authenticated
            || state.active_generation != request.expected_auth_generation
            || self.generation.load(Ordering::Acquire) != request.expected_auth_generation
        {
            return Err("The account changed; refresh sharing before continuing".into());
        }
        let session = state
            .session
            .as_ref()
            .filter(|s| s.expires_at > unix_time_now())
            .ok_or("Reconnect this account to manage sharing")?;
        let client = OpenCloudClient::new_for_guest_sharing(
            &session.server,
            session.access_token.clone(),
            &session.proxy,
        )
        .map_err(|_| "Could not prepare sharing")?;
        request.execute(&client)
    }

    fn account_avatar(&self, request: &Value) -> Result<Value, String> {
        let expected = request
            .get("expected_auth_generation")
            .and_then(Value::as_u64)
            .ok_or("Refresh the account before loading its photo")?;
        let session = {
            let state = self
                .state
                .lock()
                .map_err(|_| "Account state is unavailable")?;
            if state.retiring
                || state.logout_pending
                || state.authenticating
                || state.refreshing
                || !state.online_authenticated
                || state.active_generation != expected
                || self.generation.load(Ordering::Acquire) != expected
            {
                return Err("The account changed while loading its photo".into());
            }
            state
                .session
                .clone()
                .filter(|session| session.expires_at > unix_time_now())
                .ok_or("Connect this account to load its photo")?
        };
        let client = OpenCloudClient::new_with_proxy(
            &session.server,
            session.access_token.clone(),
            &session.proxy,
        )
        .map_err(|_| "The account photo is unavailable")?;
        let image = client
            .account_avatar()
            .map_err(|_| "The account photo is unavailable")?;
        let state = self
            .state
            .lock()
            .map_err(|_| "Account state is unavailable")?;
        if state.retiring
            || state.logout_pending
            || state.authenticating
            || !state.online_authenticated
            || state.active_generation != expected
            || self.generation.load(Ordering::Acquire) != expected
        {
            return Err("The account changed while loading its photo".into());
        }
        crate::account_avatar_wire::response(&self.profile_scope, expected, image)
    }

    fn handle_request(self: &Arc<Self>, request: &Value) -> Result<(Value, bool), String> {
        if request
            .get("profile_id")
            .is_some_and(|value| value.as_str() != Some(self.profile_scope.as_str()))
        {
            return Err("The selected Windows profile does not own this request".into());
        }
        reject_control_secret_request(request)?;
        let action = request
            .get("action")
            .and_then(Value::as_str)
            .ok_or("Control request must include a string action")?;
        if self
            .state
            .lock()
            .map_err(|_| "Account state is unavailable")?
            .retiring
            && action != "status"
        {
            return Err("This account is being removed".into());
        }
        match action {
            "status" => Ok((self.status()?, false)),
            "account_avatar" => Ok((self.account_avatar(request)?, false)),
            "guest_permissions" | "guest_invite" | "guest_update" | "guest_revoke" => {
                Ok((self.guest_sharing(request)?, false))
            }
            "sharing_capabilities"
            | "sharing_inventory"
            | "sharing_owned_settings"
            | "sharing_owned_update"
            | "sharing_owned_revoke"
            | "sharing_permissions"
            | "sharing_recipients"
            | "sharing_invite"
            | "sharing_update"
            | "sharing_revoke"
            | "sharing_link_create"
            | "sharing_link_revoke" => Ok((self.sharing(request)?, false)),
            "network_proxy" => Ok((self.proxy_settings(None)?, false)),
            "network_proxy_set" => Ok((self.proxy_settings(Some(request))?, false)),
            "bandwidth_limits" => Ok((self.bandwidth_settings(None)?, false)),
            "bandwidth_limits_set" => Ok((self.bandwidth_settings(Some(request))?, false)),
            "pairs"
            | "transfers"
            | "spaces"
            | "list"
            | "pair_add"
            | "pair_exclusions_set"
            | "pair_update"
            | "pair_remove"
            | "space_disconnect"
            | "space_sync_now"
            | "sync_now"
            | "pause"
            | "space_pause" => {
                if !WINDOWS_FOLDER_SYNC_ENABLED {
                    return Err("Windows folder sync is awaiting native acceptance".into());
                }
                Ok((self.folder_request(request)?, false))
            }
            "media_jobs" | "media_job_status" | "media_destination" | "media_job_set"
            | "media_job_remove" | "media_job_run" | "media_job_recovery" => {
                if !WINDOWS_MEDIA_METADATA_ENABLED {
                    return Err("Windows media backups are not yet supported".into());
                }
                Ok((self.folder_request(request)?, false))
            }
            // Inspection is read-only and grants no session, key or native route.
            "vault_inspect" => Ok((self.inspect_windows_vault(request)?, false)),
            "vault_list" => Ok((self.browse_windows_vault(request)?, false)),
            "vault_upload_capture" => {
                if !WINDOWS_VAULT_EDIT_UPLOAD_ENABLED {
                    return Err(
                        "Vault edit upload is awaiting native acceptance and local disposition"
                            .into(),
                    );
                }
                Ok((self.upload_windows_vault_capture_request(request)?, false))
            }
            "windows_recovery_retry" => Ok((self.retry_recovered_edit(request)?, false)),
            "windows_device_cache_quota_set" => {
                Ok((self.windows_device_cache_quota_set(request)?, false))
            }
            "windows_device_cache_usage" => Ok((self.windows_device_cache_usage(request)?, false)),
            "windows_file_cache_status" => Ok((self.windows_file_cache_status(request)?, false)),
            "windows_offline_folders" => {
                Ok((self.windows_offline_folder_request(request, "list")?, false))
            }
            "windows_offline_folder_prepare" => Ok((
                self.windows_offline_folder_request(request, "prepare")?,
                false,
            )),
            "windows_offline_folder_start" => Ok((
                self.windows_offline_folder_request(request, "start")?,
                false,
            )),
            "windows_offline_folder_resume" => Ok((
                self.windows_offline_folder_request(request, "resume")?,
                false,
            )),
            "windows_offline_folder_refresh" => Ok((
                self.windows_offline_folder_request(request, "refresh")?,
                false,
            )),
            "windows_offline_folder_status" => Ok((
                self.windows_offline_folder_request(request, "status")?,
                false,
            )),
            "windows_offline_folder_cancel" => Ok((
                self.windows_offline_folder_request(request, "cancel")?,
                false,
            )),
            "windows_offline_files" => {
                Ok((self.windows_offline_file_request(request, "list")?, false))
            }
            "windows_offline_file_start" => {
                Ok((self.windows_offline_file_request(request, "start")?, false))
            }
            "windows_offline_file_status" => {
                Ok((self.windows_offline_file_request(request, "status")?, false))
            }
            "windows_offline_file_cancel" => {
                Ok((self.windows_offline_file_request(request, "cancel")?, false))
            }
            "windows_recovery_list" => Ok((self.list_recovered_edits(request)?, false)),
            "windows_vault_capture_recovery_list" => {
                Ok((self.list_protected_vault_captures_request(request)?, false))
            }
            "windows_vault_capture_save_copy" => Ok((
                self.save_protected_vault_capture_copy_request(request)?,
                false,
            )),
            "set_autostart" => {
                let enabled = request
                    .get("enabled")
                    .and_then(Value::as_bool)
                    .ok_or("Choose whether to start Raiun at login")?;
                let executable = windows_startup_executable()?;
                raiun_control_windows::autostart::configure_autostart(&executable, enabled)
                    .map_err(|_| "Could not confirm Windows startup settings; check the setting before trying again")?;
                Ok((json!({"enabled":enabled}), false))
            }
            "diagnostics" => {
                let mounted = self.provider.is_connected();
                let state = self
                    .state
                    .lock()
                    .map_err(|_| "Account state is unavailable")?;
                let generation = state.active_generation;
                let configuration = state.root_configuration.clone();
                let binding = configuration.as_ref().and_then(|configuration| {
                    let owner = configuration.registration_ownership.as_ref()?;
                    Some(ActiveProviderBinding {
                        generation,
                        path: PathBuf::from(&configuration.path),
                        identity: raiun_cloudfiles_windows::ConfiguredRootIdentity {
                            volume_serial: configuration.volume_serial,
                            file_index: configuration.file_index,
                        },
                        personal_space_id: owner.personal_drive_id.clone(),
                        personal_root_resource_id: owner.personal_root_resource_id.clone()?,
                    })
                });
                let mut value = json!({
                    "schema_version": 1,
                    "app_version": env!("CARGO_PKG_VERSION"),
                    "target_os": std::env::consts::OS,
                    "target_arch": std::env::consts::ARCH,
                    "profile_scope": "selected_profile",
                    "profile_count": 1,
                    "profile_config": {
                        "parse_valid": null,
                        "folder_pair_count": null,
                        "mode_counts": null,
                        "vault_pair_count": null,
                    },
                    "runtime": {
                        "connected": state.session.is_some() && state.online_authenticated,
                        "mounted": mounted,
                        "sync_paused": self.provider.pause_snapshot(state.active_generation, state.online_authenticated).map(|snapshot| snapshot.paused),
                    },
                });
                drop(state);
                let mut cleanup = binding
                    .and_then(|binding| self.provider.vault_cleanup_diagnostics(binding).ok());
                let state = self
                    .state
                    .lock()
                    .map_err(|_| "Account state is unavailable")?;
                if state.active_generation != generation
                    || self.generation.load(Ordering::Acquire) != generation
                    || state.root_configuration != configuration
                {
                    cleanup = None;
                }
                value["runtime"]["vault_cleanup"] = cleanup.unwrap_or(Value::Null);
                Ok((value, false))
            }
            "accounts" => {
                let status = self.status()?;
                Ok((
                    json!({"selected":self.profile_scope.as_str(),"items":[{"id":self.profile_scope.as_str(),"label":"This PC","status":status}]}),
                    false,
                ))
            }
            "auth_begin" => Ok((self.begin_auth(request)?, false)),
            "configure" | "configure_root" => Ok((self.configure_root(request)?, false)),
            "auth_cancel" => Ok((self.cancel_auth()?, false)),
            "logout" => Ok((self.logout()?, false)),
            "shutdown" => {
                self.cancel_auth()?;
                self.provider.disconnect()?;
                Ok((json!({"stopping":true}), true))
            }
            _ => Err(PROVIDER_UNAVAILABLE.into()),
        }
    }

    fn proxy_settings(&self, update: Option<&Value>) -> Result<Value, String> {
        let (generation, session_exists) = {
            let state = self
                .state
                .lock()
                .map_err(|_| "Account state is unavailable")?;
            if update.is_some()
                && (state.session.is_some()
                    || state.authenticating
                    || state.refreshing
                    || state.logout_pending
                    || state.session_cleanup_uncertain)
            {
                return Err("Sign out before changing Windows proxy settings".into());
            }
            (state.active_generation, state.session.is_some())
        };
        let scope = if session_exists {
            self.provider.bandwidth.scope()?
        } else {
            None
        };
        let store = ProxyStore {
            store: self.session_store.as_ref(),
            profile: &self.profile_scope,
        };
        if let Some(request) = update {
            if self.provider.connected.load(Ordering::Acquire)
                || self.provider.folder_generation.load(Ordering::Acquire) != 0
            {
                return Err("Stop account work and sign out before changing proxy settings".into());
            }
            // Recheck after the snapshot, before durable CAS; no state guard is
            // held through private storage or provider/worker waits.
            {
                let state = self
                    .state
                    .lock()
                    .map_err(|_| "Account state is unavailable")?;
                if state.active_generation != generation
                    || state.session.is_some()
                    || state.authenticating
                    || state.refreshing
                    || state.logout_pending
                    || state.session_cleanup_uncertain
                {
                    return Err("Account state changed before proxy settings could be saved".into());
                }
            }
            self.provider
                .proxy
                .update(&self.profile_scope, request, &store)?;
            let state = self
                .state
                .lock()
                .map_err(|_| "Proxy settings may have been saved; account state is unavailable")?;
            if state.active_generation != generation
                || state.session.is_some()
                || state.authenticating
                || state.refreshing
                || state.logout_pending
                || state.session_cleanup_uncertain
            {
                return Err("Account state changed; proxy settings may have been saved for the next sign-in".into());
            }
        }
        let value = self.provider.proxy.value(
            &self.profile_scope,
            scope.as_ref().map(windows_bandwidth::Scope::bytes),
            &store,
        )?;
        let state = self
            .state
            .lock()
            .map_err(|_| "Proxy settings may have been saved; account state is unavailable")?;
        if state.active_generation != generation || state.session.is_some() != session_exists {
            return Err("Account state changed; proxy settings may have been saved, so refresh before continuing".into());
        }
        Ok(value)
    }

    fn bandwidth_settings(&self, update: Option<&Value>) -> Result<Value, String> {
        let (session, generation) = {
            let state = self
                .state
                .lock()
                .map_err(|_| "Account state is unavailable")?;
            if state.logout_pending
                || state.authenticating
                || state.refreshing
                || state.session_cleanup_uncertain
            {
                return Err(
                    "Wait for the current account transition before changing bandwidth settings"
                        .into(),
                );
            }
            (state.session.clone(), state.active_generation)
        };
        let Some(session) = session else {
            if update.is_some() {
                return Err("A trusted account is required for bandwidth settings".into());
            }
            return self.provider.bandwidth.value(None, generation);
        };
        let scope = self.provider.bandwidth.scope()?.filter(|scope| {
            scope.matches(
                &self.profile_scope,
                &session.server,
                &session.client_id,
                session.expected_issuer.as_deref(),
            )
        });
        // A saved root's account ID is an exclusion/registration record, not
        // proof that newly replaced credentials belong to the same subject.
        // Offline edits use only this runtime's already-verified exact owner.
        let check_current = || -> Result<(), String> {
            let state = self
                .state
                .lock()
                .map_err(|_| "Account state is unavailable")?;
            if state.active_generation != generation
                || state.logout_pending
                || state.authenticating
                || state.refreshing
                || state.session_cleanup_uncertain
                || state.session.as_ref().is_none_or(|current| {
                    current.server != session.server
                        || current.client_id != session.client_id
                        || current.expected_issuer != session.expected_issuer
                        || current.access_token != session.access_token
                })
            {
                return Err("The account changed; bandwidth settings may have been saved for the previous scope".into());
            }
            Ok(())
        };
        check_current()?;
        if let Some(request) = update {
            let scope = scope
                .as_ref()
                .ok_or("A verified account is required for bandwidth settings")?;
            self.provider.bandwidth.update(
                scope,
                request,
                &BandwidthStore {
                    store: self.session_store.as_ref(),
                    profile: &self.profile_scope,
                },
            )?;
        }
        check_current()?;
        self.provider.bandwidth.value(scope.as_ref(), generation)
    }

    fn status(&self) -> Result<Value, String> {
        let retiring = self
            .state
            .lock()
            .map_err(|_| "Account state is unavailable")?
            .retiring;
        if !retiring {
            self.maybe_start_refresh()?;
        }
        let mounted = self.provider.is_connected();
        let provider_supported = self.provider.activation_enabled();
        let folder_error = self
            .provider
            .folder_error
            .lock()
            .ok()
            .and_then(|value| value.clone());
        // Startup is a per-user app preference, independent of account secrets.
        // Query before taking account state; status never writes an entry.
        let autostart = windows_startup_executable().ok().and_then(|executable| {
            raiun_control_windows::autostart::autostart_status(&executable)
                .ok()
                .flatten()
        });
        let state = self
            .state
            .lock()
            .map_err(|_| "Account state is unavailable")?;
        let session = state.session.as_ref();
        let pause = self
            .provider
            .pause_snapshot(state.active_generation, state.online_authenticated);
        let mut status = json!({
            "agent_version": env!("CARGO_PKG_VERSION"),
            "connected": session.is_some() && state.online_authenticated,
            "offline": session.is_some() && !state.online_authenticated,
            "server": session.map(|value| value.server.as_str()),
            "client_id": session.map(|value| value.client_id.as_str()),
            "paused": pause.as_ref().map(|snapshot| snapshot.paused),
            "paused_space_ids": pause.as_ref().map(|snapshot| &snapshot.paused_space_ids),
            "mounted": mounted,
            "cloud_root": state.root_configuration.as_ref().map(|value| value.path.as_str()),
            "root_configuration": state.root_configuration.as_ref().map(|value| json!({
                "path": value.path,
                "valid": value.valid,
                "identity_bound": value.registration_ownership.is_some(),
                "registration_state": value.registration_ownership.as_ref().map(|owner| owner.state.as_str()),
                "recovery_scope_token": self.provider.configuration_recovery_scope_token(value, state.active_generation).ok(),
            })),
            "error": state.error.as_deref().or(folder_error.as_deref()).or_else(|| (!provider_supported).then_some(PROVIDER_UNAVAILABLE)),
            "autostart": autostart,
            "recovery_folder": null,
            "encrypted_edit_recovery_available": false,
            "offline_cache": null,
            "profile_id": self.profile_scope.as_str(),
            "profile_label": "This PC",
            "auth_generation": state.active_generation,
            "provider_supported": provider_supported,
            "folder_sync_supported": WINDOWS_FOLDER_SYNC_ENABLED,
            "folder_settings_supported": WINDOWS_FOLDER_SYNC_ENABLED,
            "bandwidth_limits_supported": true,
            "network_proxy_supported": true,
            "proxy_edit_requires_sign_out": state.session.is_some(),
            "media_jobs_supported": WINDOWS_MEDIA_METADATA_ENABLED,
            "vaults_supported": WINDOWS_VAULT_SESSIONS_ENABLED,
            "vault_in_app_browse_supported": true,
            "account_switch_supported": false,
            "pause_supported": WINDOWS_FOLDER_SYNC_ENABLED,
            "authenticating": state.authenticating,
            "refreshing": state.refreshing,
            "session_expires_at": session.map(|value| value.expires_at),
            "session_cleanup_uncertain": state.session_cleanup_uncertain,
            "account_removing": state.retiring,
        });
        if WINDOWS_VAULT_SESSIONS_ENABLED {
            status["vault_access_mode"] = json!("native_read_only");
        }
        Ok(status)
    }

    fn protected_recovery_context(
        &self,
        request: &Value,
    ) -> Result<ProtectedRecoveryContext, String> {
        if request
            .get("profile_id")
            .is_some_and(|value| value.as_str() != Some(self.profile_scope.as_str()))
        {
            return Err("Select the current Windows account".into());
        }
        let expected_generation = request
            .get("expected_generation")
            .and_then(Value::as_u64)
            .filter(|generation| *generation != 0)
            .ok_or("Reopen saved vault edits for the current account")?;
        let expected_scope_token = request
            .get("expected_recovery_scope_token")
            .and_then(Value::as_str)
            .filter(|token| {
                token.len() == 64
                    && token
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .ok_or("Refresh the Windows drive status before checking saved vault edits")?;
        let (session, generation, configuration) = {
            let state = self
                .state
                .lock()
                .map_err(|_| "Account state is unavailable")?;
            if !state.online_authenticated
                || state.authenticating
                || state.refreshing
                || state.logout_pending
                || state.needs_refresh
                || state.session_cleanup_uncertain
            {
                return Err("Connect the current account before opening saved vault edits".into());
            }
            let session = state
                .session
                .clone()
                .ok_or("Connect the current account before opening saved vault edits")?;
            let configuration = state
                .root_configuration
                .clone()
                .ok_or("The registered Windows drive folder is unavailable")?;
            (session, state.active_generation, configuration)
        };
        if generation != expected_generation
            || self.generation.load(Ordering::Acquire) != generation
            || self.provider.authorized_generation.load(Ordering::Acquire) != generation
            || !self.provider.is_connected()
        {
            return Err("The account or Windows drive changed; refresh saved vault edits".into());
        }
        if !configuration.valid
            || configuration.profile_scope != self.profile_scope
            || configuration.server != session.server
            || configuration.client_id != session.client_id
            || session.expires_at <= unix_time_now().saturating_add(30)
        {
            return Err("Saved vault edits do not match the connected account and drive".into());
        }
        let registration = configuration
            .registration_ownership
            .as_ref()
            .filter(|owner| owner.state == "registered")
            .ok_or("The Windows drive has no verified registered owner")?;
        validate_registration_ownership(
            registration,
            &session.server,
            configuration.volume_serial,
            configuration.file_index,
        )?;
        let root_identity = raiun_cloudfiles_windows::ConfiguredRootIdentity {
            volume_serial: configuration.volume_serial,
            file_index: configuration.file_index,
        };
        pin_registered_configured_root(Path::new(&configuration.path), root_identity)
            .map_err(root_error_text)?;
        let binding = ActiveProviderBinding {
            generation,
            path: PathBuf::from(&configuration.path),
            identity: root_identity,
            personal_space_id: registration.personal_drive_id.clone(),
            personal_root_resource_id: registration
                .personal_root_resource_id
                .clone()
                .ok_or("The registered drive root identity is incomplete")?,
        };
        let context_token = self
            .provider
            .configuration_recovery_scope_token(&configuration, generation)?;
        if context_token != expected_scope_token {
            return Err("The account or Windows drive changed; refresh saved vault edits".into());
        }
        Ok(ProtectedRecoveryContext {
            generation,
            session,
            configuration,
            binding,
            context_token,
        })
    }

    fn revalidate_protected_recovery_context(
        &self,
        context: &ProtectedRecoveryContext,
    ) -> Result<(), String> {
        let state = self
            .state
            .lock()
            .map_err(|_| "Account state is unavailable")?;
        let same_session = state.session.as_ref().is_some_and(|current| {
            current.server == context.session.server
                && current.client_id == context.session.client_id
                && current.access_token == context.session.access_token
                && current.expires_at > unix_time_now().saturating_add(30)
        });
        if !state.online_authenticated
            || state.authenticating
            || state.refreshing
            || state.logout_pending
            || state.needs_refresh
            || state.session_cleanup_uncertain
            || state.active_generation != context.generation
            || self.generation.load(Ordering::Acquire) != context.generation
            || self.provider.authorized_generation.load(Ordering::Acquire) != context.generation
            || !same_session
            || state.root_configuration.as_ref() != Some(&context.configuration)
            || !self
                .provider
                .configuration_recovery_scope_token(&context.configuration, context.generation)
                .is_ok_and(|token| token == context.context_token)
        {
            return Err(
                "The account or Windows drive changed during saved vault edit access".into(),
            );
        }
        pin_registered_configured_root(
            Path::new(&context.configuration.path),
            context.binding.identity,
        )
        .map_err(root_error_text)?;
        Ok(())
    }

    fn parse_protected_recovery_scope(
        request: &Value,
    ) -> Result<windows_vault_capture_recovery::RecoveryScope, String> {
        let required = |name: &str| -> Result<String, String> {
            let value = request
                .get(name)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty() && value.len() <= 4096)
                .ok_or_else(|| format!("Saved vault edit request has an invalid {name}"))?;
            Ok(value.to_owned())
        };
        Ok(windows_vault_capture_recovery::RecoveryScope {
            space_id: required("space_id")?,
            root_resource_id: required("root_resource_id")?,
            remote_root: required("remote_root")?,
        })
    }

    fn list_protected_vault_captures_request(&self, request: &Value) -> Result<Value, String> {
        let context = self.protected_recovery_context(request)?;
        let scope = Self::parse_protected_recovery_scope(request)?;
        let limit = match request.get("limit") {
            None => 100,
            Some(value) => value
                .as_u64()
                .filter(|limit| (1..=100).contains(limit))
                .ok_or("Saved vault edit page size must be between 1 and 100")?
                as usize,
        };
        let cursor = request.get("cursor").and_then(Value::as_str);
        if request.get("cursor").is_some() && cursor.is_none() {
            return Err("Saved vault edit cursor is invalid".into());
        }
        let after = self
            .protected_recovery_tokens
            .lock()
            .map_err(|_| "Saved vault edit pagination is unavailable")?
            .after(cursor, context.generation, &context.context_token, &scope)?;
        let (rows, next_after) = self.provider.list_protected_vault_captures(
            context.binding.clone(),
            scope.clone(),
            after,
            limit,
        )?;
        self.revalidate_protected_recovery_context(&context)?;
        let page = self
            .protected_recovery_tokens
            .lock()
            .map_err(|_| "Saved vault edit pagination is unavailable")?
            .page(
                &self.profile_scope,
                context.generation,
                &context.context_token,
                scope,
                rows,
                next_after,
            )?;
        let encoded =
            serde_json::to_vec(&page).map_err(|_| "Saved vault edit page could not be encoded")?;
        if encoded.len() > windows_vault_capture_recovery::MAX_RESPONSE_BYTES {
            return Err("Saved vault edit page exceeds the response limit".into());
        }
        serde_json::from_slice(&encoded)
            .map_err(|_| "Saved vault edit page could not be decoded".into())
    }

    fn save_protected_vault_capture_copy_request(&self, request: &Value) -> Result<Value, String> {
        let context = self.protected_recovery_context(request)?;
        let scope = Self::parse_protected_recovery_scope(request)?;
        let item_token = request
            .get("item_token")
            .and_then(Value::as_str)
            .ok_or("Choose one saved vault edit to copy")?;
        let capture_id = self
            .protected_recovery_tokens
            .lock()
            .map_err(|_| "Saved vault edit selection is unavailable")?
            .item(
                item_token,
                context.generation,
                &context.context_token,
                &scope,
            )?;
        let destination = request
            .get("destination")
            .and_then(Value::as_str)
            .filter(|path| !path.is_empty() && path.len() <= 32768)
            .ok_or("Choose one fresh local destination for Save Copy")?;
        self.revalidate_protected_recovery_context(&context)?;
        let receipt = self.provider.save_protected_vault_capture_copy(
            context.binding.clone(),
            scope,
            capture_id,
            PathBuf::from(destination),
        )?;
        self.revalidate_protected_recovery_context(&context)?;
        serde_json::to_value(receipt).map_err(|_| "Save Copy receipt could not be encoded".into())
    }

    /// Authenticated read-only discovery. No upload approval, dispatch or
    /// journal retirement is created by reading this bounded metadata page.
    fn list_recovered_edits(&self, request: &Value) -> Result<Value, String> {
        if request
            .get("profile_id")
            .is_some_and(|value| value.as_str() != Some(self.profile_scope.as_str()))
        {
            return Err("Select the current Windows account".into());
        }
        let expected_generation = request
            .get("expected_generation")
            .and_then(Value::as_u64)
            .filter(|value| *value != 0)
            .ok_or("Reopen saved edits for the current account")?;
        let expected_scope = request
            .get("expected_recovery_scope_token")
            .and_then(Value::as_str)
            .filter(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .ok_or("Refresh the Windows drive status before checking saved edits")?;
        let limit = match request.get("limit") {
            None => 100,
            Some(value) => value
                .as_u64()
                .filter(|value| (1..=100).contains(value))
                .ok_or("Saved edit page size must be between 1 and 100")?
                as usize,
        };
        if self.generation.load(Ordering::Acquire) != expected_generation {
            return Err("The account changed; reopen saved edits".into());
        }
        let verified = self.prepare_recovery_context()?;
        if expected_generation != verified.agent_generation {
            return Err("The account changed; reopen saved edits".into());
        }
        let cursor_context = self.provider.recovery_cursor_context(
            &verified.provider_scope,
            verified.local_root_identity,
            expected_generation,
        )?;
        if cursor_context != expected_scope {
            return Err("The account or Windows drive changed; refresh saved edits".into());
        }
        let after = parse_bound_recovery_list_cursor(request.get("after"), &cursor_context)?;
        let records = verified
            .recovery_provider
            .unresolved_metadata_bounded()
            .map_err(|error| match error {
                raiun_cloudfiles_windows::JournalError::ScanLimit => {
                    "Saved edits exceed this scan limit; nothing was changed"
                }
                _ => "Protected recovery records could not be verified",
            })?;
        let page = recovery_metadata_page(
            records,
            &verified.provider_scope,
            verified.local_root_identity,
            after,
            limit,
        )?;
        let next_after = bind_recovery_list_cursor(page.1, &cursor_context)?;
        // Serialize with account transitions before returning decoded paths.
        let state = self
            .state
            .lock()
            .map_err(|_| "Account state is unavailable")?;
        if state.active_generation != verified.agent_generation
            || self.generation.load(Ordering::Acquire) != verified.agent_generation
            || self.provider.authorized_generation.load(Ordering::Acquire)
                != verified.agent_generation
            || !state.online_authenticated
            || state.authenticating
            || state.refreshing
            || state.needs_refresh
            || state.session.as_ref().is_none_or(|current| {
                current.server != verified.session.server
                    || current.client_id != verified.session.client_id
                    || current.access_token != verified.session.access_token
                    || current.expires_at <= unix_time_now().saturating_add(30)
            })
            || state.root_configuration.as_ref() != Some(&verified.configuration)
            || !self
                .provider
                .configuration_recovery_scope_token(
                    &verified.configuration,
                    state.active_generation,
                )
                .is_ok_and(|current| current == expected_scope)
        {
            return Err("The account changed; reopen saved edits".into());
        }
        Ok(
            json!({"profile_id":self.profile_scope.as_str(), "auth_generation":verified.agent_generation,
            "items":page.0, "next_after":next_after, "read_only":true,
            "recovery_scope_token":cursor_context}),
        )
    }

    fn prepare_recovery_context(&self) -> Result<WindowsRecoveryContext, String> {
        self.maybe_start_refresh()?;
        let (session, agent_generation, configuration) = {
            let state = self
                .state
                .lock()
                .map_err(|_| "Account state is unavailable")?;
            if !state.online_authenticated
                || state.authenticating
                || state.refreshing
                || state.needs_refresh
            {
                return Err("Connect this account before retrying a saved edit".into());
            }
            let session = state
                .session
                .clone()
                .ok_or("Connect this account before retrying a saved edit")?;
            let configuration = state
                .root_configuration
                .clone()
                .ok_or("Choose the original Windows drive folder before retrying a saved edit")?;
            (session, state.active_generation, configuration)
        };
        if self.generation.load(Ordering::Acquire) != agent_generation
            || self.provider.authorized_generation.load(Ordering::Acquire) != agent_generation
        {
            return Err("The account changed; reopen Transfers and try again".into());
        }
        if !configuration.valid
            || configuration.server != session.server
            || configuration.client_id != session.client_id
            || session.expires_at <= unix_time_now().saturating_add(30)
        {
            return Err("The saved edit does not match the current connected account".into());
        }
        let owner = configuration
            .registration_ownership
            .as_ref()
            .filter(|owner| owner.state == "registered")
            .ok_or("The saved edit is not bound to a verified Windows drive folder")?;
        validate_registration_ownership(
            owner,
            &session.server,
            configuration.volume_serial,
            configuration.file_index,
        )?;
        let local_root_identity = raiun_cloudfiles_windows::ConfiguredRootIdentity {
            volume_serial: configuration.volume_serial,
            file_index: configuration.file_index,
        };
        let _root_lease =
            pin_registered_configured_root(Path::new(&configuration.path), local_root_identity)
                .map_err(root_error_text)?;

        let client = Arc::new(
            OpenCloudClient::new_with_proxy(
                &session.server,
                session.access_token.clone(),
                &session.proxy,
            )
            .map_err(|_| "Could not create the connected account client")?,
        );
        let server_origin = client
            .server_origin()
            .ok_or("The connected account server origin is invalid")?;
        let (_, account_id, personal_root_id, spaces, context) =
            verified_account_roots(&client, &session.server)?;
        if account_id != owner.account_id
            || spaces
                .iter()
                .find(|space| space.personal)
                .is_none_or(|space| space.id != owner.personal_drive_id)
            || owner.personal_root_resource_id.as_deref() != Some(personal_root_id.as_str())
        {
            return Err("The verified account no longer matches this drive folder".into());
        }
        let (client, _) = budget_client(
            client,
            &session,
            &self.profile_scope,
            &account_id,
            agent_generation,
            &self.provider,
            self.session_store.as_ref(),
        )?;
        let provider_scope = raiun_cloudfiles_windows::ProviderScope::new(
            client.as_ref(),
            configuration.profile_scope.clone(),
            account_id,
            server_origin,
        )
        .map_err(|_| "Could not bind recovery to the connected account")?;
        let recovery_provider =
            raiun_cloudfiles_windows::DurableEditRecoveryProvider::current_user(
                provider_scope.clone(),
                local_root_identity,
            )
            .map_err(|_| "Protected recovery storage is unavailable")?;
        Ok(WindowsRecoveryContext {
            session,
            agent_generation,
            configuration,
            local_root_identity,
            _root_lease,
            client,
            provider_scope,
            spaces,
            context,
            recovery_provider,
        })
    }

    /// Explicit, single-record recovery. Identity, server, Space root, and
    /// local root are resolved from the current authenticated profile and the
    /// protected recovery catalog; the caller supplies only an opaque record
    /// ID and its immutable generation. This path is never called by startup,
    /// refresh, reconnect, or provider callbacks.
    fn retry_recovered_edit(&self, request: &Value) -> Result<Value, String> {
        use raiun_cloudfiles_windows::EditRecoveryProvider;

        let record_id = request
            .get("record_id")
            .and_then(Value::as_str)
            .filter(|value| {
                !value.is_empty()
                    && value.len() <= 128
                    && value.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
            .ok_or("Select a valid recovery item")?;
        let record_generation = request
            .get("generation")
            .and_then(Value::as_u64)
            .filter(|generation| *generation != 0)
            .ok_or("Select a valid recovery item")?;
        let WindowsRecoveryContext {
            session,
            agent_generation,
            configuration,
            local_root_identity,
            _root_lease,
            client,
            provider_scope,
            spaces,
            context,
            recovery_provider,
        } = self.prepare_recovery_context()?;
        let candidates = recovery_provider
            .unresolved_edits()
            .map_err(|_| "Protected recovery records could not be verified")?;
        let mut selected = candidates
            .into_iter()
            .filter(|item| item.record_id == record_id && item.generation == record_generation);
        let metadata = selected
            .next()
            .ok_or("The selected recovery item is unavailable")?;
        if selected.next().is_some()
            || metadata.scope.profile_id != provider_scope.profile_id()
            || metadata.scope.server_origin != provider_scope.server_origin()
            || metadata.scope.account_subject != provider_scope.account_id()
            || metadata.scope.root_volume_serial != local_root_identity.volume_serial
            || metadata.scope.root_file_index != local_root_identity.file_index
        {
            return Err(
                "The selected recovery item belongs to a different account or drive folder".into(),
            );
        }
        let space = spaces
            .iter()
            .find(|space| space.id == metadata.scope.space_id)
            .filter(|space| !space.encrypted && space.writable)
            .ok_or("The saved edit’s Space is unavailable or protected")?;
        let remote_root = client
            .stat_discovered_space_root_with_context(space, context)
            .map_err(|_| "Could not verify the saved edit’s Space root")?;
        if !remote_root.directory
            || remote_root.encrypted
            || remote_root.id != metadata.scope.root_resource_id
        {
            return Err("The saved edit’s Space root has changed".into());
        }
        let prepared = recovery_provider
            .prepare(&provider_scope, local_root_identity)
            .map_err(|_| "Protected recovery storage is unavailable")?;
        if prepared.provider_scope() != &provider_scope
            || prepared.root_identity() != local_root_identity
        {
            return Err("Could not bind recovery to the current account and drive folder".into());
        }
        let client_generation = client.token_generation();
        let remote = Arc::new(
            raiun_cloudfiles_windows::OpenCloudRecoveryRemote::new(
                Arc::clone(&client),
                metadata.scope,
                remote_root.path,
                client_generation,
            )
            .map_err(|_| "Could not prepare the conditional recovery request")?,
        );
        let remote: Arc<dyn raiun_cloudfiles_windows::RecoveryRemote> =
            Arc::new(AgentGenerationRecoveryRemote {
                inner: RecoveryRemoteHandle::Owned(remote),
                authorized_generation: Arc::clone(&self.provider.authorized_generation),
                expected_generation: agent_generation,
            });
        {
            let state = self
                .state
                .lock()
                .map_err(|_| "Account state is unavailable")?;
            if state.active_generation != agent_generation
                || !state.online_authenticated
                || state.authenticating
                || state.refreshing
                || state.session.as_ref().is_none_or(|current| {
                    current.server != session.server
                        || current.client_id != session.client_id
                        || current.access_token != session.access_token
                })
                || state.root_configuration.as_ref() != Some(&configuration)
            {
                return Err("The account changed; reopen Transfers and try again".into());
            }
        }
        let outcome = self.provider.dispatch_recovery(
            agent_generation,
            prepared,
            record_id.to_owned(),
            record_generation,
            remote,
        )?;
        if self.generation.load(Ordering::Acquire) != agent_generation {
            return Err("The account changed while the recovery attempt was running".into());
        }
        Ok(recovery_outcome_json(outcome))
    }

    /// Prepare exclusion metadata from the live authenticated account, never
    /// from the saved document or a request-supplied account identity. The broker
    /// retains this pin through durable publication and worker admission.
    fn prepare_source_reservation(
        &self,
        request: &Value,
    ) -> Result<
        (
            windows_profile_registry::SourceReservation,
            raiun_control_windows::PinnedDirectory,
        ),
        String,
    > {
        use raiun_engine::folder_pairs::AccountScope;
        use sha2::Digest;
        use windows_folder_requests::FolderRequest;
        use windows_media_requests::MediaRequest;
        use windows_profile_registry::{RootReservation, SourceKind, SourceReservation};
        if request
            .get("profile_id")
            .is_some_and(|value| value.as_str() != Some(self.profile_scope.as_str()))
        {
            return Err("Select the current Windows account".into());
        }
        let (session, generation) = {
            let state = self
                .state
                .lock()
                .map_err(|_| "Account state is unavailable")?;
            if !state.online_authenticated
                || state.logout_pending
                || state.authenticating
                || state.refreshing
                || state.needs_refresh
                || state.session_cleanup_uncertain
            {
                return Err("Connect this account before admitting a source".into());
            }
            (
                state.session.clone().ok_or("Connect this account")?,
                state.active_generation,
            )
        };
        let client = Arc::new(
            OpenCloudClient::new_with_proxy(
                &session.server,
                session.access_token.clone(),
                &session.proxy,
            )
            .map_err(|_| "Could not verify the source account")?,
        );
        let (_, account, _, _, _) = verified_account_roots(&client, &session.server)?;
        let (kind, id, path) = match windows_folder_requests::decode(request)? {
            FolderRequest::Add(pair) => (SourceKind::FolderPair, pair.id, pair.local_path),
            FolderRequest::Media(MediaRequest::Set {
                job,
                expected_account_id,
                ..
            }) => {
                if job.account_id != account || expected_account_id != account {
                    return Err("Media source belongs to another account".into());
                }
                (SourceKind::MediaJob, job.id, job.source_root)
            }
            _ => return Err("This request does not admit a source".into()),
        };
        let issuer = session
            .expected_issuer
            .as_ref()
            .map(|value| url::Url::parse(value).map(|url| url.to_string()))
            .transpose()
            .map_err(|_| "The account issuer is invalid")?;
        let scope = AccountScope::new(
            self.profile_scope.clone(),
            url::Url::parse(&session.server)
                .map_err(|_| "The account server is invalid")?
                .to_string(),
            session.client_id.clone(),
            issuer,
            account,
        )
        .map_err(|_| "The source account scope is invalid")?;
        let bytes =
            serde_json::to_vec(&scope).map_err(|_| "The source account scope is invalid")?;
        let pin = raiun_control_windows::PinnedDirectory::open(&path)
            .map_err(|_| "The source folder is unavailable or contains a reparse point")?;
        let identity = pin.identity();
        let reservation = SourceReservation::new(
            format!("{:x}", sha2::Sha256::digest(bytes)),
            kind,
            id,
            RootReservation::new(
                path.to_str().ok_or("The source path is invalid")?.into(),
                identity.volume_serial,
                identity.file_index,
                false,
            )?,
        )?;
        {
            let state = self
                .state
                .lock()
                .map_err(|_| "Account state is unavailable")?;
            if state.active_generation != generation
                || !state.online_authenticated
                || state.logout_pending
                || state.authenticating
                || state.refreshing
                || state.needs_refresh
                || state.session_cleanup_uncertain
                || state.session.as_ref().is_none_or(|current| {
                    current.server != session.server
                        || current.client_id != session.client_id
                        || current.expected_issuer != session.expected_issuer
                        || current.access_token != session.access_token
                        || current.expires_at != session.expires_at
                })
            {
                return Err("The account changed during source admission".into());
            }
        }
        pin.verify_path()
            .map_err(|_| "The source changed during admission")?;
        Ok((reservation, pin))
    }

    fn folder_request(&self, request: &Value) -> Result<Value, String> {
        use raiun_control_windows::{PinnedDirectory, PrivateDirectory};
        use raiun_engine::folder_pairs::AccountScope;
        use sha2::Digest;
        let _lifecycle = self
            .folder_lifecycle
            .lock()
            .map_err(|_| "Folder setup is unavailable")?;
        if request
            .get("profile_id")
            .is_some_and(|id| id.as_str() != Some(self.profile_scope.as_str()))
        {
            return Err("The selected account is unavailable".into());
        }
        let decoded = windows_folder_requests::decode(request)?;
        let (session, generation, cloud_root) = {
            let state = self
                .state
                .lock()
                .map_err(|_| "Account state is unavailable")?;
            if !state.online_authenticated
                || state.logout_pending
                || state.authenticating
                || state.refreshing
                || state.needs_refresh
            {
                return Err("Connect this account before using folder sync".into());
            }
            (
                state
                    .session
                    .clone()
                    .ok_or("Sign in before using folder sync")?,
                state.active_generation,
                state.root_configuration.clone(),
            )
        };
        if self.provider.folder_generation.load(Ordering::Acquire) != generation {
            let client = Arc::new(
                OpenCloudClient::new_with_proxy(
                    &session.server,
                    session.access_token.clone(),
                    &session.proxy,
                )
                .map_err(|_| "Could not prepare the connected account")?,
            );
            let (_, account_id, _, spaces, _) = verified_account_roots(&client, &session.server)?;
            let server = url::Url::parse(&session.server)
                .map_err(|_| "The account server is invalid")?
                .to_string();
            let issuer = session
                .expected_issuer
                .as_ref()
                .map(|issuer| url::Url::parse(issuer).map(|value| value.to_string()))
                .transpose()
                .map_err(|_| "The account issuer is invalid")?;
            let scope = AccountScope::new(
                self.profile_scope.as_str().into(),
                server,
                session.client_id.clone(),
                issuer,
                account_id.clone(),
            )
            .map_err(|_| "The verified folder account is invalid")?;
            let identity =
                serde_json::to_vec(&scope).map_err(|_| "The verified folder account is invalid")?;
            let name = format!("folder-sync-{:x}", sha2::Sha256::digest(&identity));
            let store = DpapiSessionStore::current_user()
                .map_err(|_| "Private Windows storage is unavailable")?;
            let parent = PinnedDirectory::open(store.local_edit_state_directory())
                .map_err(|_| "Private Windows storage is unavailable")?;
            let directory =
                PrivateDirectory::create_or_open_under(&parent, std::ffi::OsStr::new(&name))
                    .map_err(|_| "Private account storage could not be admitted")?;
            let (client, bandwidth_scope) = budget_client(
                client,
                &session,
                &self.profile_scope,
                &account_id,
                generation,
                &self.provider,
                self.session_store.as_ref(),
            )?;
            let origin = client
                .server_origin()
                .ok_or("The connected server origin is invalid")?;
            {
                let state = self
                    .state
                    .lock()
                    .map_err(|_| "Account state is unavailable")?;
                if state.active_generation != generation
                    || !state.online_authenticated
                    || state.logout_pending
                    || state.root_configuration != cloud_root
                    || state.session.as_ref().is_none_or(|current| {
                        current.server != session.server
                            || current.client_id != session.client_id
                            || current.expected_issuer != session.expected_issuer
                    })
                {
                    return Err("The account changed during folder setup".into());
                }
            }
            self.provider.install_folders(windows_folder_sync::Setup {
                source_admissions: windows_folder_sync::SourceAdmissions::Broker {
                    profile: self.profile_scope.clone(),
                    registry: self
                        .source_admissions
                        .clone()
                        .ok_or("Broker source admission is unavailable")?,
                },
                generation,
                scope,
                account_id,
                origin,
                client,
                spaces,
                directory,
                cloud_root,
            })?;
            self.provider
                .bandwidth
                .publish(&bandwidth_scope, generation)?;
        }
        let result = self.provider.folder_request(generation, decoded)?;
        if self.generation.load(Ordering::Acquire) != generation {
            return Err("The account changed during folder work".into());
        }
        Ok(result)
    }

    fn configure_root(&self, request: &Value) -> Result<Value, String> {
        let _folder_lifecycle = self
            .folder_lifecycle
            .lock()
            .map_err(|_| "Folder setup is unavailable")?;
        // Drain ordinary folder work before changing its cloud-root boundary.
        // Preserve the existing native-only configure path while C04 is gated.
        if WINDOWS_FOLDER_SYNC_ENABLED
            || self.provider.folder_generation.load(Ordering::Acquire) != 0
        {
            self.provider.disconnect()?;
        }
        let (session, generation, previous_root) = {
            let state = self
                .state
                .lock()
                .map_err(|_| "Account state is unavailable")?;
            let session = state
                .session
                .as_ref()
                .ok_or("Sign in before choosing a drive folder")?;
            if !state.online_authenticated || state.authenticating || state.refreshing {
                return Err("Connect this account before choosing a drive folder".into());
            }
            (
                session.clone(),
                state.active_generation,
                state.root_configuration.clone(),
            )
        };
        let path = request
            .get("cloud_root")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 32_000)
            .ok_or("Choose a valid local Windows folder")?;
        if path.chars().any(char::is_control) {
            return Err("Choose a valid local Windows folder".into());
        }
        let candidate = PathBuf::from(path);
        let root_lease = if let Some(previous) = previous_root.as_ref().filter(|previous| {
            previous
                .registration_ownership
                .as_ref()
                .is_some_and(|owner| owner.state != "prepared_not_registered")
        }) {
            pin_registered_configured_root(
                &candidate,
                raiun_cloudfiles_windows::ConfiguredRootIdentity {
                    volume_serial: previous.volume_serial,
                    file_index: previous.file_index,
                },
            )
            .map_err(root_error_text)?
        } else {
            pin_configured_root(&candidate).map_err(root_error_text)?
        };
        let identity = root_lease.identity();
        let registered_identity = previous_root.as_ref().and_then(|previous| {
            previous
                .registration_ownership
                .as_ref()
                .filter(|owner| owner.state != "prepared_not_registered")
                .map(|_| identity)
        });
        if overlaps_private_state(&candidate, registered_identity)? {
            return Err("The selected folder overlaps Raiun's private app data".into());
        }
        if let Some(previous) = previous_root.as_ref()
            && previous
                .registration_ownership
                .as_ref()
                .is_some_and(|owner| owner.state != "prepared_not_registered")
            && (identity.volume_serial != previous.volume_serial
                || identity.file_index != previous.file_index)
        {
            return Err("This account already owns a registered drive folder; disconnect it before choosing another folder".into());
        }
        if let Some(previous) = previous_root.as_ref()
            && Path::new(&previous.path).exists()
            && (identity.volume_serial != previous.volume_serial
                || identity.file_index != previous.file_index)
            && configured_roots_overlap(&candidate, Path::new(&previous.path))
                .map_err(root_error_text)?
        {
            return Err("The selected folder overlaps this account's existing drive folder".into());
        }
        let (personal_drive_id, account_id, personal_root_resource_id) =
            verified_personal_root_identity(&session)?;
        if previous_root.as_ref().is_some_and(|previous| {
            previous
                .registration_ownership
                .as_ref()
                .is_some_and(|owner| {
                    owner.state != "prepared_not_registered"
                        && (owner.account_id != account_id
                            || owner.personal_drive_id != personal_drive_id)
                })
        }) {
            return Err("This registered folder belongs to a different verified account".into());
        }
        if previous_root.as_ref().is_some_and(|previous| {
            previous
                .registration_ownership
                .as_ref()
                .is_some_and(|owner| {
                    owner.state != "prepared_not_registered"
                        && owner.personal_root_resource_id.as_deref()
                            != Some(personal_root_resource_id.as_str())
                })
        }) {
            return Err("The registered Personal drive root changed; choose a new local folder after safely removing the old registration".into());
        }
        let registration_state = previous_root
            .as_ref()
            .filter(|previous| {
                previous.volume_serial == identity.volume_serial
                    && previous.file_index == identity.file_index
                    && previous.server == session.server
                    && previous.client_id == session.client_id
            })
            .and_then(|previous| previous.registration_ownership.as_ref())
            .map(|owner| owner.state.clone())
            .unwrap_or_else(|| "prepared_not_registered".into());
        let configuration = RootConfiguration {
            profile_scope: self.profile_scope.as_str().into(),
            server: session.server.clone(),
            client_id: session.client_id.clone(),
            issuer: session.expected_issuer.clone(),
            path: candidate.to_string_lossy().into_owned(),
            volume_serial: identity.volume_serial,
            file_index: identity.file_index,
            registration_ownership: Some(RegistrationOwnership {
                state: registration_state,
                account_id,
                personal_drive_id,
                personal_root_resource_id: Some(personal_root_resource_id),
                volume_serial: identity.volume_serial,
                file_index: identity.file_index,
            }),
            valid: true,
        };
        let bytes = encode_root_configuration(&configuration)?;
        if bytes.len() > MAX_ROOT_CONFIG_BYTES {
            return Err("The selected folder configuration exceeds the storage limit".into());
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| "Account state is unavailable")?;
        // Hold the state lock across persistence so logout/auth refresh cannot
        // change the identity between validation and durable publication.
        if state.active_generation != generation
            || !state.online_authenticated
            || state.authenticating
            || state.refreshing
            || state.session.as_ref().is_none_or(|current| {
                current.server != configuration.server
                    || current.client_id != configuration.client_id
            })
        {
            return Err("Account changed while configuring the drive folder".into());
        }
        if overlaps_private_state(&candidate, registered_identity)? {
            return Err("The selected folder overlaps Raiun's private app data".into());
        }
        let registered_root = configuration
            .registration_ownership
            .as_ref()
            .is_some_and(|owner| owner.state != "prepared_not_registered");
        let inspect_current_root = || {
            let lease = if registered_root {
                pin_registered_configured_root(&candidate, identity)
            } else {
                pin_configured_root(&candidate)
            }?;
            Ok::<_, raiun_cloudfiles_windows::Error>(lease.identity())
        };
        let current_identity = inspect_current_root().map_err(root_error_text)?;
        if current_identity != identity {
            return Err("The selected folder changed while it was being configured".into());
        }
        self.session_store
            .save_root_config(
                &configuration.profile_scope,
                &configuration.server,
                &configuration.client_id,
                &bytes,
            )
            .map_err(|_| "Could not save the drive folder in private Windows storage")?;
        let still_same_root = inspect_current_root().is_ok_and(|current| current == identity);
        if !still_same_root {
            state.root_configuration = None;
            let cleared = self
                .session_store
                .remove_root_config(
                    &configuration.profile_scope,
                    &configuration.server,
                    &configuration.client_id,
                )
                .is_ok();
            return Err(if cleared {
                "The selected folder changed while setup was being saved; choose it again".into()
            } else {
                "The selected folder changed and its saved setup could not be cleared; no drive was mounted".into()
            });
        }
        state.root_configuration = Some(configuration.clone());
        // The lifecycle hook reacquires account state. Keep persistence atomic
        // above, then release the guard before entering that hook.
        drop(state);
        drop(root_lease);
        Self::maybe_connect_provider_with_exclusions(
            &self.session_store,
            &self.state,
            &self.provider,
            self.source_admissions.as_ref(),
        )?;
        let state = self
            .state
            .lock()
            .map_err(|_| "Account state is unavailable")?;
        let current = state
            .root_configuration
            .as_ref()
            .filter(|current| {
                current.server == configuration.server
                    && current.client_id == configuration.client_id
                    && current.path == configuration.path
                    && current.volume_serial == configuration.volume_serial
                    && current.file_index == configuration.file_index
                    && current
                        .registration_ownership
                        .as_ref()
                        .map(|owner| &owner.account_id)
                        == configuration
                            .registration_ownership
                            .as_ref()
                            .map(|owner| &owner.account_id)
            })
            .filter(|_| state.active_generation == generation)
            .ok_or("The account or root changed while connecting the drive folder")?;
        Ok(json!({
            "configured": true,
            "cloud_root": current.path,
            "mounted": self.provider.is_connected(),
            "provider_supported": self.provider.activation_enabled(),
            "root_identity_bound": current.registration_ownership.is_some(),
            "registration_state": current.registration_ownership.as_ref().map(|owner| owner.state.as_str()),
        }))
    }

    /// Normal lifecycle entry point. It is called after authentication,
    /// session refresh, and root configuration. Every connection still requires
    /// exact account/root ownership and durable recovery preparation. Ordinary
    /// unit-test instances stay disconnected unless explicitly opted in.
    #[cfg(test)]
    fn maybe_connect_provider(
        session_store: &Arc<dyn SessionStore>,
        state: &Arc<Mutex<AccountState>>,
        provider: &Arc<ProviderManager>,
    ) -> Result<(), String> {
        Self::maybe_connect_provider_with_exclusions(session_store, state, provider, None)
    }

    fn maybe_connect_provider_with_exclusions(
        session_store: &Arc<dyn SessionStore>,
        state: &Arc<Mutex<AccountState>>,
        provider: &Arc<ProviderManager>,
        admissions: Option<&SharedSourceAdmissions>,
    ) -> Result<(), String> {
        if provider.activation_enabled() {
            let has_ready_root = state.lock().is_ok_and(|state| {
                state.online_authenticated
                    && !state.authenticating
                    && !state.refreshing
                    && state.session.is_some()
                    && state.root_configuration.is_some()
            });
            if !has_ready_root {
                return Ok(());
            }
            Self::connect_verified_root_with_exclusions(session_store, state, provider, admissions)
        } else {
            Ok(())
        }
    }

    /// Establish a provider connection only from a freshly verified session,
    /// the exact persisted Personal-drive ownership record, a repinned local
    /// directory identity, and a current-user DPAPI recovery provider.
    #[cfg(test)]
    fn connect_verified_root(
        session_store: &Arc<dyn SessionStore>,
        state: &Arc<Mutex<AccountState>>,
        provider: &Arc<ProviderManager>,
    ) -> Result<(), String> {
        Self::connect_verified_root_with_exclusions(session_store, state, provider, None)
    }

    fn connect_verified_root_with_exclusions(
        session_store: &Arc<dyn SessionStore>,
        state_mutex: &Arc<Mutex<AccountState>>,
        provider: &Arc<ProviderManager>,
        admissions: Option<&SharedSourceAdmissions>,
    ) -> Result<(), String> {
        let (session, generation, configuration) = {
            let state = state_mutex
                .lock()
                .map_err(|_| "Account state is unavailable")?;
            if !state.online_authenticated || state.authenticating || state.refreshing {
                return Err("Connect the account before mounting its Windows drive".into());
            }
            let session = state
                .session
                .clone()
                .ok_or("Sign in before mounting the Windows drive")?;
            let configuration = state
                .root_configuration
                .clone()
                .ok_or("Choose a drive folder before connecting the Windows provider")?;
            (session, state.active_generation, configuration)
        };
        if !configuration.valid
            || configuration.server != session.server
            || configuration.client_id != session.client_id
        {
            return Err("The saved drive folder does not match this account session".into());
        }
        let owner = configuration
            .registration_ownership
            .as_ref()
            .ok_or("The saved drive folder has no verified ownership record")?;
        validate_registration_ownership(
            owner,
            &session.server,
            configuration.volume_serial,
            configuration.file_index,
        )?;

        let (personal_drive_id, account_id, personal_root_resource_id) =
            verified_personal_root_identity(&session)?;
        if personal_drive_id != owner.personal_drive_id
            || account_id != owner.account_id
            || owner.personal_root_resource_id.as_deref()
                != Some(personal_root_resource_id.as_str())
        {
            return Err("The verified Personal drive does not match this registered folder".into());
        }
        let identity = raiun_cloudfiles_windows::ConfiguredRootIdentity {
            volume_serial: configuration.volume_serial,
            file_index: configuration.file_index,
        };
        let _root_lease = if owner.state == "prepared_not_registered" {
            pin_configured_root(Path::new(&configuration.path))
        } else {
            pin_registered_configured_root(Path::new(&configuration.path), identity)
        }
        .map_err(root_error_text)?;
        let current_identity = _root_lease.identity();
        if current_identity != identity {
            return Err("The saved Windows drive folder identity changed".into());
        }
        let binding = ActiveProviderBinding {
            generation,
            path: PathBuf::from(&configuration.path),
            identity,
            personal_space_id: owner.personal_drive_id.clone(),
            personal_root_resource_id: personal_root_resource_id.clone(),
        };
        let connection_current = provider.connection_matches(binding.clone())?;
        let mut save_admission = provider.prepare_existing_file_save_worker(
            &binding,
            state_mutex,
            session_store,
            connection_current,
        )?;
        if connection_current
            && save_admission
                .as_ref()
                .is_none_or(|admission| admission.connection_current)
        {
            let state = state_mutex
                .lock()
                .map_err(|_| "Account state is unavailable")?;
            if state.active_generation != generation
                || !state.online_authenticated
                || state.authenticating
                || state.refreshing
                || state.root_configuration.as_ref() != Some(&configuration)
                || state.session.as_ref().is_none_or(|current| {
                    current.server != session.server
                        || current.client_id != session.client_id
                        || current.access_token != session.access_token
                })
            {
                return Err("The Windows account changed during drive inspection".into());
            }
            // The worker confirmed the exact active binding. Repeated hooks
            // must not overwrite its committed registration with pending.
            drop(state);
            if let Some(admission) = save_admission.as_mut() {
                admission.owner.check_existing_file_save_account(&binding)?;
                admission.committed = true;
            }
            return Ok(());
        }

        let client = Arc::new(
            OpenCloudClient::new_with_proxy(
                &session.server,
                session.access_token.clone(),
                &session.proxy,
            )
            .map_err(|_| "Could not create an authenticated Windows drive client")?,
        );
        let server_origin = client
            .server_origin()
            .ok_or("The authenticated server origin is invalid")?;
        let (client, bandwidth_scope) = budget_client(
            client,
            &session,
            &configuration.profile_scope,
            &account_id,
            generation,
            provider,
            session_store.as_ref(),
        )?;
        let scope = raiun_cloudfiles_windows::ProviderScope::new(
            &client,
            configuration.profile_scope.clone(),
            account_id,
            server_origin,
        )
        .map_err(|_| "Could not bind the Windows provider to this account session")?;
        if scope.token_generation() == 0 {
            return Err("The authenticated Windows provider generation is invalid".into());
        }
        let recovery: Arc<dyn raiun_cloudfiles_windows::EditRecoveryProvider> = Arc::new(
            raiun_cloudfiles_windows::DurableEditRecoveryProvider::current_user(
                scope.clone(),
                identity,
            )
            .map_err(|_| "Could not prepare current-user durable edit recovery")?,
        );
        let identity_catalog = recovery
            .identity_catalog()
            .ok_or("Could not prepare the durable Windows identity catalog")?;
        // This parent is prepared with the current user's protected DACL;
        // cache construction pins it and refuses unsafe existing members.
        // Actual data is scoped by verified origin/account/Space/root IDs.
        let cache_parent = DpapiSessionStore::current_user()
            .map_err(|_| "Could not prepare private Windows cache storage")?;
        let cache = raiun_cache::Cache::open(cache_parent.local_edit_state_directory(), 1 << 30)
            .map_err(|_| "Could not safely open the Windows content cache")?;
        let backend = Arc::new(
            raiun_cloudfiles_windows::OpenCloudPlaceholderBackend::new_with_identity_catalog_and_cache(
                client,
                scope,
                identity,
                identity_catalog,
                cache,
            )
            .map_err(|_| "Could not prepare the authenticated Windows drive")?,
        );
        // The exact Personal Space/root identity is checked again by runtime
        // preparation before it becomes the native sync-root FileIdentity.

        if let Some(admissions) = admissions {
            // Clone and release the broker snapshot before provider/route locks.
            // Historical scopes are exclusions, never current unlock authority.
            let snapshot = admissions
                .lock()
                .map_err(|_| "Vault exclusions are unavailable")?
                .clone();
            let record = snapshot
                .profiles()
                .get(&configuration.profile_scope)
                .ok_or("Vault exclusion profile is unavailable")?;
            let locations = record
                .vault_reservations()
                .iter()
                .map(|row| (row.space_id().to_owned(), row.root_path().to_owned()))
                .collect::<Vec<_>>();
            backend
                .restore_vault_exclusions(identity, &locations)
                .map_err(|_| "Could not restore encrypted-location exclusions")?;
        }
        {
            let state = state_mutex
                .lock()
                .map_err(|_| "Account state is unavailable")?;
            if state.active_generation != generation
                || !state.online_authenticated
                || state.authenticating
                || state.refreshing
                || state.session.as_ref().is_none_or(|current| {
                    current.server != session.server
                        || current.client_id != session.client_id
                        || current.access_token != session.access_token
                })
                || state.root_configuration.as_ref() != Some(&configuration)
            {
                backend.revoke();
                return Err("The Windows account changed during provider preflight".into());
            }
        }

        // Persist an indeterminate transition before native registration. If
        // the process exits between CfRegisterSyncRoot and the final commit,
        // restart will verify the exact OS registration instead of treating
        // an already-registered root as a fresh empty folder.
        let mut connecting = configuration.clone();
        if let Some(ownership) = connecting.registration_ownership.as_mut() {
            ownership.state = "registration_pending".into();
        }
        let pending_bytes = match encode_root_configuration(&connecting) {
            Ok(bytes) => bytes,
            Err(error) => {
                backend.revoke();
                return Err(error);
            }
        };
        {
            let mut state = match state_mutex.lock() {
                Ok(state) => state,
                Err(_) => {
                    backend.revoke();
                    return Err("Account state is unavailable".into());
                }
            };
            if state.active_generation != generation
                || !state.online_authenticated
                || state.authenticating
                || state.refreshing
                || state.session.as_ref().is_none_or(|current| {
                    current.server != session.server
                        || current.client_id != session.client_id
                        || current.access_token != session.access_token
                })
                || state.root_configuration.as_ref() != Some(&configuration)
            {
                backend.revoke();
                return Err("The Windows account changed before registration".into());
            }
            if session_store
                .save_root_config(
                    &connecting.profile_scope,
                    &connecting.server,
                    &connecting.client_id,
                    &pending_bytes,
                )
                .is_err()
            {
                backend.revoke();
                return Err("Could not persist Windows registration intent".into());
            }
            state.root_configuration = Some(connecting.clone());
        }

        provider.connect(
            PathBuf::from(&configuration.path),
            generation,
            identity,
            owner.state != "prepared_not_registered",
            owner.personal_drive_id.clone(),
            owner
                .personal_root_resource_id
                .clone()
                .ok_or("The saved Windows drive has no verified Personal root identity")?,
            Arc::clone(&backend),
            recovery,
            bandwidth_scope.bytes().to_vec(),
            Arc::clone(session_store),
        )?;

        provider.bandwidth.publish(&bandwidth_scope, generation)?;

        let persist_result = (|| -> Result<(), String> {
            let mut updated = configuration.clone();
            if let Some(ownership) = updated.registration_ownership.as_mut() {
                ownership.state = "registered".into();
            }
            let bytes = encode_root_configuration(&updated)?;
            let mut state = state_mutex
                .lock()
                .map_err(|_| "Account state is unavailable")?;
            if state.active_generation != generation
                || !state.online_authenticated
                || state.authenticating
                || state.refreshing
                || state.session.as_ref().is_none_or(|current| {
                    current.server != session.server
                        || current.client_id != session.client_id
                        || current.access_token != session.access_token
                })
                || state.root_configuration.as_ref() != Some(&connecting)
            {
                Err("The Windows account changed while its provider was connecting".to_owned())
            } else {
                session_store
                    .save_root_config(
                        &updated.profile_scope,
                        &updated.server,
                        &updated.client_id,
                        &bytes,
                    )
                    .map_err(|_| "Could not persist Windows registration ownership".to_owned())
                    .map(|()| state.root_configuration = Some(updated))
            }
        })();
        if let Err(error) = persist_result {
            let _ = provider.disconnect();
            return Err(error);
        }
        if let Some(admission) = save_admission.as_mut() {
            admission.owner.check_existing_file_save_account(&binding)?;
            admission.committed = true;
        }
        Ok(())
    }

    fn maybe_start_refresh(&self) -> Result<(), String> {
        {
            let mut worker = self
                .refresh_thread
                .lock()
                .map_err(|_| "Session refresh worker state is unavailable")?;
            if worker.as_ref().is_some_and(JoinHandle::is_finished) {
                if let Some(finished) = worker.take() {
                    let _ = finished.join();
                }
            }
        }

        let (session, generation) = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| "Account state is unavailable")?;
            if state.retiring {
                return Ok(());
            }
            let Some(session) = state.session.clone() else {
                return Ok(());
            };
            // A startup/transport failure leaves a retained session unverified.
            // Retry it after the existing backoff even when its token is fresh.
            let refresh_due = state.needs_refresh
                || !state.online_authenticated
                || session.expires_at
                    <= unix_time_now().saturating_add(WINDOWS_REFRESH_LEAD_SECONDS);
            if state.logout_pending
                || !refresh_due
                || state.authenticating
                || state.refreshing
                || state.refresh_retry_at > unix_time_now()
            {
                return Ok(());
            }
            let generation = self.next_generation()?;
            state.active_generation = generation;
            state.needs_refresh = false;
            state.refreshing = true;
            state.online_authenticated = false;
            (session, generation)
        };

        let state = Arc::clone(&self.state);
        let current_generation = Arc::clone(&self.generation);
        let store = Arc::clone(&self.session_store);
        let profile_scope = self.profile_scope.clone();
        let provider = Arc::clone(&self.provider);
        let admissions = self.source_admissions.clone();
        let worker = thread::spawn(move || {
            let mut refreshed = session.clone();
            let result = refreshed.refresh_classified();
            match result {
                Ok(()) => {
                    if let Err(error) = provider.disconnect() {
                        if let Ok(mut state) = state.lock()
                            && current_generation.load(Ordering::Acquire) == generation
                            && state.active_generation == generation
                            && state.refreshing
                        {
                            state.refreshing = false;
                            state.online_authenticated = false;
                            state.refresh_retry_at = unix_time_now().saturating_add(30);
                            state.error = Some(error);
                        }
                        return;
                    }
                    let mut cleanup = false;
                    if let Ok(mut state) = state.lock()
                        && current_generation.load(Ordering::Acquire) == generation
                        && state.active_generation == generation
                        && state.refreshing
                    {
                        match store.save_pending(profile_scope.as_str(), &refreshed) {
                            Ok(()) => {
                                state.session = Some(refreshed);
                                state.online_authenticated = true;
                                state.refreshing = false;
                                state.refresh_retry_at = 0;
                                state.error = None;
                                state.session_cleanup_uncertain = false;
                            }
                            Err(error) => {
                                state.session = None;
                                state.root_configuration = None;
                                state.online_authenticated = false;
                                state.refreshing = false;
                                state.error = Some(error);
                                cleanup = true;
                            }
                        }
                    }
                    if cleanup {
                        let uncertain = revoke_and_remove(&store, &profile_scope, &session);
                        if let Ok(mut state) = state.lock() {
                            state.session_cleanup_uncertain = uncertain;
                        }
                    } else if let Err(error) = WindowsAgent::maybe_connect_provider_with_exclusions(
                        &store,
                        &state,
                        &provider,
                        admissions.as_ref(),
                    ) {
                        if let Ok(mut state) = state.lock()
                            && state.active_generation == generation
                        {
                            state.error = Some(error);
                        }
                    }
                }
                Err(error) => {
                    let is_rejected = matches!(error, auth::RefreshError::Rejected(_));
                    let message = error.to_string();
                    let provider_error = if is_rejected {
                        provider.disconnect().err()
                    } else {
                        None
                    };
                    let mut cleanup = false;
                    if let Ok(mut state) = state.lock()
                        && current_generation.load(Ordering::Acquire) == generation
                        && state.active_generation == generation
                        && state.refreshing
                    {
                        state.refreshing = false;
                        state.online_authenticated = false;
                        state.refresh_retry_at = unix_time_now().saturating_add(30);
                        state.error = Some(provider_error.unwrap_or(message));
                        if is_rejected {
                            state.session = None;
                            state.root_configuration = None;
                            cleanup = true;
                        }
                    }
                    if cleanup {
                        let uncertain = revoke_and_remove(&store, &profile_scope, &session);
                        if let Ok(mut state) = state.lock() {
                            state.session_cleanup_uncertain = uncertain;
                        }
                    }
                }
            }
        });
        *self
            .refresh_thread
            .lock()
            .map_err(|_| "Session refresh worker state is unavailable")? = Some(worker);
        Ok(())
    }

    fn begin_auth(self: &Arc<Self>, request: &Value) -> Result<Value, String> {
        let _credential_operation = self
            .vault_credential_operation
            .lock()
            .map_err(|_| "Vault credential changes are unavailable")?;

        {
            let state = self
                .state
                .lock()
                .map_err(|_| "Account state is unavailable")?;
            if state.session.is_some() {
                return Err(
                    "This Windows account is already connected. Sign out before signing in again"
                        .into(),
                );
            }
            if state.authenticating {
                return Err("Sign-in is already in progress".into());
            }
        }
        self.provider.disconnect()?;
        self.join_finished_auth()?;
        // A failed refresh may have cleared credentials without explicit logout.
        // New sign-in must never inherit the prior subject's preferences owner.
        self.provider.bandwidth.clear();
        let raw = request
            .get("server")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or("Missing server")?;
        let server = if raw.contains("://") {
            raw.to_owned()
        } else {
            format!("https://{raw}")
        };
        let client_id = request
            .get("client_id")
            .and_then(Value::as_str)
            .unwrap_or("");
        let generation = self.next_generation()?;
        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| "Account state is unavailable")?;
            if state.session.is_some() || state.authenticating {
                return Err("Account state changed while starting sign-in".into());
            }
            state.authenticating = true;
            state.active_generation = generation;
            state.error = None;
        }
        let flow = (|| {
            if WINDOWS_VAULT_SESSIONS_ENABLED {
                windows_vault_credentials::revoke_profile(
                    &VaultCredentialStore {
                        store: self.session_store.as_ref(),
                        profile: &self.profile_scope,
                    },
                    &self.profile_scope,
                )?;
            }
            let proxy = self.provider.proxy.auth_proxy(
                &self.profile_scope,
                generation,
                &ProxyStore {
                    store: self.session_store.as_ref(),
                    profile: &self.profile_scope,
                },
            )?;
            if proxy == raiun_opencloud::ProxyConfig::System {
                auth::AuthFlow::begin(&server, client_id)
            } else {
                auth::AuthFlow::begin_with_proxy(&server, client_id, proxy)
            }
        })();
        let flow = match flow {
            Ok(flow) => flow,
            Err(error) => {
                if let Ok(mut state) = self.state.lock()
                    && state.active_generation == generation
                {
                    state.authenticating = false;
                    state.error = Some(error.clone());
                }
                return Err(error);
            }
        };
        let public_info = flow.public_info();
        let (expected_server, expected_client_id) = flow.configured_identity();
        let expected_server = expected_server.to_owned();
        let expected_client_id = expected_client_id.to_owned();
        {
            let state = self
                .state
                .lock()
                .map_err(|_| "Account state is unavailable")?;
            if state.active_generation != generation
                || !state.authenticating
                || state.session.is_some()
                || self.generation.load(Ordering::Acquire) != generation
            {
                return Err("Sign-in was cancelled while preparing its proxy route".into());
            }
        }
        let previous_identity = self.session_store.revoke_active();
        let previous_identity = match previous_identity {
            Ok(identity) => identity,
            Err(_) => {
                if let Ok(mut state) = self.state.lock() {
                    if state.active_generation == generation {
                        state.authenticating = false;
                        state.error = Some(
                            "Could not revoke the previous saved session; sign-in was not started"
                                .into(),
                        );
                    }
                }
                return Err(
                    "Could not revoke the previous saved session; sign-in was not started".into(),
                );
            }
        };
        if let Some((scope, server, client_id)) = previous_identity
            && self
                .session_store
                .remove(&scope, &server, &client_id)
                .is_err()
        {
            if let Ok(mut state) = self.state.lock() {
                if state.active_generation == generation {
                    state.authenticating = false;
                    state.session_cleanup_uncertain = true;
                    state.error = Some(
                        "Could not remove the previous saved session; sign-in was not started"
                            .into(),
                    );
                }
            }
            return Err(
                "Could not remove the previous saved session; sign-in was not started".into(),
            );
        }
        let state = Arc::clone(&self.state);
        let current_generation = Arc::clone(&self.generation);
        let store = Arc::clone(&self.session_store);
        let profile_scope = self.profile_scope.clone();
        let provider = Arc::clone(&self.provider);
        let admissions = self.source_admissions.clone();
        let thread = thread::spawn(move || {
            let result = flow
                .wait_with_cancel(|| current_generation.load(Ordering::Acquire) != generation)
                .and_then(|session| {
                    if session.server == expected_server && session.client_id == expected_client_id
                    {
                        Ok(session)
                    } else {
                        Err("Sign-in returned an unexpected account identity".to_owned())
                    }
                });
            match result {
                Ok(session) if current_generation.load(Ordering::Acquire) == generation => {
                    if let Err(error) = store.save_pending(profile_scope.as_str(), &session) {
                        if current_generation.load(Ordering::Acquire) == generation {
                            if let Ok(mut state) = state.lock() {
                                if state.active_generation == generation {
                                    state.error = Some(error);
                                    state.authenticating = false;
                                }
                            }
                        }
                        return;
                    }
                    if current_generation.load(Ordering::Acquire) != generation {
                        record_cleanup_failure(&state, &store, &profile_scope, &session);
                        return;
                    }
                    let root_configuration =
                        load_root_configuration(&store, &profile_scope, &session)
                            .ok()
                            .flatten();
                    store.before_publish();
                    let installed = if let Ok(mut state) = state.lock() {
                        if state.authenticating && state.active_generation == generation {
                            match store.publish_active(profile_scope.as_str(), &session) {
                                Ok(()) => {
                                    state.session = Some(session.clone());
                                    state.root_configuration = root_configuration;
                                    state.online_authenticated = true;
                                    state.needs_refresh = false;
                                    state.refreshing = false;
                                    state.refresh_retry_at = 0;
                                    state.authenticating = false;
                                    state.error = None;
                                    state.session_cleanup_uncertain = false;
                                    true
                                }
                                Err(error) => {
                                    state.authenticating = false;
                                    state.error = Some(error);
                                    false
                                }
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    };
                    if !installed {
                        record_cleanup_failure(&state, &store, &profile_scope, &session);
                    } else if let Err(error) = WindowsAgent::maybe_connect_provider_with_exclusions(
                        &store,
                        &state,
                        &provider,
                        admissions.as_ref(),
                    ) {
                        if let Ok(mut state) = state.lock()
                            && state.active_generation == generation
                        {
                            state.error = Some(error);
                        }
                    }
                }
                // The callback completed after cancellation but before the
                // session was saved. Do not remove a prior saved identity.
                Ok(_session) => {}
                Err(error) => {
                    if current_generation.load(Ordering::Acquire) == generation {
                        if let Ok(mut state) = state.lock() {
                            if state.active_generation == generation {
                                state.authenticating = false;
                                if error != "Sign-in was cancelled" {
                                    state.error = Some(error);
                                }
                            }
                        }
                    }
                }
            }
        });
        *self
            .auth_thread
            .lock()
            .map_err(|_| "Sign-in worker state is unavailable")? = Some(thread);
        Ok(public_info)
    }

    fn cancel_auth(&self) -> Result<Value, String> {
        let active = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| "Account state is unavailable")?;
            let active = state.authenticating || state.refreshing;
            if active {
                state.active_generation = self.next_generation()?;
                state.authenticating = false;
                if state.refreshing {
                    state.refreshing = false;
                    state.online_authenticated = false;
                    state.refresh_retry_at = unix_time_now().saturating_add(30);
                }
                state.error = None;
            }
            active
        };
        if active {
            // Revoke callbacks as soon as the account generation changes.
            // Do this before waiting for a possibly slow browser/refresh
            // worker so the old token cannot continue serving Cloud Files
            // requests during cancellation.
            let disconnect_result = self.provider.disconnect();
            let handle = self
                .auth_thread
                .lock()
                .map_err(|_| "Sign-in worker state is unavailable")?
                .take();
            if let Some(handle) = handle {
                handle
                    .join()
                    .map_err(|_| "Sign-in worker stopped unexpectedly")?;
            }
            let handle = self
                .refresh_thread
                .lock()
                .map_err(|_| "Session refresh worker state is unavailable")?
                .take();
            if let Some(handle) = handle {
                handle
                    .join()
                    .map_err(|_| "Session refresh worker stopped unexpectedly")?;
            }
            disconnect_result?;
        }
        let cleanup_uncertain = self
            .state
            .lock()
            .map_err(|_| "Account state is unavailable")?
            .session_cleanup_uncertain;
        Ok(json!({"cancelled":active,"cleanup_uncertain":cleanup_uncertain}))
    }

    fn logout(&self) -> Result<Value, String> {
        let _credential_operation = self
            .vault_credential_operation
            .lock()
            .map_err(|_| "Vault credential changes are unavailable")?;
        if WINDOWS_VAULT_SESSIONS_ENABLED {
            windows_vault_credentials::revoke_profile(
                &VaultCredentialStore {
                    store: self.session_store.as_ref(),
                    profile: &self.profile_scope,
                },
                &self.profile_scope,
            )?;
        }

        self.provider.bandwidth.clear();
        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| "Account state is unavailable")?;
            // Revoke both queued worker commands and new lifecycle admission
            // before disconnect. A failed logout retains credentials/recovery
            // for retry, but cannot reconnect a drive from that old session.
            state.active_generation = self.next_generation()?;
            state.online_authenticated = false;
            state.logout_pending = true;
            state.needs_refresh = state.session.is_some();
        }
        let _ = self.cancel_auth()?;
        self.provider.disconnect()?;
        let (session, root_configuration) = {
            let state = self
                .state
                .lock()
                .map_err(|_| "Account state is unavailable")?;
            (state.session.clone(), state.root_configuration.clone())
        };
        let preserve_registered_root = root_configuration
            .as_ref()
            .and_then(|configuration| configuration.registration_ownership.as_ref())
            .is_some_and(|ownership| ownership.state == "registered");
        // The active pointer is the only startup restore authority. Revoke it
        // first so a later blob cleanup failure cannot resurrect the session.
        let pointer_identity = self.session_store.revoke_active()?;
        let mut cleanup_uncertain = false;
        if let Some((scope, server, client_id)) = pointer_identity {
            cleanup_uncertain |= self
                .session_store
                .remove(&scope, &server, &client_id)
                .is_err();
            if !preserve_registered_root {
                cleanup_uncertain |= self
                    .session_store
                    .remove_root_config(&scope, &server, &client_id)
                    .is_err();
            }
        }
        if let Some(session) = &session {
            cleanup_uncertain |= self
                .session_store
                .remove(
                    self.profile_scope.as_str(),
                    &session.server,
                    &session.client_id,
                )
                .is_err();
            if !preserve_registered_root {
                cleanup_uncertain |= self
                    .session_store
                    .remove_root_config(
                        self.profile_scope.as_str(),
                        &session.server,
                        &session.client_id,
                    )
                    .is_err();
            }
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| "Account state is unavailable")?;
        state.session = None;
        state.root_configuration = None;
        state.logout_pending = false;
        state.online_authenticated = false;
        state.needs_refresh = false;
        state.refreshing = false;
        state.session_cleanup_uncertain = cleanup_uncertain;
        state.error = cleanup_uncertain.then(|| {
            "Signed out, but a protected session file could not be removed; it will not be restored"
                .into()
        });
        Ok(json!({"logged_out":true,"session_cleanup_uncertain":cleanup_uncertain}))
    }

    fn begin_retirement(&self, expected_generation: u64) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "Account state is unavailable")?;
        if state.active_generation != expected_generation
            || self.generation.load(Ordering::Acquire) != expected_generation
        {
            return Err("The account changed; refresh and try again".into());
        }
        if state.session_cleanup_uncertain {
            return Err("The saved sign-in state is uncertain; resolve sign-out first".into());
        }
        if state.retiring {
            return Err("This account is already being removed".into());
        }
        // Close request admission before incrementing the generation. A late
        // sign-in/refresh completion and queued provider commands become stale.
        state.retiring = true;
        match self.next_generation() {
            Ok(generation) => {
                state.active_generation = generation;
                state.online_authenticated = false;
                state.needs_refresh = false;
                state.logout_pending = true;
                Ok(())
            }
            Err(error) => {
                state.retiring = false;
                Err(error)
            }
        }
    }

    fn cancel_retirement(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.retiring = false;
            state.logout_pending = false;
        }
    }

    fn next_generation(&self) -> Result<u64, String> {
        let mut current = self.generation.load(Ordering::Acquire);
        loop {
            let next = current
                .checked_add(1)
                .ok_or_else(|| "Sign-in generation is exhausted".to_string())?;
            match self.generation.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.provider.authorize_generation(next);
                    self.vault_sessions
                        .logout_account(&self.profile_scope)
                        .map_err(|_| "Could not revoke the account vault sessions")?;
                    return Ok(next);
                }
                Err(actual) => current = actual,
            }
        }
    }

    fn join_finished_auth(&self) -> Result<(), String> {
        let handle = self
            .auth_thread
            .lock()
            .map_err(|_| "Sign-in worker state is unavailable")?
            .take();
        if let Some(handle) = handle {
            if !handle.is_finished() {
                *self
                    .auth_thread
                    .lock()
                    .map_err(|_| "Sign-in worker state is unavailable")? = Some(handle);
                return Err("The previous sign-in is still stopping".into());
            }
            handle
                .join()
                .map_err(|_| "Sign-in worker stopped unexpectedly")?;
        }
        Ok(())
    }

    fn stop_and_join(&self) -> Result<(), String> {
        self.provider.cancel_fresh_close();
        let _ = self.cancel_auth()?;
        let handle = self
            .auth_thread
            .lock()
            .map_err(|_| "Sign-in worker state is unavailable")?
            .take();
        if let Some(handle) = handle {
            handle
                .join()
                .map_err(|_| "Sign-in worker stopped unexpectedly")?;
        }
        let refresh = self
            .refresh_thread
            .lock()
            .map_err(|_| "Session refresh worker state is unavailable")?
            .take();
        if let Some(handle) = refresh {
            handle
                .join()
                .map_err(|_| "Session refresh worker stopped unexpectedly")?;
        }
        let disconnect = self.provider.disconnect();
        let worker = self.stop_fresh_close_worker();
        disconnect?;
        worker?;
        Ok(())
    }
}

impl Drop for WindowsAgent {
    fn drop(&mut self) {
        self.provider.cancel_fresh_close();
        let worker = self
            .fresh_close_worker
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(worker) = worker {
            let _ = worker.stop();
        }
    }
}

fn record_cleanup_failure(
    state: &Arc<Mutex<AccountState>>,
    store: &Arc<dyn SessionStore>,
    profile_scope: &str,
    session: &auth::Session,
) {
    // A cancelled flow only staged an unreferenced blob. It never published
    // startup restore authority, so failed cleanup can leave private bytes but
    // cannot resurrect the cancelled session on the next launch.
    let cleanup_uncertain = store
        .remove(profile_scope, &session.server, &session.client_id)
        .is_err();
    if !cleanup_uncertain {
        return;
    }
    if let Ok(mut state) = state.lock() {
        state.session_cleanup_uncertain = true;
        state.error = Some(
            "Sign-in was cancelled, but Raiun could not remove the saved session from Windows protected storage".into(),
        );
    }
}

fn revoke_and_remove(
    store: &Arc<dyn SessionStore>,
    profile_scope: &str,
    session: &auth::Session,
) -> bool {
    let pointer = store.revoke_active();
    let mut uncertain = pointer.is_err();
    if let Ok(Some((scope, server, client_id))) = pointer {
        uncertain |= store.remove(&scope, &server, &client_id).is_err();
    }
    // Try the exact identity even when pointer reading/revocation failed.
    // If both operations fail, startup may retry refresh but never marks the
    // session connected without a successful token response.
    uncertain |= store
        .remove(profile_scope, &session.server, &session.client_id)
        .is_err();
    uncertain
}

fn encode_root_configuration(configuration: &RootConfiguration) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&json!({
        "version": 3,
        "profile_scope": configuration.profile_scope,
        "server": configuration.server,
        "client_id": configuration.client_id,
        "issuer": configuration.issuer,
        "path": configuration.path,
        "volume_serial": configuration.volume_serial,
        "file_index": configuration.file_index,
        "registration_ownership": configuration.registration_ownership.as_ref().map(|owner| json!({
            "version": 2,
            "state": owner.state,
            "account_id": owner.account_id,
            "personal_drive_id": owner.personal_drive_id,
            "personal_root_resource_id": owner.personal_root_resource_id,
            "volume_serial": owner.volume_serial,
            "file_index": owner.file_index,
        })),
    }))
    .map_err(|_| "Could not encode the drive folder configuration".into())
}

fn load_root_configuration(
    store: &Arc<dyn SessionStore>,
    expected_profile: &str,
    session: &auth::Session,
) -> Result<Option<RootConfiguration>, String> {
    let Some(bytes) =
        store.load_root_config(expected_profile, &session.server, &session.client_id)?
    else {
        return Ok(None);
    };
    let mut configuration = decode_root_metadata(&bytes, expected_profile)?;
    // Metadata alone only reserves a local path. Restoring a provider still
    // requires exact binding to this real session, including issuer identity.
    if configuration.server != session.server
        || configuration.client_id != session.client_id
        || configuration.issuer != session.expected_issuer
    {
        return Err("Saved drive folder configuration identity does not match".into());
    }
    let expected = raiun_cloudfiles_windows::ConfiguredRootIdentity {
        volume_serial: configuration.volume_serial,
        file_index: configuration.file_index,
    };
    let lease = if configuration
        .registration_ownership
        .as_ref()
        .is_some_and(|owner| owner.state != "prepared_not_registered")
    {
        pin_registered_configured_root(Path::new(&configuration.path), expected)
    } else {
        pin_configured_root(Path::new(&configuration.path))
    };
    configuration.valid = lease.is_ok_and(|lease| lease.identity() == expected);
    Ok(Some(configuration))
}

/// Decode protected root metadata for exclusion/reservation only. This does
/// not restore credentials, inspect/register a root, or grant provider authority.
/// The authenticated loader separately binds the server/client/issuer and root.
fn decode_root_metadata(bytes: &[u8], expected_profile: &str) -> Result<RootConfiguration, String> {
    if bytes.is_empty() || bytes.len() > MAX_ROOT_CONFIG_BYTES {
        return Err("Saved drive folder configuration is invalid".into());
    }
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| "Saved drive folder configuration is invalid")?;
    let version = value["version"]
        .as_u64()
        .ok_or("Saved drive folder configuration is invalid")?;
    let object = value
        .as_object()
        .filter(|object| {
            (version == 1 && object.len() == 8)
                || ((version == 2 || version == 3) && object.len() == 9)
        })
        .ok_or("Saved drive folder configuration is invalid")?;
    let profile_scope = object
        .get("profile_scope")
        .and_then(Value::as_str)
        .filter(|value| *value == expected_profile)
        .ok_or("Saved drive folder configuration is invalid")?;
    let server = object
        .get("server")
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty() && value.len() <= 4096 && !value.chars().any(char::is_control)
        })
        .ok_or("Saved drive folder configuration identity does not match")?;
    let client_id = object
        .get("client_id")
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty() && value.len() <= 4096 && !value.chars().any(char::is_control)
        })
        .ok_or("Saved drive folder configuration identity does not match")?;
    let issuer = match object.get("issuer") {
        Some(Value::String(issuer))
            if !issuer.is_empty()
                && issuer.len() <= 4096
                && !issuer.chars().any(char::is_control) =>
        {
            Some(issuer.clone())
        }
        Some(Value::Null) => None,
        _ => return Err("Saved drive folder configuration identity does not match".into()),
    };
    let path = object
        .get("path")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 32_000)
        .ok_or("Saved drive folder configuration is invalid")?;
    let volume_serial = object
        .get("volume_serial")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or("Saved drive folder configuration is invalid")?;
    let file_index = object
        .get("file_index")
        .and_then(Value::as_u64)
        .filter(|value| *value != 0)
        .ok_or("Saved drive folder configuration is invalid")?;
    if path.chars().any(char::is_control) {
        return Err("Saved drive folder configuration is invalid".into());
    }
    let registration_ownership = if version == 1 {
        // Old configurations contain a selected path, but no proof that it
        // belongs to the current account's Personal drive. Keep them visible
        // for migration, but never treat them as attachable roots.
        None
    } else {
        match object.get("registration_ownership") {
            Some(Value::Null) => None,
            Some(owner_value) => {
                let owner = owner_value
                    .as_object()
                    .filter(|owner| {
                        (owner.len() == 6 && owner_value["version"].as_u64() == Some(1))
                            || (owner.len() == 7
                                && owner_value["version"].as_u64() == Some(2)
                                && version == 3)
                    })
                    .ok_or("Saved drive folder ownership record is invalid")?;
                let state = owner
                    .get("state")
                    .and_then(Value::as_str)
                    .filter(|value| {
                        matches!(
                            *value,
                            "prepared_not_registered" | "registration_pending" | "registered"
                        )
                    })
                    .ok_or("Saved drive folder ownership record is invalid")?;
                let personal_drive_id = owner
                    .get("personal_drive_id")
                    .and_then(Value::as_str)
                    .filter(|value| {
                        !value.trim().is_empty()
                            && value.len() <= 16 * 1024
                            && !value.chars().any(char::is_control)
                    })
                    .ok_or("Saved drive folder ownership record is invalid")?;
                let personal_root_resource_id = match owner.get("personal_root_resource_id") {
                    Some(Value::String(value))
                        if !value.trim().is_empty()
                            && value.len() <= 16 * 1024
                            && !value.chars().any(char::is_control) =>
                    {
                        Some(value.clone())
                    }
                    None if owner_value["version"].as_u64() == Some(1) => None,
                    _ => return Err("Saved drive folder ownership record is invalid".into()),
                };
                let account_id = owner
                    .get("account_id")
                    .and_then(Value::as_str)
                    .ok_or("Saved drive folder ownership does not match this account")?;
                let owner_volume_serial = owner
                    .get("volume_serial")
                    .and_then(Value::as_u64)
                    .and_then(|value| u32::try_from(value).ok())
                    .ok_or("Saved drive folder ownership record is invalid")?;
                let owner_file_index = owner
                    .get("file_index")
                    .and_then(Value::as_u64)
                    .filter(|value| *value != 0)
                    .ok_or("Saved drive folder ownership record is invalid")?;
                let ownership = RegistrationOwnership {
                    state: state.to_owned(),
                    account_id: account_id.to_owned(),
                    personal_drive_id: personal_drive_id.to_owned(),
                    personal_root_resource_id,
                    volume_serial: owner_volume_serial,
                    file_index: owner_file_index,
                };
                validate_registration_ownership(&ownership, server, volume_serial, file_index)?;
                Some(ownership)
            }
            None => return Err("Saved drive folder ownership record is invalid".into()),
        }
    };
    Ok(RootConfiguration {
        profile_scope: profile_scope.to_owned(),
        server: server.to_owned(),
        client_id: client_id.to_owned(),
        issuer,
        path: path.to_owned(),
        volume_serial,
        file_index,
        registration_ownership,
        valid: false,
    })
}

fn verified_personal_root_identity(
    session: &auth::Session,
) -> Result<(String, String, String), String> {
    let client = OpenCloudClient::new_with_proxy(
        &session.server,
        session.access_token.clone(),
        &session.proxy,
    )
    .map_err(|_| "Could not verify this account's Personal drive")?;
    let token_generation = client.token_generation();
    let context = RangeReadContext {
        deadline: std::time::Instant::now() + Duration::from_secs(30),
        token_generation,
    };
    let spaces = client
        .spaces_with_context(context)
        .map_err(|_| "Could not verify this account's Personal drive")?;
    let (personal_drive_id, account_id) =
        verified_personal_identity_from_spaces(&session.server, &spaces)?;
    let personal = spaces
        .iter()
        .find(|space| space.id == personal_drive_id && space.personal)
        .ok_or("The server did not return the verified Personal drive")?;
    let root = client
        .stat_discovered_space_root_with_context(personal, context)
        .map_err(|_| "Could not verify the Personal drive root identity")?;
    if !root.directory || root.encrypted || root.id.trim().is_empty() || root.id.len() > 16 * 1024 {
        return Err("The Personal drive root identity is not usable".into());
    }
    Ok((personal_drive_id, account_id, root.id))
}

fn verified_account_roots(
    client: &Arc<OpenCloudClient>,
    server: &str,
) -> Result<(String, String, String, Vec<CloudSpace>, RangeReadContext), String> {
    let token_generation = client.token_generation();
    let context = RangeReadContext {
        deadline: std::time::Instant::now() + Duration::from_secs(30),
        token_generation,
    };
    let spaces = client
        .spaces_with_context(context)
        .map_err(|_| "Could not verify the connected account’s Spaces")?;
    let (personal_space_id, account_id) = verified_personal_identity_from_spaces(server, &spaces)?;
    let personal_space = spaces
        .iter()
        .find(|space| space.id == personal_space_id && space.personal)
        .ok_or("The server did not return the verified Personal drive")?;
    let personal_root = client
        .stat_discovered_space_root_with_context(personal_space, context)
        .map_err(|_| "Could not verify the Personal drive root identity")?;
    if !personal_root.directory
        || personal_root.encrypted
        || personal_root.id.trim().is_empty()
        || personal_root.id.len() > 16 * 1024
    {
        return Err("The Personal drive root identity is not usable".into());
    }
    Ok((
        personal_space_id,
        account_id,
        personal_root.id,
        spaces,
        context,
    ))
}

fn dispatch_one_initial_edit(
    connection: Option<&raiun_cloudfiles_windows::ConfiguredRootConnection>,
    backend: Option<&Arc<raiun_cloudfiles_windows::OpenCloudPlaceholderBackend>>,
    binding: Option<&ActiveProviderBinding>,
    generation: &Arc<AtomicU64>,
) -> Result<Option<raiun_cloudfiles_windows::ReconciliationOutcome>, String> {
    let (Some(connection), Some(backend), Some(binding)) = (connection, backend, binding) else {
        return Ok(None);
    };
    if binding.generation == 0
        || generation.load(Ordering::Acquire) != binding.generation
        || backend.is_revoked()
    {
        return Err("The account changed before initial save".into());
    }
    let root_lease = pin_registered_configured_root(&binding.path, binding.identity)
        .map_err(|_| "The connected Windows root changed".to_owned())?;
    if root_lease.identity() != binding.identity {
        return Err("The Windows root changed".into());
    }
    let Some(pending) = connection
        .take_initial_edit()
        .map_err(|_| "The fresh edit handoff is unavailable".to_owned())?
    else {
        return Ok(None);
    };
    if !pending.matches_provider(backend.scope(), binding.identity) {
        return Err("The fresh edit belongs to a different provider".into());
    }
    let scope = pending.scope().clone();
    backend
        .with_initial_edit_session(&scope, |session| {
            let remote = AgentGenerationRecoveryRemote {
                inner: RecoveryRemoteHandle::Borrowed(session.remote()),
                authorized_generation: Arc::clone(generation),
                expected_generation: binding.generation,
            };
            let dispatched = pending
                .dispatch_verified(&remote)
                .map_err(|_| "The initial save requires recovery review".to_owned())?;
            if let Some(proof) = dispatched.proof {
                let location = dispatched.location.ok_or_else(|| {
                    #[cfg(all(test, debug_assertions))]
                    eprintln!("synthetic_save_completion_missing_location");
                    "The saved edit needs local recovery review".to_owned()
                })?;
                if generation.load(Ordering::Acquire) != binding.generation
                    || location.root_identity() != binding.identity
                    || location.local_file_identity() != proof.metadata().local_file
                {
                    return Err("The local save binding changed".to_owned());
                }
                let publication = session
                    .prepare_verified_edit(location.identity(), &proof)
                    .map_err(|_| "The saved cloud version changed".to_owned())?;
                let components: Vec<&str> =
                    location.components().iter().map(String::as_str).collect();
                connection
                    .acknowledge_verified_edit(&components, &publication)
                    .map_err(|error| {
                        #[cfg(all(test, debug_assertions))]
                        eprintln!("synthetic_save_completion_rejected: {error}");
                        #[cfg(not(all(test, debug_assertions)))]
                        let _ = error;
                        "The saved edit needs local recovery review".to_owned()
                    })?;
            } else if matches!(
                dispatched.outcome,
                raiun_cloudfiles_windows::ReconciliationOutcome::VerifiedApplied { .. }
            ) {
                return Err("The saved edit needs fresh verification".to_owned());
            }
            Ok(Some(dispatched.outcome))
        })
        .map_err(|_| "Could not verify the fresh edit's current Space root".to_owned())?
}

enum RecoveryRemoteHandle<'a> {
    Owned(Arc<dyn raiun_cloudfiles_windows::RecoveryRemote>),
    Borrowed(&'a dyn raiun_cloudfiles_windows::RecoveryRemote),
}

impl RecoveryRemoteHandle<'_> {
    fn remote(&self) -> &dyn raiun_cloudfiles_windows::RecoveryRemote {
        match self {
            Self::Owned(remote) => remote.as_ref(),
            Self::Borrowed(remote) => *remote,
        }
    }
}

struct AgentGenerationRecoveryRemote<'a> {
    inner: RecoveryRemoteHandle<'a>,
    authorized_generation: Arc<AtomicU64>,
    expected_generation: u64,
}

impl AgentGenerationRecoveryRemote<'_> {
    fn ensure_current(
        &self,
        scope: &raiun_cloudfiles_windows::EditJournalScope,
    ) -> Result<(), raiun_core::backend::CloudError> {
        if self.expected_generation == 0
            || self.authorized_generation.load(Ordering::Acquire) != self.expected_generation
        {
            return Err(raiun_core::backend::CloudError::new(
                raiun_core::backend::ErrorKind::Unauthorized,
                "the connected account generation changed",
            ));
        }
        self.inner.remote().ensure_authorized(scope)
    }
}

impl raiun_cloudfiles_windows::RecoveryRemote for AgentGenerationRecoveryRemote<'_> {
    fn server_origin(&self) -> Option<&str> {
        (self.authorized_generation.load(Ordering::Acquire) == self.expected_generation)
            .then(|| self.inner.remote().server_origin())
            .flatten()
    }

    fn ensure_authorized(
        &self,
        scope: &raiun_cloudfiles_windows::EditJournalScope,
    ) -> Result<(), raiun_core::backend::CloudError> {
        self.ensure_current(scope)
    }

    fn stat(
        &self,
        scope: &raiun_cloudfiles_windows::EditJournalScope,
        relative_path: &str,
    ) -> Result<raiun_cloudfiles_windows::RecoveryRemoteVersion, raiun_core::backend::CloudError>
    {
        self.ensure_current(scope)?;
        self.inner.remote().stat(scope, relative_path)
    }

    fn conditional_upload(
        &self,
        scope: &raiun_cloudfiles_windows::EditJournalScope,
        relative_path: &str,
        content: &[u8],
        expected_resource_id: &str,
        condition: raiun_core::backend::WriteCondition,
        expected_size: u64,
    ) -> Result<raiun_cloudfiles_windows::RecoveryRemoteVersion, raiun_core::backend::CloudError>
    {
        self.ensure_current(scope)?;
        self.inner.remote().conditional_upload(
            scope,
            relative_path,
            content,
            expected_resource_id,
            condition,
            expected_size,
        )
    }

    fn readback(
        &self,
        scope: &raiun_cloudfiles_windows::EditJournalScope,
        relative_path: &str,
        expected_resource_id: &str,
        expected_etag: Option<&str>,
        max_bytes: usize,
    ) -> Result<raiun_cloudfiles_windows::RecoveryRemoteBody, raiun_core::backend::CloudError> {
        self.ensure_current(scope)?;
        self.inner.remote().readback(
            scope,
            relative_path,
            expected_resource_id,
            expected_etag,
            max_bytes,
        )
    }
}

type RecoveryListCursor = (String, String, String, u64);

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundRecoveryListCursor {
    version: u8,
    context: String,
    after: String,
}

fn bind_recovery_list_cursor(
    after: Option<String>,
    context: &str,
) -> Result<Option<String>, String> {
    after
        .map(|after| {
            let encoded = serde_json::to_string(&BoundRecoveryListCursor {
                version: 1,
                context: context.to_owned(),
                after,
            })
            .map_err(|_| "Saved edit cursor is unavailable")?;
            if encoded.len() > 16_384 {
                return Err("Saved edit cursor exceeds its display bound".into());
            }
            Ok(encoded)
        })
        .transpose()
}

fn parse_bound_recovery_list_cursor(
    value: Option<&Value>,
    context: &str,
) -> Result<Option<RecoveryListCursor>, String> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let encoded = value
        .as_str()
        .filter(|value| value.len() <= 16_384)
        .ok_or("Saved edit cursor is invalid")?;
    let cursor: BoundRecoveryListCursor = serde_json::from_str(encoded)
        .map_err(|_| "Saved edit cursor is invalid; refresh the list")?;
    if cursor.version != 1 || cursor.context != context {
        return Err(
            "The account, drive folder or agent session changed; refresh saved edits".into(),
        );
    }
    parse_recovery_list_cursor(Some(&Value::String(cursor.after)))
}

fn parse_recovery_list_cursor(value: Option<&Value>) -> Result<Option<RecoveryListCursor>, String> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let encoded = value
        .as_str()
        .filter(|value| value.len() <= 16_384)
        .ok_or("Saved edit cursor is invalid")?;
    let cursor: RecoveryListCursor =
        serde_json::from_str(encoded).map_err(|_| "Saved edit cursor is invalid")?;
    if cursor.0.is_empty()
        || cursor.0.len() > 4096
        || cursor.1.is_empty()
        || cursor.1.len() > 4096
        || cursor.2.is_empty()
        || cursor.2.len() > 128
        || !cursor.2.bytes().all(|byte| byte.is_ascii_hexdigit())
        || cursor.3 == 0
    {
        return Err("Saved edit cursor is invalid".into());
    }
    Ok(Some(cursor))
}

fn recovery_list_key(metadata: &raiun_cloudfiles_windows::LocalEditMetadata) -> RecoveryListCursor {
    (
        metadata.scope.space_id.clone(),
        metadata.scope.root_resource_id.clone(),
        metadata.record_id.clone(),
        metadata.generation,
    )
}

fn recovery_metadata_page(
    mut records: Vec<raiun_cloudfiles_windows::LocalEditMetadata>,
    scope: &raiun_cloudfiles_windows::ProviderScope,
    root: raiun_cloudfiles_windows::ConfiguredRootIdentity,
    after: Option<RecoveryListCursor>,
    limit: usize,
) -> Result<(Vec<Value>, Option<String>), String> {
    if !(1..=100).contains(&limit) {
        return Err("Saved edit page size is invalid".into());
    }
    if records.iter().any(|record| {
        record.scope.profile_id != scope.profile_id()
            || record.scope.server_origin != scope.server_origin()
            || record.scope.account_subject != scope.account_id()
            || record.scope.root_volume_serial != root.volume_serial
            || record.scope.root_file_index != root.file_index
    }) {
        return Err("Protected recovery records do not match this account and drive folder".into());
    }
    records.sort_by(|a, b| {
        (
            &a.scope.space_id,
            &a.scope.root_resource_id,
            &a.record_id,
            a.generation,
        )
            .cmp(&(
                &b.scope.space_id,
                &b.scope.root_resource_id,
                &b.record_id,
                b.generation,
            ))
    });
    if records
        .windows(2)
        .any(|pair| recovery_list_key(&pair[0]) == recovery_list_key(&pair[1]))
    {
        return Err("Protected recovery records are ambiguous".into());
    }
    let mut items = Vec::new();
    let mut last = None;
    let mut has_more = false;
    // Stay well below the 1 MiB control frame even for long escaped paths.
    let mut page_bytes = 0_usize;
    for record in records {
        let key = recovery_list_key(&record);
        if after.as_ref().is_some_and(|after| &key <= after) {
            continue;
        }
        let row = json!({"record_id":record.record_id, "generation":record.generation,
            "space_id":record.scope.space_id, "path":record.relative_path,
            "bytes":record.content_len, "state":"needs_review",
            "has_remote_baseline":record.remote.is_some(), "retry_requires_review":true});
        let row_bytes = serde_json::to_vec(&row)
            .map_err(|_| "Saved edit metadata is unavailable")?
            .len();
        if row_bytes > 512 * 1024 {
            return Err("Saved edit metadata exceeds the display bound".into());
        }
        if items.len() == limit || page_bytes.saturating_add(row_bytes) > 512 * 1024 {
            has_more = true;
            break;
        }
        page_bytes += row_bytes;
        items.push(row);
        last = Some(key);
    }
    let next = if has_more {
        last.map(|key| {
            serde_json::to_string(&key).map_err(|_| "Saved edit cursor is unavailable".to_owned())
        })
        .transpose()?
    } else {
        None
    };
    Ok((items, next))
}

fn recovery_outcome_json(outcome: raiun_cloudfiles_windows::ReconciliationOutcome) -> Value {
    use raiun_cloudfiles_windows::{ReconciliationIssue, ReconciliationOutcome};
    match outcome {
        ReconciliationOutcome::VerifiedApplied { attempts } => json!({
            "state": "verified_applied",
            "attempts": attempts,
            "retained": true,
        }),
        ReconciliationOutcome::Conflict(issue) => json!({
            "state": "conflict",
            "reason": match issue {
                ReconciliationIssue::InvalidRecord => "invalid_record",
                ReconciliationIssue::ScopeMismatch => "scope_mismatch",
                ReconciliationIssue::MissingStrongBaseline => "missing_baseline",
                ReconciliationIssue::RemoteObjectMissing => "remote_missing",
                ReconciliationIssue::RemoteObjectChanged => "remote_changed",
                ReconciliationIssue::RemoteNotWritable => "remote_not_writable",
                ReconciliationIssue::ContentMismatch => "content_mismatch",
                ReconciliationIssue::ResponseInconsistent => "response_inconsistent",
            },
            "retained": true,
        }),
        ReconciliationOutcome::Ambiguous => json!({
            "state": "outcome_unknown",
            "retained": true,
        }),
        ReconciliationOutcome::Deferred => json!({
            "state": "not_completed",
            "retained": true,
        }),
    }
}

fn verified_personal_identity_from_spaces(
    server: &str,
    spaces: &[CloudSpace],
) -> Result<(String, String), String> {
    let personal: Vec<_> = spaces.iter().filter(|space| space.personal).collect();
    if personal.len() != 1
        || personal[0].id.trim().is_empty()
        || personal[0].id.len() > 16 * 1024
        || personal[0].id.chars().any(char::is_control)
        || !personal[0].writable
        || personal[0].encrypted
    {
        return Err("The server did not identify one usable Personal drive".into());
    }
    let personal_drive_id = personal[0].id.clone();
    let account_id = personal_account_identity(server, &personal_drive_id);
    Ok((personal_drive_id, account_id))
}

fn personal_account_identity(server: &str, personal_drive_id: &str) -> String {
    let identity = format!("{server}\0{personal_drive_id}");
    let mut encoded = String::with_capacity(identity.len() * 2);
    for byte in identity.bytes() {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn validate_registration_ownership(
    owner: &RegistrationOwnership,
    server: &str,
    volume_serial: u32,
    file_index: u64,
) -> Result<(), String> {
    if owner.personal_drive_id.trim().is_empty()
        || owner.personal_drive_id.len() > 16 * 1024
        || owner.personal_drive_id.chars().any(char::is_control)
        || owner.account_id != personal_account_identity(server, &owner.personal_drive_id)
        || owner
            .personal_root_resource_id
            .as_ref()
            .is_some_and(|root_id| {
                root_id.trim().is_empty()
                    || root_id.len() > 16 * 1024
                    || root_id.chars().any(char::is_control)
            })
        || !matches!(
            owner.state.as_str(),
            "prepared_not_registered" | "registration_pending" | "registered"
        )
    {
        return Err("Saved drive folder ownership does not match this account".into());
    }
    if owner.volume_serial != volume_serial || owner.file_index != file_index {
        return Err("Saved drive folder ownership does not match this local folder".into());
    }
    Ok(())
}

fn root_error_text(error: raiun_cloudfiles_windows::Error) -> String {
    match error {
        raiun_cloudfiles_windows::Error::ConfiguredRootNotEmpty => {
            "Choose an empty folder; Raiun will not adopt existing files".into()
        }
        raiun_cloudfiles_windows::Error::InvalidConfiguredRoot => {
            "Choose an ordinary local Windows folder without junctions or symbolic links".into()
        }
        raiun_cloudfiles_windows::Error::UnsupportedPlatform => {
            "Windows folder configuration is unavailable on this platform".into()
        }
        _ => "Could not safely inspect the selected Windows folder".into(),
    }
}

fn overlaps_private_state(
    candidate: &Path,
    registered_identity: Option<raiun_cloudfiles_windows::ConfiguredRootIdentity>,
) -> Result<bool, String> {
    let local_app_data = std::env::var_os("LOCALAPPDATA")
        .filter(|value| !value.is_empty())
        .ok_or("Current-user app data is unavailable")?;
    let private_state = PathBuf::from(local_app_data).join("Raiun");
    if !private_state.exists() {
        // Before the first agent start there is no private state directory to
        // alias; lexical component overlap still prevents selecting its path.
        return Ok(windows_paths_overlap(
            &candidate.to_string_lossy(),
            &private_state.to_string_lossy(),
        ));
    }
    let overlap = if let Some(identity) = registered_identity {
        raiun_cloudfiles_windows::registered_configured_root_overlaps(
            candidate,
            identity,
            &private_state,
        )
    } else {
        configured_roots_overlap(candidate, &private_state)
    };
    let identity_overlap = overlap
        .map_err(|_| "Could not verify the selected folder against Raiun's private app data")?;
    Ok(identity_overlap
        || windows_paths_overlap(
            &candidate.to_string_lossy(),
            &private_state.to_string_lossy(),
        ))
}

fn windows_paths_overlap(left: &str, right: &str) -> bool {
    fn key(value: &str) -> String {
        value
            .replace('/', "\\")
            .split('\\')
            .filter(|component| !component.is_empty())
            .map(str::to_ascii_lowercase)
            .collect::<Vec<_>>()
            .join("\\")
    }
    fn contains(parent: &str, child: &str) -> bool {
        child == parent
            || child
                .strip_prefix(parent)
                .is_some_and(|suffix| suffix.starts_with('\\'))
    }
    let left = key(left);
    let right = key(right);
    contains(&left, &right) || contains(&right, &left)
}

fn unix_time_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

struct DpapiStore {
    store: DpapiSessionStore,
    // Trusted runtime identity, never selected by an individual RPC payload.
    profile_scope: String,
}

impl DpapiStore {
    fn current_user() -> Result<Self, String> {
        Self::for_profile("default")
    }
    fn for_profile(profile: &str) -> Result<Self, String> {
        if !valid_runtime_profile(profile) {
            return Err("Invalid Windows runtime profile".into());
        }
        let base = DpapiSessionStore::current_user()
            .map_err(|_| "Could not initialize private current-user session storage".to_owned())?;
        let store = base
            .for_profile(profile)
            .map_err(|_| "Could not admit private profile storage".to_owned())?;
        Ok(Self {
            store,
            profile_scope: profile.into(),
        })
    }
    fn check_scope(&self, scope: &str) -> Result<(), String> {
        if scope != self.profile_scope {
            return Err("Protected Windows storage belongs to another profile".into());
        }
        Ok(())
    }
}

impl SessionStore for DpapiStore {
    fn load_vault_existing_edit_capture(
        &self,
        binding: &[u8],
    ) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, String> {
        self.store
            .load_vault_existing_edit_capture(binding)
            .map_err(|_| "Protected vault capture is unavailable".into())
    }
    fn put_new_vault_existing_edit_capture(
        &self,
        binding: &[u8],
        record: &[u8],
    ) -> Result<(), String> {
        self.store
            .put_new_vault_existing_edit_capture(binding, record)
            .map_err(|_| "Vault capture publication is uncertain".into())
    }
    fn load_vault_completed_history_segment(
        &self,
        binding: &[u8],
    ) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, String> {
        self.store
            .load_vault_completed_history_segment(binding)
            .map_err(|_| "Protected completed vault history is unavailable".into())
    }
    fn put_new_vault_completed_history_segment(
        &self,
        binding: &[u8],
        record: &[u8],
    ) -> Result<(), String> {
        self.store
            .put_new_vault_completed_history_segment(binding, record)
            .map_err(|_| "Completed vault history publication is uncertain".into())
    }
    fn load_vault_custody(
        &self,
        scope: &[u8],
    ) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, String> {
        self.store
            .load_vault_custody(scope)
            .map_err(|_| "Protected vault history is unavailable".into())
    }
    fn compare_exchange_vault_custody(
        &self,
        scope: &[u8],
        old: Option<&[u8]>,
        next: &[u8],
    ) -> Result<(), String> {
        self.store
            .compare_exchange_vault_custody(scope, old, next)
            .map_err(|_| "Vault history publication is uncertain".into())
    }

    fn load_vault_credentials(
        &self,
        profile: &str,
    ) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, String> {
        self.check_scope(profile)?;
        self.store
            .load_vault_credentials(profile)
            .map_err(|_| "Protected vault credentials are unavailable".into())
    }
    fn compare_exchange_vault_credentials(
        &self,
        profile: &str,
        old: Option<&[u8]>,
        next: &[u8],
    ) -> Result<(), String> {
        self.check_scope(profile)?;
        self.store
            .compare_exchange_vault_credentials(profile, old, next)
            .map_err(|_| "Vault credential publication is uncertain".into())
    }

    fn load_proxy_settings(&self, profile: &str) -> Result<Option<Vec<u8>>, String> {
        self.check_scope(profile)?;
        self.store
            .load_proxy_settings(profile)
            .map_err(|_| "Protected proxy settings could not be read".into())
    }
    fn compare_exchange_proxy_settings(
        &self,
        profile: &str,
        old: Option<&[u8]>,
        next: &[u8],
    ) -> Result<(), String> {
        self.check_scope(profile)?;
        self.store
            .compare_exchange_proxy_settings(profile, old, next)
            .map_err(|_| "Proxy settings changed or durable publication is uncertain".into())
    }

    fn load_bandwidth_settings(
        &self,
        profile: &str,
        scope: &[u8],
    ) -> Result<Option<Vec<u8>>, String> {
        self.check_scope(profile)?;
        self.store
            .load_bandwidth_settings(scope)
            .map_err(|_| "Protected bandwidth settings could not be read".into())
    }
    fn compare_exchange_bandwidth_settings(
        &self,
        profile: &str,
        scope: &[u8],
        old: Option<&[u8]>,
        next: &[u8],
    ) -> Result<(), String> {
        self.check_scope(profile)?;
        self.store
            .compare_exchange_bandwidth_settings(scope, old, next)
            .map_err(|_| {
                "Bandwidth settings changed or their durable publication is uncertain".into()
            })
    }

    fn bound_profile(&self) -> Option<&str> {
        Some(&self.profile_scope)
    }

    fn save_pending(&self, scope: &str, session: &auth::Session) -> Result<(), String> {
        self.check_scope(scope)?;
        let bytes = Zeroizing::new(
            serde_json::to_vec(session).map_err(|_| "Could not serialize the sign-in session")?,
        );
        if bytes.is_empty() || bytes.len() > MAX_SESSION_BYTES {
            return Err("Sign-in session exceeds the secure storage limit".into());
        }
        self.store
            .save(Some(scope), &session.server, &session.client_id, &bytes)
            .map_err(|_| "Could not save the session in Windows protected storage".to_string())
    }

    fn publish_active(&self, scope: &str, session: &auth::Session) -> Result<(), String> {
        self.check_scope(scope)?;
        self.store
            .set_active_identity(scope, &session.server, &session.client_id)
            .map_err(|_| "Could not save the active session pointer in protected storage".into())
    }

    fn load_active(&self, expected_scope: &str) -> Result<Option<auth::Session>, String> {
        self.check_scope(expected_scope)?;
        let identity = self
            .store
            .active_identity()
            .map_err(|_| "Could not read the active session pointer".to_string())?;
        let Some((profile_scope, server, client_id)) = identity else {
            return Ok(None);
        };
        if profile_scope != expected_scope {
            return Err("Saved Windows session belongs to a different profile".into());
        }
        let bytes = self
            .store
            .load(Some(expected_scope), &server, &client_id)
            .map_err(|_| "Could not read the saved Windows session".to_string())?
            .ok_or_else(|| "Saved Windows session is unavailable; sign in again".to_string())?;
        let session: auth::Session = serde_json::from_slice(&bytes)
            .map_err(|_| "Saved Windows session is invalid; sign in again".to_string())?;
        auth::validate_session(&session)
            .map_err(|_| "Saved Windows session is invalid; sign in again".to_string())?;
        if session.server != server || session.client_id != client_id {
            return Err("Saved Windows session does not match its active identity".into());
        }
        Ok(Some(session))
    }

    fn revoke_active(&self) -> Result<Option<(String, String, String)>, String> {
        let identity = self
            .store
            .active_identity()
            .map_err(|_| "Could not read the active session pointer".to_string())?;
        if let Some((profile, _, _)) = &identity {
            self.check_scope(profile)?;
        }
        self.store
            .clear_active_identity()
            .map_err(|_| "Could not revoke the active session pointer".to_string())?;
        Ok(identity)
    }

    fn remove(&self, scope: &str, server: &str, client_id: &str) -> Result<(), String> {
        self.check_scope(scope)?;
        self.store
            .remove(Some(scope), server, client_id)
            .map_err(|_| "Could not remove the session from Windows protected storage".into())
    }

    fn save_root_config(
        &self,
        scope: &str,
        server: &str,
        client_id: &str,
        bytes: &[u8],
    ) -> Result<(), String> {
        self.check_scope(scope)?;
        self.store
            .save_root_config(scope, server, client_id, bytes)
            .map_err(|_| "Could not save the drive folder in private Windows storage".into())
    }

    fn load_root_config(
        &self,
        scope: &str,
        server: &str,
        client_id: &str,
    ) -> Result<Option<Vec<u8>>, String> {
        self.check_scope(scope)?;
        self.store
            .load_root_config(scope, server, client_id)
            .map_err(|_| "Could not read the drive folder from private Windows storage".into())
    }

    fn remove_root_config(&self, scope: &str, server: &str, client_id: &str) -> Result<(), String> {
        self.check_scope(scope)?;
        self.store
            .remove_root_config(scope, server, client_id)
            .map_err(|_| "Could not clear the drive folder from private Windows storage".into())
    }
}

/// Factory seam for the eventual Windows auth runtime. It is initialized at
/// startup so current-user storage problems are surfaced before sign-in can
/// be offered; no session is created or loaded by the unsupported bootstrap.
fn session_store_factory() -> Result<impl SessionStore, String> {
    DpapiStore::current_user()
}

pub(super) fn run() -> Result<(), String> {
    let args = Args::parse();
    match args.command {
        Command::Request { message } => request_once(&message),
        Command::Serve => {
            if WINDOWS_ACCOUNTS_ENABLED {
                windows_profiles::serve_profiles()
            } else {
                serve(session_store_factory()?)
            }
        }
    }
}

fn request_once(message: &str) -> Result<(), String> {
    let request: Value = serde_json::from_str(message).map_err(|_| "Invalid control request")?;
    reject_secret_request(&request)?;
    let timeout = request_timeout(&request);
    let mut stream = connect_current_user(timeout)
        .map_err(|_| "Raiun agent is not running for this Windows user".to_owned())?;
    write_json_line(&mut stream, &request)
        .map_err(|_| "Could not send control request".to_owned())?;
    let mut response = Vec::new();
    stream
        .take(raiun_control::MAX_CONTROL_MESSAGE_BYTES as u64 + 1)
        .read_to_end(&mut response)
        .map_err(|_| "Could not read the agent response".to_owned())?;
    if response.len() > raiun_control::MAX_CONTROL_MESSAGE_BYTES {
        return Err("Agent response exceeded the control limit".into());
    }
    let response = std::str::from_utf8(&response).map_err(|_| "Agent response is not UTF-8")?;
    println!("{}", response.trim_end());
    Ok(())
}

// A health probe may connect and close without sending a frame, or a client
// may disappear after its request. Neither event retires the current account
// or its native provider. Listener ownership/security failures remain fatal.
fn disconnected_pipe_client(error: &std::io::Error) -> bool {
    matches!(error.raw_os_error(), Some(109 | 232 | 233))
        || matches!(
            error.kind(),
            std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::NotConnected
        )
}

fn serve_control_connection<S: Read + Write>(agent: &Arc<WindowsAgent>, stream: &mut S) -> bool {
    let result = read_json_value(stream).and_then(|request| {
        let request = windows_vault_requests::OwnedControlRequest::new(request);
        agent.handle_request(request.value())
    });
    let (response, should_stop) = match result {
        Ok((data, should_stop)) => (json!({"ok":true,"data":data}), should_stop),
        Err(error) => (json!({"ok":false,"error":error}), false),
    };
    // A reply failure belongs only to this connection. A successfully admitted
    // shutdown must still stop the server if its caller loses the reply.
    let _ = write_json_line(stream, &response);
    should_stop
}

fn serve(session_store: impl SessionStore + 'static) -> Result<(), String> {
    let agent = Arc::new(WindowsAgent::new(session_store));
    serve_agent(agent)
}

fn serve_agent(agent: Arc<WindowsAgent>) -> Result<(), String> {
    agent.attach_existing_file_save_owner()?;
    let stopping = Arc::new(AtomicBool::new(false));
    while !stopping.load(Ordering::Acquire) {
        // Do not classify bind errors as disconnected clients: claiming the
        // first same-user pipe instance is part of the ownership boundary.
        let listener = NamedPipeListener::bind(Duration::from_millis(500))
            .map_err(|_| "Could not bind the current-user control pipe".to_owned())?;
        let mut stream = match listener.accept() {
            Ok(stream) => stream,
            Err(error)
                if error.kind() == std::io::ErrorKind::TimedOut
                    || disconnected_pipe_client(&error) =>
            {
                continue;
            }
            Err(_) => return Err("Could not accept a current-user control request".into()),
        };
        if serve_control_connection(&agent, &mut stream) {
            stopping.store(true, Ordering::Release);
        }
    }
    agent.stop_and_join()
}

fn reject_secret_request(request: &Value) -> Result<(), String> {
    let action = request.get("action").and_then(Value::as_str).unwrap_or("");
    if request.get("password").is_some()
        || matches!(
            action,
            "vault_unlock" | "vault_create" | "vault_unlock_offline"
        )
    {
        return Err(
            "Enter vault passwords in Raiun Desktop, never in command-line arguments".into(),
        );
    }
    Ok(())
}

/// The Windows control channel may carry a public-link password only as part
/// of a fully validated sharing-link create request. All other control and CLI
/// requests retain the strict generic secret rejection.
fn reject_control_secret_request(request: &Value) -> Result<(), String> {
    if request.get("action").and_then(Value::as_str) == Some("sharing_link_create") {
        crate::sharing_wire::Request::parse(request)?;
        return Ok(());
    }
    reject_secret_request(request)
}

fn request_timeout(request: &Value) -> Duration {
    match request.get("action").and_then(Value::as_str).unwrap_or("") {
        "auth_begin" => Duration::from_secs(65),
        "shutdown"
        | "auth_cancel"
        | "logout"
        | "pause"
        | "space_pause"
        | "vault_lock"
        | "windows_recovery_retry"
        | "vault_upload_capture" => Duration::from_secs(300),
        _ => Duration::from_secs(30),
    }
}

#[cfg(test)]
pub(super) mod tests {
    mod windows_media_worker_test {
        include!("windows_media_worker_test.rs");
    }
    mod windows_folder_worker_test {
        include!("windows_folder_worker_test.rs");
    }
    use super::{
        AccountState, ActiveProviderBinding, AgentGenerationRecoveryRemote, CloudSpace,
        PROVIDER_UNAVAILABLE, RecoveryRemoteHandle, RegistrationOwnership, SessionStore,
        WindowsAgent, encode_root_configuration, load_root_configuration,
        personal_account_identity, record_cleanup_failure, reject_control_secret_request,
        reject_secret_request, request_timeout, unix_time_now, validate_registration_ownership,
        verified_account_roots, verified_personal_identity_from_spaces, windows_paths_overlap,
    };
    #[cfg(all(windows, debug_assertions))]
    use super::{
        NativeReadFixturePath, NativeReadOnlyObservation, NativeRestartProbePath, ProviderManager,
    };
    use crate::agent_windows::auth;
    use raiun_cloudfiles_windows::verify_configured_root_identity;
    use serde_json::{Value, json};
    #[cfg(all(windows, debug_assertions))]
    use std::path::{Path, PathBuf};
    use std::{
        collections::HashMap,
        io::{BufRead, BufReader, Read, Write},
        net::{TcpListener, TcpStream},
        sync::{Arc, Mutex, atomic::Ordering, mpsc},
        thread,
        time::{Duration, Instant},
    };

    #[cfg(all(windows, debug_assertions))]
    const MAX_NATIVE_READ_DIRECTORY_ENTRIES: usize = 256;

    #[cfg(all(windows, debug_assertions))]
    #[derive(Debug)]
    struct ChildDirectoryComparison {
        matches_expected: bool,
        entry_count: usize,
        known_names: Vec<String>,
        unknown_name_count: usize,
    }

    #[cfg(all(windows, debug_assertions))]
    fn child_process_directory_matches(
        path: &Path,
        expected_names: &[&str],
    ) -> Result<ChildDirectoryComparison, String> {
        use std::process::{Command, Stdio};

        let expected = expected_names.join("|");
        let mut child = Command::new("powershell.exe")
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "$ErrorActionPreference='Stop'; $items=[System.Collections.Generic.List[string]]::new(); $enumerator=[System.IO.Directory]::EnumerateFileSystemEntries($env:RAIUN_NATIVE_ENUM_PATH).GetEnumerator(); try { while ($items.Count -lt 257 -and $enumerator.MoveNext()) { [void]$items.Add([System.IO.Path]::GetFileName($enumerator.Current)) } } finally { $enumerator.Dispose() }; $expected=@($env:RAIUN_NATIVE_EXPECTED_NAMES -split '\\|'); $actualItems=$items.ToArray(); [Array]::Sort($expected,[StringComparer]::Ordinal); [Array]::Sort($actualItems,[StringComparer]::Ordinal); $actual=($actualItems -join '|'); $expectedJoined=($expected -join '|'); $known=@($items | Where-Object { $_ -in @('RecoveryRoot','native-read.bin','Projects') } | Sort-Object -Unique); $unknown=$items.Count-$known.Count; $match=($actual -ceq $expectedJoined); Write-Output ('COUNT={0};MATCH={1};KNOWN={2};UNKNOWN={3}' -f $items.Count,[int]$match,($known -join ','),$unknown); if ($items.Count -gt 256) { exit 24 }; if ($match) { exit 0 }; exit 23",
            ])
            .env("RAIUN_NATIVE_ENUM_PATH", path)
            .env("RAIUN_NATIVE_EXPECTED_NAMES", expected)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| format!("could not start bounded child OS enumeration: {error}"))?;
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            match child
                .try_wait()
                .map_err(|error| format!("could not poll child OS enumeration: {error}"))?
            {
                Some(status) => {
                    let output = child.wait_with_output().map_err(|error| {
                        format!("could not collect bounded child OS enumeration: {error}")
                    })?;
                    let summary = String::from_utf8_lossy(&output.stdout);
                    let mut fields = summary.trim().splitn(4, ';');
                    let entry_count = fields
                        .next()
                        .and_then(|field| field.strip_prefix("COUNT="))
                        .and_then(|value| value.parse::<usize>().ok())
                        .ok_or_else(|| {
                            "bounded child OS enumeration returned invalid count telemetry"
                                .to_owned()
                        })?;
                    let reported_match = fields
                        .next()
                        .and_then(|field| field.strip_prefix("MATCH="))
                        .map(|value| value == "1")
                        .ok_or_else(|| {
                            "bounded child OS enumeration returned invalid match telemetry"
                                .to_owned()
                        })?;
                    let known_names = fields
                        .next()
                        .and_then(|field| field.strip_prefix("KNOWN="))
                        .filter(|value| {
                            value.is_empty()
                                || value.split(',').all(|name| {
                                    matches!(name, "RecoveryRoot" | "native-read.bin" | "Projects")
                                })
                        })
                        .map(|value| {
                            value
                                .split(',')
                                .filter(|name| !name.is_empty())
                                .map(str::to_owned)
                                .collect::<Vec<_>>()
                        })
                        .ok_or_else(|| {
                            "bounded child OS enumeration returned unexpected name telemetry"
                                .to_owned()
                        })?;
                    let unknown_name_count = fields
                        .next()
                        .and_then(|field| field.strip_prefix("UNKNOWN="))
                        .and_then(|value| value.parse::<usize>().ok())
                        .ok_or_else(|| {
                            "bounded child OS enumeration returned invalid unknown-name count"
                                .to_owned()
                        })?;
                    return Ok(ChildDirectoryComparison {
                        matches_expected: status.success() && reported_match,
                        entry_count,
                        known_names,
                        unknown_name_count,
                    });
                }
                None if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
                None => {
                    std::mem::forget(child);
                    return Err(
                        "child OS enumeration exceeded its bounded wait; child left running and synthetic root/recovery preserved"
                            .to_owned(),
                    );
                }
            }
        }
    }

    #[cfg(all(windows, debug_assertions))]
    fn child_process_rust_directory_matches(
        path: &Path,
        expected_names: &[&str],
    ) -> Result<ChildDirectoryComparison, String> {
        use std::os::windows::ffi::OsStrExt;
        use std::process::{Command, Stdio};

        let path_units = path.as_os_str().encode_wide().collect::<Vec<_>>();
        if !path.is_absolute()
            || path_units.is_empty()
            || path_units.len() > 16 * 1024
            || path_units
                .iter()
                .any(|unit| *unit == 0 || *unit < 0x20 || (0x7f..=0x9f).contains(unit))
        {
            return Err("Rust child enumeration path exceeded its bounded input policy".to_owned());
        }
        if expected_names.is_empty()
            || expected_names.len() > MAX_NATIVE_READ_DIRECTORY_ENTRIES
            || expected_names.iter().any(|name| {
                name.is_empty()
                    || name.len() > 16 * 1024
                    || name.chars().any(char::is_control)
                    || !matches!(*name, "RecoveryRoot" | "native-read.bin" | "Projects")
            })
        {
            return Err(
                "Rust child enumeration expected names exceeded their bounded input policy"
                    .to_owned(),
            );
        }

        let executable = std::env::current_exe()
            .map_err(|_| "could not resolve current test executable".to_owned())?;
        if !executable.is_absolute() {
            return Err("current test executable path was not absolute".to_owned());
        }
        let expected = expected_names.join("|");
        let mut child = Command::new(executable)
            .args([
                "--exact",
                "agent_windows::tests::native_rust_child_directory_probe",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("RAIUN_NATIVE_RUST_CHILD_PATH", path)
            .env("RAIUN_NATIVE_RUST_CHILD_EXPECTED", expected)
            .env(
                "RAIUN_NATIVE_RUST_CHILD_MARKER",
                "raiun-native-enum-child-v1",
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "could not start bounded Rust child enumeration".to_owned())?;
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let child_status = match child.try_wait() {
                Ok(status) => status,
                Err(_) => {
                    std::mem::forget(child);
                    return Err(
                        "Rust child enumeration process state uncertain; child left running and synthetic root/recovery preserved"
                            .to_owned(),
                    );
                }
            };
            match child_status {
                Some(status) => {
                    let output = child.wait_with_output().map_err(|_| {
                        "could not collect bounded Rust child enumeration".to_owned()
                    })?;
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let mut summaries = stdout
                        .lines()
                        .filter(|line| line.starts_with("RAIUN_RUST_CHILD_DIRECTORY "));
                    let summary = summaries
                        .next()
                        .ok_or_else(|| "Rust child enumeration returned no summary".to_owned())?;
                    if summaries.next().is_some() {
                        return Err(
                            "Rust child enumeration returned duplicate summaries".to_owned()
                        );
                    }
                    let mut fields = summary.split_whitespace();
                    if fields.next() != Some("RAIUN_RUST_CHILD_DIRECTORY") {
                        return Err("Rust child enumeration returned invalid telemetry".to_owned());
                    }
                    let entry_count = fields
                        .next()
                        .and_then(|field| field.strip_prefix("COUNT="))
                        .and_then(|value| value.parse::<usize>().ok())
                        .filter(|value| *value <= MAX_NATIVE_READ_DIRECTORY_ENTRIES)
                        .ok_or_else(|| {
                            "Rust child enumeration returned invalid count".to_owned()
                        })?;
                    let reported_match = fields
                        .next()
                        .and_then(|field| field.strip_prefix("MATCH="))
                        .and_then(|value| match value {
                            "0" => Some(false),
                            "1" => Some(true),
                            _ => None,
                        })
                        .ok_or_else(|| {
                            "Rust child enumeration returned invalid match flag".to_owned()
                        })?;
                    let known_names = fields
                        .next()
                        .and_then(|field| field.strip_prefix("KNOWN="))
                        .filter(|value| {
                            value.is_empty()
                                || value.split(',').all(|name| {
                                    matches!(name, "RecoveryRoot" | "native-read.bin" | "Projects")
                                })
                        })
                        .map(|value| {
                            value
                                .split(',')
                                .filter(|name| !name.is_empty())
                                .map(str::to_owned)
                                .collect::<Vec<_>>()
                        })
                        .ok_or_else(|| {
                            "Rust child enumeration returned invalid known names".to_owned()
                        })?;
                    let unknown_name_count = fields
                        .next()
                        .and_then(|field| field.strip_prefix("UNKNOWN="))
                        .and_then(|value| value.parse::<usize>().ok())
                        .ok_or_else(|| {
                            "Rust child enumeration returned invalid unknown count".to_owned()
                        })?;
                    if fields.next().is_some() {
                        return Err("Rust child enumeration returned extra telemetry".to_owned());
                    }
                    if known_names.len().saturating_add(unknown_name_count) != entry_count {
                        return Err(
                            "Rust child enumeration returned inconsistent counts".to_owned()
                        );
                    }
                    return Ok(ChildDirectoryComparison {
                        matches_expected: status.success() && reported_match,
                        entry_count,
                        known_names,
                        unknown_name_count,
                    });
                }
                None if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
                None => {
                    std::mem::forget(child);
                    return Err(
                        "Rust child enumeration exceeded its bounded wait; child left running and synthetic root/recovery preserved"
                            .to_owned(),
                    );
                }
            }
        }
    }

    #[cfg(all(windows, debug_assertions))]
    fn explorer_first_view_checkpoint(
        checkpoint_dir: &Path,
        run_id: &str,
        root: &Path,
        target: &Path,
        label: &str,
        expected_names: &[&str],
        provider: &ProviderManager,
    ) -> Result<(), String> {
        use std::io::Write as _;

        const RESPONSE_LIMIT: u64 = 16 * 1024;
        const WAIT_LIMIT: Duration = Duration::from_secs(120);
        let expected_path = root.join(match label {
            "Personal" => "Personal",
            "Spaces" => "Spaces",
            "Projects Space" => "Spaces\\Projects",
            _ => return Err("Explorer checkpoint label is outside the synthetic fixture".into()),
        });
        if target != expected_path || !target.starts_with(root) || target == root {
            return Err("Explorer checkpoint target is not the exact synthetic child".into());
        }
        let file_stem = label.to_ascii_lowercase().replace(' ', "-");
        let request_path = checkpoint_dir.join(format!("request-{file_stem}.json"));
        let response_path = checkpoint_dir.join(format!("response-{file_stem}.json"));
        let result_path = checkpoint_dir.join(format!("result-{file_stem}.json"));
        for path in [&request_path, &response_path, &result_path] {
            if path.exists() {
                return Err("Explorer checkpoint files must be fresh and absent".into());
            }
        }

        let callback_snapshot = |observation: &super::NativeCallbackObservation| {
            json!({
                "directory_entries": observation.0.0,
                "directory_guard_rejections": observation.0.1,
                "accepted_directory_callbacks": observation.0.2,
                "entries_submitted": observation.0.4
            })
        };
        let before = provider
            .directory_observation()
            .map_err(|_| "could not capture callbacks before Explorer checkpoint".to_owned())?;
        let nonce = format!("{run_id}:{file_stem}");
        let request = json!({
            "protocol": "raiun-explorer-first-view-v1",
            "run_id": run_id,
            "nonce": nonce,
            "phase": "before-first-child-directory-enumeration",
            "label": label,
            "test_process_id": std::process::id(),
            "root": root.to_string_lossy(),
            "target": target.to_string_lossy(),
            "explorer_evidence_provenance": "external harness reports Explorer process identity; test process does not authenticate that identity",
            "expected_names": expected_names,
            "maximum_entries": MAX_NATIVE_READ_DIRECTORY_ENTRIES
        });
        let request_bytes = serde_json::to_vec_pretty(&request)
            .map_err(|_| "could not encode Explorer checkpoint request".to_owned())?;
        if request_bytes.len() > RESPONSE_LIMIT as usize {
            return Err("Explorer checkpoint request exceeded its size bound".into());
        }
        let mut request_file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&request_path)
            .map_err(|_| "could not create fresh Explorer checkpoint request".to_owned())?;
        request_file
            .write_all(&request_bytes)
            .and_then(|()| request_file.sync_all())
            .map_err(|_| "could not persist Explorer checkpoint request".to_owned())?;

        let deadline = Instant::now() + WAIT_LIMIT;
        let response_bytes = loop {
            match std::fs::symlink_metadata(&response_path) {
                Ok(metadata) => {
                    use std::os::windows::fs::MetadataExt;
                    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
                    if !metadata.is_file()
                        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
                        || metadata.len() > RESPONSE_LIMIT
                    {
                        return Err("Explorer checkpoint response failed file bounds".into());
                    }
                    use std::os::windows::fs::OpenOptionsExt;
                    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
                    let response_file = std::fs::OpenOptions::new()
                        .read(true)
                        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                        .open(&response_path)
                        .map_err(|_| "could not open Explorer checkpoint response".to_owned())?;
                    let before_read = response_file
                        .metadata()
                        .map_err(|_| "could not inspect opened Explorer response".to_owned())?;
                    if !before_read.is_file()
                        || before_read.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
                        || before_read.len() > RESPONSE_LIMIT
                    {
                        return Err("opened Explorer response failed file bounds".into());
                    }
                    let mut bounded_file = response_file.take(RESPONSE_LIMIT + 1);
                    let mut bytes = Vec::with_capacity(RESPONSE_LIMIT as usize);
                    bounded_file
                        .read_to_end(&mut bytes)
                        .map_err(|_| "could not read bounded Explorer response".to_owned())?;
                    let after_read = bounded_file
                        .get_ref()
                        .metadata()
                        .map_err(|_| "could not reinspect opened Explorer response".to_owned())?;
                    if bytes.len() as u64 > RESPONSE_LIMIT
                        || before_read.len() != after_read.len()
                        || before_read.last_write_time() != after_read.last_write_time()
                    {
                        return Err("Explorer response changed while it was read".into());
                    }
                    break bytes;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    if Instant::now() >= deadline {
                        let timeout_path = checkpoint_dir.join(format!("timeout-{file_stem}.json"));
                        if let Ok(timeout_bytes) = serde_json::to_vec_pretty(&json!({
                            "protocol": "raiun-explorer-first-view-v1",
                            "run_id": run_id,
                            "nonce": nonce,
                            "phase": "timeout",
                            "label": label,
                            "target": target.to_string_lossy(),
                            "callback_before": callback_snapshot(&before)
                        })) {
                            if let Ok(mut timeout_file) = std::fs::OpenOptions::new()
                                .write(true)
                                .create_new(true)
                                .open(timeout_path)
                            {
                                let _ = timeout_file
                                    .write_all(&timeout_bytes)
                                    .and_then(|()| timeout_file.sync_all());
                            }
                        }
                        return Err("Explorer checkpoint exceeded its 120-second wait".into());
                    }
                    thread::sleep(Duration::from_millis(50));
                }
                Err(_) => return Err("could not inspect Explorer checkpoint response".into()),
            }
        };
        if response_bytes.len() > RESPONSE_LIMIT as usize {
            return Err("Explorer checkpoint response exceeded its size bound".into());
        }
        let response: Value = serde_json::from_slice(&response_bytes)
            .map_err(|_| "Explorer checkpoint response was not complete JSON".to_owned())?;
        let image_path = response
            .pointer("/explorer/image_path")
            .and_then(Value::as_str)
            .ok_or_else(|| "Explorer checkpoint omitted the Explorer image path".to_owned())?;
        let image_sha256 = response
            .pointer("/explorer/image_sha256")
            .and_then(Value::as_str)
            .ok_or_else(|| "Explorer checkpoint omitted the Explorer image hash".to_owned())?;
        let explorer_pid = response
            .pointer("/explorer/pid")
            .and_then(Value::as_u64)
            .filter(|pid| *pid > 0 && *pid <= u32::MAX as u64)
            .ok_or_else(|| "Explorer checkpoint omitted the Explorer process ID".to_owned())?;
        let explorer_session = response
            .pointer("/explorer/session_id")
            .and_then(Value::as_u64)
            .filter(|session| *session <= u32::MAX as u64)
            .ok_or_else(|| "Explorer checkpoint omitted the Explorer session ID".to_owned())?;
        if response.get("protocol").and_then(Value::as_str) != Some("raiun-explorer-first-view-v1")
            || response.get("run_id").and_then(Value::as_str) != Some(run_id)
            || response.get("nonce").and_then(Value::as_str) != Some(nonce.as_str())
            || response.get("phase").and_then(Value::as_str)
                != Some("before-first-child-directory-enumeration")
            || response.get("label").and_then(Value::as_str) != Some(label)
            || response.get("target").and_then(Value::as_str)
                != Some(target.to_string_lossy().as_ref())
            || response.get("complete").and_then(Value::as_bool) != Some(true)
            || !std::path::Path::new(image_path).is_absolute()
            || !std::path::Path::new(image_path)
                .file_name()
                .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case("explorer.exe"))
            || image_sha256.len() != 64
            || !image_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("Explorer checkpoint response identity did not match its request".into());
        }
        let reported_names = response
            .get("visible_names")
            .and_then(Value::as_array)
            .filter(|names| names.len() <= MAX_NATIVE_READ_DIRECTORY_ENTRIES)
            .ok_or_else(|| "Explorer checkpoint omitted bounded visible names".to_owned())?
            .iter()
            .map(|name| {
                name.as_str()
                    .filter(|name| {
                        !name.is_empty()
                            && name.len() <= 260
                            && !name.chars().any(char::is_control)
                            && !name.contains('/')
                            && !name.contains('\\')
                    })
                    .map(str::to_owned)
                    .ok_or_else(|| {
                        "Explorer checkpoint returned an invalid visible name".to_owned()
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut actual_names = reported_names.clone();
        let mut expected_sorted = expected_names
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>();
        actual_names.sort();
        expected_sorted.sort();
        let missing_names = expected_sorted
            .iter()
            .filter(|name| !actual_names.contains(name))
            .cloned()
            .collect::<Vec<_>>();
        let unexpected_names = actual_names
            .iter()
            .filter(|name| !expected_sorted.contains(name))
            .cloned()
            .collect::<Vec<_>>();
        let duplicate_names = actual_names
            .windows(2)
            .filter(|pair| pair[0] == pair[1])
            .map(|pair| pair[0].clone())
            .collect::<Vec<_>>();
        let exact_names_match = actual_names == expected_sorted;
        let after = provider
            .directory_observation()
            .map_err(|_| "could not capture callbacks after Explorer checkpoint".to_owned())?;
        let result = json!({
            "protocol": "raiun-explorer-first-view-v1",
            "run_id": run_id,
            "nonce": nonce,
            "phase": "before-first-child-directory-enumeration",
            "label": label,
            "root": root.to_string_lossy(),
            "target": target.to_string_lossy(),
            "explorer_evidence_provenance": "self-reported by external harness; not independently authenticated by the test process",
            "explorer": {
                "pid": explorer_pid,
                "session_id": explorer_session,
                "image_path": image_path,
                "image_sha256": image_sha256
            },
            "visible_names": reported_names,
            "missing_names": missing_names,
            "unexpected_names": unexpected_names,
            "duplicate_names": duplicate_names,
            "exact_names_match": exact_names_match,
            "callback_before": callback_snapshot(&before),
            "callback_after": callback_snapshot(&after)
        });
        let result_bytes = serde_json::to_vec_pretty(&result)
            .map_err(|_| "could not encode Explorer checkpoint result".to_owned())?;
        let mut result_file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(result_path)
            .map_err(|_| "could not create fresh Explorer checkpoint result".to_owned())?;
        result_file
            .write_all(&result_bytes)
            .and_then(|()| result_file.sync_all())
            .map_err(|_| "could not persist Explorer checkpoint result".to_owned())?;
        eprintln!(
            "native Explorer first-view checkpoint label={} pid={} session={} exact_names_match={}",
            label, explorer_pid, explorer_session, exact_names_match
        );
        if !unexpected_names.is_empty() || !duplicate_names.is_empty() {
            return Err(
                "Explorer checkpoint returned names outside the exact synthetic fixture set".into(),
            );
        }
        Ok(())
    }

    #[cfg(all(windows, debug_assertions))]
    #[test]
    #[ignore = "only launched by the bounded native lifecycle diagnostic"]
    fn native_rust_child_directory_probe() {
        let probe = (|| -> Result<ChildDirectoryComparison, ()> {
            if std::env::var("RAIUN_NATIVE_RUST_CHILD_MARKER")
                .ok()
                .as_deref()
                != Some("raiun-native-enum-child-v1")
            {
                return Err(());
            }
            use std::os::windows::ffi::OsStrExt;
            let path = std::env::var_os("RAIUN_NATIVE_RUST_CHILD_PATH")
                .map(std::path::PathBuf::from)
                .filter(|path| path.is_absolute())
                .ok_or(())?;
            let path_units = path.as_os_str().encode_wide().collect::<Vec<_>>();
            if path_units.is_empty()
                || path_units.len() > 16 * 1024
                || path_units
                    .iter()
                    .any(|unit| *unit == 0 || *unit < 0x20 || (0x7f..=0x9f).contains(unit))
            {
                return Err(());
            }
            let expected = std::env::var("RAIUN_NATIVE_RUST_CHILD_EXPECTED").map_err(|_| ())?;
            if expected.len() > 16 * 1024 || expected.chars().any(char::is_control) {
                return Err(());
            }
            let expected_names = expected.split('|').collect::<Vec<_>>();
            if expected_names.is_empty()
                || expected_names.len() > MAX_NATIVE_READ_DIRECTORY_ENTRIES
                || expected_names.iter().any(|name| {
                    name.is_empty()
                        || !matches!(*name, "RecoveryRoot" | "native-read.bin" | "Projects")
                })
            {
                return Err(());
            }
            let mut expected_sorted = expected_names
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>();
            expected_sorted.sort();
            expected_sorted.dedup();
            if expected_sorted.len() != expected_names.len() {
                return Err(());
            }
            let mut actual = Vec::new();
            for entry in std::fs::read_dir(path)
                .map_err(|_| ())?
                .take(MAX_NATIVE_READ_DIRECTORY_ENTRIES + 1)
            {
                let name = entry
                    .map_err(|_| ())?
                    .file_name()
                    .into_string()
                    .map_err(|_| ())?;
                actual.push(name);
            }
            if actual.len() > MAX_NATIVE_READ_DIRECTORY_ENTRIES {
                return Err(());
            }
            actual.sort();
            let entry_count = actual.len();
            let known_names = actual
                .iter()
                .filter(|name| {
                    matches!(
                        name.as_str(),
                        "RecoveryRoot" | "native-read.bin" | "Projects"
                    )
                })
                .cloned()
                .collect::<Vec<_>>();
            let unknown_name_count = entry_count.saturating_sub(known_names.len());
            Ok(ChildDirectoryComparison {
                matches_expected: actual == expected_sorted,
                entry_count,
                known_names,
                unknown_name_count,
            })
        })();
        match probe {
            Ok(result) => println!(
                "\nRAIUN_RUST_CHILD_DIRECTORY COUNT={} MATCH={} KNOWN={} UNKNOWN={}",
                result.entry_count,
                u8::from(result.matches_expected),
                result.known_names.join(","),
                result.unknown_name_count,
            ),
            Err(()) => panic!("Rust child directory probe failed closed"),
        }
    }

    struct GuardedRecoveryRemoteProbe {
        calls: std::sync::atomic::AtomicUsize,
    }

    impl raiun_cloudfiles_windows::RecoveryRemote for GuardedRecoveryRemoteProbe {
        fn server_origin(&self) -> Option<&str> {
            Some("https://fixture.invalid")
        }

        fn stat(
            &self,
            _scope: &raiun_cloudfiles_windows::EditJournalScope,
            _relative_path: &str,
        ) -> Result<raiun_cloudfiles_windows::RecoveryRemoteVersion, raiun_core::backend::CloudError>
        {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(raiun_core::backend::CloudError::new(
                raiun_core::backend::ErrorKind::Offline,
                "fixture",
            ))
        }

        fn conditional_upload(
            &self,
            _scope: &raiun_cloudfiles_windows::EditJournalScope,
            _relative_path: &str,
            _content: &[u8],
            _expected_resource_id: &str,
            _condition: raiun_core::backend::WriteCondition,
            _expected_size: u64,
        ) -> Result<raiun_cloudfiles_windows::RecoveryRemoteVersion, raiun_core::backend::CloudError>
        {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(raiun_core::backend::CloudError::new(
                raiun_core::backend::ErrorKind::Offline,
                "fixture",
            ))
        }

        fn readback(
            &self,
            _scope: &raiun_cloudfiles_windows::EditJournalScope,
            _relative_path: &str,
            _expected_resource_id: &str,
            _expected_etag: Option<&str>,
            _max_bytes: usize,
        ) -> Result<raiun_cloudfiles_windows::RecoveryRemoteBody, raiun_core::backend::CloudError>
        {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(raiun_core::backend::CloudError::new(
                raiun_core::backend::ErrorKind::Offline,
                "fixture",
            ))
        }
    }

    #[cfg(all(windows, debug_assertions))]
    struct DispatchRecoveryProbe {
        scope: raiun_cloudfiles_windows::ProviderScope,
        root: raiun_cloudfiles_windows::ConfiguredRootIdentity,
        calls: std::sync::atomic::AtomicUsize,
    }

    #[cfg(all(windows, debug_assertions))]
    impl raiun_cloudfiles_windows::PreparedEditRecovery for DispatchRecoveryProbe {
        fn provider_scope(&self) -> &raiun_cloudfiles_windows::ProviderScope {
            &self.scope
        }

        fn root_identity(&self) -> raiun_cloudfiles_windows::ConfiguredRootIdentity {
            self.root
        }

        fn append_edit(
            &self,
            _binding: &raiun_cloudfiles_windows::PlaceholderEditBinding,
            _root_identity: raiun_cloudfiles_windows::ConfiguredRootIdentity,
            _local_file: raiun_cloudfiles_windows::LocalFileIdentity,
            _relative_path: &str,
            _content: &[u8],
        ) -> Result<(), raiun_cloudfiles_windows::BackendError> {
            Err(raiun_cloudfiles_windows::BackendError::Unavailable)
        }

        fn has_unresolved(&self) -> Result<bool, raiun_cloudfiles_windows::BackendError> {
            Ok(false)
        }

        fn dispatch_recovered_edit(
            &self,
            record_id: &str,
            generation: u64,
            remote: &dyn raiun_cloudfiles_windows::RecoveryRemote,
            _approval: raiun_cloudfiles_windows::ExplicitRecoveryApproval,
        ) -> Result<
            raiun_cloudfiles_windows::ReconciliationOutcome,
            raiun_cloudfiles_windows::JournalError,
        > {
            if record_id != "aabbccdd"
                || generation != 9
                || remote.server_origin() != Some(self.scope.server_origin())
            {
                return Err(raiun_cloudfiles_windows::JournalError::ScopeMismatch);
            }
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(raiun_cloudfiles_windows::ReconciliationOutcome::Deferred)
        }
    }

    #[cfg(all(windows, debug_assertions))]
    #[test]
    fn provider_manager_dispatches_only_the_current_recovery_generation() {
        use raiun_cloudfiles_windows::ProviderScope;
        use raiun_opencloud::OpenCloudClient;

        let client = OpenCloudClient::new("https://fixture.invalid", "synthetic-token".to_owned())
            .expect("synthetic client configuration is valid");
        let scope = ProviderScope::new(
            &client,
            "default".into(),
            "synthetic-account".into(),
            "https://fixture.invalid".into(),
        )
        .expect("scope binds to this client generation");
        let recovery = Arc::new(DispatchRecoveryProbe {
            scope,
            root: raiun_cloudfiles_windows::ConfiguredRootIdentity {
                volume_serial: 11,
                file_index: 22,
            },
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let remote = Arc::new(GuardedRecoveryRemoteProbe {
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let manager = ProviderManager::new();

        assert!(matches!(
            manager
                .dispatch_recovery(1, recovery.clone(), "aabbccdd".into(), 9, remote.clone(),)
                .expect("current generation reaches prepared dispatch"),
            raiun_cloudfiles_windows::ReconciliationOutcome::Deferred
        ));
        assert_eq!(recovery.calls.load(Ordering::SeqCst), 1);

        manager.authorize_generation(2);
        assert!(
            manager
                .dispatch_recovery(1, recovery.clone(), "aabbccdd".into(), 9, remote)
                .is_err()
        );
        assert_eq!(recovery.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn disconnected_control_clients_preserve_agent_and_shutdown_semantics() {
        struct LostReply(std::io::Cursor<Vec<u8>>);
        impl std::io::Read for LostReply {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                self.0.read(buffer)
            }
        }
        impl std::io::Write for LostReply {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let agent = Arc::new(WindowsAgent::new(MemoryStore::default()));
        for frame in [
            b"".as_slice(),
            b"{not-json}\n",
            b"{\"action\":\"status\"}\n",
        ] {
            let mut client = LostReply(std::io::Cursor::new(frame.to_vec()));
            assert!(!super::serve_control_connection(&agent, &mut client));
            assert_eq!(agent.status().unwrap()["connected"], false);
            assert!(!agent.provider.is_connected());
        }
        let mut client = LostReply(std::io::Cursor::new(
            b"{\"action\":\"shutdown\"}\n".to_vec(),
        ));
        assert!(super::serve_control_connection(&agent, &mut client));
    }

    #[test]
    fn disconnected_client_codes_do_not_hide_pipe_ownership_errors() {
        for code in [109, 232, 233] {
            assert!(super::disconnected_pipe_client(
                &std::io::Error::from_raw_os_error(code)
            ));
        }
        for code in [5, 231, 183] {
            assert!(!super::disconnected_pipe_client(
                &std::io::Error::from_raw_os_error(code)
            ));
        }
    }

    #[cfg(all(windows, debug_assertions))]
    fn recovery_page_fixture() -> (
        raiun_cloudfiles_windows::ProviderScope,
        raiun_cloudfiles_windows::ConfiguredRootIdentity,
        raiun_cloudfiles_windows::LocalEditMetadata,
    ) {
        let client = raiun_opencloud::OpenCloudClient::new(
            "https://fixture.invalid",
            "synthetic-token".into(),
        )
        .unwrap();
        let scope = raiun_cloudfiles_windows::ProviderScope::new(
            &client,
            "default".into(),
            "synthetic-account".into(),
            "https://fixture.invalid".into(),
        )
        .unwrap();
        let root = raiun_cloudfiles_windows::ConfiguredRootIdentity {
            volume_serial: 1,
            file_index: 2,
        };
        let metadata = raiun_cloudfiles_windows::LocalEditMetadata {
            record_id: "aabbccdd".into(),
            generation: 9,
            scope: raiun_cloudfiles_windows::EditJournalScope {
                profile_id: "default".into(),
                server_origin: "https://fixture.invalid".into(),
                account_subject: "synthetic-account".into(),
                space_id: "space-a".into(),
                root_resource_id: "root-a".into(),
                root_volume_serial: 1,
                root_file_index: 2,
            },
            local_file: raiun_cloudfiles_windows::LocalFileIdentity {
                volume_serial: 1,
                file_index: 3,
            },
            relative_path: "Personal/saved.txt".into(),
            remote: Some(raiun_cloudfiles_windows::RemoteEditBaseline {
                resource_id: "remote-private-id".into(),
                etag: "\"remote-private-etag\"".into(),
                byte_len: 4,
            }),
            content_len: 4,
            content_sha256: "private-content-digest".into(),
            state: raiun_cloudfiles_windows::LocalEditState::Dirty,
        };
        (scope, root, metadata)
    }

    #[test]
    fn recovery_cursors_refuse_other_accounts_roots_generations_and_agent_instances() {
        let (scope, root, _) = recovery_page_fixture();
        let mut manager = ProviderManager::new();
        let context = manager.recovery_cursor_context(&scope, root, 2).unwrap();
        let raw = serde_json::to_string(&("space-a", "root-a", "aabb", 1_u64)).unwrap();
        let encoded = super::bind_recovery_list_cursor(Some(raw.clone()), &context)
            .unwrap()
            .unwrap();
        let value = Value::String(encoded);
        assert!(
            super::parse_bound_recovery_list_cursor(Some(&value), &context)
                .unwrap()
                .is_some()
        );
        let mut other_root = root;
        other_root.file_index += 1;
        let restarted = ProviderManager::new();
        let mut changed_contexts = vec![
            manager
                .recovery_cursor_context(&scope, other_root, 2)
                .unwrap(),
            manager.recovery_cursor_context(&scope, root, 3).unwrap(),
            restarted.recovery_cursor_context(&scope, root, 2).unwrap(),
        ];
        for (profile, origin, account) in [
            ("other", "https://fixture.invalid", "synthetic-account"),
            ("default", "https://other.invalid", "synthetic-account"),
            ("default", "https://fixture.invalid", "another-account"),
        ] {
            let client =
                raiun_opencloud::OpenCloudClient::new(origin, "synthetic-token".into()).unwrap();
            let other = raiun_cloudfiles_windows::ProviderScope::new(
                &client,
                profile.into(),
                account.into(),
                origin.into(),
            )
            .unwrap();
            changed_contexts.push(manager.recovery_cursor_context(&other, root, 2).unwrap());
        }
        for changed in changed_contexts {
            assert_ne!(context, changed);
            assert!(super::parse_bound_recovery_list_cursor(Some(&value), &changed).is_err());
        }
        assert!(
            super::parse_bound_recovery_list_cursor(Some(&Value::String(raw)), &context).is_err()
        );
        assert!(
            super::parse_bound_recovery_list_cursor(None, &context)
                .unwrap()
                .is_none()
        );
        manager.recovery_cursor_nonce = None;
        assert!(manager.recovery_cursor_context(&scope, root, 2).is_err());
    }

    #[test]
    fn recovery_metadata_pages_preserve_scopes_generations_and_redact_baselines() {
        let (scope, root, first) = recovery_page_fixture();
        let mut second = first.clone();
        second.scope.space_id = "space-b".into();
        let (page, next) =
            super::recovery_metadata_page(vec![second.clone(), first], &scope, root, None, 1)
                .unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0]["space_id"], "space-a");
        assert_eq!(page[0]["state"], "needs_review");
        assert_eq!(page[0]["generation"], 9);
        let encoded = serde_json::to_string(&page).unwrap();
        for private in [
            "remote-private-id",
            "remote-private-etag",
            "private-content-digest",
            "account_subject",
            "server_origin",
        ] {
            assert!(!encoded.contains(private));
        }
        let cursor = super::parse_recovery_list_cursor(
            next.as_ref()
                .map(|value| Value::String(value.clone()))
                .as_ref(),
        )
        .unwrap();
        let (page, next) =
            super::recovery_metadata_page(vec![second], &scope, root, cursor, 1).unwrap();
        assert_eq!(page[0]["space_id"], "space-b");
        assert!(next.is_none());
    }

    #[test]
    fn recovery_metadata_page_refuses_foreign_scope_and_ambiguous_records() {
        let (scope, root, record) = recovery_page_fixture();
        for field in ["profile", "origin", "account", "volume", "root"] {
            let mut changed = record.clone();
            match field {
                "profile" => changed.scope.profile_id = "other".into(),
                "origin" => changed.scope.server_origin = "https://other.invalid".into(),
                "account" => changed.scope.account_subject = "other".into(),
                "volume" => changed.scope.root_volume_serial += 1,
                _ => changed.scope.root_file_index += 1,
            }
            assert!(
                super::recovery_metadata_page(vec![changed], &scope, root, None, 100).is_err(),
                "{field}"
            );
        }
        assert!(
            super::recovery_metadata_page(vec![record.clone(), record], &scope, root, None, 100)
                .is_err()
        );
    }

    #[test]
    fn recovery_metadata_page_honors_control_byte_bound_and_validates_cursors() {
        let (scope, root, record) = recovery_page_fixture();
        let records = (1..=100)
            .map(|generation| {
                let mut row = record.clone();
                row.generation = generation;
                row.relative_path = "\"".repeat(32_000);
                row
            })
            .collect();
        let (page, next) = super::recovery_metadata_page(records, &scope, root, None, 100).unwrap();
        assert!(!page.is_empty() && page.len() < 100 && next.is_some());
        assert!(
            serde_json::to_vec(&page).unwrap().len()
                < raiun_control::MAX_CONTROL_MESSAGE_BYTES / 2 + 1024
        );
        for invalid in [
            json!(true),
            json!("[]"),
            json!("[\"a\",\"b\",\"not-hex\",1]"),
            json!("[\"a\",\"b\",\"aabb\",0]"),
        ] {
            assert!(super::parse_recovery_list_cursor(Some(&invalid)).is_err());
        }
        let agent = Arc::new(WindowsAgent::new(MemoryStore::default()));
        assert!(
            agent
                .handle_request(&json!({"action":"windows_recovery_list","expected_generation":1}))
                .is_err()
        );
        assert!(agent.handle_request(&json!({"action":"windows_recovery_list","profile_id":"other","expected_generation":1})).is_err());
    }

    #[test]
    fn windows_cache_status_account_fence_rejects_transition_and_replaced_root() {
        let agent = WindowsAgent::new(MemoryStore::default());
        let generation = agent.generation.load(Ordering::Acquire);
        agent.provider.authorize_generation(generation);
        let server = "http://127.0.0.1:1";
        let mut state = agent.state.lock().unwrap();
        state.active_generation = generation;
        state.online_authenticated = true;
        state.session = Some(synthetic_session(
            server,
            "synthetic-client",
            unix_time_now() + 3600,
        ));
        let configuration = super::RootConfiguration {
            profile_scope: "default".into(),
            server: server.into(),
            client_id: "synthetic-client".into(),
            issuer: None,
            path: r"C:\SyntheticCacheStatus".into(),
            volume_serial: 4,
            file_index: 5,
            valid: true,
            registration_ownership: Some(RegistrationOwnership {
                state: "registered".into(),
                account_id: personal_account_identity(server, "personal"),
                personal_drive_id: "personal".into(),
                personal_root_resource_id: Some("root".into()),
                volume_serial: 4,
                file_index: 5,
            }),
        };
        state.root_configuration = Some(configuration.clone());
        let token = agent
            .provider
            .configuration_recovery_scope_token(&configuration, generation)
            .unwrap();
        assert!(
            agent
                .check_cache_status_account(&state, generation, &token)
                .is_ok()
        );
        for flag in 0..6 {
            state.logout_pending = flag == 0;
            state.authenticating = flag == 1;
            state.refreshing = flag == 2;
            state.needs_refresh = flag == 3;
            state.session_cleanup_uncertain = flag == 4;
            state.online_authenticated = flag != 5;
            assert!(
                agent
                    .check_cache_status_account(&state, generation, &token)
                    .is_err()
            );
        }
        state.logout_pending = false;
        state.authenticating = false;
        state.refreshing = false;
        state.needs_refresh = false;
        state.session_cleanup_uncertain = false;
        state.online_authenticated = true;
        assert!(
            agent
                .check_cache_status_account(&state, generation, &token)
                .is_ok()
        );
        assert!(
            agent
                .check_cache_status_account(&state, generation + 1, &token)
                .is_err()
        );
        assert!(
            agent
                .check_cache_status_account(&state, generation, &"0".repeat(64))
                .is_err()
        );
        state.root_configuration.as_mut().unwrap().file_index += 1;
        assert!(
            agent
                .check_cache_status_account(&state, generation, &token)
                .is_err()
        );
        state.root_configuration = Some(configuration);
        state.session.as_mut().unwrap().expires_at = unix_time_now();
        assert!(
            agent
                .check_cache_status_account(&state, generation, &token)
                .is_err()
        );
        assert!(!agent.provider.is_connected());
    }

    #[test]
    fn windows_cache_status_rejects_unbound_account_requests_without_connecting() {
        let agent = Arc::new(WindowsAgent::new(MemoryStore::default()));
        let request = json!({"action":"windows_file_cache_status", "profile_id":"default",
            "expected_generation":1, "expected_recovery_scope_token":"0".repeat(64),
            "space_id":"space", "root_resource_id":"root", "path":"/file",
            "resource_id":"file", "etag":"v1", "size":42});
        assert!(agent.handle_request(&request).is_err());
        for (key, value) in [
            ("profile_id", json!("other")),
            ("expected_generation", json!(0)),
            ("expected_recovery_scope_token", json!("A".repeat(64))),
            ("expected_recovery_scope_token", json!("0".repeat(63))),
        ] {
            let mut invalid = request.clone();
            invalid[key] = value;
            assert!(agent.handle_request(&invalid).is_err());
        }
        assert!(!agent.provider.is_connected());
        assert!(agent.state.lock().unwrap().session.is_none());
        assert!(agent.state.lock().unwrap().root_configuration.is_none());
    }

    fn offline_file_test_binding(generation: u64) -> ActiveProviderBinding {
        ActiveProviderBinding {
            generation,
            path: std::path::PathBuf::from(format!("C:/synthetic/offline-{generation}")),
            identity: raiun_cloudfiles_windows::ConfiguredRootIdentity {
                volume_serial: 0x1234,
                file_index: 0x5678,
            },
            personal_space_id: "synthetic-personal-drive".into(),
            personal_root_resource_id: "synthetic-personal-root".into(),
        }
    }

    #[test]
    fn offline_file_page_worker_refuses_stale_binding_disconnect_and_missing_backend() {
        let binding = offline_file_test_binding(7);
        let cancellation = raiun_cloudfiles_windows::CancellationToken::new();
        let inspect = super::windows_cache_status::inspect_worker_file_page;

        assert!(inspect(8, &binding, Some(&binding), true, None, None, &cancellation).is_err());
        assert!(inspect(7, &binding, None, false, None, None, &cancellation).is_err());
        assert!(
            inspect(
                7,
                &binding,
                Some(&binding),
                false,
                None,
                None,
                &cancellation
            )
            .is_err()
        );

        let mut replaced = binding.clone();
        replaced.path = std::path::PathBuf::from(r"C:\Synthetic\replacement");
        assert!(
            inspect(
                7,
                &binding,
                Some(&replaced),
                true,
                None,
                None,
                &cancellation
            )
            .is_err()
        );

        // An exact active binding is still unavailable when the worker has no
        // backend; it must never synthesize an empty listing.
        let error = inspect(7, &binding, Some(&binding), true, None, None, &cancellation)
            .expect_err("missing worker backend cannot become an empty file page");
        assert!(error.contains("disconnected"));
    }

    #[test]
    fn windows_recovery_retry_needs_current_authenticated_scope() {
        let agent = Arc::new(WindowsAgent::new(MemoryStore::default()));
        let error = agent
            .handle_request(&json!({
                "action":"windows_recovery_retry",
                "record_id":"aabbccdd",
                "generation":9
            }))
            .expect_err("disconnected requests cannot dispatch a recovered edit");
        assert!(error.contains("Connect this account"));
        assert_eq!(agent.status().unwrap()["mounted"], false);
        assert_eq!(agent.status().unwrap()["provider_supported"], false);
    }

    #[test]
    #[cfg(debug_assertions)]
    fn initial_save_dispatch_stays_disabled_and_empty_worker_does_not_scan_recovery() {
        let manager = super::ProviderManager::new();
        assert!(!manager.initial_save_test_activation.load(Ordering::Acquire));
        assert_eq!(
            super::dispatch_one_initial_edit(None, None, None, &manager.authorized_generation)
                .unwrap(),
            None
        );
        // No connection is created and no recovered journal is inspected.
        assert!(!manager.connected.load(Ordering::Acquire));
    }

    #[test]
    fn initial_save_borrowed_remote_rejects_revoked_agent_generation_before_io() {
        use raiun_cloudfiles_windows::RecoveryRemote as _;
        let generation = Arc::new(std::sync::atomic::AtomicU64::new(8));
        let probe = GuardedRecoveryRemoteProbe {
            calls: std::sync::atomic::AtomicUsize::new(0),
        };
        let remote = AgentGenerationRecoveryRemote {
            inner: RecoveryRemoteHandle::Borrowed(&probe),
            authorized_generation: Arc::clone(&generation),
            expected_generation: 7,
        };
        let scope = raiun_cloudfiles_windows::EditJournalScope {
            profile_id: "default".into(),
            server_origin: "https://fixture.invalid".into(),
            account_subject: "synthetic-account".into(),
            space_id: "synthetic-space".into(),
            root_resource_id: "synthetic-root".into(),
            root_volume_serial: 1,
            root_file_index: 2,
        };
        assert_eq!(remote.server_origin(), None);
        assert!(remote.ensure_authorized(&scope).is_err());
        assert!(remote.stat(&scope, "notes.txt").is_err());
        assert_eq!(probe.calls.load(Ordering::Acquire), 0);
    }

    #[test]
    fn recovery_remote_refuses_calls_after_agent_generation_changes() {
        use raiun_cloudfiles_windows::RecoveryRemote as _;

        let generation = Arc::new(std::sync::atomic::AtomicU64::new(7));
        let probe = Arc::new(GuardedRecoveryRemoteProbe {
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let remote = super::AgentGenerationRecoveryRemote {
            inner: RecoveryRemoteHandle::Owned(probe.clone()),
            authorized_generation: Arc::clone(&generation),
            expected_generation: 7,
        };
        let scope = raiun_cloudfiles_windows::EditJournalScope {
            profile_id: "default".into(),
            server_origin: "https://fixture.invalid".into(),
            account_subject: "synthetic-account".into(),
            space_id: "synthetic-space".into(),
            root_resource_id: "synthetic-root".into(),
            root_volume_serial: 1,
            root_file_index: 2,
        };
        assert_eq!(remote.server_origin(), Some("https://fixture.invalid"));
        remote.ensure_authorized(&scope).unwrap();

        generation.store(8, Ordering::Release);
        assert_eq!(remote.server_origin(), None);
        assert!(remote.ensure_authorized(&scope).is_err());
        assert!(remote.stat(&scope, "/file.txt").is_err());
        assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
    }

    #[cfg(all(windows, debug_assertions))]
    #[test]
    #[ignore = "requires disposable Windows VM, packaged GUI, Cloud Files and current-user DPAPI"]
    fn native_normal_lifecycle_restores_and_reconnects_registered_namespace() {
        // An external VM harness may opt into a bounded Explorer first-view
        // handshake. The absent-variable path deliberately leaves the native
        // lifecycle test unchanged.
        let explorer_checkpoint_dir = std::env::var_os("RAIUN_NATIVE_EXPLORER_CHECKPOINT_DIR")
            .map(std::path::PathBuf::from)
            .map(|path| {
                let metadata = std::fs::symlink_metadata(&path)
                    .expect("Explorer checkpoint directory must already exist");
                use std::os::windows::fs::MetadataExt;
                const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
                assert!(
                    metadata.is_dir()
                        && !metadata.file_type().is_symlink()
                        && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
                    "Explorer checkpoint path must be a plain directory"
                );
                let path = std::fs::canonicalize(path)
                    .expect("canonicalize Explorer checkpoint directory");
                assert!(
                    std::fs::read_dir(&path)
                        .expect("inspect Explorer checkpoint directory")
                        .next()
                        .is_none(),
                    "Explorer checkpoint directory must be fresh and empty"
                );
                path
            });
        let explorer_checkpoint_run_id = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock is after Unix epoch")
                .as_nanos()
        );
        let smoke = std::env::temp_dir().join(format!(
            "Raiun-Rust-Child-Smoke-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock is after Unix epoch")
                .as_nanos()
        ));
        std::fs::create_dir(&smoke).expect("create unique ordinary Rust-child smoke directory");
        std::fs::write(smoke.join("native-read.bin"), b"bounded probe smoke")
            .expect("write ordinary Rust-child smoke file");
        let smoke_result = child_process_rust_directory_matches(&smoke, &["native-read.bin"])
            .expect("bounded Rust child process returns a parseable summary");
        assert!(smoke_result.matches_expected);
        assert_eq!(smoke_result.entry_count, 1);
        assert_eq!(smoke_result.known_names, ["native-read.bin"]);
        assert_eq!(smoke_result.unknown_name_count, 0);
        std::fs::remove_file(smoke.join("native-read.bin"))
            .expect("remove successful ordinary Rust-child smoke file");
        std::fs::remove_dir(&smoke).expect("remove successful ordinary Rust-child smoke directory");

        let (server, fixture) = synthetic_personal_spaces_server_with_native_read_files(|_| {});
        let store = Arc::new(MemoryStore::default());
        let session = session_for_refresh(&format!("{server}/token"), unix_time_now() + 3600);
        seed_active_session(&store, "default", session);
        let agent = Arc::new(WindowsAgent::new(store.clone()));
        let authorize_fixture = |agent: &Arc<WindowsAgent>| {
            let generation = agent.generation.load(Ordering::Acquire);
            let mut state = agent.state.lock().unwrap();
            state.active_generation = generation;
            state.online_authenticated = true;
            state.needs_refresh = false;
            state.refreshing = false;
            agent.provider.authorize_generation(generation);
        };
        authorize_fixture(&agent);
        let root = std::env::temp_dir().join(format!(
            "Raiun-Normal-Lifecycle-{}-{}",
            std::process::id(),
            unix_time_now()
        ));
        std::fs::create_dir(&root).unwrap();
        if let Some(checkpoint_dir) = explorer_checkpoint_dir.as_deref() {
            let canonical_root = std::fs::canonicalize(&root)
                .expect("canonicalize exact synthetic Cloud Files root");
            assert!(
                !checkpoint_dir.starts_with(&canonical_root)
                    && !canonical_root.starts_with(checkpoint_dir),
                "Explorer checkpoint files must remain outside the synthetic root"
            );
        }
        let request = json!({"action":"configure_root", "cloud_root":root.to_str().unwrap()});
        agent
            .handle_request(&request)
            .expect("default gate configures without activation");
        assert!(!agent.provider.connected.load(Ordering::Acquire));
        assert!(std::fs::read_dir(&root).unwrap().next().is_none());
        // Enable only this test instance, then use the actual configure action
        // and its normal lifecycle hook; no direct connect helper is called.
        agent
            .provider
            .lifecycle_test_activation
            .store(true, Ordering::Release);
        agent
            .handle_request(&request)
            .expect("configure action connects the exact fixture root");
        let initial_scope_token =
            agent.status().unwrap()["root_configuration"]["recovery_scope_token"].clone();
        assert_eq!(initial_scope_token.as_str().unwrap().len(), 64);
        assert!(agent.provider.connected.load(Ordering::Acquire));
        assert!(root.join("Personal").is_dir() && root.join("Spaces").is_dir());
        let registered_identity = raiun_cloudfiles_windows::pin_registered_configured_root(
            &root,
            agent
                .state
                .lock()
                .unwrap()
                .root_configuration
                .as_ref()
                .map(|config| raiun_cloudfiles_windows::ConfiguredRootIdentity {
                    volume_serial: config.volume_serial,
                    file_index: config.file_index,
                })
                .unwrap(),
        )
        .unwrap()
        .identity();
        assert!(
            raiun_cloudfiles_windows::registered_configured_root_overlaps(
                &root,
                registered_identity,
                root.parent().unwrap(),
            )
            .unwrap()
        );
        assert!(
            raiun_cloudfiles_windows::registered_configured_root_overlaps(
                &root,
                raiun_cloudfiles_windows::ConfiguredRootIdentity {
                    file_index: registered_identity.file_index ^ 1,
                    ..registered_identity
                },
                root.parent().unwrap(),
            )
            .is_err()
        );
        let configured = agent
            .state
            .lock()
            .unwrap()
            .root_configuration
            .clone()
            .unwrap();
        assert_eq!(
            configured.registration_ownership.as_ref().unwrap().state,
            "registered"
        );
        agent
            .handle_request(&request)
            .expect("reconfiguring the exact active registered root stays idempotent");
        let stored = agent
            .session_store
            .load_root_config("default", &server, "synthetic-client")
            .unwrap();
        WindowsAgent::maybe_connect_provider(&agent.session_store, &agent.state, &agent.provider)
            .expect("repeated normal hook reuses only the exact active binding");
        assert_eq!(
            agent.status().unwrap()["root_configuration"]["recovery_scope_token"],
            initial_scope_token
        );
        assert_eq!(
            agent.state.lock().unwrap().root_configuration.as_ref(),
            Some(&configured)
        );
        assert_eq!(
            agent
                .session_store
                .load_root_config("default", &server, "synthetic-client")
                .unwrap(),
            stored
        );
        let owner = configured.registration_ownership.as_ref().unwrap();
        assert!(
            agent
                .provider
                .connection_matches(super::ActiveProviderBinding {
                    generation: agent.generation.load(Ordering::Acquire),
                    path: root.join("different-root"),
                    identity: raiun_cloudfiles_windows::ConfiguredRootIdentity {
                        volume_serial: configured.volume_serial,
                        file_index: configured.file_index,
                    },
                    personal_space_id: owner.personal_drive_id.clone(),
                    personal_root_resource_id: owner.personal_root_resource_id.clone().unwrap(),
                })
                .is_err()
        );
        assert_eq!(
            agent.state.lock().unwrap().root_configuration.as_ref(),
            Some(&configured)
        );
        assert_eq!(
            agent
                .session_store
                .load_root_config("default", &server, "synthetic-client")
                .unwrap(),
            stored
        );
        agent
            .provider
            .disconnect()
            .expect("disconnect preserves registration");
        drop(agent);
        let restored = Arc::new(WindowsAgent::new(store));
        let loaded = restored
            .state
            .lock()
            .unwrap()
            .root_configuration
            .clone()
            .unwrap();
        assert!(
            loaded.valid,
            "populated exact registered root must remain valid after load"
        );
        assert_eq!(loaded.volume_serial, configured.volume_serial);
        assert_eq!(loaded.file_index, configured.file_index);
        assert!(!restored.provider.connected.load(Ordering::Acquire));
        // Restored credentials alone cannot connect. The normal startup refresh
        // must rotate the synthetic token before admitting this exact root.
        restored
            .provider
            .lifecycle_test_activation
            .store(true, Ordering::Release);
        WindowsAgent::maybe_connect_provider(
            &restored.session_store,
            &restored.state,
            &restored.provider,
        )
        .unwrap();
        assert!(!restored.provider.connected.load(Ordering::Acquire));
        restored.maybe_start_refresh().unwrap();
        restored
            .refresh_thread
            .lock()
            .unwrap()
            .take()
            .expect("startup launches the actual refresh worker")
            .join()
            .expect("synthetic refresh and native reconnect complete");
        {
            let state = restored.state.lock().unwrap();
            assert!(state.online_authenticated && !state.refreshing);
            let session = state.session.as_ref().unwrap();
            assert_eq!(session.access_token, "rotated-native-access-token");
            assert_eq!(
                session.refresh_token.as_deref(),
                Some("rotated-native-refresh-token")
            );
        }
        let saved = restored
            .session_store
            .load_active("default")
            .unwrap()
            .unwrap();
        assert_eq!(saved.access_token, "rotated-native-access-token");
        assert_ne!(
            restored.status().unwrap()["root_configuration"]["recovery_scope_token"],
            initial_scope_token
        );
        assert!(restored.provider.connected.load(Ordering::Acquire));
        assert!(
            restored
                .provider
                .connection_matches(super::ActiveProviderBinding {
                    generation: restored.state.lock().unwrap().active_generation,
                    path: root.clone(),
                    identity: raiun_cloudfiles_windows::ConfiguredRootIdentity {
                        volume_serial: configured.volume_serial,
                        file_index: configured.file_index,
                    },
                    personal_space_id: owner.personal_drive_id.clone(),
                    personal_root_resource_id: owner
                        .personal_root_resource_id
                        .clone()
                        .expect("the exact verified Personal root remains bound"),
                })
                .expect("inspect the live exact native root/account binding")
        );
        assert!(root.join("Personal").is_dir() && root.join("Spaces").is_dir());
        let enumerate_with_timeout = |path: &Path| {
            let (response, result) = std::sync::mpsc::sync_channel(1);
            let path = path.to_path_buf();
            thread::spawn(move || {
                let entries = (|| -> std::io::Result<Vec<String>> {
                    let mut names = Vec::new();
                    for entry in
                        std::fs::read_dir(path)?.take(MAX_NATIVE_READ_DIRECTORY_ENTRIES + 1)
                    {
                        let name = entry?.file_name().into_string().map_err(|_| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "native fixture entry name is not UTF-8",
                            )
                        })?;
                        names.push(name);
                    }
                    if names.len() > MAX_NATIVE_READ_DIRECTORY_ENTRIES {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "native fixture directory exceeds the entry bound",
                        ));
                    }
                    names.sort();
                    Ok(names)
                })();
                let _ = response.send(entries);
            });
            result.recv_timeout(Duration::from_secs(20))
        };
        let inspect_directory_with_timeout = |path: &Path| {
            let (response, result) = std::sync::mpsc::sync_channel(1);
            let path = path.to_path_buf();
            thread::spawn(move || {
                use std::os::windows::fs::MetadataExt;
                const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
                let state = std::fs::symlink_metadata(path).map(|metadata| {
                    let attributes = metadata.file_attributes();
                    (attributes, attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0)
                });
                let _ = response.send(state);
            });
            result.recv_timeout(Duration::from_secs(20))
        };
        macro_rules! assert_native_entries {
            ($path:expr, $label:literal, [$($expected:literal),* $(,)?], $compare_child:expr) => {{
                let path = $path;
                let expected: Vec<&str> = vec![$($expected),*];
                if let Some(checkpoint_dir) = explorer_checkpoint_dir.as_deref() {
                    if let Err(error) = explorer_first_view_checkpoint(
                        checkpoint_dir,
                        &explorer_checkpoint_run_id,
                        &root,
                        &path,
                        $label,
                        &expected,
                        &restored.provider,
                    ) {
                        // The external listing is uncertain. Keep the exact
                        // synthetic connection and fixture alive for inspection.
                        std::mem::forget(Arc::clone(&restored));
                        std::mem::forget(fixture);
                        panic!("Explorer first-view checkpoint failed for {}: {}", $label, error);
                    }
                }
                let state_before = match inspect_directory_with_timeout(&path) {
                    Ok(Ok(state)) => state,
                    Ok(Err(error)) => panic!("native directory metadata inspection failed for {}: {}", $label, error),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        std::mem::forget(Arc::clone(&restored));
                        std::mem::forget(fixture);
                        panic!("native directory metadata inspection timed out for {}", $label);
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        panic!("native directory metadata worker stopped for {}", $label);
                    }
                };
                let callbacks_before = restored
                    .provider
                    .directory_observation()
                    .expect("capture native directory callbacks before OS enumeration");
                let propfind_before = fixture.native_reads.lock().unwrap()
                    .personal_depth_one_propfind_count;
                let first_read_started = std::time::Instant::now();
                let actual_result = match enumerate_with_timeout(&path) {
                    Ok(Ok(names)) => Ok(names),
                    Ok(Err(error)) => Err(error.to_string()),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        // An OS enumeration may still be servicing Cloud Files;
                        // leave the registered root and recovery state intact.
                        std::mem::forget(Arc::clone(&restored));
                        std::mem::forget(fixture);
                        panic!("native OS enumeration timed out for {}", $label);
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        panic!("native OS enumeration worker stopped for {}", $label);
                    }
                };
                let first_read_elapsed = first_read_started.elapsed();
                let mut expected_sorted = expected
                    .iter()
                    .map(|name| (*name).to_owned())
                    .collect::<Vec<_>>();
                expected_sorted.sort();
                let read_dir_matches = actual_result.as_ref().is_ok_and(|names| {
                    let mut names = names.clone();
                    names.sort();
                    names == expected_sorted
                });
                let callbacks_after_read_dir = restored
                    .provider
                    .directory_observation()
                    .expect("capture native directory callbacks after OS enumeration");
                let state_after_read_dir = match inspect_directory_with_timeout(&path) {
                    Ok(Ok(state)) => state,
                    Ok(Err(error)) => panic!("post-enumeration directory metadata inspection failed for {}: {}", $label, error),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        std::mem::forget(Arc::clone(&restored));
                        std::mem::forget(fixture);
                        panic!("post-enumeration directory metadata inspection timed out for {}", $label);
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        panic!("post-enumeration directory metadata worker stopped for {}", $label);
                    }
                };
                let first_callback_entries = callbacks_after_read_dir.0.0
                    .saturating_sub(callbacks_before.0.0);
                let first_callback_guard_rejections = callbacks_after_read_dir.0.1
                    .saturating_sub(callbacks_before.0.1);
                let first_accepted_callbacks = callbacks_after_read_dir.0.2
                    .saturating_sub(callbacks_before.0.2);
                let first_entries_submitted = callbacks_after_read_dir.0.4
                    .saturating_sub(callbacks_before.0.4);
                let first_propfind_after = fixture.native_reads.lock().unwrap()
                    .personal_depth_one_propfind_count;
                let mut child_comparison = None;
                let mut child_comparison_error = None;
                let mut rust_child_comparison = None;
                let mut rust_child_comparison_error = None;
                let mut rust_child_callback_entries = None;
                let mut rust_child_guard_rejections = None;
                let mut rust_child_accepted_callbacks = None;
                let mut rust_child_entries_submitted = None;
                let mut rust_child_propfind_delta = None;
                let mut second_read_dir_result = None;
                let mut second_read_dir_matches = None;
                let mut second_read_elapsed = None;
                let mut second_read_callback_entries = None;
                let mut second_read_guard_rejections = None;
                let mut second_read_accepted_callbacks = None;
                let mut second_read_entries_submitted = None;
                let mut second_read_propfind_delta = None;
                let mut post_child_read_dir_result = None;
                let mut post_child_read_dir_matches = None;
                let mut post_child_read_dir_callback_delta = None;
                let mut final_state = state_after_read_dir;
                if $compare_child && !read_dir_matches {
                    // Reopen and enumerate from this same process before the
                    // external child query. This separates first-call
                    // population timing from process/API differences; it is
                    // diagnostic and does not replace the first-read result.
                    let callbacks_before_second_read = restored
                        .provider
                        .directory_observation()
                        .expect("capture callbacks before immediate second Rust enumeration");
                    let second_read_started = std::time::Instant::now();
                    let second_result = match enumerate_with_timeout(&path) {
                        Ok(Ok(names)) => Ok(names),
                        Ok(Err(error)) => Err(error.to_string()),
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                            std::mem::forget(Arc::clone(&restored));
                            std::mem::forget(fixture);
                            panic!("immediate second Rust enumeration timed out for {}", $label);
                        }
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                            Err("immediate second Rust enumeration worker stopped".to_owned())
                        }
                    };
                    second_read_elapsed = Some(second_read_started.elapsed());
                    let callbacks_after_second_read = restored
                        .provider
                        .directory_observation()
                        .expect("capture callbacks after immediate second Rust enumeration");
                    second_read_callback_entries = Some(
                        callbacks_after_second_read
                            .0
                            .0
                            .saturating_sub(callbacks_before_second_read.0.0),
                    );
                    second_read_guard_rejections = Some(
                        callbacks_after_second_read
                            .0
                            .1
                            .saturating_sub(callbacks_before_second_read.0.1),
                    );
                    second_read_accepted_callbacks = Some(
                        callbacks_after_second_read
                            .0
                            .2
                            .saturating_sub(callbacks_before_second_read.0.2),
                    );
                    second_read_entries_submitted = Some(
                        callbacks_after_second_read
                            .0
                            .4
                            .saturating_sub(callbacks_before_second_read.0.4),
                    );
                    second_read_propfind_delta = Some(
                        fixture
                            .native_reads
                            .lock()
                            .unwrap()
                            .personal_depth_one_propfind_count
                            .saturating_sub(first_propfind_after),
                    );
                    second_read_dir_matches = Some(second_result.as_ref().is_ok_and(|names| {
                        let mut names = names.clone();
                        names.sort();
                        names == expected_sorted
                    }));
                    second_read_dir_result = Some(second_result);

                    if !second_read_dir_matches.unwrap_or(false) {
                        let callbacks_before_rust_child = restored
                            .provider
                            .directory_observation()
                            .expect("capture callbacks before Rust child enumeration");
                        let rust_child_propfind_before = fixture
                            .native_reads
                            .lock()
                            .unwrap()
                            .personal_depth_one_propfind_count;
                        rust_child_comparison = match
                            child_process_rust_directory_matches(&path, &expected)
                        {
                            Ok(comparison) => Some(comparison),
                            Err(error) if error.contains("child left running") => {
                                std::mem::forget(Arc::clone(&restored));
                                std::mem::forget(fixture);
                                panic!("Rust child enumeration timed out for {}", $label);
                            }
                            Err(error) => {
                                eprintln!("Rust child enumeration diagnostic failed label={} error={}", $label, error);
                                rust_child_comparison_error = Some(error);
                                None
                            }
                        };
                        let callbacks_after_rust_child = restored
                            .provider
                            .directory_observation()
                            .expect("capture callbacks after Rust child enumeration");
                        rust_child_callback_entries = Some(
                            callbacks_after_rust_child
                                .0
                                .0
                                .saturating_sub(callbacks_before_rust_child.0.0),
                        );
                        rust_child_guard_rejections = Some(
                            callbacks_after_rust_child
                                .0
                                .1
                                .saturating_sub(callbacks_before_rust_child.0.1),
                        );
                        rust_child_accepted_callbacks = Some(
                            callbacks_after_rust_child
                                .0
                                .2
                                .saturating_sub(callbacks_before_rust_child.0.2),
                        );
                        rust_child_entries_submitted = Some(
                            callbacks_after_rust_child
                                .0
                                .4
                                .saturating_sub(callbacks_before_rust_child.0.4),
                        );
                        rust_child_propfind_delta = Some(
                            fixture
                                .native_reads
                                .lock()
                                .unwrap()
                                .personal_depth_one_propfind_count
                                .saturating_sub(rust_child_propfind_before),
                        );
                    }

                    child_comparison = match child_process_directory_matches(&path, &expected) {
                        Ok(comparison) => Some(comparison),
                        Err(error) if error.contains("exceeded its bounded wait") => {
                            std::mem::forget(Arc::clone(&restored));
                            std::mem::forget(fixture);
                            panic!("child OS enumeration timed out for {}", $label);
                        }
                        Err(error) => {
                            eprintln!("child OS enumeration diagnostic failed label={} error={}", $label, error);
                            child_comparison_error = Some(error);
                            None
                        }
                    };
                    if child_comparison
                        .as_ref()
                        .is_some_and(|comparison| comparison.matches_expected)
                    {
                        // A fresh in-process read after the child query helps
                        // distinguish a transient first enumeration result
                        // from a stable namespace state. This is diagnostic
                        // only: do not treat the second read as proof that the
                        // first read succeeded or was repaired.
                        let callbacks_before_post_child = restored
                            .provider
                            .directory_observation()
                            .expect("capture callbacks before post-child Rust enumeration");
                        let fresh_result = match enumerate_with_timeout(&path) {
                            Ok(Ok(names)) => Ok(names),
                            Ok(Err(error)) => Err(error.to_string()),
                            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                                std::mem::forget(Arc::clone(&restored));
                                std::mem::forget(fixture);
                                panic!("post-child Rust enumeration timed out for {}", $label);
                            }
                            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                                Err("post-child Rust enumeration worker stopped".to_owned())
                            }
                        };
                        let callbacks_after_post_child = restored
                            .provider
                            .directory_observation()
                            .expect("capture callbacks after post-child Rust enumeration");
                        post_child_read_dir_callback_delta = Some(
                            callbacks_after_post_child
                                .0
                                .2
                                .saturating_sub(callbacks_before_post_child.0.2),
                        );
                        post_child_read_dir_matches = Some(fresh_result.as_ref().is_ok_and(|names| {
                            let mut names = names.clone();
                            names.sort();
                            names == expected_sorted
                        }));
                        post_child_read_dir_result = Some(fresh_result);
                    }
                    let after_child = restored
                        .provider
                        .directory_observation()
                        .expect("capture native callbacks after child OS enumeration");
                    final_state = match inspect_directory_with_timeout(&path) {
                        Ok(Ok(state)) => state,
                        Ok(Err(error)) => panic!("child-query directory metadata inspection failed for {}: {}", $label, error),
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                            std::mem::forget(Arc::clone(&restored));
                            std::mem::forget(fixture);
                            panic!("child-query directory metadata inspection timed out for {}", $label);
                        }
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                            panic!("child-query directory metadata worker stopped for {}", $label);
                        }
                    };
                    let child_query_propfind_after = fixture.native_reads.lock().unwrap()
                        .personal_depth_one_propfind_count;
                    eprintln!(
                        "native OS directory cumulative-after-child label={} callback_entries={} guard_rejections={} accepted_callbacks={} entries_submitted={} personal_depth1_propfinds={}",
                        $label,
                        after_child.0.0.saturating_sub(callbacks_before.0.0),
                        after_child.0.1.saturating_sub(callbacks_before.0.1),
                        after_child.0.2.saturating_sub(callbacks_before.0.2),
                        after_child.0.4.saturating_sub(callbacks_before.0.4),
                        child_query_propfind_after.saturating_sub(propfind_before),
                    );
                }
                eprintln!(
                    "native OS directory diagnostic label={} first_rust_read_dir_elapsed={:?} first_read_dir_result={:?} first_read_dir_matches={} first_phase_callback_entries={} first_phase_guard_rejections={} first_phase_accepted_callbacks={} first_phase_entries_submitted={} first_phase_personal_depth1_propfinds={} immediate_second_rust_elapsed={:?} immediate_second_rust_result={:?} immediate_second_rust_matches={:?} second_phase_callback_entries={:?} second_phase_guard_rejections={:?} second_phase_accepted_callbacks={:?} second_phase_entries_submitted={:?} second_phase_personal_depth1_propfinds={:?} rust_child_matches={:?} rust_child_entry_count={:?} rust_child_known_synthetic_names={:?} rust_child_unknown_name_count={:?} rust_child_error={:?} rust_child_callback_entries={:?} rust_child_guard_rejections={:?} rust_child_accepted_callbacks={:?} rust_child_entries_submitted={:?} rust_child_personal_depth1_propfinds={:?} child_matches={:?} child_entry_count={:?} child_known_synthetic_names={:?} child_unknown_name_count={:?} child_error={:?} post_child_rust_read_dir_result={:?} post_child_rust_read_dir_matches={:?} post_child_rust_accepted_callback_delta={:?} windows_file_attributes_before_after={:?}->{:?} exact_cloud_files_placeholder_state=unavailable_through_safe_agent_api",
                    $label,
                    first_read_elapsed,
                    actual_result,
                    read_dir_matches,
                    first_callback_entries,
                    first_callback_guard_rejections,
                    first_accepted_callbacks,
                    first_entries_submitted,
                    first_propfind_after.saturating_sub(propfind_before),
                    second_read_elapsed,
                    second_read_dir_result,
                    second_read_dir_matches,
                    second_read_callback_entries,
                    second_read_guard_rejections,
                    second_read_accepted_callbacks,
                    second_read_entries_submitted,
                    second_read_propfind_delta,
                    rust_child_comparison
                        .as_ref()
                        .map(|comparison| comparison.matches_expected),
                    rust_child_comparison
                        .as_ref()
                        .map(|comparison| comparison.entry_count),
                    rust_child_comparison
                        .as_ref()
                        .map(|comparison| &comparison.known_names),
                    rust_child_comparison
                        .as_ref()
                        .map(|comparison| comparison.unknown_name_count),
                    rust_child_comparison_error,
                    rust_child_callback_entries,
                    rust_child_guard_rejections,
                    rust_child_accepted_callbacks,
                    rust_child_entries_submitted,
                    rust_child_propfind_delta,
                    child_comparison
                        .as_ref()
                        .map(|comparison| comparison.matches_expected),
                    child_comparison
                        .as_ref()
                        .map(|comparison| comparison.entry_count),
                    child_comparison
                        .as_ref()
                        .map(|comparison| &comparison.known_names),
                    child_comparison
                        .as_ref()
                        .map(|comparison| comparison.unknown_name_count),
                    child_comparison_error,
                    post_child_read_dir_result,
                    post_child_read_dir_matches,
                    post_child_read_dir_callback_delta,
                    state_before,
                    final_state,
                );
                assert!(
                    read_dir_matches
                        || child_comparison
                            .as_ref()
                            .is_some_and(|comparison| comparison.matches_expected),
                    "native OS enumeration did not expose expected {} entries",
                    $label
                );
            }};
        }
        assert_native_entries!(root.join("Personal"), "Personal", ["native-read.bin"], true);
        assert_native_entries!(root.join("Spaces"), "Spaces", ["Projects"], true);
        assert_native_entries!(
            root.join("Spaces").join("Projects"),
            "Projects Space",
            ["RecoveryRoot", "native-read.bin"],
            true
        );
        let native_reads = [
            (
                root.join("Personal").join("native-read.bin"),
                b"synthetic Personal native read bytes".as_slice(),
                NativeReadFixturePath::Personal,
            ),
            (
                root.join("Spaces").join("Projects").join("native-read.bin"),
                b"synthetic Projects Space native read bytes".as_slice(),
                NativeReadFixturePath::ProjectsSpace,
            ),
        ];
        let read_with_timeout = |path: &Path, maximum_bytes: usize| {
            let (response, result) = std::sync::mpsc::sync_channel(1);
            let path = path.to_path_buf();
            thread::spawn(move || {
                let read = std::fs::File::open(path).and_then(|file| {
                    let mut bounded = file.take(maximum_bytes.saturating_add(1) as u64);
                    let mut bytes = Vec::with_capacity(maximum_bytes);
                    bounded.read_to_end(&mut bytes)?;
                    Ok(bytes)
                });
                let _ = response.send(read);
            });
            result.recv_timeout(Duration::from_secs(20))
        };
        let hydration_provider = Arc::clone(&restored.provider);
        let hydrate_with_timeout = move |fixture| {
            let (response, result) = std::sync::mpsc::sync_channel(1);
            let provider = Arc::clone(&hydration_provider);
            thread::spawn(move || {
                let _ = response.send(provider.hydrate_native_read_fixture_for_test(fixture));
            });
            result.recv_timeout(Duration::from_secs(20))
        };
        for (path, expected, native_file) in native_reads {
            let mut read = read_with_timeout(&path, expected.len());
            let mut hydration_mode = "implicit_os_read";
            if matches!(&read, Ok(Err(_))) {
                let hydration_result = match hydrate_with_timeout(native_file) {
                    Ok(Ok(result)) => result,
                    Ok(Err(error)) => panic!("native test hydration failed: {error}"),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        // Do not tear down a connection while native hydration
                        // may still be in flight.
                        std::mem::forget(restored);
                        std::mem::forget(fixture);
                        panic!("native fixture hydration exceeded its bounded wait");
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        panic!("native fixture hydration worker stopped unexpectedly");
                    }
                };
                assert!(
                    hydration_result >= 0,
                    "CFAPI accepts explicit test hydration"
                );
                hydration_mode = "explicit_test_cfapi";
                read = read_with_timeout(&path, expected.len());
            }
            match read {
                Ok(Ok(bytes)) => {
                    assert_eq!(bytes, expected, "native read hydrates {path:?}");
                    let mut reads = fixture.native_reads.lock().unwrap();
                    match native_file {
                        NativeReadFixturePath::Personal => {
                            reads.personal_hydration_mode = Some(hydration_mode);
                        }
                        NativeReadFixturePath::ProjectsSpace => {
                            reads.project_hydration_mode = Some(hydration_mode);
                        }
                    }
                }
                Ok(Err(error)) => panic!("native placeholder read failed at {path:?}: {error}"),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    // A pending CFAPI read owns this registered root. Leave the
                    // agent, fixture, and root intact instead of forcing teardown.
                    std::mem::forget(restored);
                    std::mem::forget(fixture);
                    panic!("native placeholder read exceeded its bounded wait: {path:?}");
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    panic!("native placeholder read worker stopped unexpectedly at {path:?}");
                }
            }
        }
        {
            let reads = fixture.native_reads.lock().unwrap();
            assert!(
                reads.files_enabled,
                "only the opted-in fixture exposes read files"
            );
            assert!(
                reads.personal_range_count > 0,
                "Personal hydration uses range reads"
            );
            assert!(reads.personal_range_bytes >= b"synthetic Personal native read bytes".len());
            assert!(matches!(
                reads.personal_hydration_mode,
                Some("implicit_os_read" | "explicit_test_cfapi")
            ));
            assert!(
                reads.project_range_count > 0,
                "Projects Space hydration uses range reads"
            );
            assert!(
                reads.project_range_bytes >= b"synthetic Projects Space native read bytes".len()
            );
            assert!(matches!(
                reads.project_hydration_mode,
                Some("implicit_os_read" | "explicit_test_cfapi")
            ));
            assert_eq!(
                reads.etag_mismatch_count, 0,
                "hydration keeps the listed ETag bound"
            );
            assert_eq!(
                reads.mutation_attempt_count, 0,
                "native reads issue no mutations"
            );
            eprintln!(
                "native_read_hydration_modes=Personal:{},ProjectsSpace:{}",
                reads.personal_hydration_mode.unwrap(),
                reads.project_hydration_mode.unwrap()
            );
        }
        // Exercise the public request bridge against the actual connected
        // worker after both native callbacks admitted exact catalog versions.
        // Unit rejection tests alone do not establish this positive path.
        let cache_counts = || {
            let reads = fixture.native_reads.lock().unwrap();
            (
                reads.request_count,
                reads.personal_depth_one_propfind_count,
                reads.personal_get_count,
                reads.personal_range_count,
                reads.project_get_count,
                reads.project_range_count,
                reads.etag_mismatch_count,
                reads.mutation_attempt_count,
            )
        };
        let cache_counts_before = cache_counts();
        let cache_generation = restored.generation.load(Ordering::Acquire);
        let cache_scope_token =
            restored.status().unwrap()["root_configuration"]["recovery_scope_token"].clone();
        let usage_request = json!({"action":"windows_device_cache_usage", "profile_id":"default",
            "expected_generation":cache_generation,
            "expected_recovery_scope_token":cache_scope_token});
        let (usage, stop) = restored
            .handle_request(&usage_request)
            .expect("connected worker exposes explicit shared-device cache accounting");
        assert!(!stop);
        assert_eq!(usage["scope"], "device_all_accounts");
        assert_eq!(usage["read_only"], true);
        assert_eq!(usage["last_observed"], true);
        assert_eq!(usage["atomic_snapshot"], false);
        assert_eq!(usage["profile_id"], "default");
        assert_eq!(usage["auth_generation"], cache_generation);
        assert_eq!(usage["recovery_scope_token"], cache_scope_token);
        assert!(usage["used_bytes"].as_u64().unwrap() > 0);
        assert_eq!(usage["quota_bytes"], 1_u64 << 30);
        for (field, value) in [
            ("profile_id", json!("foreign")),
            ("expected_generation", json!(cache_generation + 1)),
            ("expected_recovery_scope_token", json!("0".repeat(64))),
        ] {
            let mut stale = usage_request.clone();
            stale[field] = value;
            assert!(restored.handle_request(&stale).is_err(), "{field}");
        }
        eprintln!(
            "native_device_cache_usage=shared_device_scope_positive_bytes_stale_scope_refused"
        );
        let mut admitted_cache_requests = Vec::new();
        for (space, root_id, resource, etag, expected) in [
            (
                "synthetic-personal-drive",
                "synthetic-personal-root",
                "synthetic-personal-native-read",
                "\"synthetic-personal-native-read-v1\"",
                b"synthetic Personal native read bytes".as_slice(),
            ),
            (
                "synthetic-project-drive",
                "synthetic-project-root",
                "synthetic-project-native-read",
                "\"synthetic-project-native-read-v1\"",
                b"synthetic Projects Space native read bytes".as_slice(),
            ),
        ] {
            let request = json!({"action":"windows_file_cache_status", "profile_id":"default",
                "expected_generation":cache_generation,
                "expected_recovery_scope_token":cache_scope_token,
                "space_id":space, "root_resource_id":root_id, "path":"/native-read.bin",
                "resource_id":resource, "etag":etag, "size":expected.len()});
            let (status, stop) = restored.handle_request(&request).expect(
                "connected worker returns exact catalog cache status through request dispatch",
            );
            assert!(!stop);
            assert_eq!(status["read_only"], true);
            assert_eq!(status["last_observed"], true);
            assert_eq!(status["atomic_snapshot"], false);
            assert_eq!(status["auth_generation"], cache_generation);
            assert_eq!(status["recovery_scope_token"], cache_scope_token);
            assert_eq!(status["policy"], "recent");
            assert_eq!(status["recorded_complete_version"], true);
            assert_eq!(status["recorded_bytes"], expected.len());
            for (field, value) in [
                ("space_id", json!("replaced-space")),
                ("root_resource_id", json!("replaced-root")),
                ("path", json!("/different-file.bin")),
                ("resource_id", json!("replaced-resource")),
                ("etag", json!("\"replaced-version\"")),
                ("size", json!(expected.len() + 1)),
            ] {
                let mut stale = request.clone();
                stale[field] = value;
                assert!(restored.handle_request(&stale).is_err(), "{field}");
            }
            admitted_cache_requests.push(request);
        }
        assert_eq!(
            cache_counts(),
            cache_counts_before,
            "cache status and stale-row refusal must not trigger network or mutation callbacks"
        );
        eprintln!(
            "native_cache_status_rpc=two_exact_complete_versions_twelve_stale_rows_refused_no_network"
        );

        let file_list_request = json!({"action":"windows_offline_files", "profile_id":"default",
            "expected_generation":cache_generation,
            "expected_recovery_scope_token":cache_scope_token});
        let no_file_list_side_effects = cache_counts();
        let (file_page, stop) = restored
            .handle_request(&file_list_request)
            .expect("connected worker lists the exact ordinary-file catalog");
        assert!(!stop);
        assert_eq!(file_page["profile_id"], "default");
        assert_eq!(file_page["auth_generation"], cache_generation);
        assert_eq!(file_page["recovery_scope_token"], cache_scope_token);
        assert_eq!(file_page["read_only"], true);
        assert_eq!(file_page["last_observed"], true);
        assert_eq!(file_page["atomic_snapshot"], false);
        assert_eq!(file_page["unavailable_rows"], 0);
        assert_eq!(file_page["next_cursor"], Value::Null);
        let mut listed = file_page["rows"].as_array().unwrap().clone();
        listed.sort_by(|left, right| {
            left["resource_id"]
                .as_str()
                .cmp(&right["resource_id"].as_str())
        });
        assert_eq!(
            listed,
            vec![
                json!({
                    "space_id":"synthetic-personal-drive",
                    "root_resource_id":"synthetic-personal-root",
                    "path":"/native-read.bin",
                    "resource_id":"synthetic-personal-native-read",
                    "etag":"\"synthetic-personal-native-read-v1\"",
                    "size":b"synthetic Personal native read bytes".len()
                }),
                json!({
                    "space_id":"synthetic-project-drive",
                    "root_resource_id":"synthetic-project-root",
                    "path":"/native-read.bin",
                    "resource_id":"synthetic-project-native-read",
                    "etag":"\"synthetic-project-native-read-v1\"",
                    "size":b"synthetic Projects Space native read bytes".len()
                })
            ],
            "the page contains only the two exact known ordinary file versions"
        );

        for (field, value) in [
            ("profile_id", json!("other")),
            ("expected_generation", json!(cache_generation + 1)),
        ] {
            let mut stale = file_list_request.clone();
            stale[field] = value;
            assert!(restored.handle_request(&stale).is_err(), "{field}");
        }
        let mut wrong_scope = file_list_request.clone();
        let mut wrong_token = cache_scope_token.as_str().unwrap().to_owned();
        let replacement = if &wrong_token[0..1] == "0" { "1" } else { "0" };
        wrong_token.replace_range(0..1, replacement);
        wrong_scope["expected_recovery_scope_token"] = json!(wrong_token);
        assert!(restored.handle_request(&wrong_scope).is_err());
        assert_eq!(cache_counts(), no_file_list_side_effects);
        assert!(restored.provider.connected.load(Ordering::Acquire));
        assert_eq!(
            restored.status().unwrap()["root_configuration"]["recovery_scope_token"],
            cache_scope_token
        );
        eprintln!(
            "native_offline_files_rpc=two_exact_rows_scope_echoed_stale_profile_generation_token_refused_no_network"
        );

        for request in &admitted_cache_requests {
            let mut start_request = request.clone();
            start_request["action"] = json!("windows_offline_file_start");
            let (started, stop) = restored
                .handle_request(&start_request)
                .expect("exact connected cache version admits explicit offline job");
            assert!(!stop);
            let job_id = started["job_id"].as_str().unwrap().to_owned();
            assert_eq!(job_id.len(), 32);

            let mut status_request = request.clone();
            status_request["action"] = json!("windows_offline_file_status");
            status_request["job_id"] = json!(job_id);
            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            let terminal = loop {
                let (status, stop) = restored
                    .handle_request(&status_request)
                    .expect("admitted offline job remains inspectable by its exact drive");
                assert!(!stop);
                match status["state"].as_str() {
                    Some("complete") => break status,
                    Some("running") => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "offline job timed out"
                        );
                        thread::yield_now();
                    }
                    other => panic!("offline job ended without durable completion: {other:?}"),
                }
            };
            assert_eq!(terminal["cancel_requested"], false);
            assert_eq!(terminal["recovery_required"], false);

            let (cache_status, stop) = restored
                .handle_request(request)
                .expect("completed exact cache version remains inspectable");
            assert!(!stop);
            assert_eq!(cache_status["policy"], "always_offline");
            assert_eq!(cache_status["recorded_complete_version"], true);
            assert_eq!(cache_status["pending_offline_intent"], false);
            assert_eq!(cache_status["recorded_bytes"], request["size"]);

            // Wrong job ID, auth generation, and exact recovery-scope token must fail
            // for both observation and cancellation, without changing the real job.
            let mut wrong_job_id = job_id.clone().into_bytes();
            wrong_job_id[0] = if wrong_job_id[0] == b'0' { b'1' } else { b'0' };
            let wrong_job_id = String::from_utf8(wrong_job_id).unwrap();
            let mut wrong_generation = status_request.clone();
            wrong_generation["expected_generation"] = json!(cache_generation + 1);
            let mut wrong_scope = status_request.clone();
            let mut wrong_token = cache_scope_token.as_str().unwrap().to_owned();
            let replacement = if &wrong_token[0..1] == "0" { "1" } else { "0" };
            wrong_token.replace_range(0..1, replacement);
            wrong_scope["expected_recovery_scope_token"] = json!(wrong_token);
            let mut wrong_id = status_request.clone();
            wrong_id["job_id"] = json!(wrong_job_id);
            for mut invalid in [wrong_generation, wrong_scope, wrong_id] {
                assert!(restored.handle_request(&invalid).is_err());
                invalid["action"] = json!("windows_offline_file_cancel");
                assert!(restored.handle_request(&invalid).is_err());
            }
            let (still_complete, stop) = restored
                .handle_request(&status_request)
                .expect("invalid status/cancel attempts do not affect the real job");
            assert!(!stop);
            assert_eq!(still_complete["state"], "complete");
            assert_eq!(still_complete["cancel_requested"], false);

            // The six cache-status row-mutation cases must also be refused by start,
            // before a job is entered or a policy intent is changed.
            for (field, value) in [
                ("space_id", json!("replaced-space")),
                ("root_resource_id", json!("replaced-root")),
                ("path", json!("/different-file.bin")),
                ("resource_id", json!("replaced-resource")),
                ("etag", json!("\"replaced-version\"")),
                ("size", json!(request["size"].as_u64().unwrap() + 1)),
            ] {
                let mut stale_start = request.clone();
                stale_start["action"] = json!("windows_offline_file_start");
                stale_start[field] = value;
                assert!(restored.handle_request(&stale_start).is_err(), "{field}");
            }
            let (still_cached, stop) = restored
                .handle_request(request)
                .expect("stale start requests leave the exact cache version unchanged");
            assert!(!stop);
            assert_eq!(still_cached["policy"], "always_offline");
            assert_eq!(still_cached["recorded_complete_version"], true);
            assert_eq!(still_cached["recorded_bytes"], request["size"]);
        }
        assert_eq!(
            cache_counts(),
            cache_counts_before,
            "promoting already cached versions and refusing stale requests performs no network work"
        );
        eprintln!(
            "native_offline_jobs=two_cached_versions_complete_wrong_scope_and_stale_starts_refused_no_network"
        );

        assert_eq!(fixture.recovery.lock().unwrap().put_count, 0);
        let before_revocation = restored.state.lock().unwrap().root_configuration.clone();
        let stored = restored
            .session_store
            .load_root_config("default", &server, "synthetic-client")
            .unwrap();
        // Model the retained-connection/revoked-backend state of a failed OS
        // disconnect without claiming that this forces an OS disconnect error.
        restored.provider.revoke_backend_for_test().unwrap();
        let mut revoked_start = admitted_cache_requests[0].clone();
        revoked_start["action"] = json!("windows_offline_file_start");
        assert!(restored.handle_request(&revoked_start).is_err());
        assert_eq!(
            cache_counts(),
            cache_counts_before,
            "revoked backend refuses new offline admission without network work"
        );

        for request in &admitted_cache_requests {
            assert!(
                restored.handle_request(request).is_err(),
                "retained connection with revoked backend cannot report cache status"
            );
        }
        assert_eq!(cache_counts(), cache_counts_before);
        assert!(
            WindowsAgent::maybe_connect_provider(
                &restored.session_store,
                &restored.state,
                &restored.provider
            )
            .is_err()
        );
        assert_eq!(
            restored.state.lock().unwrap().root_configuration,
            before_revocation
        );
        assert_eq!(
            restored
                .session_store
                .load_root_config("default", &server, "synthetic-client")
                .unwrap(),
            stored
        );
        assert!(restored.provider.connected.load(Ordering::Acquire));
        restored.provider.disconnect().unwrap();
        drop(restored);
        fixture.join().unwrap();
    }

    #[cfg(all(windows, debug_assertions))]
    fn broker_vault_read_in_child(
        path: &Path,
        expected_len: usize,
        expected_sha: &str,
    ) -> Result<bool, String> {
        use std::process::{Command, Stdio};

        assert!(path.is_absolute());
        assert_eq!(path.file_name().unwrap(), "1");
        assert_eq!(path.parent().unwrap().file_name().unwrap(), "Travel.vault");
        assert_eq!(
            path.parent()
                .unwrap()
                .parent()
                .unwrap()
                .file_name()
                .unwrap(),
            "Personal"
        );
        let mut child = Command::new("powershell.exe")
            .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
                "$ErrorActionPreference='Stop'; try { $b=[System.IO.File]::ReadAllBytes($env:RAIUN_SYNTHETIC_FILE); $h=[System.Security.Cryptography.SHA256]::Create(); try { $s=[BitConverter]::ToString($h.ComputeHash($b)).Replace('-','').ToLowerInvariant(); [Console]::WriteLine(('{0}|{1}' -f $b.Length,$s)) } finally { $h.Dispose() } } catch { $e=$_.Exception; while ($e.InnerException) { $e=$e.InnerException }; [Console]::WriteLine(('ERROR|{0}' -f $e.HResult)); exit 24 }"])
            .env("RAIUN_SYNTHETIC_FILE", path)
            .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null())
            .spawn().map_err(|_| "could not start synthetic vault reader")?;
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = child
                .try_wait()
                .map_err(|_| "could not poll vault reader")?
            {
                let output = child
                    .wait_with_output()
                    .map_err(|_| "could not collect vault reader")?;
                let summary =
                    String::from_utf8(output.stdout).map_err(|_| "invalid vault reader summary")?;
                let summary = summary.trim();
                if status.success() && summary == format!("{expected_len}|{expected_sha}") {
                    println!("C06_VAULT_EXTERNAL_READ_VERIFIED=true");
                    return Ok(true);
                }
                if status.code() == Some(24)
                    && summary
                        .strip_prefix("ERROR|")
                        .and_then(|value| value.parse::<i32>().ok())
                        .is_some_and(|hr| hr < 0)
                {
                    println!("C06_VAULT_EXTERNAL_READ_REJECTED=true");
                    return Ok(false);
                }
                return Err("synthetic vault reader returned unexpected status/content".into());
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err("synthetic vault reader timed out; preserve owned fixture".into());
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    #[cfg(all(windows, debug_assertions))]
    #[test]
    #[ignore = "requires isolated ordinary RaiunLabUser child with fresh owned LOCALAPPDATA; C05 cleanup acceptance prerequisite"]
    fn native_broker_manual_remember_lock_saved_forget_lifecycle() {
        broker_remembered_lifecycle_fixture(false);
    }

    #[cfg(all(windows, debug_assertions))]
    #[test]
    #[ignore = "requires isolated ordinary RaiunLabUser child with fresh owned LOCALAPPDATA and qualified C05 payload cleanup"]
    fn native_broker_saved_payload_forget_and_lock() {
        broker_remembered_lifecycle_fixture(true);
    }

    #[cfg(all(windows, debug_assertions))]
    #[test]
    #[ignore = "requires isolated ordinary RaiunLabUser child with fresh owned LOCALAPPDATA; forced synthetic vault modification preserves dirty fixture"]
    fn native_broker_vault_modified_close_retains_indexed_edit() {
        broker_remembered_lifecycle_fixture_mode(true, true);
    }

    #[cfg(all(windows, debug_assertions))]
    #[test]
    #[ignore = "requires isolated ordinary RaiunLabUser with fresh child-only LOCALAPPDATA; explicit synthetic encrypted upload retains dirty namespace"]
    fn native_broker_vault_captured_edit_explicit_upload_verifies_ciphertext() {
        broker_remembered_lifecycle_fixture_with_upload(true, true, true);
    }

    #[cfg(all(windows, debug_assertions))]
    #[derive(Debug)]
    enum VaultWriterOpenOutcome {
        Opened,
        Error(Option<i32>),
    }

    #[cfg(all(windows, debug_assertions))]
    struct VaultWriterOpenResult {
        outcome: VaultWriterOpenOutcome,
        critical_span_finished: bool,
    }

    #[cfg(all(windows, debug_assertions))]
    enum VaultCompletionProbeState {
        NotStarted,
        SharingDenied,
        Pending {
            received: std::sync::mpsc::Receiver<VaultWriterOpenResult>,
            competitor: thread::JoinHandle<()>,
        },
        Failed,
        Finalized,
    }

    #[cfg(all(windows, debug_assertions))]
    pub(super) struct VaultCompletionProbeHandle {
        state: Arc<Mutex<VaultCompletionProbeState>>,
        critical_span_finished: Arc<std::sync::atomic::AtomicBool>,
    }

    #[cfg(all(windows, debug_assertions))]
    pub(super) fn finalize_vault_completion_probe(
        probe: VaultCompletionProbeHandle,
    ) -> Result<Value, String> {
        let state = std::mem::replace(
            &mut *probe
                .state
                .lock()
                .map_err(|_| "writer probe lock poisoned")?,
            VaultCompletionProbeState::Finalized,
        );
        match state {
            VaultCompletionProbeState::SharingDenied => {
                if !probe.critical_span_finished.load(Ordering::SeqCst) {
                    return Err(
                        "sharing denial observed but full critical span did not finish".into(),
                    );
                }
                Ok(json!({"native_writer_exclusion":"sharing_denied", "native_writer_error":32}))
            }
            VaultCompletionProbeState::Pending {
                received,
                competitor,
            } => {
                // This is an observed channel/marker ordering, not proof of the
                // exact kernel admission instant: the thread may be preempted.
                // The real retained native reference and production postproofs
                // remain the security authority for completion.
                let result = received
                    .recv_timeout(Duration::from_secs(5))
                    .map_err(|error| {
                        // Do not block joining a still-pending open or kill its thread.
                        // Releasing the native guard lets it finish naturally.
                        eprintln!("C06_VAULT_WRITER_PROBE_FINALIZE_FAILED={error:?}");
                        "writer open result was not received within five seconds after command returned"
                            .to_string()
                    })?;
                competitor
                    .join()
                    .map_err(|_| "writer probe thread panicked")?;
                let raw = match result.outcome {
                    VaultWriterOpenOutcome::Opened => 0,
                    VaultWriterOpenOutcome::Error(Some(5)) => 5,
                    other => {
                        return Err(format!("unexpected post-command writer outcome: {other:?}"));
                    }
                };
                if !result.critical_span_finished {
                    return Err(
                        "writer thread sampled an unfinished critical span after Open returned"
                            .into(),
                    );
                }
                eprintln!(
                    "C06_VAULT_NATIVE_WRITER_EXCLUSION=pending_through_completion;error={raw}"
                );
                Ok(
                    json!({"native_writer_exclusion":"pending_through_completion", "native_writer_error":raw}),
                )
            }
            _ => Err("writer exclusion probe never reached a qualifying completed state".into()),
        }
    }

    #[cfg(all(windows, debug_assertions))]
    pub(super) fn instrument_vault_completion_store(
        inner: Box<dyn raiun_cloudfiles_windows::VaultLocalCompletionStore>,
        root: PathBuf,
    ) -> (
        Box<dyn raiun_cloudfiles_windows::VaultLocalCompletionStore>,
        VaultCompletionProbeHandle,
    ) {
        struct Instrumented {
            inner: Box<dyn raiun_cloudfiles_windows::VaultLocalCompletionStore>,
            root: PathBuf,
            state: Arc<Mutex<VaultCompletionProbeState>>,
            critical_span_finished: Arc<std::sync::atomic::AtomicBool>,
        }
        impl raiun_cloudfiles_windows::VaultLocalCompletionStore for Instrumented {
            fn target(&self) -> &raiun_cloudfiles_windows::VaultLocalCompletionTarget {
                self.inner.target()
            }
            fn prepare(
                &mut self,
                proof: &raiun_cloudfiles_windows::VaultNativePreparation,
            ) -> Result<(), raiun_cloudfiles_windows::BackendError> {
                self.inner.prepare(proof)
            }
            fn complete(
                &mut self,
                proof: &raiun_cloudfiles_windows::VaultNativeCompletionProof,
            ) -> Result<(), raiun_cloudfiles_windows::BackendError> {
                self.inner.complete(proof)
            }
            fn before_in_sync_for_test(
                &mut self,
            ) -> Result<(), raiun_cloudfiles_windows::BackendError> {
                use raiun_cloudfiles_windows::BackendError;
                let mut state = self.state.lock().map_err(|_| BackendError::Unavailable)?;
                if !matches!(*state, VaultCompletionProbeState::NotStarted) {
                    return Err(BackendError::Unavailable);
                }
                *state = VaultCompletionProbeState::Failed;
                let components = self.inner.target().components();
                if !self.root.is_absolute()
                    || components.is_empty()
                    || components.iter().any(|component| {
                        component.is_empty()
                            || component == "."
                            || component == ".."
                            || component.contains(['/', '\\', ':'])
                    })
                {
                    return Err(BackendError::Unavailable);
                }
                let mut path = self.root.clone();
                for component in components {
                    path.push(component);
                }
                let (entered_sent, entered_received) = std::sync::mpsc::sync_channel(1);
                let (sent, received) = std::sync::mpsc::sync_channel(1);
                let finished = Arc::clone(&self.critical_span_finished);
                let competitor = thread::spawn(move || {
                    let _ = entered_sent.send(());
                    // Ordinary existing-file write OPEN only: never write bytes,
                    // truncate, create, alter permissions or retry after denial.
                    let opened = std::fs::OpenOptions::new().write(true).open(path);
                    let critical_span_finished = finished.load(Ordering::SeqCst);
                    let outcome = match opened {
                        Ok(file) => {
                            drop(file);
                            VaultWriterOpenOutcome::Opened
                        }
                        Err(error) => VaultWriterOpenOutcome::Error(error.raw_os_error()),
                    };
                    eprintln!(
                        "C06_VAULT_WRITER_OPEN_RETURN={outcome:?};critical_span_finished={critical_span_finished}"
                    );
                    let _ = sent.send(VaultWriterOpenResult {
                        outcome,
                        critical_span_finished,
                    });
                });
                if entered_received
                    .recv_timeout(Duration::from_secs(1))
                    .is_err()
                {
                    eprintln!("C06_VAULT_WRITER_PROBE_ENTER_TIMEOUT");
                    return Err(BackendError::Unavailable);
                }
                match received.recv_timeout(Duration::from_secs(2)) {
                    Ok(VaultWriterOpenResult {
                        outcome: VaultWriterOpenOutcome::Error(Some(32)),
                        ..
                    }) => {
                        competitor.join().map_err(|_| BackendError::Unavailable)?;
                        *state = VaultCompletionProbeState::SharingDenied;
                        eprintln!("C06_VAULT_NATIVE_WRITER_EXCLUSION=sharing_denied;error=32");
                        Ok(())
                    }
                    Ok(result) => {
                        eprintln!(
                            "C06_VAULT_WRITER_PROBE_IMMEDIATE_FAILURE={:?}",
                            result.outcome
                        );
                        let _ = competitor.join();
                        Err(BackendError::Unavailable)
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        // Provisional only. The final hook must still observe a
                        // pending probe result, and finalization must qualify its return.
                        *state = VaultCompletionProbeState::Pending {
                            received,
                            competitor,
                        };
                        eprintln!("C06_VAULT_WRITER_PROBE_PENDING_PROVISIONAL=true");
                        Ok(())
                    }
                    Err(error) => {
                        eprintln!("C06_VAULT_WRITER_PROBE_CHANNEL_FAILURE={error:?}");
                        let _ = competitor.join();
                        Err(BackendError::Unavailable)
                    }
                }
            }
            fn before_completion_guard_release_for_test(
                &mut self,
            ) -> Result<(), raiun_cloudfiles_windows::BackendError> {
                use raiun_cloudfiles_windows::BackendError;
                let mut state = self.state.lock().map_err(|_| BackendError::Unavailable)?;
                match &*state {
                    VaultCompletionProbeState::SharingDenied => {}
                    VaultCompletionProbeState::Pending { received, .. } => {
                        if !matches!(
                            received.try_recv(),
                            Err(std::sync::mpsc::TryRecvError::Empty)
                        ) {
                            eprintln!(
                                "C06_VAULT_WRITER_PROBE_RETURNED_BEFORE_CRITICAL_SPAN_END=true"
                            );
                            *state = VaultCompletionProbeState::Failed;
                            return Err(BackendError::Unavailable);
                        }
                    }
                    _ => return Err(BackendError::Unavailable),
                }
                // No result has been observed yet for the pending branch. This
                // does not establish the exact kernel admission instant.
                // Native completion, postproof and exact dirty resolution are
                // already durable. The exclusive guard/fences remain held here.
                self.critical_span_finished.store(true, Ordering::SeqCst);
                eprintln!("C06_VAULT_WRITER_PROBE_CRITICAL_SPAN_FINISHED=true");
                Ok(())
            }
        }
        let state = Arc::new(Mutex::new(VaultCompletionProbeState::NotStarted));
        let critical_span_finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
        (
            Box::new(Instrumented {
                inner,
                root,
                state: Arc::clone(&state),
                critical_span_finished: Arc::clone(&critical_span_finished),
            }),
            VaultCompletionProbeHandle {
                state,
                critical_span_finished,
            },
        )
    }

    #[cfg(all(windows, debug_assertions))]
    #[test]
    #[ignore = "requires isolated ordinary RaiunLabUser with fresh child-only LOCALAPPDATA; verifies native local disposition after one explicit synthetic upload"]
    fn native_broker_vault_verified_upload_completes_local_disposition() {
        broker_remembered_lifecycle_fixture_with_disposition(true, true, true, true);
    }

    #[cfg(all(windows, debug_assertions))]
    #[test]
    #[ignore = "requires isolated ordinary RaiunLabUser with fresh child-only LOCALAPPDATA; verifies full local disposition after normal close without an injected writer"]
    fn native_broker_vault_verified_upload_normal_close_completes_local_disposition() {
        broker_remembered_lifecycle_fixture_with_writer_probe(true, true, true, true, false);
    }

    #[cfg(all(windows, debug_assertions))]
    #[test]
    #[ignore = "requires isolated ordinary RaiunLabUser/fresh child-only LOCALAPPDATA; automatic fresh-close upload leaves dirty native fixture"]
    fn native_broker_vault_fresh_close_automatically_uploads_retained_edit() {
        broker_remembered_lifecycle_fixture_with_automatic_upload(true, true, true, true);
    }

    #[cfg(all(windows, debug_assertions))]
    #[test]
    #[ignore = "requires isolated ordinary RaiunLabUser/fresh child LOCALAPPDATA; missing volatile receipt refuses cleanup despite historical native writable-byte completion"]
    fn native_broker_vault_writable_bytes_complete_preserves_pending_cleanup() {
        broker_remembered_lifecycle_fixture_with_modes(
            true,
            true,
            true,
            true,
            false,
            false,
            WritableCleanupFixtureMode::MissingReceipt,
        );
    }

    #[cfg(all(windows, debug_assertions))]
    #[test]
    #[ignore = "requires isolated ordinary RaiunLabUser/fresh child appdata; verifies same-live writable cleanup boundary and one bounded late-write outcome"]
    fn native_broker_vault_writable_bytes_lock_evicts_with_late_activity_truthfulness() {
        broker_remembered_lifecycle_fixture_with_modes(
            true,
            true,
            true,
            true,
            false,
            false,
            WritableCleanupFixtureMode::NormalCleanup,
        );
    }

    #[cfg(all(windows, debug_assertions))]
    #[test]
    #[ignore = "requires isolated ordinary RaiunLabUser/fresh child appdata; one fresh close automatically completes writable bytes then clean Lock without manual upload"]
    fn native_broker_vault_fresh_close_automatically_completes_writable_bytes_and_locks() {
        broker_remembered_lifecycle_fixture_with_modes(
            true,
            true,
            true,
            true,
            false,
            true,
            WritableCleanupFixtureMode::FreshNative,
        );
    }

    #[cfg(all(windows, debug_assertions))]
    #[test]
    #[ignore = "requires isolated ordinary RaiunLabUser/fresh child appdata; normal admitted worker and fresh writable publication complete two same-live in-place saves then Lock"]
    fn native_broker_vault_normal_existing_file_two_saves_automatically_complete_and_lock() {
        broker_remembered_lifecycle_fixture_with_modes(
            true,
            true,
            true,
            true,
            false,
            true,
            WritableCleanupFixtureMode::NormalExisting,
        );
    }

    #[cfg(all(windows, debug_assertions))]
    #[test]
    #[ignore = "requires isolated ordinary RaiunLabUser/fresh child appdata; normal writable publication full clean read and same-connection reunlock/Lock without any edit"]
    fn native_broker_vault_normal_clean_read_reunlock_and_lock_without_edits() {
        broker_remembered_lifecycle_fixture_with_modes(
            true,
            false,
            false,
            false,
            false,
            false,
            WritableCleanupFixtureMode::NormalCleanRead,
        );
    }

    #[cfg(all(windows, debug_assertions))]
    #[test]
    fn normal_existing_save_owner_is_weak_and_failed_admission_releases_gate() {
        let agent = Arc::new(WindowsAgent::new(MemoryStore::default()));
        let owners = Arc::strong_count(&agent);
        agent.attach_existing_file_save_owner().unwrap();
        agent.attach_existing_file_save_owner().unwrap();
        assert_eq!(
            Arc::strong_count(&agent),
            owners,
            "owner attachment cannot create a cycle"
        );
        let binding = ActiveProviderBinding {
            generation: agent.generation.load(Ordering::Acquire),
            path: PathBuf::from(r"C:\SyntheticRoot"),
            identity: raiun_cloudfiles_windows::ConfiguredRootIdentity {
                volume_serial: 9,
                file_index: 42,
            },
            personal_space_id: "space".into(),
            personal_root_resource_id: "root".into(),
        };
        assert!(
            agent
                .provider
                .prepare_existing_file_save_worker(
                    &binding,
                    &agent.state,
                    &agent.session_store,
                    false
                )
                .is_err(),
            "an unattested account cannot mint a save source"
        );
        assert!(
            !agent
                .provider
                .existing_save_admission
                .load(Ordering::Acquire)
        );
        assert!(agent.provider.fresh_close_source.lock().unwrap().is_none());
        assert!(agent.fresh_close_worker.lock().unwrap().is_none());
        // Busy admission must not release another caller's finite gate.
        agent
            .provider
            .existing_save_admission
            .store(true, Ordering::Release);
        assert!(
            agent
                .provider
                .prepare_existing_file_save_worker(
                    &binding,
                    &agent.state,
                    &agent.session_store,
                    false
                )
                .is_err()
        );
        assert!(
            agent
                .provider
                .existing_save_admission
                .load(Ordering::Acquire)
        );
        agent
            .provider
            .existing_save_admission
            .store(false, Ordering::Release);
        let weak = Arc::downgrade(&agent);
        drop(agent);
        assert!(weak.upgrade().is_none());
    }

    #[cfg(all(windows, debug_assertions))]
    #[test]
    fn normal_existing_save_source_is_exact_binding_and_cancelled_identity_only() {
        let agent = Arc::new(WindowsAgent::new(MemoryStore::default()));
        let generation = agent.provider.authorized_generation.load(Ordering::Acquire);
        let worker =
            super::windows_vault_close_worker::FreshCloseWorker::start_for_existing_file_saves(
                Arc::downgrade(&agent),
                Arc::clone(&agent.provider.authorized_generation),
                generation,
            )
            .unwrap();
        let source = worker.source();
        let active = source.existing_file_save_marker(generation).unwrap();
        let binding = ActiveProviderBinding {
            generation,
            path: PathBuf::from(r"C:\SyntheticRoot"),
            identity: raiun_cloudfiles_windows::ConfiguredRootIdentity {
                volume_serial: 9,
                file_index: 42,
            },
            personal_space_id: "space".into(),
            personal_root_resource_id: "root".into(),
        };
        let publication = super::FreshClosePublication {
            source,
            binding: Some(binding.clone()),
            original_active: Some(Arc::clone(&active)),
        };
        assert!(publication.marker(&binding).is_some());
        let mut foreign = binding.clone();
        foreign.identity.file_index += 1;
        assert!(publication.marker(&foreign).is_none());
        foreign = binding.clone();
        foreign.path = PathBuf::from(r"C:\OtherRoot");
        assert!(publication.marker(&foreign).is_none());
        publication.cancel();
        assert!(publication.marker(&binding).is_none());
        assert!(!active.load(Ordering::Acquire));
        assert!(worker.owns_existing_file_save_marker(generation, &active));
        assert!(
            !worker.owns_existing_file_save_marker(
                generation,
                &Arc::new(std::sync::atomic::AtomicBool::new(true))
            ),
            "a replacement active Arc cannot adopt the cancelled original"
        );
        worker.stop().unwrap();
    }

    #[cfg(all(windows, debug_assertions))]
    #[test]
    fn vault_readiness_binding_refuses_stale_missing_or_foreign_root() {
        use super::vault_worker_binding_current;
        let binding = ActiveProviderBinding {
            generation: 7,
            path: PathBuf::from(r"C:\SyntheticRoot"),
            identity: raiun_cloudfiles_windows::ConfiguredRootIdentity {
                volume_serial: 9,
                file_index: 42,
            },
            personal_space_id: "space".into(),
            personal_root_resource_id: "root".into(),
        };
        assert!(vault_worker_binding_current(7, &binding, Some(&binding)));
        assert!(!vault_worker_binding_current(8, &binding, Some(&binding)));
        assert!(!vault_worker_binding_current(7, &binding, None));
        let mut foreign = binding.clone();
        foreign.identity.file_index += 1;
        assert!(!vault_worker_binding_current(7, &binding, Some(&foreign)));
        for changed in 0..4 {
            foreign = binding.clone();
            match changed {
                0 => foreign.identity.volume_serial += 1,
                1 => foreign.path = PathBuf::from(r"C:\ForeignRoot"),
                2 => foreign.personal_space_id = "foreign-space".into(),
                _ => foreign.personal_root_resource_id = "foreign-root".into(),
            }
            assert!(!vault_worker_binding_current(7, &binding, Some(&foreign)));
        }
        foreign = binding.clone();
        foreign.generation = 0;
        assert!(!vault_worker_binding_current(0, &foreign, Some(&foreign)));
    }

    #[cfg(all(windows, debug_assertions))]
    fn broker_remembered_lifecycle_fixture(payload: bool) {
        broker_remembered_lifecycle_fixture_mode(payload, false);
    }

    #[cfg(all(windows, debug_assertions))]
    fn broker_remembered_lifecycle_fixture_mode(payload: bool, capture_edit: bool) {
        broker_remembered_lifecycle_fixture_with_upload(payload, capture_edit, false);
    }

    #[cfg(all(windows, debug_assertions))]
    fn broker_remembered_lifecycle_fixture_with_upload(
        payload: bool,
        capture_edit: bool,
        upload_edit: bool,
    ) {
        broker_remembered_lifecycle_fixture_with_disposition(
            payload,
            capture_edit,
            upload_edit,
            false,
        );
    }

    #[cfg(all(windows, debug_assertions))]
    fn broker_remembered_lifecycle_fixture_with_automatic_upload(
        payload: bool,
        capture_edit: bool,
        upload_edit: bool,
        automatic: bool,
    ) {
        broker_remembered_lifecycle_fixture_with_modes(
            payload,
            capture_edit,
            upload_edit,
            false,
            true,
            automatic,
            WritableCleanupFixtureMode::Disabled,
        );
    }

    #[cfg(all(windows, debug_assertions))]
    fn broker_remembered_lifecycle_fixture_with_disposition(
        payload: bool,
        capture_edit: bool,
        upload_edit: bool,
        complete_local: bool,
    ) {
        broker_remembered_lifecycle_fixture_with_writer_probe(
            payload,
            capture_edit,
            upload_edit,
            complete_local,
            true,
        );
    }

    #[cfg(all(windows, debug_assertions))]
    fn broker_remembered_lifecycle_fixture_with_writer_probe(
        payload: bool,
        capture_edit: bool,
        upload_edit: bool,
        complete_local: bool,
        inject_writer_probe: bool,
    ) {
        broker_remembered_lifecycle_fixture_with_modes(
            payload,
            capture_edit,
            upload_edit,
            complete_local,
            inject_writer_probe,
            false,
            WritableCleanupFixtureMode::Disabled,
        );
    }

    #[cfg(all(windows, debug_assertions))]
    enum WritableCleanupFixtureMode {
        Disabled,
        MissingReceipt,
        NormalCleanup,
        FreshNative,
        NormalExisting,
        NormalCleanRead,
    }

    #[cfg(all(windows, debug_assertions))]
    fn broker_remembered_lifecycle_fixture_with_modes(
        payload: bool,
        capture_edit: bool,
        upload_edit: bool,
        complete_local: bool,
        inject_writer_probe: bool,
        automatic: bool,
        writable_mode: WritableCleanupFixtureMode,
    ) {
        let normal_clean_read =
            matches!(writable_mode, WritableCleanupFixtureMode::NormalCleanRead);
        let writable_bytes = !matches!(
            writable_mode,
            WritableCleanupFixtureMode::Disabled | WritableCleanupFixtureMode::NormalCleanRead
        );
        let normal_existing = matches!(
            writable_mode,
            WritableCleanupFixtureMode::NormalExisting
                | WritableCleanupFixtureMode::NormalCleanRead
        );
        let fresh_native = matches!(
            writable_mode,
            WritableCleanupFixtureMode::FreshNative | WritableCleanupFixtureMode::NormalExisting
        );
        let writable_cleanup = matches!(
            writable_mode,
            WritableCleanupFixtureMode::NormalCleanup
                | WritableCleanupFixtureMode::FreshNative
                | WritableCleanupFixtureMode::NormalExisting
        );
        assert!(!fresh_native || automatic);
        assert!(
            !writable_bytes
                || (complete_local && (!automatic || fresh_native) && !inject_writer_probe)
        );
        assert!(!automatic || (upload_edit && (!complete_local || fresh_native)));
        assert!(!complete_local || upload_edit);
        assert!(!upload_edit || capture_edit);
        assert!(!capture_edit || payload);
        use super::{
            DpapiSessionStore, DpapiStore, VaultCredentialStore, windows_profile_registry,
            windows_profiles, windows_vault_credentials,
        };
        assert_eq!(std::env::var("USERNAME").as_deref(), Ok("RaiunLabUser"));
        // Operator must supply this only in the child ProcessStartInfo environment.
        // No process/global environment mutation or real-profile fallback exists.
        let appdata =
            PathBuf::from(std::env::var_os("LOCALAPPDATA").expect("isolated child appdata"));
        let fixture = appdata.parent().expect("owned fixture parent").to_owned();
        assert_eq!(appdata.file_name().unwrap(), "appdata");
        assert_eq!(fixture.parent().unwrap(), Path::new(r"C:\RaiunLab"));
        let name = fixture.file_name().unwrap().to_str().unwrap();
        let nonce = name
            .strip_prefix("c06-broker-lifecycle-")
            .expect("fixed fixture prefix");
        assert_eq!(nonce.len(), 32);
        assert!(
            nonce
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        assert_eq!(
            std::fs::canonicalize(&appdata).unwrap(),
            PathBuf::from(format!(r"\\?\{}", appdata.display()))
        );
        assert_eq!(
            std::fs::read_dir(&appdata).unwrap().count(),
            0,
            "refuse replay before opening storage"
        );
        assert_eq!(
            std::fs::read_dir(&fixture).unwrap().count(),
            1,
            "fresh root contains only empty appdata"
        );
        let appdata_pin = raiun_control_windows::PinnedDirectory::open(&appdata).unwrap();
        appdata_pin.verify_path().unwrap();
        eprintln!("synthetic_c06_broker_fixture={}", fixture.display());

        let (server, remote) = synthetic_personal_spaces_server_inner_with_vault_upload(
            |_| {},
            false,
            false,
            false,
            true,
            payload,
            upload_edit,
        );
        let storage = DpapiSessionStore::current_user().unwrap();
        let _registry_owner = storage.lock_profile_registry().unwrap();
        assert!(storage.load_profile_registry().unwrap().is_none());
        assert!(storage.active_identity().unwrap().is_none());
        let profile = format!("profile-{nonce}");
        let registry = windows_profile_registry::Registry::decode_or_default(None)
            .unwrap()
            .with_added(&profile, "Synthetic remembered vault")
            .unwrap()
            .with_selected(&profile)
            .unwrap();
        let admissions = Arc::new(Mutex::new(Arc::new(registry.clone())));
        let sessions = Arc::new(raiun_vault::session::VaultSessionCoordinator::new());
        let store = DpapiStore::for_profile(&profile).unwrap();
        let session = synthetic_session(&server, "synthetic-client", unix_time_now() + 3600);
        store.save_pending(&profile, &session).unwrap();
        store.publish_active(&profile, &session).unwrap();
        let mut runtime = Arc::new(
            WindowsAgent::new_for_profile_with_services(
                &profile,
                store,
                Some(admissions),
                sessions.clone(),
            )
            .unwrap(),
        );
        Arc::get_mut(&mut runtime)
            .expect("fresh test runtime has one owner before operations")
            .synthetic_vault_completion_writer_probe = inject_writer_probe;
        let generation = runtime.generation.load(Ordering::Acquire);
        {
            let mut state = runtime.state.lock().unwrap();
            state.active_generation = generation;
            state.online_authenticated = true;
            state.needs_refresh = false;
        }
        runtime.provider.authorize_generation(generation);
        if normal_existing {
            runtime.attach_existing_file_save_owner().unwrap();
            runtime
                .provider
                .lifecycle_test_activation
                .store(true, Ordering::Release);
        }

        let drive = fixture.join("drive");
        std::fs::create_dir(&drive).unwrap();
        runtime
            .configure_root(
                &json!({"action":"configure_root","profile_id":profile,"cloud_root":drive}),
            )
            .unwrap();
        if automatic && !normal_existing {
            if fresh_native {
                runtime
                    .start_fresh_close_worker_with_writable_completion_for_test()
                    .unwrap();
            } else {
                runtime.start_fresh_close_worker_for_test().unwrap();
            }
            assert_eq!(
                runtime
                    .fresh_close_observation_for_test()
                    .unwrap()
                    .attempted,
                0
            );
        }
        if normal_existing {
            WindowsAgent::maybe_connect_provider(
                &runtime.session_store,
                &runtime.state,
                &runtime.provider,
            )
            .unwrap();
            let admitted = runtime.fresh_close_observation_for_test().unwrap();
            assert_eq!(
                admitted.attempted, 0,
                "normal startup admits an idle worker before any child save"
            );
        } else {
            WindowsAgent::connect_verified_root(
                &runtime.session_store,
                &runtime.state,
                &runtime.provider,
            )
            .unwrap();
        }
        assert!(
            child_process_directory_matches(&drive, &["Personal", "Spaces"])
                .unwrap()
                .matches_expected
        );
        let broker = windows_profiles::WindowsProfiles::for_isolated_lifecycle_fixture(
            storage.clone(),
            registry,
            runtime.clone(),
        )
        .unwrap();
        let scope = raiun_vault::session::VaultSessionScope::new(
            &profile,
            &server,
            "synthetic-personal-drive",
            "synthetic-vault-root",
        )
        .unwrap();
        let target = || {
            json!({"profile_id":profile,"space_id":"synthetic-personal-drive",
            "root_path":"/Travel.vault","root_resource_id":"synthetic-vault-root"})
        };
        let mut manual = target();
        manual["action"] = json!("vault_unlock");
        manual["password"] = json!("potato"); // public fixture password, never owner credentials
        manual["remember"] = json!(true);
        let unlocked = broker.handle_isolated_lifecycle_session(manual).unwrap().0;
        assert_eq!(unlocked["unlocked"], true);
        assert_eq!(unlocked["remembered_status"], "known_saved");
        assert_eq!(unlocked["root_resource_id"], "synthetic-vault-root");
        assert_eq!(unlocked["vault_mount_ready"], true);
        if normal_existing {
            assert_eq!(unlocked["vault_mount_existing_file_in_place"], true);
            assert_eq!(unlocked["vault_mount_writable"], false);
            assert_eq!(unlocked["vault_mount_existing_file_overwrite"], false);
        }

        assert!(sessions.is_unlocked(&scope).unwrap());
        let mut lock = target();
        lock["action"] = json!("vault_lock");
        assert_eq!(
            broker.handle_isolated_lifecycle_session(lock).unwrap().0["unlocked"],
            false
        );
        assert!(!sessions.is_unlocked(&scope).unwrap());
        assert!(
            runtime
                .confirm_windows_vault_readiness(&scope, "/Travel.vault")
                .is_err()
        );
        let mut saved = target();
        saved["action"] = json!("vault_unlock");
        saved["use_saved"] = json!(true);
        let unlocked = broker.handle_isolated_lifecycle_session(saved).unwrap().0;
        assert_eq!(unlocked["remembered_status"], "known_saved");
        assert!(sessions.is_unlocked(&scope).unwrap());
        if payload {
            let personal = drive.join("Personal");
            assert!(
                child_process_directory_matches(&personal, &["Travel.vault"])
                    .unwrap()
                    .matches_expected
            );
            assert!(
                child_process_directory_matches(&personal.join("Travel.vault"), &["1"])
                    .unwrap()
                    .matches_expected
            );
            use sha2::Digest as _;
            let expected = (0..65537).map(|i| (i * 31 + 7) as u8).collect::<Vec<_>>();
            let hash = format!("{:x}", sha2::Sha256::digest(&expected));
            assert!(
                broker_vault_read_in_child(&personal.join("Travel.vault/1"), expected.len(), &hash)
                    .unwrap(),
                "Saved unlock must serve the verified public fixture bytes"
            );
            let gets = remote.native_reads.lock().unwrap().vault_get_count;
            assert!(
                (1..=16).contains(&gets),
                "bounded conditional ciphertext download"
            );
            println!("C06_SAVED_PAYLOAD_READ_VERIFIED=true");
        }
        if normal_clean_read {
            use sha2::Digest as _;
            use std::os::windows::fs::MetadataExt as _;
            let file = drive.join("Personal/Travel.vault/1");
            let expected = (0..65537).map(|i| (i * 31 + 7) as u8).collect::<Vec<_>>();
            let hash = format!("{:x}", sha2::Sha256::digest(&expected));
            let (configuration, root_pin) = runtime
                .confirm_windows_vault_readiness(&scope, "/Travel.vault")
                .unwrap();
            let owner = configuration.registration_ownership.as_ref().unwrap();
            let active = ActiveProviderBinding {
                generation,
                path: PathBuf::from(&configuration.path),
                identity: raiun_cloudfiles_windows::ConfiguredRootIdentity {
                    volume_serial: configuration.volume_serial,
                    file_index: configuration.file_index,
                },
                personal_space_id: owner.personal_drive_id.clone(),
                personal_root_resource_id: owner.personal_root_resource_id.clone().unwrap(),
            };
            assert!(runtime.provider.connection_matches(active.clone()).unwrap());
            let original_source = runtime
                .provider
                .existing_vault_save_worker_marker(&active)
                .unwrap()
                .expect("normal admitted existing-file worker");
            let verified = runtime
                .provider
                .verified_vault_backend(active.clone())
                .unwrap();
            let before = verified
                .custody
                .inspect_capture_for_test(&scope, "/Travel.vault")
                .unwrap();
            assert!(
                before.captures.is_empty(),
                "ordinary hydration is not edit capture/NativeCompleted authority"
            );
            let original = before
                .entries
                .iter()
                .find(|entry| !entry.is_directory() && entry.root_relative_path() == "/1")
                .unwrap()
                .clone();
            assert_eq!(original.length(), expected.len() as u64);
            let first_epoch = sessions
                .capture_session_epoch(&scope)
                .unwrap()
                .historical_generation();
            let initial_native = runtime
                .provider
                .read_only_placeholder_observation(NativeRestartProbePath::VaultCapturedFile)
                .unwrap()
                .2
                .unwrap();
            assert_eq!(
                initial_native.0 & 1,
                0,
                "fresh eligible normal publication remains writable without fixture attribute changes"
            );
            assert_ne!(
                initial_native.2 & 8,
                0,
                "full clean hydration must be native in-sync"
            );
            assert_eq!(initial_native.3, expected.len() as u64);
            assert_eq!(std::fs::metadata(&file).unwrap().file_attributes() & 1, 0);
            assert!(
                !runtime
                    .provider
                    .vault_cleanup_fixture(active.clone(), None)
                    .unwrap(),
                "ordinary full read must have real ONDISK bytes before Lock"
            );
            let first_gets = remote.native_reads.lock().unwrap().vault_get_count;
            assert!((1..=16).contains(&first_gets));
            let closes = runtime.provider.close_observation().unwrap();
            assert_eq!(
                (closes.0, closes.1, closes.4, closes.5, closes.7),
                (0, 0, 0, 0, 0)
            );
            let observed = runtime.fresh_close_observation_for_test().unwrap();
            assert_eq!(
                (observed.attempted, observed.completed, observed.failed),
                (0, 0, 0)
            );
            assert!(!observed.local_completed && !observed.remote_verified);
            assert_eq!(observed.native_confirmation, None);
            println!(
                "C06_VAULT_NORMAL_CLEAN_READ_FULL_VERIFIED=true;bytes=65537;GET={first_gets};readonly=false;edits=0;captures=0;NativeCompleted=0;PUT=0;DELETE=0"
            );
            let mut first_lock = target();
            first_lock["action"] = json!("vault_lock");
            let locked = broker
                .handle_isolated_lifecycle_session(first_lock)
                .expect("fresh acknowledged clean-read provenance permits current same-live Lock")
                .0;
            assert_eq!(locked["unlocked"], false);
            assert_eq!(locked["vault_lock_cleanup_status"], "complete");
            assert!(!sessions.is_unlocked(&scope).unwrap());
            assert!(sessions.capture_session_epoch(&scope).is_err());
            assert!(
                runtime
                    .provider
                    .vault_cleanup_fixture(active.clone(), None)
                    .unwrap()
            );
            let empty_native = runtime
                .provider
                .read_only_placeholder_observation(NativeRestartProbePath::VaultCapturedFile)
                .unwrap()
                .2
                .unwrap();
            assert_eq!(empty_native.0 & 1, 0);
            assert_eq!(empty_native.3, expected.len() as u64);
            assert!(
                !broker_vault_read_in_child(&file, expected.len(), &hash).unwrap(),
                "ordinary reader cannot restore plaintext after clean-read Lock"
            );
            assert!(
                runtime
                    .provider
                    .vault_cleanup_fixture(active.clone(), None)
                    .unwrap()
            );
            assert_eq!(
                remote.native_reads.lock().unwrap().vault_get_count,
                first_gets,
                "locked read cannot perform authenticated GET"
            );
            let after_first_lock = verified
                .custody
                .inspect_capture_for_test(&scope, "/Travel.vault")
                .unwrap();
            assert!(after_first_lock.captures.is_empty());
            assert!(
                after_first_lock
                    .entries
                    .iter()
                    .any(|entry| entry == &original),
                "read/Lock never promotes protected original metadata"
            );
            println!(
                "C06_VAULT_NORMAL_CLEAN_READ_FIRST_LOCK_VERIFIED=true;keys_locked=true;on_disk_empty=true;locked_read_refused=true;noGET=true;captures=0;NativeCompleted=0"
            );
            // One same-connection manual reunlock, not remembered/history adoption.
            let mut reunlock = target();
            reunlock["action"] = json!("vault_unlock");
            reunlock["password"] = json!("potato"); // public synthetic fixture only
            reunlock["remember"] = json!(false);
            let unlocked = broker
                .handle_isolated_lifecycle_session(reunlock)
                .unwrap()
                .0;
            assert_eq!(unlocked["unlocked"], true);
            assert_eq!(unlocked["vault_mount_ready"], true);
            assert_eq!(unlocked["vault_mount_existing_file_in_place"], true);
            assert_eq!(unlocked["vault_mount_writable"], false);
            assert!(runtime.provider.connection_matches(active.clone()).unwrap());
            let current_source = runtime
                .provider
                .existing_vault_save_worker_marker(&active)
                .unwrap()
                .unwrap();
            assert!(
                Arc::ptr_eq(&original_source, &current_source),
                "reunlock cannot replace or adopt a new worker source"
            );
            let current = runtime
                .provider
                .verified_vault_backend(active.clone())
                .unwrap();
            assert!(
                Arc::ptr_eq(&verified.backend, &current.backend),
                "same native connection/root backend spans both Locks"
            );
            let second_epoch = sessions
                .capture_session_epoch(&scope)
                .unwrap()
                .historical_generation();
            assert_ne!(
                first_epoch, second_epoch,
                "new crypto epoch label is diagnostic; fresh binding authority is enforced by native provenance"
            );
            assert!(
                runtime
                    .provider
                    .vault_cleanup_fixture(active.clone(), None)
                    .unwrap(),
                "confirmed-evicted cache remains empty before second ordinary full read"
            );
            assert!(broker_vault_read_in_child(&file, expected.len(), &hash).unwrap());
            assert!(
                !runtime
                    .provider
                    .vault_cleanup_fixture(active.clone(), None)
                    .unwrap(),
                "second bound full hydration must create current native cache bytes"
            );
            let full_again = runtime
                .provider
                .read_only_placeholder_observation(NativeRestartProbePath::VaultCapturedFile)
                .unwrap()
                .2
                .unwrap();
            assert_eq!(full_again.0 & 1, 0);
            assert_ne!(full_again.2 & 8, 0);
            assert_eq!(full_again.3, expected.len() as u64);
            let second_gets = remote.native_reads.lock().unwrap().vault_get_count;
            assert!(
                second_gets >= first_gets && second_gets - first_gets <= 16,
                "fresh native read may use authenticated private stage cache; HTTP delta remains bounded"
            );
            println!(
                "C06_VAULT_NORMAL_CLEAN_READ_REUNLOCK_FULL_VERIFIED=true;same_connection=true;same_worker=true;new_epoch_label=true;native_empty_to_full=true;first_GET={first_gets};second_GET={second_gets};delta={};captures=0;NativeCompleted=0",
                second_gets - first_gets
            );
            let mut second_lock = target();
            second_lock["action"] = json!("vault_lock");
            let locked = broker.handle_isolated_lifecycle_session(second_lock).expect("fresh new-binding clean read can roll confirmed eviction forward and Lock again").0;
            assert_eq!(locked["unlocked"], false);
            assert_eq!(locked["vault_lock_cleanup_status"], "complete");
            assert!(!sessions.is_unlocked(&scope).unwrap());
            assert!(sessions.capture_session_epoch(&scope).is_err());
            assert!(
                runtime
                    .provider
                    .vault_cleanup_fixture(active.clone(), None)
                    .unwrap()
            );
            assert!(!broker_vault_read_in_child(&file, expected.len(), &hash).unwrap());
            assert!(
                runtime
                    .provider
                    .vault_cleanup_fixture(active.clone(), None)
                    .unwrap()
            );
            assert_eq!(
                remote.native_reads.lock().unwrap().vault_get_count,
                second_gets
            );
            let final_snapshot = current
                .custody
                .inspect_capture_for_test(&scope, "/Travel.vault")
                .unwrap();
            assert!(
                final_snapshot.captures.is_empty(),
                "reads never create edit capture/NativeCompleted rows"
            );
            assert!(
                final_snapshot
                    .entries
                    .iter()
                    .any(|entry| entry == &original)
            );
            let final_closes = runtime.provider.close_observation().unwrap();
            assert_eq!(
                (
                    final_closes.0,
                    final_closes.1,
                    final_closes.4,
                    final_closes.5,
                    final_closes.7
                ),
                (0, 0, 0, 0, 0)
            );
            let final_worker = runtime.fresh_close_observation_for_test().unwrap();
            assert_eq!(
                (
                    final_worker.attempted,
                    final_worker.completed,
                    final_worker.failed
                ),
                (0, 0, 0)
            );
            assert!(!final_worker.local_completed && !final_worker.remote_verified);
            assert_eq!(remote.recovery.lock().unwrap().put_count, 0);
            assert_eq!(
                remote.native_reads.lock().unwrap().mutation_attempt_count,
                0
            );
            assert!(
                remote.vault_upload.is_none(),
                "default read-only HTTP fixture has no opt-in upload state"
            );
            broker
                .stop_all()
                .expect("two acknowledged clean-read Locks permit normal provider stop");
            assert_eq!(
                remote.native_reads.lock().unwrap().vault_get_count,
                second_gets
            );
            drop(root_pin);
            drop(verified);
            drop(current);
            drop(broker);
            drop(runtime);
            drop(sessions);
            remote.join().unwrap();
            appdata_pin.verify_path().unwrap();
            println!(
                "C06_VAULT_NORMAL_CLEAN_READ_REUNLOCK_LOCK_VERIFIED=true;normal_owner=true;normal_worker=true;readonly=false;ordinary_full_reads=2;clean_locks=2;same_connection=true;same_worker=true;fresh_reunlock_binding=true;keys_locked=true;on_disk_empty=true;locked_read_refused=true;noGET_afterLocks=true;PUT=0;DELETE=0;edits=0;captures=0;NativeCompleted=0;original_entry_unchanged=true;private_worker_start=false;readonly_clear=false;manual_upload=false;late_probe=false;partial_cache_claim=false;package_acceptance=false"
            );
            return;
        }
        if capture_edit {
            let (configuration, root_pin) = runtime
                .confirm_windows_vault_readiness(&scope, "/Travel.vault")
                .unwrap();
            let owner = configuration.registration_ownership.as_ref().unwrap();
            let active = ActiveProviderBinding {
                generation,
                path: PathBuf::from(&configuration.path),
                identity: raiun_cloudfiles_windows::ConfiguredRootIdentity {
                    volume_serial: configuration.volume_serial,
                    file_index: configuration.file_index,
                },
                personal_space_id: owner.personal_drive_id.clone(),
                personal_root_resource_id: owner.personal_root_resource_id.clone().unwrap(),
            };
            let verified = runtime
                .provider
                .verified_vault_backend(active.clone())
                .unwrap();
            let (_, trusted) = verified
                .backend
                .vault_read_context(active.identity)
                .unwrap();
            let original_epoch = sessions
                .capture_session_epoch(&scope)
                .unwrap()
                .historical_generation();
            let before = verified
                .custody
                .inspect_capture_for_test(&scope, "/Travel.vault")
                .unwrap();
            assert!(before.captures.is_empty());
            let original = before
                .entries
                .iter()
                .find(|entry| !entry.is_directory() && entry.root_relative_path() == "/1")
                .unwrap()
                .clone();
            assert_eq!(original.length(), 65537);
            let hydration = before
                .hydrations
                .iter()
                .find(|item| item.opaque() == original.opaque())
                .unwrap();
            let components = vec![
                "Personal".to_owned(),
                "Travel.vault".to_owned(),
                "1".to_owned(),
            ];
            assert_eq!(hydration.components(), components.as_slice());
            assert_eq!(hydration.length(), original.length());
            let ordinary = runtime
                .prepare_recovery_context()
                .unwrap()
                .recovery_provider;
            assert!(ordinary.unresolved_metadata_bounded().unwrap().is_empty());
            let file = drive.join("Personal/Travel.vault/1");
            use std::os::windows::fs::MetadataExt as _;
            let attributes = std::fs::metadata(&file).unwrap().file_attributes();
            assert_ne!(
                attributes & 0x400,
                0,
                "fixture must remain a Cloud Files reparse point"
            );
            let edited = (0..65553).map(|i| (i * 13 + 11) as u8).collect::<Vec<_>>();
            assert_ne!(edited.len() as u64, original.length());
            let gets = remote.native_reads.lock().unwrap().vault_get_count;
            assert_eq!(remote.recovery.lock().unwrap().put_count, 0);
            let before_close = runtime.provider.close_observation().unwrap();
            assert_eq!(before_close.0, 0, "fresh fixture has no modified closes");
            assert_eq!(before_close.7, 0);
            if automatic {
                let mut state = remote.vault_upload.as_ref().unwrap().lock().unwrap();
                assert!(!state.enabled);
                assert_eq!(state.put_count, 0);
                assert_eq!(state.body_get_count, 0);
                if normal_existing {
                    state.max_successful_puts = 2;
                }
                state.enabled = true;
            }
            // Exact fresh fixture path only. Open existing preserves the native
            // file ID/reparse point; only read-only is cleared for this forced
            // synthetic edit. Production vault publication remains read-only.
            use std::process::{Command, Stdio};
            if normal_existing {
                assert_eq!(
                    std::fs::metadata(&file).unwrap().file_attributes() & 1,
                    0,
                    "actual fresh eligible publication must already be writable without fixture metadata mutation"
                );
                assert!(
                    runtime
                        .provider
                        .existing_vault_save_worker_marker(&active)
                        .unwrap()
                        .is_some()
                );
            }
            let edit_command = if normal_existing {
                "$ErrorActionPreference='Stop'; $p=$env:RAIUN_SYNTHETIC_EDIT_FILE; $b=New-Object byte[] 65553; for($i=0;$i -lt $b.Length;$i++){$b[$i]=[byte](($i*13+11)-band 255)}; $f=[IO.File]::Open($p,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::Read); try{$f.SetLength($b.Length); $f.Write($b,0,$b.Length); $f.Flush($true)}finally{$f.Dispose()}"
            } else {
                "$ErrorActionPreference='Stop'; $p=$env:RAIUN_SYNTHETIC_EDIT_FILE; $a=[IO.File]::GetAttributes($p); [IO.File]::SetAttributes($p,($a -band (-bnot [IO.FileAttributes]::ReadOnly))); $b=New-Object byte[] 65553; for($i=0;$i -lt $b.Length;$i++){$b[$i]=[byte](($i*13+11)-band 255)}; $f=[IO.File]::Open($p,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::Read); try{$f.SetLength($b.Length); $f.Write($b,0,$b.Length); $f.Flush($true)}finally{$f.Dispose()}"
            };
            let mut writer = Command::new("powershell.exe")
                .args([
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    edit_command,
                ])
                .env("RAIUN_SYNTHETIC_EDIT_FILE", &file)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                if let Some(status) = writer.try_wait().unwrap() {
                    assert_eq!(status.code(), Some(0), "synthetic in-place writer failed");
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "synthetic writer timed out; process and fixture preserved"
                );
                thread::sleep(Duration::from_millis(20));
            }
            let deadline = Instant::now() + Duration::from_secs(30);
            let observation = loop {
                let observation = runtime.provider.close_observation().unwrap();
                if observation.0 > before_close.0 {
                    break observation;
                }
                assert!(
                    Instant::now() < deadline,
                    "native modified-close callback did not complete"
                );
                thread::sleep(Duration::from_millis(25));
            };
            if automatic {
                // No protected inspector runs while the off-provider ledger CAS
                // is in flight. This per-Agent observation contains no payload.
                let deadline = Instant::now() + Duration::from_secs(60);
                let completed = loop {
                    let value = runtime.fresh_close_observation_for_test().unwrap();
                    if value.completed != 0 {
                        break value;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "fresh native close did not finish its bounded off-provider attempt; preserve fixture"
                    );
                    thread::sleep(Duration::from_millis(25));
                };
                assert_eq!(completed.attempted, 1);
                assert_eq!(completed.completed, 1);
                assert_eq!(completed.failed, 0);
                assert!(completed.remote_verified);
                assert_eq!(completed.native_confirmation, Some(fresh_native));
                assert_eq!(completed.local_completed, fresh_native);
                let provider_thread = runtime
                    .provider
                    .worker
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .thread()
                    .id();
                assert_ne!(completed.thread, Some(provider_thread));
                assert_ne!(completed.thread, Some(thread::current().id()));
            }
            // A protected read holds an immutable no-delete pin. Wait for the
            // producer callback's completed outcome before opening any index or
            // body, so acceptance inspection cannot interfere with its CAS.
            let captured = verified
                .custody
                .inspect_capture_for_test(&scope, "/Travel.vault")
                .expect("completed callback must retain exact protected capture");
            assert_eq!(captured.captures.len(), 1);
            let (retained, entry) = &captured.captures[0];
            assert!(
                entry == &original,
                "capture must preserve original protected catalogue row"
            );
            assert_eq!(retained.bytes_for_recovery(), edited.as_slice());
            let baseline = serde_json::to_value(retained.historical_baseline()).unwrap();
            assert_eq!(
                baseline["opaque_file"],
                serde_json::to_value(original.opaque()).unwrap()
            );
            assert_eq!(baseline["strong_etag"], original.etag());
            assert_eq!(baseline["native_volume"], configuration.volume_serial);
            assert_eq!(baseline["native_file"], hydration.file_index());
            assert_eq!(baseline["unlock_epoch"], original_epoch);
            assert_eq!(baseline["token_generation"], trusted.token_generation());
            assert_eq!(
                observation.7, 0,
                "vault capture is not ordinary journal completion"
            );
            assert!(ordinary.unresolved_metadata_bounded().unwrap().is_empty());
            assert_eq!(remote.recovery.lock().unwrap().put_count, 0);
            assert_eq!(
                remote.native_reads.lock().unwrap().vault_get_count,
                gets + usize::from(automatic)
            );
            assert_eq!(
                std::fs::metadata(&file).unwrap().file_attributes() & 0x400,
                attributes & 0x400
            );
            if upload_edit {
                let capture_ids = verified
                    .custody
                    .retained_capture_ids(&trusted, &scope, "/Travel.vault")
                    .unwrap();
                assert_eq!(capture_ids.len(), 1);
                let capture_id = &capture_ids[0];
                let original_frame = retained.encoded_frame_ref();
                let vault_remote = remote
                    .vault_upload
                    .as_ref()
                    .expect("explicit opt-in remote state");
                if !automatic {
                    let mut state = vault_remote.lock().unwrap();
                    assert!(!state.enabled);
                    assert_eq!(state.put_count, 0);
                    assert_eq!(state.body_get_count, 0);
                    assert_eq!(state.etag, original.etag());
                    state.enabled = true;
                }
                if !automatic {
                    if complete_local {
                        assert!(
                            runtime
                                .provider
                                .vault_file_pending_for_test(original.opaque())
                                .unwrap(),
                            "the exact captured file is pending before live completion"
                        );
                    }
                    // Completion remains an explicit mode; old remote-only entry
                    // point and native selector retain their pending-local behavior.
                    let result = if writable_bytes {
                        runtime.upload_windows_vault_capture_with_writable_completion(
                            &scope,
                            "/Travel.vault",
                            capture_id,
                        )
                    } else if complete_local {
                        runtime.upload_windows_vault_capture_with_completion(
                            &scope,
                            "/Travel.vault",
                            capture_id,
                            true,
                        )
                    } else {
                        runtime.upload_windows_vault_capture(&scope, "/Travel.vault", capture_id)
                    }
                    .expect("explicit broker worker must verify its requested outcome");
                    assert_eq!(
                        result["state"],
                        if complete_local {
                            "local_completed"
                        } else {
                            "remote_verified_pending_local"
                        }
                    );
                    if complete_local {
                        if writable_bytes {
                            assert_eq!(result["native_confirmation"], true);
                            assert_eq!(result["read_only_restored"], false);
                        }
                        if inject_writer_probe {
                            match result["native_writer_exclusion"].as_str() {
                                Some("sharing_denied") => {
                                    assert_eq!(result["native_writer_error"], 32)
                                }
                                Some("pending_through_completion") => assert!(
                                    matches!(result["native_writer_error"].as_i64(), Some(0 | 5)),
                                    "observed pending probe completes after the marker: open succeeds or is denied by restored readonly"
                                ),
                                other => {
                                    panic!(
                                        "actual guarded writer exclusion was not qualified: {other:?}"
                                    )
                                }
                            }
                        } else {
                            assert!(result.get("native_writer_exclusion").is_none());
                            assert!(result.get("native_writer_error").is_none());
                            eprintln!("C06_VAULT_NORMAL_CLOSE_WITHOUT_INJECTED_WRITER=true");
                        }
                        assert_eq!(result["local_cleanup"], "requires_current_native_check");
                        assert!(
                            !runtime
                                .provider
                                .vault_file_pending_for_test(original.opaque())
                                .unwrap(),
                            "only this exact native-completed file resolves"
                        );
                        assert!(
                            runtime.provider.close_observation().unwrap().0 >= observation.0,
                            "historical modified telemetry must never be globally reset"
                        );
                    }
                }
                {
                    let state = vault_remote.lock().unwrap();
                    assert_eq!(state.put_attempt_count, 1);
                    assert_eq!(state.put_count, 1);
                    assert_eq!(state.last_put_if_match.as_deref(), Some(original.etag()));
                    assert_eq!(state.resource_id, original.remote_id());
                    assert_eq!(state.etag, "\"child-rev-2\"");
                    assert_eq!(state.body_get_count, 1);
                    assert_eq!(
                        state.last_read_if_match.as_deref(),
                        Some(state.etag.as_str())
                    );
                    assert_ne!(state.ciphertext.as_slice(), edited.as_slice());
                    assert_ne!(
                        state.ciphertext.as_slice(),
                        include_bytes!("../../raiun-vault/tests/fixtures/web-65537.bin")
                    );
                    assert!(state.ciphertext.len() <= 1024 * 1024);
                }
                use sha2::Digest as _;
                let ledger = verified
                    .custody
                    .upload_ledger(&trusted, &scope, "/Travel.vault", capture_id)
                    .unwrap();
                let attempt = ledger.reopen_attempt().unwrap();
                let proof = attempt
                    .readback_evidence()
                    .unwrap()
                    .expect("persisted authenticated remote readback");
                assert_eq!(proof.resource_id(), original.remote_id());
                assert_eq!(proof.etag(), "\"child-rev-2\"");
                assert_eq!(proof.body_len(), edited.len());
                assert_eq!(
                    proof.body_sha256(),
                    <[u8; 32]>::from(sha2::Sha256::digest(&edited))
                );
                if complete_local {
                    let status = ledger
                        .local_disposition()
                        .unwrap()
                        .expect("persisted v4 native disposition");
                    assert!(
                        status.is_native_completed(),
                        "native S_OK alone is not durable completion"
                    );
                    assert!(status.reference().frame() == original_frame);
                    assert!(status.reference().entry() == &original);
                    assert_eq!(status.verified_entry().opaque(), original.opaque());
                    assert_eq!(status.verified_entry().remote_id(), original.remote_id());
                    assert_eq!(status.verified_entry().etag(), "\"child-rev-2\"");
                    assert_eq!(status.verified_entry().length(), edited.len() as u64);
                    assert_eq!(
                        status.promoted_hydration().file_index(),
                        hydration.file_index()
                    );
                    assert_eq!(
                        status.promoted_hydration().components(),
                        components.as_slice()
                    );
                    assert_eq!(status.promoted_hydration().length(), edited.len() as u64);
                    assert_eq!(status.descriptor().body_len(), edited.len() as u64);
                    assert_eq!(
                        status.descriptor().body_sha256(),
                        <[u8; 32]>::from(sha2::Sha256::digest(&edited))
                    );
                }
                if !automatic {
                    assert!(
                        runtime
                            .upload_windows_vault_capture(&scope, "/Travel.vault", capture_id)
                            .is_err(),
                        "persisted attempt must refuse a second dispatch"
                    );
                } else if !fresh_native {
                    // Reopening protected references cannot mint a fresh job.
                    let reopened = verified
                        .custody
                        .retained_capture_ids(&trusted, &scope, "/Travel.vault")
                        .unwrap();
                    assert_eq!(reopened, capture_ids);
                    let _reopened_attempt = verified
                        .custody
                        .upload_ledger(&trusted, &scope, "/Travel.vault", capture_id)
                        .unwrap()
                        .reopen_attempt()
                        .unwrap();
                    let before_repeat = runtime.provider.close_observation().unwrap();
                    assert_eq!(before_repeat.1, 0, "no earlier unverifiable close");
                    assert_eq!(before_repeat.4, 0, "no earlier close failure stage");
                    assert_eq!(before_repeat.5, 0, "no earlier close failure HRESULT");
                    assert_eq!(before_repeat.7, 0, "no ordinary journal completion");
                    // A read-only reopen need not emit a native close callback.
                    // Reuse the exact existing-file writer with IDENTICAL bytes;
                    // the capture identity deliberately excludes USN/time.
                    let mut repeat_writer = Command::new("powershell.exe")
                        .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
                            "$ErrorActionPreference='Stop'; $p=$env:RAIUN_SYNTHETIC_EDIT_FILE; $a=[IO.File]::GetAttributes($p); [IO.File]::SetAttributes($p,($a -band (-bnot [IO.FileAttributes]::ReadOnly))); $b=New-Object byte[] 65553; for($i=0;$i -lt $b.Length;$i++){$b[$i]=[byte](($i*13+11)-band 255)}; $f=[IO.File]::Open($p,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::Read); try{$f.SetLength($b.Length); $f.Write($b,0,$b.Length); $f.Flush($true)}finally{$f.Dispose()}"])
                        .env("RAIUN_SYNTHETIC_EDIT_FILE", &file)
                        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
                        .spawn().unwrap();
                    let writer_deadline = Instant::now() + Duration::from_secs(20);
                    loop {
                        if let Some(status) = repeat_writer.try_wait().unwrap() {
                            assert_eq!(status.code(), Some(0), "identical synthetic writer failed");
                            break;
                        }
                        assert!(
                            Instant::now() < writer_deadline,
                            "identical synthetic writer timed out; process and fixture preserved"
                        );
                        thread::sleep(Duration::from_millis(20));
                    }
                    let deadline = Instant::now() + Duration::from_secs(15);
                    let after_repeat = loop {
                        let value = runtime.provider.close_observation().unwrap();
                        if value.0 > before_repeat.0 {
                            break value;
                        }
                        assert!(
                            Instant::now() < deadline,
                            "identical modified-close callback was not observed"
                        );
                        thread::sleep(Duration::from_millis(25));
                    };
                    // Modified count also rises on refusal. The existing failure
                    // stage is published before that increment, so require all
                    // error/journal fields to remain at their fresh baseline.
                    assert_eq!(
                        after_repeat.1, 0,
                        "duplicate close must not be unverifiable"
                    );
                    assert_eq!(
                        after_repeat.4, 0,
                        "duplicate close must not fail validation"
                    );
                    assert_eq!(after_repeat.5, 0, "duplicate close must not fail natively");
                    assert_eq!(
                        after_repeat.7, 0,
                        "duplicate vault close is not journal completion"
                    );
                    let observed = runtime.fresh_close_observation_for_test().unwrap();
                    assert_eq!(
                        observed.attempted, 1,
                        "identical close/reopened history must not enqueue a new dispatch"
                    );
                    assert_eq!(observed.completed, 1);
                }
                if fresh_native {
                    let reopened = verified
                        .custody
                        .retained_capture_ids(&trusted, &scope, "/Travel.vault")
                        .unwrap();
                    assert_eq!(reopened, capture_ids);
                    let _reopened_attempt = verified
                        .custody
                        .upload_ledger(&trusted, &scope, "/Travel.vault", capture_id)
                        .unwrap()
                        .reopen_attempt()
                        .unwrap();
                    let completed = runtime.fresh_close_observation_for_test().unwrap();
                    assert_eq!(
                        completed.attempted, 1,
                        "reopened references cannot enqueue or replay work"
                    );
                    assert_eq!(completed.completed, 1);
                    assert_eq!(completed.failed, 0);
                    assert!(completed.local_completed);
                    assert_eq!(completed.native_confirmation, Some(true));
                }
                {
                    let state = vault_remote.lock().unwrap();
                    assert_eq!(state.put_attempt_count, 1, "no conditional PUT replay");
                    assert_eq!(state.put_count, 1);
                    assert_eq!(state.body_get_count, 1);
                }
                let after_upload = verified
                    .custody
                    .inspect_capture_for_test(&scope, "/Travel.vault")
                    .unwrap();
                assert_eq!(after_upload.captures.len(), 1);
                assert!(
                    after_upload.captures[0].0.encoded_frame_ref() == original_frame,
                    "immutable capture frame must remain unchanged"
                );
                assert_eq!(
                    after_upload.captures[0].0.bytes_for_recovery(),
                    edited.as_slice()
                );
                assert!(after_upload.captures[0].1 == original);
                assert_eq!(std::fs::read(&file).unwrap(), edited);
                if automatic {
                    let after_protected_read = runtime.provider.close_observation().unwrap();
                    assert_eq!(
                        after_protected_read.1, 0,
                        "protected duplicate/frame inspection must not hide an unverifiable close"
                    );
                    assert_eq!(
                        after_protected_read.4, 0,
                        "protected duplicate/frame inspection must not hide validation refusal"
                    );
                    assert_eq!(
                        after_protected_read.5, 0,
                        "protected duplicate/frame inspection must not hide native error"
                    );
                    assert_eq!(
                        after_protected_read.7, 0,
                        "no ordinary journal completion after duplicate"
                    );
                }
                assert!(ordinary.unresolved_metadata_bounded().unwrap().is_empty());
                assert_eq!(remote.recovery.lock().unwrap().put_count, 0);
                assert_eq!(runtime.provider.close_observation().unwrap().7, 0);
                if automatic && !fresh_native {
                    println!(
                        "C06_VAULT_FRESH_CLOSE_AUTO_UPLOAD_VERIFIED=true;vaultPUT=1;authenticatedBodyGET=1;off_provider_thread=true;noReplay=true;native_confirmation=false;capture_pending=true;cleanup=incomplete"
                    );
                } else if !complete_local {
                    println!(
                        "C06_VAULT_EXPLICIT_CAPTURE_UPLOAD_VERIFIED=true;vaultPUT=1;authenticatedBodyGET=1;noReplay=true;capture_pending=true;cleanup=incomplete"
                    );
                }
            }
            if complete_local {
                let after = runtime
                    .provider
                    .read_only_placeholder_observation(NativeRestartProbePath::VaultCapturedFile)
                    .unwrap()
                    .2
                    .expect("completed native placeholder observation");
                assert_ne!(after.0 & 0x400, 0, "Cloud Files reparse point retained");
                assert_ne!(after.2 & 0x8, 0, "actual native IN_SYNC state required");
                assert_eq!(after.3, edited.len() as u64);
                assert_eq!(std::fs::read(&file).unwrap(), edited);
                let promoted = verified
                    .custody
                    .inspect_capture_for_test(&scope, "/Travel.vault")
                    .unwrap();
                assert_eq!(promoted.captures.len(), 1);
                assert_eq!(
                    promoted.captures[0].0.bytes_for_recovery(),
                    edited.as_slice()
                );
                assert!(
                    promoted.captures[0].1 == original,
                    "historical capture baseline must not be rebased"
                );
                let entry = promoted
                    .entries
                    .iter()
                    .find(|entry| entry.opaque() == original.opaque())
                    .unwrap();
                assert_eq!(entry.remote_id(), original.remote_id());
                assert_eq!(entry.etag(), "\"child-rev-2\"");
                assert_eq!(entry.length(), edited.len() as u64);
                let hydration = promoted
                    .hydrations
                    .iter()
                    .find(|item| item.opaque() == original.opaque())
                    .unwrap();
                assert_eq!(
                    hydration.file_index(),
                    baseline["native_file"].as_u64().unwrap()
                );
                assert_eq!(hydration.length(), edited.len() as u64);
                assert_eq!(hydration.components(), components.as_slice());
                let gets_after_upload = remote.native_reads.lock().unwrap().vault_get_count;
                assert_eq!(
                    gets_after_upload,
                    gets + 1,
                    "local disposition does no download"
                );
                if writable_bytes {
                    assert_eq!(
                        after.0 & 1,
                        0,
                        "writable byte completion must not restore READONLY"
                    );
                    assert!(
                        !runtime
                            .provider
                            .vault_file_pending_for_test(original.opaque())
                            .unwrap()
                    );
                    if normal_existing {
                        // First save above used only fresh per-child publication and the
                        // normal authenticated connection hook. No private start/upload.
                        let first_ids = verified
                            .custody
                            .retained_capture_ids(&trusted, &scope, "/Travel.vault")
                            .unwrap();
                        assert_eq!(first_ids.len(), 1);
                        let second_baseline = (*entry).clone();
                        assert_eq!(second_baseline.etag(), "\"child-rev-2\"");
                        assert_eq!(second_baseline.length(), edited.len() as u64);
                        assert!(
                            runtime
                                .provider
                                .existing_vault_save_worker_marker(&active)
                                .unwrap()
                                .is_some()
                        );
                        let second_bytes =
                            (0..65569).map(|i| (i * 17 + 3) as u8).collect::<Vec<_>>();
                        let before_second = runtime.provider.close_observation().unwrap();
                        assert_eq!(std::fs::metadata(&file).unwrap().file_attributes() & 1, 0);
                        let mut second_writer = Command::new("powershell.exe")
                            .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
                                "$ErrorActionPreference='Stop'; $b=New-Object byte[] 65569; for($i=0;$i -lt $b.Length;$i++){$b[$i]=[byte](($i*17+3)-band 255)}; $f=[IO.File]::Open($env:RAIUN_SYNTHETIC_EDIT_FILE,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::Read); try{$f.SetLength($b.Length); $f.Write($b,0,$b.Length); $f.Flush($true)}finally{$f.Dispose()}"])
                            .env("RAIUN_SYNTHETIC_EDIT_FILE", &file)
                            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
                        let deadline = Instant::now() + Duration::from_secs(20);
                        loop {
                            if let Some(status) = second_writer.try_wait().unwrap() {
                                assert_eq!(
                                    status.code(),
                                    Some(0),
                                    "second normal in-place writer failed; preserve fixture"
                                );
                                break;
                            }
                            assert!(
                                Instant::now() < deadline,
                                "second normal writer timed out; preserve process and fixture"
                            );
                            thread::sleep(Duration::from_millis(20));
                        }
                        let deadline = Instant::now() + Duration::from_secs(30);
                        loop {
                            if runtime.provider.close_observation().unwrap().0 > before_second.0 {
                                break;
                            }
                            assert!(
                                Instant::now() < deadline,
                                "second normal modified close not observed"
                            );
                            thread::sleep(Duration::from_millis(25));
                        }
                        // Do not hold a protected inspector against the second CAS.
                        let deadline = Instant::now() + Duration::from_secs(60);
                        let completed = loop {
                            let value = runtime.fresh_close_observation_for_test().unwrap();
                            if value.completed >= 2 {
                                break value;
                            }
                            assert!(
                                Instant::now() < deadline,
                                "second automatic native save did not finish"
                            );
                            thread::sleep(Duration::from_millis(25));
                        };
                        assert_eq!(completed.attempted, 2);
                        assert_eq!(completed.completed, 2);
                        assert_eq!(completed.failed, 0);
                        assert!(completed.remote_verified && completed.local_completed);
                        assert_eq!(completed.native_confirmation, Some(true));
                        let provider_thread = runtime
                            .provider
                            .worker
                            .lock()
                            .unwrap()
                            .as_ref()
                            .unwrap()
                            .thread()
                            .id();
                        assert_ne!(completed.thread, Some(provider_thread));
                        assert_ne!(completed.thread, Some(thread::current().id()));
                        let after_second_close = runtime.provider.close_observation().unwrap();
                        assert!(
                            after_second_close.0 >= 2,
                            "historical modified telemetry must not be reset"
                        );
                        assert_eq!(
                            (
                                after_second_close.1,
                                after_second_close.4,
                                after_second_close.5,
                                after_second_close.7
                            ),
                            (0, 0, 0, 0)
                        );
                        assert!(
                            !runtime
                                .provider
                                .vault_file_pending_for_test(original.opaque())
                                .unwrap()
                        );
                        let second_snapshot = verified
                            .custody
                            .inspect_capture_for_test(&scope, "/Travel.vault")
                            .unwrap();
                        assert_eq!(second_snapshot.captures.len(), 2);
                        let old_capture = second_snapshot
                            .captures
                            .iter()
                            .find(|(capture, _)| {
                                capture.encoded_frame_ref() == retained.encoded_frame_ref()
                            })
                            .unwrap();
                        assert_eq!(old_capture.0.bytes_for_recovery(), edited.as_slice());
                        assert!(old_capture.1 == original);
                        let (second_capture, second_original) = second_snapshot
                            .captures
                            .iter()
                            .find(|(capture, _)| {
                                capture.encoded_frame_ref() != retained.encoded_frame_ref()
                            })
                            .unwrap();
                        assert_eq!(second_capture.bytes_for_recovery(), second_bytes.as_slice());
                        assert!(
                            second_original == &second_baseline,
                            "second capture must bind promoted first-save baseline"
                        );
                        let second_historical =
                            serde_json::to_value(second_capture.historical_baseline()).unwrap();
                        assert_eq!(second_historical["strong_etag"], second_baseline.etag());
                        assert_eq!(second_historical["native_file"], baseline["native_file"]);
                        assert_eq!(second_historical["unlock_epoch"], original_epoch);
                        assert_eq!(
                            second_historical["token_generation"],
                            trusted.token_generation()
                        );
                        let all_ids = verified
                            .custody
                            .retained_capture_ids(&trusted, &scope, "/Travel.vault")
                            .unwrap();
                        assert_eq!(all_ids.len(), 2);
                        let second_id = all_ids.iter().find(|id| !first_ids.contains(id)).unwrap();
                        let second_ledger = verified
                            .custody
                            .upload_ledger(&trusted, &scope, "/Travel.vault", second_id)
                            .unwrap();
                        let second_attempt = second_ledger.reopen_attempt().unwrap();
                        let readback = second_attempt.readback_evidence().unwrap().unwrap();
                        assert_eq!(readback.resource_id(), original.remote_id());
                        assert_eq!(readback.etag(), "\"child-rev-3\"");
                        assert_eq!(readback.body_len(), second_bytes.len());
                        use sha2::Digest as _;
                        assert_eq!(
                            readback.body_sha256(),
                            <[u8; 32]>::from(sha2::Sha256::digest(&second_bytes))
                        );
                        let second_status = second_ledger.local_disposition().unwrap().unwrap();
                        assert!(second_status.is_native_completed());
                        assert!(second_status.reference().entry() == second_original);
                        assert!(
                            second_status.reference().frame() == second_capture.encoded_frame_ref()
                        );
                        assert_eq!(second_status.verified_entry().etag(), "\"child-rev-3\"");
                        assert_eq!(
                            second_status.verified_entry().length(),
                            second_bytes.len() as u64
                        );
                        assert_eq!(
                            second_status.promoted_hydration().file_index(),
                            hydration.file_index()
                        );
                        assert_eq!(
                            second_status.promoted_hydration().components(),
                            components.as_slice()
                        );
                        assert_eq!(
                            second_status.promoted_hydration().length(),
                            second_bytes.len() as u64
                        );
                        let current = second_snapshot
                            .entries
                            .iter()
                            .find(|entry| entry.opaque() == original.opaque())
                            .unwrap();
                        assert_eq!(current.etag(), "\"child-rev-3\"");
                        assert_eq!(current.length(), second_bytes.len() as u64);
                        assert_eq!(current.remote_id(), original.remote_id());
                        let native = runtime
                            .provider
                            .read_only_placeholder_observation(
                                NativeRestartProbePath::VaultCapturedFile,
                            )
                            .unwrap()
                            .2
                            .unwrap();
                        assert_eq!(native.0 & 1, 0);
                        assert_ne!(native.2 & 8, 0);
                        assert_eq!(native.3, second_bytes.len() as u64);
                        assert_eq!(std::fs::read(&file).unwrap(), second_bytes);
                        let gets_after_two = remote.native_reads.lock().unwrap().vault_get_count;
                        assert_eq!(gets_after_two, gets + 2);
                        {
                            let state = remote.vault_upload.as_ref().unwrap().lock().unwrap();
                            assert_eq!(
                                (
                                    state.put_attempt_count,
                                    state.put_count,
                                    state.body_get_count
                                ),
                                (2, 2, 2)
                            );
                            assert_eq!(state.last_put_if_match.as_deref(), Some("\"child-rev-2\""));
                            assert_eq!(
                                state.last_read_if_match.as_deref(),
                                Some("\"child-rev-3\"")
                            );
                            assert_eq!(state.resource_id, original.remote_id());
                            assert_eq!(state.forbidden_mutation_count, 0);
                        }
                        assert!(ordinary.unresolved_metadata_bounded().unwrap().is_empty());
                        assert_eq!(remote.recovery.lock().unwrap().put_count, 0);
                        println!(
                            "C06_VAULT_NORMAL_EXISTING_FILE_TWO_SAVES_COMPLETED=true;vaultPUT=2;authenticatedBodyGET=2;firstIfMatch=child-rev-1;secondIfMatch=child-rev-2;currentETag=child-rev-3;captures=2;native_completed=2;dirty_resolved=true;manual_upload=false;readonly_clear=false"
                        );
                        let mut lock = target();
                        lock["action"] = json!("vault_lock");
                        let locked = broker
                            .handle_isolated_lifecycle_session(lock)
                            .expect("normal two-save current native state permits clean Lock")
                            .0;
                        assert_eq!(locked["unlocked"], false);
                        assert_eq!(locked["vault_lock_cleanup_status"], "complete");
                        assert!(!sessions.is_unlocked(&scope).unwrap());
                        assert!(sessions.capture_session_epoch(&scope).is_err());
                        assert!(
                            runtime
                                .provider
                                .vault_cleanup_fixture(active.clone(), None)
                                .unwrap()
                        );
                        let locked_native = runtime
                            .provider
                            .read_only_placeholder_observation(
                                NativeRestartProbePath::VaultCapturedFile,
                            )
                            .unwrap()
                            .2
                            .unwrap();
                        assert_eq!(locked_native.0 & 1, 0);
                        assert_eq!(locked_native.3, second_bytes.len() as u64);
                        let hash = format!("{:x}", sha2::Sha256::digest(&second_bytes));
                        assert!(
                            !broker_vault_read_in_child(&file, second_bytes.len(), &hash).unwrap()
                        );
                        assert!(
                            runtime
                                .provider
                                .vault_cleanup_fixture(active.clone(), None)
                                .unwrap()
                        );
                        assert_eq!(
                            remote.native_reads.lock().unwrap().vault_get_count,
                            gets_after_two
                        );
                        let after_lock = verified
                            .custody
                            .inspect_capture_for_test(&scope, "/Travel.vault")
                            .unwrap();
                        assert_eq!(after_lock.captures.len(), 2);
                        for (capture, entry) in &after_lock.captures {
                            if capture.encoded_frame_ref() == retained.encoded_frame_ref() {
                                assert_eq!(capture.bytes_for_recovery(), edited.as_slice());
                                assert!(entry == &original);
                            } else {
                                assert!(
                                    capture.encoded_frame_ref()
                                        == second_capture.encoded_frame_ref()
                                );
                                assert_eq!(capture.bytes_for_recovery(), second_bytes.as_slice());
                                assert!(entry == second_original);
                            }
                        }
                        let final_worker = runtime.fresh_close_observation_for_test().unwrap();
                        assert_eq!(
                            (
                                final_worker.attempted,
                                final_worker.completed,
                                final_worker.failed
                            ),
                            (2, 2, 0)
                        );
                        broker
                            .stop_all()
                            .expect("normal two-save locked provider stops without force");
                        assert_eq!(
                            remote.native_reads.lock().unwrap().vault_get_count,
                            gets_after_two
                        );
                        {
                            let state = remote.vault_upload.as_ref().unwrap().lock().unwrap();
                            assert_eq!(
                                (
                                    state.put_attempt_count,
                                    state.put_count,
                                    state.body_get_count
                                ),
                                (2, 2, 2)
                            );
                        }
                        drop(root_pin);
                        drop(verified);
                        drop(broker);
                        drop(runtime);
                        drop(sessions);
                        remote.join().unwrap();
                        appdata_pin.verify_path().unwrap();
                        println!(
                            "C06_VAULT_NORMAL_EXISTING_FILE_TWO_SAVE_LOCK_VERIFIED=true;normal_owner=true;normal_worker=true;fresh_writable_publication=true;vaultPUT=2;authenticatedBodyGET=2;native_completed=2;captures_retained=2;dirty_resolved=true;keys_locked=true;on_disk_empty=true;locked_read_refused=true;noGET_afterLock=true;manual_upload=false;readonly_clear=false;late_probe=false;namespace_writable=false;DELETE=0;package_acceptance=false"
                        );
                        return;
                    }
                    if writable_cleanup {
                        let mut lock = target();
                        lock["action"] = json!("vault_lock");
                        let locked = broker
                            .handle_isolated_lifecycle_session(lock)
                            .expect(
                                "same-live writable completion permits held-reference clean Lock",
                            )
                            .0;
                        assert_eq!(locked["unlocked"], false);
                        assert_eq!(locked["vault_lock_cleanup_status"], "complete");
                        assert!(!sessions.is_unlocked(&scope).unwrap());
                        assert!(sessions.capture_session_epoch(&scope).is_err());
                        assert!(
                            runtime
                                .provider
                                .vault_cleanup_fixture(active.clone(), None)
                                .unwrap(),
                            "current native ONDISK ranges must be empty after Lock"
                        );
                        let empty_native = runtime
                            .provider
                            .read_only_placeholder_observation(
                                NativeRestartProbePath::VaultCapturedFile,
                            )
                            .unwrap()
                            .2
                            .expect("evicted writable native observation");
                        assert_eq!(empty_native.0 & 1, 0, "cleanup never restores READONLY");
                        assert_eq!(empty_native.3, edited.len() as u64);
                        use sha2::Digest as _;
                        let hash = format!("{:x}", sha2::Sha256::digest(&edited));
                        assert!(
                            !broker_vault_read_in_child(&file, edited.len(), &hash).unwrap(),
                            "fresh ordinary reader must refuse after keys locked/cache eviction"
                        );
                        assert!(
                            runtime
                                .provider
                                .vault_cleanup_fixture(active.clone(), None)
                                .unwrap(),
                            "refused read must not restore native plaintext"
                        );
                        assert_eq!(
                            remote.native_reads.lock().unwrap().vault_get_count,
                            gets_after_upload
                        );
                        let protected = verified
                            .custody
                            .inspect_capture_for_test(&scope, "/Travel.vault")
                            .unwrap();
                        assert_eq!(protected.captures.len(), 1);
                        assert_eq!(
                            protected.captures[0].0.bytes_for_recovery(),
                            edited.as_slice()
                        );
                        assert!(
                            protected.captures[0].0.encoded_frame_ref()
                                == retained.encoded_frame_ref()
                        );
                        assert!(protected.captures[0].1 == original);
                        println!(
                            "C06_VAULT_WRITABLE_CLEANUP_LOCK_VERIFIED=true;keys_locked=true;on_disk_empty=true;locked_read_refused=true;readonly=false;protected_body_retained=true;DELETE=0"
                        );
                        if fresh_native {
                            let completed = runtime.fresh_close_observation_for_test().unwrap();
                            assert_eq!(completed.attempted, 1);
                            assert_eq!(completed.completed, 1);
                            assert_eq!(completed.failed, 0);
                            assert!(completed.remote_verified && completed.local_completed);
                            assert_eq!(completed.native_confirmation, Some(true));
                            assert!(
                                !runtime
                                    .provider
                                    .vault_file_pending_for_test(original.opaque())
                                    .unwrap()
                            );
                            assert!(
                                runtime.provider.close_observation().unwrap().0 >= observation.0,
                                "automatic completion never resets historical modified telemetry"
                            );
                            assert!(ordinary.unresolved_metadata_bounded().unwrap().is_empty());
                            assert_eq!(remote.recovery.lock().unwrap().put_count, 0);
                            {
                                let state = remote.vault_upload.as_ref().unwrap().lock().unwrap();
                                assert_eq!(state.put_attempt_count, 1);
                                assert_eq!(state.put_count, 1);
                                assert_eq!(state.body_get_count, 1);
                                assert_eq!(state.forbidden_mutation_count, 0);
                            }
                            broker.stop_all().expect(
                                "automatically completed same-live capture stops after clean Lock",
                            );
                            drop(root_pin);
                            drop(verified);
                            drop(broker);
                            drop(runtime);
                            drop(sessions);
                            remote.join().unwrap();
                            appdata_pin.verify_path().unwrap();
                            println!(
                                "C06_VAULT_FRESH_CLOSE_AUTO_NATIVE_LOCK_VERIFIED=true;vaultPUT=1;authenticatedBodyGET=1;off_provider_thread=true;noReplay=true;native_confirmation=true;native_completed=true;dirty_resolved=true;keys_locked=true;on_disk_empty=true;locked_read_refused=true;protected_frame_retained=true;readonly=false;manual_upload=false;late_probe=false;DELETE=0;no_product_activation=true"
                            );
                            return;
                        }
                        // The held-reference proof ends at Lock. This one ordinary
                        // existing-file write measures later activity, never permanent
                        // exclusion. No permission/metadata mutation or hydration read.
                        let before_late = runtime.provider.close_observation().unwrap();
                        let late = (0..31).map(|i| (i * 7 + 5) as u8).collect::<Vec<_>>();
                        let mut late_writer = Command::new("powershell.exe")
                            .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
                                "$ErrorActionPreference='Stop'; try { $b=New-Object byte[] 31; for($i=0;$i -lt $b.Length;$i++){$b[$i]=[byte](($i*7+5)-band 255)}; $f=[IO.File]::Open($env:RAIUN_SYNTHETIC_EDIT_FILE,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::Read); try{$f.SetLength($b.Length); $f.Write($b,0,$b.Length); $f.Flush($true)}finally{$f.Dispose()}; [Console]::WriteLine('WRITTEN') } catch { $e=$_.Exception; while($e.InnerException){$e=$e.InnerException}; [Console]::WriteLine(('DENIED|{0}' -f $e.HResult)); exit 24 }"])
                            .env("RAIUN_SYNTHETIC_EDIT_FILE", &file)
                            .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
                        let deadline = Instant::now() + Duration::from_secs(20);
                        let status = loop {
                            if let Some(status) = late_writer.try_wait().unwrap() {
                                break status;
                            }
                            assert!(
                                Instant::now() < deadline,
                                "late writer timed out; preserve owned process and fixture"
                            );
                            thread::sleep(Duration::from_millis(20));
                        };
                        let output = late_writer.wait_with_output().unwrap();
                        let report = String::from_utf8(output.stdout).unwrap();
                        let report = report.trim();
                        println!(
                            "C06_VAULT_WRITABLE_CLEANUP_LATE_WRITER_RAW={report};exit={:?}",
                            status.code()
                        );
                        let late_written = if status.success() {
                            assert_eq!(report, "WRITTEN");
                            let deadline = Instant::now() + Duration::from_secs(15);
                            loop {
                                let observation = runtime.provider.close_observation().unwrap();
                                if observation.0 > before_late.0 || observation.1 > before_late.1 {
                                    break;
                                }
                                assert!(
                                    Instant::now() < deadline,
                                    "late modified/uncertain close not observed; preserve fixture"
                                );
                                thread::sleep(Duration::from_millis(25));
                            }
                            assert!(
                                runtime
                                    .provider
                                    .vault_lock_cleanup_status(
                                        active.clone(),
                                        "synthetic-personal-drive".into(),
                                        "synthetic-vault-root".into(),
                                        "/Travel.vault".into()
                                    )
                                    .unwrap(),
                                "later observed activity must make current cleanup incomplete after route removal"
                            );
                            assert_eq!(
                                std::fs::read(&file).unwrap(),
                                late,
                                "late native bytes must survive"
                            );
                            assert!(
                                !runtime
                                    .provider
                                    .vault_cleanup_fixture(active.clone(), None)
                                    .unwrap(),
                                "same recorded native file now has retained late ONDISK bytes"
                            );
                            assert!(
                                broker.stop_all().is_err(),
                                "later dirty bytes refuse stop cleanup"
                            );
                            println!(
                                "C06_VAULT_WRITABLE_CLEANUP_LATE_ACTIVITY=true;current_cleanup=incomplete;new_bytes_retained=true;permanent_exclusion_claim=false"
                            );
                            true
                        } else {
                            assert_eq!(status.code(), Some(24));
                            let hr = report
                                .strip_prefix("DENIED|")
                                .and_then(|s| s.parse::<i32>().ok())
                                .expect("late refusal must report actual HRESULT");
                            let code = hr as u32 & 0xffff;
                            assert_eq!(
                                hr as u32 & 0xffff0000,
                                0x80070000,
                                "unexpected setup/.NET error is not a safe write denial"
                            );
                            assert!(
                                matches!(code, 5 | 32 | 362 | 389 | 395),
                                "late failure must be a known access/sharing/cloud-file error"
                            );
                            let after_denial = runtime
                                .provider
                                .read_only_placeholder_observation(
                                    NativeRestartProbePath::VaultCapturedFile,
                                )
                                .unwrap()
                                .2
                                .expect("current metadata after denied late write");
                            assert_eq!(
                                after_denial.0, empty_native.0,
                                "late denied writer must not change attributes"
                            );
                            println!(
                                "C06_VAULT_WRITABLE_CLEANUP_LATE_DENIAL_METADATA=hresult:{hr};win32:{code};before_attrs:{};after_attrs:{};before_tag:{};after_tag:{};before_state:{};after_state:{};before_len:{};after_len:{}",
                                empty_native.0,
                                after_denial.0,
                                empty_native.1,
                                after_denial.1,
                                empty_native.2,
                                after_denial.2,
                                empty_native.3,
                                after_denial.3
                            );
                            assert!(
                                runtime
                                    .provider
                                    .vault_cleanup_fixture(active.clone(), None)
                                    .unwrap(),
                                "denied writer must leave current ONDISK empty, including after a length-only side effect"
                            );
                            let observed = runtime.provider.close_observation().unwrap();
                            let pending = runtime
                                .provider
                                .vault_lock_cleanup_status(
                                    active.clone(),
                                    "synthetic-personal-drive".into(),
                                    "synthetic-vault-root".into(),
                                    "/Travel.vault".into(),
                                )
                                .unwrap();
                            println!(
                                "C06_VAULT_WRITABLE_CLEANUP_LATE_DENIAL_OBSERVATION=before:{before_late:?};after:{observed:?};pending:{pending}"
                            );
                            let changed = after_denial != empty_native
                                || observed.0 > before_late.0
                                || observed.1 > before_late.1
                                || pending;
                            let stopped = if changed {
                                None
                            } else {
                                Some(broker.stop_all())
                            };
                            let incomplete =
                                changed || stopped.as_ref().is_some_and(Result::is_err);
                            if incomplete {
                                let deadline = Instant::now() + Duration::from_secs(15);
                                let observed = loop {
                                    let observation = runtime.provider.close_observation().unwrap();
                                    if observation.0 > before_late.0
                                        || observation.1 > before_late.1
                                    {
                                        break observation;
                                    }
                                    assert!(
                                        Instant::now() < deadline,
                                        "denied late write side effect has no observed modified/uncertain close; preserve fixture"
                                    );
                                    thread::sleep(Duration::from_millis(25));
                                };
                                assert!(
                                    runtime
                                        .provider
                                        .vault_lock_cleanup_status(
                                            active.clone(),
                                            "synthetic-personal-drive".into(),
                                            "synthetic-vault-root".into(),
                                            "/Travel.vault".into()
                                        )
                                        .unwrap()
                                );
                                if stopped.is_none() {
                                    assert!(
                                        broker.stop_all().is_err(),
                                        "observed late side effects refuse stop cleanup"
                                    );
                                }
                                println!(
                                    "C06_VAULT_WRITABLE_CLEANUP_LATE_DENIAL_SIDE_EFFECT=true;hresult={hr};win32={code};native_len={};modified_closes={};uncertain_closes={};current_cleanup=incomplete;native_state_preserved=true;permanent_exclusion_claim=false",
                                    after_denial.3, observed.0, observed.1
                                );
                            } else {
                                assert!(stopped.unwrap().is_ok());
                                println!(
                                    "C06_VAULT_WRITABLE_CLEANUP_LATE_WRITE_DENIED=true;hresult={hr};win32={code};observed_mutation=false;actual_stop=complete;permanent_exclusion_claim=false"
                                );
                            }
                            false
                        };
                        assert!(!sessions.is_unlocked(&scope).unwrap());
                        assert!(sessions.capture_session_epoch(&scope).is_err());
                        assert_eq!(
                            remote.native_reads.lock().unwrap().vault_get_count,
                            gets_after_upload
                        );
                        assert_eq!(remote.recovery.lock().unwrap().put_count, 0);
                        assert!(ordinary.unresolved_metadata_bounded().unwrap().is_empty());
                        let protected_after_late = verified
                            .custody
                            .inspect_capture_for_test(&scope, "/Travel.vault")
                            .unwrap();
                        assert_eq!(protected_after_late.captures.len(), 1);
                        assert_eq!(
                            protected_after_late.captures[0].0.bytes_for_recovery(),
                            edited.as_slice()
                        );
                        assert!(
                            protected_after_late.captures[0].0.encoded_frame_ref()
                                == retained.encoded_frame_ref()
                        );
                        assert!(protected_after_late.captures[0].1 == original);
                        {
                            let state = remote.vault_upload.as_ref().unwrap().lock().unwrap();
                            assert_eq!(state.put_attempt_count, 1);
                            assert_eq!(state.put_count, 1);
                            assert_eq!(state.body_get_count, 1);
                            assert_eq!(state.forbidden_mutation_count, 0);
                        }
                        drop(root_pin);
                        drop(verified);
                        drop(broker);
                        drop(runtime);
                        drop(sessions);
                        remote.join().unwrap();
                        appdata_pin.verify_path().unwrap();
                        println!(
                            "C06_VAULT_WRITABLE_CLEANUP_BOUNDARY_VERIFIED=true;vaultPUT=1;authenticatedBodyGET=1;noReplay=true;native_completed=true;keys_locked=true;late_written={late_written};no_product_activation=true"
                        );
                        return;
                    }
                    // Historical NativeCompleted is NOT cleanup authority. This
                    // legacy denial case drops only the exact live volatile row.
                    runtime
                        .provider
                        .vault_cleanup_fixture(active.clone(), Some(original.opaque()))
                        .unwrap();
                    println!(
                        "C06_VAULT_WRITABLE_CLEANUP_VOLATILE_RECEIPT_DROPPED=true;protected_history_unchanged=true"
                    );
                    let mut lock = target();
                    lock["action"] = json!("vault_lock");
                    assert!(
                        broker.handle_isolated_lifecycle_session(lock).is_err(),
                        "historical native completion without live receipt cannot authorize writable cleanup"
                    );
                    assert!(!sessions.is_unlocked(&scope).unwrap());
                    assert!(
                        sessions.capture_session_epoch(&scope).is_err(),
                        "Lock must refuse a new vault key/epoch lease"
                    );
                    assert!(
                        runtime
                            .provider
                            .vault_lock_cleanup_status(
                                active.clone(),
                                "synthetic-personal-drive".into(),
                                "synthetic-vault-root".into(),
                                "/Travel.vault".into()
                            )
                            .unwrap()
                    );
                    let locked_native = runtime
                        .provider
                        .read_only_placeholder_observation(
                            NativeRestartProbePath::VaultCapturedFile,
                        )
                        .unwrap()
                        .2
                        .expect("retained writable native file observation");
                    assert_eq!(
                        locked_native.0 & 1,
                        0,
                        "failed readonly cleanup cannot claim attribute restoration"
                    );
                    assert_eq!(locked_native.3, edited.len() as u64);
                    assert_eq!(
                        std::fs::read(&file).unwrap(),
                        edited,
                        "incomplete cleanup preserves owned native bytes"
                    );
                    assert_eq!(
                        remote.native_reads.lock().unwrap().vault_get_count,
                        gets_after_upload
                    );
                    let retained_after_lock = verified
                        .custody
                        .inspect_capture_for_test(&scope, "/Travel.vault")
                        .unwrap();
                    assert_eq!(retained_after_lock.captures.len(), 1);
                    assert_eq!(
                        retained_after_lock.captures[0].0.bytes_for_recovery(),
                        edited.as_slice()
                    );
                    assert!(
                        retained_after_lock.captures[0].0.encoded_frame_ref()
                            == retained.encoded_frame_ref()
                    );
                    assert!(retained_after_lock.captures[0].1 == original);
                    let diagnostics = runtime
                        .provider
                        .vault_cleanup_diagnostics(active.clone())
                        .unwrap();
                    assert!(
                        diagnostics["modified_closes"].as_u64().unwrap() >= 1,
                        "historical modified telemetry remains"
                    );
                    assert_eq!(diagnostics["journaled_closes"], 0);
                    assert!(ordinary.unresolved_metadata_bounded().unwrap().is_empty());
                    assert_eq!(remote.recovery.lock().unwrap().put_count, 0);
                    {
                        let state = remote.vault_upload.as_ref().unwrap().lock().unwrap();
                        assert_eq!(state.put_attempt_count, 1);
                        assert_eq!(state.put_count, 1);
                        assert_eq!(state.body_get_count, 1);
                        assert_eq!(state.forbidden_mutation_count, 0);
                    }
                    assert!(
                        broker.stop_all().is_err(),
                        "writable-byte completion must retain incomplete readonly cleanup"
                    );
                    drop(root_pin);
                    drop(verified);
                    drop(broker);
                    drop(runtime);
                    drop(sessions);
                    remote.join().unwrap();
                    appdata_pin.verify_path().unwrap();
                    println!(
                        "C06_VAULT_WRITABLE_BYTES_NATIVE_COMPLETED_CLEANUP_PENDING=true;vaultPUT=1;authenticatedBodyGET=1;noReplay=true;native_confirmation=true;read_only_restored=false;metadata_overwrite=false;keys_locked=true;cleanup=incomplete;no_product_activation=true"
                    );
                    return;
                }
                let mut lock = target();
                lock["action"] = json!("vault_lock");
                let locked = broker
                    .handle_isolated_lifecycle_session(lock)
                    .expect("verified local completion permits clean Lock")
                    .0;
                assert_eq!(locked["unlocked"], false);
                assert_eq!(locked["vault_lock_cleanup_status"], "complete");
                assert!(!sessions.is_unlocked(&scope).unwrap());
                let locked_native = runtime
                    .provider
                    .read_only_placeholder_observation(NativeRestartProbePath::VaultCapturedFile)
                    .unwrap()
                    .2
                    .expect("locked native placeholder observation");
                assert_eq!(locked_native.3, edited.len() as u64);
                assert_ne!(locked_native.0 & 1, 0, "clean locked file remains readonly");
                use sha2::Digest as _;
                let hash = format!("{:x}", sha2::Sha256::digest(&edited));
                assert!(
                    !broker_vault_read_in_child(&file, edited.len(), &hash).unwrap(),
                    "one ordinary read after genuine clean Lock must refuse"
                );
                assert_eq!(
                    remote.native_reads.lock().unwrap().vault_get_count,
                    gets_after_upload
                );
                assert!(ordinary.unresolved_metadata_bounded().unwrap().is_empty());
                assert_eq!(remote.recovery.lock().unwrap().put_count, 0);
                {
                    let state = remote.vault_upload.as_ref().unwrap().lock().unwrap();
                    assert_eq!(state.put_attempt_count, 1);
                    assert_eq!(state.put_count, 1);
                    assert_eq!(state.body_get_count, 1);
                    assert_eq!(state.forbidden_mutation_count, 0);
                }
                broker
                    .stop_all()
                    .expect("clean disposition stops normally without force");
                drop(root_pin);
                drop(verified);
                drop(broker);
                drop(runtime);
                drop(sessions);
                remote.join().unwrap();
                appdata_pin.verify_path().unwrap();
                if inject_writer_probe {
                    println!(
                        "C06_VAULT_FULL_SAVE_LOCAL_DISPOSITION_VERIFIED=true;vaultPUT=1;authenticatedBodyGET=1;noReplay=true;local_completed=true;locked_read_refused=true;DELETE=0"
                    );
                } else {
                    println!(
                        "C06_VAULT_NORMAL_CLOSE_FULL_SAVE_LOCAL_DISPOSITION_VERIFIED=true;vaultPUT=1;authenticatedBodyGET=1;noReplay=true;local_completed=true;locked_read_refused=true;DELETE=0;injected_writer=false"
                    );
                }
                return;
            }
            let mut lock = target();
            lock["action"] = json!("vault_lock");
            assert!(
                broker.handle_isolated_lifecycle_session(lock).is_err(),
                "dirty historical capture cannot acknowledge complete cleanup"
            );
            assert!(!sessions.is_unlocked(&scope).unwrap());
            assert!(
                runtime
                    .provider
                    .vault_lock_cleanup_status(
                        active.clone(),
                        "synthetic-personal-drive".into(),
                        "synthetic-vault-root".into(),
                        "/Travel.vault".into()
                    )
                    .unwrap()
            );
            let diagnostics = runtime.provider.vault_cleanup_diagnostics(active).unwrap();
            assert!(diagnostics["modified_closes"].as_u64().unwrap() >= 1);
            assert_eq!(diagnostics["journaled_closes"], 0);
            assert_eq!(std::fs::read(&file).unwrap(), edited);
            assert!(ordinary.unresolved_metadata_bounded().unwrap().is_empty());
            assert_eq!(remote.recovery.lock().unwrap().put_count, 0);
            assert_eq!(
                remote.native_reads.lock().unwrap().vault_get_count,
                gets + usize::from(upload_edit)
            );
            let retained_after_lock = verified
                .custody
                .inspect_capture_for_test(&scope, "/Travel.vault")
                .unwrap();
            assert_eq!(retained_after_lock.captures.len(), 1);
            assert_eq!(
                retained_after_lock.captures[0].0.bytes_for_recovery(),
                edited.as_slice()
            );
            assert!(
                broker.stop_all().is_err(),
                "dirty native namespace remains retained on stop"
            );
            if automatic {
                runtime.stop_fresh_close_worker().unwrap();
            }
            drop(root_pin);
            drop(verified);
            drop(broker);
            drop(runtime);
            drop(sessions);
            remote.join().unwrap();
            appdata_pin.verify_path().unwrap();
            if automatic {
                println!(
                    "C06_VAULT_FRESH_CLOSE_AUTO_UPLOAD_DIRTY_FIXTURE_RETAINED=true;ordinaryPUT=0;cleanup=incomplete;no_native_completion=true"
                );
            } else if upload_edit {
                println!(
                    "C06_VAULT_EXPLICIT_UPLOAD_DIRTY_FIXTURE_RETAINED=true;ordinaryPUT=0;cleanup=incomplete"
                );
            } else {
                println!(
                    "C06_VAULT_MODIFIED_CLOSE_INDEXED_CAPTURE_VERIFIED=true;ordinary_journal=0;PUT=0;cleanup=incomplete;dirty_fixture_retained=true"
                );
            }
            return;
        }
        let forgotten = broker.handle_isolated_lifecycle_session(json!({"action":"vault_forget",
            "profile_id":profile,"space_id":"synthetic-personal-drive","root_resource_id":"synthetic-vault-root"})).unwrap().0;
        assert_eq!(forgotten["forgotten"], true);
        assert_eq!(forgotten["remembered_status"], "not_saved");
        assert!(
            sessions.is_unlocked(&scope).unwrap(),
            "Forget does not lock"
        );
        let readiness_path = "/Travel.vault";
        runtime
            .confirm_windows_vault_readiness(&scope, readiness_path)
            .unwrap();
        let account = runtime.provider.bandwidth.scope().unwrap().unwrap();
        let remembered = windows_vault_credentials::Scope::from_trusted_account(
            &profile,
            account.bytes(),
            &scope,
        )
        .unwrap();
        assert!(
            !windows_vault_credentials::contains_saved(
                &VaultCredentialStore {
                    store: runtime.session_store.as_ref(),
                    profile: &profile,
                },
                &remembered
            )
            .unwrap()
        );
        let mut lock = target();
        lock["action"] = json!("vault_lock");
        assert_eq!(
            broker.handle_isolated_lifecycle_session(lock).unwrap().0["unlocked"],
            false
        );
        assert!(!sessions.is_unlocked(&scope).unwrap());
        assert!(
            runtime
                .confirm_windows_vault_readiness(&scope, "/Travel.vault")
                .is_err()
        );
        if payload {
            let file = drive.join("Personal/Travel.vault/1");
            let metadata = std::fs::metadata(&file).unwrap();
            assert_eq!(metadata.len(), 65537);
            assert!(metadata.permissions().readonly());
            let gets = remote.native_reads.lock().unwrap().vault_get_count;
            use sha2::Digest as _;
            let expected = (0..65537).map(|i| (i * 31 + 7) as u8).collect::<Vec<_>>();
            let hash = format!("{:x}", sha2::Sha256::digest(&expected));
            // Successful actual Lock already requires the native ONDISK-empty
            // postproof. This one ordinary read must fail; it is never an
            // explicit hydrate/retry, and cannot contact the retired route.
            assert!(
                !broker_vault_read_in_child(&file, expected.len(), &hash).unwrap(),
                "Locked vault must refuse the single external read"
            );
            assert_eq!(
                remote.native_reads.lock().unwrap().vault_get_count,
                gets,
                "post-Lock refusal cannot download ciphertext"
            );
            println!("C06_PAYLOAD_LOCK_AND_READ_REFUSAL=true");
            // A new adapter assigns new callback identities. Reopen the same
            // retained native file through a new exact route, without saving
            // the public password again after Forget.
            let mut manual = target();
            manual["action"] = json!("vault_unlock");
            manual["password"] = json!("potato"); // public fixture only
            manual["remember"] = json!(false);
            let reopened = broker.handle_isolated_lifecycle_session(manual).unwrap().0;
            assert_eq!(reopened["unlocked"], true);
            assert_eq!(reopened["remembered_status"], "unknown");
            assert_eq!(reopened["remembered"], false);
            assert!(sessions.is_unlocked(&scope).unwrap());
            let personal = drive.join("Personal");
            assert!(
                child_process_directory_matches(&personal, &["Travel.vault"])
                    .unwrap()
                    .matches_expected
            );
            assert!(
                child_process_directory_matches(&personal.join("Travel.vault"), &["1"])
                    .unwrap()
                    .matches_expected
            );
            assert!(
                broker_vault_read_in_child(&file, expected.len(), &hash).unwrap(),
                "Manual reopen must serve the same verified public fixture bytes"
            );
            let reopened_gets = remote.native_reads.lock().unwrap().vault_get_count;
            assert!(
                reopened_gets > gets && reopened_gets <= 32,
                "new route must perform a bounded ciphertext download"
            );
            let mut lock = target();
            lock["action"] = json!("vault_lock");
            assert_eq!(
                broker.handle_isolated_lifecycle_session(lock).unwrap().0["unlocked"],
                false
            );
            assert!(!sessions.is_unlocked(&scope).unwrap());
            assert!(
                runtime
                    .confirm_windows_vault_readiness(&scope, "/Travel.vault")
                    .is_err()
            );
            assert!(
                !windows_vault_credentials::contains_saved(
                    &VaultCredentialStore {
                        store: runtime.session_store.as_ref(),
                        profile: &profile,
                    },
                    &remembered
                )
                .unwrap(),
                "Manual reopen cannot restore forgotten credentials"
            );
            assert_eq!(remote.recovery.lock().unwrap().put_count, 0);
            println!("C06_PAYLOAD_MANUAL_REOPEN_AND_SECOND_LOCK=true");
        }
        assert_eq!(remote.recovery.lock().unwrap().put_count, 0);
        broker.stop_all().unwrap();
        drop(broker);
        drop(runtime);
        drop(sessions);
        if payload {
            // New Agent/coordinator/native connection, same protected profile and
            // retained root. This is not an OS-process restart or crash test.
            let registry_bytes = storage.load_profile_registry().unwrap();
            assert!(registry_bytes.is_some());
            let restored_registry =
                windows_profile_registry::Registry::decode_or_default(registry_bytes.as_deref())
                    .unwrap();
            let admissions = Arc::new(Mutex::new(Arc::new(restored_registry.clone())));
            let restarted_sessions = Arc::new(raiun_vault::session::VaultSessionCoordinator::new());
            let restarted = Arc::new(
                WindowsAgent::new_for_profile_with_services(
                    &profile,
                    DpapiStore::for_profile(&profile).unwrap(),
                    Some(admissions),
                    restarted_sessions.clone(),
                )
                .unwrap(),
            );
            let generation = restarted.generation.load(Ordering::Acquire);
            {
                let mut state = restarted.state.lock().unwrap();
                state.active_generation = generation;
                state.online_authenticated = true;
                state.needs_refresh = false;
            }
            restarted.provider.authorize_generation(generation);
            WindowsAgent::connect_verified_root_with_exclusions(
                &restarted.session_store,
                &restarted.state,
                &restarted.provider,
                restarted.source_admissions.as_ref(),
            )
            .unwrap();
            assert!(!restarted_sessions.is_unlocked(&scope).unwrap());
            assert!(
                restarted
                    .confirm_windows_vault_readiness(&scope, "/Travel.vault")
                    .is_err()
            );
            let account = restarted.provider.bandwidth.scope().unwrap().unwrap();
            let remembered = windows_vault_credentials::Scope::from_trusted_account(
                &profile,
                account.bytes(),
                &scope,
            )
            .unwrap();
            assert!(
                !windows_vault_credentials::contains_saved(
                    &VaultCredentialStore {
                        store: restarted.session_store.as_ref(),
                        profile: &profile
                    },
                    &remembered,
                )
                .unwrap()
            );
            let file = drive.join("Personal/Travel.vault/1");
            use sha2::Digest as _;
            let expected = (0..65537).map(|i| (i * 31 + 7) as u8).collect::<Vec<_>>();
            let hash = format!("{:x}", sha2::Sha256::digest(&expected));
            let gets = remote.native_reads.lock().unwrap().vault_get_count;
            assert!(
                !broker_vault_read_in_child(&file, expected.len(), &hash).unwrap(),
                "New locked coordinator must refuse the retained file read"
            );
            assert_eq!(remote.native_reads.lock().unwrap().vault_get_count, gets);
            println!("C06_PAYLOAD_RECONNECT_NO_SECRET_RESTORE=true");
            let restarted_broker =
                windows_profiles::WindowsProfiles::for_isolated_lifecycle_fixture(
                    storage.clone(),
                    restored_registry,
                    restarted.clone(),
                )
                .unwrap();
            let mut manual = target();
            manual["action"] = json!("vault_unlock");
            manual["password"] = json!("potato"); // public fixture only
            manual["remember"] = json!(false);
            let unlocked = restarted_broker
                .handle_isolated_lifecycle_session(manual)
                .unwrap()
                .0;
            assert_eq!(unlocked["unlocked"], true);
            assert_eq!(unlocked["remembered_status"], "unknown");
            assert_eq!(unlocked["remembered"], false);
            assert!(restarted_sessions.is_unlocked(&scope).unwrap());
            assert!(
                child_process_directory_matches(&drive.join("Personal"), &["Travel.vault"])
                    .unwrap()
                    .matches_expected
            );
            assert!(
                child_process_directory_matches(&drive.join("Personal/Travel.vault"), &["1"])
                    .unwrap()
                    .matches_expected
            );
            assert!(
                broker_vault_read_in_child(&file, expected.len(), &hash).unwrap(),
                "Reconnected route must serve verified public fixture bytes"
            );
            let reopened_gets = remote.native_reads.lock().unwrap().vault_get_count;
            assert!(
                reopened_gets > gets && reopened_gets <= gets + 16,
                "Reconnected route performs bounded ciphertext downloads"
            );
            let mut lock = target();
            lock["action"] = json!("vault_lock");
            assert_eq!(
                restarted_broker
                    .handle_isolated_lifecycle_session(lock)
                    .unwrap()
                    .0["unlocked"],
                false
            );
            assert!(!restarted_sessions.is_unlocked(&scope).unwrap());
            assert!(
                restarted
                    .confirm_windows_vault_readiness(&scope, "/Travel.vault")
                    .is_err()
            );
            assert!(
                !windows_vault_credentials::contains_saved(
                    &VaultCredentialStore {
                        store: restarted.session_store.as_ref(),
                        profile: &profile
                    },
                    &remembered,
                )
                .unwrap()
            );
            assert_eq!(remote.recovery.lock().unwrap().put_count, 0);
            println!("C06_PAYLOAD_RECONNECT_READ_AND_LOCK=true");
            restarted_broker.stop_all().unwrap();
            drop(restarted_broker);
            drop(restarted);
            drop(restarted_sessions);
        }
        remote.join().unwrap();
        appdata_pin.verify_path().unwrap();
        // Registered native namespace and private fixture evidence deliberately
        // remain owned here after normal disconnect; no force/unregister/delete.
        eprintln!("synthetic_c06_broker_lifecycle=passed;fixture_retained=true");
    }

    #[cfg(all(windows, debug_assertions))]
    #[test]
    #[ignore = "requires disposable Windows VM with Cloud Files and current-user DPAPI"]
    fn native_recovery_gui_pipe_fixture_preserves_journal_until_graceful_quit() {
        use raiun_cloudfiles_windows::EditRecoveryProvider as _;
        let (server, fixture) = synthetic_personal_spaces_server_with_native_read_files(|_| {});
        let store = Arc::new(MemoryStore::default());
        let session = synthetic_session(&server, "synthetic-client", unix_time_now() + 3600);
        seed_active_session(&store, "default", session.clone());
        let agent = Arc::new(WindowsAgent::new(store));
        let generation = agent.generation.load(Ordering::Acquire);
        {
            let mut state = agent.state.lock().unwrap();
            state.active_generation = generation;
            state.online_authenticated = true;
            state.needs_refresh = false;
        }
        agent.provider.authorize_generation(generation);
        let root = std::env::temp_dir().join(format!(
            "Raiun-Recovery-Gui-{}-{}",
            std::process::id(),
            unix_time_now()
        ));
        std::fs::create_dir(&root).expect("create fresh synthetic recovery root");
        agent
            .configure_root(
                &json!({"action":"configure_root", "cloud_root":root.to_str().unwrap()}),
            )
            .expect("configure only the fresh synthetic root");
        WindowsAgent::connect_verified_root(&agent.session_store, &agent.state, &agent.provider)
            .expect("test explicitly exercises the gated production preflight");
        let verified = agent
            .prepare_recovery_context()
            .expect("verify native recovery scope");
        let owner = verified
            .configuration
            .registration_ownership
            .as_ref()
            .unwrap();
        let body = b"Raiun native metadata discovery retained synthetic bytes";
        let prepared = verified
            .recovery_provider
            .prepare(&verified.provider_scope, verified.local_root_identity)
            .unwrap();
        prepared
            .append_edit(
                &raiun_cloudfiles_windows::PlaceholderEditBinding {
                    profile_id: "default".into(),
                    server_origin: verified.provider_scope.server_origin().into(),
                    account_subject: verified.provider_scope.account_id().into(),
                    account_generation: verified.provider_scope.token_generation(),
                    space_id: owner.personal_drive_id.clone(),
                    root_resource_id: owner.personal_root_resource_id.clone().unwrap(),
                    remote_resource_id: "synthetic-discovery-file".into(),
                    virtual_path: "/saved-edit.txt".into(),
                    base_etag: "\"synthetic-discovery-v1\"".into(),
                    base_size: body.len() as u64,
                },
                verified.local_root_identity,
                raiun_cloudfiles_windows::LocalFileIdentity {
                    volume_serial: verified.local_root_identity.volume_serial,
                    file_index: verified.local_root_identity.file_index.wrapping_add(1),
                },
                "Personal/saved-edit.txt",
                body,
            )
            .expect("retain a synthetic DPAPI journal body");
        let before = verified.recovery_provider.unresolved_edits().unwrap();
        assert_eq!(before.len(), 1);
        let expected_scope = agent.status().unwrap()["root_configuration"]["recovery_scope_token"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(
            agent
                .handle_request(&json!({"action":"windows_recovery_list",
            "expected_generation":generation, "expected_recovery_scope_token":"0".repeat(64)}))
                .is_err()
        );
        let result = agent
            .handle_request(&json!({"action":"windows_recovery_list",
            "profile_id":"default", "expected_generation":generation,
            "expected_recovery_scope_token":expected_scope, "limit":1}))
            .unwrap()
            .0;
        assert_eq!(result["read_only"], true);
        assert_eq!(result["recovery_scope_token"], expected_scope);
        assert_eq!(result["items"].as_array().unwrap().len(), 1);
        assert_eq!(result["items"][0]["record_id"], before[0].record_id);
        assert_eq!(result["items"][0]["generation"], before[0].generation);
        assert_eq!(result["items"][0]["path"], "Personal/saved-edit.txt");
        assert_eq!(result["items"][0]["state"], "needs_review");
        assert_eq!(
            verified.recovery_provider.unresolved_edits().unwrap(),
            before
        );
        assert_eq!(
            fixture.recovery.lock().unwrap().put_count,
            0,
            "listing cannot dispatch an upload"
        );
        assert!(
            agent
                .handle_request(&json!({"action":"windows_recovery_list",
            "expected_generation":generation.wrapping_add(1)}))
                .is_err()
        );
        assert!(
            agent
                .handle_request(&json!({"action":"windows_recovery_list",
            "profile_id":"other", "expected_generation":generation}))
                .is_err()
        );

        drop(prepared);
        let scope = verified.provider_scope.clone();
        let root_identity = verified.local_root_identity;
        let protector = raiun_cloudfiles_windows::DpapiEditRecordProtector::current_user()
            .expect("initialize current-user DPAPI snapshot scope");
        let journal_root = protector
            .local_state_directory()
            .join("cloud-files-edit-journal-v1");
        let journal_before = snapshot_gui_fixture_journal(&journal_root)
            .expect("bounded snapshot of the protected journal after fixture seeding");
        drop(verified);

        let (server_tx, server_rx) = mpsc::channel();
        let server_agent = Arc::clone(&agent);
        let server_thread = thread::spawn(move || {
            let _ = server_tx.send(super::serve_agent(server_agent));
        });

        let ready_deadline = Instant::now() + Duration::from_secs(30);
        let mut status = None;
        while Instant::now() < ready_deadline {
            match server_rx.try_recv() {
                Ok(Ok(())) => panic!("fixture server stopped before readiness"),
                Ok(Err(_)) => panic!("fixture server failed before readiness"),
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => {
                    panic!("fixture server exited before reporting its result")
                }
            }
            if let Ok(value) = gui_fixture_pipe_request(&json!({"action":"status"})) {
                let root_config = &value["root_configuration"];
                if value["connected"] == true
                    && value["provider_supported"] == false
                    && value["server"].as_str() == Some(server.as_str())
                    && value["cloud_root"] == root.to_string_lossy().as_ref()
                    && root_config["identity_bound"] == true
                    && root_config["registration_state"] == "registered"
                    && value["auth_generation"].as_u64() == Some(generation)
                {
                    status = Some(value);
                    break;
                }
            }
            thread::sleep(Duration::from_millis(100));
        }
        let status = status.expect("real current-user framed status proves listener ownership");
        let scope_token = status["root_configuration"]["recovery_scope_token"]
            .as_str()
            .expect("agent returned an opaque recovery scope token");
        let listed = gui_fixture_pipe_request(&json!({
            "action":"windows_recovery_list",
            "profile_id":"default",
            "expected_generation":generation,
            "expected_recovery_scope_token":scope_token,
            "limit":1
        }))
        .expect("real current-user framed recovery-list request");
        assert_eq!(listed["read_only"], true);
        assert_eq!(listed["items"].as_array().unwrap().len(), 1);
        assert_eq!(listed["items"][0]["path"], "Personal/saved-edit.txt");
        assert_eq!(listed["items"][0]["state"], "needs_review");
        println!("RaiunWindowsRecoveryGuiFixtureReady=1");

        let shutdown_result = match server_rx.recv_timeout(Duration::from_secs(10 * 60)) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let _ = gui_fixture_pipe_request(&json!({"action":"shutdown"}));
                let _ = server_rx.recv_timeout(Duration::from_secs(10));
                panic!("bounded Windows recovery GUI fixture session timed out; state preserved");
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!("fixture server exited without reporting graceful shutdown")
            }
        };
        shutdown_result.expect("normal shell Quit shuts down the shared fixture server cleanly");
        server_thread
            .join()
            .expect("fixture listener thread exits after graceful shutdown");

        let after = raiun_cloudfiles_windows::DurableEditRecoveryProvider::current_user(
            scope,
            root_identity,
        )
        .expect("reopen the same current-user recovery scope after shell shutdown")
        .unresolved_edits()
        .expect("reopen the protected recovery journal after shell shutdown");
        assert_eq!(
            after, before,
            "GUI refresh and quit must retain the recovery record"
        );
        let journal_after = snapshot_gui_fixture_journal(&journal_root)
            .expect("bounded snapshot of the protected journal after shell shutdown");
        assert_eq!(
            journal_after, journal_before,
            "GUI list/refresh did not mutate journal bytes"
        );
        assert_eq!(
            fixture.recovery.lock().unwrap().put_count,
            0,
            "read-only GUI acceptance did not upload"
        );
        assert!(root.join("Personal").exists() && root.join("Spaces").exists());
        fixture.join().expect("close synthetic fixture");
    }

    #[cfg(all(windows, debug_assertions))]
    fn gui_fixture_pipe_request(request: &Value) -> Result<Value, String> {
        let mut stream = super::connect_current_user(Duration::from_secs(5))
            .map_err(|_| "current-user fixture pipe was unavailable".to_owned())?;
        super::write_json_line(&mut stream, request)?;
        let response: Value = super::read_json_value(&mut stream)?;
        if response.get("ok").and_then(Value::as_bool) != Some(true) {
            return Err("current-user agent rejected the fixture request".into());
        }
        response
            .get("data")
            .cloned()
            .ok_or_else(|| "current-user agent returned no fixture data".into())
    }

    #[cfg(all(windows, debug_assertions))]
    fn snapshot_gui_fixture_journal(
        journal_root: &Path,
    ) -> Result<std::collections::BTreeMap<PathBuf, (u64, String)>, String> {
        fn walk(
            root: &Path,
            path: &Path,
            files: &mut std::collections::BTreeMap<PathBuf, (u64, String)>,
            total_bytes: &mut u64,
            entries: &mut usize,
        ) -> Result<(), String> {
            use sha2::Digest as _;
            use std::io::Read as _;
            use std::os::windows::fs::MetadataExt as _;

            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
            const MAX_ENTRIES: usize = 20_000;
            const MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
            const MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;

            *entries = entries
                .checked_add(1)
                .filter(|count| *count <= MAX_ENTRIES)
                .ok_or_else(|| "fixture journal exceeds the bounded snapshot limit".to_owned())?;
            let metadata = std::fs::symlink_metadata(path)
                .map_err(|_| "could not inspect fixture journal entry".to_owned())?;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err("fixture journal contains a reparse point".into());
            }
            if metadata.is_dir() {
                files.insert(
                    path.strip_prefix(root)
                        .map_err(|_| "fixture journal entry escaped its root".to_owned())?
                        .to_path_buf(),
                    (0, "directory".into()),
                );
                for entry in std::fs::read_dir(path)
                    .map_err(|_| "could not enumerate fixture journal".to_owned())?
                {
                    let entry =
                        entry.map_err(|_| "could not read fixture journal entry".to_owned())?;
                    walk(root, &entry.path(), files, total_bytes, entries)?;
                }
                return Ok(());
            }
            if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES {
                return Err("fixture journal exceeds the bounded snapshot limit".into());
            }
            *total_bytes = total_bytes
                .checked_add(metadata.len())
                .filter(|total| *total <= MAX_TOTAL_BYTES)
                .ok_or_else(|| "fixture journal exceeds the bounded snapshot limit".to_owned())?;
            let mut file = std::fs::File::open(path)
                .map_err(|_| "could not read fixture journal file".to_owned())?;
            let mut hasher = sha2::Sha256::new();
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let read = file
                    .read(&mut buffer)
                    .map_err(|_| "could not hash fixture journal file".to_owned())?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
            }
            files.insert(
                path.strip_prefix(root)
                    .map_err(|_| "fixture journal entry escaped its root".to_owned())?
                    .to_path_buf(),
                (metadata.len(), format!("{:x}", hasher.finalize())),
            );
            Ok(())
        }

        let mut files = std::collections::BTreeMap::new();
        let mut total_bytes = 0;
        let mut entries = 0;
        walk(
            journal_root,
            journal_root,
            &mut files,
            &mut total_bytes,
            &mut entries,
        )?;
        Ok(files)
    }

    #[cfg(all(windows, debug_assertions))]
    struct SyntheticAgentRecoveryProvider {
        scope: raiun_cloudfiles_windows::ProviderScope,
        root: raiun_cloudfiles_windows::ConfiguredRootIdentity,
        state_directory: PathBuf,
        protector: raiun_cloudfiles_windows::DpapiEditRecordProtector,
    }

    #[cfg(all(windows, debug_assertions))]
    struct SyntheticAgentRecovery {
        scope: raiun_cloudfiles_windows::ProviderScope,
        root: raiun_cloudfiles_windows::ConfiguredRootIdentity,
        state_directory: PathBuf,
        protector: raiun_cloudfiles_windows::DpapiEditRecordProtector,
        journal_scopes: Mutex<Vec<raiun_cloudfiles_windows::EditJournalScope>>,
    }

    #[cfg(all(windows, debug_assertions))]
    impl raiun_cloudfiles_windows::EditRecoveryProvider for SyntheticAgentRecoveryProvider {
        fn prepare(
            &self,
            provider_scope: &raiun_cloudfiles_windows::ProviderScope,
            root_identity: raiun_cloudfiles_windows::ConfiguredRootIdentity,
        ) -> Result<
            Arc<dyn raiun_cloudfiles_windows::PreparedEditRecovery>,
            raiun_cloudfiles_windows::BackendError,
        > {
            use raiun_cloudfiles_windows::{EditJournal, EditJournalScope};

            if provider_scope != &self.scope || root_identity != self.root {
                return Err(raiun_cloudfiles_windows::BackendError::Unavailable);
            }
            // This root-level journal scope is used only to preflight DPAPI,
            // private ACLs, and writable durable storage before CfConnect.
            // Actual records carry the exact Space/root IDs from their
            // authenticated backend binding.
            let preflight_scope = EditJournalScope {
                profile_id: self.scope.profile_id().to_owned(),
                server_origin: self.scope.server_origin().to_owned(),
                account_subject: self.scope.account_id().to_owned(),
                space_id: "__configured_root_preflight__".into(),
                root_resource_id: format!(
                    "{:08x}:{:016x}",
                    self.root.volume_serial, self.root.file_index
                ),
                root_volume_serial: self.root.volume_serial,
                root_file_index: self.root.file_index,
            };
            let journal = EditJournal::open(
                &self.state_directory,
                preflight_scope.clone(),
                self.protector.clone(),
            )
            .map_err(|_| raiun_cloudfiles_windows::BackendError::Unavailable)?;
            journal
                .recover_all()
                .map_err(|_| raiun_cloudfiles_windows::BackendError::Unavailable)?;
            Ok(Arc::new(SyntheticAgentRecovery {
                scope: self.scope.clone(),
                root: self.root,
                state_directory: self.state_directory.clone(),
                protector: self.protector.clone(),
                journal_scopes: Mutex::new(vec![preflight_scope]),
            }))
        }
    }

    #[cfg(all(windows, debug_assertions))]
    impl raiun_cloudfiles_windows::PreparedEditRecovery for SyntheticAgentRecovery {
        fn provider_scope(&self) -> &raiun_cloudfiles_windows::ProviderScope {
            &self.scope
        }

        fn root_identity(&self) -> raiun_cloudfiles_windows::ConfiguredRootIdentity {
            self.root
        }

        fn append_edit(
            &self,
            binding: &raiun_cloudfiles_windows::PlaceholderEditBinding,
            root_identity: raiun_cloudfiles_windows::ConfiguredRootIdentity,
            local_file: raiun_cloudfiles_windows::LocalFileIdentity,
            relative_path: &str,
            content: &[u8],
        ) -> Result<(), raiun_cloudfiles_windows::BackendError> {
            use raiun_cloudfiles_windows::{EditJournal, EditJournalScope, RemoteEditBaseline};

            if root_identity != self.root
                || binding.profile_id != self.scope.profile_id()
                || binding.server_origin != self.scope.server_origin()
                || binding.account_subject != self.scope.account_id()
                || binding.account_generation != self.scope.token_generation()
            {
                return Err(raiun_cloudfiles_windows::BackendError::Unavailable);
            }
            let journal_scope = EditJournalScope {
                profile_id: binding.profile_id.clone(),
                server_origin: binding.server_origin.clone(),
                account_subject: binding.account_subject.clone(),
                space_id: binding.space_id.clone(),
                root_resource_id: binding.root_resource_id.clone(),
                root_volume_serial: root_identity.volume_serial,
                root_file_index: root_identity.file_index,
            };
            let journal = EditJournal::open(
                &self.state_directory,
                journal_scope.clone(),
                self.protector.clone(),
            )
            .map_err(|_| raiun_cloudfiles_windows::BackendError::Unavailable)?;
            journal
                .append_edit(
                    binding.account_generation,
                    local_file,
                    relative_path,
                    Some(RemoteEditBaseline {
                        resource_id: binding.remote_resource_id.clone(),
                        etag: binding.base_etag.clone(),
                        byte_len: binding.base_size,
                    }),
                    content,
                )
                .map_err(|_| raiun_cloudfiles_windows::BackendError::Unavailable)?;
            let mut scopes = self
                .journal_scopes
                .lock()
                .map_err(|_| raiun_cloudfiles_windows::BackendError::Unavailable)?;
            if !scopes.contains(&journal_scope) {
                scopes.push(journal_scope);
            }
            Ok(())
        }

        fn has_unresolved(&self) -> Result<bool, raiun_cloudfiles_windows::BackendError> {
            use raiun_cloudfiles_windows::EditJournal;

            let scopes = self
                .journal_scopes
                .lock()
                .map_err(|_| raiun_cloudfiles_windows::BackendError::Unavailable)?
                .clone();
            for scope in scopes {
                let journal =
                    EditJournal::open(&self.state_directory, scope, self.protector.clone())
                        .map_err(|_| raiun_cloudfiles_windows::BackendError::Unavailable)?;
                let snapshot = journal
                    .recover_all()
                    .map_err(|_| raiun_cloudfiles_windows::BackendError::Unavailable)?;
                if snapshot.incomplete_staging_files != 0 || !snapshot.records.is_empty() {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }

    struct PublicationGate {
        reached: mpsc::Sender<()>,
        release: Mutex<mpsc::Receiver<()>>,
    }

    type MemoryBandwidthSettings = HashMap<(String, Vec<u8>), Vec<u8>>;

    #[derive(Default)]
    pub(super) struct MemoryStore {
        sessions: Mutex<HashMap<(String, String, String), auth::Session>>,
        root_configs: Mutex<HashMap<(String, String, String), Vec<u8>>>,
        bandwidth_settings: Mutex<MemoryBandwidthSettings>,
        proxy_settings: Mutex<HashMap<String, Vec<u8>>>,
        active_identity: Mutex<Option<(String, String, String)>>,
        fail_saves: Mutex<bool>,
        fail_removes: Mutex<bool>,
        fail_root_config_removes: Mutex<bool>,
        fail_revokes: Mutex<bool>,
        publication_gate: Mutex<Option<Arc<PublicationGate>>>,
    }

    pub(super) fn synthetic_profile_runtime(
        profile: &str,
        source_admissions: Option<super::SharedSourceAdmissions>,
        vault_sessions: Arc<raiun_vault::session::VaultSessionCoordinator>,
    ) -> (Arc<WindowsAgent>, Arc<MemoryStore>) {
        let store = Arc::new(MemoryStore::default());
        let runtime = Arc::new(
            WindowsAgent::new_for_profile_with_services(
                profile,
                store.clone(),
                source_admissions,
                vault_sessions,
            )
            .expect("create synthetic account runtime"),
        );
        runtime
            .attach_existing_file_save_owner()
            .expect("attach synthetic account runtime");
        (runtime, store)
    }

    pub(super) fn set_synthetic_revoke_failure(store: &MemoryStore, fail: bool) {
        *store.fail_revokes.lock().expect("synthetic store lock") = fail;
    }

    impl SessionStore for MemoryStore {
        fn load_proxy_settings(&self, profile: &str) -> Result<Option<Vec<u8>>, String> {
            Ok(self.proxy_settings.lock().unwrap().get(profile).cloned())
        }
        fn compare_exchange_proxy_settings(
            &self,
            profile: &str,
            old: Option<&[u8]>,
            next: &[u8],
        ) -> Result<(), String> {
            let mut records = self.proxy_settings.lock().unwrap();
            if records.get(profile).map(Vec::as_slice) != old {
                return Err("synthetic stale proxy settings".into());
            }
            records.insert(profile.into(), next.to_vec());
            Ok(())
        }

        fn load_bandwidth_settings(
            &self,
            profile: &str,
            scope: &[u8],
        ) -> Result<Option<Vec<u8>>, String> {
            Ok(self
                .bandwidth_settings
                .lock()
                .unwrap()
                .get(&(profile.into(), scope.to_vec()))
                .cloned())
        }
        fn compare_exchange_bandwidth_settings(
            &self,
            profile: &str,
            scope: &[u8],
            old: Option<&[u8]>,
            next: &[u8],
        ) -> Result<(), String> {
            let mut settings = self.bandwidth_settings.lock().unwrap();
            let key = (profile.into(), scope.to_vec());
            if settings.get(&key).map(Vec::as_slice) != old {
                return Err("synthetic stale settings".into());
            }
            settings.insert(key, next.to_vec());
            Ok(())
        }

        fn save_pending(&self, scope: &str, session: &auth::Session) -> Result<(), String> {
            if *self.fail_saves.lock().unwrap() {
                return Err("synthetic protected storage failure".into());
            }
            self.sessions.lock().unwrap().insert(
                (
                    scope.to_owned(),
                    session.server.clone(),
                    session.client_id.clone(),
                ),
                session.clone(),
            );
            Ok(())
        }

        fn publish_active(&self, scope: &str, session: &auth::Session) -> Result<(), String> {
            *self.active_identity.lock().unwrap() = Some((
                scope.to_owned(),
                session.server.clone(),
                session.client_id.clone(),
            ));
            Ok(())
        }

        fn load_active(&self, expected_scope: &str) -> Result<Option<auth::Session>, String> {
            let Some((scope, server, client_id)) = self.active_identity.lock().unwrap().clone()
            else {
                return Ok(None);
            };
            if scope != expected_scope {
                return Err("synthetic profile mismatch".into());
            }
            self.sessions
                .lock()
                .unwrap()
                .get(&(scope, server, client_id))
                .cloned()
                .map(Some)
                .ok_or_else(|| "synthetic active session is missing".into())
        }

        fn revoke_active(&self) -> Result<Option<(String, String, String)>, String> {
            if *self.fail_revokes.lock().unwrap() {
                return Err("synthetic active pointer revocation failure".into());
            }
            Ok(self.active_identity.lock().unwrap().take())
        }

        fn remove(&self, scope: &str, server: &str, client_id: &str) -> Result<(), String> {
            if *self.fail_removes.lock().unwrap() {
                return Err("synthetic protected storage cleanup failure".into());
            }
            self.sessions.lock().unwrap().remove(&(
                scope.to_owned(),
                server.to_owned(),
                client_id.to_owned(),
            ));
            Ok(())
        }

        fn save_root_config(
            &self,
            scope: &str,
            server: &str,
            client_id: &str,
            bytes: &[u8],
        ) -> Result<(), String> {
            self.root_configs.lock().unwrap().insert(
                (scope.to_owned(), server.to_owned(), client_id.to_owned()),
                bytes.to_vec(),
            );
            Ok(())
        }

        fn load_root_config(
            &self,
            scope: &str,
            server: &str,
            client_id: &str,
        ) -> Result<Option<Vec<u8>>, String> {
            Ok(self
                .root_configs
                .lock()
                .unwrap()
                .get(&(scope.to_owned(), server.to_owned(), client_id.to_owned()))
                .cloned())
        }

        fn remove_root_config(
            &self,
            scope: &str,
            server: &str,
            client_id: &str,
        ) -> Result<(), String> {
            if *self.fail_root_config_removes.lock().unwrap() {
                return Err("synthetic root configuration cleanup failure".into());
            }
            self.root_configs.lock().unwrap().remove(&(
                scope.to_owned(),
                server.to_owned(),
                client_id.to_owned(),
            ));
            Ok(())
        }

        fn before_publish(&self) {
            let gate = self.publication_gate.lock().unwrap().clone();
            if let Some(gate) = gate {
                gate.reached.send(()).unwrap();
                gate.release.lock().unwrap().recv().unwrap();
            }
        }
    }

    impl SessionStore for Arc<MemoryStore> {
        fn load_proxy_settings(&self, profile: &str) -> Result<Option<Vec<u8>>, String> {
            self.as_ref().load_proxy_settings(profile)
        }
        fn compare_exchange_proxy_settings(
            &self,
            profile: &str,
            old: Option<&[u8]>,
            next: &[u8],
        ) -> Result<(), String> {
            self.as_ref()
                .compare_exchange_proxy_settings(profile, old, next)
        }

        fn load_bandwidth_settings(
            &self,
            profile: &str,
            scope: &[u8],
        ) -> Result<Option<Vec<u8>>, String> {
            self.as_ref().load_bandwidth_settings(profile, scope)
        }
        fn compare_exchange_bandwidth_settings(
            &self,
            profile: &str,
            scope: &[u8],
            old: Option<&[u8]>,
            next: &[u8],
        ) -> Result<(), String> {
            self.as_ref()
                .compare_exchange_bandwidth_settings(profile, scope, old, next)
        }

        fn save_pending(&self, scope: &str, session: &auth::Session) -> Result<(), String> {
            self.as_ref().save_pending(scope, session)
        }

        fn publish_active(&self, scope: &str, session: &auth::Session) -> Result<(), String> {
            self.as_ref().publish_active(scope, session)
        }

        fn load_active(&self, expected_scope: &str) -> Result<Option<auth::Session>, String> {
            self.as_ref().load_active(expected_scope)
        }

        fn revoke_active(&self) -> Result<Option<(String, String, String)>, String> {
            self.as_ref().revoke_active()
        }

        fn remove(&self, scope: &str, server: &str, client_id: &str) -> Result<(), String> {
            self.as_ref().remove(scope, server, client_id)
        }

        fn save_root_config(
            &self,
            scope: &str,
            server: &str,
            client_id: &str,
            bytes: &[u8],
        ) -> Result<(), String> {
            self.as_ref()
                .save_root_config(scope, server, client_id, bytes)
        }

        fn load_root_config(
            &self,
            scope: &str,
            server: &str,
            client_id: &str,
        ) -> Result<Option<Vec<u8>>, String> {
            self.as_ref().load_root_config(scope, server, client_id)
        }

        fn remove_root_config(
            &self,
            scope: &str,
            server: &str,
            client_id: &str,
        ) -> Result<(), String> {
            self.as_ref().remove_root_config(scope, server, client_id)
        }

        fn before_publish(&self) {
            self.as_ref().before_publish();
        }
    }

    #[test]
    fn private_root_overlap_is_case_insensitive_and_component_bounded() {
        assert!(windows_paths_overlap(
            r"C:\Users\Test\AppData\Local\Raiun",
            r"c:\users\test\appdata\local\RAIUN\sessions"
        ));
        assert!(windows_paths_overlap(
            r"C:\Users\Test\AppData\Local",
            r"C:\Users\Test\AppData\Local\Raiun\sessions"
        ));
        assert!(!windows_paths_overlap(
            r"C:\Users\Test\AppData\Local\RaiunDrive",
            r"C:\Users\Test\AppData\Local\Raiun"
        ));
        assert!(!windows_paths_overlap(
            r"D:\Cloud",
            r"C:\Users\Test\AppData\Local\Raiun"
        ));
    }

    #[test]
    fn selected_root_is_persisted_to_exact_profile_server_client_without_mounting() {
        let store = Arc::new(MemoryStore::default());
        let (server, personal_fixture) = synthetic_personal_spaces_server(|_| {});
        let session = synthetic_session(&server, "synthetic-client", unix_time_now() + 3600);
        seed_active_session(&store, "default", session);
        let agent = Arc::new(WindowsAgent::new(store.clone()));
        {
            let mut state = agent.state.lock().unwrap();
            state.online_authenticated = true;
            state.needs_refresh = false;
        }
        let root = std::env::temp_dir().join(format!(
            "Raiun-Root-Config-Test-{}-{}",
            std::process::id(),
            unix_time_now()
        ));
        std::fs::create_dir(&root).expect("create unique empty synthetic root");
        let root_text = root.to_string_lossy().into_owned();

        let configured = agent
            .handle_request(&json!({"action":"configure","cloud_root":root_text}))
            .expect("configure synthetic root")
            .0;
        assert_eq!(configured["configured"], true);
        assert_eq!(configured["mounted"], false);
        assert_eq!(configured["provider_supported"], false);
        assert_eq!(configured["root_identity_bound"], true);
        assert_eq!(configured["registration_state"], "prepared_not_registered");
        assert_eq!(agent.status().unwrap()["mounted"], false);
        assert!(!agent.provider.is_connected());
        assert_eq!(
            agent.status().unwrap()["root_configuration"]["identity_bound"],
            true
        );

        let persisted = store
            .load_root_config("default", &server, "synthetic-client")
            .unwrap()
            .expect("root config is persisted for this exact session");
        let persisted: Value = serde_json::from_slice(&persisted).unwrap();
        assert_eq!(persisted["version"], 3);
        assert_eq!(
            persisted["registration_ownership"]["state"],
            "prepared_not_registered"
        );
        assert_eq!(
            persisted["registration_ownership"]["account_id"],
            personal_account_identity(&server, "synthetic-personal-drive")
        );
        assert_eq!(
            persisted["registration_ownership"]["personal_drive_id"],
            "synthetic-personal-drive"
        );
        assert_eq!(
            persisted["registration_ownership"]["personal_root_resource_id"],
            "synthetic-personal-root"
        );

        // Until a provider owns this root, a later file is unknown local data
        // and invalidates the configuration instead of being adopted.
        std::fs::write(root.join("synthetic-placeholder"), b"placeholder")
            .expect("add synthetic placeholder-shaped file");
        let restarted = Arc::new(WindowsAgent::new(store.clone()));
        assert_eq!(
            restarted.status().unwrap()["root_configuration"]["valid"],
            false
        );
        assert_eq!(
            restarted.status().unwrap()["root_configuration"]["identity_bound"],
            true
        );
        assert_eq!(restarted.status().unwrap()["mounted"], false);
        assert!(
            store
                .load_root_config("default", &server, "synthetic-client")
                .unwrap()
                .is_some()
        );
        restarted
            .handle_request(&json!({"action":"logout"}))
            .expect("logout clears the account-scoped root choice");
        assert!(
            store
                .load_root_config("default", &server, "synthetic-client")
                .unwrap()
                .is_none()
        );
        assert!(
            root.exists(),
            "logout must preserve the user's local folder"
        );
        assert!(
            root.join("synthetic-placeholder").exists(),
            "logout must not delete local folder contents"
        );

        let child = root.join("synthetic-placeholder");
        std::fs::remove_file(child).expect("remove owned synthetic child");
        std::fs::remove_dir(root).expect("remove owned synthetic root");
        personal_fixture.join().unwrap();
    }

    #[test]
    fn registered_root_ownership_survives_logout_for_exact_reconnect() {
        let store = Arc::new(MemoryStore::default());
        let server = "https://registered-root.synthetic".to_owned();
        let session = synthetic_session(&server, "synthetic-client", unix_time_now() + 3600);
        seed_active_session(&store, "default", session.clone());
        let root = std::env::temp_dir().join(format!(
            "Raiun-Registered-Root-Test-{}-{}",
            std::process::id(),
            unix_time_now()
        ));
        std::fs::create_dir(&root).expect("create unique synthetic root");
        let identity = verify_configured_root_identity(&root).expect("inspect synthetic root");
        let configuration = super::RootConfiguration {
            profile_scope: "default".into(),
            server: session.server.clone(),
            client_id: session.client_id.clone(),
            issuer: session.expected_issuer.clone(),
            path: root.to_string_lossy().into_owned(),
            volume_serial: identity.volume_serial,
            file_index: identity.file_index,
            registration_ownership: Some(RegistrationOwnership {
                state: "registered".into(),
                account_id: personal_account_identity(&session.server, "personal-drive-a"),
                personal_drive_id: "personal-drive-a".into(),
                personal_root_resource_id: Some("personal-root-a".into()),
                volume_serial: identity.volume_serial,
                file_index: identity.file_index,
            }),
            valid: true,
        };
        let bytes = encode_root_configuration(&configuration).unwrap();
        store
            .save_root_config("default", &session.server, &session.client_id, &bytes)
            .unwrap();

        let agent = WindowsAgent::new(store.clone());
        assert_eq!(agent.status().unwrap()["mounted"], false);
        agent
            .logout()
            .expect("logout disconnects but preserves registration ownership");
        assert_eq!(
            store
                .load_root_config("default", &session.server, &session.client_id)
                .unwrap()
                .as_deref(),
            Some(bytes.as_slice())
        );
        assert!(
            root.exists(),
            "logout preserves the registered root directory"
        );
        assert_eq!(agent.status().unwrap()["mounted"], false);
        std::fs::remove_dir(root).expect("remove only the owned empty synthetic root");
    }

    /// End-to-end agent-owned runtime assembly is available only in the
    /// disposable Windows test VM. No IPC action or production startup path
    /// invokes this connection helper.
    #[cfg(all(windows, debug_assertions))]
    #[test]
    #[ignore = "requires disposable Windows VM, Cloud Files, and current-user DPAPI"]
    fn agent_preflights_exact_scope_and_dpapi_before_connect_then_revokes_before_logout() {
        run_prepared_agent_runtime_test(false);
    }

    #[cfg(all(windows, debug_assertions))]
    #[test]
    #[ignore = "requires disposable Windows VM, Cloud Files, and current-user DPAPI"]
    fn initial_save_dispatch_marks_in_sync_and_reopens_clean_journal() {
        run_prepared_agent_runtime_test(true);
    }

    #[cfg(all(windows, debug_assertions))]
    fn run_prepared_agent_runtime_test(automatic_initial_save: bool) {
        use raiun_cloudfiles_windows::{
            CancellationToken, DpapiEditRecordProtector, DurableEditRecoveryProvider, EditJournal,
            EditJournalScope, EditRecordProtector, EditRecoveryProvider,
            OpenCloudPlaceholderBackend, PlaceholderBackend, ProviderScope, RecoveryAttemptState,
            synthetic_agent_integration,
        };
        use raiun_core::backend::CloudBackend;
        use raiun_opencloud::OpenCloudClient;
        use std::sync::atomic::Ordering;

        let emit_stage = |stage: &str| {
            let marker = format!("windows_cfapi_recovery_stage={stage}");
            if let Some(path) = std::env::var_os("RAIUN_SYNTHETIC_CFAPI_STAGE_FILE") {
                if let Ok(mut file) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                {
                    use std::io::Write as _;
                    let _ = writeln!(file, "{marker}");
                    let _ = file.sync_all();
                }
            }
            // The ordinary-user test runner may not provide a stderr handle.
            // Persist the marker first and keep diagnostics best-effort so an
            // unavailable console cannot abort the integration test itself.
            use std::io::Write as _;
            let _ = writeln!(std::io::stderr().lock(), "{marker}");
        };
        let emit_close_observation = |observation: super::NativeCloseObservation| {
            let marker = format!(
                "windows_cfapi_close_observation=modified:{},unverifiable:{},callbacks:{},param_size:{},validation_stage:{},validation_hresult:{:#x},path_prefix_bytes:{},journaled:{}",
                observation.0,
                observation.1,
                observation.2,
                observation.3,
                observation.4,
                observation.5,
                observation.6,
                observation.7,
            );
            if let Some(path) = std::env::var_os("RAIUN_SYNTHETIC_CFAPI_STAGE_FILE") {
                if let Ok(mut file) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                {
                    use std::io::Write as _;
                    let _ = writeln!(file, "{marker}");
                    let _ = file.sync_all();
                }
            }
            use std::io::Write as _;
            let _ = writeln!(std::io::stderr().lock(), "{marker}");
        };
        emit_stage("entry");
        const CLIENT_MODE: &str = "RAIUN_SYNTHETIC_CFAPI_CLIENT_MODE";
        const CLIENT_ROOT: &str = "RAIUN_SYNTHETIC_CFAPI_CLIENT_ROOT";
        if matches!(
            std::env::var(CLIENT_MODE).as_deref(),
            Ok("hydrate-only"
                | "initial-save-only"
                | "edit-only"
                | "edit-race"
                | "edit-after-race"
                | "edit-after-success")
        ) {
            let mode = std::env::var(CLIENT_MODE).expect("client mode remains set");
            let root = PathBuf::from(
                std::env::var_os(CLIENT_ROOT).expect("parent supplies the owned test root"),
            );
            assert_eq!(root.parent(), Some(std::env::temp_dir().as_path()));
            assert!(root.file_name().is_some_and(|name| {
                name.to_string_lossy()
                    .starts_with("Raiun-Agent-Prepared-Runtime-")
            }));
            let spaces = root.join("Spaces");
            let names = std::fs::read_dir(&spaces)
                .expect("client enumerates the Spaces placeholder")
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            assert!(names.iter().any(|name| name == "Projects"));
            let recovery = spaces.join("Projects").join("RecoveryRoot");
            let recovery_names = std::fs::read_dir(&recovery)
                .expect("client enumerates the synthetic recovery directory")
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            assert!(recovery_names.iter().any(|name| name == "document.bin"));
            let file = recovery.join("document.bin");
            let baseline = b"original synthetic placeholder bytes";
            if mode == "hydrate-only" {
                let bytes = std::fs::read(&file)
                    .expect("client hydrates the placeholder through FETCH_DATA");
                assert_eq!(bytes, baseline);
                println!("synthetic_cfapi_client=spaces,projects,recovery,hydrate");
            } else {
                let mut bytes = Vec::with_capacity(baseline.len());
                use std::io::{Seek, SeekFrom, Write};
                let mut edited = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&file)
                    .expect("client opens the hydrated placeholder for writing");
                std::io::Read::read_to_end(&mut edited, &mut bytes)
                    .expect("read baseline through the same edit handle");
                if mode == "edit-after-success" {
                    let mut after_success = baseline.to_vec();
                    after_success[0] ^= 0x5a;
                    assert_eq!(bytes, after_success);
                    bytes[1] ^= 0x33;
                } else if mode != "edit-after-race" {
                    assert_eq!(bytes, baseline);
                    bytes[0] ^= 0x5a;
                } else {
                    let mut after_race = baseline.to_vec();
                    after_race[0] ^= 0x5a;
                    assert_eq!(bytes, after_race);
                    bytes[1] ^= 0x33;
                }
                edited.seek(SeekFrom::Start(0)).expect("seek to file start");
                edited.write_all(&bytes).expect("write synthetic edit");
                edited.sync_all().expect("flush synthetic edit");
                drop(edited);
                if !matches!(mode.as_str(), "edit-race" | "initial-save-only") {
                    assert_eq!(
                        std::fs::read(&file).expect("client reads edited content"),
                        bytes
                    );
                }
                println!("synthetic_cfapi_client=spaces,projects,recovery,write,flush,close");
            }
            return;
        }

        let store = Arc::new(MemoryStore::default());
        emit_stage("fixture_start");
        let (server, personal_fixture) = synthetic_personal_spaces_server(emit_stage);
        emit_stage("fixture_ready");
        emit_stage("session_create_begin");
        let session = synthetic_session(&server, "synthetic-client", unix_time_now() + 3600);
        emit_stage("session_created");
        emit_stage("session_seed_begin");
        seed_active_session(&store, "default", session.clone());
        emit_stage("session_seeded");
        let agent = Arc::new(WindowsAgent::new(store));
        {
            let mut state = agent.state.lock().unwrap();
            state.active_generation = agent.generation.load(Ordering::Acquire);
            state.online_authenticated = true;
            state.needs_refresh = false;
        }
        emit_stage("agent_state_ready");
        emit_stage("root_create_begin");
        let root = std::env::temp_dir().join(format!(
            "Raiun-Agent-Prepared-Runtime-{}-{}",
            std::process::id(),
            unix_time_now()
        ));
        std::fs::create_dir(&root).expect("create fresh synthetic agent root");
        emit_stage("root_created");
        emit_stage("configure_request_begin");
        let configured_result = agent.handle_request(&json!({
            "action":"configure",
            "cloud_root":root.to_string_lossy()
        }));
        emit_stage(if configured_result.is_ok() {
            "configure_response_ok"
        } else {
            "configure_response_error"
        });
        let configured = configured_result
            .expect("configure the synthetic account root")
            .0;
        assert_eq!(configured["mounted"], false);
        assert_eq!(configured["provider_supported"], false);
        emit_stage("root_configured");
        let configuration = agent
            .state
            .lock()
            .unwrap()
            .root_configuration
            .clone()
            .expect("persisted root identity is present");
        let owner = configuration
            .registration_ownership
            .clone()
            .expect("verified Personal ownership is present");
        assert!(configuration.valid);
        assert_eq!(configuration.server, session.server);
        assert_eq!(configuration.client_id, session.client_id);
        assert_eq!(owner.personal_drive_id, "synthetic-personal-drive");
        assert_eq!(
            owner.personal_root_resource_id.as_deref(),
            Some("synthetic-personal-root")
        );
        assert_eq!(
            owner.account_id,
            personal_account_identity(&session.server, &owner.personal_drive_id)
        );
        let state_protector = DpapiEditRecordProtector::current_user()
            .expect("current-user DPAPI is available before native connection");
        let state_directory = state_protector.local_state_directory().join(format!(
            "agent-runtime-test-{}-{}",
            std::process::id(),
            unix_time_now()
        ));
        std::fs::create_dir(&state_directory)
            .expect("create a fresh persistent recovery state scope under LocalAppData");
        state_protector
            .protect_directory(&state_directory)
            .expect("protect the isolated recovery scope for the current Windows user");

        let make_runtime = |lease: raiun_cloudfiles_windows::ConfiguredRootLease| {
            let (current_session, current_generation, current_root) = {
                let state = agent.state.lock().unwrap();
                (
                    state
                        .session
                        .clone()
                        .expect("authenticated session remains"),
                    state.active_generation,
                    state
                        .root_configuration
                        .clone()
                        .expect("account root remains configured"),
                )
            };
            assert_eq!(current_generation, agent.generation.load(Ordering::Acquire));
            assert_eq!(current_session.server, configuration.server);
            assert_eq!(current_session.client_id, configuration.client_id);
            assert_eq!(current_root, configuration);
            assert_eq!(lease.identity().volume_serial, configuration.volume_serial);
            assert_eq!(lease.identity().file_index, configuration.file_index);
            let current_owner = current_root.registration_ownership.unwrap();
            assert_eq!(current_owner, owner);

            let client = Arc::new(
                OpenCloudClient::new(
                    &current_session.server,
                    current_session.access_token.clone(),
                )
                .expect("construct client from the exact authenticated session"),
            );
            let scope = ProviderScope::new(
                &client,
                current_root.profile_scope.clone(),
                current_owner.account_id,
                client.server_origin().expect("normalized server origin"),
            )
            .expect("bind provider scope to the captured client generation");
            let protector = DpapiEditRecordProtector::current_user()
                .expect("current-user DPAPI is available before native connection");
            let root_identity = lease.identity();
            let recovery = Arc::new(DurableEditRecoveryProvider::new(
                state_directory.clone(),
                scope.clone(),
                root_identity,
                protector.clone(),
            ));
            let backend = Arc::new(
                OpenCloudPlaceholderBackend::new_with_identity_catalog(
                    client,
                    scope,
                    root_identity,
                    recovery.identity_catalog(),
                )
                .expect("backend binds the durable catalog to this root and account"),
            );
            (lease, backend, recovery, protector)
        };

        let (mismatch_lease, mismatch_backend, _valid_recovery, protector) = make_runtime(
            raiun_cloudfiles_windows::pin_configured_root(&root)
                .expect("preflight mismatch uses the same selected empty root"),
        );
        let wrong_root = raiun_cloudfiles_windows::ConfiguredRootIdentity {
            volume_serial: mismatch_lease.identity().volume_serial,
            file_index: mismatch_lease.identity().file_index.wrapping_add(1),
        };
        let mismatched_recovery = Arc::new(SyntheticAgentRecoveryProvider {
            scope: mismatch_backend.scope().clone(),
            root: wrong_root,
            state_directory: state_directory.clone(),
            protector,
        });
        let mismatch_result = synthetic_agent_integration::connect(
            mismatch_lease,
            Arc::clone(&mismatch_backend),
            &owner.personal_drive_id,
            owner
                .personal_root_resource_id
                .as_deref()
                .expect("persisted Personal root identity"),
            mismatched_recovery,
        );
        assert!(matches!(
            mismatch_result,
            Err(raiun_cloudfiles_windows::Error::EditRecoveryUnavailable)
        ));
        mismatch_backend.revoke();
        assert!(
            std::fs::read_dir(&root)
                .expect("mismatched recovery must leave the root untouched")
                .next()
                .is_none()
        );

        let (first_lease, first_backend, first_recovery, _) = make_runtime(
            raiun_cloudfiles_windows::pin_configured_root(&root)
                .expect("pin the exact selected root before connecting"),
        );
        let first_identity = first_lease.identity();
        drop(first_lease);
        agent
            .provider
            .connect(
                PathBuf::from(&configuration.path),
                agent.state.lock().unwrap().active_generation,
                first_identity,
                false,
                owner.personal_drive_id.clone(),
                owner
                    .personal_root_resource_id
                    .clone()
                    .expect("persisted Personal root identity"),
                Arc::clone(&first_backend),
                first_recovery.clone(),
                super::windows_bandwidth::Scope::new(
                    &configuration.profile_scope,
                    &session.server,
                    &session.client_id,
                    session.expected_issuer.as_deref(),
                    &owner.account_id,
                )
                .expect("bind exact fixture account history")
                .bytes()
                .to_vec(),
                Arc::clone(&agent.session_store),
            )
            .expect("agent manager holds the exact-scope native connection");
        emit_stage("provider_connected");
        let guard_barrier = PathBuf::from(
            std::env::var_os("RAIUN_SYNTHETIC_CFAPI_PATH_GUARD_DIR")
                .expect("ordinary-user runner supplies the private test barrier directory"),
        );
        assert!(guard_barrier.is_dir());
        assert!(!guard_barrier.join("armed").exists());
        assert!(!guard_barrier.join("guard-pinned").exists());
        assert!(!guard_barrier.join("release").exists());
        let mut published: Vec<_> = std::fs::read_dir(&root)
            .expect("Cloud Files root enumeration reaches the synthetic namespace")
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        published.sort();
        assert_eq!(published, vec!["Personal", "Spaces"]);
        emit_stage("root_enumerated");
        assert_eq!(agent.status().unwrap()["mounted"], true);
        assert_eq!(agent.status().unwrap()["provider_supported"], false);
        let first_composite_identity = first_backend
            .register_composite_root_for(
                &owner.personal_drive_id,
                owner
                    .personal_root_resource_id
                    .as_deref()
                    .expect("persisted Personal root identity"),
            )
            .expect("resolve the exact composite root identity");
        let first_root_rows = first_backend
            .enumerate(
                first_composite_identity.as_bytes(),
                &CancellationToken::new(),
            )
            .expect("enumerate Personal and Spaces through the exact backend");
        let first_personal_identity = first_root_rows
            .iter()
            .find(|row| row.name == "Personal")
            .expect("Personal is listed")
            .identity
            .clone();
        let first_spaces_identity = first_root_rows
            .iter()
            .find(|row| row.name == "Spaces")
            .expect("Spaces is listed")
            .identity
            .clone();
        let first_space_rows = first_backend
            .enumerate(&first_spaces_identity, &CancellationToken::new())
            .expect("enumerate the Spaces namespace");
        let first_project_identity = first_space_rows
            .iter()
            .find(|row| row.name == "Projects")
            .expect("Projects is listed beneath Spaces")
            .identity
            .clone();

        // After a real placeholder close callback persists the current-user
        // DPAPI snapshot, dispatch it through the agent-owned generation
        // fence and the real conditional OpenCloud byte adapter below.
        let agent_generation = agent.state.lock().unwrap().active_generation;
        let prepared_recovery = first_recovery
            .prepare(first_backend.scope(), first_identity)
            .expect("preflight the same account/root recovery capability");
        let recovery_client = Arc::new(
            OpenCloudClient::new(&session.server, session.access_token.clone())
                .expect("construct exact synthetic account client"),
        );
        let (verified_account, verified_account_id, verified_personal_root, spaces, context) =
            verified_account_roots(&recovery_client, &session.server)
                .expect("revalidate the synthetic authenticated account");
        assert_eq!(verified_account, owner.personal_drive_id);
        assert_eq!(verified_account_id, owner.account_id);
        assert_eq!(
            verified_personal_root,
            owner
                .personal_root_resource_id
                .as_deref()
                .expect("registered Personal root identity")
        );
        let project_space = spaces
            .iter()
            .find(|space| space.id == "synthetic-project-drive")
            .expect("fixture exposes the ordinary writable Project Space");
        assert!(project_space.writable && !project_space.encrypted);
        let project_root = recovery_client
            .stat_discovered_space_root_with_context(project_space, context)
            .expect("verify the exact ordinary Space root before recovery");
        assert_eq!(project_root.id, "synthetic-project-root");
        assert!(project_root.directory && !project_root.encrypted);

        let recovery_path = "RecoveryRoot/document.bin";
        let baseline_bytes = b"original synthetic placeholder bytes";
        let mut modified_bytes = baseline_bytes.to_vec();
        modified_bytes[0] ^= 0x5a;
        let journal_scope = EditJournalScope {
            profile_id: first_backend.scope().profile_id().to_owned(),
            server_origin: first_backend.scope().server_origin().to_owned(),
            account_subject: first_backend.scope().account_id().to_owned(),
            space_id: project_space.id.clone(),
            root_resource_id: project_root.id.clone(),
            root_volume_serial: first_identity.volume_serial,
            root_file_index: first_identity.file_index,
        };
        // Drive the real Cloud Files namespace and callbacks: enumerate the
        // nested Space directory, hydrate its placeholder, then make an OS
        // write and close. The close-completion callback captures the bytes
        // into the same current-user DPAPI journal used by recovery dispatch.
        let spaces_directory = root.join("Spaces");
        let project_directory = spaces_directory.join("Projects");
        let recovery_directory = project_directory.join("RecoveryRoot");
        let local_placeholder = recovery_directory.join("document.bin");
        let executable = std::env::current_exe().expect("resolve the exact test binary");
        let run_client = |mode: &str, probe_guard_race: bool| {
            let baseline_close = probe_guard_race.then(|| {
                agent
                    .provider
                    .close_observation()
                    .expect("capture close callback baseline before race")
            });
            let race_probe = if probe_guard_race {
                // This test-only switch is read only by the
                // synthetic-agent-integration build. Arming is a marker-file
                // operation, so the concurrent callback test does not mutate
                // process environment after worker threads have started.
                std::fs::write(guard_barrier.join("armed"), b"armed\n")
                    .expect("arm the private synthetic callback race barrier");
                let watcher_barrier = guard_barrier.clone();
                let watcher_file = local_placeholder.clone();
                let watcher_directory = recovery_directory.clone();
                let watcher_file_move = root.join("document-race-moved.bin");
                let watcher_directory_move = project_directory.join("RecoveryRoot-race-moved");
                Some(thread::spawn(move || {
                    let marker = watcher_barrier.join("guard-pinned");
                    let release = watcher_barrier.join("release");
                    let deadline = Instant::now() + Duration::from_secs(10);
                    while !marker.exists() && Instant::now() < deadline {
                        thread::sleep(Duration::from_millis(10));
                    }
                    if !marker.exists() {
                        return None;
                    }
                    let file_rename_blocked =
                        std::fs::rename(&watcher_file, &watcher_file_move).is_err();
                    let mut replacement_created = false;
                    let ancestor_rename_blocked = if file_rename_blocked {
                        std::fs::rename(&watcher_directory, &watcher_directory_move).is_err()
                    } else {
                        // Replace the original name with an ordinary file
                        // containing a fixed synthetic sentinel. The callback
                        // must compare the reopened handle to the pinned
                        // Cloud Files placeholder and reject before reading or
                        // journaling this replacement.
                        use std::io::Write as _;
                        let mut replacement = std::fs::OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .open(&watcher_file)
                            .expect("create the owned synthetic replacement at the moved name");
                        replacement
                            .write_all(b"outside synthetic replacement sentinel")
                            .expect("write the fixed synthetic replacement sentinel");
                        replacement
                            .sync_all()
                            .expect("flush the fixed synthetic replacement sentinel");
                        drop(replacement);
                        replacement_created = true;
                        true // No ancestor rename is needed for this attack.
                    };
                    // Always release the callback before attempting cleanup.
                    // If either rename succeeded, it must remain in effect
                    // while the callback tries to reopen its original path;
                    // that forces the production identity/path checks to
                    // reject rather than accidentally snapshot a replacement.
                    std::fs::write(&release, b"release\n")
                        .expect("release callback after both guarded rename probes");
                    Some((
                        file_rename_blocked,
                        ancestor_rename_blocked,
                        watcher_file,
                        watcher_file_move,
                        watcher_directory,
                        watcher_directory_move,
                        replacement_created,
                    ))
                }))
            } else {
                None
            };
            let mut client = std::process::Command::new(&executable)
                .arg("agent_windows::tests::agent_preflights_exact_scope_and_dpapi_before_connect_then_revokes_before_logout")
                .arg("--exact")
                .arg("--ignored")
                .arg("--nocapture")
                .env(CLIENT_MODE, mode)
                .env(CLIENT_ROOT, &root)
                .env_remove("RAIUN_SYNTHETIC_CFAPI_PATH_GUARD_DIR")
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("start a separate synthetic filesystem client process");
            let client_deadline = Instant::now() + Duration::from_secs(30);
            loop {
                if client.try_wait().expect("poll synthetic client").is_some() {
                    break;
                }
                if Instant::now() >= client_deadline {
                    let _ = client.kill();
                    let _ = client.wait();
                    panic!("synthetic filesystem client exceeded its 30 second bound");
                }
                thread::sleep(Duration::from_millis(20));
            }
            let output = client
                .wait_with_output()
                .expect("collect synthetic client result");
            let race_result = race_probe.map(|thread| {
                let (
                    file_rename_blocked,
                    ancestor_rename_blocked,
                    watcher_file,
                    watcher_file_move,
                    watcher_directory,
                    watcher_directory_move,
                    replacement_created,
                ) = thread.join().expect("guarded rename probe thread")?;
                // Do not restore names until the native close callback has
                // completed its post-barrier stream reopen and identity
                // checks. Otherwise cleanup would mask the race.
                let baseline = baseline_close.expect("race baseline exists");
                let baseline_completed = baseline.0.saturating_add(baseline.1);
                let callback_deadline = Instant::now() + Duration::from_secs(10);
                let completed = loop {
                    let observation = agent
                        .provider
                        .close_observation()
                        .expect("poll bounded close callback completion");
                    if observation.0.saturating_add(observation.1) > baseline_completed {
                        break observation;
                    }
                    if Instant::now() >= callback_deadline {
                        panic!("close callback did not finish after race barrier release");
                    }
                    thread::sleep(Duration::from_millis(10));
                };
                if replacement_created {
                    assert_eq!(
                        std::fs::read(&watcher_file)
                            .expect("replacement remains at synthetic original name"),
                        b"outside synthetic replacement sentinel",
                        "cleanup removes only the fixed replacement created by this test"
                    );
                    std::fs::remove_file(&watcher_file)
                        .expect("remove only the exact synthetic replacement path");
                }
                // Restore the ancestor first because a successful directory
                // rename also moves the file-move name.
                if !ancestor_rename_blocked {
                    std::fs::rename(&watcher_directory_move, &watcher_directory)
                        .expect("restore the owned synthetic ancestor after callback");
                }
                if !file_rename_blocked {
                    std::fs::rename(&watcher_file_move, &watcher_file)
                        .expect("restore the owned synthetic file after callback");
                }
                Some((file_rename_blocked, ancestor_rename_blocked, completed))
            });
            (output, race_result)
        };
        let (mut client_output, _) = run_client("hydrate-only", false);
        let (
            mut directory_observation,
            mut fetch_observation,
            mut placeholder_observation,
            mut explicit_hydration,
            mut post_hydration_observation,
        ) = agent
            .provider
            .directory_observation()
            .expect("read bounded native callback telemetry");
        // The Windows runtime rejects implicit open-triggered hydration in this
        // synthetic harness before delivering FETCH_DATA. Test the documented
        // explicit hydration path against the same pinned placeholder, then
        // retry the independent read-only client before the separate edit
        // handle is opened. This keeps the race barrier on the modified close.
        if !client_output.status.success()
            && explicit_hydration.as_ref().is_ok_and(|result| *result >= 0)
            && fetch_observation.0 > 0
        {
            client_output = run_client("hydrate-only", false).0;
            (
                directory_observation,
                fetch_observation,
                placeholder_observation,
                explicit_hydration,
                post_hydration_observation,
            ) = agent
                .provider
                .directory_observation()
                .expect("refresh bounded callback telemetry");
        }
        assert!(
            client_output.status.success(),
            "synthetic filesystem client failed with status {:?}: stdout={:?} stderr={:?}; directory={directory_observation:?}; fetch={fetch_observation:?}; placeholder={placeholder_observation:?}; explicit_hydration={explicit_hydration:?}; post_hydration={post_hydration_observation:?}",
            client_output.status.code(),
            String::from_utf8_lossy(&client_output.stdout),
            String::from_utf8_lossy(&client_output.stderr),
        );
        if automatic_initial_save {
            // This exact test instance alone enables the ordinary production
            // handoff. No environment or persisted/production flag changes.
            const { assert!(!super::WINDOWS_INITIAL_SAVE_DISPATCH_ENABLED) };
            agent
                .provider
                .initial_save_test_activation
                .store(true, Ordering::Release);
            // Defer readback until native completion: a second read-only
            // close while the file is dirty could capture another snapshot.
            let output = run_client("initial-save-only", false).0;
            assert!(output.status.success(), "ordinary save failed: {output:?}");
            let journal = EditJournal::open(
                &state_directory,
                journal_scope.clone(),
                state_protector.clone(),
            )
            .expect("open the exact protected close-capture journal");
            let deadline = Instant::now() + Duration::from_secs(30);
            let saved_metadata = loop {
                let snapshot = journal
                    .recover_all()
                    .expect("authenticate complete save history");
                if snapshot.records.len() == 1 {
                    let record = &snapshot.records[0];
                    assert_eq!(record.metadata.scope, journal_scope);
                    assert_eq!(
                        record.metadata.generation,
                        first_backend.scope().token_generation()
                    );
                    assert_eq!(record.metadata.relative_path, recovery_path);
                    assert_eq!(record.content, modified_bytes);
                    if matches!(
                        snapshot.recovery_states.get(&record.metadata.record_id),
                        Some(RecoveryAttemptState::VerifiedApplied {
                            attempt_id: 1,
                            attempts: 1
                        })
                    ) && !first_recovery
                        .has_unresolved_edits()
                        .expect("read durable local completion")
                    {
                        break record.metadata.clone();
                    }
                }
                assert!(
                    snapshot.records.len() <= 1,
                    "unexpected additional snapshots; preserve scope"
                );
                if Instant::now() >= deadline {
                    // Read existing bounded callback telemetry once on failure;
                    // no reopen, rescan or retry. Diagnostic collection alone
                    // has a 250ms bound after the unchanged save deadline.
                    if let Ok(observation) = agent.provider.close_failure_observation() {
                        emit_close_observation(observation);
                    }
                }
                assert!(
                    Instant::now() < deadline,
                    "automatic save did not complete; preserve root and protected journal; record_count={}; incomplete_staging_files={:?}; recovery_states={:?}; last_dispatch={:?}; fixture_counts_put_get_range_bodylen={:?}",
                    snapshot.records.len(),
                    snapshot.incomplete_staging_files,
                    snapshot.recovery_states.values().collect::<Vec<_>>(),
                    agent
                        .provider
                        .initial_save_test_observation
                        .lock()
                        .unwrap()
                        .as_deref(),
                    {
                        let remote = personal_fixture.recovery.lock().unwrap();
                        (
                            remote.put_count,
                            remote.get_count,
                            remote.range_count,
                            remote.body.len(),
                        )
                    },
                );
                thread::sleep(Duration::from_millis(50));
            };
            assert!(first_recovery.unresolved_edits().unwrap().is_empty());
            assert!(
                first_recovery
                    .unresolved_metadata_bounded()
                    .unwrap()
                    .is_empty()
            );
            let (_, _, os_state) = agent
                .provider
                .read_only_placeholder_observation(NativeRestartProbePath::RecoveryDocument)
                .expect("observe exact original placeholder without hydration");
            let (_, _, flags, size) = os_state.expect("read Cloud Files OS state");
            assert_ne!(flags & 0x8, 0, "CF_PLACEHOLDER_STATE_IN_SYNC must be set");
            assert_eq!(size, modified_bytes.len() as u64);
            assert_eq!(std::fs::read(&local_placeholder).unwrap(), modified_bytes);
            {
                let fixture = personal_fixture.recovery.lock().unwrap();
                assert_eq!(fixture.put_count, 1);
                assert_eq!(
                    fixture.last_put_if_match.as_deref(),
                    Some("\"synthetic-file-v1\"")
                );
                assert!(
                    fixture.get_count >= 2,
                    "upload verification and fresh completion readback both run"
                );
                assert_eq!(
                    fixture.last_read_if_match.as_deref(),
                    Some("\"synthetic-file-v2\"")
                );
                assert_eq!(fixture.etag, "\"synthetic-file-v2\"");
                assert_eq!(fixture.body, modified_bytes);
            }
            emit_stage("initial_save_verified_os_in_sync_and_locally_acknowledged");
            agent
                .provider
                .initial_save_test_activation
                .store(false, Ordering::Release);
            agent
                .provider
                .disconnect()
                .expect("disconnect without unregistering retained root");
            assert!(root.exists());
            let root_lease =
                raiun_cloudfiles_windows::pin_registered_configured_root(&root, first_identity)
                    .expect("exact registration and root identity survive disconnect");
            let reopened = DurableEditRecoveryProvider::new(
                state_directory.clone(),
                first_backend.scope().clone(),
                root_lease.identity(),
                DpapiEditRecordProtector::current_user().unwrap(),
            );
            assert!(!reopened.has_unresolved_edits().unwrap());
            assert!(reopened.unresolved_edits().unwrap().is_empty());
            assert!(reopened.unresolved_metadata_bounded().unwrap().is_empty());
            let reopened_journal =
                EditJournal::open(&state_directory, journal_scope, state_protector.clone())
                    .unwrap();
            let retained = reopened_journal.recover_all().unwrap();
            assert_eq!(retained.records.len(), 1);
            assert_eq!(retained.records[0].metadata, saved_metadata);
            assert_eq!(retained.records[0].content, modified_bytes);
            assert_eq!(
                personal_fixture.recovery.lock().unwrap().put_count,
                1,
                "discovery must not replay upload"
            );
            emit_stage("initial_save_restart_discovery_clean_encrypted_body_retained");
            personal_fixture.join().unwrap();
            return;
        }
        let (raced_edit_output, guard_race) = run_client("edit-race", true);
        let (file_rename_blocked, ancestor_rename_blocked, raced_observation) = guard_race
            .flatten()
            .expect("modified-file close callback reached the guarded race barrier");
        let guard_marker = std::fs::read_to_string(guard_barrier.join("guard-pinned"))
            .expect("read the fixed callback guard marker");
        assert!(guard_marker.starts_with(
            "invocation=1;root_identity=verified;entry_identity=verified;entry_handle=live;delete_share=denied"
        ));
        let attacked_path = !file_rename_blocked || !ancestor_rename_blocked;
        if attacked_path {
            assert!(
                raced_observation.4 == 39 || (40..=80).contains(&raced_observation.4),
                "a changed original name must fail final path revalidation: {raced_observation:?}"
            );
            assert_eq!(
                raced_observation.5, 0,
                "path revalidation rejects the replacement before journal publication"
            );
            assert_eq!(
                raced_observation.7, 0,
                "a renamed path must not be journaled"
            );
            assert!(
                first_recovery
                    .unresolved_edits()
                    .expect("read recovery metadata after rejected path change")
                    .is_empty(),
                "a callback whose original path changed cannot publish a recovery record"
            );
            emit_close_observation(raced_observation);
            emit_stage(if raced_observation.4 == 39 {
                "callback_revalidation_identity_mismatch"
            } else {
                "callback_revalidation_path_rejected"
            });
        } else {
            emit_stage("guarded_file_and_ancestor_rename_rejected");
        }
        assert!(
            raced_edit_output.status.success(),
            "synthetic edit client failed with status {:?}: stdout={:?} stderr={:?}",
            raced_edit_output.status.code(),
            String::from_utf8_lossy(&raced_edit_output.stdout),
            String::from_utf8_lossy(&raced_edit_output.stderr),
        );
        let edit_output = if attacked_path {
            // The first close correctly failed closed because the callback's
            // original name was moved. Retry the synthetic edit only after
            // restoring its owned names, without the adversarial barrier, so
            // the remainder of this test can verify ordinary journal/recovery.
            let retry = run_client("edit-after-race", false).0;
            modified_bytes[1] ^= 0x33;
            retry
        } else {
            raced_edit_output
        };
        assert!(
            edit_output.status.success(),
            "synthetic edit client failed with status {:?}: stdout={:?} stderr={:?}",
            edit_output.status.code(),
            String::from_utf8_lossy(&edit_output.stdout),
            String::from_utf8_lossy(&edit_output.stderr),
        );
        let client_stdout = String::from_utf8_lossy(&client_output.stdout);
        assert!(client_stdout.contains("synthetic_cfapi_client=spaces,projects,recovery,hydrate"));
        assert!(
            String::from_utf8_lossy(&edit_output.stdout)
                .contains("synthetic_cfapi_client=spaces,projects,recovery,write,flush,close")
        );
        emit_stage("os_edit_closed");
        assert!(
            directory_observation.2 > 0,
            "FETCH_PLACEHOLDERS callback must run: {directory_observation:?}"
        );
        assert!(
            directory_observation.4 >= 3,
            "three directory levels must be published: {directory_observation:?}"
        );
        assert!(
            fetch_observation.0 > 0,
            "FETCH_DATA callback must run: {fetch_observation:?}"
        );
        {
            let fixture = personal_fixture.recovery.lock().unwrap();
            assert!(
                fixture.range_count > 0,
                "placeholder hydration uses a range GET"
            );
            assert!(
                fixture.range_bytes >= baseline_bytes.len(),
                "range responses provide the full hydrated placeholder"
            );
            assert_eq!(
                fixture.get_count, 0,
                "hydration is separate from recovery readback"
            );
        }
        assert_eq!(
            std::fs::read(&local_placeholder).expect("read back the locally edited placeholder"),
            modified_bytes
        );
        let capture_deadline = Instant::now() + Duration::from_secs(30);
        let mut close_observation = agent
            .provider
            .close_observation()
            .expect("read bounded native close callback telemetry");
        let edit_metadata = loop {
            let recovered = match first_recovery.unresolved_edits() {
                Ok(records) => records,
                Err(_) => {
                    emit_close_observation(close_observation);
                    emit_stage("recovery_metadata_unavailable");
                    panic!("enumerate protected synthetic recovery metadata");
                }
            };
            if let Some(record) = recovered
                .into_iter()
                .find(|item| item.relative_path == recovery_path)
            {
                assert_eq!(record.scope, journal_scope);
                assert_eq!(
                    record
                        .remote
                        .as_ref()
                        .map(|remote| remote.resource_id.as_str()),
                    Some("synthetic-recovery-file")
                );
                assert_eq!(
                    record.remote.as_ref().map(|remote| remote.etag.as_str()),
                    Some("\"synthetic-file-v1\"")
                );
                break record;
            }
            if Instant::now() >= capture_deadline {
                emit_close_observation(close_observation);
                panic!(
                    "the native close-completion callback did not persist the edit; telemetry={close_observation:?}"
                );
            }
            close_observation = agent
                .provider
                .close_observation()
                .expect("refresh bounded native close callback telemetry");
            thread::sleep(Duration::from_millis(50));
        };
        emit_stage("edit_journal_captured");
        let captured_snapshot = EditJournal::open(
            &state_directory,
            journal_scope.clone(),
            state_protector.clone(),
        )
        .and_then(|journal| journal.recover_all())
        .expect("authenticate the close-callback DPAPI snapshot");
        let captured_record = captured_snapshot
            .records
            .iter()
            .find(|item| item.metadata.record_id == edit_metadata.record_id)
            .expect("the callback persisted the exact selected edit");
        assert_eq!(
            captured_record.metadata.generation,
            edit_metadata.generation
        );
        assert_eq!(captured_record.content.as_slice(), modified_bytes);
        let remote = Arc::new(
            raiun_cloudfiles_windows::OpenCloudRecoveryRemote::new(
                Arc::clone(&recovery_client),
                journal_scope.clone(),
                project_root.path.clone(),
                recovery_client.token_generation(),
            )
            .expect("bind HTTP recovery to the exact server and token generation"),
        );
        let remote: Arc<dyn raiun_cloudfiles_windows::RecoveryRemote> =
            Arc::new(AgentGenerationRecoveryRemote {
                inner: RecoveryRemoteHandle::Owned(remote),
                authorized_generation: Arc::clone(&agent.provider.authorized_generation),
                expected_generation: agent_generation,
            });
        let outcome = agent.provider.dispatch_recovery(
            agent_generation,
            Arc::clone(&prepared_recovery),
            edit_metadata.record_id.clone(),
            edit_metadata.generation,
            remote,
        );
        emit_stage("dispatch_returned");
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(_error) => {
                let state = EditJournal::open(
                    &state_directory,
                    journal_scope.clone(),
                    state_protector.clone(),
                )
                .and_then(|journal| journal.recover_all())
                .ok()
                .and_then(|snapshot| {
                    snapshot
                        .recovery_states
                        .get(&edit_metadata.record_id)
                        .copied()
                });
                let fixture = personal_fixture.recovery.lock().unwrap();
                panic!(
                    "guarded recovery dispatch failed: {_error}; journal_state={state:?}; puts={}; gets={}; etag={}",
                    fixture.put_count, fixture.get_count, fixture.etag
                );
            }
        };
        assert!(matches!(
            outcome,
            raiun_cloudfiles_windows::ReconciliationOutcome::VerifiedApplied { attempts: 1 }
        ));
        emit_stage("conditional_readback_verified");
        {
            let fixture = personal_fixture.recovery.lock().unwrap();
            assert_eq!(fixture.put_count, 1, "one conditional PUT is sent");
            assert_eq!(
                fixture.last_put_if_match.as_deref(),
                Some("\"synthetic-file-v1\"")
            );
            assert_eq!(
                fixture.last_read_if_match.as_deref(),
                Some("\"synthetic-file-v2\"")
            );
            assert_eq!(
                fixture.get_count, 1,
                "the uploaded version is read back once"
            );
            assert!(
                fixture.range_count > 0,
                "the native placeholder was hydrated by HTTP range"
            );
            assert!(fixture.range_bytes >= baseline_bytes.len());
            assert_eq!(fixture.body.as_slice(), modified_bytes);
        }
        let journal = EditJournal::open(
            &state_directory,
            journal_scope.clone(),
            state_protector.clone(),
        )
        .expect("reopen the same current-user protected journal");
        let retained = journal
            .recover_all()
            .expect("recover retained DPAPI record");
        let retained = retained
            .records
            .iter()
            .find(|item| item.metadata.record_id == edit_metadata.record_id)
            .expect("verified upload does not delete the original recovery bytes");
        assert_eq!(retained.content.as_slice(), modified_bytes);
        assert_eq!(
            retained.recovered_state(),
            raiun_cloudfiles_windows::LocalEditState::Uncertain,
            "the immutable content record remains available after dispatch"
        );
        assert_eq!(
            journal
                .recover_all()
                .unwrap()
                .recovery_states
                .get(&edit_metadata.record_id),
            Some(&RecoveryAttemptState::VerifiedApplied {
                attempt_id: 1,
                attempts: 1,
            })
        );

        agent
            .provider
            .disconnect()
            .expect("logout-style disconnect revokes and drains callbacks");
        assert_eq!(agent.status().unwrap()["mounted"], false);
        assert!(matches!(
            first_backend.enumerate(&[], &CancellationToken::new()),
            Err(raiun_cloudfiles_windows::BackendError::Unavailable)
        ));

        let registered = raiun_cloudfiles_windows::pin_registered_configured_root(
            &root,
            raiun_cloudfiles_windows::ConfiguredRootIdentity {
                volume_serial: configuration.volume_serial,
                file_index: configuration.file_index,
            },
        )
        .expect("re-pin only the exact previously registered root");
        let (reconnect_lease, second_backend, second_recovery, _) = make_runtime(registered);
        let second_recovery_for_connection: Arc<dyn EditRecoveryProvider> = second_recovery.clone();
        let second_connection = synthetic_agent_integration::connect(
            reconnect_lease,
            Arc::clone(&second_backend),
            &owner.personal_drive_id,
            owner
                .personal_root_resource_id
                .as_deref()
                .expect("persisted Personal root identity"),
            second_recovery_for_connection,
        )
        .expect("reconnect with exact account and recovery scope");
        let second_composite_identity = second_backend
            .register_composite_root_for(
                &owner.personal_drive_id,
                owner
                    .personal_root_resource_id
                    .as_deref()
                    .expect("persisted Personal root identity"),
            )
            .expect("fresh backend resolves the same composite root");
        assert_eq!(second_composite_identity, first_composite_identity);
        emit_stage("fresh_backend_identity_resolved");
        let second_root_rows = second_backend
            .enumerate(
                second_composite_identity.as_bytes(),
                &CancellationToken::new(),
            )
            .expect("fresh backend rehydrates root descendants from the DPAPI catalog");
        emit_stage("fresh_backend_rehydrated");
        assert_eq!(
            second_root_rows
                .iter()
                .find(|row| row.name == "Personal")
                .expect("Personal survives backend recreation")
                .identity
                .clone(),
            first_personal_identity
        );
        let second_spaces_identity = second_root_rows
            .iter()
            .find(|row| row.name == "Spaces")
            .expect("Spaces survives backend recreation")
            .identity
            .clone();
        assert_eq!(second_spaces_identity, first_spaces_identity);
        let second_space_rows = second_backend
            .enumerate(&second_spaces_identity, &CancellationToken::new())
            .expect("fresh backend rehydrates Spaces children");
        assert_eq!(
            second_space_rows
                .iter()
                .find(|row| row.name == "Projects")
                .expect("Projects survives backend recreation")
                .identity
                .clone(),
            first_project_identity
        );

        // Exercise a second ordinary OS write after backend/recovery recreation.
        // The close callback must journal the dirty bytes under the same exact
        // account/root, and a changed remote baseline must conflict without
        // replacing either copy.
        let prior_record_ids: std::collections::HashSet<_> = second_recovery
            .unresolved_edits()
            .expect("enumerate retained edit metadata after reconnect")
            .into_iter()
            .map(|record| record.record_id)
            .collect();
        let conflict_edit_output = run_client("edit-after-success", false).0;
        assert!(
            conflict_edit_output.status.success(),
            "post-reconnect ordinary OS edit failed: stdout={:?} stderr={:?}",
            String::from_utf8_lossy(&conflict_edit_output.stdout),
            String::from_utf8_lossy(&conflict_edit_output.stderr),
        );
        assert!(
            String::from_utf8_lossy(&conflict_edit_output.stdout)
                .contains("synthetic_cfapi_client=spaces,projects,recovery,write,flush,close")
        );
        let mut conflict_dirty_bytes = modified_bytes.clone();
        conflict_dirty_bytes[1] ^= 0x33;
        let conflict_capture_deadline = Instant::now() + Duration::from_secs(30);
        let conflict_metadata = loop {
            let records = second_recovery
                .unresolved_edits()
                .expect("reopen DPAPI recovery metadata after native close");
            if let Some(record) = records.into_iter().find(|record| {
                record.relative_path == recovery_path
                    && !prior_record_ids.contains(&record.record_id)
            }) {
                assert_eq!(record.scope, journal_scope);
                assert_eq!(record.content_len, conflict_dirty_bytes.len() as u64);
                break record;
            }
            if Instant::now() >= conflict_capture_deadline {
                panic!("post-reconnect native close did not publish a new recovery record");
            }
            thread::sleep(Duration::from_millis(50));
        };
        let conflict_journal = EditJournal::open(
            &state_directory,
            journal_scope.clone(),
            state_protector.clone(),
        )
        .expect("reopen the current-user DPAPI journal after reconnect");
        let conflict_snapshot = conflict_journal
            .recover_all()
            .expect("authenticate the post-reconnect dirty snapshot");
        let conflict_record = conflict_snapshot
            .records
            .iter()
            .find(|record| record.metadata.record_id == conflict_metadata.record_id)
            .expect("new post-reconnect record remains in the journal");
        assert_eq!(conflict_record.content.as_slice(), conflict_dirty_bytes);

        let conflicting_remote_bytes = b"external concurrent synthetic version".to_vec();
        {
            let mut remote = personal_fixture.recovery.lock().unwrap();
            assert_eq!(
                remote.put_count, 1,
                "only the earlier verified edit uploaded"
            );
            remote.body = conflicting_remote_bytes.clone();
            remote.etag = "\"synthetic-file-v3\"".into();
        }
        let second_prepared_recovery = second_recovery
            .prepare(second_backend.scope(), first_identity)
            .expect("prepare recovery against the reconnected exact scope");
        let conflict_remote = Arc::new(
            raiun_cloudfiles_windows::OpenCloudRecoveryRemote::new(
                Arc::clone(&recovery_client),
                journal_scope.clone(),
                project_root.path.clone(),
                recovery_client.token_generation(),
            )
            .expect("bind conflict check to the verified remote path and generation"),
        );
        let conflict_remote: Arc<dyn raiun_cloudfiles_windows::RecoveryRemote> =
            Arc::new(AgentGenerationRecoveryRemote {
                inner: RecoveryRemoteHandle::Owned(conflict_remote),
                authorized_generation: Arc::clone(&agent.provider.authorized_generation),
                expected_generation: agent_generation,
            });
        let conflict_outcome = agent
            .provider
            .dispatch_recovery(
                agent_generation,
                second_prepared_recovery,
                conflict_metadata.record_id.clone(),
                conflict_metadata.generation,
                conflict_remote,
            )
            .expect("post-reconnect recovery dispatch returns a durable conflict result");
        assert_eq!(
            conflict_outcome,
            raiun_cloudfiles_windows::ReconciliationOutcome::Conflict(
                raiun_cloudfiles_windows::ReconciliationIssue::ContentMismatch
            )
        );
        assert_eq!(
            std::fs::read(&local_placeholder).expect("local dirty placeholder remains readable"),
            conflict_dirty_bytes,
            "a remote conflict must preserve the exact local dirty bytes"
        );
        let durable_conflict = EditJournal::open(
            &state_directory,
            journal_scope.clone(),
            state_protector.clone(),
        )
        .and_then(|journal| journal.recover_all())
        .expect("reopen durable conflict outcome");
        assert_eq!(
            durable_conflict
                .recovery_states
                .get(&conflict_metadata.record_id),
            Some(&RecoveryAttemptState::Conflict {
                attempt_id: 0,
                attempts: 0,
            })
        );
        assert_eq!(
            durable_conflict
                .records
                .iter()
                .find(|record| record.metadata.record_id == conflict_metadata.record_id)
                .expect("conflicted snapshot remains retained")
                .content,
            conflict_dirty_bytes
        );
        {
            let remote = personal_fixture.recovery.lock().unwrap();
            assert_eq!(remote.put_count, 1, "conflict must not dispatch a PUT");
            assert_eq!(remote.etag, "\"synthetic-file-v3\"");
            assert_eq!(remote.body, conflicting_remote_bytes);
        }

        second_backend.revoke();
        assert!(matches!(
            second_connection.unregister(),
            Err(raiun_cloudfiles_windows::Error::UnresolvedPlaceholderEdits)
        ));
        agent
            .handle_request(&json!({"action":"logout"}))
            .expect("logout only after callback scope has been revoked and drained");
        assert_eq!(agent.status().unwrap()["mounted"], false);
        assert_eq!(agent.status().unwrap()["provider_supported"], false);
        assert!(root.exists(), "logout preserves the registered test root");
        let mut preserved: Vec<_> = std::fs::read_dir(&root)
            .expect("inspect preserved synthetic root")
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        preserved.sort();
        assert_eq!(
            preserved,
            vec!["Personal", "Spaces"],
            "unresolved Cloud Files directory placeholders must remain registered and intact"
        );
        // Deliberately retain this unique registered root for inspection. The
        // reconnect scan cannot prove that a directory placeholder has no
        // hidden descendants, so explicit unregister must fail closed.
        personal_fixture.join().unwrap();
    }

    /// Preserves the external-change conflict acceptance exactly.
    #[cfg(all(windows, debug_assertions))]
    #[test]
    #[ignore = "requires disposable Windows VM, Cloud Files, and current-user DPAPI"]
    fn pending_dirty_edit_survives_process_restart_and_conflicts_without_upload() {
        run_pending_dirty_edit_process_restart(false);
    }

    /// Proves duplicate OS-written snapshots dispatch once after a real process
    /// restart; subsequent snapshots verify the already-applied remote bytes.
    #[cfg(all(windows, debug_assertions))]
    #[test]
    #[ignore = "requires disposable Windows VM, Cloud Files, and current-user DPAPI"]
    fn pending_dirty_duplicate_dispatch_survives_process_restart() {
        run_pending_dirty_edit_process_restart(true);
    }

    #[cfg(all(windows, debug_assertions))]
    fn run_pending_dirty_edit_process_restart(successful_duplicate_dispatch: bool) {
        use raiun_cloudfiles_windows::{
            DpapiEditRecordProtector, DurableEditRecoveryProvider, EditJournal, EditJournalScope,
            EditRecordProtector, EditRecoveryProvider, LocalEditState, OpenCloudPlaceholderBackend,
            OpenCloudRecoveryRemote, ProviderScope, RecoveryAttemptState,
            synthetic_agent_integration,
        };
        use raiun_core::backend::CloudBackend;
        use raiun_opencloud::OpenCloudClient;
        use std::process::{Command, Stdio};

        const PHASE: &str = "RAIUN_SYNTHETIC_RESTART_PHASE";
        const ROOT: &str = "RAIUN_SYNTHETIC_RESTART_ROOT";
        const STATE: &str = "RAIUN_SYNTHETIC_RESTART_STATE";
        const CLIENT_MODE: &str = "RAIUN_SYNTHETIC_RESTART_CLIENT_MODE";
        const CLIENT_ROOT: &str = "RAIUN_SYNTHETIC_RESTART_CLIENT_ROOT";
        const TRACE: &str = "RAIUN_SYNTHETIC_RESTART_TRACE";
        const SESSION_COMPARE_HOLD: &str = "RAIUN_SYNTHETIC_RESTART_SESSION_COMPARE_HOLD";
        let test_name = if successful_duplicate_dispatch {
            "agent_windows::tests::pending_dirty_duplicate_dispatch_survives_process_restart"
        } else {
            "agent_windows::tests::pending_dirty_edit_survives_process_restart_and_conflicts_without_upload"
        };
        const RELATIVE_PATH: &str = "RecoveryRoot/document.bin";
        const ORIGINAL: &[u8] = b"original synthetic placeholder bytes";

        fn synthetic_sha256(bytes: &[u8]) -> String {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(bytes))
        }

        fn emit_marker(line: &str) {
            assert!(line.starts_with("synthetic_restart_"));
            if let Some(path) = std::env::var_os(TRACE) {
                let mut file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(PathBuf::from(path))
                    .expect("append bounded synthetic restart marker");
                let current_len = file.metadata().expect("inspect marker file").len();
                let new_len = current_len
                    .checked_add(line.len() as u64 + 1)
                    .expect("marker length does not overflow");
                assert!(
                    new_len <= 32 * 1024,
                    "synthetic marker log exceeded its fixed bound"
                );
                use std::io::Write;
                writeln!(file, "{line}").expect("write bounded synthetic restart marker");
            }
            println!("{line}");
        }

        fn read_markers(path: &Path) -> String {
            let trace_file = std::fs::File::open(path).expect("read synthetic marker file");
            let mut bounded = Vec::new();
            use std::io::Read;
            trace_file
                .take(32 * 1024 + 1)
                .read_to_end(&mut bounded)
                .expect("read bounded marker file");
            assert!(
                bounded.len() <= 32 * 1024,
                "synthetic marker log exceeded its fixed bound"
            );
            let text = String::from_utf8(bounded).expect("synthetic markers are UTF-8");
            assert!(
                text.lines()
                    .all(|line| line.starts_with("synthetic_restart_")),
                "unexpected marker content"
            );
            text
        }

        fn wait_child(mut child: std::process::Child, what: &str) -> std::process::ExitStatus {
            let deadline = Instant::now() + Duration::from_secs(300);
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => return status,
                    Ok(None) if Instant::now() < deadline => {
                        thread::sleep(Duration::from_millis(50))
                    }
                    Ok(None) => {
                        panic!(
                            "{what} exceeded the five minute acceptance bound (pid={}); child is left running and synthetic root/recovery are preserved",
                            child.id()
                        );
                    }
                    Err(error) => panic!(
                        "could not poll {what} (pid={}): {error}; child is left running and synthetic root/recovery are preserved",
                        child.id()
                    ),
                }
            }
        }

        fn run_phase(
            executable: &std::path::Path,
            phase: &str,
            root: &Path,
            state: &Path,
            test_name: &str,
        ) -> Vec<String> {
            let trace = root
                .parent()
                .expect("synthetic root has a parent")
                .join(format!(
                    "{}-{phase}.trace",
                    root.file_name()
                        .expect("synthetic root name")
                        .to_string_lossy()
                ));
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&trace)
                .expect("new bounded marker file outside Cloud Files root");
            let child_stderr = trace.with_extension("stderr");
            let stderr_file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&child_stderr)
                .expect("new bounded child stderr file outside Cloud Files root");
            let child = Command::new(executable)
                .arg(test_name)
                .arg("--exact")
                .arg("--ignored")
                .arg("--nocapture")
                .env(PHASE, phase)
                .env(ROOT, root)
                .env(STATE, state)
                .env(TRACE, &trace)
                .env_remove(CLIENT_MODE)
                .stdout(Stdio::null())
                .stderr(Stdio::from(stderr_file))
                .spawn()
                .unwrap_or_else(|error| {
                    panic!("could not start fresh {phase} agent process: {error}")
                });
            let status = wait_child(child, phase);
            let trace_text = read_markers(&trace);
            let stderr_size = std::fs::metadata(&child_stderr)
                .expect("child stderr file metadata")
                .len();
            assert!(
                stderr_size <= 32 * 1024,
                "bounded child stderr exceeded limit"
            );
            let stderr_bytes = std::fs::read(&child_stderr).expect("read bounded child stderr");
            let stderr_text = String::from_utf8_lossy(&stderr_bytes);
            if !stderr_text.is_empty() {
                println!(
                    "synthetic_restart_child_stderr={phase},{}",
                    stderr_text.trim()
                );
            }
            for line in trace_text.lines() {
                println!("{line}");
            }
            println!(
                "synthetic_restart_child_exit={phase},success={}",
                status.success()
            );
            assert!(
                status.success(),
                "{phase} agent process failed with status {status}; bounded trace retained at {trace:?}",
            );
            trace_text.lines().map(str::to_owned).collect()
        }

        fn run_access_probe(
            executable: &std::path::Path,
            mode: &str,
            root: &Path,
            trace: &Path,
            test_name: &str,
        ) -> std::process::ExitStatus {
            let child = Command::new(executable)
                .arg(test_name)
                .arg("--exact")
                .arg("--ignored")
                .arg("--nocapture")
                .env(CLIENT_MODE, mode)
                .env(CLIENT_ROOT, root)
                .env(TRACE, trace)
                .env_remove(PHASE)
                .env_remove("RAIUN_SYNTHETIC_CFAPI_PATH_GUARD_DIR")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap_or_else(|error| panic!("could not start bounded {mode} probe: {error}"));
            wait_child(child, mode)
        }

        fn synthetic_conditional_remote_readback(server: &str, etag: &str) -> (String, Vec<u8>) {
            let address = server
                .strip_prefix("http://")
                .expect("synthetic fixture uses loopback HTTP");
            let mut stream = TcpStream::connect(address).expect("connect to loopback fixture");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("bound final conditional readback");
            write!(
                stream,
                "GET /remote.php/dav/projects/synthetic-project-drive/RecoveryRoot/document.bin HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer synthetic-access-token\r\nIf-Match: {etag}\r\nConnection: close\r\n\r\n"
            )
            .expect("request final conditional readback");
            let mut response = Vec::new();
            stream
                .take(16 * 1024)
                .read_to_end(&mut response)
                .expect("read bounded final conditional response");
            let header_end = response
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .expect("final conditional response contains headers");
            let headers = String::from_utf8_lossy(&response[..header_end]);
            assert!(
                headers.starts_with("HTTP/1.1 200 "),
                "final If-Match read succeeds: {headers}"
            );
            let response_etag = headers
                .lines()
                .find_map(|line| line.strip_prefix("ETag: "))
                .expect("final readback includes ETag")
                .to_owned();
            (response_etag, response[header_end + 4..].to_vec())
        }

        fn synthetic_remote_read_counts(server: &str) -> (usize, usize, usize) {
            let address = server
                .strip_prefix("http://")
                .expect("synthetic fixture uses loopback HTTP");
            let mut stream = TcpStream::connect(address).expect("connect to loopback fixture");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("bound fixture counter response read");
            write!(
                stream,
                "GET /__test/remote_counts HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
            )
            .expect("request bounded fixture counters");
            let mut response = String::new();
            stream
                .read_to_string(&mut response)
                .expect("read bounded fixture counter response");
            let body = response
                .split_once("\r\n\r\n")
                .expect("fixture counter HTTP response has headers")
                .1
                .trim();
            let mut counts = body.split(',').map(|value| {
                value
                    .parse::<usize>()
                    .expect("fixture counter is an unsigned integer")
            });
            let result = (
                counts.next().expect("GET count"),
                counts.next().expect("range count"),
                counts.next().expect("range byte count"),
            );
            assert!(counts.next().is_none(), "fixture counter has fixed shape");
            result
        }

        fn synthetic_native_read_counts(
            server: &str,
        ) -> (usize, usize, usize, usize, usize, usize) {
            let address = server
                .strip_prefix("http://")
                .expect("synthetic fixture uses loopback HTTP");
            let mut stream = TcpStream::connect(address).expect("connect to loopback fixture");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("bound native fixture counter response read");
            write!(
                stream,
                "GET /__test/native_read_counts HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
            )
            .expect("request bounded native fixture counters");
            let mut response = String::new();
            stream
                .read_to_string(&mut response)
                .expect("read bounded native fixture counter response");
            let body = response
                .split_once("\r\n\r\n")
                .expect("native fixture counter HTTP response has headers")
                .1
                .trim();
            let mut counts = body.split(',').map(|value| {
                value
                    .parse::<usize>()
                    .expect("native fixture counter is an unsigned integer")
            });
            let result = (
                counts.next().expect("Personal GET count"),
                counts.next().expect("Personal range count"),
                counts.next().expect("Personal range byte count"),
                counts.next().expect("Projects GET count"),
                counts.next().expect("Projects range count"),
                counts.next().expect("Projects range byte count"),
            );
            assert!(
                counts.next().is_none(),
                "native fixture counter has fixed shape"
            );
            result
        }

        fn placeholder_fields(observation: &NativeReadOnlyObservation) -> String {
            match &observation.2 {
                Ok((attributes, reparse_tag, state, size)) => {
                    format!("attr={attributes},tag={reparse_tag},state={state},size={size}")
                }
                Err(_) => "unavailable".to_owned(),
            }
        }

        fn placeholder_classification(observation: &NativeReadOnlyObservation) -> String {
            const PLACEHOLDER: u32 = 0x1;
            const PARTIAL: u32 = 0x10;
            const PARTIALLY_ON_DISK: u32 = 0x20;
            observation.2.as_ref().map_or_else(
                |_| "unknown".to_owned(),
                |(_, _, state, _)| {
                    if state & PLACEHOLDER == 0 {
                        "not_placeholder_or_unknown".to_owned()
                    } else if state & (PARTIAL | PARTIALLY_ON_DISK) != 0 {
                        "partial_before_read".to_owned()
                    } else {
                        "already_hydrated_before_read".to_owned()
                    }
                },
            )
        }

        fn report_differential_access_probe(
            label: &str,
            before: &super::NativeDifferentialObservation,
            after: &super::NativeDifferentialObservation,
        ) {
            let before_fields = placeholder_fields(&before.0);
            let after_fields = placeholder_fields(&after.0);
            let before_classification = placeholder_classification(&before.0);
            let after_classification = placeholder_classification(&after.0);
            let prior_directory = before.0.0;
            let after_directory = after.0.0;
            let prior_fetch = before.0.1;
            let after_fetch = after.0.1;
            emit_marker(&format!(
                "synthetic_restart_differential_access={label},before={before_classification}:{before_fields},after={after_classification}:{after_fields},directory_entries_delta={},directory_guard_rejections_delta={},accepted_directory_callbacks_delta={},entries_submitted_delta={},admitted_fetch_callbacks_delta={},fetch_bytes_delta={},first_failed_hresult_before=0x{:08x},first_failed_hresult_after=0x{:08x},recovery_gets_delta={},recovery_ranges_delta={},recovery_range_bytes_delta={},personal_gets_delta={},personal_ranges_delta={},personal_range_bytes_delta={},projects_gets_delta={},projects_ranges_delta={},projects_range_bytes_delta={}",
                after_directory.0.saturating_sub(prior_directory.0),
                after_directory.1.saturating_sub(prior_directory.1),
                after_directory.2.saturating_sub(prior_directory.2),
                after_directory.4.saturating_sub(prior_directory.4),
                after_fetch.0.saturating_sub(prior_fetch.0),
                after_fetch.2.saturating_sub(prior_fetch.2),
                prior_fetch.3 as u32,
                after_fetch.3 as u32,
                after.1.0.saturating_sub(before.1.0),
                after.1.1.saturating_sub(before.1.1),
                after.1.2.saturating_sub(before.1.2),
                after.2.0.saturating_sub(before.2.0),
                after.2.1.saturating_sub(before.2.1),
                after.2.2.saturating_sub(before.2.2),
                after.2.3.saturating_sub(before.2.3),
                after.2.4.saturating_sub(before.2.4),
                after.2.5.saturating_sub(before.2.5),
            ));
        }

        fn report_namespace_directory(
            agent: &WindowsAgent,
            server: &str,
            path: &Path,
            label: &str,
            expected: &[&str],
        ) {
            const MAX_ENTRIES: usize = 256;
            let before = agent
                .provider
                .read_only_placeholder_observation(NativeRestartProbePath::RecoveryDocument)
                .expect("read-only callback snapshot before namespace enumeration");
            let remote_before = synthetic_remote_read_counts(server);
            let direct = (|| -> Result<Vec<String>, String> {
                let iterator = std::fs::read_dir(path).map_err(|error| error.to_string())?;
                let mut names = Vec::new();
                for entry in iterator.take(MAX_ENTRIES + 1) {
                    let name = entry
                        .map_err(|error| error.to_string())?
                        .file_name()
                        .into_string()
                        .map_err(|_| "synthetic entry name is not UTF-8".to_owned())?;
                    names.push(name);
                }
                if names.len() > MAX_ENTRIES {
                    return Err("synthetic directory exceeded entry bound".to_owned());
                }
                names.sort();
                Ok(names)
            })();
            let direct_matches = direct.as_ref().is_ok_and(|names| {
                let mut expected = expected
                    .iter()
                    .map(|name| (*name).to_owned())
                    .collect::<Vec<_>>();
                expected.sort();
                names == &expected
            });
            let child = child_process_directory_matches(path, expected);
            let after = agent
                .provider
                .read_only_placeholder_observation(NativeRestartProbePath::RecoveryDocument)
                .expect("read-only callback snapshot after child directory query");
            let remote_after = synthetic_remote_read_counts(server);
            let child_matches = child
                .as_ref()
                .is_ok_and(|comparison| comparison.matches_expected);
            let child_summary = child.as_ref().map_or_else(
                |error| format!("error={}", error.chars().take(120).collect::<String>()),
                |comparison| {
                    format!(
                        "matches={},entries={},known={},unknown={}",
                        comparison.matches_expected,
                        comparison.entry_count,
                        comparison.known_names.join("+"),
                        comparison.unknown_name_count
                    )
                },
            );
            let before_directory = before.0;
            let after_directory = after.0;
            let before_fetch = before.1;
            let after_fetch = after.1;
            emit_marker(&format!(
                "synthetic_restart_namespace_enumeration={label},direct_result={},direct_matches={direct_matches},child={child_summary},directory_entries_delta={},directory_rejections_delta={},accepted_callbacks_delta={},entries_submitted_delta={},fetch_callbacks_delta={},fetch_bytes_delta={},fetch_hresult_before=0x{:08x},fetch_hresult_after=0x{:08x},remote_gets_delta={},remote_ranges_delta={},remote_range_bytes_delta={}",
                direct.as_ref().map_or_else(
                    |error| format!("error:{}", error.chars().take(100).collect::<String>()),
                    |names| format!("names:{}", names.join("+"))
                ),
                after_directory.0.saturating_sub(before_directory.0),
                after_directory.1.saturating_sub(before_directory.1),
                after_directory.2.saturating_sub(before_directory.2),
                after_directory.4.saturating_sub(before_directory.4),
                after_fetch.0.saturating_sub(before_fetch.0),
                after_fetch.2.saturating_sub(before_fetch.2),
                before_fetch.3 as u32,
                after_fetch.3 as u32,
                remote_after.0.saturating_sub(remote_before.0),
                remote_after.1.saturating_sub(remote_before.1),
                remote_after.2.saturating_sub(remote_before.2),
            ));
            assert!(
                direct_matches || child_matches,
                "ordinary OS directory enumeration failed for synthetic {label}"
            );
        }

        fn catalog_fingerprints(markers: &[String], phase: &str) -> Vec<String> {
            let prefix = format!("synthetic_restart_catalog={phase},");
            let mut records: Vec<_> = markers
                .iter()
                .filter_map(|line| line.strip_prefix(&prefix).map(str::to_owned))
                .collect();
            records.sort();
            records
        }

        // This branch is a read-only ordinary client process. Its paths and
        // expected bytes are fixed synthetic leaves; it never mutates or
        // explicitly hydrates a placeholder.
        if matches!(
            std::env::var(CLIENT_MODE).as_deref(),
            Ok("probe-personal-native-read"
                | "probe-projects-native-read"
                | "probe-recovery-document"
                | "probe-recovery-read-probe")
        ) {
            let mode = std::env::var(CLIENT_MODE).expect("probe mode remains set");
            let root = PathBuf::from(std::env::var_os(CLIENT_ROOT).expect("test supplies root"));
            let (relative_path, expected): (&str, &[u8]) = match mode.as_str() {
                "probe-personal-native-read" => (
                    "Personal/native-read.bin",
                    b"synthetic Personal native read bytes",
                ),
                "probe-projects-native-read" => (
                    "Spaces/Projects/native-read.bin",
                    b"synthetic Projects Space native read bytes",
                ),
                "probe-recovery-document" => {
                    ("Spaces/Projects/RecoveryRoot/document.bin", ORIGINAL)
                }
                "probe-recovery-read-probe" => {
                    ("Spaces/Projects/RecoveryRoot/read-probe.bin", ORIGINAL)
                }
                _ => unreachable!("mode was checked against the fixed probe list"),
            };
            let path = root.join(relative_path);
            let opened = std::fs::File::open(&path).and_then(|file| {
                let mut limited = file.take(expected.len() as u64 + 1);
                let mut bytes = Vec::with_capacity(expected.len());
                limited.read_to_end(&mut bytes)?;
                if bytes != expected {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "synthetic file bytes differ from exact fixture payload",
                    ));
                }
                Ok(bytes.len())
            });
            match opened {
                Ok(size) => emit_marker(&format!(
                    "synthetic_restart_differential_read={mode},result=read_exact,size={size}"
                )),
                Err(error) => emit_marker(&format!(
                    "synthetic_restart_differential_read={mode},error={},kind={:?}",
                    error.raw_os_error().unwrap_or(-1),
                    error.kind()
                )),
            }
            return;
        }

        if matches!(
            std::env::var(CLIENT_MODE).as_deref(),
            Ok("restart-edit" | "restart-duplicate-edit")
        ) {
            let mode = std::env::var(CLIENT_MODE).expect("writer mode remains set");
            let root = PathBuf::from(std::env::var_os(CLIENT_ROOT).expect("test supplies root"));
            let spaces = root.join("Spaces");
            assert!(
                std::fs::read_dir(&spaces)
                    .unwrap()
                    .any(|entry| { entry.unwrap().file_name().to_string_lossy() == "Projects" })
            );
            let projects = spaces.join("Projects");
            assert!(
                std::fs::read_dir(&projects).unwrap().any(|entry| {
                    entry.unwrap().file_name().to_string_lossy() == "RecoveryRoot"
                })
            );
            let directory = projects.join("RecoveryRoot");
            let path = directory.join("document.bin");
            let mut file = match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
            {
                Ok(file) => file,
                Err(error) => {
                    emit_marker(&format!(
                        "synthetic_restart_client_open_error={}",
                        error.raw_os_error().unwrap_or(-1)
                    ));
                    panic!("ordinary client could not open synthetic placeholder");
                }
            };
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)
                .expect("hydrate/read synthetic bytes");
            if mode == "restart-edit" {
                assert_eq!(bytes, ORIGINAL);
                bytes[0] ^= 0x5a;
            } else {
                let mut expected_dirty = ORIGINAL.to_vec();
                expected_dirty[0] ^= 0x5a;
                assert_eq!(
                    bytes, expected_dirty,
                    "duplicate writer only rewrites the first durable dirty version"
                );
            }
            use std::io::{Seek, SeekFrom};
            file.seek(SeekFrom::Start(0)).unwrap();
            file.write_all(&bytes)
                .expect("ordinary client writes synthetic dirty bytes");
            file.sync_all()
                .expect("ordinary client flushes synthetic dirty bytes");
            drop(file);
            assert_eq!(std::fs::read(path).unwrap(), bytes);
            emit_marker(if mode == "restart-edit" {
                "synthetic_restart_client=ordinary_open,read,write,flush,close"
            } else {
                "synthetic_restart_client=duplicate_ordinary_open,read,write_same_bytes,flush,close"
            });
            return;
        }

        match std::env::var(PHASE).as_deref() {
            Ok("prepare") | Ok("recover") => {
                let phase = std::env::var(PHASE).expect("phase remains set");
                let root = PathBuf::from(std::env::var_os(ROOT).expect("supervisor supplies root"));
                let state_directory = PathBuf::from(
                    std::env::var_os(STATE).expect("supervisor supplies recovery state"),
                );
                assert!(root.is_dir() && state_directory.is_dir());
                let agent = std::sync::Arc::new(WindowsAgent::new(
                    super::DpapiStore::current_user()
                        .expect("fresh synthetic user's DPAPI session store"),
                ));
                let (session, configuration) = {
                    let mut state = agent.state.lock().unwrap();
                    let session = state
                        .session
                        .clone()
                        .expect("exact DPAPI-backed synthetic session restored");
                    let configuration = state
                        .root_configuration
                        .clone()
                        .expect("exact DPAPI-backed root configuration restored");
                    state.active_generation = agent.generation.load(Ordering::Acquire);
                    state.online_authenticated = true;
                    state.needs_refresh = false;
                    (session, configuration)
                };
                assert_eq!(configuration.path, root.to_string_lossy().as_ref());
                assert_eq!(configuration.server, session.server);
                let owner = configuration
                    .registration_ownership
                    .clone()
                    .expect("verified synthetic Personal ownership");
                assert_eq!(owner.personal_drive_id, "synthetic-personal-drive");
                assert_eq!(
                    owner.personal_root_resource_id.as_deref(),
                    Some("synthetic-personal-root")
                );

                let state_protector = DpapiEditRecordProtector::current_user()
                    .expect("same synthetic SID DPAPI recovery protector");
                let identity = raiun_cloudfiles_windows::ConfiguredRootIdentity {
                    volume_serial: configuration.volume_serial,
                    file_index: configuration.file_index,
                };
                let lease = if phase == "prepare" {
                    raiun_cloudfiles_windows::pin_configured_root(&root)
                        .expect("phase 1 pins exact prepared root")
                } else {
                    raiun_cloudfiles_windows::pin_registered_configured_root(&root, identity)
                        .expect("phase 2 re-pins exact registered root")
                };
                assert_eq!(lease.identity(), identity);
                let client = std::sync::Arc::new(
                    OpenCloudClient::new(&session.server, session.access_token.clone())
                        .expect("synthetic authenticated client"),
                );
                let scope = ProviderScope::new(
                    &client,
                    configuration.profile_scope.clone(),
                    owner.account_id.clone(),
                    client.server_origin().expect("normalized fixture origin"),
                )
                .expect("same persisted account/root scope");
                let recovery = std::sync::Arc::new(DurableEditRecoveryProvider::new(
                    state_directory.clone(),
                    scope.clone(),
                    identity,
                    state_protector.clone(),
                ));
                let backend = std::sync::Arc::new(
                    OpenCloudPlaceholderBackend::new_with_identity_catalog(
                        client.clone(),
                        scope.clone(),
                        identity,
                        recovery.identity_catalog(),
                    )
                    .expect("backend bound to exact synthetic account and root"),
                );
                let recovery_provider: std::sync::Arc<dyn EditRecoveryProvider> = recovery.clone();
                let log_catalog = |label: &str,
                                   records: &[raiun_cloudfiles_windows::LocalEditMetadata],
                                   states: &std::collections::HashMap<
                    String,
                    RecoveryAttemptState,
                >| {
                    for record in records {
                        emit_marker(&format!(
                            "synthetic_restart_catalog={label},record_id={},generation={},path={},etag={},content_len={},content_sha256={},local_state={:?},recovery_state={:?}",
                            record.record_id,
                            record.generation,
                            record.relative_path,
                            record
                                .remote
                                .as_ref()
                                .map(|remote| remote.etag.as_str())
                                .unwrap_or("<none>"),
                            record.content_len,
                            record.content_sha256,
                            record.state,
                            states
                                .get(&record.record_id)
                                .unwrap_or(&RecoveryAttemptState::NotAttempted),
                        ));
                    }
                    emit_marker(&format!(
                        "synthetic_restart_catalog_count={label},count={}",
                        records.len()
                    ));
                };
                let root_identity = lease.identity();
                drop(lease);
                agent
                    .provider
                    .connect(
                        PathBuf::from(&configuration.path),
                        agent.state.lock().unwrap().active_generation,
                        root_identity,
                        phase == "recover",
                        owner.personal_drive_id.clone(),
                        owner
                            .personal_root_resource_id
                            .as_deref()
                            .unwrap()
                            .to_owned(),
                        backend.clone(),
                        recovery_provider,
                        super::windows_bandwidth::Scope::new(
                            &configuration.profile_scope,
                            &session.server,
                            &session.client_id,
                            session.expected_issuer.as_deref(),
                            &owner.account_id,
                        )
                        .expect("bind exact fixture account history")
                        .bytes()
                        .to_vec(),
                        Arc::clone(&agent.session_store),
                    )
                    .expect("agent-owned native lifecycle connects exact synthetic root");

                // Exercise the sync-root's ordinary OS enumeration before
                // traversing its hydrated placeholders. Cloud Files does not
                // issue FETCH_PLACEHOLDERS for the sync-root itself, so the
                // initial root listing must materialize Personal and Spaces.
                let mut root_entries: Vec<_> = std::fs::read_dir(&root)
                    .expect("ordinary OS enumeration of the registered sync root")
                    .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                    .collect();
                root_entries.sort();
                assert_eq!(root_entries, vec!["Personal", "Spaces"]);
                emit_marker("synthetic_restart_root_enumeration=Personal,Spaces");

                let spaces_root = root.join("Spaces");
                report_namespace_directory(
                    &agent,
                    &session.server,
                    &root.join("Personal"),
                    "Personal",
                    &["native-read.bin"],
                );
                report_namespace_directory(
                    &agent,
                    &session.server,
                    &spaces_root,
                    "Spaces",
                    &["Projects"],
                );
                let projects_root = spaces_root.join("Projects");
                report_namespace_directory(
                    &agent,
                    &session.server,
                    &projects_root,
                    "Projects",
                    &["RecoveryRoot", "native-read.bin"],
                );
                let recovery_root = projects_root.join("RecoveryRoot");
                if phase == "prepare" {
                    let executable = std::env::current_exe().expect("current test executable");
                    let trace =
                        PathBuf::from(std::env::var_os(TRACE).expect("phase supplies marker path"));
                    report_namespace_directory(
                        &agent,
                        &session.server,
                        &recovery_root,
                        "RecoveryRoot",
                        &["document.bin", "read-probe.bin"],
                    );
                    let mut recovery_entries: Vec<_> = std::fs::read_dir(&recovery_root)
                        .expect("ordinary OS enumeration of synthetic recovery directory")
                        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                        .collect();
                    recovery_entries.sort();
                    assert_eq!(recovery_entries, ["document.bin", "read-probe.bin"]);
                    emit_marker(
                        "synthetic_restart_recovery_enumeration=document.bin,read-probe.bin",
                    );
                    let snapshot_probe = |path| {
                        let observation = agent
                            .provider
                            .read_only_placeholder_observation(path)
                            .expect("read-only per-leaf Cloud Files observation");
                        (
                            observation,
                            synthetic_remote_read_counts(&session.server),
                            synthetic_native_read_counts(&session.server),
                        )
                    };
                    let differential_probes = [
                        (
                            "personal_native_read",
                            NativeRestartProbePath::PersonalNativeRead,
                            "probe-personal-native-read",
                            b"synthetic Personal native read bytes".len(),
                        ),
                        (
                            "projects_native_read",
                            NativeRestartProbePath::ProjectsNativeRead,
                            "probe-projects-native-read",
                            b"synthetic Projects Space native read bytes".len(),
                        ),
                        (
                            "recovery_document",
                            NativeRestartProbePath::RecoveryDocument,
                            "probe-recovery-document",
                            ORIGINAL.len(),
                        ),
                        (
                            "recovery_read_probe",
                            NativeRestartProbePath::RecoveryReadOnlyProbe,
                            "probe-recovery-read-probe",
                            ORIGINAL.len(),
                        ),
                    ];
                    for (label, path, mode, expected_size) in differential_probes {
                        let before = snapshot_probe(path);
                        let (_, _, _, before_size) = before.0.2.as_ref().unwrap_or_else(|error| {
                            panic!("{label} leaf metadata unavailable before read: {error}")
                        });
                        assert_eq!(
                            *before_size, expected_size as u64,
                            "{label} placeholder has exact synthetic size before read"
                        );
                        let status = run_access_probe(&executable, mode, &root, &trace, test_name);
                        assert!(status.success(), "read-only {label} child completed");
                        let after = snapshot_probe(path);
                        let (_, _, _, after_size) = after.0.2.as_ref().unwrap_or_else(|error| {
                            panic!("{label} leaf metadata unavailable after read: {error}")
                        });
                        assert_eq!(
                            *after_size, expected_size as u64,
                            "{label} placeholder retains exact synthetic size after read"
                        );
                        report_differential_access_probe(label, &before, &after);
                        let probe_markers = read_markers(&trace);
                        assert!(
                            probe_markers.lines().any(|line| {
                                line.starts_with(&format!(
                                    "synthetic_restart_differential_read={mode},"
                                ))
                            }),
                            "read-only {label} child emitted a bounded result marker"
                        );
                    }
                    if std::env::var(SESSION_COMPARE_HOLD).is_ok_and(|value| value == "1") {
                        // Optional test-only gate for a same-SID, different-session
                        // ordinary read. It is placed after all Session 0 leaf
                        // probes and before any explicit hydration fallback.
                        let recovery_document = NativeRestartProbePath::RecoveryDocument;
                        let before = snapshot_probe(recovery_document);
                        let (_, _, _, before_size) = before
                            .0
                            .2
                            .as_ref()
                            .expect("RecoveryRoot/document.bin metadata before session probe");
                        assert_eq!(*before_size, ORIGINAL.len() as u64);
                        let root_name = root
                            .file_name()
                            .expect("synthetic root has a leaf name")
                            .to_string_lossy();
                        let ready_path =
                            root.with_file_name(format!("{root_name}.session-probe.ready"));
                        let completion_path =
                            root.with_file_name(format!("{root_name}.session-probe.complete"));
                        let trace_line_count_before = read_markers(&trace).lines().count();
                        assert!(
                            !ready_path.exists() && !completion_path.exists(),
                            "session comparison markers must be fresh"
                        );
                        let mut ready = std::fs::OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .open(&ready_path)
                            .expect("create the unique bounded session-probe ready marker");
                        ready
                            .write_all(b"ready\n")
                            .expect("write fixed session-probe ready marker");
                        ready.sync_all().expect("flush ready marker");
                        emit_marker(
                            "synthetic_restart_session_compare=ready,leaf=RecoveryRoot/document.bin",
                        );

                        let deadline = Instant::now() + Duration::from_secs(180);
                        let completion = loop {
                            if completion_path.is_file() {
                                let mut bytes = Vec::new();
                                std::fs::File::open(&completion_path)
                                    .expect("open session-probe completion marker")
                                    .take(65)
                                    .read_to_end(&mut bytes)
                                    .expect("read bounded session-probe completion marker");
                                assert!(bytes.len() <= 64, "completion marker is bounded");
                                let completion = String::from_utf8(bytes)
                                    .expect("session-probe completion is ASCII");
                                let completion = completion.trim();
                                assert!(
                                    matches!(
                                        completion,
                                        "probe_exit_0"
                                            | "probe_exit_nonzero"
                                            | "session_assignment_denied"
                                    ),
                                    "completion marker uses a fixed result vocabulary"
                                );
                                break completion.to_owned();
                            }
                            assert!(
                                Instant::now() < deadline,
                                "console-session probe exceeded its three-minute bound; root and recovery are preserved"
                            );
                            thread::sleep(Duration::from_millis(50));
                        };
                        let after = snapshot_probe(recovery_document);
                        let (_, _, _, after_size) = after
                            .0
                            .2
                            .as_ref()
                            .expect("RecoveryRoot/document.bin metadata after session probe");
                        assert_eq!(*after_size, ORIGINAL.len() as u64);
                        report_differential_access_probe(
                            "recovery_document_console_session",
                            &before,
                            &after,
                        );
                        let markers = read_markers(&trace);
                        let probe_result = markers
                            .lines()
                            .skip(trace_line_count_before)
                            .filter(|line| {
                                line.starts_with(
                                    "synthetic_restart_differential_read=probe-recovery-document,",
                                )
                            })
                            .last()
                            .map(|line| line.split_once(',').unwrap().1.to_owned())
                            .unwrap_or_else(|| "no_probe_result_marker".to_owned());
                        emit_marker(&format!(
                            "synthetic_restart_session_compare=complete,wrapper={completion},probe={probe_result}"
                        ));
                    }
                    let run_writer = |mode: &str| {
                        let child = Command::new(&executable)
                            .arg(test_name)
                            .arg("--exact")
                            .arg("--ignored")
                            .arg("--nocapture")
                            .env(CLIENT_MODE, mode)
                            .env(CLIENT_ROOT, &root)
                            .env_remove(PHASE)
                            .env_remove("RAIUN_SYNTHETIC_CFAPI_PATH_GUARD_DIR")
                            .stdout(Stdio::null())
                            .stderr(Stdio::null())
                            .spawn()
                            .expect("start ordinary OS writer process");
                        wait_child(child, mode)
                    };
                    let mut writer_status = run_writer("restart-edit");
                    let mut hydration_mode = "implicit_os_read";
                    let trace = std::env::var_os(TRACE).expect("phase supplies marker path");
                    let implicit_open_was_denied = read_markers(Path::new(&trace))
                        .contains("synthetic_restart_client_open_error=395");
                    if !writer_status.success() && implicit_open_was_denied {
                        // The existing native integration fixture has shown
                        // that this Windows harness can reject implicit
                        // open-triggered hydration before FETCH_DATA. If so,
                        // use its test-only CfHydratePlaceholder seam for this
                        // exact fixed fixture path, then retry the same
                        // ordinary OS writer. This fallback never creates or
                        // changes a recovery record itself.
                        let observation = agent
                            .provider
                            .directory_observation()
                            .expect("inspect bounded native hydration telemetry");
                        let fetch_observation = observation.1;
                        let explicit_hydration = &observation.3;
                        if fetch_observation.0 > 0
                            && explicit_hydration.as_ref().is_ok_and(|result| *result >= 0)
                        {
                            assert_eq!(
                                std::fs::read(recovery_root.join("document.bin"))
                                    .expect("read explicitly hydrated synthetic baseline"),
                                ORIGINAL,
                                "test-only hydration must expose only the original fixture bytes"
                            );
                            emit_marker("synthetic_restart_implicit_open=denied_code_395");
                            hydration_mode = "explicit_test_cfapi_fallback";
                            writer_status = run_writer("restart-edit");
                        } else {
                            panic!(
                                "ordinary OS writer failed without a successful fixed-path hydration fallback; native_observation={observation:?}",
                            );
                        }
                    } else if !writer_status.success() {
                        panic!(
                            "ordinary OS writer failed for a reason other than the known code 395 open denial"
                        );
                    }
                    assert!(
                        writer_status.success(),
                        "ordinary OS writer failed after the bounded test-only hydration fallback"
                    );
                    emit_marker(&format!(
                        "synthetic_restart_hydration_mode={hydration_mode}"
                    ));
                    let expected: Vec<u8> = {
                        let mut bytes = ORIGINAL.to_vec();
                        bytes[0] ^= 0x5a;
                        bytes
                    };
                    let deadline = Instant::now() + Duration::from_secs(30);
                    loop {
                        let records = recovery
                            .unresolved_edits()
                            .expect("inspect DPAPI journal after OS close");
                        if let Some(record) = records
                            .iter()
                            .find(|record| record.relative_path == RELATIVE_PATH)
                        {
                            assert_eq!(record.scope.space_id, "synthetic-project-drive");
                            assert_eq!(record.scope.root_resource_id, "synthetic-project-root");
                            assert_eq!(record.scope.root_volume_serial, identity.volume_serial);
                            assert_eq!(record.scope.root_file_index, identity.file_index);
                            assert_eq!(
                                record.remote.as_ref().map(|remote| remote.etag.as_str()),
                                Some("\"synthetic-file-v1\"")
                            );
                            break;
                        }
                        assert!(
                            Instant::now() < deadline,
                            "native close callback did not persist the pending record within 30 seconds; preserving root and recovery state"
                        );
                        thread::sleep(Duration::from_millis(50));
                    }
                    if successful_duplicate_dispatch {
                        // The first ordinary write-close may yield only one
                        // durable snapshot. Produce another through the OS
                        // file API, never by fabricating a journal row.
                        let current_records = recovery
                            .unresolved_edits()
                            .expect("authenticate first dirty snapshot before duplicate writer");
                        assert!(
                            !current_records.is_empty(),
                            "the ordinary writer must persist its first dirty snapshot before the duplicate write"
                        );
                        let duplicate_status = run_writer("restart-duplicate-edit");
                        assert!(
                            duplicate_status.success(),
                            "second ordinary write-close must preserve the existing dirty bytes"
                        );
                        let duplicate_deadline = Instant::now() + Duration::from_secs(30);
                        loop {
                            let records = recovery
                                .unresolved_edits()
                                .expect("authenticate dirty snapshots after duplicate OS close");
                            let matching_records: Vec<_> = records
                                .iter()
                                .filter(|record| record.relative_path == RELATIVE_PATH)
                                .collect();
                            let distinct_ids: std::collections::HashSet<_> = matching_records
                                .iter()
                                .map(|record| record.record_id.as_str())
                                .collect();
                            if matching_records.len() >= 2 && distinct_ids.len() >= 2 {
                                break;
                            }
                            assert!(
                                Instant::now() < duplicate_deadline,
                                "second ordinary write-close did not persist a second distinct dirty snapshot within 30 seconds; preserving root and recovery state"
                            );
                            thread::sleep(Duration::from_millis(50));
                        }
                        emit_marker(
                            "synthetic_restart_duplicate_snapshots=two_authenticated_records_before_disconnect",
                        );
                    }
                    let journal_scope = EditJournalScope {
                        profile_id: scope.profile_id().to_owned(),
                        server_origin: scope.server_origin().to_owned(),
                        account_subject: scope.account_id().to_owned(),
                        space_id: "synthetic-project-drive".into(),
                        root_resource_id: "synthetic-project-root".into(),
                        root_volume_serial: identity.volume_serial,
                        root_file_index: identity.file_index,
                    };
                    let snapshot =
                        EditJournal::open(&state_directory, journal_scope, state_protector)
                            .and_then(|journal| journal.recover_all())
                            .expect("authenticate phase-1 DPAPI snapshot");
                    log_catalog(
                        "phase1_after_close",
                        &snapshot
                            .records
                            .iter()
                            .map(|record| record.metadata.clone())
                            .collect::<Vec<_>>(),
                        &snapshot.recovery_states,
                    );
                    assert!(
                        (1..=8).contains(&snapshot.records.len()),
                        "ordinary write must leave 1..=8 durable snapshots; preserve all unexpected records"
                    );
                    if successful_duplicate_dispatch {
                        assert!(
                            snapshot.records.len() >= 2,
                            "duplicate dispatch setup must authenticate at least two snapshots before phase-1 disconnect"
                        );
                    }
                    let mut snapshot_ids = std::collections::HashSet::new();
                    for record in &snapshot.records {
                        assert!(snapshot_ids.insert(record.metadata.record_id.as_str()));
                        assert_eq!(record.metadata.relative_path, RELATIVE_PATH);
                        assert_eq!(record.metadata.scope.profile_id, scope.profile_id());
                        assert_eq!(record.metadata.scope.server_origin, scope.server_origin());
                        assert_eq!(record.metadata.scope.account_subject, scope.account_id());
                        assert_eq!(record.metadata.scope.space_id, "synthetic-project-drive");
                        assert_eq!(
                            record.metadata.scope.root_resource_id,
                            "synthetic-project-root"
                        );
                        assert_eq!(record.metadata.content_len, expected.len() as u64);
                        assert_eq!(record.metadata.content_sha256, synthetic_sha256(&expected));
                        assert_eq!(record.content.as_slice(), expected);
                        assert_eq!(record.metadata.state, LocalEditState::Dirty);
                        assert_eq!(
                            record
                                .metadata
                                .remote
                                .as_ref()
                                .map(|remote| remote.etag.as_str()),
                            Some("\"synthetic-file-v1\"")
                        );
                        assert_eq!(
                            snapshot.recovery_states.get(&record.metadata.record_id),
                            None
                        );
                    }
                    assert_eq!(
                        std::fs::read(recovery_root.join("document.bin")).unwrap(),
                        expected
                    );
                    assert!(
                        recovery
                            .has_unresolved_edits()
                            .expect("pending record remains unresolved")
                    );
                    agent
                        .provider
                        .disconnect()
                        .expect("phase 1 gracefully disconnects and preserves registration");
                    emit_marker(
                        "synthetic_restart_phase=prepare,record_persisted=true,dirty_bytes_verified=true,dispatches=0",
                    );
                } else {
                    let records = recovery
                        .unresolved_edits()
                        .expect("reopen phase-1 DPAPI recovery catalog");
                    let journal_scope = EditJournalScope {
                        profile_id: scope.profile_id().to_owned(),
                        server_origin: scope.server_origin().to_owned(),
                        account_subject: scope.account_id().to_owned(),
                        space_id: "synthetic-project-drive".into(),
                        root_resource_id: "synthetic-project-root".into(),
                        root_volume_serial: identity.volume_serial,
                        root_file_index: identity.file_index,
                    };
                    let reopened = EditJournal::open(
                        &state_directory,
                        journal_scope.clone(),
                        state_protector.clone(),
                    )
                    .and_then(|journal| journal.recover_all())
                    .expect("authenticate phase-1 journal before checking catalog size");
                    log_catalog(
                        "phase2_reopen",
                        &reopened
                            .records
                            .iter()
                            .map(|record| record.metadata.clone())
                            .collect::<Vec<_>>(),
                        &reopened.recovery_states,
                    );
                    assert_eq!(records.len(), reopened.records.len());
                    assert!(
                        (1..=8).contains(&records.len()),
                        "phase-1 dirty snapshots must remain in a bounded 1..=8 set"
                    );
                    let mut expected_local = ORIGINAL.to_vec();
                    expected_local[0] ^= 0x5a;
                    let mut record_ids = std::collections::HashSet::new();
                    for record in &records {
                        assert!(record_ids.insert(record.record_id.as_str()));
                        assert_eq!(record.relative_path, RELATIVE_PATH);
                        assert_eq!(record.scope.profile_id, scope.profile_id());
                        assert_eq!(record.scope.server_origin, scope.server_origin());
                        assert_eq!(record.scope.account_subject, scope.account_id());
                        assert_eq!(record.scope.space_id, "synthetic-project-drive");
                        assert_eq!(record.scope.root_resource_id, "synthetic-project-root");
                        assert_eq!(record.scope.root_volume_serial, identity.volume_serial);
                        assert_eq!(record.scope.root_file_index, identity.file_index);
                        assert_eq!(record.content_len, expected_local.len() as u64);
                        assert_eq!(record.content_sha256, synthetic_sha256(&expected_local));
                        assert_eq!(record.state, LocalEditState::Dirty);
                        assert_eq!(
                            record.remote.as_ref().map(|remote| remote.etag.as_str()),
                            Some("\"synthetic-file-v1\"")
                        );
                        let recovered = reopened
                            .records
                            .iter()
                            .find(|entry| entry.metadata.record_id == record.record_id)
                            .expect("each catalog record has its authenticated body");
                        assert_eq!(recovered.content.as_slice(), expected_local);
                        assert_eq!(reopened.recovery_states.get(&record.record_id), None);
                    }
                    assert_eq!(
                        std::fs::read(recovery_root.join("document.bin")).unwrap(),
                        expected_local
                    );
                    let prepared = recovery
                        .prepare(backend.scope(), identity)
                        .expect("preflight same persisted account/root recovery scope");
                    let before = EditJournal::open(
                        &state_directory,
                        journal_scope.clone(),
                        state_protector.clone(),
                    )
                    .and_then(|journal| journal.recover_all())
                    .expect("authenticate recovered phase-1 record");
                    for record in &records {
                        let before_record = before
                            .records
                            .iter()
                            .find(|entry| entry.metadata.record_id == record.record_id)
                            .expect("exact recovered record");
                        assert_eq!(before_record.content.as_slice(), expected_local);
                        assert_eq!(before.recovery_states.get(&record.record_id), None);
                    }
                    let (verified_account, verified_id, verified_personal_root, spaces, context) =
                        verified_account_roots(&client, &session.server)
                            .expect("revalidate synthetic account after restart");
                    assert_eq!(verified_account, owner.personal_drive_id);
                    assert_eq!(verified_id, owner.account_id);
                    assert_eq!(
                        verified_personal_root,
                        owner.personal_root_resource_id.as_deref().unwrap()
                    );
                    let project_space = spaces
                        .iter()
                        .find(|space| space.id == "synthetic-project-drive")
                        .expect("exact writable fixture Space");
                    let project_root = client
                        .stat_discovered_space_root_with_context(project_space, context)
                        .expect("verify exact Space root after restart");
                    assert_eq!(project_root.id, "synthetic-project-root");
                    let inner_remote: std::sync::Arc<dyn raiun_cloudfiles_windows::RecoveryRemote> =
                        std::sync::Arc::new(
                            OpenCloudRecoveryRemote::new(
                                client.clone(),
                                journal_scope.clone(),
                                project_root.path.clone(),
                                client.token_generation(),
                            )
                            .expect("bind conflict check to same remote scope and generation"),
                        );
                    let remote: std::sync::Arc<dyn raiun_cloudfiles_windows::RecoveryRemote> =
                        std::sync::Arc::new(AgentGenerationRecoveryRemote {
                            inner: RecoveryRemoteHandle::Owned(inner_remote),
                            authorized_generation: std::sync::Arc::clone(
                                &agent.provider.authorized_generation,
                            ),
                            expected_generation: agent.state.lock().unwrap().active_generation,
                        });
                    let mut success_attempts = std::collections::BTreeMap::new();
                    for record in &records {
                        let outcome = agent.provider.dispatch_recovery(
                            agent.state.lock().unwrap().active_generation,
                            prepared.clone(),
                            record.record_id.clone(),
                            record.generation,
                            remote.clone(),
                        ).expect("agent-generation-fenced recovery dispatch must durably complete or fail closed");
                        if successful_duplicate_dispatch {
                            let attempts = match outcome {
                                raiun_cloudfiles_windows::ReconciliationOutcome::VerifiedApplied { attempts } => attempts,
                                other => panic!("duplicate dispatch must verify applied bytes, got {other:?}"),
                            };
                            success_attempts.insert(record.record_id.clone(), attempts);
                        } else {
                            assert_eq!(
                                outcome,
                                raiun_cloudfiles_windows::ReconciliationOutcome::Conflict(
                                    raiun_cloudfiles_windows::ReconciliationIssue::ContentMismatch,
                                )
                            );
                        }
                    }
                    if successful_duplicate_dispatch {
                        assert!(
                            records.len() >= 2,
                            "duplicate dispatch requires at least two snapshots"
                        );
                        assert_eq!(
                            success_attempts.len(),
                            records.len(),
                            "every retained snapshot was dispatched"
                        );
                        assert_eq!(
                            success_attempts
                                .values()
                                .filter(|attempts| **attempts == 1)
                                .count(),
                            1,
                            "exactly one snapshot performs a conditional upload"
                        );
                        assert_eq!(
                            success_attempts
                                .values()
                                .filter(|attempts| **attempts == 0)
                                .count(),
                            records.len() - 1,
                            "remaining snapshots verify the uploaded bytes without another upload"
                        );
                    }
                    let after = EditJournal::open(&state_directory, journal_scope, state_protector)
                        .and_then(|journal| journal.recover_all())
                        .expect("reopen durable conflict after restart");
                    assert_eq!(after.records.len(), records.len());
                    for record in &records {
                        let expected_state = if successful_duplicate_dispatch {
                            let attempts = *success_attempts
                                .get(&record.record_id)
                                .expect("every duplicate record was dispatched");
                            RecoveryAttemptState::VerifiedApplied {
                                attempt_id: if attempts == 0 { 0 } else { 1 },
                                attempts,
                            }
                        } else {
                            RecoveryAttemptState::Conflict {
                                attempt_id: 0,
                                attempts: 0,
                            }
                        };
                        assert_eq!(
                            after.recovery_states.get(&record.record_id),
                            Some(&expected_state)
                        );
                        assert_eq!(
                            after
                                .records
                                .iter()
                                .find(|entry| entry.metadata.record_id == record.record_id)
                                .expect("terminal outcome keeps every dirty body")
                                .content
                                .as_slice(),
                            expected_local
                        );
                    }
                    assert_eq!(
                        std::fs::read(recovery_root.join("document.bin")).unwrap(),
                        expected_local
                    );
                    agent
                        .provider
                        .disconnect()
                        .expect("phase 2 drains callbacks and preserves the registered root");
                    if successful_duplicate_dispatch {
                        emit_marker(
                            "synthetic_restart_phase=recover,duplicate_dispatch_verified=true,local_preserved=true,unregister_attempted=false",
                        );
                    } else {
                        let unregister_lease =
                            raiun_cloudfiles_windows::pin_registered_configured_root(
                                &root, identity,
                            )
                            .expect("only the exact previously registered root is re-pinned");
                        let unregister_recovery: std::sync::Arc<dyn EditRecoveryProvider> =
                            recovery.clone();
                        let unregister_backend = std::sync::Arc::new(
                            OpenCloudPlaceholderBackend::new_with_identity_catalog(
                                client.clone(),
                                scope.clone(),
                                identity,
                                recovery.identity_catalog(),
                            )
                            .expect(
                                "fresh backend for unregister refusal check after manager revocation",
                            ),
                        );
                        let unregister_connection = synthetic_agent_integration::connect(
                            unregister_lease,
                            unregister_backend.clone(),
                            &owner.personal_drive_id,
                            owner.personal_root_resource_id.as_deref().unwrap(),
                            unregister_recovery,
                        ).expect("native registration remains available for explicit unregister refusal check");
                        unregister_backend.revoke();
                        assert!(
                            matches!(
                                unregister_connection.unregister(),
                                Err(raiun_cloudfiles_windows::Error::UnresolvedPlaceholderEdits)
                            ),
                            "unregister must remain refused while conflict records are retained"
                        );
                        emit_marker(
                            "synthetic_restart_phase=recover,conflict_durable=true,local_preserved=true,unregister_refused=true",
                        );
                    }
                }
                drop(agent);
                return;
            }
            _ => {}
        }

        // The supervisor itself never connects Cloud Files. It persists only
        // the synthetic fixture session/root and holds the loopback server
        // across both fresh agent processes so its remote body and request
        // counters can be changed and checked without fabricating a journal.
        let (server, fixture) =
            synthetic_personal_spaces_server_inner_with_restart_probe(|_| {}, true, true);
        let store = super::DpapiStore::current_user().expect("fresh synthetic SID DPAPI store");
        assert!(
            store
                .store
                .active_identity()
                .expect("read fresh synthetic active pointer")
                .is_none(),
            "acceptance requires a newly created empty synthetic user profile"
        );
        let session = synthetic_session(&server, "synthetic-client", unix_time_now() + 3600);
        store
            .save_pending("default", &session)
            .expect("persist synthetic session with current-user DPAPI");
        store
            .publish_active("default", &session)
            .expect("persist active synthetic account identity");
        let root = std::env::temp_dir().join(format!(
            "Raiun-Agent-Prepared-Runtime-restart-{}-{}",
            std::process::id(),
            unix_time_now()
        ));
        std::fs::create_dir(&root).expect("create unique synthetic registered root");
        let setup_agent = std::sync::Arc::new(WindowsAgent::new(
            super::DpapiStore::current_user().unwrap(),
        ));
        {
            let mut state = setup_agent.state.lock().unwrap();
            state.active_generation = setup_agent.generation.load(Ordering::Acquire);
            state.online_authenticated = true;
            state.needs_refresh = false;
        }
        setup_agent
            .handle_request(&json!({"action":"configure", "cloud_root":root.to_string_lossy()}))
            .expect("persist exact synthetic root configuration");
        let configuration = setup_agent
            .state
            .lock()
            .unwrap()
            .root_configuration
            .clone()
            .expect("configured root persisted");
        assert!(configuration.valid && configuration.registration_ownership.is_some());
        drop(setup_agent);
        let protector =
            DpapiEditRecordProtector::current_user().expect("current-user test protector");
        let state_directory = protector.local_state_directory().join(format!(
            "agent-restart-test-{}-{}",
            std::process::id(),
            unix_time_now()
        ));
        std::fs::create_dir(&state_directory).expect("create unique DPAPI recovery scope");
        protector
            .protect_directory(&state_directory)
            .expect("protect synthetic restart recovery state");

        let executable = std::env::current_exe().expect("current test executable");
        let phase1_markers = run_phase(&executable, "prepare", &root, &state_directory, test_name);
        assert_eq!(
            std::fs::read(root.join("Spaces/Projects/RecoveryRoot/document.bin"))
                .expect("phase-1 dirty file remains"),
            {
                let mut bytes = ORIGINAL.to_vec();
                bytes[0] ^= 0x5a;
                bytes
            }
        );
        let mut expected_dirty = ORIGINAL.to_vec();
        expected_dirty[0] ^= 0x5a;
        let remote_bytes = b"external remote version changed after process exit".to_vec();
        {
            let mut remote = fixture.recovery.lock().unwrap();
            assert_eq!(remote.put_count, 0, "phase 1 must not dispatch any upload");
            if successful_duplicate_dispatch {
                assert_eq!(remote.body.as_slice(), ORIGINAL);
                assert_eq!(remote.etag, "\"synthetic-file-v1\"");
            } else {
                remote.body = remote_bytes.clone();
                remote.etag = "\"synthetic-file-v2-external\"".into();
            }
        }
        let phase2_get_count_before = fixture.recovery.lock().unwrap().get_count;
        let phase2_markers = run_phase(&executable, "recover", &root, &state_directory, test_name);
        assert_eq!(
            catalog_fingerprints(&phase1_markers, "phase1_after_close"),
            catalog_fingerprints(&phase2_markers, "phase2_reopen"),
            "phase 2 must recover exactly the phase-1 record IDs, generations, bindings and snapshot hashes"
        );
        {
            if successful_duplicate_dispatch {
                let expected_records =
                    catalog_fingerprints(&phase1_markers, "phase1_after_close").len();
                assert!(
                    expected_records >= 2,
                    "success case requires duplicate journal records"
                );
                let (final_etag, final_body) =
                    synthetic_conditional_remote_readback(&server, "\"synthetic-file-v2\"");
                assert_eq!(final_etag, "\"synthetic-file-v2\"");
                assert_eq!(
                    final_body, expected_dirty,
                    "final conditional readback matches exact dirty bytes"
                );
                let remote = fixture.recovery.lock().unwrap();
                assert_eq!(
                    remote.body, expected_dirty,
                    "verified readback matches local dirty bytes"
                );
                assert_eq!(remote.etag, "\"synthetic-file-v2\"");
                assert_eq!(
                    remote.put_count, 1,
                    "duplicate snapshots produce one conditional PUT"
                );
                assert_eq!(
                    remote.last_put_if_match.as_deref(),
                    Some("\"synthetic-file-v1\"")
                );
                assert_eq!(
                    remote.get_count.saturating_sub(phase2_get_count_before),
                    expected_records + 1,
                    "each duplicate is read back, plus the final conditional body check"
                );
                assert_eq!(
                    remote.last_read_if_match.as_deref(),
                    Some("\"synthetic-file-v2\"")
                );
            } else {
                let remote = fixture.recovery.lock().unwrap();
                assert_eq!(
                    remote.body, remote_bytes,
                    "phase 2 must preserve the externally changed remote bytes"
                );
                assert_eq!(remote.etag, "\"synthetic-file-v2-external\"");
                assert_eq!(remote.put_count, 0, "a conflict must not send a PUT");
                assert_eq!(remote.last_put_if_match, None);
            }
        }
        assert_eq!(
            fixture.native_reads.lock().unwrap().mutation_attempt_count,
            0,
            "synthetic fixture rejects and counts any PUT/DELETE/MOVE attempt"
        );
        assert_eq!(
            std::fs::read(root.join("Spaces/Projects/RecoveryRoot/document.bin")).unwrap(),
            {
                let mut bytes = ORIGINAL.to_vec();
                bytes[0] ^= 0x5a;
                bytes
            }
        );
        let final_put_count = fixture.recovery.lock().unwrap().put_count;
        assert_eq!(final_put_count, usize::from(successful_duplicate_dispatch));
        if successful_duplicate_dispatch {
            let record_count = catalog_fingerprints(&phase1_markers, "phase1_after_close").len();
            println!(
                "synthetic_restart_duplicate_acceptance=passed,processes=2,records={record_count},put_count=1,delete_count=0,move_count=0,root_and_recovery=preserved"
            );
        } else {
            println!(
                "synthetic_restart_acceptance=passed,processes=2,put_count=0,delete_count=0,move_count=0,root_and_recovery=preserved"
            );
        }
        fixture.join().unwrap();
    }

    #[test]
    fn registration_ownership_requires_verified_personal_drive_and_exact_local_identity() {
        let spaces = vec![CloudSpace {
            id: "personal-drive-a".into(),
            name: "Personal".into(),
            dav_url: "https://synthetic.example/dav/personal/personal-drive-a".into(),
            personal: true,
            writable: true,
            encrypted: false,
        }];
        let (personal_id, account_id) =
            verified_personal_identity_from_spaces("https://synthetic.example", &spaces)
                .expect("one usable Personal drive establishes the account identity");
        assert_eq!(personal_id, "personal-drive-a");
        let owner = RegistrationOwnership {
            state: "prepared_not_registered".into(),
            account_id,
            personal_drive_id: personal_id,
            personal_root_resource_id: Some("personal-root-a".into()),
            volume_serial: 17,
            file_index: 29,
        };
        assert!(
            validate_registration_ownership(&owner, "https://synthetic.example", 17, 29).is_ok()
        );
        assert!(validate_registration_ownership(&owner, "https://other.example", 17, 29).is_err());
        assert!(
            validate_registration_ownership(&owner, "https://synthetic.example", 17, 30).is_err()
        );

        let duplicate_personal = [spaces[0].clone(), spaces[0].clone()];
        assert!(
            verified_personal_identity_from_spaces(
                "https://synthetic.example",
                &duplicate_personal
            )
            .is_err()
        );
    }

    #[test]
    fn legacy_root_configuration_is_kept_unbound_and_cannot_become_registration_owner() {
        let store = Arc::new(MemoryStore::default());
        let session = synthetic_session(
            "https://synthetic.example",
            "synthetic-client",
            unix_time_now() + 3600,
        );
        let legacy = json!({
            "version": 1,
            "profile_scope": "default",
            "server": session.server,
            "client_id": session.client_id,
            "issuer": session.expected_issuer,
            "path": "C:\\Raiun\\SyntheticDrive",
            "volume_serial": 17,
            "file_index": 29,
        });
        store
            .save_root_config(
                "default",
                &session.server,
                &session.client_id,
                &serde_json::to_vec(&legacy).unwrap(),
            )
            .unwrap();
        let stored: Arc<dyn SessionStore> = store;
        let loaded = load_root_configuration(&stored, "default", &session)
            .unwrap()
            .expect("legacy selected root remains available for review");
        assert!(loaded.registration_ownership.is_none());
        assert!(!loaded.valid);
        let migrated_bytes = encode_root_configuration(&loaded).unwrap();
        let migrated: Value = serde_json::from_slice(&migrated_bytes).unwrap();
        assert_eq!(migrated["version"], 3);
        assert!(migrated["registration_ownership"].is_null());
    }

    fn read_request(stream: &TcpStream) -> (String, Vec<u8>) {
        let (request, _, body) = read_request_with_headers(stream);
        (request, body)
    }

    fn read_request_with_headers(stream: &TcpStream) -> (String, Vec<(String, String)>, Vec<u8>) {
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let first = line.trim_end().to_owned();
        let mut content_length = 0usize;
        let mut headers = Vec::new();
        loop {
            line.clear();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" || line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.trim_end().split_once(':') {
                headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
            }
            if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                content_length = value.trim().parse().unwrap_or(0);
            }
        }
        let mut body = vec![0; content_length];
        reader.read_exact(&mut body).unwrap();
        (first, headers, body)
    }

    fn respond(stream: &mut TcpStream, status: u16, body: &str) {
        let description = if status == 200 { "OK" } else { "Not Found" };
        write!(stream, "HTTP/1.1 {status} {description}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
    }

    struct SyntheticRecoveryFile {
        present: bool,
        body: Vec<u8>,
        etag: String,
        put_count: usize,
        get_count: usize,
        range_count: usize,
        range_bytes: usize,
        last_put_if_match: Option<String>,
        last_read_if_match: Option<String>,
    }

    struct SyntheticVaultUploadFixture {
        enabled: bool,
        ciphertext: Vec<u8>,
        etag: String,
        resource_id: &'static str,
        put_attempt_count: usize,
        put_count: usize,
        max_successful_puts: usize,
        body_get_count: usize,
        last_put_if_match: Option<String>,
        last_read_if_match: Option<String>,
        forbidden_mutation_count: usize,
    }

    struct SyntheticPersonalSpacesFixture {
        stop: std::sync::mpsc::Sender<()>,
        worker: thread::JoinHandle<()>,
        recovery: Arc<Mutex<SyntheticRecoveryFile>>,
        native_reads: Arc<Mutex<SyntheticNativeReadFixture>>,
        vault_upload: Option<Arc<Mutex<SyntheticVaultUploadFixture>>>,
    }

    #[derive(Default)]
    struct SyntheticNativeReadFixture {
        vault_get_count: usize,
        request_count: usize,
        files_enabled: bool,
        personal_depth_one_propfind_count: usize,
        personal_get_count: usize,
        personal_range_count: usize,
        personal_range_bytes: usize,
        project_get_count: usize,
        project_range_count: usize,
        project_range_bytes: usize,
        personal_hydration_mode: Option<&'static str>,
        project_hydration_mode: Option<&'static str>,
        etag_mismatch_count: usize,
        mutation_attempt_count: usize,
    }

    impl SyntheticPersonalSpacesFixture {
        fn join(self) -> thread::Result<()> {
            let _ = self.stop.send(());
            self.worker.join()
        }
    }

    fn synthetic_personal_spaces_server(
        emit_stage: impl Fn(&str),
    ) -> (String, SyntheticPersonalSpacesFixture) {
        synthetic_personal_spaces_server_inner(emit_stage, false)
    }

    fn synthetic_personal_spaces_server_with_native_read_files(
        emit_stage: impl Fn(&str),
    ) -> (String, SyntheticPersonalSpacesFixture) {
        synthetic_personal_spaces_server_inner(emit_stage, true)
    }

    fn synthetic_personal_spaces_server_inner(
        emit_stage: impl Fn(&str),
        native_read_files_enabled: bool,
    ) -> (String, SyntheticPersonalSpacesFixture) {
        synthetic_personal_spaces_server_inner_with_restart_probe(
            emit_stage,
            native_read_files_enabled,
            false,
        )
    }

    fn synthetic_personal_spaces_server_inner_with_restart_probe(
        emit_stage: impl Fn(&str),
        native_read_files_enabled: bool,
        recovery_read_probe_enabled: bool,
    ) -> (String, SyntheticPersonalSpacesFixture) {
        synthetic_personal_spaces_server_inner_with_media_leaf(
            emit_stage,
            native_read_files_enabled,
            recovery_read_probe_enabled,
            false,
        )
    }

    fn synthetic_personal_spaces_server_with_absent_media_leaf(
        emit_stage: impl Fn(&str),
    ) -> (String, SyntheticPersonalSpacesFixture) {
        synthetic_personal_spaces_server_inner_with_media_leaf(emit_stage, true, false, true)
    }

    fn synthetic_personal_spaces_server_inner_with_media_leaf(
        emit_stage: impl Fn(&str),
        native_read_files_enabled: bool,
        recovery_read_probe_enabled: bool,
        initially_absent: bool,
    ) -> (String, SyntheticPersonalSpacesFixture) {
        synthetic_personal_spaces_server_inner_with_vault(
            emit_stage,
            native_read_files_enabled,
            recovery_read_probe_enabled,
            initially_absent,
            false,
        )
    }

    fn synthetic_personal_spaces_server_inner_with_vault(
        emit_stage: impl Fn(&str),
        native_read_files_enabled: bool,
        recovery_read_probe_enabled: bool,
        initially_absent: bool,
        initialized_vault: bool,
    ) -> (String, SyntheticPersonalSpacesFixture) {
        synthetic_personal_spaces_server_inner_with_vault_payload(
            emit_stage,
            native_read_files_enabled,
            recovery_read_probe_enabled,
            initially_absent,
            initialized_vault,
            false,
        )
    }

    fn synthetic_personal_spaces_server_inner_with_vault_payload(
        emit_stage: impl Fn(&str),
        native_read_files_enabled: bool,
        recovery_read_probe_enabled: bool,
        initially_absent: bool,
        initialized_vault: bool,
        vault_payload: bool,
    ) -> (String, SyntheticPersonalSpacesFixture) {
        synthetic_personal_spaces_server_inner_with_vault_upload(
            emit_stage,
            native_read_files_enabled,
            recovery_read_probe_enabled,
            initially_absent,
            initialized_vault,
            vault_payload,
            false,
        )
    }

    fn synthetic_personal_spaces_server_inner_with_vault_upload(
        emit_stage: impl Fn(&str),
        native_read_files_enabled: bool,
        recovery_read_probe_enabled: bool,
        initially_absent: bool,
        initialized_vault: bool,
        vault_payload: bool,
        allow_vault_upload: bool,
    ) -> (String, SyntheticPersonalSpacesFixture) {
        assert!(!allow_vault_upload || (initialized_vault && vault_payload));
        emit_stage("listener_bind_begin");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| {
            emit_stage(&format!("listener_bind_error_kind_{:?}", error.kind()));
            if let Some(code) = error.raw_os_error() {
                emit_stage(&format!("listener_bind_error_code_{code}"));
            }
            panic!("synthetic loopback fixture listener could not bind");
        });
        emit_stage("listener_bound");
        let address = listener.local_addr().unwrap_or_else(|error| {
            emit_stage("listener_local_addr_error");
            panic!(
                "synthetic fixture local address unavailable: {:?}",
                error.kind()
            );
        });
        emit_stage("listener_address_ready");
        let server = format!("http://{address}");
        let worker_server = server.clone();
        let webdav = format!("{server}/remote.php/dav/personal/synthetic-personal-drive");
        let recovery = Arc::new(Mutex::new(SyntheticRecoveryFile {
            present: !initially_absent,
            body: if initially_absent {
                Vec::new()
            } else {
                b"original synthetic placeholder bytes".to_vec()
            },
            etag: "\"synthetic-file-v1\"".into(),
            put_count: 0,
            get_count: 0,
            range_count: 0,
            range_bytes: 0,
            last_put_if_match: None,
            last_read_if_match: None,
        }));
        let worker_recovery = Arc::clone(&recovery);
        let native_reads = Arc::new(Mutex::new(SyntheticNativeReadFixture {
            files_enabled: native_read_files_enabled,
            ..SyntheticNativeReadFixture::default()
        }));
        let worker_native_reads = Arc::clone(&native_reads);
        let vault_upload = allow_vault_upload.then(|| {
            Arc::new(Mutex::new(SyntheticVaultUploadFixture {
                enabled: false,
                ciphertext: include_bytes!("../../raiun-vault/tests/fixtures/web-65537.bin")
                    .to_vec(),
                etag: "\"child-rev-1\"".into(),
                resource_id: "child-resource-id",
                put_attempt_count: 0,
                put_count: 0,
                max_successful_puts: 1,
                body_get_count: 0,
                last_put_if_match: None,
                last_read_if_match: None,
                forbidden_mutation_count: 0,
            }))
        });
        let worker_vault_upload = vault_upload.as_ref().map(Arc::clone);
        listener.set_nonblocking(true).unwrap_or_else(|error| {
            emit_stage("listener_nonblocking_error");
            panic!(
                "synthetic listener nonblocking setup failed: {:?}",
                error.kind()
            );
        });
        emit_stage("listener_nonblocking_ready");
        let (stop, stop_receiver) = std::sync::mpsc::channel();
        let worker = thread::spawn(move || {
            let mut expected_access = "Bearer synthetic-access-token";
            loop {
                if stop_receiver.try_recv().is_ok() {
                    break;
                }
                let (mut request_stream, _) = match listener.accept() {
                    Ok(accepted) => accepted,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("synthetic namespace listener failed: {error}"),
                };
                request_stream
                    .set_nonblocking(false)
                    .expect("accepted synthetic request stream is blocking");
                request_stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("bound synthetic request reads");
                let (request, headers, body) = read_request_with_headers(&request_stream);
                worker_native_reads.lock().unwrap().request_count += 1;
                // Count forbidden methods without granting them a handler.
                // The existing initialized-vault assertion still rejects them.
                if ["DELETE ", "MOVE "]
                    .iter()
                    .any(|method| request.starts_with(method))
                    && let Some(remote) = worker_vault_upload.as_ref()
                {
                    remote.lock().unwrap().forbidden_mutation_count += 1;
                }
                if request.starts_with("GET /__test/remote_counts ") {
                    let snapshot = worker_recovery.lock().unwrap();
                    let counters = format!(
                        "{},{},{}",
                        snapshot.get_count, snapshot.range_count, snapshot.range_bytes
                    );
                    write!(request_stream, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{counters}", counters.len()).unwrap();
                    continue;
                }
                if request.starts_with("GET /__test/native_read_counts ") {
                    let snapshot = worker_native_reads.lock().unwrap();
                    let counters = format!(
                        "{},{},{},{},{},{}",
                        snapshot.personal_get_count,
                        snapshot.personal_range_count,
                        snapshot.personal_range_bytes,
                        snapshot.project_get_count,
                        snapshot.project_range_count,
                        snapshot.project_range_bytes,
                    );
                    write!(request_stream, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{counters}", counters.len()).unwrap();
                    continue;
                }
                let vault_child_path = "/remote.php/dav/personal/synthetic-personal-drive/Travel.vault/9cmn80lns8obm4t3koceogil20";
                if initialized_vault {
                    let exact_opt_in_put = request.starts_with("PUT ")
                        && request.split_whitespace().nth(1) == Some(vault_child_path)
                        && worker_vault_upload
                            .as_ref()
                            .is_some_and(|state| state.lock().unwrap().enabled);
                    assert!(
                        request.starts_with("GET ")
                            || request.starts_with("PROPFIND ")
                            || exact_opt_in_put,
                        "initialized vault fixture permits no remote mutation"
                    );
                }
                if request.starts_with("POST /token ") {
                    let form: HashMap<String, String> =
                        url::form_urlencoded::parse(&body).into_owned().collect();
                    assert_eq!(
                        form.get("grant_type").map(String::as_str),
                        Some("refresh_token")
                    );
                    assert_eq!(
                        form.get("refresh_token").map(String::as_str),
                        Some("synthetic-refresh-token")
                    );
                    assert_eq!(
                        form.get("client_id").map(String::as_str),
                        Some("synthetic-client")
                    );
                    expected_access = "Bearer rotated-native-access-token";
                    respond(
                        &mut request_stream,
                        200,
                        r#"{"access_token":"rotated-native-access-token","refresh_token":"rotated-native-refresh-token","expires_in":3600}"#,
                    );
                    continue;
                }
                let authorization = headers
                    .iter()
                    .find(|(name, _)| name == "authorization")
                    .map(|(_, value)| value.as_str());
                if authorization != Some(expected_access) {
                    write!(request_stream, "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                    continue;
                }
                // Common bearer-auth gate above must precede every opt-in mutation.
                if request.starts_with("PUT ")
                    && request.split_whitespace().nth(1) == Some(vault_child_path)
                    && let Some(remote) = worker_vault_upload.as_ref()
                {
                    let mut remote = remote.lock().unwrap();
                    assert!(remote.enabled);
                    remote.put_attempt_count += 1;
                    let condition = headers
                        .iter()
                        .find(|(name, _)| name == "if-match")
                        .map(|(_, value)| value.as_str());
                    if condition != Some(remote.etag.as_str())
                        || remote.put_count >= remote.max_successful_puts
                        || (remote.etag != "\"child-rev-1\""
                            && !(remote.max_successful_puts == 2
                                && remote.put_count == 1
                                && remote.etag == "\"child-rev-2\""))
                        || headers.iter().any(|(name, _)| name == "if-none-match")
                        || body.is_empty()
                        || body.len() > 1024 * 1024
                    {
                        write!(request_stream, "HTTP/1.1 412 Precondition Failed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                        continue;
                    }
                    remote.last_put_if_match = condition.map(str::to_owned);
                    remote.put_count += 1;
                    remote.ciphertext = body;
                    remote.etag = format!("\"child-rev-{}\"", remote.put_count + 1);
                    write!(request_stream, "HTTP/1.1 204 No Content\r\nETag: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", remote.etag).unwrap();
                    continue;
                }
                let vault_child = if initialized_vault
                    && vault_payload
                    && let Some(remote) = worker_vault_upload.as_ref()
                {
                    let remote = remote.lock().unwrap();
                    format!(
                        r#"<d:response><d:href>{worker_server}{vault_child_path}</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>{}</d:getcontentlength><d:getetag>{}</d:getetag><oc:fileid>{}</oc:fileid><oc:name>9cmn80lns8obm4t3koceogil20</oc:name><oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"#,
                        remote.ciphertext.len(),
                        remote.etag,
                        remote.resource_id
                    )
                } else if initialized_vault && vault_payload {
                    format!(
                        r#"<d:response><d:href>{worker_server}{vault_child_path}</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>{}</d:getcontentlength><d:getetag>"child-rev-1"</d:getetag><oc:fileid>child-resource-id</oc:fileid><oc:name>9cmn80lns8obm4t3koceogil20</oc:name><oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"#,
                        include_bytes!("../../raiun-vault/tests/fixtures/web-65537.bin").len()
                    )
                } else {
                    String::new()
                };
                if initialized_vault
                    && vault_payload
                    && request.starts_with("PROPFIND ")
                    && request.split_whitespace().nth(1) == Some(vault_child_path)
                {
                    let xml = format!(
                        r#"<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">{vault_child}</d:multistatus>"#
                    );
                    write!(request_stream, "HTTP/1.1 207 Multi-Status\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{xml}", xml.len()).unwrap();
                    continue;
                }
                if initialized_vault && request.starts_with("PROPFIND ") {
                    let path = request.split_whitespace().nth(1).unwrap();
                    if path.trim_end_matches('/')
                        == "/remote.php/dav/personal/synthetic-personal-drive/Travel.vault"
                    {
                        let token = include_str!(
                            "../../raiun-vault/tests/fixtures/web-integrity-token.b64"
                        )
                        .trim();
                        let xml = format!(
                            r#"<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:ocrclone="ocrclone"><d:response><d:href>{worker_server}/remote.php/dav/personal/synthetic-personal-drive/Travel.vault/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getcontentlength>0</d:getcontentlength><d:getetag>"vault-v1"</d:getetag><d:getcontenttype>application/vnd.opencloud.vault</d:getcontenttype><oc:fileid>synthetic-vault-root</oc:fileid><oc:name>Travel.vault</oc:name><oc:size>0</oc:size><oc:permissions>RDNVW</oc:permissions><ocrclone:integrity-id>{token}</ocrclone:integrity-id></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#
                        );
                        let xml = if vault_payload
                            && headers
                                .iter()
                                .any(|(name, value)| name == "depth" && value == "1")
                        {
                            xml.replace(
                                "</d:multistatus>",
                                &(vault_child.clone() + "</d:multistatus>"),
                            )
                        } else {
                            xml
                        };
                        write!(request_stream, "HTTP/1.1 207 Multi-Status\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{xml}", xml.len()).unwrap();
                        continue;
                    }
                }
                if initialized_vault && request.starts_with("GET /remote.php/dav/personal/synthetic-personal-drive/Travel.vault/9cmn80lns8obm4t3koceogil20 ") {
                    if let Some(remote) = worker_vault_upload.as_ref() {
                        let mut remote = remote.lock().unwrap();
                        let condition = headers.iter().find(|(name,_)| name == "if-match").map(|(_,value)| value.as_str());
                        if condition != Some(remote.etag.as_str()) {
                            write!(request_stream, "HTTP/1.1 412 Precondition Failed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                            continue;
                        }
                        worker_native_reads.lock().unwrap().vault_get_count += 1;
                        if remote.put_count != 0 {
                            remote.body_get_count += 1;
                            remote.last_read_if_match = condition.map(str::to_owned);
                        }
                        write!(request_stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: {}\r\nConnection: close\r\n\r\n", remote.ciphertext.len(), remote.etag).unwrap();
                        request_stream.write_all(&remote.ciphertext).unwrap();
                        continue;
                    }
                    if vault_payload {
                        worker_native_reads.lock().unwrap().vault_get_count += 1;
                    }
                    let bytes = include_bytes!("../../raiun-vault/tests/fixtures/web-65537.bin");
                    assert!(headers.iter().any(|(name, value)| name == "if-match" && value == "\"child-rev-1\""));
                    write!(request_stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", bytes.len()).unwrap();
                    request_stream.write_all(bytes).unwrap();
                    continue;
                }
                if request.starts_with("GET /graph/v1.0/me/drives") {
                    let response = json!({
                        "value": [{
                            "id": "synthetic-personal-drive",
                            "name": "Personal",
                            "driveType": "personal",
                            "root": {"webDavUrl": webdav, "permissions": ["read", "write"]}
                        }, {
                            "id": "synthetic-project-drive",
                            "name": "Projects",
                            "driveType": "project",
                            "root": {"webDavUrl": format!("{worker_server}/remote.php/dav/projects/synthetic-project-drive"), "permissions": ["read", "write"]}
                        }]
                    })
                    .to_string();
                    respond(&mut request_stream, 200, &response);
                } else if request.starts_with("PROPFIND ") {
                    let path = request.split_whitespace().nth(1).unwrap_or("/");
                    let normalized = path.trim_end_matches('/');
                    let project_prefix =
                        "/remote.php/dav/projects/synthetic-project-drive";
                    let (root_id, name, is_directory, etag, size) =
                        if native_read_files_enabled
                            && normalized
                                == "/remote.php/dav/personal/synthetic-personal-drive/native-read.bin"
                        {
                            ("synthetic-personal-native-read", "native-read.bin", false, "\"synthetic-personal-native-read-v1\"".to_owned(), b"synthetic Personal native read bytes".len())
                        } else if native_read_files_enabled
                            && normalized
                                == "/remote.php/dav/projects/synthetic-project-drive/native-read.bin"
                        {
                            ("synthetic-project-native-read", "native-read.bin", false, "\"synthetic-project-native-read-v1\"".to_owned(), b"synthetic Projects Space native read bytes".len())
                        } else if normalized == "/remote.php/dav/personal/synthetic-personal-drive" {
                            ("synthetic-personal-root", "Personal", true, "\"synthetic-personal-root-etag\"".to_owned(), 0)
                        } else if normalized == project_prefix {
                            ("synthetic-project-root", "Projects", true, "\"synthetic-project-root-etag\"".to_owned(), 0)
                        } else if normalized == format!("{project_prefix}/RecoveryRoot") {
                            ("synthetic-recovery-directory", "RecoveryRoot", true, "\"synthetic-recovery-directory-etag\"".to_owned(), 0)
                        } else if normalized == format!("{project_prefix}/RecoveryRoot/document.bin") {
                            let snapshot = worker_recovery.lock().unwrap();
                            if !snapshot.present {
                                write!(request_stream, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                                continue;
                            }
                            ("synthetic-recovery-file", "document.bin", false, snapshot.etag.clone(), snapshot.body.len())
                        } else if recovery_read_probe_enabled
                            && normalized == format!("{project_prefix}/RecoveryRoot/read-probe.bin")
                        {
                            let snapshot = worker_recovery.lock().unwrap();
                            ("synthetic-recovery-read-probe", "read-probe.bin", false, snapshot.etag.clone(), snapshot.body.len())
                        } else if path.contains("synthetic-personal-drive") {
                            ("synthetic-personal-root", "Personal", true, "\"synthetic-personal-root-etag\"".to_owned(), 0)
                        } else if path.contains("synthetic-project-drive") {
                            ("synthetic-project-root", "Projects", true, "\"synthetic-project-root-etag\"".to_owned(), 0)
                        } else {
                            write!(request_stream, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                            continue;
                        };
                    let mut entries = vec![(
                        if is_directory && !path.ends_with('/') {
                            format!("{path}/")
                        } else {
                            path.to_owned()
                        },
                        root_id.to_owned(),
                        name.to_owned(),
                        is_directory,
                        etag,
                        size,
                    )];
                    let depth_one = headers
                        .iter()
                        .find(|(name, _)| name == "depth")
                        .is_some_and(|(_, value)| value.trim() == "1");
                    if native_read_files_enabled
                        && depth_one
                        && normalized == "/remote.php/dav/personal/synthetic-personal-drive"
                    {
                        worker_native_reads
                            .lock()
                            .unwrap()
                            .personal_depth_one_propfind_count += 1;
                    }
                    if depth_one && normalized == project_prefix {
                        entries.push((
                            format!("{project_prefix}/RecoveryRoot/"),
                            "synthetic-recovery-directory".into(),
                            "RecoveryRoot".into(),
                            true,
                            "\"synthetic-recovery-directory-etag\"".into(),
                            0,
                        ));
                        if native_read_files_enabled {
                            entries.push((
                                format!("{project_prefix}/native-read.bin"),
                                "synthetic-project-native-read".into(),
                                "native-read.bin".into(),
                                false,
                                "\"synthetic-project-native-read-v1\"".into(),
                                b"synthetic Projects Space native read bytes".len(),
                            ));
                        }
                    } else if depth_one
                        && normalized == format!("{project_prefix}/RecoveryRoot")
                    {
                        let snapshot = worker_recovery.lock().unwrap();
                        if snapshot.present {
                        entries.push((
                            format!("{project_prefix}/RecoveryRoot/document.bin"),
                            "synthetic-recovery-file".into(),
                            "document.bin".into(),
                            false,
                            snapshot.etag.clone(),
                            snapshot.body.len(),
                        ));
                        }
                        if recovery_read_probe_enabled {
                            entries.push((
                                format!("{project_prefix}/RecoveryRoot/read-probe.bin"),
                                "synthetic-recovery-read-probe".into(),
                                "read-probe.bin".into(),
                                false,
                                snapshot.etag.clone(),
                                snapshot.body.len(),
                            ));
                        }
                    } else if depth_one
                        && normalized == "/remote.php/dav/personal/synthetic-personal-drive"
                        && native_read_files_enabled
                    {
                        entries.push((
                            "/remote.php/dav/personal/synthetic-personal-drive/native-read.bin".into(),
                            "synthetic-personal-native-read".into(),
                            "native-read.bin".into(),
                            false,
                            "\"synthetic-personal-native-read-v1\"".into(),
                            b"synthetic Personal native read bytes".len(),
                        ));
                    }
                    if initialized_vault && depth_one
                        && normalized == "/remote.php/dav/personal/synthetic-personal-drive"
                    {
                        entries.push((
                            format!("{normalized}/Travel.vault/"),
                            "synthetic-vault-root".into(), "Travel.vault".into(), true,
                            "\"vault-v1\"".into(), 0,
                        ));
                    }
                    let response_xml = entries
                        .into_iter()
                        .map(|(href, id, name, is_directory, etag, size)| {
                            let resource_kind = if is_directory {
                                "<d:resourcetype><d:collection/></d:resourcetype>"
                            } else {
                                "<d:resourcetype/>"
                            };
                            let vault_props = if initialized_vault && id == "synthetic-vault-root" {
                                format!(r#"<d:getcontenttype>application/vnd.opencloud.vault</d:getcontenttype><ocrclone:integrity-id xmlns:ocrclone="ocrclone">{}</ocrclone:integrity-id>"#,
                                    include_str!("../../raiun-vault/tests/fixtures/web-integrity-token.b64").trim())
                            } else { String::new() };
                            format!(
                                "<d:response><d:href>{worker_server}{href}</d:href><d:propstat><d:prop>{resource_kind}{vault_props}<d:getcontentlength>{size}</d:getcontentlength><d:getetag>{etag}</d:getetag><oc:fileid>{id}</oc:fileid><oc:name>{name}</oc:name><oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
                            )
                        })
                        .collect::<String>();
                    let xml = format!(
                        "<?xml version=\"1.0\"?><d:multistatus xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\">{response_xml}</d:multistatus>"
                    );
                    write!(request_stream, "HTTP/1.1 207 Multi-Status\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{xml}", xml.len()).unwrap();
                } else if request.starts_with("PUT /remote.php/dav/projects/synthetic-project-drive/RecoveryRoot/document.bin") {
                    let if_match = headers
                        .iter()
                        .find(|(name, _)| name == "if-match")
                        .map(|(_, value)| value.clone());
                    let mut snapshot = worker_recovery.lock().unwrap();
                    let absent_condition = headers.iter().find(|(name, _)| name == "if-none-match").map(|(_, value)| value.as_str());
                    if (snapshot.present && if_match.as_deref() != Some(snapshot.etag.as_str()))
                        || (!snapshot.present && (if_match.is_some() || absent_condition != Some("*"))) {
                        write!(request_stream, "HTTP/1.1 412 Precondition Failed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                        continue;
                    }
                    snapshot.present = true;
                    snapshot.put_count += 1;
                    snapshot.last_put_if_match = if_match;
                    snapshot.body = body;
                    snapshot.etag = "\"synthetic-file-v2\"".into();
                    write!(request_stream, "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                } else if request.starts_with("GET /remote.php/dav/projects/synthetic-project-drive/RecoveryRoot/document.bin")
                    || (recovery_read_probe_enabled
                        && request.starts_with("GET /remote.php/dav/projects/synthetic-project-drive/RecoveryRoot/read-probe.bin"))
                {
                    let if_match = headers
                        .iter()
                        .find(|(name, _)| name == "if-match")
                        .map(|(_, value)| value.clone());
                    let mut snapshot = worker_recovery.lock().unwrap();
                    if !snapshot.present {
                        write!(request_stream, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                        continue;
                    }
                    if if_match.as_deref() != Some(snapshot.etag.as_str()) {
                        write!(request_stream, "HTTP/1.1 412 Precondition Failed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                        continue;
                    }
                    let range = headers
                        .iter()
                        .find(|(name, _)| name == "range")
                        .and_then(|(_, value)| value.strip_prefix("bytes="))
                        .and_then(|value| value.split_once('-'))
                        .and_then(|(start, end)| Some((start.parse::<usize>().ok()?, end.parse::<usize>().ok()?)));
                    if let Some((start, requested_end)) = range {
                        if start >= snapshot.body.len() || requested_end < start {
                            write!(request_stream, "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                            continue;
                        }
                        let end = requested_end.min(snapshot.body.len() - 1);
                        let body = snapshot.body[start..=end].to_vec();
                        snapshot.range_count += 1;
                        snapshot.range_bytes += body.len();
                        write!(request_stream, "HTTP/1.1 206 Partial Content\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nContent-Range: bytes {start}-{end}/{}\r\nAccept-Ranges: bytes\r\nETag: {}\r\nConnection: close\r\n\r\n", body.len(), snapshot.body.len(), snapshot.etag).unwrap();
                        request_stream.write_all(&body).unwrap();
                    } else {
                        snapshot.get_count += 1;
                        snapshot.last_read_if_match = if_match;
                        write!(request_stream, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nETag: {}\r\nConnection: close\r\n\r\n", snapshot.body.len(), snapshot.etag).unwrap();
                        request_stream.write_all(&snapshot.body).unwrap();
                    }
                } else if native_read_files_enabled
                    && (request.starts_with("GET /remote.php/dav/personal/synthetic-personal-drive/native-read.bin")
                        || request.starts_with("GET /remote.php/dav/projects/synthetic-project-drive/native-read.bin"))
                {
                    let personal = request.starts_with(
                        "GET /remote.php/dav/personal/synthetic-personal-drive/native-read.bin",
                    );
                    let (body, etag) = if personal {
                        (b"synthetic Personal native read bytes".as_slice(), "\"synthetic-personal-native-read-v1\"")
                    } else {
                        (b"synthetic Projects Space native read bytes".as_slice(), "\"synthetic-project-native-read-v1\"")
                    };
                    let if_match = headers
                        .iter()
                        .find(|(name, _)| name == "if-match")
                        .map(|(_, value)| value.as_str());
                    if if_match != Some(etag) {
                        worker_native_reads.lock().unwrap().etag_mismatch_count += 1;
                        write!(request_stream, "HTTP/1.1 412 Precondition Failed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                        continue;
                    }
                    {
                        let mut reads = worker_native_reads.lock().unwrap();
                        if personal {
                            reads.personal_get_count += 1;
                        } else {
                            reads.project_get_count += 1;
                        }
                    }
                    let range = headers
                        .iter()
                        .find(|(name, _)| name == "range")
                        .and_then(|(_, value)| value.strip_prefix("bytes="))
                        .and_then(|value| value.split_once('-'))
                        .and_then(|(start, end)| Some((start.parse::<usize>().ok()?, end.parse::<usize>().ok()?)));
                    if let Some((start, requested_end)) = range {
                        if start >= body.len() || requested_end < start {
                            write!(request_stream, "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                            continue;
                        }
                        let end = requested_end.min(body.len() - 1);
                        let chunk = &body[start..=end];
                        {
                            let mut reads = worker_native_reads.lock().unwrap();
                            if personal {
                                reads.personal_range_count += 1;
                                reads.personal_range_bytes += chunk.len();
                            } else {
                                reads.project_range_count += 1;
                                reads.project_range_bytes += chunk.len();
                            }
                        }
                        write!(request_stream, "HTTP/1.1 206 Partial Content\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nContent-Range: bytes {start}-{end}/{}\r\nAccept-Ranges: bytes\r\nETag: {etag}\r\nConnection: close\r\n\r\n", chunk.len(), body.len()).unwrap();
                        request_stream.write_all(chunk).unwrap();
                    } else {
                        write!(request_stream, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nETag: {etag}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
                        request_stream.write_all(body).unwrap();
                    }
                } else if native_read_files_enabled
                    && ["PUT ", "DELETE ", "MOVE "].iter().any(|method| {
                        request.starts_with(&format!("{method}/remote.php/dav/"))
                    })
                {
                    worker_native_reads.lock().unwrap().mutation_attempt_count += 1;
                    write!(request_stream, "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                } else {
                    respond(&mut request_stream, 404, "not found");
                }
            }
        });
        emit_stage("listener_worker_started");
        (
            server,
            SyntheticPersonalSpacesFixture {
                stop,
                worker,
                recovery,
                native_reads,
                vault_upload,
            },
        )
    }

    fn synthetic_refresh_server(
        status: u16,
        body: &'static str,
    ) -> (String, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server = format!("http://{}", listener.local_addr().unwrap());
        let endpoint = format!("{server}/token");
        let worker = thread::spawn(move || {
            let (mut token, _) = listener.accept().unwrap();
            let (request, request_body) = read_request(&token);
            assert!(request.starts_with("POST /token"));
            let form: HashMap<String, String> = url::form_urlencoded::parse(&request_body)
                .into_owned()
                .collect();
            assert_eq!(
                form.get("grant_type").map(String::as_str),
                Some("refresh_token")
            );
            assert_eq!(
                form.get("refresh_token").map(String::as_str),
                Some("synthetic-refresh-token")
            );
            assert_eq!(
                form.get("client_id").map(String::as_str),
                Some("synthetic-client")
            );
            respond(&mut token, status, body);
            server
        });
        (endpoint, worker)
    }

    fn blocked_refresh_server() -> (
        String,
        mpsc::Receiver<()>,
        mpsc::Sender<()>,
        thread::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}/token", listener.local_addr().unwrap());
        let (seen_tx, seen_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let (mut token, _) = listener.accept().unwrap();
            let (request, request_body) = read_request(&token);
            assert!(request.starts_with("POST /token"));
            let form: HashMap<String, String> = url::form_urlencoded::parse(&request_body)
                .into_owned()
                .collect();
            assert_eq!(
                form.get("grant_type").map(String::as_str),
                Some("refresh_token")
            );
            seen_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            respond(
                &mut token,
                200,
                r#"{"access_token":"late-access-token","refresh_token":"late-refresh-token","expires_in":3600}"#,
            );
        });
        (endpoint, seen_rx, release_tx, worker)
    }

    fn wait_for_refresh(agent: &WindowsAgent) -> Value {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let status = agent.status().unwrap();
            if status["refreshing"] != true && !status["authenticating"].as_bool().unwrap_or(false)
            {
                return status;
            }
            assert!(Instant::now() < deadline, "session refresh did not finish");
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn synthetic_oidc_server(expect_token: bool) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server = format!("http://{}", listener.local_addr().unwrap());
        let issuer = server.clone();
        let worker = thread::spawn(move || {
            let (mut webfinger, _) = listener.accept().unwrap();
            let (request, _) = read_request(&webfinger);
            assert!(request.starts_with("GET /.well-known/webfinger?"));
            respond(&mut webfinger, 404, "{}");

            let (mut discovery, _) = listener.accept().unwrap();
            let (request, _) = read_request(&discovery);
            assert!(request.starts_with("GET /.well-known/openid-configuration"));
            let metadata = json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{issuer}/authorize"),
                "token_endpoint": format!("{issuer}/token"),
            })
            .to_string();
            respond(&mut discovery, 200, &metadata);

            if expect_token {
                let (mut token, _) = listener.accept().unwrap();
                let (request, body) = read_request(&token);
                assert!(request.starts_with("POST /token"));
                let body = String::from_utf8(body).unwrap();
                assert!(body.contains("grant_type=authorization_code"));
                assert!(body.contains("code=synthetic-code"));
                respond(
                    &mut token,
                    200,
                    r#"{"access_token":"synthetic-access-token","refresh_token":"synthetic-refresh-token","expires_in":3600}"#,
                );
            }
        });
        (server, worker)
    }

    #[test]
    fn windows_status_never_claims_a_mount_or_cloud_provider() {
        let agent = Arc::new(WindowsAgent::new(MemoryStore::default()));
        let status = agent.status().unwrap();
        assert_eq!(status["connected"], false);
        assert_eq!(status["mounted"], false);
        assert_eq!(status["provider_supported"], false);
        assert_eq!(status["error"], PROVIDER_UNAVAILABLE);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn windows_drive_capability_does_not_claim_unimplemented_controls() {
        let agent = Arc::new(WindowsAgent::new(MemoryStore::default()));
        agent
            .provider
            .lifecycle_test_activation
            .store(true, Ordering::Release);
        let status = agent.status().unwrap();
        assert_eq!(status["provider_supported"], true);
        assert_eq!(status["mounted"], false);
        assert!(status["error"].is_null());
        for capability in [
            "folder_sync_supported",
            "media_jobs_supported",
            "vaults_supported",
            "account_switch_supported",
            "pause_supported",
        ] {
            assert_eq!(status[capability], false);
        }
    }

    #[test]
    fn folder_control_dispatch_rejects_foreign_profile_before_worker_admission() {
        let agent = Arc::new(WindowsAgent::new(MemoryStore::default()));
        for action in [
            "windows_offline_folders",
            "windows_offline_folder_prepare",
            "windows_offline_folder_start",
            "windows_offline_folder_resume",
            "windows_offline_folder_refresh",
            "windows_offline_folder_status",
            "windows_offline_folder_cancel",
        ] {
            let result = agent.handle_request(&json!({
                "action": action,
                "profile_id": "other-account",
            }));
            assert_eq!(
                result.unwrap_err(),
                "The selected Windows profile does not own this request",
                "{action}"
            );
        }
        #[cfg(debug_assertions)]
        assert_eq!(
            agent.provider.disconnect_test_calls.load(Ordering::SeqCst),
            0
        );
        let status = agent.status().unwrap();
        assert_eq!(status["connected"], false);
        assert_eq!(status["mounted"], false);
    }

    #[test]
    fn synthetic_oauth_sign_in_is_persisted_before_connected_status() {
        let (server, fixture) = synthetic_oidc_server(true);
        let store = Arc::new(MemoryStore::default());
        store.root_configs.lock().unwrap().insert(
            ("default".into(), server.clone(), "synthetic-client".into()),
            br#"{"old_user_root":"never_reuse"}"#.to_vec(),
        );
        let agent = Arc::new(WindowsAgent {
            source_admissions: None,
            vault_sessions: Arc::new(raiun_vault::session::VaultSessionCoordinator::new()),
            profile_scope: "default".into(),
            session_store: store.clone(),
            state: Arc::new(Mutex::new(AccountState::default())),
            generation: Arc::new(std::sync::atomic::AtomicU64::new(1)),
            provider: Arc::new(ProviderManager::new()),
            auth_thread: Mutex::new(None),
            refresh_thread: Mutex::new(None),
            fresh_close_worker: Mutex::new(None),
            folder_lifecycle: Mutex::new(()),
            vault_credential_operation: Mutex::new(()),
            protected_recovery_tokens: Mutex::new(
                super::windows_vault_capture_recovery::Tokens::default(),
            ),
            #[cfg(all(test, debug_assertions))]
            synthetic_vault_completion_writer_probe: true,
        });
        let info = agent
            .begin_auth(&json!({"server":server,"client_id":"synthetic-client"}))
            .unwrap();
        assert!(
            store
                .load_root_config("default", &server, "synthetic-client")
                .unwrap()
                .is_some_and(|bytes| bytes == br#"{"old_user_root":"never_reuse"}"#)
        );
        let auth_url = url::Url::parse(info["url"].as_str().unwrap()).unwrap();
        let query: HashMap<_, _> = auth_url.query_pairs().into_owned().collect();
        let redirect = url::Url::parse(query.get("redirect_uri").unwrap()).unwrap();
        let callback = format!(
            "/?code=synthetic-code&state={}",
            query.get("state").unwrap()
        );
        let mut browser = TcpStream::connect(("127.0.0.1", redirect.port().unwrap())).unwrap();
        write!(
            browser,
            "GET {callback} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut reply = Vec::new();
        browser.read_to_end(&mut reply).unwrap();
        assert!(String::from_utf8_lossy(&reply).starts_with("HTTP/1.1 200 OK"));

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let status = agent.status().unwrap();
            if status["connected"] == true {
                assert_eq!(status["mounted"], false);
                assert_eq!(status["provider_supported"], false);
                assert_eq!(status["server"], server);
                assert_eq!(status["client_id"], "synthetic-client");
                break;
            }
            assert!(
                Instant::now() < deadline,
                "sign-in did not reach saved state"
            );
            thread::sleep(Duration::from_millis(10));
        }
        fixture.join().unwrap();
        assert_eq!(store.sessions.lock().unwrap().len(), 1);
        agent.logout().unwrap();
        assert_eq!(agent.status().unwrap()["connected"], false);
        assert!(store.sessions.lock().unwrap().is_empty());
        assert!(store.active_identity.lock().unwrap().is_none());
    }

    #[cfg(all(test, debug_assertions))]
    #[test]
    fn rejected_auth_begin_preserves_existing_account_and_provider_admission() {
        let provider = Arc::new(super::ProviderManager::new());
        let store = Arc::new(MemoryStore::default());
        let session = synthetic_session(
            "https://existing.example",
            "synthetic-client",
            unix_time_now().saturating_add(3600),
        );
        let root_configuration = super::RootConfiguration {
            profile_scope: "default".into(),
            server: session.server.clone(),
            client_id: session.client_id.clone(),
            issuer: Some("https://existing.example".into()),
            path: "C:\\RaiunSyntheticRoot".into(),
            volume_serial: 17,
            file_index: 29,
            registration_ownership: Some(RegistrationOwnership {
                state: "registered".into(),
                account_id: "synthetic-account".into(),
                personal_drive_id: "synthetic-drive".into(),
                personal_root_resource_id: Some("synthetic-root".into()),
                volume_serial: 17,
                file_index: 29,
            }),
            valid: true,
        };
        let state = Arc::new(Mutex::new(AccountState {
            session: Some(session.clone()),
            root_configuration: Some(root_configuration.clone()),
            online_authenticated: true,
            active_generation: 41,
            ..AccountState::default()
        }));
        let agent = Arc::new(WindowsAgent {
            source_admissions: None,
            vault_sessions: Arc::new(raiun_vault::session::VaultSessionCoordinator::new()),
            profile_scope: "default".into(),
            session_store: store,
            state: state.clone(),
            generation: Arc::new(std::sync::atomic::AtomicU64::new(41)),
            provider: provider.clone(),
            auth_thread: Mutex::new(None),
            refresh_thread: Mutex::new(None),
            fresh_close_worker: Mutex::new(None),
            folder_lifecycle: Mutex::new(()),
            vault_credential_operation: Mutex::new(()),
            protected_recovery_tokens: Mutex::new(
                super::windows_vault_capture_recovery::Tokens::default(),
            ),
            #[cfg(all(test, debug_assertions))]
            synthetic_vault_completion_writer_probe: true,
        });

        assert_eq!(
            agent
                .begin_auth(&json!({"server":"https://other.example","client_id":"other-client"}))
                .unwrap_err(),
            "This Windows account is already connected. Sign out before signing in again"
        );
        {
            let state = state.lock().unwrap();
            assert_eq!(state.session.as_ref().unwrap().server, session.server);
            assert_eq!(state.session.as_ref().unwrap().client_id, session.client_id);
            assert_eq!(state.root_configuration, Some(root_configuration));
            assert!(state.online_authenticated);
            assert!(!state.authenticating);
            assert_eq!(state.active_generation, 41);
        }
        assert_eq!(agent.generation.load(Ordering::Acquire), 41);
        assert_eq!(provider.disconnect_test_calls.load(Ordering::SeqCst), 0);

        {
            let mut state = state.lock().unwrap();
            state.session = None;
            state.root_configuration = None;
            state.authenticating = true;
        }
        assert_eq!(
            agent
                .begin_auth(&json!({"server":"https://other.example","client_id":"other-client"}))
                .unwrap_err(),
            "Sign-in is already in progress"
        );
        assert!(state.lock().unwrap().authenticating);
        assert_eq!(agent.generation.load(Ordering::Acquire), 41);
        assert_eq!(provider.disconnect_test_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn fresh_sign_in_does_not_destroy_persisted_registration_ownership() {
        let (server, fixture) = synthetic_oidc_server(false);
        let store = Arc::new(MemoryStore::default());
        store.root_configs.lock().unwrap().insert(
            ("default".into(), server.clone(), "synthetic-client".into()),
            br#"{"old_user_root":"never_reuse"}"#.to_vec(),
        );
        let agent = Arc::new(WindowsAgent {
            source_admissions: None,
            vault_sessions: Arc::new(raiun_vault::session::VaultSessionCoordinator::new()),
            profile_scope: "default".into(),
            session_store: store.clone(),
            state: Arc::new(Mutex::new(AccountState::default())),
            generation: Arc::new(std::sync::atomic::AtomicU64::new(1)),
            provider: Arc::new(ProviderManager::new()),
            auth_thread: Mutex::new(None),
            refresh_thread: Mutex::new(None),
            fresh_close_worker: Mutex::new(None),
            folder_lifecycle: Mutex::new(()),
            vault_credential_operation: Mutex::new(()),
            protected_recovery_tokens: Mutex::new(
                super::windows_vault_capture_recovery::Tokens::default(),
            ),
            #[cfg(all(test, debug_assertions))]
            synthetic_vault_completion_writer_probe: true,
        });

        agent
            .begin_auth(&json!({"server":server,"client_id":"synthetic-client"}))
            .expect("sign-in must not delete a persisted root registration record");
        agent
            .cancel_auth()
            .expect("cancel the synthetic pending sign-in");
        fixture.join().unwrap();
        let state = agent.state.lock().unwrap();
        assert!(!state.authenticating);
        assert!(state.session.is_none());
        assert!(store.sessions.lock().unwrap().is_empty());
        assert_eq!(
            store
                .load_root_config("default", &server, "synthetic-client")
                .unwrap()
                .as_deref(),
            Some(br#"{"old_user_root":"never_reuse"}"#.as_slice())
        );
    }

    #[test]
    #[ignore = "requires isolated native Windows user profile and current-user DPAPI"]
    fn dpapi_adapter_rejects_foreign_scope_without_mutating_fixture() {
        use std::{collections::BTreeMap, fs};

        let base = super::DpapiSessionStore::current_user().expect("open current-user storage");
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).expect("generate unique synthetic profile ID");
        let profile = format!("profile-{:032x}", u128::from_be_bytes(nonce));
        let foreign = if profile == "profile-ffffffffffffffffffffffffffffffff" {
            "profile-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        } else {
            "profile-ffffffffffffffffffffffffffffffff"
        };
        let path = base.local_edit_state_directory().join(&profile);
        assert!(
            matches!(fs::symlink_metadata(&path), Err(error) if error.kind() == std::io::ErrorKind::NotFound),
            "synthetic profile must not already exist"
        );
        let raw = base
            .for_profile(&profile)
            .expect("create unique private profile fixture");
        assert_eq!(raw.local_edit_state_directory(), path);
        // Only this new child is read below; never read the base/default pointer.
        let server = "https://synthetic.invalid";
        let client = "synthetic-client";
        let session = synthetic_session(server, client, unix_time_now() + 3600);
        let body = serde_json::to_vec(&session).expect("encode synthetic session");
        let roots = br#"{"synthetic_root":"not-a-user-folder"}"#;
        // Intentionally seed a foreign identity through the raw storage API inside
        // our own new child. This exercises the adapter's independent scope fence.
        raw.save(Some(foreign), server, client, &body)
            .expect("seed foreign synthetic session");
        raw.save_root_config(foreign, server, client, roots)
            .expect("seed foreign synthetic root metadata");
        raw.set_active_identity(foreign, server, client)
            .expect("seed foreign synthetic pointer");
        let snapshot = |directory: &std::path::Path| -> BTreeMap<std::ffi::OsString, Vec<u8>> {
            fs::read_dir(directory)
                .expect("enumerate only owned fixture")
                .map(|entry| {
                    let entry = entry.expect("fixture entry");
                    (
                        entry.file_name(),
                        fs::read(entry.path()).expect("read owned fixture bytes"),
                    )
                })
                .collect()
        };
        let before = snapshot(&path);
        let adapter = super::DpapiStore {
            store: raw.clone(),
            profile_scope: profile.clone(),
        };
        assert!(adapter.save_pending(foreign, &session).is_err());
        assert!(adapter.publish_active(foreign, &session).is_err());
        assert!(adapter.load_active(foreign).is_err());
        assert!(adapter.remove(foreign, server, client).is_err());
        assert!(
            adapter
                .save_root_config(foreign, server, client, b"replacement")
                .is_err()
        );
        assert!(adapter.load_root_config(foreign, server, client).is_err());
        assert!(adapter.remove_root_config(foreign, server, client).is_err());
        // Even a trusted-scope load must refuse the foreign pointer; revoke must
        // check before clear_active_identity rather than destroying it first.
        assert!(adapter.load_active(&profile).is_err());
        assert!(adapter.revoke_active().is_err());
        assert_eq!(
            raw.active_identity().expect("read owned synthetic pointer"),
            Some((foreign.into(), server.into(), client.into()))
        );
        assert_eq!(
            raw.load(Some(foreign), server, client)
                .expect("read owned session")
                .expect("owned session exists")
                .as_slice(),
            body.as_slice()
        );
        assert_eq!(
            raw.load_root_config(foreign, server, client)
                .expect("read owned root metadata"),
            Some(roots.to_vec())
        );
        assert!(
            snapshot(&path) == before,
            "foreign calls must not alter any owned fixture bytes or names"
        );
        // A mismatched constructor must refuse before restore or revocation.
        assert!(WindowsAgent::new_for_profile(foreign, adapter).is_err());
        assert!(snapshot(&path) == before);
        // Success-only exact fixture cleanup; preserve all evidence on panic.
        raw.clear_active_identity()
            .expect("clear synthetic pointer");
        raw.remove(Some(foreign), server, client)
            .expect("remove synthetic session");
        raw.remove_root_config(foreign, server, client)
            .expect("remove synthetic root metadata");
        drop(raw);
        fs::remove_dir(&path).expect("remove only empty synthetic profile child");
    }

    #[test]
    fn root_inventory_metadata_cannot_restore_a_different_issuer() {
        let session = synthetic_session(
            "https://synthetic.invalid",
            "synthetic-client",
            unix_time_now() + 3600,
        );
        let configuration = super::RootConfiguration {
            profile_scope: "default".into(),
            server: session.server.clone(),
            client_id: session.client_id.clone(),
            issuer: session.expected_issuer.clone(),
            path: "C:\\SyntheticReservation".into(),
            volume_serial: 1,
            file_index: 42,
            registration_ownership: None,
            valid: true,
        };
        let bytes = encode_root_configuration(&configuration).unwrap();
        let decoded = super::decode_root_metadata(&bytes, "default").unwrap();
        assert!(
            !decoded.valid,
            "inventory decoding grants exclusion only, never attach authority"
        );
        assert_eq!(decoded.path, configuration.path);
        let store: Arc<dyn SessionStore> = Arc::new(MemoryStore::default());
        store
            .save_root_config("default", &session.server, &session.client_id, &bytes)
            .unwrap();
        let mut foreign = session;
        foreign.expected_issuer = Some("https://different-issuer.invalid".into());
        assert!(load_root_configuration(&store, "default", &foreign).is_err());
        assert!(
            super::decode_root_metadata(&bytes, "profile-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .is_err()
        );
    }

    #[test]
    fn independent_profile_runtimes_reject_foreign_logout_and_preserve_other_session() {
        let profile_a = "profile-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let profile_b = "profile-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let server = "https://synthetic.invalid";
        let client = "synthetic-client";
        let store_a = Arc::new(MemoryStore::default());
        let store_b = Arc::new(MemoryStore::default());
        let mut session_a = synthetic_session(server, client, unix_time_now() + 3600);
        let mut session_b = session_a.clone();
        session_a.access_token = "synthetic-profile-a-token".into();
        session_b.access_token = "synthetic-profile-b-token".into();
        seed_active_session(&store_a, profile_a, session_a);
        seed_active_session(&store_b, profile_b, session_b);
        let agent_a = Arc::new(WindowsAgent::new_for_profile(profile_a, store_a.clone()).unwrap());
        let agent_b = Arc::new(WindowsAgent::new_for_profile(profile_b, store_b.clone()).unwrap());
        // Restored runtimes normally refresh on status. Keep this storage/routing
        // fixture offline via the existing retry deadline; no auth/network thread
        // is started and no online authentication or capability is fabricated.
        agent_a.state.lock().unwrap().refresh_retry_at = u64::MAX;
        agent_b.state.lock().unwrap().refresh_retry_at = u64::MAX;
        let key_a = (profile_a.to_owned(), server.to_owned(), client.to_owned());
        let key_b = (profile_b.to_owned(), server.to_owned(), client.to_owned());
        let preserved_a = || {
            assert!(store_a.active_identity.lock().unwrap().as_ref() == Some(&key_a));
            let sessions = store_a.sessions.lock().unwrap();
            assert_eq!(sessions.len(), 1);
            assert!(sessions.get(&key_a).unwrap().access_token == "synthetic-profile-a-token");
        };
        let preserved_b = || {
            assert!(store_b.active_identity.lock().unwrap().as_ref() == Some(&key_b));
            let sessions = store_b.sessions.lock().unwrap();
            assert_eq!(sessions.len(), 1);
            assert!(sessions.get(&key_b).unwrap().access_token == "synthetic-profile-b-token");
        };
        let status_a = agent_a
            .handle_request(&json!({"action":"status", "profile_id":profile_a}))
            .unwrap()
            .0;
        let status_b = agent_b
            .handle_request(&json!({"action":"status", "profile_id":profile_b}))
            .unwrap()
            .0;
        assert_eq!(status_a["profile_id"], profile_a);
        assert_eq!(status_b["profile_id"], profile_b);
        assert_eq!(status_a["connected"], false);
        assert_eq!(status_b["connected"], false);
        preserved_a();
        preserved_b();
        let generation_a = agent_a.state.lock().unwrap().active_generation;
        assert!(
            agent_a
                .handle_request(&json!({"action":"logout", "profile_id":profile_b}))
                .is_err()
        );
        assert_eq!(
            agent_a.state.lock().unwrap().active_generation,
            generation_a
        );
        preserved_a();
        preserved_b();
        let (logout, stopping) = agent_a
            .handle_request(&json!({"action":"logout", "profile_id":profile_a}))
            .unwrap();
        assert_eq!(logout["logged_out"], true);
        assert!(!stopping);
        assert!(store_a.active_identity.lock().unwrap().is_none());
        assert!(store_a.sessions.lock().unwrap().is_empty());
        assert!(agent_a.state.lock().unwrap().session.is_none());
        preserved_b();
        assert!(
            agent_b
                .state
                .lock()
                .unwrap()
                .session
                .as_ref()
                .unwrap()
                .access_token
                == "synthetic-profile-b-token"
        );
        agent_a.stop_and_join().unwrap();
        agent_b.stop_and_join().unwrap();
        drop(agent_a);
        drop(agent_b);
        assert!(store_a.active_identity.lock().unwrap().is_none());
        assert!(store_a.sessions.lock().unwrap().is_empty());
        preserved_b();
    }

    fn synthetic_session(server: &str, client_id: &str, expires_at: u64) -> auth::Session {
        auth::Session {
            server: server.to_owned(),
            client_id: client_id.to_owned(),
            access_token: "synthetic-access-token".into(),
            refresh_token: Some("synthetic-refresh-token".into()),
            expires_at,
            token_endpoint: "https://issuer.example/token".into(),
            expected_issuer: Some("https://issuer.example".into()),
            last_refresh_at: None,
            proxy: raiun_opencloud::ProxyConfig::System,
        }
    }

    fn session_for_refresh(endpoint: &str, expires_at: u64) -> auth::Session {
        let server = endpoint.trim_end_matches("/token").to_owned();
        auth::Session {
            server: server.clone(),
            client_id: "synthetic-client".into(),
            access_token: "synthetic-access-token".into(),
            refresh_token: Some("synthetic-refresh-token".into()),
            expires_at,
            token_endpoint: endpoint.to_owned(),
            expected_issuer: Some(server),
            last_refresh_at: None,
            proxy: raiun_opencloud::ProxyConfig::System,
        }
    }

    #[test]
    fn proxy_rpc_is_profile_local_signed_out_only_and_preserves_retained_session() {
        let store = Arc::new(MemoryStore::default());
        let a = "profile-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let b = "profile-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let agent_a = Arc::new(WindowsAgent::new_for_profile(a, store.clone()).unwrap());
        let agent_b = Arc::new(WindowsAgent::new_for_profile(b, store.clone()).unwrap());
        let read = json!({"action":"network_proxy","profile_id":a});
        let initial = agent_a.handle_request(&read).unwrap().0;
        assert_eq!(initial["revision"], 1);
        let update = json!({"action":"network_proxy_set","profile_id":a,"proxy":{"mode":"direct"},"expected_account_id":null,"expected_revision":1});
        let saved = agent_a.handle_request(&update).unwrap().0;
        assert_eq!(saved["revision"], 2);
        assert!(agent_a.handle_request(&update).is_err());
        assert_eq!(
            agent_b
                .handle_request(&json!({"action":"network_proxy","profile_id":b}))
                .unwrap()
                .0["revision"],
            1
        );
        assert!(agent_b.handle_request(&update).is_err());
        let before = store.load_proxy_settings(a).unwrap();
        {
            let mut state = agent_a.state.lock().unwrap();
            state.session = Some(synthetic_session(
                "https://fixture.invalid",
                "synthetic-client",
                unix_time_now() + 3600,
            ));
        }
        let mut retained = update.clone();
        retained["expected_revision"] = json!(2);
        assert!(agent_a.handle_request(&retained).is_err());
        assert_eq!(store.load_proxy_settings(a).unwrap(), before);
        assert!(agent_a.state.lock().unwrap().session.is_some());
        agent_a.stop_and_join().unwrap();
        agent_b.stop_and_join().unwrap();
    }

    fn seed_active_session(store: &MemoryStore, scope: &str, session: auth::Session) {
        let identity = (
            scope.to_owned(),
            session.server.clone(),
            session.client_id.clone(),
        );
        store
            .sessions
            .lock()
            .unwrap()
            .insert(identity.clone(), session);
        *store.active_identity.lock().unwrap() = Some(identity);
    }

    #[test]
    fn startup_restores_only_the_exact_nonexpired_active_identity() {
        let (endpoint, fixture) = synthetic_refresh_server(
            200,
            r#"{"access_token":"rotated-access-token","refresh_token":"rotated-refresh-token","expires_in":3600}"#,
        );
        let server = endpoint.trim_end_matches("/token").to_owned();
        let store = Arc::new(MemoryStore::default());
        seed_active_session(
            &store,
            "default",
            session_for_refresh(&endpoint, unix_time_now() + 25),
        );

        let agent = WindowsAgent::new(store.clone());
        let initial = agent.status().unwrap();
        assert_eq!(initial["connected"], false);
        assert_eq!(initial["offline"], true);
        let status = wait_for_refresh(&agent);
        fixture.join().unwrap();
        assert_eq!(status["connected"], true);
        assert_eq!(status["offline"], false);
        assert_eq!(status["server"], server);
        assert_eq!(status["client_id"], "synthetic-client");
        assert_eq!(status["mounted"], false);
        assert_eq!(status["provider_supported"], false);
        assert_eq!(
            store
                .sessions
                .lock()
                .unwrap()
                .values()
                .next()
                .unwrap()
                .access_token,
            "rotated-access-token"
        );
        assert_eq!(
            store
                .sessions
                .lock()
                .unwrap()
                .values()
                .next()
                .unwrap()
                .refresh_token
                .as_deref(),
            Some("rotated-refresh-token")
        );
    }

    #[test]
    fn successful_refresh_with_five_minute_token_stays_connected_on_status() {
        let (endpoint, fixture) = synthetic_refresh_server(
            200,
            r#"{"access_token":"rotated-access-token","refresh_token":"rotated-refresh-token","expires_in":300}"#,
        );
        let store = Arc::new(MemoryStore::default());
        seed_active_session(
            &store,
            "default",
            session_for_refresh(&endpoint, unix_time_now() + 25),
        );

        let agent = WindowsAgent::new(store.clone());
        assert_eq!(agent.status().unwrap()["offline"], true);
        let refreshed = wait_for_refresh(&agent);
        assert_eq!(refreshed["connected"], true);
        fixture.join().unwrap();

        let generation = refreshed["auth_generation"].as_u64().unwrap();
        let saved = store.sessions.lock().unwrap();
        let session = saved.values().next().unwrap();
        assert!(session.expires_at > unix_time_now() + 250);
        assert!(session.last_refresh_at.is_some());
        drop(saved);

        let status = agent.status().unwrap();
        assert_eq!(status["connected"], true);
        assert_eq!(status["offline"], false);
        assert_eq!(status["refreshing"], false);
        assert_eq!(status["auth_generation"], generation);
        assert_eq!(agent.generation.load(Ordering::Acquire), generation);
        agent.stop_and_join().unwrap();
    }

    #[test]
    fn startup_rejects_a_pointer_for_a_different_profile() {
        let store = MemoryStore::default();
        seed_active_session(
            &store,
            "another-profile",
            synthetic_session(
                "https://cloud.example",
                "synthetic-client",
                unix_time_now() + 3600,
            ),
        );

        let agent = WindowsAgent::new(store);
        let status = agent.status().unwrap();
        assert_eq!(status["connected"], false);
        assert_eq!(status["server"], serde_json::Value::Null);
        assert_eq!(status["mounted"], false);
        assert!(status["error"].as_str().unwrap().contains("profile"));
    }

    #[test]
    fn expired_session_is_revoked_and_never_restored() {
        let (endpoint, fixture) = synthetic_refresh_server(401, r#"{"error":"invalid_grant"}"#);
        let store = Arc::new(MemoryStore::default());
        seed_active_session(&store, "default", session_for_refresh(&endpoint, 1));

        let agent = WindowsAgent::new(store.clone());
        let status = agent.status().unwrap();
        assert_eq!(status["offline"], true);
        let status = wait_for_refresh(&agent);
        fixture.join().unwrap();
        assert_eq!(status["connected"], false);
        assert_eq!(status["offline"], false);
        assert!(status["error"].as_str().unwrap().contains("invalid_grant"));
        assert!(store.active_identity.lock().unwrap().is_none());
        assert!(store.sessions.lock().unwrap().is_empty());

        let restarted = WindowsAgent::new(store);
        assert_eq!(restarted.status().unwrap()["connected"], false);
    }

    #[test]
    fn refresh_transport_failure_keeps_cached_session_offline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}/token", listener.local_addr().unwrap());
        drop(listener);
        let store = Arc::new(MemoryStore::default());
        seed_active_session(
            &store,
            "default",
            session_for_refresh(&endpoint, unix_time_now() + 3600),
        );
        let agent = WindowsAgent::new(store.clone());
        assert_eq!(agent.status().unwrap()["offline"], true);
        let status = wait_for_refresh(&agent);
        assert_eq!(status["connected"], false);
        assert_eq!(status["offline"], true);
        assert!(
            status["error"]
                .as_str()
                .unwrap()
                .contains("Could not contact")
        );
        assert!(store.active_identity.lock().unwrap().is_some());
        assert_eq!(store.sessions.lock().unwrap().len(), 1);

        let failed_generation = agent.generation.load(Ordering::Acquire);
        agent.maybe_start_refresh().unwrap();
        assert_eq!(agent.generation.load(Ordering::Acquire), failed_generation);
        {
            let mut state = agent.state.lock().unwrap();
            assert!(!state.needs_refresh);
            assert!(state.session.as_ref().unwrap().expires_at > unix_time_now() + 300);
            // Advance the retry gate without sleeping or changing the token.
            state.refresh_retry_at = 0;
        }
        agent.maybe_start_refresh().unwrap();
        assert!(agent.generation.load(Ordering::Acquire) > failed_generation);
        agent
            .refresh_thread
            .lock()
            .unwrap()
            .take()
            .unwrap()
            .join()
            .unwrap();
        let state = agent.state.lock().unwrap();
        assert!(state.session.is_some());
        assert!(!state.online_authenticated);
        assert!(!state.refreshing);
    }

    #[test]
    fn cancelled_refresh_cannot_publish_rotated_tokens() {
        let (endpoint, seen, release, fixture) = blocked_refresh_server();
        let store = Arc::new(MemoryStore::default());
        seed_active_session(
            &store,
            "default",
            session_for_refresh(&endpoint, unix_time_now() + 10),
        );
        let agent = Arc::new(WindowsAgent::new(store.clone()));
        assert_eq!(agent.status().unwrap()["refreshing"], true);
        seen.recv_timeout(Duration::from_secs(5)).unwrap();

        let cancelling = Arc::clone(&agent);
        let (done_tx, done_rx) = mpsc::channel();
        let canceller = thread::spawn(move || {
            done_tx.send(cancelling.cancel_auth()).unwrap();
        });
        thread::sleep(Duration::from_millis(50));
        release.send(()).unwrap();
        let result = done_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap();
        canceller.join().unwrap();
        fixture.join().unwrap();

        assert_eq!(result["cancelled"], true);
        let status = agent.status().unwrap();
        assert_eq!(status["connected"], false);
        assert_eq!(status["offline"], true);
        let saved = store.sessions.lock().unwrap();
        assert_eq!(
            saved.values().next().unwrap().access_token,
            "synthetic-access-token"
        );
        assert!(store.active_identity.lock().unwrap().is_some());
    }

    #[test]
    fn logout_waits_for_refresh_and_revokes_its_restore_identity() {
        let (endpoint, seen, release, fixture) = blocked_refresh_server();
        let store = Arc::new(MemoryStore::default());
        seed_active_session(
            &store,
            "default",
            session_for_refresh(&endpoint, unix_time_now() + 10),
        );
        let agent = Arc::new(WindowsAgent::new(store.clone()));
        assert_eq!(agent.status().unwrap()["refreshing"], true);
        seen.recv_timeout(Duration::from_secs(5)).unwrap();

        let logging_out = Arc::clone(&agent);
        let (done_tx, done_rx) = mpsc::channel();
        let logout_thread = thread::spawn(move || {
            done_tx.send(logging_out.logout()).unwrap();
        });
        thread::sleep(Duration::from_millis(50));
        release.send(()).unwrap();
        let result = done_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap();
        logout_thread.join().unwrap();
        fixture.join().unwrap();

        assert_eq!(result["logged_out"], true);
        assert_eq!(agent.status().unwrap()["connected"], false);
        assert!(store.active_identity.lock().unwrap().is_none());
        assert!(store.sessions.lock().unwrap().is_empty());
        let restarted = WindowsAgent::new(store);
        assert_eq!(restarted.status().unwrap()["connected"], false);
    }

    #[test]
    fn logout_revokes_restore_pointer_even_when_blob_cleanup_fails() {
        let store = Arc::new(MemoryStore::default());
        seed_active_session(
            &store,
            "default",
            synthetic_session(
                "https://cloud.example",
                "synthetic-client",
                unix_time_now() + 3600,
            ),
        );
        *store.fail_removes.lock().unwrap() = true;
        let agent = WindowsAgent::new(store.clone());
        {
            let mut state = agent.state.lock().unwrap();
            state.online_authenticated = true;
            state.needs_refresh = false;
        }
        assert_eq!(agent.status().unwrap()["connected"], true);

        let result = agent.logout().unwrap();
        assert_eq!(result["logged_out"], true);
        assert_eq!(result["session_cleanup_uncertain"], true);
        assert_eq!(agent.status().unwrap()["connected"], false);
        assert!(store.active_identity.lock().unwrap().is_none());
        assert_eq!(store.sessions.lock().unwrap().len(), 1);

        let restarted = WindowsAgent::new(store);
        assert_eq!(restarted.status().unwrap()["connected"], false);
    }

    #[test]
    fn idle_logout_revokes_provider_generation_before_later_lifecycle_commands() {
        let store = Arc::new(MemoryStore::default());
        seed_active_session(
            &store,
            "default",
            synthetic_session(
                "https://cloud.example",
                "synthetic-client",
                unix_time_now() + 3600,
            ),
        );
        let agent = WindowsAgent::new(store.clone());
        let old_generation = {
            let mut state = agent.state.lock().unwrap();
            state.online_authenticated = true;
            state.needs_refresh = false;
            assert!(!state.authenticating && !state.refreshing);
            state.active_generation
        };
        agent.logout().unwrap();
        let generation = agent.generation.load(Ordering::Acquire);
        assert!(generation > old_generation);
        assert_eq!(
            agent.provider.authorized_generation.load(Ordering::Acquire),
            generation
        );
        let state = agent.state.lock().unwrap();
        assert_eq!(state.active_generation, generation);
        assert!(!state.online_authenticated);
        assert!(state.session.is_none());
        drop(state);
        assert!(store.active_identity.lock().unwrap().is_none());
        let error = agent
            .provider
            .connection_matches(super::ActiveProviderBinding {
                generation: old_generation,
                path: PathBuf::from(r"C:\Synthetic-Stale-Logout"),
                identity: raiun_cloudfiles_windows::ConfiguredRootIdentity {
                    volume_serial: 1,
                    file_index: 1,
                },
                personal_space_id: "synthetic-personal".into(),
                personal_root_resource_id: "synthetic-root".into(),
            })
            .unwrap_err();
        assert!(error.contains("account changed"));
    }

    #[test]
    fn logout_does_not_claim_success_when_restore_pointer_cannot_be_revoked() {
        let store = Arc::new(MemoryStore::default());
        seed_active_session(
            &store,
            "default",
            synthetic_session(
                "https://cloud.example",
                "synthetic-client",
                unix_time_now() + 3600,
            ),
        );
        let agent = WindowsAgent::new(store.clone());
        {
            let mut state = agent.state.lock().unwrap();
            state.online_authenticated = true;
            state.needs_refresh = false;
        }
        *store.fail_revokes.lock().unwrap() = true;

        let old_generation = agent.generation.load(Ordering::Acquire);
        assert!(agent.logout().is_err());
        assert_eq!(agent.status().unwrap()["connected"], false);
        assert!(agent.generation.load(Ordering::Acquire) > old_generation);
        let state = agent.state.lock().unwrap();
        assert!(state.session.is_some());
        assert!(!state.online_authenticated && state.needs_refresh);
        assert!(state.logout_pending && !state.refreshing);
        assert_eq!(
            agent.generation.load(Ordering::Acquire),
            state.active_generation
        );
        assert!(store.active_identity.lock().unwrap().is_some());
    }

    #[test]
    fn sign_in_is_not_reported_connected_when_protected_storage_fails() {
        let store = Arc::new(MemoryStore::default());
        *store.fail_saves.lock().unwrap() = true;
        let agent = Arc::new(WindowsAgent {
            source_admissions: None,
            vault_sessions: Arc::new(raiun_vault::session::VaultSessionCoordinator::new()),
            profile_scope: "default".into(),
            session_store: store,
            state: Arc::new(Mutex::new(AccountState::default())),
            generation: Arc::new(std::sync::atomic::AtomicU64::new(1)),
            provider: Arc::new(ProviderManager::new()),
            auth_thread: Mutex::new(None),
            refresh_thread: Mutex::new(None),
            fresh_close_worker: Mutex::new(None),
            folder_lifecycle: Mutex::new(()),
            vault_credential_operation: Mutex::new(()),
            protected_recovery_tokens: Mutex::new(
                super::windows_vault_capture_recovery::Tokens::default(),
            ),
            #[cfg(all(test, debug_assertions))]
            synthetic_vault_completion_writer_probe: true,
        });
        let (server, fixture) = synthetic_oidc_server(true);
        let info = agent
            .begin_auth(&json!({"server":server,"client_id":"synthetic-client"}))
            .unwrap();
        let auth_url = url::Url::parse(info["url"].as_str().unwrap()).unwrap();
        let query: HashMap<_, _> = auth_url.query_pairs().into_owned().collect();
        let redirect = url::Url::parse(query.get("redirect_uri").unwrap()).unwrap();
        let callback = format!(
            "/?code=synthetic-code&state={}",
            query.get("state").unwrap()
        );
        let mut browser = TcpStream::connect(("127.0.0.1", redirect.port().unwrap())).unwrap();
        write!(
            browser,
            "GET {callback} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut reply = Vec::new();
        browser.read_to_end(&mut reply).unwrap();
        fixture.join().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while agent.status().unwrap()["authenticating"] == true && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        let status = agent.status().unwrap();
        assert_eq!(status["connected"], false);
        assert!(
            status["error"]
                .as_str()
                .unwrap()
                .contains("protected storage failure")
        );
    }

    #[test]
    fn cancelling_sign_in_invalidates_late_callback_completion() {
        let (server, fixture) = synthetic_oidc_server(false);
        let store = Arc::new(MemoryStore::default());
        let agent = Arc::new(WindowsAgent {
            source_admissions: None,
            vault_sessions: Arc::new(raiun_vault::session::VaultSessionCoordinator::new()),
            profile_scope: "default".into(),
            session_store: store.clone(),
            state: Arc::new(Mutex::new(AccountState::default())),
            generation: Arc::new(std::sync::atomic::AtomicU64::new(1)),
            provider: Arc::new(ProviderManager::new()),
            auth_thread: Mutex::new(None),
            refresh_thread: Mutex::new(None),
            fresh_close_worker: Mutex::new(None),
            folder_lifecycle: Mutex::new(()),
            vault_credential_operation: Mutex::new(()),
            protected_recovery_tokens: Mutex::new(
                super::windows_vault_capture_recovery::Tokens::default(),
            ),
            #[cfg(all(test, debug_assertions))]
            synthetic_vault_completion_writer_probe: true,
        });
        let _info = agent
            .begin_auth(&json!({"server":server,"client_id":"synthetic-client"}))
            .unwrap();
        assert_eq!(agent.status().unwrap()["authenticating"], true);
        assert_eq!(agent.cancel_auth().unwrap()["cancelled"], true);
        assert_eq!(agent.status().unwrap()["connected"], false);
        assert_eq!(agent.status().unwrap()["authenticating"], false);
        assert!(store.sessions.lock().unwrap().is_empty());
        fixture.join().unwrap();
    }

    #[test]
    fn cancellation_between_session_save_and_publication_never_connects() {
        let (server, fixture) = synthetic_oidc_server(true);
        let store = Arc::new(MemoryStore::default());
        *store.fail_removes.lock().unwrap() = true;
        let (reached_tx, reached_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        *store.publication_gate.lock().unwrap() = Some(Arc::new(PublicationGate {
            reached: reached_tx,
            release: Mutex::new(release_rx),
        }));
        let agent = Arc::new(WindowsAgent {
            source_admissions: None,
            vault_sessions: Arc::new(raiun_vault::session::VaultSessionCoordinator::new()),
            profile_scope: "default".into(),
            session_store: store.clone(),
            state: Arc::new(Mutex::new(AccountState::default())),
            generation: Arc::new(std::sync::atomic::AtomicU64::new(1)),
            provider: Arc::new(ProviderManager::new()),
            auth_thread: Mutex::new(None),
            refresh_thread: Mutex::new(None),
            fresh_close_worker: Mutex::new(None),
            folder_lifecycle: Mutex::new(()),
            vault_credential_operation: Mutex::new(()),
            protected_recovery_tokens: Mutex::new(
                super::windows_vault_capture_recovery::Tokens::default(),
            ),
            #[cfg(all(test, debug_assertions))]
            synthetic_vault_completion_writer_probe: true,
        });
        let info = agent
            .begin_auth(&json!({"server":server,"client_id":"synthetic-client"}))
            .unwrap();
        *store.fail_revokes.lock().unwrap() = true;
        let auth_url = url::Url::parse(info["url"].as_str().unwrap()).unwrap();
        let query: HashMap<_, _> = auth_url.query_pairs().into_owned().collect();
        let redirect = url::Url::parse(query.get("redirect_uri").unwrap()).unwrap();
        let callback = format!(
            "/?code=synthetic-code&state={}",
            query.get("state").unwrap()
        );
        let mut browser = TcpStream::connect(("127.0.0.1", redirect.port().unwrap())).unwrap();
        write!(
            browser,
            "GET {callback} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut reply = Vec::new();
        browser.read_to_end(&mut reply).unwrap();
        fixture.join().unwrap();
        reached_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("worker reaches the post-save publication barrier");

        let cancel_agent = Arc::clone(&agent);
        let (cancel_tx, cancel_rx) = mpsc::channel();
        let cancel_worker = thread::spawn(move || {
            cancel_tx.send(cancel_agent.cancel_auth()).unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        while agent.status().unwrap()["authenticating"] == true && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(agent.status().unwrap()["authenticating"], false);
        release_tx.send(()).unwrap();
        let cancelled = cancel_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("cancel waits for the worker to stop")
            .unwrap();
        cancel_worker.join().unwrap();

        assert_eq!(cancelled["cancelled"], true);
        assert_eq!(cancelled["cleanup_uncertain"], true);
        let status = agent.status().unwrap();
        assert_eq!(status["connected"], false);
        assert_eq!(status["session_cleanup_uncertain"], true);
        assert!(
            status["error"]
                .as_str()
                .unwrap()
                .contains("could not remove")
        );
        assert_eq!(store.sessions.lock().unwrap().len(), 1);
        assert!(store.active_identity.lock().unwrap().is_none());
        let restarted = WindowsAgent::new(store);
        assert_eq!(restarted.status().unwrap()["connected"], false);
    }

    #[test]
    fn failed_cleanup_of_unpublished_cancelled_blob_cannot_restore_it() {
        let store = Arc::new(MemoryStore::default());
        let session = synthetic_session(
            "https://cloud.example",
            "synthetic-client",
            unix_time_now() + 3600,
        );
        store.sessions.lock().unwrap().insert(
            (
                "default".into(),
                session.server.clone(),
                session.client_id.clone(),
            ),
            session.clone(),
        );
        *store.fail_revokes.lock().unwrap() = true;
        *store.fail_removes.lock().unwrap() = true;
        let state = Arc::new(Mutex::new(AccountState::default()));
        let store_trait: Arc<dyn SessionStore> = store.clone();

        record_cleanup_failure(&state, &store_trait, "default", &session);

        assert_eq!(store.sessions.lock().unwrap().len(), 1);
        assert!(store.active_identity.lock().unwrap().is_none());
        assert!(state.lock().unwrap().session_cleanup_uncertain);
        let restarted = WindowsAgent::new(store);
        assert_eq!(restarted.status().unwrap()["connected"], false);
    }

    #[test]
    fn requests_do_not_accept_passwords_over_the_generic_pipe_or_cli_path() {
        for request in [
            json!({"action":"vault_unlock","password":"sentinel"}),
            json!({"action":"status","password":"sentinel"}),
            json!({"action":"vault_unlock_offline"}),
        ] {
            assert!(reject_secret_request(&request).is_err());
        }
    }

    #[test]
    fn control_secret_admission_allows_only_valid_public_link_create_passwords() {
        let profile = "profile-0123456789abcdef0123456789abcdef";
        let valid = json!({
            "action":"sharing_link_create",
            "profile_id":profile,
            "expected_auth_generation":7,
            "space_id":"space-1",
            "path":"/folder",
            "expected_item_id":"item-1",
            "link_type":"view",
            "password":"synthetic-link-password"
        });
        assert!(reject_control_secret_request(&valid).is_ok());
        assert!(reject_secret_request(&valid).is_err(), "CLI remains strict");

        for invalid in [
            json!({
                "action":"sharing_link_create",
                "profile_id":profile,
                "expected_auth_generation":7,
                "space_id":"space-1",
                "path":"/folder",
                "expected_item_id":"item-1",
                "link_type":"view",
                "password":""
            }),
            json!({
                "action":"sharing_link_create",
                "profile_id":profile,
                "expected_auth_generation":7,
                "space_id":"space-1",
                "path":"/folder",
                "expected_item_id":"item-1",
                "link_type":"view",
                "password":"x".repeat(73)
            }),
            json!({"action":"sharing_invite","profile_id":profile,"password":"synthetic"}),
            json!({"action":"vault_unlock","profile_id":profile,"password":"synthetic"}),
        ] {
            assert!(reject_control_secret_request(&invalid).is_err());
        }
    }

    #[cfg(all(windows, debug_assertions))]
    struct R114TracingIdentityCatalog {
        inner: Arc<dyn raiun_cloudfiles_windows::ProviderIdentityCatalog>,
    }

    #[cfg(all(windows, debug_assertions))]
    impl raiun_cloudfiles_windows::ProviderIdentityCatalog for R114TracingIdentityCatalog {
        fn load(
            &self,
            scope: &raiun_cloudfiles_windows::ProviderIdentityCatalogScope,
        ) -> Result<
            Vec<raiun_cloudfiles_windows::ProviderIdentityBinding>,
            raiun_cloudfiles_windows::BackendError,
        > {
            println!("r114_catalog_load=start");
            let result = self.inner.load(scope);
            match &result {
                Ok(bindings) if bindings.is_empty() => println!("r114_catalog_load=ok_empty"),
                Ok(_) => println!("r114_catalog_load=ok_nonempty"),
                Err(_) => println!("r114_catalog_load=error"),
            }
            result
        }

        fn upsert(
            &self,
            scope: &raiun_cloudfiles_windows::ProviderIdentityCatalogScope,
            binding: &raiun_cloudfiles_windows::ProviderIdentityBinding,
        ) -> Result<(), raiun_cloudfiles_windows::BackendError> {
            println!("r114_catalog_upsert=start");
            let result = self.inner.upsert(scope, binding);
            println!(
                "r114_catalog_upsert={}",
                if result.is_ok() { "ok" } else { "error" }
            );
            result
        }

        fn remove(
            &self,
            scope: &raiun_cloudfiles_windows::ProviderIdentityCatalogScope,
            identity: raiun_cloudfiles_windows::OpaqueIdentity,
        ) -> Result<(), raiun_cloudfiles_windows::BackendError> {
            println!("r114_catalog_remove=start");
            let result = self.inner.remove(scope, identity);
            println!(
                "r114_catalog_remove={}",
                if result.is_ok() { "ok" } else { "error" }
            );
            result
        }
    }

    #[cfg(all(windows, debug_assertions))]
    fn r114_probe_catalog_path_depth(
        protector: &raiun_cloudfiles_windows::DpapiEditRecordProtector,
        real_state_directory: &Path,
    ) {
        use raiun_cloudfiles_windows::EditRecordProtector as _;
        use std::os::windows::ffi::OsStrExt as _;

        let local_state = protector.local_state_directory();
        // Same-length sibling name as the real test state directory, so each
        // corresponding catalog-depth path has the same UTF-16 length.
        let probe_state = local_state.join(format!(
            "r114-pathprobe-{}-{}",
            std::process::id(),
            unix_time_now()
        ));
        if let Err(error) = std::fs::create_dir(&probe_state) {
            println!(
                "r114_path_probe_create_state_os={}",
                error.raw_os_error().unwrap_or(-1)
            );
            return;
        }
        if let Err(error) = protector.protect_directory(&probe_state) {
            println!("r114_path_probe_acl_state={error:?}");
            return;
        }
        println!("r114_path_probe_acl_state=ok");
        let mut parent = probe_state.clone();
        let components = [
            "cloud-files-provider-identities-v1".to_owned(),
            "a".repeat(64),
            "b".repeat(32),
        ];
        let mut real_state = real_state_directory.to_path_buf();
        println!(
            "r114_path_units_probe_state={}",
            probe_state.as_os_str().encode_wide().count()
        );
        println!(
            "r114_path_units_real_state={}",
            real_state.as_os_str().encode_wide().count()
        );
        assert_eq!(
            probe_state.as_os_str().encode_wide().count(),
            real_state.as_os_str().encode_wide().count(),
            "fresh probe and real catalog directory must have equal UTF-16 path lengths"
        );
        for (index, component) in components.iter().enumerate() {
            let stage = index + 1;
            let next = parent.join(component);
            println!(
                "r114_path_units_probe_depth_{stage}={}",
                next.as_os_str().encode_wide().count()
            );
            real_state.push(component);
            println!(
                "r114_path_units_real_depth_{stage}={}",
                real_state.as_os_str().encode_wide().count()
            );
            assert_eq!(
                next.as_os_str().encode_wide().count(),
                real_state.as_os_str().encode_wide().count(),
                "fresh path probe must match the real catalog path length at each depth"
            );
            if let Err(error) = std::fs::create_dir(&next) {
                println!(
                    "r114_path_probe_create_depth_{stage}_os={}",
                    error.raw_os_error().unwrap_or(-1)
                );
                break;
            }
            println!("r114_path_probe_create_depth_{stage}=ok");
            match protector.protect_directory(&next) {
                Ok(()) => println!("r114_path_probe_acl_depth_{stage}=ok"),
                Err(error) => println!("r114_path_probe_acl_depth_{stage}={error:?}"),
            }
            parent = next;
        }
    }

    #[cfg(all(windows, debug_assertions))]
    #[test]
    #[ignore = "requires disposable Windows VM with current-user DPAPI and loopback fixture"]
    fn native_composite_root_preflight_localizes_catalog_failure() {
        use raiun_cloudfiles_windows::{
            DpapiEditRecordProtector, DurableEditRecoveryProvider, EditRecordProtector as _,
            OpenCloudPlaceholderBackend, ProviderIdentityCatalog, ProviderIdentityCatalogScope,
            ProviderScope, pin_configured_root,
        };
        use raiun_core::backend::CloudBackend as _;
        use std::os::windows::ffi::OsStrExt as _;

        let (server, fixture) = synthetic_personal_spaces_server(|_| {});
        let session = synthetic_session(&server, "synthetic-client", unix_time_now() + 3600);
        let client = Arc::new(
            raiun_opencloud::OpenCloudClient::new(&session.server, session.access_token.clone())
                .expect("construct exact synthetic provider client"),
        );
        let (personal_space_id, account_id, personal_root_id, spaces, context) =
            verified_account_roots(&client, &session.server)
                .expect("verify synthetic Spaces and Personal root before catalog access");
        assert_eq!(personal_space_id, "synthetic-personal-drive");
        assert_eq!(personal_root_id, "synthetic-personal-root");
        assert_eq!(spaces.iter().filter(|space| space.personal).count(), 1);
        println!("r114_preflight_spaces=ok");
        println!("r114_preflight_personal_root_first=ok");

        let personal = spaces
            .iter()
            .find(|space| space.id == personal_space_id && space.personal)
            .expect("the one verified synthetic Personal space");
        let root_second = client
            .stat_discovered_space_root_with_context(personal, context)
            .expect("stat the exact Personal root a second time");
        assert!(root_second.directory && !root_second.encrypted);
        assert_eq!(root_second.id, personal_root_id);
        println!("r114_preflight_personal_root_second=ok");

        let configured_server = client.configured_server_url();
        let expected_account = format!("{configured_server}\0{personal_space_id}")
            .bytes()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(account_id, expected_account);
        println!("r114_preflight_account_binding=ok");

        let root = std::env::temp_dir().join(format!(
            "Raiun-R114-Preflight-{}-{}",
            std::process::id(),
            unix_time_now()
        ));
        std::fs::create_dir(&root).expect("create one fresh empty diagnostic root");
        let root_lease = pin_configured_root(&root).expect("pin exact empty non-reparse root");
        let root_identity = root_lease.identity();

        let protector = DpapiEditRecordProtector::current_user()
            .expect("current-user synthetic test DPAPI protector");
        let state_directory = protector.local_state_directory().join(format!(
            "r114-preflight-{}-{}",
            std::process::id(),
            unix_time_now()
        ));
        std::fs::create_dir(&state_directory).expect("create fresh isolated catalog directory");
        protector
            .protect_directory(&state_directory)
            .expect("protect isolated catalog directory for this test user");
        println!(
            "r114_path_units_catalog_state={}",
            state_directory.as_os_str().encode_wide().count()
        );
        r114_probe_catalog_path_depth(&protector, &state_directory);
        // The normalized DPAPI state root also feeds the Windows cache VFS.
        // Exercise a private extended path beyond MAX_PATH, without cloud I/O.
        let cache_parent = state_directory.join("cache-path-probe-".to_owned() + &"a".repeat(160));
        std::fs::create_dir(&cache_parent).expect("create bounded long private cache parent");
        protector
            .protect_directory(&cache_parent)
            .expect("protect long cache parent");
        let cache = raiun_cache::Cache::open(&cache_parent, 1024 * 1024)
            .expect("open Windows cache VFS under extended private state path");
        cache.usage().expect("query extended-path cache database");
        drop(cache);
        println!("r114_extended_cache=ok");
        let scope = ProviderScope::new(
            &client,
            "r114-native-preflight-diagnostic".to_owned(),
            account_id,
            client.server_origin().expect("validated synthetic origin"),
        )
        .expect("bind provider to the verified synthetic account and token generation");
        let recovery = Arc::new(DurableEditRecoveryProvider::new(
            state_directory,
            scope.clone(),
            root_identity,
            protector,
        ));
        let inner_catalog = recovery.identity_catalog();
        let catalog: Arc<dyn ProviderIdentityCatalog> = Arc::new(R114TracingIdentityCatalog {
            inner: inner_catalog,
        });
        let catalog_scope = ProviderIdentityCatalogScope::new(
            &scope,
            root_identity,
            &personal_space_id,
            &personal_root_id,
        )
        .expect("construct exact account/Personal/root/local-root catalog key");
        let direct = catalog
            .load(&catalog_scope)
            .expect("directly preflight the fresh protected identity catalog");
        assert!(
            direct.is_empty(),
            "fresh diagnostic catalog must start empty"
        );
        println!("r114_catalog_direct_load=empty");

        let backend = OpenCloudPlaceholderBackend::new_with_identity_catalog(
            client,
            scope,
            root_identity,
            catalog,
        )
        .expect("construct backend with exact synthetic scope and catalog");
        let result = backend.register_composite_root_for(&personal_space_id, &personal_root_id);
        match result {
            Ok(_) => println!("r114_composite_register=ok"),
            Err(_) => {
                println!("r114_composite_register=error");
                panic!("composite preflight failed; fixed catalog/network stage markers retained");
            }
        }
        assert!(
            std::fs::read_dir(&root)
                .expect("inspect retained plain root")
                .next()
                .is_none()
        );
        drop(root_lease);
        fixture.join().expect("stop and join loopback fixture");
    }

    #[test]
    fn long_running_agent_actions_have_bounded_windows_pipe_timeouts() {
        assert_eq!(
            request_timeout(&json!({"action":"auth_begin"})),
            Duration::from_secs(65)
        );
        assert_eq!(
            request_timeout(&json!({"action":"auth_cancel"})),
            Duration::from_secs(300)
        );
        assert_eq!(
            request_timeout(&json!({"action":"shutdown"})),
            Duration::from_secs(300)
        );
        assert_eq!(
            request_timeout(&json!({"action":"status"})),
            Duration::from_secs(30)
        );
    }

    #[test]
    fn account_retirement_is_generation_bound_and_closes_runtime_admission() {
        let agent = Arc::new(
            WindowsAgent::new_for_profile("default", MemoryStore::default())
                .expect("create synthetic signed-out runtime"),
        );
        let generation = agent.generation.load(Ordering::Acquire);
        assert!(
            agent
                .begin_retirement(generation.saturating_add(1))
                .is_err()
        );
        assert!(!agent.state.lock().unwrap().retiring);

        agent
            .begin_retirement(generation)
            .expect("retire exact expected generation");
        assert_eq!(
            agent.generation.load(Ordering::Acquire),
            generation.saturating_add(1)
        );
        assert!(agent.state.lock().unwrap().retiring);
        assert!(
            agent
                .handle_request(&json!({"action":"network_proxy"}))
                .is_err()
        );

        agent.cancel_retirement();
        assert!(!agent.state.lock().unwrap().retiring);
        assert!(
            agent
                .handle_request(&json!({"action":"network_proxy"}))
                .is_ok()
        );
        agent.stop_and_join().expect("stop synthetic runtime");
    }
}
