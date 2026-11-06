//! Narrow Windows Cloud Files API boundary.
//!
//! This crate probes Cloud Files, safely inspects explicitly selected empty
//! local directories, and provides a narrowly scoped synthetic provider
//! fixture for disposable Windows tests. Root inspection does not register or
//! mount a provider; this is not yet a production sync provider.

use std::{error::Error as StdError, fmt};

mod backend;
#[cfg(any(windows, test))]
mod close_capture_admission;
#[cfg(any(windows, test))]
mod directory_create_phase;
mod edit_journal;
#[cfg(any(windows, test))]
mod file_create_phase;
mod initial_edit_queue;
#[cfg(any(windows, test))]
mod namespace_entry_observation;
#[cfg(windows)]
pub use namespace_entry_observation::NamespaceEntryKind;
#[cfg(windows)]
mod native_file_rename_producer;
#[cfg(any(windows, test))]
mod save_rename_admission;
#[cfg(windows)]
pub use native_file_rename_producer::NativeFileRenameError;
#[cfg(any(windows, test))]
pub mod namespace_file_delete;
#[cfg(any(windows, test))]
pub mod namespace_file_rename;
pub mod namespace_intent;
#[cfg(any(windows, test))]
pub mod namespace_reconcile;

mod opencloud;
#[cfg(windows)]
pub use opencloud::{
    VaultCachedChildCreateDescriptor, VaultCachedNamespaceDescriptor,
    VaultCachedNamespaceOperation, VaultCachedNamespaceQueued, VaultCachedRetargetDescriptor,
};

/// Expected current local presentation, supplied by authenticated custody.
/// This value is never authority without the guarded SDK proof and a fresh
/// physical-root inspection in `complete_cached_vault_pending`.
#[cfg(windows)]
pub struct VaultCachedNativeExpectation {
    pub root: ConfiguredRootIdentity,
    pub operation: raiun_opencloud::vault_cache::VaultPendingOperationKind,
    pub write_id: String,
    pub revision: u64,
    pub identity: [u8; 16],
    pub file: u64,
    pub usn: i64,
    pub components: Vec<String>,
    pub original: Option<raiun_core::backend::RemoteEntry>,
    pub entry: Option<raiun_core::backend::RemoteEntry>,
    pub plaintext_len: u64,
    pub source_sha256: Option<[u8; 32]>,
}

/// One-use factual native readback. Only the native owner constructs it from
/// a real guarded SDK proof; serialized pending rows cannot create this type.
#[cfg(windows)]
pub struct VaultCachedNativeCompleted {
    pub(crate) write_id: String,
    pub(crate) revision: u64,
    pub(crate) identity: [u8; 16],
    pub(crate) file: u64,
    pub(crate) usn: i64,
    pub(crate) entry: Option<raiun_core::backend::RemoteEntry>,
    pub(crate) observed_dirty: Option<vault_dirty::Observation>,
    pub(crate) root: ConfiguredRootIdentity,
    pub(crate) components: Vec<String>,
    pub(crate) length: u64,
    pub(crate) source_sha256: Option<[u8; 32]>,
}
#[cfg(windows)]
impl VaultCachedNativeCompleted {
    pub fn write_id(&self) -> &str {
        &self.write_id
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn identity(&self) -> [u8; 16] {
        self.identity
    }
    pub fn file(&self) -> u64 {
        self.file
    }
    pub fn usn(&self) -> i64 {
        self.usn
    }
    pub fn entry(&self) -> Option<&raiun_core::backend::RemoteEntry> {
        self.entry.as_ref()
    }
}
#[cfg(windows)]
pub use opencloud::{VaultCachedQueuedCapture, VaultCachedQueuedEdit};
#[cfg(windows)]
mod vault_cached_edit;
#[cfg(windows)]
pub use vault_cached_edit::{
    CachedVaultEditBaselineFacts, CachedVaultEditCapture, CachedVaultEditOperation,
    CachedVaultEditPending,
};
#[cfg(windows)]
pub(crate) mod recovery_admission;
mod recovery_provider;
mod recovery_reconcile;
#[cfg(windows)]
pub(crate) mod recovery_state;
#[cfg(any(windows, test))]
mod registration_domain;
#[cfg(any(windows, test))]
pub mod streamed_reconcile;
pub mod streamed_snapshot;
#[cfg(any(windows, test))]
pub mod streamed_store;
#[cfg(any(windows, test))]
pub use streamed_store::namespace_store;
#[cfg(any(windows, test))]
mod vault_capture_dispatch;
#[cfg(any(windows, test))]
pub use vault_capture_dispatch::FreshVaultCaptureDispatch;
#[cfg(windows)]
mod vault_completion;
#[cfg(any(windows, test))]
mod vault_dirty;
#[cfg(any(windows, test))]
mod vault_hydration;
#[cfg(windows)]
pub use vault_hydration::FreshVaultHydration;
#[cfg(any(windows, test))]
mod writable_cleanup_receipts;
#[cfg(windows)]
pub use vault_completion::{
    FreshVaultUpload, VaultLiveUploadOutcome, VaultLocalCompletionStore,
    VaultLocalCompletionTarget, VaultNativeCompletionProof, VaultNativePreparation,
    VaultUploadControl,
};
#[cfg(windows)]
pub mod vault_file_delete;
#[cfg(windows)]
mod vault_file_rename;
#[cfg(windows)]
pub mod vault_file_replace;
#[cfg(windows)]
pub use vault_file_rename::{
    VaultDirectoryRenameNode, VaultFileRenameDescriptor, VaultFileRenameDestination,
    VaultFileRenameFacts, VaultFileRenameRecord,
};
#[cfg(windows)]
pub mod vault_custody;
#[cfg(any(windows, test))]
pub mod vault_placeholder;
#[cfg(windows)]
pub mod vault_read;
#[cfg(windows)]
pub mod vault_routes;
#[cfg(windows)]
pub(crate) use backend::placeholder_population_completed;
pub use backend::{
    BackendError, BoundedPermit, BoundedPermitPool, CancellationToken, DEFAULT_FETCH_TIMEOUT,
    DeferredVaultCaptureNotification, EditRecoveryProvider, FetchRange,
    MAX_CONCURRENT_DIRECTORY_ENUMERATIONS, MAX_CONCURRENT_FETCHES, MAX_DIRECTORY_CHILDREN,
    MAX_FILE_BYTES, MAX_RANGE_BYTES, MAX_REQUEST_BYTES, MAX_STAGED_CALLBACKS,
    MAX_VAULT_EDIT_CAPTURE_BYTES, PlaceholderBackend, PlaceholderChild, PlaceholderEditBinding,
    PlaceholderMetadata, PreparedEditBinding, PreparedEditRecovery, PreparedEnumeration,
    PreparedFetch, PreparedFetchSession, PublishPermit, RequestPublicationGate,
    RequestPublicationPermit, StreamedRecoveryJob, StreamedRecoveryPolicy, checked_fetch_range,
    next_chunk_len,
};
#[cfg(windows)]
pub use backend::{ExistingVaultEditCapture, VaultCleanupRootLocator};
#[cfg(windows)]
pub use edit_journal::DpapiEditRecordProtector;
pub use edit_journal::{
    EditJournal, EditJournalScope, EditRecordProtector, ExplicitRecoveryApproval, JournalError,
    LocalEditMetadata, LocalEditRecord, LocalEditState, LocalFileIdentity, RecoveryAttemptOutcome,
    RecoveryAttemptState, RecoverySnapshot, RemoteEditBaseline,
};
pub use initial_edit_queue::{
    InitialEditDispatch, InitialEditLocation, MAX_PENDING_INITIAL_EDITS, PendingInitialEdit,
};
#[cfg(windows)]
pub(crate) use opencloud::CapturedDirectoryParent;
#[cfg(windows)]
pub use opencloud::FileRenameBindingCandidate;
#[cfg(any(windows, test))]
pub use opencloud::{
    DirectoryCreateSession, FileRenameSession, PlainFileCaptureParent,
    VerifiedDirectoryPublication, VerifiedFileRenamePublication,
};
pub use opencloud::{
    FileCacheBindingExpectation, FileCacheStatus, InitialEditSession, ListedFilePage,
    ListedFileRow, OpaqueIdentity, OpenCloudPlaceholderBackend, ProviderIdentityBinding,
    ProviderIdentityCatalog, ProviderIdentityCatalogScope, ProviderScope, VerifiedEditPublication,
};
#[cfg(windows)]
pub use opencloud::{
    FolderCacheBindingExpectation, ListedFolderPage, ListedFolderRow, OfflineDownloadError,
};
#[cfg(windows)]
pub use recovery_provider::StagedStreamedEdit;
pub use recovery_provider::{
    CompletedLocalEdit, DurableEditRecoveryProvider, InitialEditReceipt, SavedEditCloudCheck,
};
pub use recovery_reconcile::{
    MAX_RECOVERY_UPLOAD_ATTEMPTS, MAX_RECOVERY_UPLOAD_BYTES, OpenCloudRecoveryRemote,
    ReconciliationIssue, ReconciliationOutcome, RecoveryRemote, RecoveryRemoteBody,
    RecoveryRemoteVersion, VerifiedEditReadback, verify_edit_readback,
};
#[cfg(windows)]
pub use vault_custody::{
    ExistingVaultEditBaseline, ExistingVaultEditPayload, ExistingVaultUploadTarget,
};

#[cfg(windows)]
#[allow(unsafe_code)]
mod native;
#[cfg(windows)]
pub use native::native_file_create::{FileCreateReply, FileCreateStep, FileCreateTask};
#[cfg(windows)]
pub use native::native_namespace_directory::{
    DirectoryCreateReply, DirectoryCreateStep, DirectoryCreateTask,
};

/// Fresh native completion is distinct from closing a previously recorded
/// historical link after an interrupted durable commit.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileCreateContinuationOutcome {
    LocallyCompleted,
    HistoricalLinkCompleted,
    /// Original native ACK is historical evidence, not a permit for another PUT.
    HistoricalReviewRequired,
}

/// Fixed, data-free phase of an explicitly selected file-create recovery.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileCreateContinuationStage {
    Context,
    History,
    Capture,
    Remote,
    NativePreflight,
    NativeCompletion,
    NativeVerify,
    NativePublication,
    NativePostPublish,
    NativeSeal,
    Custody,
}

#[cfg(windows)]
impl fmt::Display for FileCreateContinuationStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Context => "account and drive verification",
            Self::History => "saved file verification",
            Self::Capture => "local file capture",
            Self::Remote => "cloud verification",
            Self::NativePreflight => "local completion preflight",
            Self::NativeCompletion => "local file completion",
            Self::NativeVerify => "converted file verification",
            Self::NativePublication => "completed identity publication",
            Self::NativePostPublish => "postpublication local verification",
            Self::NativeSeal => "local completion seal",
            Self::Custody => "recovery history completion",
        })
    }
}

/// Cloud Files API platform version. This reports API capability only; it is
/// not evidence that Raiun has connected a provider or mounted a drive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlatformVersion {
    pub build: u32,
    pub revision: u32,
    pub integration: u32,
}

/// Read-only connection-bound cached metadata. Implementations must return
/// None during uncertain/native capture activity, never scan files or bodies.
pub trait OrdinaryEditStatusSource: Send + Sync {
    fn cached_pending_count(&self) -> Option<usize>;
}

/// Read-only support evidence; no file names, identities or content are included.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VaultCleanupDiagnostics {
    pub modified_closes: usize,
    /// Legacy aggregate includes both actual close failures and reconnect
    /// inventory uncertainty; existing destructive-operation guards retain it.
    pub unverifiable_closes: usize,
    /// Actual observed close failures only; excludes reconnect scan inventory.
    pub observed_unverifiable_closes: usize,
    pub journaled_closes: usize,
    pub close_callbacks: usize,
    pub close_pool_refusals: usize,
    pub deleted_closes: usize,
    pub last_close_stage: usize,
    pub last_close_hresult: i32,
    /// None means the short inventory lock was unavailable, not complete.
    pub inventory_complete: Option<bool>,
}

// SDK helpers also compile on the host; only native workers emit these labels.
#[cfg_attr(not(windows), allow(dead_code))]
mod creation_preparation;
#[cfg(windows)]
mod file_create_completion_diagnostics;
#[cfg(windows)]
mod fresh_create_send_gate;
#[cfg_attr(not(windows), allow(dead_code))]
mod fresh_create_target;

/// An exact Space identity captured by the retained SDK create admission.
/// This read-only health input grants no dispatch or old-record authority.
#[cfg(windows)]
pub struct FreshCreateSpace {
    scope: EditJournalScope,
    target: Option<fresh_create_target::FreshCreateTarget>,
    preparation_trace: Option<std::sync::Arc<creation_preparation::Trace>>,
}
#[cfg(windows)]
impl FreshCreateSpace {
    pub(crate) fn from_verified_scope(scope: EditJournalScope) -> Self {
        Self {
            scope,
            target: None,
            preparation_trace: None,
        }
    }
    pub(crate) fn from_verified_target(
        scope: EditJournalScope,
        target: fresh_create_target::FreshCreateTarget,
    ) -> Self {
        Self {
            scope,
            target: Some(target),
            preparation_trace: None,
        }
    }
    pub(crate) fn target(&self) -> Option<&fresh_create_target::FreshCreateTarget> {
        self.target.as_ref()
    }
    pub(crate) fn with_preparation_trace(
        mut self,
        trace: std::sync::Arc<creation_preparation::Trace>,
    ) -> Self {
        self.preparation_trace = Some(trace);
        self
    }
    pub(crate) fn preparation_trace(&self) -> Option<&creation_preparation::Trace> {
        self.preparation_trace.as_deref()
    }
    pub(crate) fn scope(&self) -> &EditJournalScope {
        &self.scope
    }
}

#[cfg(windows)]
pub use streamed_store::namespace_file_store::PendingFileCreateClassification;

/// Authenticated namespace metadata counts; no bodies or recovery authority.
#[cfg(windows)]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NamespaceRecoverySummary {
    pub rename_records: usize,
    pub rename_unresolved: usize,
    pub directory_records: usize,
    pub directory_unresolved: usize,
    pub file_records: usize,
    pub file_unresolved: usize,
    /// Historical original native ACK0/0, with the join event still incomplete.
    /// This is not current-content verification or cleanup/recovery authority.
    pub file_acknowledged_join_gaps: usize,
    /// Static authenticated phase histogram, populated by explicit diagnostics.
    pub file_pending_classifications: Vec<PendingFileCreateClassification>,
    pub delete_records: usize,
    pub delete_unresolved: usize,
}

/// Fixed, non-path-bearing creation admission boundaries.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateAdmissionStage {
    Candidate,
    OwnerBorrow,
    OwnerClosed,
    OwnerCounter,
    NativeContext,
    UnverifiedClose,
    VaultDirty,
    RecoveryContext,
    RecoveryScan,
    RecoveryPending,
    ContentScan,
    ContentPending,
    CloseAdmission,
    OriginalJob,
    Authorization,
    Ticket,
    Root,
}
#[cfg(windows)]
impl CreateAdmissionStage {
    pub fn reason(self) -> &'static str {
        match self {
            Self::Candidate => {
                "Creation paused: candidate or account authorization changed. Recovery files have been kept."
            }
            Self::OwnerBorrow => {
                "Creation paused: native owner is already borrowed. Recovery files have been kept."
            }
            Self::OwnerClosed => {
                "Creation paused: native creation owner is closed. Recovery files have been kept."
            }
            Self::OwnerCounter => {
                "Creation paused: native creation owner counter is exhausted. Recovery files have been kept."
            }
            Self::NativeContext => {
                "Creation paused: native account, root or dirty-close context could not be verified. Recovery files have been kept."
            }
            Self::UnverifiedClose => {
                "Creation paused: a native placeholder close could not be verified. Recovery files have been kept."
            }
            Self::VaultDirty => {
                "Creation paused: protected vault capture is pending or could not be verified. Recovery files have been kept."
            }
            Self::RecoveryContext => {
                "Creation paused: protected recovery account or root binding could not be verified. Recovery files have been kept."
            }
            Self::RecoveryScan => {
                "Creation paused: protected recovery history could not be verified. Recovery files have been kept."
            }
            Self::RecoveryPending => {
                "Creation paused: unresolved protected recovery history needs review. Recovery files have been kept."
            }
            Self::ContentScan => {
                "Creation paused: retained content history could not be verified. Recovery files have been kept."
            }
            Self::ContentPending => {
                "Creation paused: retained content recovery needs review. Recovery files have been kept."
            }
            Self::CloseAdmission => {
                "Creation paused: native close-admission bookkeeping is unknown. Recovery files have been kept."
            }
            Self::OriginalJob => {
                "Creation paused: the original job expired or was cancelled. Recovery files have been kept."
            }
            Self::Authorization => {
                "Creation paused: original account authorization is no longer current. Recovery files have been kept."
            }
            Self::Ticket => {
                "Creation paused: original native close-admission ticket is no longer current. Recovery files have been kept."
            }
            Self::Root => {
                "Creation paused: original registered root could not be verified. Recovery files have been kept."
            }
        }
    }
}

/// Safe, non-path-bearing error from the Cloud Files adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// This target does not provide the Windows Cloud Files API.
    UnsupportedPlatform,
    /// A native Cloud Files operation failed. The code is an HRESULT.
    Native {
        operation: &'static str,
        hresult: i32,
    },
    /// The synthetic test directory could not be created or removed.
    Io {
        operation: &'static str,
        kind: std::io::ErrorKind,
    },
    /// The test directory was unexpectedly not empty before registration.
    SyntheticRootNotEmpty,
    /// The path could not be represented as a bounded Windows path.
    InvalidSyntheticPath,
    /// A callback or native operation found unexpected content in the test root.
    SyntheticRootChanged,
    /// The requested synthetic callback fixture did not complete correctly.
    SyntheticCallbackFailed,
    /// A protected edit-recovery capability could not be prepared for this
    /// account/root, so the native provider connection was not started.
    EditRecoveryUnavailable,
    #[cfg(windows)]
    CreateAdmission { stage: CreateAdmissionStage },
    /// A selected file-create continuation stopped at a fixed safe phase.
    #[cfg(windows)]
    FileCreateContinuation { stage: FileCreateContinuationStage },
    /// A configured sync root is not a safe ordinary local directory.
    InvalidConfiguredRoot,
    /// A configured sync root must be empty before Raiun adopts it.
    ConfiguredRootNotEmpty,
    /// The selected root's path or stable file identity changed.
    ConfiguredRootChanged,
    /// Native connection ownership state did not match its lease.
    ConnectionStateInvalid,
    /// The exact owned observer still has outstanding I/O. Keep the whole
    /// connection alive and retry normal cancellation/drain; do not force-drop.
    NamespaceObserverDrainPending,
    /// The exact authenticated account namespace could not be enumerated.
    ProviderUnavailable,
    /// At least one closed placeholder has modified or unverifiable data.
    /// The registration is deliberately retained for recovery.
    UnresolvedPlaceholderEdits,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => {
                formatter.write_str("Windows Cloud Files is unavailable on this platform")
            }
            Self::Native { operation, hresult } => {
                write!(formatter, "{operation} failed (HRESULT {hresult:#010x})")
            }
            Self::Io { operation, kind } => write!(formatter, "{operation} failed ({kind})"),
            Self::SyntheticRootNotEmpty => {
                formatter.write_str("synthetic registration directory was not empty")
            }
            Self::InvalidSyntheticPath => {
                formatter.write_str("synthetic registration path is invalid")
            }
            Self::SyntheticRootChanged => {
                formatter.write_str("synthetic registration root ownership changed")
            }
            Self::SyntheticCallbackFailed => {
                formatter.write_str("synthetic provider callback failed")
            }
            Self::EditRecoveryUnavailable => formatter
                .write_str("durable edit recovery is unavailable for this account and root"),
            #[cfg(windows)]
            Self::CreateAdmission { stage } => formatter.write_str(stage.reason()),
            #[cfg(windows)]
            Self::FileCreateContinuation { stage } => {
                write!(
                    formatter,
                    "saved file recovery could not finish during {stage}"
                )
            }
            Self::InvalidConfiguredRoot => {
                formatter.write_str("configured root is not a safe local directory")
            }
            Self::ConfiguredRootNotEmpty => {
                formatter.write_str("configured root must be empty before setup")
            }
            Self::ConfiguredRootChanged => formatter.write_str("configured root identity changed"),
            Self::ConnectionStateInvalid => {
                formatter.write_str("Cloud Files connection state is invalid")
            }
            Self::NamespaceObserverDrainPending => formatter
                .write_str("directory observation I/O is still draining; connection retained"),
            Self::ProviderUnavailable => {
                formatter.write_str("the authenticated provider namespace is unavailable")
            }
            Self::UnresolvedPlaceholderEdits => formatter.write_str(
                "modified or unverifiable placeholder data must be recovered before unregistering",
            ),
        }
    }
}

impl StdError for Error {}

/// Stable Windows filesystem identity captured for an explicitly selected
/// ordinary directory. This does not imply Cloud Files registration/mounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfiguredRootIdentity {
    pub volume_serial: u32,
    pub file_index: u64,
}

/// A validated empty root whose component handles remain open during the
/// configuration transaction. Callers must revalidate the path identity
/// immediately before and after persistence; an open handle alone is not a
/// guarantee that every filesystem operation will block renames.
#[allow(dead_code)]
pub struct ConfiguredRootLease {
    identity: ConfiguredRootIdentity,
    registered: bool,
    #[cfg(windows)]
    path: std::path::PathBuf,
    #[cfg(windows)]
    _native: native::RootInspectionLease,
}

impl ConfiguredRootLease {
    pub fn identity(&self) -> ConfiguredRootIdentity {
        self.identity
    }
}

/// Validate an empty local directory and retain its no-follow component
/// handles for a config transaction. It does not create a Cloud Files
/// registration; callers must revalidate the path before using the identity.
pub fn pin_configured_root(path: &std::path::Path) -> Result<ConfiguredRootLease, Error> {
    #[cfg(windows)]
    {
        let inner = native::pin_configured_root(path)?;
        Ok(ConfiguredRootLease {
            identity: inner.identity,
            registered: false,
            #[cfg(windows)]
            path: path.to_path_buf(),
            _native: inner,
        })
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(Error::UnsupportedPlatform)
    }
}

/// Re-pin an already registered root from persisted configuration. The path
/// must still resolve to the exact stored directory identity, and the Cloud
/// Files registration's provider name/version and opaque root identity must
/// match Raiun's registration. Existing namespace contents are allowed here;
/// the empty-root adoption rule remains exclusive to `pin_configured_root`.
pub fn pin_registered_configured_root(
    path: &std::path::Path,
    expected: ConfiguredRootIdentity,
) -> Result<ConfiguredRootLease, Error> {
    #[cfg(windows)]
    {
        let inner = native::pin_registered_configured_root(path, expected)?;
        Ok(ConfiguredRootLease {
            identity: inner.identity,
            registered: true,
            path: path.to_path_buf(),
            _native: inner,
        })
    }
    #[cfg(not(windows))]
    {
        let _ = (path, expected);
        Err(Error::UnsupportedPlatform)
    }
}

/// Borrowed proof for preparing protected vault metadata. Construction requires
/// an actual pinned root and the current authenticated composite backend. This
/// does not prove complete historical custody or authorize any native cleanup.
#[cfg(windows)]
pub struct VaultCustodyRootContext<'a> {
    lease: &'a ConfiguredRootLease,
    backend: &'a OpenCloudPlaceholderBackend,
    composite: OpaqueIdentity,
    registration: String,
}

#[cfg(windows)]
impl VaultCustodyRootContext<'_> {
    pub fn provider_scope(&self) -> &ProviderScope {
        self.backend.scope()
    }

    pub fn root_identity(&self) -> ConfiguredRootIdentity {
        self.lease.identity()
    }

    /// Expected registration domain, including the checked native SyncRootIdentity
    /// and the authenticated backend's composite identity. This does not claim
    /// native readback of CF_SYNC_REGISTRATION.FileIdentity.
    pub fn registration_binding(&self) -> &str {
        &self.registration
    }

    pub fn is_new_registration(&self) -> bool {
        !self.lease.registered
    }

    /// Re-pin rather than relying on the old component handles to prevent every
    /// rename. Call before and after protected initialization/persistence.
    pub fn revalidate(&self) -> Result<(), Error> {
        if !self.backend.owns_composite_root_identity(self.composite) {
            return Err(Error::ConfiguredRootChanged);
        }
        let current = if self.lease.registered {
            pin_registered_configured_root(&self.lease.path, self.lease.identity())?
        } else {
            pin_configured_root(&self.lease.path)?
        };
        if current.identity() != self.lease.identity()
            || !self.backend.owns_composite_root_identity(self.composite)
        {
            return Err(Error::ConfiguredRootChanged);
        }
        Ok(())
    }
}

/// No caller-supplied "fresh" boolean or filesystem identity is accepted here.
#[cfg(windows)]
pub fn prepare_vault_custody_root<'a>(
    lease: &'a ConfiguredRootLease,
    backend: &'a OpenCloudPlaceholderBackend,
    composite: OpaqueIdentity,
) -> Result<VaultCustodyRootContext<'a>, Error> {
    let context = VaultCustodyRootContext {
        lease,
        backend,
        composite,
        registration: native::vault_custody_registration_binding(lease.identity(), composite)?,
    };
    context.revalidate()?;
    Ok(context)
}

/// Complete, preflighted input for a configured-root connection. The root,
/// authenticated backend scope, and durable recovery lease are acquired as a
/// unit before Cloud Files callbacks can start.
#[cfg(windows)]
#[allow(dead_code)]
pub struct PreparedConfiguredRootRuntime {
    root: ConfiguredRootLease,
    backend: std::sync::Arc<OpenCloudPlaceholderBackend>,
    composite_root_identity: OpaqueIdentity,
    recovery: std::sync::Arc<dyn PreparedEditRecovery>,
    vault_history: Option<std::sync::Arc<dyn vault_custody::VaultPublishedHistorySource>>,
}

/// Prepare all required identity and recovery capabilities before native root
/// registration or connection. A recovery-preflight failure leaves the root
/// unregistered and no callback route active.
#[cfg(windows)]
#[allow(dead_code)]
pub fn prepare_configured_root_runtime(
    lease: ConfiguredRootLease,
    backend: std::sync::Arc<OpenCloudPlaceholderBackend>,
    composite_root_identity: OpaqueIdentity,
    recovery_provider: std::sync::Arc<dyn EditRecoveryProvider>,
) -> Result<PreparedConfiguredRootRuntime, Error> {
    if !backend.owns_composite_root_identity(composite_root_identity) {
        return Err(Error::ConfiguredRootChanged);
    }
    let recovery = prepare_root_recovery(&backend, lease.identity(), recovery_provider.as_ref())?;
    Ok(PreparedConfiguredRootRuntime {
        root: lease,
        backend,
        composite_root_identity,
        recovery,
        vault_history: None,
    })
}

/// Attach only the trusted protected-history service. The native owner invokes
/// it after CfConnectSyncRoot establishes the sole root connection, while data
/// callbacks remain fenced. Merely attaching it cannot admit vault sessions.
#[cfg(windows)]
pub fn attach_vault_published_history(
    mut runtime: PreparedConfiguredRootRuntime,
    history: std::sync::Arc<dyn vault_custody::VaultPublishedHistorySource>,
) -> Result<PreparedConfiguredRootRuntime, Error> {
    prepare_vault_custody_root(
        &runtime.root,
        runtime.backend.as_ref(),
        runtime.composite_root_identity,
    )?
    .revalidate()?;
    runtime.vault_history = Some(history);
    Ok(runtime)
}

#[cfg(any(windows, test))]
fn prepare_root_recovery(
    backend: &OpenCloudPlaceholderBackend,
    root_identity: ConfiguredRootIdentity,
    provider: &dyn EditRecoveryProvider,
) -> Result<std::sync::Arc<dyn PreparedEditRecovery>, Error> {
    let scope = backend.scope();
    if backend.is_revoked() || scope.token_generation() == 0 {
        return Err(Error::EditRecoveryUnavailable);
    }
    let recovery = provider
        .prepare(scope, root_identity)
        .map_err(|_| Error::EditRecoveryUnavailable)?;
    if backend.is_revoked()
        || recovery.provider_scope() != scope
        || recovery.root_identity() != root_identity
    {
        return Err(Error::EditRecoveryUnavailable);
    }
    Ok(recovery)
}

/// Connect only from the full preflighted runtime bundle. Ordinary shutdown
/// disconnects without unregistering the persisted placeholder namespace.
#[cfg(windows)]
#[allow(dead_code)]
pub fn connect_configured_root(
    runtime: PreparedConfiguredRootRuntime,
) -> Result<ConfiguredRootConnection, Error> {
    Ok(ConfiguredRootConnection {
        inner: native::ConfiguredRootConnection::connect(runtime)?,
    })
}

/// Connect the normal account-bound Windows drive with clean-file delete
/// callbacks. The owner supplies its original generation fence; no path or
/// recovered history can create a new dispatch capability.
#[cfg(windows)]
pub fn connect_configured_root_with_file_delete(
    runtime: PreparedConfiguredRootRuntime,
    authorization: namespace_intent::CapturedAuthorization,
    current: std::sync::Arc<dyn Fn(namespace_intent::CapturedAuthorization) -> bool + Send + Sync>,
    generation: std::sync::Arc<std::sync::atomic::AtomicU64>,
) -> Result<ConfiguredRootConnection, Error> {
    native::ConfiguredRootConnection::connect_owned_delete(
        runtime,
        native::native_file_delete::Config {
            authorization,
            current,
            generation: Some(generation),
        },
    )
    .map(|inner| ConfiguredRootConnection { inner })
}

/// Owner-thread-only held writable eviction proof. Dropping it releases native
/// references but never confirms cleanup or reconstructs authority from history.
#[cfg(windows)]
pub struct VaultCleanupFence {
    inner: native::VaultCleanupFence,
}

/// Internal connection lease for one fully prepared configured root.
#[cfg(windows)]
#[allow(dead_code)]
pub struct ConfiguredRootConnection {
    inner: native::ConfiguredRootConnection,
}

/// Closed plain-file capture guard. No public constructor, serialization,
/// upload/conversion operation or historical-record adoption exists.
#[cfg(windows)]
pub struct NativePlainFileCapture<'connection, 'parent, 'lease> {
    inner: native::native_plain_file_capture::NativePlainFileCapture<'connection, 'parent, 'lease>,
}
/// Explicit same-invocation outcomes; retained incomplete states never grant replay.
#[cfg(windows)]
#[derive(Debug, Eq, PartialEq)]
pub enum FreshFileCreateOutcome {
    BusyBeforeCapture,
    CapturedLocalIncomplete,
    SubmittedUncertain,
    RemoteVerifiedLocalIncomplete,
    LocallyCompleted,
}
#[cfg(windows)]
impl NativePlainFileCapture<'_, '_, '_> {
    /// Returns protected local evidence only. No network/conversion/in-sync.
    pub fn capture_and_join(
        self,
        store: &std::sync::Arc<streamed_store::namespace_file_store::FileCreateStore>,
    ) -> Result<streamed_store::namespace_file_store::PublishedFileJoin, Error> {
        self.inner.capture_and_join(store)
    }
}

/// Owner-thread bounded scan state. It contains no publication authority and
/// must be discarded when its original connection context is retired.
#[cfg(windows)]
pub struct NamespaceScanCursor {
    inner: native::native_namespace_scan::Scan,
}
#[cfg(windows)]
pub struct NamespaceDirectoryCandidate {
    pub parent_components: Vec<String>,
    pub name: String,
    pub local_file: LocalFileIdentity,
}
/// Hints only, including when `finished`: no scan establishes continuity or
/// grants ordinary classification, catalog adoption or namespace authority.
#[cfg(windows)]
pub struct NamespaceScanPage {
    pub candidates: Vec<NamespaceDirectoryCandidate>,
    pub finished: bool,
    pub limit_reached: bool,
}

/// Exact native plain-directory pins, not constructible from a path or stored
/// namespace report. Metadata is exposed only after current owned CF parent
/// routing, complete no-follow pins and FileIDs have independently joined.
#[cfg(windows)]
pub struct PreparedNamespaceDirectory<'connection> {
    inner: native::native_namespace_directory::PinnedNamespaceDirectory<'connection>,
}
/// Value-only diagnostic snapshot; no admission, clean-state or completion authority.
#[cfg(all(windows, debug_assertions, feature = "synthetic-agent-integration"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RenamePublicEntryFixtureActivity {
    pub dirty_close_entries: u64,
    pub close_admission_unknown: bool,
    pub active_callbacks: usize,
    pub active_fetches: usize,
    pub staged_fetches: usize,
    pub modified_closes: usize,
    pub journaled_closes: usize,
    pub unverifiable_closes: usize,
}
#[cfg(all(windows, debug_assertions, feature = "synthetic-agent-integration"))]
pub type RenamePublicEntryFixtureActivitySource =
    std::sync::Arc<dyn Fn() -> Option<RenamePublicEntryFixtureActivity> + Send + Sync>;
/// Only the two fixed R58 fixture file names; never a caller-provided path.
#[cfg(all(windows, debug_assertions, feature = "synthetic-agent-integration"))]
#[derive(Clone, Copy)]
pub enum RenamePublicEntryFixturePath {
    Source,
    Destination,
}
/// Physical metadata only. Constructing or serializing these values cannot
/// construct native admission, a live session or a publication capability.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamespaceDirectoryObservation {
    pub local_file: LocalFileIdentity,
    pub attributes: u32,
    pub reparse_tag: u32,
    pub placeholder_state: u32,
    pub opaque_identity: Option<[u8; 16]>,
}
/// Value-only metadata from a pinned, no-follow Personal entry. The kind only
/// distinguishes physical entry shapes; it does not establish provider ownership,
/// clean content, continuity, a completed upload or permission to mutate it.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamespaceEntryObservation {
    pub local_file: LocalFileIdentity,
    pub kind: NamespaceEntryKind,
    pub attributes: u32,
    pub reparse_tag: u32,
    pub placeholder_state: u32,
    pub byte_len: u64,
}
/// Copied physical metadata from a live connected root. These values are
/// untrusted hints; they carry no retained pin, classification, publication
/// permission or native completion authority.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamespaceFileObservation {
    pub local_file: LocalFileIdentity,
    pub attributes: u32,
    pub reparse_tag: u32,
    pub placeholder_state: u32,
    pub byte_len: u64,
}
#[cfg(windows)]
pub struct NativeDirectoryCreateLocal<'pin, 'connection, 'session, 'backend> {
    inner: native::native_namespace_directory::NativeDirectoryLocal<
        'pin,
        'connection,
        'session,
        'backend,
    >,
}
#[cfg(windows)]
impl<'connection> PreparedNamespaceDirectory<'connection> {
    pub fn entry(&self) -> &namespace_intent::LocalNamespaceEntry {
        self.inner.entry()
    }
    pub fn parent_identity(&self) -> OpaqueIdentity {
        self.inner.parent_identity()
    }
    pub fn intent(&self) -> namespace_intent::NamespaceIntent {
        self.inner.intent()
    }
    /// Recheck this pinned plain directory after a dispatch-lease wait. This
    /// local validation grants no publication authority; local.admit remains
    /// mandatory within the live publication session before mutation.
    pub fn validate_presend(
        &self,
        intent: &namespace_intent::NamespaceIntent,
    ) -> Result<(), Error> {
        self.inner.validate_presend(intent)
    }
    /// Physical metadata only, never a directory publication capability.
    pub fn observation(&self) -> Result<NamespaceDirectoryObservation, Error> {
        self.inner.observation()
    }
    pub fn local<'pin, 'session, 'backend>(
        &'pin mut self,
        session: &'session DirectoryCreateSession<'backend>,
    ) -> NativeDirectoryCreateLocal<'pin, 'connection, 'session, 'backend> {
        NativeDirectoryCreateLocal {
            inner: self.inner.local(session),
        }
    }
}
#[cfg(windows)]
impl namespace_reconcile::DirectoryCreateLocal for NativeDirectoryCreateLocal<'_, '_, '_, '_> {
    fn admit(
        &mut self,
        intent: &namespace_intent::NamespaceIntent,
    ) -> Result<(), raiun_core::backend::CloudError> {
        namespace_reconcile::DirectoryCreateLocal::admit(&mut self.inner, intent)
    }
    fn publish(
        &mut self,
        intent: &namespace_intent::NamespaceIntent,
        readback: &namespace_reconcile::DirectoryCreateReadback,
    ) -> Result<(), raiun_core::backend::CloudError> {
        namespace_reconcile::DirectoryCreateLocal::publish(&mut self.inner, intent, readback)
    }
    fn record_completion<F>(
        &mut self,
        intent: &namespace_intent::NamespaceIntent,
        readback: &namespace_reconcile::DirectoryCreateReadback,
        record: F,
    ) -> Result<(), namespace_reconcile::DirectoryCompletionError>
    where
        F: FnOnce() -> Result<(), streamed_store::StoreError>,
    {
        namespace_reconcile::DirectoryCreateLocal::record_completion(
            &mut self.inner,
            intent,
            readback,
            record,
        )
    }
}

/// Owned, untrusted hints from one exact connected-root observation instance.
/// This is neither a complete inventory nor account/namespace mutation,
/// conversion, clean-state or delete authority. Every consumer must revalidate
/// its own current agent/backend/root/ordinary-ancestry context.
#[cfg(windows)]
pub struct NamespaceObservation {
    root: ConfiguredRootIdentity,
    provider_scope: ProviderScope,
    instance: u64,
    poll: raiun_control_windows::directory_notifications::ObserverPoll,
}

#[cfg(windows)]
impl NamespaceObservation {
    pub fn root_identity(&self) -> ConfiguredRootIdentity {
        self.root
    }
    pub fn provider_scope(&self) -> &ProviderScope {
        &self.provider_scope
    }
    pub fn instance(&self) -> u64 {
        self.instance
    }
    /// Always true: observing hints cannot establish inventory continuity.
    pub fn inventory_unknown(&self) -> bool {
        true
    }
    pub fn poll(&self) -> &raiun_control_windows::directory_notifications::ObserverPoll {
        &self.poll
    }
}

#[cfg(windows)]
impl fmt::Debug for NamespaceObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NamespaceObservation")
            .field("instance", &self.instance)
            .field("inventory_unknown", &true)
            .finish_non_exhaustive()
    }
}

// Shared path correspondence only; native component and managed-parent admission
// remain mandatory. The first component is the local namespace, never a Space.
#[cfg(any(windows, test))]
fn personal_create_relative(parent: &[&str], leaf: &str) -> Option<String> {
    let prefix = match parent.first().copied() {
        Some("Personal") => 1,
        Some("Spaces") if parent.len() >= 2 => 2,
        _ => return None,
    };
    if parent.len() >= 256 {
        return None;
    }
    let valid = |part: &str| {
        !part.is_empty()
            && !matches!(part, "." | "..")
            && !part.contains(['/', '\\'])
            && !part.chars().any(char::is_control)
    };
    if !valid(leaf) || parent.iter().any(|part| !valid(part)) {
        return None;
    }
    // Bound before collecting/joining caller input, including separators.
    let total = parent
        .iter()
        .copied()
        .chain(std::iter::once(leaf))
        .try_fold(0usize, |total, part| {
            total.checked_add(part.len())?.checked_add(1)
        })?;
    if total > 32768 {
        return None;
    }
    let relative = parent[prefix..]
        .iter()
        .copied()
        .chain(std::iter::once(leaf))
        .collect::<Vec<_>>()
        .join("/");
    (relative.len() <= 32768).then_some(relative)
}

#[cfg(test)]
mod personal_create_path_tests {
    use super::personal_create_relative;
    #[test]
    fn parent_and_leaf_keep_exact_full_relative_path() {
        assert_eq!(
            personal_create_relative(&["Personal"], "file.bin").as_deref(),
            Some("file.bin")
        );
        assert_eq!(
            personal_create_relative(&["Personal", "Courses & CEUs #1", "nested"], "file.bin")
                .as_deref(),
            Some("Courses & CEUs #1/nested/file.bin")
        );
        assert_ne!(
            personal_create_relative(&["Personal", "a"], "file.bin"),
            personal_create_relative(&["Personal", "b"], "file.bin")
        );
    }
    #[test]
    fn invalid_scope_components_and_limits_refuse() {
        for parent in [
            vec![],
            vec!["Spaces"],
            vec!["personal"],
            vec!["Personal", ".."],
            vec!["Personal", "a/b"],
        ] {
            assert!(personal_create_relative(&parent, "file.bin").is_none());
        }
        assert!(personal_create_relative(&["Personal"], "a/b").is_none());
        assert!(personal_create_relative(&["Personal"], "").is_none());
        assert!(personal_create_relative(&vec!["Personal"; 256], "file.bin").is_none());
        assert!(personal_create_relative(&["Personal"], &"a".repeat(32768)).is_none());
    }
}

#[cfg(windows)]
#[allow(dead_code)]
impl ConfiguredRootConnection {
    /// Owner-thread observation only. Each fresh complete batch may supply
    /// rename hints, which still require independent live admission. Neither
    /// the first result nor later hints establish inventory continuity or
    /// permit adoption; inventory work requires its own bounded scan.
    pub fn attach_namespace_observer(&mut self) -> Result<NamespaceObservation, Error> {
        self.inner.attach_namespace_observer()
    }
    /// Production callers should pass ZERO. The test wait is capped at 250ms;
    /// all returned paths are untrusted hints, never namespace authority.
    /// An error does not prove I/O drained: retain the owner and call stop or
    /// normal disconnect, including after backend or token revocation.
    pub fn poll_namespace_observer(
        &mut self,
        wait: std::time::Duration,
    ) -> Result<NamespaceObservation, Error> {
        self.inner.poll_namespace_observer(wait)
    }
    /// Physical cancellation remains available after authentication revocation.
    /// A pending error retains the same observer/root/connection aggregate.
    pub fn stop_namespace_observer(&mut self, wait: std::time::Duration) -> Result<(), Error> {
        self.inner.stop_namespace_observer(wait)
    }
    /// Scheduling reservation only; no mutation/credential authority.
    pub fn namespace_file_operation_pending(&self) -> bool {
        self.inner.namespace_file_operation_pending()
    }
    /// Ignore duplicate hints only after exact original native publication and
    /// a fresh same-FileID/opaque/root metadata observation.
    pub fn completed_file_replacement(&self, components: &[&str]) -> Result<bool, Error> {
        self.inner.completed_file_replacement(components)
    }
    /// Retire an oldsource hint only with a completed target, fresh physical
    /// source absence and no admitted source catalog binding. No MOVE authority.
    pub fn completed_replacement_source_absent(
        &self,
        old: &[&str],
        new: &[&str],
    ) -> Result<bool, Error> {
        self.inner.completed_replacement_source_absent(old, new)
    }
    /// Inspect physical kind without admission, adoption, hydration or cloud I/O.
    /// A cloud-shaped entry can be excluded from ordinary-directory candidates;
    /// it must never be treated as proof of a healthy or completed upload.
    pub fn observe_namespace_entry(
        &self,
        components: &[&str],
    ) -> Result<NamespaceEntryObservation, Error> {
        self.inner.observe_namespace_entry(components)
    }
    /// Read metadata only for an existing Personal file placeholder beneath
    /// this connected root. Returned values never replace the public rename
    /// entry's independent account, catalog, native and capture admission.
    pub fn observe_namespace_file(
        &self,
        components: &[&str],
    ) -> Result<NamespaceFileObservation, Error> {
        self.inner.observe_namespace_file(components)
    }
    #[cfg(feature = "synthetic-agent-integration")]
    pub fn namespace_observer_fixture_file(
        &self,
    ) -> Result<(LocalFileIdentity, u32, u32, u64), Error> {
        self.inner.namespace_observer_fixture_file()
    }
    /// Weak, value-only source tied to this callback owner. No native handles escape.
    #[cfg(all(debug_assertions, feature = "synthetic-agent-integration"))]
    pub fn rename_public_entry_fixture_activity_source(
        &self,
    ) -> RenamePublicEntryFixtureActivitySource {
        self.inner.rename_public_entry_fixture_activity_source()
    }
    /// Nonblocking diagnostic snapshot, never a quiescence/admission capability.
    #[cfg(all(debug_assertions, feature = "synthetic-agent-integration"))]
    pub fn rename_public_entry_fixture_callback_counts(&self) -> Option<(usize, usize, usize)> {
        self.inner.rename_public_entry_fixture_callback_counts()
    }
    /// Read-only fixed R58 file metadata; no capture or publication authority.
    #[cfg(all(debug_assertions, feature = "synthetic-agent-integration"))]
    pub fn rename_public_entry_fixture_observation(
        &self,
        selected: RenamePublicEntryFixturePath,
    ) -> Result<NamespaceDirectoryObservation, Error> {
        self.inner.rename_public_entry_fixture_observation(selected)
    }
    /// Fixed synthetic Personal/Courses & CEUs #1/source.bin parent+file values;
    /// no caller path, native handle, read, mutation or completion capability.
    #[cfg(all(debug_assertions, feature = "synthetic-agent-integration"))]
    pub fn create_worker_subfolder_fixture_observation(
        &self,
    ) -> Result<(NamespaceDirectoryObservation, NamespaceDirectoryObservation), Error> {
        self.inner.create_worker_subfolder_fixture_observation()
    }
    /// Open only the namespace-rename store already associated with this live
    /// connection's prepared recovery capability. This grants storage access
    /// only; rename admission still requires the explicit live producer call.
    pub fn file_rename_store(
        &self,
        backend: &std::sync::Arc<OpenCloudPlaceholderBackend>,
        scope: &EditJournalScope,
        authorization: namespace_intent::CapturedAuthorization,
    ) -> Result<
        Option<std::sync::Arc<streamed_store::namespace_rename_store::FileRenameStore>>,
        Error,
    > {
        self.inner.file_rename_store(backend, scope, authorization)
    }

    pub fn prepare_plain_file_capture<'connection, 'parent, 'lease>(
        &'connection self,
        backend: &std::sync::Arc<OpenCloudPlaceholderBackend>,
        parent: &'parent PlainFileCaptureParent<'lease>,
        name: &str,
        record_generation: u64,
    ) -> Result<NativePlainFileCapture<'connection, 'parent, 'lease>, Error> {
        self.inner
            .prepare_plain_file_capture(backend, parent, name, record_generation)
            .map(|inner| NativePlainFileCapture { inner })
    }
    /// Start one owner-held attempt. Only the returned task may travel to a
    /// joined SDK worker; native custody stays inside this original connection.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_fresh_personal_file_create(
        &self,
        backend: &std::sync::Arc<OpenCloudPlaceholderBackend>,
        name: &str,
        authorization: namespace_intent::CapturedAuthorization,
        generation: u64,
        job: &StreamedRecoveryJob,
        current: std::sync::Arc<
            dyn Fn(namespace_intent::CapturedAuthorization) -> bool + Send + Sync,
        >,
    ) -> Result<FileCreateStep, Error> {
        self.inner.begin_fresh_personal_file_create(
            backend,
            name,
            authorization,
            generation,
            job,
            current,
        )
    }
    /// Start one create under an existing managed ordinary Personal parent.
    /// Components are immutable hints; the original owner independently admits
    /// the exact managed/native parent. No parent creation or fallback occurs.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_fresh_personal_file_create_in_parent(
        &self,
        backend: &std::sync::Arc<OpenCloudPlaceholderBackend>,
        parent_components: &[&str],
        name: &str,
        authorization: namespace_intent::CapturedAuthorization,
        generation: u64,
        job: &StreamedRecoveryJob,
        current: std::sync::Arc<
            dyn Fn(namespace_intent::CapturedAuthorization) -> bool + Send + Sync,
        >,
    ) -> Result<FileCreateStep, Error> {
        self.inner.begin_fresh_personal_file_create_in_parent(
            backend,
            parent_components,
            name,
            authorization,
            generation,
            job,
            current,
        )
    }
    /// Explicitly continue one interrupted create selected from protected
    /// recovery. Its current bytes are a new conditional edit, never a replay
    /// of the historical create or an acknowledgement of its old body.
    #[allow(clippy::too_many_arguments)]
    pub fn continue_personal_file_create(
        &self,
        backend: &std::sync::Arc<OpenCloudPlaceholderBackend>,
        parent_components: &[&str],
        name: &str,
        record_id: &str,
        record_generation: u64,
        authorization: namespace_intent::CapturedAuthorization,
        job: &StreamedRecoveryJob,
        current: std::sync::Arc<
            dyn Fn(namespace_intent::CapturedAuthorization) -> bool + Send + Sync,
        >,
    ) -> Result<FileCreateContinuationOutcome, Error> {
        self.inner.continue_personal_file_create(
            backend,
            parent_components,
            name,
            record_id,
            record_generation,
            authorization,
            job,
            current,
        )
    }

    /// Start one explicit ordinary Personal directory attempt. Only returned
    /// SDK tasks are Send; native pins/journal admission stay with this owner.
    /// Callers MUST close admission and drain/join actual SDK workers/results
    /// before auth/session mutation or disconnect. Backend revoke alone does
    /// not drain these unleased tasks. No Agent routing is enabled here.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_fresh_personal_directory_create(
        &self,
        backend: &std::sync::Arc<OpenCloudPlaceholderBackend>,
        parent_components: &[&str],
        name: &str,
        authorization: namespace_intent::CapturedAuthorization,
        generation: u64,
        job: &StreamedRecoveryJob,
        current: std::sync::Arc<
            dyn Fn(namespace_intent::CapturedAuthorization) -> bool + Send + Sync,
        >,
    ) -> Result<DirectoryCreateStep, Error> {
        self.inner.begin_fresh_personal_directory_create(
            backend,
            parent_components,
            name,
            authorization,
            generation,
            job,
            current,
        )
    }
    pub fn advance_fresh_personal_directory_create(
        &self,
        reply: DirectoryCreateReply,
    ) -> Result<DirectoryCreateStep, Error> {
        self.inner.advance_fresh_personal_directory_create(reply)
    }
    /// False means the original task data is still in flight. Drain/join SDK
    /// workers before disconnect; neither this call nor history grants replay.
    pub fn close_fresh_personal_directory_create(&self) -> bool {
        self.inner.close_fresh_personal_directory_create()
    }
    /// Compatibility driver of the SAME phases. This blocks its caller; actual
    /// Agent asynchronous scheduling is a separate, currently disabled route.
    #[allow(clippy::too_many_arguments)]
    pub fn reconcile_fresh_personal_directory_create(
        &self,
        backend: &std::sync::Arc<OpenCloudPlaceholderBackend>,
        parent_components: &[&str],
        name: &str,
        authorization: namespace_intent::CapturedAuthorization,
        generation: u64,
        job: &StreamedRecoveryJob,
        current: std::sync::Arc<
            dyn Fn(namespace_intent::CapturedAuthorization) -> bool + Send + Sync,
        >,
    ) -> Result<namespace_reconcile::DirectoryCreateOutcome, Error> {
        self.inner.reconcile_fresh_personal_directory_create(
            backend,
            parent_components,
            name,
            authorization,
            generation,
            job,
            current,
        )
    }
    /// Consume exactly the original attempt's next reply on the owner thread.
    pub fn advance_fresh_personal_file_create(
        &self,
        reply: FileCreateReply,
    ) -> Result<FileCreateStep, Error> {
        self.inner.advance_fresh_personal_file_create(reply)
    }
    /// Close admission/cancel original jobs. False retains root/native custody
    /// until actual task-owned SDK data is dropped; caller still joins workers.
    pub fn close_fresh_personal_file_create(&self) -> bool {
        self.inner.close_fresh_personal_file_create()
    }
    /// Explicit direct-Personal create with same-invocation native/custody completion.
    /// The currentness callback must use nonblocking original owner/epoch checks.
    #[allow(clippy::too_many_arguments)]
    pub fn reconcile_fresh_personal_file_create(
        &self,
        backend: &std::sync::Arc<OpenCloudPlaceholderBackend>,
        name: &str,
        authorization: namespace_intent::CapturedAuthorization,
        generation: u64,
        job: &StreamedRecoveryJob,
        current: std::sync::Arc<
            dyn Fn(namespace_intent::CapturedAuthorization) -> bool + Send + Sync,
        >,
    ) -> Result<FreshFileCreateOutcome, Error> {
        self.inner.reconcile_fresh_personal_file_create(
            backend,
            name,
            authorization,
            generation,
            job,
            current,
        )
    }
    #[cfg(all(debug_assertions, feature = "synthetic-agent-integration"))]
    pub fn namespace_directory_fixture_observation(
        &self,
        components: &[&str],
    ) -> Result<NamespaceDirectoryObservation, Error> {
        self.inner
            .namespace_directory_fixture_observation(components)
    }
    pub fn begin_namespace_scan(
        &self,
        backend: &std::sync::Arc<OpenCloudPlaceholderBackend>,
        composite: OpaqueIdentity,
        authorization: namespace_intent::CapturedAuthorization,
        generation: u64,
        max_entries: usize,
    ) -> Result<NamespaceScanCursor, Error> {
        self.inner
            .begin_namespace_scan(backend, composite, authorization, generation, max_entries)
            .map(|inner| NamespaceScanCursor { inner })
    }
    pub fn advance_namespace_scan(
        &self,
        backend: &std::sync::Arc<OpenCloudPlaceholderBackend>,
        cursor: &mut NamespaceScanCursor,
    ) -> Result<NamespaceScanPage, Error> {
        self.inner
            .advance_namespace_scan(backend, &mut cursor.inner)
    }
    /// Components are only observation hints. Current backend routing and the
    /// exact native handles, never those strings, provide admission evidence.
    pub fn prepare_namespace_directory<'connection>(
        &'connection self,
        backend: &std::sync::Arc<OpenCloudPlaceholderBackend>,
        parent_components: &[&str],
        name: &str,
        authorization: namespace_intent::CapturedAuthorization,
        generation: u64,
    ) -> Result<PreparedNamespaceDirectory<'connection>, Error> {
        self.inner
            .prepare_namespace_directory(
                backend,
                parent_components,
                name,
                authorization,
                generation,
            )
            .map(|inner| PreparedNamespaceDirectory { inner })
    }
    pub fn ordinary_edit_status_source(&self) -> std::sync::Arc<dyn OrdinaryEditStatusSource> {
        self.inner.ordinary_edit_status_source()
    }
    /// Conservative admission fence for new vault sessions. Unknown historical
    /// custody (including reconnects) refuses activation; this does not hide
    /// existing plaintext or prove complete filesystem cleanup.
    pub fn can_admit_vault_session(&self) -> bool {
        self.inner.can_admit_vault_session()
    }

    /// Fixed support counters only; this does not authorize cleanup or admission.
    pub fn vault_cleanup_diagnostics(&self) -> VaultCleanupDiagnostics {
        self.inner.vault_cleanup_diagnostics()
    }
    /// Authenticated namespace metadata counts only, never recovery authority.
    pub fn namespace_recovery_summary(&self) -> Result<NamespaceRecoverySummary, BackendError> {
        self.inner.namespace_recovery_summary()
    }

    /// Revoke/drain this retained route before cleaning recorded plaintext.
    /// Dirty/uncertain state or failed postproof returns incomplete cleanup;
    /// the owner must retain the route for retry and never report fully locked.
    pub fn cleanup_retired_vault_route(
        &self,
        route: &vault_routes::VerifiedVaultRoute,
    ) -> Result<(), Error> {
        let fence = self.begin_cleanup_retired_vault_route(route)?;
        self.finish_vault_cleanup(fence)
    }

    /// Revoke/drain and retain every writable eviction reference until finish.
    /// The provider keeps this opaque span on its owner thread across key clear.
    pub fn begin_cleanup_retired_vault_route(
        &self,
        route: &vault_routes::VerifiedVaultRoute,
    ) -> Result<VaultCleanupFence, Error> {
        let owned = route
            .revoke_and_cleanup_identities()
            .map_err(|_| Error::EditRecoveryUnavailable)?;
        self.inner
            .begin_cleanup_recorded_vault_files(route, &owned)
            .map(|inner| VaultCleanupFence { inner })
    }

    /// Final current proof on the same native connection, after owner key clear.
    pub fn finish_vault_cleanup(&self, fence: VaultCleanupFence) -> Result<(), Error> {
        self.inner.finish_vault_cleanup(fence.inner)
    }

    /// Conservative current connection footprint; absence is not Lock authority.
    pub fn writable_vault_cleanup_incomplete(&self) -> Result<bool, Error> {
        self.inner.writable_vault_cleanup_incomplete()
    }

    #[cfg(feature = "synthetic-agent-integration")]
    pub fn placeholder_on_disk_empty_for_integration(
        &self,
        relative_components: &[&str],
    ) -> Result<bool, Error> {
        self.inner
            .placeholder_on_disk_empty_for_integration(relative_components)
    }

    /// Denial-only fixture helper: deletes only this connection's volatile receipt.
    #[cfg(feature = "synthetic-agent-integration")]
    pub fn forget_writable_cleanup_receipt_for_integration(
        &self,
        identity: [u8; 16],
    ) -> Result<(), Error> {
        self.inner
            .forget_writable_cleanup_receipt_for_integration(identity)
    }

    /// Native owner-thread continuation of one fresh live vault upload. No
    /// historical proof, unlocked replacement route, or recovered ticket works.
    pub fn complete_vault_upload(
        &self,
        upload: FreshVaultUpload,
        store: &mut dyn VaultLocalCompletionStore,
    ) -> Result<(), Error> {
        self.inner.complete_vault_upload(upload, store)
    }

    /// Complete verified writable bytes under the same fresh native fences,
    /// without an explicit attribute or timestamp overwrite. Platform effects
    /// from Mark are sampled and verified. This does not restore READONLY or
    /// authorize cleanup/Lock from historical evidence.
    pub fn complete_writable_vault_upload(
        &self,
        upload: FreshVaultUpload,
        store: &mut dyn VaultLocalCompletionStore,
    ) -> Result<(), Error> {
        self.inner.complete_writable_vault_upload(upload, store)
    }

    /// Complete only the original current native object after guarded SDK
    /// reconciliation. The proof and physical inspection must both succeed.
    #[cfg(windows)]
    pub fn complete_cached_vault_pending(
        &self,
        backend: &std::sync::Arc<OpenCloudPlaceholderBackend>,
        route: &std::sync::Arc<vault_routes::VerifiedVaultRoute>,
        proof: &raiun_opencloud::vault_backend::VaultReconciledPending,
        expected: &VaultCachedNativeExpectation,
        provider: &std::sync::Arc<std::sync::atomic::AtomicU64>,
        provider_generation: u64,
    ) -> Result<VaultCachedNativeCompleted, Error> {
        self.inner.complete_cached_vault_pending(
            backend,
            route,
            proof,
            expected,
            provider,
            provider_generation,
        )
    }
    /// Retire one initial known-pending guard only after durable Agent custody
    /// has recorded the typed native completion returned by this connection.
    #[cfg(windows)]
    pub fn acknowledge_cached_native_durable(
        &self,
        completed: &VaultCachedNativeCompleted,
    ) -> Result<(), Error> {
        self.inner.acknowledge_cached_native_durable(completed)
    }
    /// Factual retained-root audit for a cached-only disconnect decision.
    /// This does not authorize cleanup, unregister, or clearing queued data.
    #[cfg(windows)]
    pub fn audit_cached_pending_for_disconnect(
        &self,
        history: &dyn vault_custody::VaultPublishedHistorySource,
        owner: &ProviderScope,
        registration: &str,
    ) -> Result<bool, Error> {
        self.inner
            .audit_cached_pending_for_disconnect(history, owner, registration)
    }
    /// Dehydrate disjoint clean published files while retaining exact queued
    /// cached objects and the registration for ordinary disconnect.
    #[cfg(windows)]
    pub fn cleanup_retired_vault_route_preserving_cached_pending(
        &self,
        route: &vault_routes::VerifiedVaultRoute,
        history: &dyn vault_custody::VaultPublishedHistorySource,
        owner: &ProviderScope,
        registration: &str,
    ) -> Result<bool, Error> {
        let owned = route
            .revoke_and_cleanup_identities()
            .map_err(|_| Error::EditRecoveryUnavailable)?;
        self.inner.cleanup_clean_history_preserving_cached_pending(
            route.local_root(),
            &owned,
            history,
            owner,
            registration,
        )
    }
    /// Exact per-file tracker observation only; never global cleanup authority.
    #[cfg(feature = "synthetic-agent-integration")]
    pub fn vault_file_pending_for_test(&self, identity: &[u8; 16]) -> Result<bool, Error> {
        self.inner.vault_file_pending_for_test(identity)
    }

    /// Complete one freshly verified existing file under its exact live
    /// backend session. Local components must come from the native handoff,
    /// not a guessed remote path. This never retires the journal. Failure
    /// retains recovery even if the OS accepted completion before a later
    /// validation failed.
    pub fn acknowledge_verified_edit(
        &self,
        local_components: &[&str],
        publication: &VerifiedEditPublication<'_, '_>,
    ) -> Result<(), Error> {
        self.inner
            .acknowledge_verified_edit(local_components, publication)
    }

    /// Current memory-only scheduling hint; never a dispatch or root proof.
    /// An empty queue avoids idle inspection. Every nonempty take must still
    /// pass all existing root, identity, registration and receipt checks.
    pub fn has_pending_initial_edit(&self) -> Result<bool, Error> {
        self.inner.has_pending_initial_edit()
    }

    /// Take one newly captured close receipt from this exact live connection.
    /// This never scans recovered edits or authorizes a remote mutation.
    pub fn take_initial_edit(&self) -> Result<Option<PendingInitialEdit>, Error> {
        self.inner.take_initial_edit()
    }

    /// Bounded callback telemetry for the synthetic agent integration test.
    /// No path, account identity, or file data is exposed.
    #[cfg(feature = "synthetic-agent-integration")]
    pub fn directory_observation(&self) -> (usize, usize, usize, usize, usize) {
        self.inner.directory_observation()
    }

    /// Fixed admission-stage number only; no paths or account data.
    #[cfg(feature = "synthetic-agent-integration")]
    pub fn fetch_validation_stage(&self) -> usize {
        self.inner.fetch_validation_stage()
    }

    /// Bounded hydration callback telemetry for the synthetic agent test.
    #[cfg(feature = "synthetic-agent-integration")]
    pub fn fetch_observation(&self) -> (usize, usize, usize, i32) {
        self.inner.fetch_observation()
    }

    /// Fixed, value-free close callback counters for the synthetic agent
    /// integration test. The production crate surface does not expose this.
    #[cfg(feature = "synthetic-agent-integration")]
    pub fn close_observation_for_integration(
        &self,
    ) -> (usize, usize, usize, usize, usize, i32, usize, usize) {
        self.inner.close_observation_for_integration()
    }

    /// Exact test-fixture placeholder metadata, with no path returned.
    #[cfg(feature = "synthetic-agent-integration")]
    pub fn placeholder_observation(
        &self,
        relative_components: &[&str],
    ) -> Result<(u32, u32, u32, u64), Error> {
        self.inner.placeholder_observation(relative_components)
    }

    /// Explicitly request hydration for a bounded synthetic fixture path.
    #[cfg(feature = "synthetic-agent-integration")]
    pub fn hydrate_test_placeholder(&self, relative_components: &[&str]) -> Result<i32, Error> {
        self.inner.hydrate_test_placeholder(relative_components)
    }

    /// Cancel/join the original delete owner before revoking backend read
    /// leases. Failure retains this connection and its original native custody.
    pub fn cancel_file_delete_in_place(&mut self) -> Result<(), Error> {
        self.inner.cancel_file_delete()
    }

    /// Retry a disconnect without discarding the lease if the OS rejects the
    /// operation. The caller retains the connection object on error and must
    /// keep its authenticated scope revoked until a later disconnect succeeds.
    pub fn disconnect_in_place(&mut self) -> Result<(), Error> {
        self.inner.disconnect()
    }

    /// Drain callbacks and disconnect for ordinary shutdown while preserving
    /// the Cloud Files registration and namespace for the next process run.
    pub fn disconnect(mut self) -> Result<(), Error> {
        self.disconnect_in_place()
    }

    /// Explicitly unregister this exact, identity-verified root. Ordinary app
    /// shutdown must use `disconnect` so placeholders remain available.
    pub fn unregister(self) -> Result<(), Error> {
        self.inner.unregister()
    }
}

/// Test-only bridge for exercising the complete agent-to-Cloud-Files
/// lifecycle in a disposable Windows VM. The default production build does
/// not expose this entry point, and the application has no call site for it.
#[cfg(all(windows, debug_assertions, feature = "synthetic-agent-integration"))]
pub mod synthetic_agent_integration {
    /// One-shot owner-thread diagnostic barrier; never a send or completion permit.
    #[cfg(debug_assertions)]
    pub use crate::save_rename_admission::completion_fixture::{
        Guard as FileRenameCompletionFixtureGuard, arm as arm_file_rename_completion_fixture,
    };

    use std::sync::Arc;

    use super::{
        ConfiguredRootConnection, ConfiguredRootLease, EditRecoveryProvider, Error,
        OpenCloudPlaceholderBackend, PreparedConfiguredRootRuntime, connect_configured_root,
        prepare_configured_root_runtime,
    };

    /// Opaque connection handle whose operations are intentionally limited to
    /// disconnect-preserving-registration and explicit unregister.
    pub struct Connection(ConfiguredRootConnection);

    /// Preflight the authenticated backend scope and durable recovery
    /// capability, then connect only the supplied pinned synthetic root.
    pub fn connect(
        lease: ConfiguredRootLease,
        backend: Arc<OpenCloudPlaceholderBackend>,
        personal_space_id: &str,
        personal_root_resource_id: &str,
        recovery: Arc<dyn EditRecoveryProvider>,
    ) -> Result<Connection, Error> {
        let composite_root_identity = backend
            .register_composite_root_for(personal_space_id, personal_root_resource_id)
            .map_err(|_| Error::ConfiguredRootChanged)?;
        let runtime: PreparedConfiguredRootRuntime =
            prepare_configured_root_runtime(lease, backend, composite_root_identity, recovery)?;
        connect_configured_root(runtime).map(Connection)
    }

    /// Explicit pre-connect delete diagnostic using the same owned delete
    /// callbacks as the normal account-bound app factory.
    pub fn connect_owned_delete(
        runtime: PreparedConfiguredRootRuntime,
        authorization: crate::namespace_intent::CapturedAuthorization,
        current: Arc<dyn Fn(crate::namespace_intent::CapturedAuthorization) -> bool + Send + Sync>,
    ) -> Result<Connection, Error> {
        crate::native::ConfiguredRootConnection::connect_owned_delete(
            runtime,
            crate::native::native_file_delete::Config {
                authorization,
                current,
                generation: None,
            },
        )
        .map(|inner| Connection(ConfiguredRootConnection { inner }))
    }

    impl Connection {
        #[cfg(all(test, debug_assertions))]
        pub fn namespace_directory_setup_diagnostics(&self) -> serde_json::Value {
            let (entries, rejected, callbacks, param_size, submitted) =
                self.0.directory_observation();
            let (_, _, _, first_failed_hresult) = self.0.fetch_observation();
            serde_json::json!({"directory_callback_entries":entries,"directory_guard_rejections":rejected,
                "directory_callbacks":callbacks,"last_directory_param_size":param_size,
                "placeholder_entries_submitted":submitted,"first_failed_hresult":first_failed_hresult})
        }
        pub fn prepare_namespace_directory<'a>(
            &'a self,
            backend: &Arc<OpenCloudPlaceholderBackend>,
            parent_components: &[&str],
            name: &str,
            authorization: super::namespace_intent::CapturedAuthorization,
            generation: u64,
        ) -> Result<super::PreparedNamespaceDirectory<'a>, Error> {
            self.0.prepare_namespace_directory(
                backend,
                parent_components,
                name,
                authorization,
                generation,
            )
        }
        #[cfg(all(test, debug_assertions))]
        pub fn namespace_directory_fixture_observation(
            &self,
            components: &[&str],
        ) -> Result<super::NamespaceDirectoryObservation, Error> {
            self.0
                .inner
                .namespace_directory_fixture_observation(components)
        }
        pub fn attach_namespace_observer(&mut self) -> Result<super::NamespaceObservation, Error> {
            self.0.attach_namespace_observer()
        }
        pub fn poll_namespace_observer(
            &mut self,
            wait: std::time::Duration,
        ) -> Result<super::NamespaceObservation, Error> {
            self.0.poll_namespace_observer(wait)
        }
        pub fn stop_namespace_observer(&mut self, wait: std::time::Duration) -> Result<(), Error> {
            self.0.stop_namespace_observer(wait)
        }
        pub fn namespace_observer_fixture_file(
            &self,
        ) -> Result<(super::LocalFileIdentity, u32, u32, u64), Error> {
            self.0.namespace_observer_fixture_file()
        }
        pub fn disconnect_in_place(&mut self) -> Result<(), Error> {
            self.0.disconnect_in_place()
        }
        /// Drain callbacks and disconnect while retaining registration.
        pub fn disconnect(self) -> Result<(), Error> {
            self.0.disconnect()
        }

        /// Explicitly remove the exact validated registration.
        pub fn unregister(self) -> Result<(), Error> {
            self.0.unregister()
        }
    }
}

/// Validate a user-selected Windows root without registering it as a sync
/// root. The directory and every ancestor must be ordinary non-reparse
/// directories, and the final directory must be empty at inspection time.
pub fn inspect_configured_root(path: &std::path::Path) -> Result<ConfiguredRootIdentity, Error> {
    #[cfg(windows)]
    {
        native::inspect_configured_root(path, true)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(Error::UnsupportedPlatform)
    }
}

/// Revalidate a previously selected root's current ordinary-directory
/// identity and empty-state while no provider owns its contents. No
/// registration occurs.
pub fn verify_configured_root_identity(
    path: &std::path::Path,
) -> Result<ConfiguredRootIdentity, Error> {
    #[cfg(windows)]
    {
        native::inspect_configured_root(path, true)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(Error::UnsupportedPlatform)
    }
}

/// Check whether two already-existing local roots overlap by directory
/// identity, including case/alias paths. Every component is pinned and
/// checked without following reparse points; no registration occurs.
pub fn configured_roots_overlap(
    left: &std::path::Path,
    right: &std::path::Path,
) -> Result<bool, Error> {
    #[cfg(windows)]
    {
        native::configured_roots_overlap(left, right)
    }
    #[cfg(not(windows))]
    {
        let _ = (left, right);
        Err(Error::UnsupportedPlatform)
    }
}

/// Compare an exactly identified, OS-registered Cloud Files root with a plain
/// private directory. Only the registered root's final component may be a
/// reparse point; all ancestors and the private directory remain plain.
pub fn registered_configured_root_overlaps(
    registered: &std::path::Path,
    expected: ConfiguredRootIdentity,
    plain: &std::path::Path,
) -> Result<bool, Error> {
    #[cfg(windows)]
    {
        native::registered_configured_root_overlaps(registered, expected, plain)
    }
    #[cfg(not(windows))]
    {
        let _ = (registered, expected, plain);
        Err(Error::UnsupportedPlatform)
    }
}

/// Compare two exactly identified, OS-registered Cloud Files roots.
/// Only each final root may carry Cloud Files reparse state; ancestors remain
/// plain and pinned. No registration, repair or account authorization occurs.
pub fn registered_configured_roots_overlap(
    left: &std::path::Path,
    expected_left: ConfiguredRootIdentity,
    right: &std::path::Path,
    expected_right: ConfiguredRootIdentity,
) -> Result<bool, Error> {
    #[cfg(windows)]
    {
        native::registered_configured_roots_overlap(left, expected_left, right, expected_right)
    }
    #[cfg(not(windows))]
    {
        let _ = (left, expected_left, right, expected_right);
        Err(Error::UnsupportedPlatform)
    }
}

/// Query the Windows Cloud Files API version.
///
/// Success indicates only that the platform API answered the query.
pub fn platform_version() -> Result<PlatformVersion, Error> {
    #[cfg(windows)]
    {
        native::platform_version()
    }
    #[cfg(not(windows))]
    {
        Err(Error::UnsupportedPlatform)
    }
}

/// A registration lease for an internally created synthetic test root.
///
/// The root path is intentionally not exposed. This prevents callers from
/// registering arbitrary user directories through this test-only boundary.
/// Dropping the lease attempts to unregister the root. If ownership checks or
/// unregistration fail, cleanup leaves the path untouched. Connecting it is
/// possible only through the bounded deterministic test-provider API below.
pub struct SyntheticRegistration {
    #[cfg(windows)]
    root: native::OwnedSyntheticRoot,
}

/// Connected, deterministic provider used only by ignored Windows VM tests.
/// It creates a small multi-entry synthetic namespace and hydrates files from
/// deterministic in-memory ranges; it has no account, network, or user path.
#[cfg(windows)]
pub struct SyntheticConnection {
    inner: native::SyntheticConnection,
}

impl SyntheticRegistration {
    /// Create and register a unique empty root with a current-user-only ACL in
    /// the user's temporary directory. Intended for disposable Windows VM
    /// tests only.
    pub fn create() -> Result<Self, Error> {
        #[cfg(windows)]
        {
            platform_version()?;
            Ok(Self {
                root: native::OwnedSyntheticRoot::create_and_register()?,
            })
        }
        #[cfg(not(windows))]
        {
            Err(Error::UnsupportedPlatform)
        }
    }

    /// Explicitly unregister this synthetic root and remove its empty folder.
    pub fn unregister(self) -> Result<(), Error> {
        #[cfg(windows)]
        {
            self.root.unregister()
        }
        #[cfg(not(windows))]
        {
            let _ = self;
            Err(Error::UnsupportedPlatform)
        }
    }

    /// Connect deterministic callbacks to this crate's private test root.
    ///
    /// This method creates a bounded fixture with two directories and two
    /// files at the synthetic root. The returned connection can enumerate the
    /// fixture and read deterministic payloads. This is a Cloud Files API
    /// integration test, not production provider support.
    #[cfg(windows)]
    pub fn connect(self) -> Result<SyntheticConnection, Error> {
        Ok(SyntheticConnection {
            inner: native::SyntheticConnection::connect(self.root)?,
        })
    }

    /// Reopen only a uniquely named private test registration created by this
    /// crate. This is used to simulate process restart and is absent from
    /// production builds.
    #[cfg(all(windows, test))]
    fn reconnect_for_test(path: std::path::PathBuf) -> Result<SyntheticConnection, Error> {
        let root = native::OwnedSyntheticRoot::reopen_registered_for_test(path)?;
        Ok(SyntheticConnection {
            inner: native::SyntheticConnection::reconnect_existing_for_test(root)?,
        })
    }
}

#[cfg(windows)]
impl SyntheticConnection {
    /// Enumerate the one test placeholder without exposing the private root.
    pub fn enumerate(&self) -> Result<Vec<SyntheticEntry>, Error> {
        self.inner.enumerate()
    }

    /// Read the fixed nested fixture directory through the operating system.
    /// This forces a real FETCH_PLACEHOLDERS callback; the returned contents
    /// are deterministic local test metadata only.
    pub fn enumerate_directory(
        &mut self,
        directory_name: &str,
    ) -> Result<Vec<SyntheticEntry>, Error> {
        self.inner.enumerate_directory(directory_name)
    }

    /// Return the already-validated private fixture folder for a test-only
    /// external directory query. This accessor is absent from non-test builds.
    #[cfg(test)]
    pub fn owned_fixture_directory_path_for_test(
        &self,
        directory_name: &str,
    ) -> Result<std::path::PathBuf, Error> {
        self.inner
            .owned_fixture_directory_path_for_test(directory_name)
    }

    /// Read the Cloud Files placeholder state for the fixed nested fixture
    /// directory. This is synthetic-test telemetry only; it accepts no path.
    #[cfg(test)]
    pub fn registered_population_policy(&self) -> Result<u32, Error> {
        self.inner.registered_population_policy()
    }

    #[cfg(test)]
    pub fn enable_directory_population(&self, directory_name: &str) -> Result<i32, Error> {
        self.inner.enable_directory_population(directory_name)
    }

    pub fn directory_placeholder_state(&self, directory_name: &str) -> Result<u32, Error> {
        self.inner.directory_placeholder_state(directory_name)
    }

    /// Read and hydrate the deterministic test file through the registered
    /// FETCH_DATA callback.
    pub fn read_payload(&self) -> Result<Vec<u8>, Error> {
        self.inner.read_payload()
    }

    /// Hydrate the fixed nested file by opening it through the local test root.
    pub fn read_nested_payload(&self) -> Result<Vec<u8>, Error> {
        self.inner.read_nested_payload()
    }

    /// Hydrate the fixed child in the second directory after its real
    /// population callback has completed.
    #[cfg(test)]
    pub fn read_second_folder_child_payload(&self) -> Result<Vec<u8>, Error> {
        self.inner.read_second_folder_child_payload()
    }

    /// Hydrate one named fixture file. Names are matched against the private
    /// fixed fixture; this does not accept a path or identity from the caller.
    pub fn read_file(&self, name: &str) -> Result<Vec<u8>, Error> {
        self.inner.read_file(name)
    }

    #[cfg(test)]
    pub fn disconnect_for_test(&mut self) -> Result<(), Error> {
        self.inner.disconnect_for_test()
    }

    #[cfg(test)]
    fn release_registration_for_restart_test(&mut self) -> Result<std::path::PathBuf, Error> {
        self.inner.release_registration_for_restart_test()
    }

    #[cfg(test)]
    pub fn owned_fixture_file_path_for_test(
        &self,
        name: &str,
    ) -> Result<std::path::PathBuf, Error> {
        self.inner.owned_fixture_file_path_for_test(name)
    }

    #[cfg(test)]
    pub fn close_observation_for_test(&self) -> (usize, usize, usize, usize, usize, i32, usize) {
        let observation = self.inner.callback_observation();
        (
            observation.modified_placeholder_closes,
            observation.unverifiable_placeholder_closes,
            observation.close_completion_callbacks,
            observation.last_close_param_size,
            observation.last_close_validation_stage,
            observation.last_close_validation_hresult,
            observation.last_close_path_common_prefix_bytes,
        )
    }

    #[cfg(test)]
    pub fn journaled_close_count_for_test(&self) -> usize {
        self.inner.journaled_close_count_for_test()
    }

    /// Return bounded test telemetry proving native fetch callback invocation
    /// and successful transfer, without exposing any path or account data.
    #[cfg(windows)]
    pub fn callback_observation(&self) -> (usize, usize, usize) {
        let observation = self.inner.callback_observation();
        (
            observation.fetch_callbacks,
            observation.last_fetch_param_size,
            observation.transferred_bytes,
        )
    }

    /// Return bounded directory-callback telemetry: callbacks observed, last
    /// ABI ParamSize, and entries submitted to CfExecute.
    pub fn directory_observation(&self) -> (usize, usize, usize, usize, usize) {
        let observation = self.inner.callback_observation();
        (
            observation.directory_callback_entries,
            observation.directory_callback_guard_rejections,
            observation.directory_callbacks,
            observation.last_directory_param_size,
            observation.placeholder_entries_submitted,
        )
    }

    #[cfg(test)]
    pub fn fixture_presence_for_test(&self) -> [bool; 5] {
        self.inner.fixture_presence_for_test()
    }

    /// Disconnect callbacks, unregister the synthetic root, and remove only
    /// the exact owned test file/root.
    pub fn shutdown(self) -> Result<(), Error> {
        self.inner.shutdown()
    }
}

/// Metadata returned by the synthetic placeholder enumeration test.
#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyntheticEntry {
    pub name: String,
    pub is_file: bool,
    pub len: u64,
}

#[cfg(all(test, not(windows)))]
#[path = "native_namespace_scan_parser.rs"]
mod native_namespace_scan_parser;
#[cfg(all(test, not(windows)))]
#[path = "native_plain_file_capture_checks.rs"]
mod native_plain_file_capture_checks;

#[cfg(test)]
mod tests {
    #[cfg(all(windows, debug_assertions, feature = "synthetic-agent-integration"))]
    mod native_namespace_directory_tests {
        include!("native_namespace_directory_tests.rs");
    }
    #[cfg(all(windows, debug_assertions, feature = "synthetic-agent-integration"))]
    mod connected_namespace_observer_tests {
        include!("connected_namespace_observer_tests.rs");
    }
    use super::{
        BackendError, ConfiguredRootIdentity, EditRecoveryProvider, Error, LocalFileIdentity,
        OpenCloudPlaceholderBackend, PlaceholderEditBinding, PreparedEditRecovery, ProviderScope,
        prepare_root_recovery,
    };
    use raiun_core::backend::CloudBackend;
    use raiun_opencloud::OpenCloudClient;
    use std::sync::Arc;

    struct TestRecovery {
        scope: ProviderScope,
        root: ConfiguredRootIdentity,
    }

    impl PreparedEditRecovery for TestRecovery {
        fn provider_scope(&self) -> &ProviderScope {
            &self.scope
        }

        fn root_identity(&self) -> ConfiguredRootIdentity {
            self.root
        }

        fn append_edit(
            &self,
            _binding: &PlaceholderEditBinding,
            _root_identity: ConfiguredRootIdentity,
            _local_file: LocalFileIdentity,
            _relative_path: &str,
            _content: &[u8],
        ) -> Result<(), BackendError> {
            Ok(())
        }

        fn has_unresolved(&self) -> Result<bool, BackendError> {
            Ok(false)
        }
    }

    struct TestRecoveryProvider {
        scope: ProviderScope,
        root: ConfiguredRootIdentity,
        fail: bool,
    }

    impl EditRecoveryProvider for TestRecoveryProvider {
        fn prepare(
            &self,
            _provider_scope: &ProviderScope,
            _root_identity: ConfiguredRootIdentity,
        ) -> Result<Arc<dyn PreparedEditRecovery>, BackendError> {
            if self.fail {
                return Err(BackendError::Unavailable);
            }
            Ok(Arc::new(TestRecovery {
                scope: self.scope.clone(),
                root: self.root,
            }))
        }
    }

    fn test_backend() -> (OpenCloudPlaceholderBackend, ProviderScope) {
        let client =
            Arc::new(OpenCloudClient::new("https://example.test", "synthetic".into()).unwrap());
        let origin = client.server_origin().expect("normalized test origin");
        let scope = ProviderScope::new(
            &client,
            "synthetic-profile".into(),
            "synthetic-account".into(),
            origin,
        )
        .expect("valid synthetic account scope");
        let backend = OpenCloudPlaceholderBackend::new(client, scope.clone())
            .expect("backend matches synthetic client scope");
        (backend, scope)
    }

    #[test]
    fn configured_root_requires_preflighted_recovery_for_exact_scope_and_identity() {
        let (backend, scope) = test_backend();
        let root = ConfiguredRootIdentity {
            volume_serial: 7,
            file_index: 19,
        };
        let provider = TestRecoveryProvider {
            scope: scope.clone(),
            root,
            fail: false,
        };
        assert!(prepare_root_recovery(&backend, root, &provider).is_ok());

        let mismatched_root = TestRecoveryProvider {
            scope: scope.clone(),
            root: ConfiguredRootIdentity {
                file_index: root.file_index + 1,
                ..root
            },
            fail: false,
        };
        assert!(matches!(
            prepare_root_recovery(&backend, root, &mismatched_root),
            Err(Error::EditRecoveryUnavailable)
        ));

        let other_client = Arc::new(
            OpenCloudClient::new("https://example.test", "synthetic-other".into()).unwrap(),
        );
        let other_scope = ProviderScope::new(
            &other_client,
            "synthetic-profile".into(),
            "different-account".into(),
            other_client.server_origin().unwrap(),
        )
        .unwrap();
        let mismatched_scope = TestRecoveryProvider {
            scope: other_scope,
            root,
            fail: false,
        };
        assert!(matches!(
            prepare_root_recovery(&backend, root, &mismatched_scope),
            Err(Error::EditRecoveryUnavailable)
        ));

        let unavailable = TestRecoveryProvider {
            scope,
            root,
            fail: true,
        };
        assert!(matches!(
            prepare_root_recovery(&backend, root, &unavailable),
            Err(Error::EditRecoveryUnavailable)
        ));

        backend.revoke();
        assert!(matches!(
            prepare_root_recovery(
                &backend,
                root,
                &TestRecoveryProvider {
                    scope: ProviderScope::new(
                        &OpenCloudClient::new("https://example.test", "synthetic".into()).unwrap(),
                        "synthetic-profile".into(),
                        "synthetic-account".into(),
                        "https://example.test".into(),
                    )
                    .unwrap(),
                    root,
                    fail: false,
                }
            ),
            Err(Error::EditRecoveryUnavailable)
        ));
    }

    use super::{SyntheticRegistration, platform_version};
    #[cfg(not(windows))]
    use super::{configured_roots_overlap, inspect_configured_root};
    #[cfg(windows)]
    const OPEN_CLOUD_PAYLOAD_LEN: usize = 16 * 1024 * 1024;
    #[cfg(windows)]
    const LARGE_OPEN_CLOUD_PAYLOAD_LEN: usize = 17 * 1024 * 1024 + 7;
    #[cfg(windows)]
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        thread,
        time::{Duration, Instant},
    };

    #[cfg(not(windows))]
    #[test]
    fn windows_only_operations_fail_closed_on_other_targets() {
        assert_eq!(platform_version(), Err(Error::UnsupportedPlatform));
        assert_eq!(
            inspect_configured_root(std::path::Path::new("C:\\synthetic")),
            Err(Error::UnsupportedPlatform)
        );
        assert_eq!(
            configured_roots_overlap(
                std::path::Path::new("C:\\first"),
                std::path::Path::new("C:\\second")
            ),
            Err(Error::UnsupportedPlatform)
        );
        assert!(matches!(
            SyntheticRegistration::create(),
            Err(Error::UnsupportedPlatform)
        ));
    }

    /// Run only in the isolated Windows test VM. It registers an internally
    /// created empty temp directory and immediately unregisters it.
    #[cfg(windows)]
    pub(crate) fn query_owned_fixture_directory_in_child(path: &std::path::Path) -> bool {
        use std::{
            process::{Command, Stdio},
            thread,
            time::{Duration, Instant},
        };

        assert!(path.is_absolute(), "fixture path must be absolute");
        let mut child = Command::new("powershell.exe")
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "$ErrorActionPreference='Stop'; $items=[System.IO.Directory]::GetFileSystemEntries($env:RAIUN_SYNTHETIC_DIRECTORY); if ($items.Count -ne 1) { exit 23 }",
            ])
            .env("RAIUN_SYNTHETIC_DIRECTORY", path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start bounded synthetic directory-query process");
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            match child
                .try_wait()
                .expect("poll synthetic directory-query process")
            {
                Some(status) => break status.success(),
                None if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
                None => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return false;
                }
            }
        }
    }

    /// Same bounded external-client pattern; emits only length and SHA256.
    #[cfg(all(windows, feature = "synthetic-agent-integration"))]
    pub(crate) fn query_owned_fixture_file_in_child(
        path: &std::path::Path,
        expected_len: usize,
        expected_sha: &str,
    ) -> bool {
        use std::{
            process::{Command, Stdio},
            thread,
            time::{Duration, Instant},
        };
        assert!(path.is_absolute(), "fixture path must be absolute");
        let mut child = Command::new("powershell.exe")
            .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
                "$ErrorActionPreference='Stop'; try { $b=[System.IO.File]::ReadAllBytes($env:RAIUN_SYNTHETIC_FILE); $h=[System.Security.Cryptography.SHA256]::Create(); try { $s=[BitConverter]::ToString($h.ComputeHash($b)).Replace('-','').ToLowerInvariant(); [Console]::WriteLine(('{0}|{1}' -f $b.Length,$s)) } finally { $h.Dispose() } } catch { $e=$_.Exception; while ($e.InnerException) { $e=$e.InnerException }; [Console]::WriteLine(('ERROR|{0}' -f $e.HResult)); exit 24 }"])
            .env("RAIUN_SYNTHETIC_FILE", path).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null())
            .spawn().expect("start bounded synthetic file-read process");
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            match child.try_wait().expect("poll synthetic file-read process") {
                Some(status) => {
                    let output = child
                        .wait_with_output()
                        .expect("collect synthetic file-read result");
                    let summary =
                        String::from_utf8(output.stdout).expect("ASCII file-read summary");
                    println!("VAULT_REFRESH_EXTERNAL_FILE={}", summary.trim());
                    println!("VAULT_REFRESH_EXTERNAL_FILE_STATUS={status}");
                    return status.success()
                        && summary.trim() == format!("{expected_len}|{expected_sha}");
                }
                None if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
                None => {
                    println!("VAULT_REFRESH_EXTERNAL_FILE_TIMEOUT=true");
                    let _ = child.kill();
                    let _ = child.wait();
                    return false;
                }
            }
        }
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "requires disposable Windows VM with Cloud Files enabled"]
    fn synthetic_root_registration_can_be_unregistered() {
        let platform = platform_version().expect("query Cloud Files platform");
        assert!(platform.build > 0);
        let registration = SyntheticRegistration::create().expect("register empty synthetic root");
        registration
            .unregister()
            .expect("unregister synthetic root");
    }

    /// Exercises the identity-pinned configured-root connection lease in a
    /// disposable Windows VM. The test disconnects and reconnects the exact
    /// registration, then confirms unresolved namespace entries block removal.
    #[cfg(all(windows, feature = "synthetic-agent-integration"))]
    #[test]
    #[ignore = "requires disposable Windows VM with Cloud Files enabled"]
    fn configured_root_reconnect_refuses_unregister_with_unresolved_namespace() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let (server, worker) = start_opencloud_fixture();
        let client = Arc::new(OpenCloudClient::new(&server, "synthetic-token".into()).unwrap());
        let server_origin = client.server_origin().expect("fixture origin");
        let account_id = canonical_test_account_id(&server_origin, "drive-personal");
        let scope = ProviderScope::new(
            client.as_ref(),
            "synthetic-profile".into(),
            account_id,
            server_origin,
        )
        .expect("valid synthetic account scope");

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "Raiun-Configured-Root-Lease-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("create empty synthetic user root");
        let lease = super::pin_configured_root(&path).expect("pin empty root identity");
        let identity = lease.identity();
        let recovery = Arc::new(
            super::DurableEditRecoveryProvider::current_user(scope.clone(), identity)
                .expect("prepare exact current-user recovery scope"),
        );
        let backend = Arc::new(
            OpenCloudPlaceholderBackend::new_with_identity_catalog(
                client,
                scope.clone(),
                identity,
                recovery.identity_catalog(),
            )
            .expect("backend binds the exact local root and durable identity catalog"),
        );
        let connection = super::synthetic_agent_integration::connect(
            lease,
            backend.clone(),
            "drive-personal",
            "root-id",
            recovery.clone(),
        )
        .expect("register and connect through the trusted synthetic integration seam");
        connection
            .disconnect()
            .expect("disconnect and preserve registration");
        assert!(matches!(
            super::pin_registered_configured_root(
                &path,
                super::ConfiguredRootIdentity {
                    volume_serial: identity.volume_serial,
                    file_index: identity.file_index.wrapping_add(1),
                }
            ),
            Err(super::Error::ConfiguredRootChanged)
        ));
        let reconnect_lease = super::pin_registered_configured_root(&path, identity)
            .expect("recover exact persisted registration after disconnect");
        let reconnected = super::synthetic_agent_integration::connect(
            reconnect_lease,
            backend.clone(),
            "drive-personal",
            "root-id",
            recovery.clone(),
        )
        .expect("reconnect without replacing registration");
        assert!(matches!(
            reconnected.unregister(),
            Err(super::Error::UnresolvedPlaceholderEdits)
        ));
        let retained_registration = super::pin_registered_configured_root(&path, identity)
            .expect("exact registration remains recoverable after refusal");
        assert_eq!(retained_registration.identity(), identity);
        drop(retained_registration);
        let mut retained_entries = std::fs::read_dir(&path)
            .expect("inspect the retained namespace")
            .map(|entry| entry.expect("read retained entry").file_name())
            .collect::<Vec<_>>();
        retained_entries.sort();
        assert_eq!(
            retained_entries,
            vec![
                std::ffi::OsString::from("Personal"),
                std::ffi::OsString::from("Spaces")
            ],
            "only the exact composite Personal/Spaces namespace should remain"
        );

        let unexpected_root_file = path.join("synthetic-unregistered-entry.bin");
        let unexpected_root_bytes = b"raiun configured root unknown immediate entry r43\0\x01\xff";
        let mut unexpected_root_handle = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&unexpected_root_file)
            .expect("create only the deterministic unknown immediate root entry");
        std::io::Write::write_all(&mut unexpected_root_handle, unexpected_root_bytes)
            .expect("write deterministic unknown root entry");
        drop(unexpected_root_handle);

        let changed_root_lease = super::pin_registered_configured_root(&path, identity)
            .expect("unknown entry must not replace or invalidate the registered root identity");
        assert_eq!(changed_root_lease.identity(), identity);
        assert!(matches!(
            super::synthetic_agent_integration::connect(
                changed_root_lease,
                backend,
                "drive-personal",
                "root-id",
                recovery,
            ),
            Err(super::Error::ConfiguredRootChanged)
        ));
        assert_eq!(
            std::fs::read(&unexpected_root_file)
                .expect("unknown root entry remains untouched after refusal"),
            unexpected_root_bytes
        );
        let unchanged_registration = super::pin_registered_configured_root(&path, identity)
            .expect("registration remains recoverable after fail-closed reconnect refusal");
        assert_eq!(unchanged_registration.identity(), identity);
        drop(unchanged_registration);
        worker.join().expect("fixture worker remains healthy");
    }

    /// A successfully created first child is preserved when initialization
    /// fails before readiness. Reconnect must not fill in or erase the partial
    /// namespace because its original outcome needs explicit recovery.
    #[cfg(all(windows, feature = "synthetic-agent-integration"))]
    #[test]
    #[ignore = "requires disposable Windows VM with Cloud Files enabled"]
    fn configured_root_partial_initialization_preserves_registration_and_refuses_reconnect() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let (server, worker) = start_opencloud_fixture();
        let client = Arc::new(OpenCloudClient::new(&server, "synthetic-token".into()).unwrap());
        let server_origin = client.server_origin().expect("fixture origin");
        let account_id = canonical_test_account_id(&server_origin, "drive-personal");
        let scope = ProviderScope::new(
            client.as_ref(),
            "synthetic-profile".into(),
            account_id,
            server_origin,
        )
        .expect("valid synthetic account scope");

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "Raiun-Partial-Initial-Root-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("create empty synthetic user root");
        let lease = super::pin_configured_root(&path).expect("pin empty root identity");
        let identity = lease.identity();
        let recovery = Arc::new(
            super::DurableEditRecoveryProvider::current_user(scope.clone(), identity)
                .expect("prepare exact current-user recovery scope"),
        );
        let backend = Arc::new(
            OpenCloudPlaceholderBackend::new_with_identity_catalog(
                client,
                scope.clone(),
                identity,
                recovery.identity_catalog(),
            )
            .expect("backend binds the exact local root and durable identity catalog"),
        );
        super::native::stop_initial_population_after_first_for_test();
        assert!(matches!(
            super::synthetic_agent_integration::connect(
                lease,
                backend.clone(),
                "drive-personal",
                "root-id",
                recovery.clone(),
            ),
            Err(super::Error::ProviderUnavailable)
        ));
        let retained = super::pin_registered_configured_root(&path, identity)
            .expect("partial initialization must retain the exact registration");
        assert_eq!(retained.identity(), identity);
        drop(retained);
        let names = || {
            let mut entries = std::fs::read_dir(&path)
                .expect("inspect preserved partial namespace")
                .map(|entry| entry.expect("read preserved child").file_name())
                .collect::<Vec<_>>();
            entries.sort();
            entries
        };
        let before = names();
        assert_eq!(before, vec![std::ffi::OsString::from("Personal")]);
        let reconnect = super::pin_registered_configured_root(&path, identity)
            .expect("repin partial registered root");
        assert!(matches!(
            super::synthetic_agent_integration::connect(
                reconnect,
                backend,
                "drive-personal",
                "root-id",
                recovery,
            ),
            Err(super::Error::ConfiguredRootChanged)
        ));
        assert_eq!(
            names(),
            before,
            "reconnect must not mutate the partial namespace"
        );
        let retained = super::pin_registered_configured_root(&path, identity)
            .expect("refused reconnect must preserve registration for recovery");
        assert_eq!(retained.identity(), identity);
        drop(retained);
        worker.join().expect("fixture worker remains healthy");
    }

    /// Two independently pinned empty-root leases must never let a losing
    /// initialization unregister or replace the successful connection's root.
    #[cfg(all(windows, feature = "synthetic-agent-integration"))]
    #[test]
    #[ignore = "requires disposable Windows VM with Cloud Files enabled"]
    fn configured_root_concurrent_initialization_preserves_winning_namespace() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let (server, worker) = start_opencloud_fixture();
        let client = Arc::new(OpenCloudClient::new(&server, "synthetic-token".into()).unwrap());
        let server_origin = client.server_origin().expect("fixture origin");
        let account_id = canonical_test_account_id(&server_origin, "drive-personal");
        let scope = ProviderScope::new(
            client.as_ref(),
            "synthetic-profile".into(),
            account_id,
            server_origin,
        )
        .expect("valid synthetic account scope");

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "Raiun-Concurrent-Initial-Root-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("create empty synthetic user root");
        let lease = super::pin_configured_root(&path).expect("pin empty root identity");
        let identity = lease.identity();
        let recovery = Arc::new(
            super::DurableEditRecoveryProvider::current_user(scope.clone(), identity)
                .expect("prepare exact current-user recovery scope"),
        );
        let backend = Arc::new(
            OpenCloudPlaceholderBackend::new_with_identity_catalog(
                client,
                scope.clone(),
                identity,
                recovery.identity_catalog(),
            )
            .expect("backend binds the exact local root and durable identity catalog"),
        );
        drop(lease);
        let start = Arc::new(std::sync::Barrier::new(2));
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let mut workers = Vec::new();
        let mut releases = Vec::new();
        for index in 0..2 {
            let path = path.clone();
            let backend = backend.clone();
            let recovery = recovery.clone();
            let start = start.clone();
            let result_tx = result_tx.clone();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            releases.push(release_tx);
            workers.push(std::thread::spawn(move || {
                // Both attempts pin before either is allowed to register.
                let lease = super::pin_configured_root(&path);
                let pinned = lease.is_ok();
                start.wait();
                let connection = lease.and_then(|lease| {
                    super::synthetic_agent_integration::connect(
                        lease,
                        backend,
                        "drive-personal",
                        "root-id",
                        recovery,
                    )
                });
                result_tx
                    .send((index, pinned, connection.is_ok()))
                    .expect("report bounded connect result");
                if let Ok(connection) = connection {
                    let _ = release_rx.recv_timeout(Duration::from_secs(30));
                    connection
                        .disconnect()
                        .expect("winner disconnect preserves registration");
                }
            }));
        }
        drop(result_tx);
        let results = (0..2)
            .map(|_| {
                result_rx
                    .recv_timeout(Duration::from_secs(30))
                    .expect("both initialization attempts finish")
            })
            .collect::<Vec<_>>();
        // Release/join every worker before asserting, including on a failed
        // invariant. Synthetic registrations and namespace remain for recovery.
        for release in releases {
            let _ = release.send(());
        }
        for worker in workers {
            worker
                .join()
                .expect("bounded connect worker remains healthy");
        }
        assert!(
            results.iter().all(|(_, pinned, _)| *pinned),
            "both leases must pin the original empty root"
        );
        assert_eq!(
            results
                .iter()
                .filter(|(_, _, connected)| *connected)
                .count(),
            1,
            "exactly one attempt owns the native connection: {results:?}"
        );
        let retained = super::pin_registered_configured_root(&path, identity)
            .expect("losing initialization must not unregister the winning root");
        assert_eq!(retained.identity(), identity);
        drop(retained);
        let mut names = std::fs::read_dir(&path)
            .expect("inspect winning namespace")
            .map(|entry| entry.expect("read preserved child").file_name())
            .collect::<Vec<_>>();
        names.sort();
        assert_eq!(
            names,
            vec![
                std::ffi::OsString::from("Personal"),
                std::ffi::OsString::from("Spaces")
            ]
        );
        let reconnect = super::pin_registered_configured_root(&path, identity)
            .expect("repin exact winning registration");
        super::synthetic_agent_integration::connect(
            reconnect,
            backend,
            "drive-personal",
            "root-id",
            recovery,
        )
        .expect("winning namespace remains reconnectable")
        .disconnect()
        .expect("preserve after reconnect");
        worker.join().expect("fixture worker remains healthy");
    }

    /// Exercises connect, callback-backed placeholder metadata, hydration,
    /// and ordered teardown only in the disposable Windows VM.
    #[cfg(windows)]
    #[test]
    #[ignore = "requires disposable Windows VM with Cloud Files enabled"]
    fn synthetic_provider_enumerates_and_hydrates_then_disconnects() {
        let registration = SyntheticRegistration::create().expect("create synthetic root");
        let mut provider = registration.connect().expect("connect synthetic callbacks");
        eprintln!(
            "synthetic fixture presence stage=connected {:?}",
            provider.fixture_presence_for_test()
        );
        assert_eq!(
            provider.enumerate().expect("enumerate synthetic entries"),
            vec![
                super::SyntheticEntry {
                    name: "first-folder".to_owned(),
                    is_file: false,
                    len: 0,
                },
                super::SyntheticEntry {
                    name: "second-folder".to_owned(),
                    is_file: false,
                    len: 0,
                },
                super::SyntheticEntry {
                    name: "synthetic.bin".to_owned(),
                    is_file: true,
                    len: 4096,
                },
                super::SyntheticEntry {
                    name: "second.bin".to_owned(),
                    is_file: true,
                    len: 8192,
                },
            ]
        );
        let folder_state = provider
            .directory_placeholder_state("first-folder")
            .expect("inspect nested fixture placeholder state");
        let population_policy = provider
            .registered_population_policy()
            .expect("read back registered population policy");
        eprintln!(
            "synthetic root population_policy={population_policy:#x} nested directory placeholder_state={folder_state:#x}"
        );
        let update_result = provider
            .enable_directory_population("first-folder")
            .expect("explicitly enable on-demand population for owned fixture directory");
        let updated_folder_state = provider
            .directory_placeholder_state("first-folder")
            .expect("inspect explicitly enabled folder placeholder");
        eprintln!(
            "synthetic explicit directory population update={update_result:#x} state={updated_folder_state:#x}"
        );
        let fixture_directory = provider
            .owned_fixture_directory_path_for_test("first-folder")
            .expect("resolve exact owned synthetic fixture directory");
        let before_directory = provider.directory_observation();
        let child_query_completed = query_owned_fixture_directory_in_child(&fixture_directory);
        let after_child_query = provider.directory_observation();
        eprintln!(
            "synthetic fixture presence stage=child_query {:?}",
            provider.fixture_presence_for_test()
        );
        eprintln!(
            "synthetic child directory query completed={} entries={} guard_rejections={} accepted_callbacks={} param_size={} entries_submitted={}",
            child_query_completed,
            after_child_query.0.saturating_sub(before_directory.0),
            after_child_query.1.saturating_sub(before_directory.1),
            after_child_query.2.saturating_sub(before_directory.2),
            after_child_query.3,
            after_child_query.4.saturating_sub(before_directory.4),
        );
        let nested_result = provider.enumerate_directory("first-folder");
        let after_directory = provider.directory_observation();
        let entries = after_directory.0.saturating_sub(before_directory.0);
        let guard_rejections = after_directory.1.saturating_sub(before_directory.1);
        let directory_callbacks = after_directory.2.saturating_sub(before_directory.2);
        let directory_param_size = after_directory.3;
        let submitted = after_directory.4.saturating_sub(before_directory.4);
        eprintln!(
            "synthetic Cloud Files directory entries={entries} guard_rejections={guard_rejections} accepted_callbacks={directory_callbacks} param_size={directory_param_size} entries_submitted={submitted} child_query_completed={child_query_completed} result_ok={}",
            nested_result.is_ok()
        );
        assert!(
            child_query_completed,
            "bounded external directory query failed; see callback telemetry above"
        );
        let nested_entries =
            nested_result.expect("enumerate nested directory through FETCH_PLACEHOLDERS");
        eprintln!(
            "synthetic fixture presence stage=nested_enumerated {:?}",
            provider.fixture_presence_for_test()
        );
        assert_eq!(
            nested_entries,
            vec![super::SyntheticEntry {
                name: "nested.bin".to_owned(),
                is_file: true,
                len: 4096,
            }]
        );
        let nested = provider
            .read_nested_payload()
            .expect("hydrate nested synthetic content");
        assert_eq!(nested.len(), 4096);
        assert_eq!(nested[0], 19);
        assert_eq!(nested[4095], ((4095_u32 * 17 + 19) % 256) as u8);
        eprintln!(
            "synthetic fixture presence stage=nested_hydrated {:?}",
            provider.fixture_presence_for_test()
        );
        // CfUnregisterSyncRoot deletes an unpopulated placeholder directory.
        // Populate this second directory through the real callback and
        // hydrate its child so teardown verifies the normal-directory path;
        // the prior r20 empty-directory failure remains separate evidence.
        let second_folder_update = provider
            .enable_directory_population("second-folder")
            .expect("explicitly enable population for the second owned directory");
        let second_folder_state = provider
            .directory_placeholder_state("second-folder")
            .expect("inspect populated second-directory placeholder");
        let second_folder_path = provider
            .owned_fixture_directory_path_for_test("second-folder")
            .expect("resolve exact second synthetic directory");
        let before_second_query = provider.directory_observation();
        let second_query_completed = query_owned_fixture_directory_in_child(&second_folder_path);
        let second_child_entries = provider
            .enumerate_directory("second-folder")
            .expect("enumerate the second directory through FETCH_PLACEHOLDERS");
        let after_second_query = provider.directory_observation();
        eprintln!(
            "synthetic second directory population update={second_folder_update:#x} state={second_folder_state:#x} child_query_completed={second_query_completed} entries={} submitted={} fixture_presence={:?}",
            after_second_query.0.saturating_sub(before_second_query.0),
            after_second_query.4.saturating_sub(before_second_query.4),
            provider.fixture_presence_for_test()
        );
        assert!(
            second_query_completed,
            "second directory must complete its bounded Cloud Files population callback"
        );
        assert_eq!(
            second_child_entries,
            vec![super::SyntheticEntry {
                name: "retained-child.bin".to_owned(),
                is_file: true,
                len: 1024,
            }]
        );
        let retained_child = provider
            .read_second_folder_child_payload()
            .expect("hydrate the second directory's known synthetic child");
        assert_eq!(retained_child.len(), 1024);
        assert_eq!(retained_child[0], 19);
        assert_eq!(retained_child[1023], ((1023_u32 * 17 + 19) % 256) as u8);
        eprintln!(
            "synthetic fixture presence stage=second_directory_hydrated {:?}",
            provider.fixture_presence_for_test()
        );
        let bytes = provider.read_payload().expect("hydrate synthetic bytes");
        assert_eq!(bytes.len(), 4096);
        assert_eq!(bytes[0], 7);
        assert_eq!(bytes[1], 38);
        assert_eq!(bytes[4095], ((4095_u32 * 31 + 7) % 256) as u8);
        eprintln!(
            "synthetic fixture presence stage=synthetic_hydrated {:?}",
            provider.fixture_presence_for_test()
        );
        let second = provider
            .read_file("second.bin")
            .expect("hydrate second file");
        assert_eq!(second.len(), 8192);
        assert_eq!(second[0], 19);
        assert_eq!(second[4096], ((4096_u32 * 17 + 19) % 256) as u8);
        eprintln!(
            "synthetic fixture presence stage=second_hydrated {:?}",
            provider.fixture_presence_for_test()
        );
        let (callbacks, param_size, transferred_bytes) = provider.callback_observation();
        eprintln!(
            "synthetic Cloud Files fetch callbacks={callbacks} param_size={param_size} transferred_bytes={transferred_bytes}"
        );
        assert!(
            callbacks >= 2,
            "both synthetic files must invoke FETCH_DATA"
        );
        assert!(matches!(param_size, 60 | 64));
        assert!(transferred_bytes >= 4096 + 8192);
        assert!(directory_callbacks > 0, "FETCH_PLACEHOLDERS must run");
        assert!(matches!(directory_param_size, 20 | 24));
        assert!(submitted >= 1);
        provider
            .shutdown()
            .expect("disconnect and clean synthetic root");
    }

    /// Exercise real Cloud Files callbacks backed by a synthetic local
    /// OpenCloud DAV server. This still uses only the internally-created test
    /// root and never connects provider support to a user account.
    #[cfg(windows)]
    #[test]
    #[ignore = "requires disposable Windows VM with Cloud Files enabled"]
    fn synthetic_cloudfiles_callbacks_hydrate_from_scoped_opencloud_ranges() {
        use super::{OpenCloudPlaceholderBackend, ProviderScope};
        use raiun_core::backend::CloudBackend;
        use raiun_opencloud::OpenCloudClient;

        let payload_len = LARGE_OPEN_CLOUD_PAYLOAD_LEN;
        let (server, worker) = start_opencloud_fixture_with_payload_len(payload_len);
        let client = Arc::new(OpenCloudClient::new(&server, "synthetic-token".into()).unwrap());
        let scope = ProviderScope::new(
            client.as_ref(),
            "synthetic-profile".into(),
            "synthetic-account".into(),
            client.server_origin().unwrap(),
        )
        .unwrap();
        let backend = Arc::new(OpenCloudPlaceholderBackend::new(client, scope).unwrap());
        let identity = backend
            .register_file("drive-personal", "root-id", "/cloud.bin")
            .expect("register one ordinary localhost file");

        let registration = SyntheticRegistration::create().expect("create synthetic root");
        let expected_payload = opencloud_payload_for_len(payload_len);
        assert_eq!(expected_payload.len(), payload_len);
        let mut provider = super::native::SyntheticConnection::connect_with_opencloud_backend(
            registration.root,
            backend,
            identity.as_bytes().to_vec(),
            expected_payload.clone(),
            None,
        )
        .expect("connect test callbacks to scoped OpenCloud backend");

        // Keep every expected directory populated across unregister. Cloud
        // Files removes empty directory placeholders during unregister; that
        // separate behavior is covered by the empty-placeholder regression.
        // Here we verify populated directories and their children survive,
        // without relaxing the owned-root cleanup predicate.
        for (directory, expected_name, expected_len) in [
            ("first-folder", "nested.bin", 4096_u64),
            ("second-folder", "retained-child.bin", 1024_u64),
        ] {
            provider
                .enable_directory_population(directory)
                .expect("enable population on the exact synthetic fixture directory");
            let path = provider
                .owned_fixture_directory_path_for_test(directory)
                .expect("resolve an identity-checked synthetic directory");
            assert!(
                query_owned_fixture_directory_in_child(&path),
                "complete the bounded child-directory population callback"
            );
            let entries = provider
                .enumerate_directory(directory)
                .expect("enumerate the populated synthetic directory");
            assert_eq!(
                entries,
                vec![super::SyntheticEntry {
                    name: expected_name.to_owned(),
                    is_file: true,
                    len: expected_len,
                }]
            );
        }
        let nested = provider
            .read_nested_payload()
            .expect("hydrate the populated first-directory child");
        assert_eq!(nested.len(), 4096);
        let retained = provider
            .read_second_folder_child_payload()
            .expect("hydrate the populated second-directory child");
        assert_eq!(retained.len(), 1024);

        let read_result = provider.read_opencloud_fixture();
        let observation = provider.callback_observation();
        eprintln!(
            "synthetic OpenCloud callback result: callbacks={} param_size={} requested_offset={} requested_length={} staged_fetch_ms={} published_bytes={} first_failed_hresult={:#x}",
            observation.fetch_callbacks,
            observation.last_fetch_param_size,
            observation.last_requested_offset,
            observation.last_requested_length,
            observation.last_staged_fetch_millis,
            observation.transferred_bytes,
            observation.first_failed_hresult,
        );
        assert_eq!(
            provider.fixture_presence_for_test(),
            [true; 5],
            "all expected fixtures must be present before unregister"
        );
        provider
            .shutdown()
            .expect("clean synthetic root and callbacks");

        let observations = worker.join().expect("local HTTP fixture remains healthy");
        assert!(
            read_result.is_ok(),
            "hydrate the 17 MiB + 7 byte placeholder: result={read_result:?}; observation={observation:?}; fixture={observations:?}"
        );
        let bytes = read_result.expect("checked successful hydration above");
        assert_eq!(bytes, expected_payload);
        assert_eq!(bytes.len(), payload_len);
        assert!(
            observation.fetch_callbacks > 0,
            "the Cloud Files callback must run"
        );
        assert!(matches!(observation.last_fetch_param_size, 60 | 64));
        assert!(
            observation.transferred_bytes >= payload_len,
            "the OS callbacks must publish the full 17 MiB + 7 byte file; observed {} bytes",
            observation.transferred_bytes
        );
        assert!(
            observations.0 > 0,
            "at least one DAV range request is required"
        );
        assert!(observations.1 > 0, "a DAV range request is required");
        assert!(
            observations.2 >= payload_len as u64,
            "the conditional DAV range path must transfer the full fixture; observed {} bytes",
            observations.2
        );
    }

    /// The isolated Windows VM writes to a hydrated OpenCloud-backed
    /// placeholder and verifies that the exact account-bound DPAPI record
    /// survives disconnect/reopen. This preserves the unique synthetic root.
    #[cfg(windows)]
    #[test]
    #[ignore = "requires disposable Windows VM with Cloud Files and current-user DPAPI"]
    fn modified_opencloud_close_is_dpapi_journaled_and_unregister_stays_blocked() {
        use super::{
            DpapiEditRecordProtector, EditJournal, EditJournalScope, EditRecordProtector,
            LocalFileIdentity, OpenCloudPlaceholderBackend, ProviderScope, RemoteEditBaseline,
        };
        use raiun_core::backend::CloudBackend;
        use raiun_opencloud::OpenCloudClient;
        use std::{
            fs::OpenOptions,
            io::Write,
            process::Command,
            thread,
            time::{Duration, Instant},
        };

        const EDIT_PATH_ENV: &str = "RAIUN_CLOUDFILES_JOURNAL_EDIT_PATH";
        const RECOVER_SCOPE_ENV: &str = "RAIUN_CLOUDFILES_JOURNAL_RECOVER_SCOPE";
        const CROSSUSER_INPUT_ENV: &str = "RAIUN_CLOUDFILES_JOURNAL_CROSSUSER_INPUT";
        const CROSSUSER_EXPORT_DIR_ENV: &str = "RAIUN_CLOUDFILES_JOURNAL_CROSSUSER_EXPORT_DIR";
        if let Some(path) = std::env::var_os(CROSSUSER_INPUT_ENV) {
            let manifest: serde_json::Value = serde_json::from_slice(
                &std::fs::read(path).expect("read only the synthetic sealed-record manifest"),
            )
            .expect("parse the test-only sealed-record manifest");
            let decode_hex = |value: &str| -> Vec<u8> {
                assert_eq!(value.len() % 2, 0, "synthetic hex data must be complete");
                value
                    .as_bytes()
                    .chunks_exact(2)
                    .map(|pair| {
                        let digit = |byte: u8| match byte {
                            b'0'..=b'9' => byte - b'0',
                            b'a'..=b'f' => byte - b'a' + 10,
                            _ => panic!("invalid synthetic hex data"),
                        };
                        (digit(pair[0]) << 4) | digit(pair[1])
                    })
                    .collect()
            };
            let associated_data = decode_hex(
                manifest["associated_data_hex"]
                    .as_str()
                    .expect("manifest includes associated data"),
            );
            let sealed = decode_hex(
                manifest["sealed_hex"]
                    .as_str()
                    .expect("manifest includes sealed record bytes"),
            );
            let protector = DpapiEditRecordProtector::current_user()
                .expect("second standard test user can create its own DPAPI protector");
            match protector.open(&associated_data, &sealed) {
                Err(super::JournalError::ProtectionFailed) => {}
                Ok(plaintext) => {
                    drop(zeroize::Zeroizing::new(plaintext));
                    panic!("a different Windows user decrypted a synthetic journal record");
                }
                Err(_) => panic!("cross-user rejection returned an unexpected safe error"),
            }
            return;
        }
        if let Ok(scope_json) = std::env::var(RECOVER_SCOPE_ENV) {
            let scope: EditJournalScope = serde_json::from_str(&scope_json)
                .expect("child receives only the parent-created synthetic scope");
            let protector = DpapiEditRecordProtector::current_user()
                .expect("same Windows user can reopen the DPAPI protector in a child process");
            let state_directory = protector.local_state_directory().to_path_buf();
            let journal = EditJournal::open(&state_directory, scope.clone(), protector)
                .expect("reopen exact synthetic account/root journal in a new process");
            let recovered = journal
                .recover_all()
                .expect("authenticate the DPAPI-protected record in a new process");
            assert_eq!(recovered.records.len(), 1);
            let record = &recovered.records[0];
            assert_eq!(record.metadata.scope, scope);
            assert_eq!(record.metadata.relative_path, "cloud.bin");
            assert_eq!(record.recovered_state(), super::LocalEditState::Uncertain);
            assert!(record.has_strong_baseline());
            let mut expected = opencloud_payload();
            expected[0] = 0xa5;
            assert_eq!(record.content, expected);
            return;
        }
        if let Some(path) = std::env::var_os(EDIT_PATH_ENV) {
            let mut file = OpenOptions::new()
                .write(true)
                .open(path)
                .expect("open only the parent-selected synthetic placeholder");
            file.write_all(&[0xa5]).expect("write one synthetic byte");
            file.sync_all().expect("flush the synthetic edit");
            return;
        }

        let (server, worker) = start_opencloud_fixture();
        let client = Arc::new(OpenCloudClient::new(&server, "synthetic-token".into()).unwrap());
        let server_origin = client.server_origin().expect("fixture origin");
        let account_id = canonical_test_account_id(&server_origin, "drive-personal");
        let scope = ProviderScope::new(
            client.as_ref(),
            "synthetic-profile".into(),
            account_id.clone(),
            server_origin.clone(),
        )
        .unwrap();
        let registration = SyntheticRegistration::create().expect("create synthetic root");
        let root_identity = registration
            .root
            .identity_for_test()
            .expect("read the exact owned synthetic root identity");
        let recovery_provider = Arc::new(
            super::DurableEditRecoveryProvider::current_user(scope.clone(), root_identity)
                .expect("prepare durable recovery for the exact account and root"),
        );
        let backend = Arc::new(
            OpenCloudPlaceholderBackend::new_with_identity_catalog(
                client,
                scope.clone(),
                root_identity,
                recovery_provider.identity_catalog(),
            )
            .expect("bind the backend to the exact synthetic root identity"),
        );
        backend
            .register_composite_root_for("drive-personal", "root-id")
            .expect("register the exact discovered Personal/Spaces root");
        let identity = backend
            .register_file("drive-personal", "root-id", "/cloud.bin")
            .expect("register the synthetic ordinary file");
        let recovery =
            super::prepare_root_recovery(&backend, root_identity, recovery_provider.as_ref())
                .expect("prepare exact scoped recovery before Cloud Files callbacks start");
        let original = opencloud_payload();
        let mut provider = super::native::SyntheticConnection::connect_with_opencloud_backend(
            registration.root,
            backend,
            identity.as_bytes().to_vec(),
            original.clone(),
            Some(recovery),
        )
        .expect("connect the identity-scoped synthetic backend");
        assert_eq!(provider.read_opencloud_fixture().unwrap(), original);
        let path = provider
            .owned_fixture_file_path_for_test("synthetic.bin")
            .expect("resolve the owned synthetic placeholder");
        let (root_volume, root_file_index) = provider
            .root_identity_for_test()
            .expect("read the pinned synthetic root identity");
        let (file_volume, file_index) = provider
            .fixture_file_identity_for_test("synthetic.bin")
            .expect("read the pinned synthetic file identity");
        let before = provider.close_observation_for_test();
        let child = Command::new(std::env::current_exe().expect("test executable"))
            .arg("--exact")
            .arg("tests::modified_opencloud_close_is_dpapi_journaled_and_unregister_stays_blocked")
            .arg("--ignored")
            .arg("--nocapture")
            .env(EDIT_PATH_ENV, &path)
            .status()
            .expect("launch a synthetic user-mode editor process");
        assert!(child.success(), "synthetic editor failed: {child}");

        let deadline = Instant::now() + Duration::from_secs(20);
        while provider.close_observation_for_test().2 == before.2 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(50));
        }
        let mut close = provider.close_observation_for_test();
        while close.0 == 0
            && close.1 == 0
            && provider.journaled_close_count_for_test() == 0
            && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(50));
            close = provider.close_observation_for_test();
        }
        assert!(
            close.0 > 0,
            "the edited placeholder must remain dirty or unresolved; expected_file_id={file_index:#x} last_close_file_id={:#x} observation={close:?}",
            provider.last_close_file_id_for_test()
        );
        assert_eq!(close.1, 0, "the exact placeholder identity must verify");
        assert!(
            provider.journaled_close_count_for_test() > 0,
            "the close callback must durably append the protected record"
        );

        let preserved_root = provider
            .release_registration_for_restart_test()
            .expect("disconnect without unregistering the edited root");
        let protector = DpapiEditRecordProtector::current_user().unwrap();
        let journal_directory = protector.local_state_directory().to_path_buf();
        let journal_scope = EditJournalScope {
            profile_id: "synthetic-profile".into(),
            server_origin,
            account_subject: account_id,
            space_id: "drive-personal".into(),
            root_resource_id: "root-id".into(),
            root_volume_serial: root_volume,
            root_file_index,
        };
        let recovery_child = Command::new(std::env::current_exe().expect("test executable"))
            .arg("--exact")
            .arg("tests::modified_opencloud_close_is_dpapi_journaled_and_unregister_stays_blocked")
            .arg("--ignored")
            .arg("--nocapture")
            .env(
                RECOVER_SCOPE_ENV,
                serde_json::to_string(&journal_scope).expect("serialize synthetic scope"),
            )
            .status()
            .expect("launch a fresh process for DPAPI journal recovery");
        assert!(
            recovery_child.success(),
            "cross-process DPAPI recovery failed: {recovery_child}"
        );
        let journal = EditJournal::open(&journal_directory, journal_scope, protector)
            .expect("reopen only the exact account/root journal");
        let recovered = journal.recover_all().expect("authenticate local records");
        assert_eq!(recovered.records.len(), 1);
        let record = &recovered.records[0];
        if let Some(export_dir) = std::env::var_os(CROSSUSER_EXPORT_DIR_ENV) {
            let (sealed, associated_data) = journal
                .sealed_record_for_test(&record.metadata.record_id)
                .expect("read only the exact synthetic sealed record");
            let to_hex = |bytes: &[u8]| {
                let mut output = String::with_capacity(bytes.len() * 2);
                for byte in bytes {
                    use std::fmt::Write as _;
                    write!(&mut output, "{byte:02x}").expect("write into String");
                }
                output
            };
            let manifest = serde_json::json!({
                "associated_data_hex": to_hex(&associated_data),
                "sealed_hex": to_hex(&sealed),
            });
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            let path = std::path::PathBuf::from(export_dir).join("sealed-record.json");
            let mut file = options
                .open(path)
                .expect("publish a new synthetic-only ciphertext fixture");
            use std::io::Write as _;
            file.write_all(&serde_json::to_vec(&manifest).unwrap())
                .expect("write the synthetic sealed fixture");
            file.sync_all().expect("flush the synthetic fixture");
        }
        assert_eq!(record.metadata.relative_path, "cloud.bin");
        assert_eq!(
            record.metadata.local_file,
            LocalFileIdentity {
                volume_serial: file_volume,
                file_index,
            }
        );
        assert_eq!(record.recovered_state(), super::LocalEditState::Uncertain);
        assert!(record.has_strong_baseline());
        assert_eq!(
            record.metadata.remote,
            Some(RemoteEditBaseline {
                resource_id: "cloud-file-id".into(),
                etag: "\"cloud-v1\"".into(),
                byte_len: OPEN_CLOUD_PAYLOAD_LEN as u64,
            })
        );
        let mut expected = original;
        expected[0] = 0xa5;
        assert_eq!(record.content, expected);
        assert_eq!(std::fs::read(path).unwrap(), record.content);
        assert!(!preserved_root.as_os_str().is_empty());

        let observations = worker.join().expect("fixture worker remains healthy");
        assert!(
            observations.1 > 0,
            "the synthetic file must be fetched by range"
        );
    }

    /// The isolated Windows VM writes to a hydrated synthetic placeholder,
    /// waits for the native close notification, and proves unregister refuses
    /// to discard the user's bytes. This intentionally preserves that unique
    /// synthetic root as recovery evidence.
    #[cfg(windows)]
    #[test]
    #[ignore = "requires disposable Windows VM with Cloud Files enabled"]
    fn modified_placeholder_close_blocks_unregister_and_retains_bytes() {
        use std::{
            ffi::OsStr,
            fs::OpenOptions,
            process::Command,
            thread,
            time::{Duration, Instant},
        };

        const EDIT_PATH_ENV: &str = "RAIUN_CLOUDFILES_SYNTHETIC_EDIT_PATH";
        const REOPEN_ROOT_ENV: &str = "RAIUN_CLOUDFILES_SYNTHETIC_REOPEN_ROOT";
        if let Some(path) = std::env::var_os(REOPEN_ROOT_ENV) {
            let path = std::path::PathBuf::from(path);
            let reopened = SyntheticRegistration::reconnect_for_test(path.clone())
                .expect("reopen the exact private synthetic registration after process restart");
            let observation = reopened.close_observation_for_test();
            assert!(
                observation.0 + observation.1 > 0,
                "reconnect scan must rediscover modified or unclassifiable filesystem state"
            );
            assert_eq!(
                reopened.inner.shutdown(),
                Err(Error::UnresolvedPlaceholderEdits),
                "reconnected provider must refuse unregister without process-local close history"
            );
            let path = path.join("synthetic.bin");
            assert_eq!(
                std::fs::read(path)
                    .expect("edited file must remain available after refused unregister"),
                b"synthetic user edit that must survive provider disconnect"
            );
            return;
        }
        if let Some(path) = std::env::var_os(EDIT_PATH_ENV) {
            let path = std::path::PathBuf::from(path);
            let parent = path.parent().and_then(std::path::Path::file_name);
            assert_eq!(path.file_name(), Some(OsStr::new("synthetic.bin")));
            assert!(
                parent.is_some_and(|name| name
                    .to_string_lossy()
                    .starts_with("Raiun-CfApi-Synthetic-"))
            );
            let edited = b"synthetic user edit that must survive provider disconnect";
            let mut file = OpenOptions::new()
                .write(true)
                .open(&path)
                .expect("open the exact private synthetic placeholder as a separate user process");
            file.write_all(edited).expect("write synthetic user edit");
            file.set_len(edited.len() as u64)
                .expect("set edited length");
            file.sync_all().expect("flush synthetic user edit");
            return;
        }

        let registration = SyntheticRegistration::create().expect("create owned test root");
        let mut provider = registration.connect().expect("connect test callbacks");
        let initial = provider
            .read_payload()
            .expect("hydrate synthetic placeholder");
        assert_eq!(initial.len(), 4096);
        let path = provider
            .owned_fixture_file_path_for_test("synthetic.bin")
            .expect("resolve only the known owned fixture path");
        let before = provider.close_observation_for_test();
        let edited = b"synthetic user edit that must survive provider disconnect";
        let child = Command::new(std::env::current_exe().expect("current test executable"))
            .arg("--exact")
            .arg("tests::modified_placeholder_close_blocks_unregister_and_retains_bytes")
            .arg("--ignored")
            .arg("--nocapture")
            .env(EDIT_PATH_ENV, &path)
            .status()
            .expect("launch separate synthetic user process");
        assert!(
            child.success(),
            "synthetic user edit process failed: {child}"
        );

        let deadline = Instant::now() + Duration::from_secs(15);
        let mut observation = provider.close_observation_for_test();
        while observation.2 == before.2 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(50));
            observation = provider.close_observation_for_test();
        }
        assert!(
            observation.2 > before.2,
            "Cloud Files close callback was not observed: before={before:?} after={observation:?}"
        );
        assert!(matches!(observation.3, 8 | 12));
        // This legacy fixture uses a synthetic backend with no authenticated
        // account binding, so journaling is intentionally unavailable. The
        // close callback must still retain an unresolved blocker rather than
        // treating the edit as clean; the OpenCloud-backed test below covers
        // durable account-scoped journal creation.
        assert!(
            observation.0 + observation.1 > 0,
            "modified or unverifiable data must remain a destructive-operation blocker: {observation:?}"
        );
        let root = provider
            .release_registration_for_restart_test()
            .expect("release process-owned handles but preserve the OS registration");
        assert_eq!(
            std::fs::read(&path).expect("edited file survives ordinary disconnect"),
            edited
        );
        let restarted = Command::new(std::env::current_exe().expect("current test executable"))
            .arg("--exact")
            .arg("tests::modified_placeholder_close_blocks_unregister_and_retains_bytes")
            .arg("--ignored")
            .arg("--nocapture")
            .env(REOPEN_ROOT_ENV, &root)
            .status()
            .expect("launch a new provider process to simulate app restart");
        assert!(
            restarted.success(),
            "restart scan failed to preserve dirty bytes and refuse unregister: {restarted}"
        );
        assert_eq!(
            provider.shutdown(),
            Err(Error::UnresolvedPlaceholderEdits),
            "unregister must fail closed while edited bytes have no recovery path"
        );
        assert_eq!(
            std::fs::read(&path).expect("edited file remains available for recovery"),
            edited
        );
    }

    #[cfg(windows)]
    fn opencloud_payload() -> Vec<u8> {
        opencloud_payload_for_len(OPEN_CLOUD_PAYLOAD_LEN)
    }

    #[cfg(windows)]
    fn opencloud_payload_for_len(length: usize) -> Vec<u8> {
        (0..length).map(|index| (index % 251) as u8).collect()
    }

    #[cfg(windows)]
    fn canonical_test_account_id(server_origin: &str, personal_space_id: &str) -> String {
        format!("{server_origin}\0{personal_space_id}")
            .bytes()
            .fold(String::new(), |mut encoded, byte| {
                use std::fmt::Write;
                write!(encoded, "{byte:02x}").expect("append account-id byte");
                encoded
            })
    }

    #[cfg(windows)]
    fn start_opencloud_fixture() -> (String, thread::JoinHandle<(usize, usize, u64)>) {
        start_opencloud_fixture_with_payload_len(OPEN_CLOUD_PAYLOAD_LEN)
    }

    #[cfg(windows)]
    fn start_opencloud_fixture_with_payload_len(
        payload_len: usize,
    ) -> (String, thread::JoinHandle<(usize, usize, u64)>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let mut requests = 0;
            let mut ranges = 0;
            let mut range_bytes = 0;
            let mut idle = 0;
            let mut request_number = 0;
            while idle < 600 {
                let (mut stream, _) = match listener.accept() {
                    Ok(value) => {
                        idle = 0;
                        value
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        idle += 1;
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    Err(error) => panic!("local DAV fixture accept failed: {error}"),
                };
                request_number += 1;
                let accepted_at = Instant::now();
                // Windows accepted sockets inherit nonblocking mode from the
                // listener, but this bounded fixture reads full requests.
                stream
                    .set_nonblocking(false)
                    .expect("fixture stream should be blocking");
                let request = read_http_request(&mut stream);
                let request_line = request.lines().next().unwrap_or("<empty>");
                eprintln!(
                    "synthetic DAV request #{request_number} headers_read_ms={} line={request_line}",
                    accepted_at.elapsed().as_millis()
                );
                let (status, headers, body, content_type) = opencloud_response(
                    &request,
                    address,
                    payload_len,
                    &mut ranges,
                    &mut range_bytes,
                );
                if let Err(error) = write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: {content_type}\r\n{headers}Connection: close\r\n\r\n",
                    body.len()
                ) {
                    eprintln!(
                        "synthetic DAV response header failed request=#{request_number} after_ms={} error={error:?}",
                        accepted_at.elapsed().as_millis()
                    );
                    break;
                }
                if let Err(error) = stream.write_all(&body) {
                    eprintln!(
                        "synthetic DAV response body failed request=#{request_number} bytes={} after_ms={} error={error:?}",
                        body.len(),
                        accepted_at.elapsed().as_millis()
                    );
                    break;
                }
                eprintln!(
                    "synthetic DAV response sent request=#{request_number} status={status} bytes={} elapsed_ms={}",
                    body.len(),
                    accepted_at.elapsed().as_millis()
                );
                requests += 1;
            }
            (requests, ranges, range_bytes)
        });
        (format!("http://{address}"), worker)
    }

    #[cfg(windows)]
    fn read_http_request(stream: &mut TcpStream) -> String {
        let mut bytes = Vec::new();
        let mut chunk = [0; 4096];
        let header_end = loop {
            if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                let end = position + 4;
                assert!(end <= 32 * 1024);
                break end;
            }
            assert!(bytes.len() <= 32 * 1024);
            let count = stream.read(&mut chunk).unwrap();
            assert_ne!(count, 0, "fixture request ended before its headers");
            bytes.extend_from_slice(&chunk[..count]);
            assert!(bytes.len() <= 32 * 1024 + chunk.len());
        };
        let headers = String::from_utf8(bytes[..header_end].to_vec()).unwrap();
        let body_len = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        assert!(body_len <= 32 * 1024);
        let request_len = header_end + body_len;
        while bytes.len() < request_len {
            let count = stream.read(&mut chunk).unwrap();
            assert_ne!(count, 0, "fixture request body ended early");
            bytes.extend_from_slice(&chunk[..count]);
            assert!(bytes.len() <= request_len + chunk.len());
        }
        headers
    }

    #[cfg(windows)]
    fn opencloud_response(
        request: &str,
        address: std::net::SocketAddr,
        payload_len: usize,
        ranges: &mut usize,
        range_bytes: &mut u64,
    ) -> (&'static str, String, Vec<u8>, &'static str) {
        let target = request.split_whitespace().nth(1).unwrap_or_default();
        if request.starts_with("GET /graph/") {
            let body = format!(
                r#"{{"value":[{{"id":"drive-personal","name":"Personal","driveType":"personal","root":{{"id":"root-id","webDavUrl":"http://{address}/dav/personal/"}}}}]}}"#
            );
            return (
                "200 OK",
                String::new(),
                body.into_bytes(),
                "application/json",
            );
        }
        if request.starts_with("PROPFIND ") {
            let (href, xml) = if target == "/dav/personal/" {
                (
                    "/dav/personal/",
                    r#"<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>/dav/personal/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getcontentlength>0</d:getcontentlength><d:getetag>root-v1</d:getetag><oc:fileid>root-id</oc:fileid></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#.to_string(),
                )
            } else {
                (
                    "/dav/personal/cloud.bin",
                    format!(
                        r#"<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>/dav/personal/cloud.bin</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>{payload_len}</d:getcontentlength><d:getetag>"cloud-v1"</d:getetag><oc:fileid>cloud-file-id</oc:fileid></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#
                    ),
                )
            };
            let _ = href;
            return (
                "207 Multi-Status",
                String::new(),
                xml.into_bytes(),
                "application/xml",
            );
        }
        if request.starts_with("GET /dav/personal/cloud.bin") {
            let lower = request.to_ascii_lowercase();
            assert!(lower.contains("if-match: \"cloud-v1\""));
            let range = lower
                .lines()
                .find_map(|line| line.strip_prefix("range: bytes="))
                .expect("range header");
            let (start, end) = range.split_once('-').expect("range bounds");
            let start = start.parse::<usize>().unwrap();
            let end = end.parse::<usize>().unwrap();
            assert!(start <= end && end < payload_len);
            let body = (start..=end)
                .map(|index| (index % 251) as u8)
                .collect::<Vec<_>>();
            *ranges += 1;
            *range_bytes += body.len() as u64;
            return (
                "206 Partial Content",
                format!(
                    "ETag: \"cloud-v1\"\r\nContent-Range: bytes {start}-{end}/{payload_len}\r\nAccept-Ranges: bytes\r\n"
                ),
                body,
                "application/octet-stream",
            );
        }
        panic!("unexpected request to synthetic DAV fixture: {request}");
    }
}

#[cfg(windows)]
pub use opencloud::vault_child_create::{
    VaultCachedChildCreateRecord, VaultChildCreateDescriptor, VaultChildCreateRecord,
    VaultChildCreateRemoteProof, VaultChildCreateSource,
};

#[cfg(windows)]
pub use native::native_vault_child_create::{
    VaultChildCreateReply, VaultChildCreateStep, VaultChildCreateTask,
};
#[cfg(windows)]
impl ConfiguredRootConnection {
    #[allow(clippy::too_many_arguments)]
    pub fn try_reconcile_fresh_vault_file_rename(
        &self,
        backend: &std::sync::Arc<OpenCloudPlaceholderBackend>,
        old: &[String],
        new: &[String],
        file: LocalFileIdentity,
        auth: namespace_intent::CapturedAuthorization,
        generation: std::sync::Arc<std::sync::atomic::AtomicU64>,
        current: std::sync::Arc<
            dyn Fn(namespace_intent::CapturedAuthorization) -> bool + Send + Sync,
        >,
    ) -> Result<bool, Error> {
        self.inner
            .try_vault_file_rename(backend, old, new, file, auth, generation, current, false)
    }
    pub fn try_reconcile_fresh_vault_directory_rename(
        &self,
        backend: &std::sync::Arc<OpenCloudPlaceholderBackend>,
        old: &[String],
        new: &[String],
        file: LocalFileIdentity,
        auth: namespace_intent::CapturedAuthorization,
        generation: std::sync::Arc<std::sync::atomic::AtomicU64>,
        current: std::sync::Arc<
            dyn Fn(namespace_intent::CapturedAuthorization) -> bool + Send + Sync,
        >,
    ) -> Result<bool, Error> {
        self.inner
            .try_vault_file_rename(backend, old, new, file, auth, generation, current, true)
    }
    pub fn begin_fresh_vault_child_create(
        &self,
        backend: &std::sync::Arc<OpenCloudPlaceholderBackend>,
        parents: &[&str],
        name: &str,
        kind: namespace_intent::NamespaceObjectKind,
        auth: namespace_intent::CapturedAuthorization,
        generation: u64,
        job: &StreamedRecoveryJob,
        current: std::sync::Arc<
            dyn Fn(namespace_intent::CapturedAuthorization) -> bool + Send + Sync,
        >,
        owner_generation: std::sync::Arc<std::sync::atomic::AtomicU64>,
    ) -> Result<VaultChildCreateStep, Error> {
        self.inner.begin_vault_child_create(
            backend,
            parents,
            name,
            kind,
            auth,
            generation,
            job,
            current,
            owner_generation,
        )
    }
    pub fn advance_fresh_vault_child_create(
        &self,
        reply: VaultChildCreateReply,
    ) -> Result<VaultChildCreateStep, Error> {
        self.inner.advance_vault_child_create(reply)
    }
    pub fn close_fresh_vault_child_create(&self) -> bool {
        self.inner.close_vault_child_create()
    }
}
