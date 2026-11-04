//! Safe, identity-scoped data-source seam for Cloud Files callbacks.
//!
//! The Windows adapter currently wires only a deterministic synthetic backend.
//! This trait does not register roots or make the application a sync provider.

use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
};

use crate::{ConfiguredRootIdentity, ProviderScope};
use std::time::{Duration, Instant};

/// Maximum number of bytes passed to one backend range read.
pub const MAX_RANGE_BYTES: usize = 64 * 1024;
/// Historical vault edit retention bound; never writable-mount activation.
pub const MAX_VAULT_EDIT_CAPTURE_BYTES: usize = 512 * 1024;
/// Bound total work accepted for one callback request.
pub const MAX_REQUEST_BYTES: u64 = 16 * 1024 * 1024;
/// Total native file/request bound; individual staging windows remain 16 MiB.
pub const MAX_FILE_BYTES: u64 = 1 << 40;
/// At most two callback-wide buffers may be staged at once (32 MiB total).
pub const MAX_STAGED_CALLBACKS: usize = 2;
/// Upper bound on callback workers allowed to call a backend concurrently.
pub const MAX_CONCURRENT_FETCHES: usize = 8;
/// Maximum direct children returned for one directory-population callback.
pub const MAX_DIRECTORY_CHILDREN: usize = 10_000;
/// Bound simultaneous directory listings, each of which may stage a capped
/// DAV response plus its validated direct-child identities.
pub const MAX_CONCURRENT_DIRECTORY_ENUMERATIONS: usize = 2;
/// Total time budget for one Cloud Files callback, including metadata checks.
pub const DEFAULT_FETCH_TIMEOUT: Duration = Duration::from_secs(30);
const TRANSFER_ALIGNMENT: u64 = 4096;

#[cfg(any(windows, test))]
pub(crate) fn placeholder_population_completed(
    hresult: i32,
    expected: usize,
    processed: usize,
    entry_results: &[i32],
) -> bool {
    hresult >= 0
        && processed == expected
        && entry_results.len() == expected
        && entry_results.iter().all(|result| *result >= 0)
}

/// Metadata for one object identified by an opaque provider identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlaceholderMetadata {
    pub is_directory: bool,
    pub length: u64,
}

/// One direct child returned to a directory-population callback. The name is
/// a single local child component; identity bytes are opaque to Cloud Files.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlaceholderChild {
    pub name: String,
    pub identity: Vec<u8>,
    pub metadata: PlaceholderMetadata,
    /// Windows FILETIME ticks. Zero means the adapter has no safe timestamp.
    pub last_write_time: i64,
}

/// Read-only original route locator, never mutation or cleanup authority.
#[cfg(windows)]
pub struct VaultCleanupRootLocator {
    pub(crate) identity: crate::OpaqueIdentity,
    pub(crate) components: Vec<String>,
    pub(crate) route: Vec<PlaceholderChild>,
}

/// Exact authenticated remote baseline needed to preserve one local edit for
/// later conditional recovery. Paths here are virtual namespace paths, never
/// host filesystem paths. A missing or weak ETag remains retainable but is
/// not sufficient for a future upload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlaceholderEditBinding {
    pub profile_id: String,
    pub server_origin: String,
    pub account_subject: String,
    /// Immutable authenticated-client generation that produced this binding.
    pub account_generation: u64,
    pub space_id: String,
    pub root_resource_id: String,
    pub remote_resource_id: String,
    pub virtual_path: String,
    pub base_etag: String,
    pub base_size: u64,
}

/// Borrowed only inside the exact live vault capture callback. This exposes
/// immutable historical metadata and local retention, never keys or a live lease.
/// A successful retain may return a one-use notification, which is not published
/// until native dirty accounting and every capture/callback guard have finished.
#[cfg(windows)]
pub trait ExistingVaultEditCapture {
    /// Pure original-route/save-owner cancellation only; no key/lease/authority
    /// escapes this callback. None keeps older adapters fail closed for streams.
    fn stream_revocation(&self) -> Option<Arc<dyn Fn() -> bool + Send + Sync>> {
        None
    }
    /// Additive >512KiB capture. The reader and original source verifier remain
    /// borrowed until protected staged-body commit/readback has completed.
    fn retain_streamed(
        &self,
        _payload: crate::vault_custody::ExistingVaultStreamedEditPayload,
        _source: &mut dyn std::io::Read,
        _verify_source: &mut dyn FnMut() -> Result<(), BackendError>,
        _cancelled: &dyn Fn() -> bool,
    ) -> Result<Option<Box<dyn DeferredVaultCaptureNotification>>, BackendError> {
        Err(BackendError::Unavailable)
    }
    fn baseline(&self) -> &crate::vault_custody::ExistingVaultEditBaseline;
    fn retain(
        &self,
        payload: crate::vault_custody::ExistingVaultEditPayload,
    ) -> Result<Option<Box<dyn DeferredVaultCaptureNotification>>, BackendError>;
}

/// Owned fresh-close locator only, never upload/session/cleanup authority.
/// Implementations perform only one bounded nonblocking send. A refused send
/// queues nothing; dropping this value must never publish. No locks, body,
/// native pointers, account lookup, provider reentry or HTTP may escape here.
pub trait DeferredVaultCaptureNotification: Send {
    fn try_publish(self: Box<Self>) -> Result<(), BackendError>;
}

#[cfg(any(windows, test))]
pub(crate) fn finish_vault_capture_notification(
    callback: Result<(), BackendError>,
    retained: bool,
    notification: Option<Box<dyn DeferredVaultCaptureNotification>>,
) -> Result<Option<Box<dyn DeferredVaultCaptureNotification>>, BackendError> {
    callback?;
    if !retained {
        return Err(BackendError::Unavailable);
    }
    Ok(notification)
}

/// Called only after native close accounting and all callback guards dropped.
/// Contain an implementation panic at the external callback boundary; neither
/// an error nor a panic retries publication or changes retained dirty history.
#[cfg(any(windows, test))]
pub(crate) fn publish_vault_capture_notification(
    notification: Option<Box<dyn DeferredVaultCaptureNotification>>,
) -> Result<(), BackendError> {
    match notification {
        Some(notification) => {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| notification.try_publish()))
                .unwrap_or(Err(BackendError::Unavailable))
        }
        None => Ok(()),
    }
}

/// Local synchronous accounting only, never a durable or live permit. Even a
/// swallowed failed/second retain attempt prevents a successful callback ack.
#[cfg(any(windows, test))]
#[derive(Default)]
pub(crate) struct ExistingCaptureAcknowledgement {
    attempts: std::cell::Cell<u8>,
    retained: std::cell::Cell<bool>,
}
#[cfg(any(windows, test))]
impl ExistingCaptureAcknowledgement {
    pub(crate) fn begin_attempt(&self) -> Result<(), BackendError> {
        let previous = self.attempts.get();
        self.attempts.set(previous.saturating_add(1));
        if previous == 0 {
            Ok(())
        } else {
            Err(BackendError::Unavailable)
        }
    }
    pub(crate) fn acknowledge_retained(&self) {
        self.retained.set(true);
    }
    pub(crate) fn finish(&self, callback: Result<(), BackendError>) -> Result<(), BackendError> {
        callback?;
        if self.attempts.get() == 1 && self.retained.get() {
            Ok(())
        } else {
            Err(BackendError::Unavailable)
        }
    }
}
#[cfg(test)]
mod existing_capture_ack_tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc::{SyncSender, sync_channel},
    };

    struct Notice {
        sender: SyncSender<()>,
        attempts: Arc<AtomicUsize>,
    }
    impl DeferredVaultCaptureNotification for Notice {
        fn try_publish(self: Box<Self>) -> Result<(), BackendError> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            self.sender
                .try_send(())
                .map_err(|_| BackendError::Unavailable)
        }
    }

    #[test]
    fn deferred_notice_requires_retention_and_successful_outer_ack() {
        let (sender, receiver) = sync_channel(1);
        let attempts = Arc::new(AtomicUsize::new(0));
        let notice = || -> Option<Box<dyn DeferredVaultCaptureNotification>> {
            Some(Box::new(Notice {
                sender: sender.clone(),
                attempts: Arc::clone(&attempts),
            }))
        };
        assert!(finish_vault_capture_notification(Ok(()), false, notice()).is_err());
        assert!(
            finish_vault_capture_notification(Err(BackendError::Unavailable), true, notice())
                .is_err()
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 0);
        assert!(receiver.try_recv().is_err());
        let deferred = finish_vault_capture_notification(Ok(()), true, notice()).unwrap();
        // Native accounting/guard unwinding must happen before this later call.
        assert_eq!(attempts.load(Ordering::SeqCst), 0);
        assert!(receiver.try_recv().is_err());
        publish_vault_capture_notification(deferred).unwrap();
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert_eq!(receiver.try_recv(), Ok(()));
        assert!(receiver.try_recv().is_err());
        assert!(
            finish_vault_capture_notification(Ok(()), true, None)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn refused_nonblocking_publish_is_not_retried_or_queued() {
        let (sender, receiver) = sync_channel(1);
        sender.try_send(()).unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let deferred = Some(Box::new(Notice {
            sender: sender.clone(),
            attempts: Arc::clone(&attempts),
        }) as Box<dyn DeferredVaultCaptureNotification>);
        assert!(publish_vault_capture_notification(deferred).is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert_eq!(receiver.try_recv(), Ok(()));
        assert!(receiver.try_recv().is_err());
        publish_vault_capture_notification(None).unwrap();
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn callback_success_requires_exactly_one_acknowledged_retain() {
        let absent = ExistingCaptureAcknowledgement::default();
        assert!(absent.finish(Ok(())).is_err());
        let failed = ExistingCaptureAcknowledgement::default();
        failed.begin_attempt().unwrap();
        assert!(failed.finish(Ok(())).is_err());
        let retained = ExistingCaptureAcknowledgement::default();
        retained.begin_attempt().unwrap();
        retained.acknowledge_retained();
        assert!(retained.finish(Ok(())).is_ok());
        // Caller errors remain errors even after durable retention succeeded.
        assert!(retained.finish(Err(BackendError::Unavailable)).is_err());
    }
    #[test]
    fn swallowed_second_retain_error_cannot_acknowledge_the_callback() {
        let retained = ExistingCaptureAcknowledgement::default();
        retained.begin_attempt().unwrap();
        retained.acknowledge_retained();
        assert!(retained.begin_attempt().is_err());
        assert!(retained.finish(Ok(())).is_err());
    }
}

/// Holds the account/root revocation lease while a local edit record is being
/// durably copied. Implementations must prevent logout/account replacement
/// from completing until the caller drops this value.
pub trait PreparedEditBinding {
    fn binding(&self) -> &PlaceholderEditBinding;
}

/// Recovery capability prepared for one authenticated account and one pinned
/// local Cloud Files root. Construction must preflight the protected journal
/// storage before the caller connects Cloud Files. The lease remains owned by
/// callback state for the full connection lifetime.
pub trait PreparedEditRecovery: Send + Sync + 'static {
    fn provider_scope(&self) -> &ProviderScope;
    fn root_identity(&self) -> ConfiguredRootIdentity;

    /// Optional namespace-rename storage for this exact prepared account/root.
    /// Implementations must opt in explicitly; storage alone grants no rename
    /// admission or publication authority.
    #[cfg(windows)]
    fn file_rename_store(
        &self,
        _scope: &crate::EditJournalScope,
        _authorization: crate::namespace_intent::CapturedAuthorization,
    ) -> Result<
        Option<std::sync::Arc<crate::streamed_store::namespace_rename_store::FileRenameStore>>,
        BackendError,
    > {
        Ok(None)
    }

    /// Optional directory journal from this SAME prepared account/root context.
    /// Storage does not grant directory dispatch or native publication authority.
    #[cfg(windows)]
    fn directory_intent_store(
        &self,
        _scope: &crate::EditJournalScope,
        _authorization: crate::namespace_intent::CapturedAuthorization,
    ) -> Result<
        Option<std::sync::Arc<crate::streamed_store::namespace_store::DirectoryIntentStore>>,
        BackendError,
    > {
        Ok(None)
    }

    /// A nonblocking cached count seeded by authenticated preflight. No disk,
    /// body decryption or network work is permitted here. Unsupported, poisoned
    /// or invalidated summaries return None, never a healthy zero.
    fn cached_ordinary_pending_count(&self) -> Option<usize> {
        None
    }

    /// Separate opt-in for the complete protected v2 capture pipeline. Legacy
    /// providers cannot make a larger native read eligible by default.
    #[cfg(windows)]
    fn supports_streamed_capture(&self) -> bool {
        false
    }

    #[cfg(windows)]
    fn begin_streamed_job(&self) -> Option<StreamedRecoveryJob> {
        None
    }

    #[cfg(windows)]
    #[allow(clippy::too_many_arguments)]
    fn stage_streamed_edit(
        &self,
        _binding: &PlaceholderEditBinding,
        _root_identity: ConfiguredRootIdentity,
        _local_file: crate::LocalFileIdentity,
        _relative_path: &str,
        _content_len: u64,
        _job: &StreamedRecoveryJob,
        _source: &mut dyn std::io::Read,
        _cancelled: &mut dyn FnMut() -> bool,
    ) -> Result<crate::StagedStreamedEdit, BackendError> {
        Err(BackendError::Unavailable)
    }

    /// Caller still owns its binding/source/path guards and has revalidated
    /// them after capture. This cannot reconstruct initial admission from disk.
    #[cfg(windows)]
    fn commit_streamed_edit(
        &self,
        _stage: crate::StagedStreamedEdit,
        _cancelled: &mut dyn FnMut() -> bool,
    ) -> Result<Option<crate::InitialEditReceipt>, BackendError> {
        Err(BackendError::Unavailable)
    }

    /// Persist complete local bytes before a close callback is considered
    /// recovered. `binding` is obtained under the backend's revocation lease;
    /// the recovery implementation must validate its account/generation and
    /// exact root against this prepared capability.
    fn append_edit(
        &self,
        binding: &PlaceholderEditBinding,
        root_identity: ConfiguredRootIdentity,
        local_file: crate::LocalFileIdentity,
        relative_path: &str,
        content: &[u8],
    ) -> Result<(), BackendError>;

    /// Publish an immutable edit and optionally return a non-persistable
    /// capability for its initial dispatch. Implementations without this
    /// capability still preserve the edit; they cannot manufacture a receipt.
    fn append_edit_for_initial_dispatch(
        &self,
        binding: &PlaceholderEditBinding,
        root_identity: ConfiguredRootIdentity,
        local_file: crate::LocalFileIdentity,
        relative_path: &str,
        content: &[u8],
    ) -> Result<Option<crate::InitialEditReceipt>, BackendError> {
        self.append_edit(binding, root_identity, local_file, relative_path, content)?;
        Ok(None)
    }

    /// Consume a capability from a fresh append through this exact prepared
    /// instance. The caller must retain its current account/root generation
    /// lease and provide a remote adapter that enforces it throughout dispatch.
    /// Recovered records never produce this capability.
    fn dispatch_initial_receipt(
        &self,
        _receipt: crate::InitialEditReceipt,
        _remote: &dyn crate::RecoveryRemote,
    ) -> Result<crate::ReconciliationOutcome, crate::JournalError> {
        Err(crate::JournalError::InvalidState)
    }

    /// Dispatch the fresh receipt and, when supported, obtain a newly read
    /// remote proof. A successful historical outcome alone cannot authorize
    /// local in-sync marking; implementations without proof support return None.
    fn dispatch_initial_receipt_verified(
        &self,
        receipt: crate::InitialEditReceipt,
        remote: &dyn crate::RecoveryRemote,
    ) -> Result<
        (
            crate::ReconciliationOutcome,
            Option<crate::VerifiedEditReadback>,
        ),
        crate::JournalError,
    > {
        self.dispatch_initial_receipt(receipt, remote)
            .map(|outcome| (outcome, None))
    }

    /// Record exact native completion while the caller still retains the
    /// active publication/account permit. Unsupported implementations refuse.
    fn record_local_completion(
        &self,
        _completion: crate::CompletedLocalEdit,
    ) -> Result<(), crate::JournalError> {
        Err(crate::JournalError::InvalidState)
    }

    /// Whether durable unresolved records remain for this connection. Errors
    /// are treated as unresolved by the native teardown path.
    fn has_unresolved(&self) -> Result<bool, BackendError>;

    /// Read-only content-recovery admission check for this exact retained
    /// account/root capability. Namespace operation history is intentionally
    /// excluded. `false` is returned only after a bounded authenticated scan;
    /// unsupported storage, corrupt/incomplete metadata, or exhausted limits
    /// return `Unavailable`. Implementations must not create or repair state,
    /// decrypt persisted content bodies, or return recovery authority here.
    #[cfg(windows)]
    fn has_unresolved_content(&self) -> Result<bool, BackendError> {
        Err(BackendError::Unavailable)
    }

    /// Compatibility health that fully authenticates the retained legacy
    /// content journal before using its terminal acknowledgement. Unlike
    /// `has_unresolved_content`, this may decrypt legacy record bodies in
    /// memory; it never returns those bodies or grants dispatch authority.
    /// Unsupported storage, corrupt/incomplete evidence, or exhausted scan
    /// budgets remain unavailable.
    /// Call only from an owner-thread operation outside callbacks, backend
    /// leases and HTTP; this is intentionally a bounded body-reading query.
    #[cfg(windows)]
    fn has_unresolved_content_authenticated_legacy(&self) -> Result<bool, BackendError> {
        Err(BackendError::Unavailable)
    }

    /// Explicitly dispatch one previously selected recovered edit. This does
    /// not connect or start a provider; implementations resolve the record
    /// internally from this prepared exact account/root scope, persist an
    /// Attempting receipt before every remote conditional write, and retain
    /// the immutable local body for every result.
    fn dispatch_recovered_edit(
        &self,
        _record_id: &str,
        _generation: u64,
        _remote: &dyn crate::RecoveryRemote,
        _approval: crate::ExplicitRecoveryApproval,
    ) -> Result<crate::ReconciliationOutcome, crate::JournalError> {
        Err(crate::JournalError::InvalidState)
    }

    /// Explicit recovery plus fresh remote readback authority for exact native
    /// completion. Historical upload outcomes alone never authorize marking
    /// local bytes clean. Older implementations safely return no proof.
    fn dispatch_recovered_edit_verified(
        &self,
        record_id: &str,
        generation: u64,
        remote: &dyn crate::RecoveryRemote,
        approval: crate::ExplicitRecoveryApproval,
    ) -> Result<
        (
            crate::ReconciliationOutcome,
            Option<crate::VerifiedEditReadback>,
        ),
        crate::JournalError,
    > {
        self.dispatch_recovered_edit(record_id, generation, remote, approval)
            .map(|outcome| (outcome, None))
    }
}

/// Creates a durable recovery lease for an exact authenticated scope and
/// pinned root. Implementations should verify DPAPI availability, private
/// directory identity/ACLs, journal bounds, and storage writability before
/// returning a lease. Failure must prevent `CfConnectSyncRoot`.
pub trait EditRecoveryProvider: Send + Sync + 'static {
    fn prepare(
        &self,
        provider_scope: &ProviderScope,
        root_identity: ConfiguredRootIdentity,
    ) -> Result<std::sync::Arc<dyn PreparedEditRecovery>, BackendError>;

    /// Optional durable catalog for resolving placeholder identities after a
    /// process restart. Production providers must supply it before connecting
    /// the native root; synthetic backend tests may omit it.
    fn identity_catalog(&self) -> Option<std::sync::Arc<dyn crate::ProviderIdentityCatalog>> {
        None
    }
}

/// Safe outcome from a backend lookup or range read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendError {
    NotFound,
    Cancelled,
    InvalidRange,
    Unavailable,
}

/// A fully validated callback range. Implementations must not expose bytes
/// until the entire requested range has been fetched and authenticated.
/// A complete, bounded directory listing staged while its identity scope is
/// valid. Implementations that depend on revocable authorization retain that
/// lease until `begin_publish` returns and the caller finishes native
/// publication.
pub trait PreparedEnumeration {
    /// Files in this complete listing must be projected read-only. Directories
    /// retain their normal attributes. This hint acquires no authorization lock.
    fn read_only(&self) -> bool {
        false
    }

    /// Per-file projection policy under the same publication permit. Existing
    /// adapters keep their listing-wide policy unless explicitly overridden.
    /// This does not change authenticated remote metadata or directory rights.
    fn file_read_only(&self, _child: &PlaceholderChild) -> bool {
        self.read_only()
    }

    /// Cached projections are partial and must keep on-demand population enabled.
    fn completes_population(&self) -> bool {
        true
    }

    fn children(&self) -> &[PlaceholderChild];

    /// Hold the relevant scope/revocation guard through one native publication.
    fn begin_publish<'a>(
        &'a self,
        cancellation: &CancellationToken,
    ) -> Result<Box<dyn PublishPermit + 'a>, BackendError> {
        if cancellation.is_cancelled() {
            Err(BackendError::Cancelled)
        } else if cancellation.is_expired() {
            Err(BackendError::Unavailable)
        } else {
            Ok(Box::new(()))
        }
    }
}

struct StagedEnumeration {
    children: Vec<PlaceholderChild>,
}

impl PreparedEnumeration for StagedEnumeration {
    fn children(&self) -> &[PlaceholderChild] {
        &self.children
    }
}

pub trait PreparedFetch {
    fn metadata(&self) -> PlaceholderMetadata;
    fn bytes(&self) -> &[u8];

    /// Called only for tracked vault data, under this fetch's existing
    /// publication permit. Implementations must use a captured custody view;
    /// resolving a route here could recursively acquire the publication lock.
    #[cfg(windows)]
    fn persist_vault_hydration(
        &self,
        _intent: &crate::vault_custody::VaultHydrationIntent,
    ) -> Result<(), BackendError> {
        Err(BackendError::Unavailable)
    }

    /// Opaque authenticated full-stage provenance before first plaintext transfer.
    /// Ordinary/readonly adapters supply None. Native acknowledgement, never the
    /// durable hydration intent, decides whether a receipt becomes ready.
    #[cfg(windows)]
    fn prepare_fresh_vault_hydration(
        &self,
        _intent: &crate::vault_custody::VaultHydrationIntent,
    ) -> Result<Option<crate::FreshVaultHydration>, BackendError> {
        Ok(None)
    }

    /// Recheck cancellation, authorization generation, and revocation before
    /// each native transfer slice. The OpenCloud implementation also retains
    /// its revocation lease for the lifetime of this value.
    fn begin_publish<'a>(
        &'a self,
        cancellation: &CancellationToken,
    ) -> Result<Box<dyn PublishPermit + 'a>, BackendError> {
        if cancellation.is_cancelled() {
            Err(BackendError::Cancelled)
        } else if cancellation.is_expired() {
            Err(BackendError::Unavailable)
        } else {
            Ok(Box::new(()))
        }
    }
}

/// Marker guard held across exactly one native `CfExecute` publication.
pub trait PublishPermit {}

impl<T: ?Sized> PublishPermit for T {}

struct StagedFetch {
    metadata: PlaceholderMetadata,
    bytes: Vec<u8>,
}

impl PreparedFetch for StagedFetch {
    fn metadata(&self) -> PlaceholderMetadata {
        self.metadata
    }

    fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Cooperative cancellation signal associated with one native request.
#[derive(Clone)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
    owner_cancelled: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
}

impl std::fmt::Debug for CancellationToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CancellationToken")
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

/// Immutable transfer-job policy, separate from storage quota and fetch limits.
#[derive(Clone, Copy, Debug)]
pub struct StreamedRecoveryPolicy {
    total_timeout: Duration,
}

impl StreamedRecoveryPolicy {
    pub fn new(total_timeout: Duration) -> Result<Self, BackendError> {
        if !(Duration::from_secs(60)..=Duration::from_secs(86_400)).contains(&total_timeout) {
            return Err(BackendError::Unavailable);
        }
        Ok(Self { total_timeout })
    }

    pub fn total_timeout(self) -> Duration {
        self.total_timeout
    }
}

impl Default for StreamedRecoveryPolicy {
    fn default() -> Self {
        Self {
            total_timeout: Duration::from_secs(21_600),
        }
    }
}

/// Ephemeral deadline/cancellation only; never upload or native ACK authority.
/// Clones retain the original deadline and cancellation state, including queue
/// wait, independent readback and joined source shutdown.
#[derive(Clone, Debug)]
pub struct StreamedRecoveryJob {
    cancellation: CancellationToken,
}

impl StreamedRecoveryJob {
    #[cfg(test)]
    pub(crate) fn for_test_timeout(timeout: Duration) -> Self {
        Self {
            cancellation: CancellationToken {
                cancelled: Arc::new(AtomicBool::new(false)),
                deadline: Instant::now() + timeout,
                owner_cancelled: None,
            },
        }
    }
    pub fn deadline(&self) -> Instant {
        self.cancellation.deadline()
    }
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }
    pub fn is_stopped(&self) -> bool {
        self.cancellation.is_cancelled() || self.cancellation.is_expired()
    }
    /// Borrow this job's original deadline and cancellation identity. This
    /// grants no upload, native completion or restored session authority.
    pub fn cancellation(&self) -> &CancellationToken {
        &self.cancellation
    }
    pub(crate) fn check(&self) -> Result<(), BackendError> {
        if self.is_stopped() {
            Err(BackendError::Unavailable)
        } else {
            Ok(())
        }
    }
    /// Add revocation without dropping earlier owner checks or extending time.
    /// Actual owner callbacks must be nonblocking atomic-only checks.
    pub fn with_revocation_check(&self, revoked: Arc<dyn Fn() -> bool + Send + Sync>) -> Self {
        let previous = self.cancellation.owner_cancelled.clone();
        let mut job = self.clone();
        job.cancellation.owner_cancelled = Some(Arc::new(move || {
            previous.as_ref().is_some_and(|check| check()) || revoked()
        }));
        job
    }
}

impl CancellationToken {
    /// Create a token for one request.
    pub fn new() -> Self {
        Self::with_timeout(DEFAULT_FETCH_TIMEOUT)
    }

    /// Create a request token with a bounded total deadline. This is public
    /// for deterministic short-timeout tests; production callers should use
    /// [`CancellationToken::new`].
    pub fn with_timeout(timeout: Duration) -> Self {
        let bounded = timeout.min(Duration::from_secs(30));
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            deadline: Instant::now() + bounded,
            owner_cancelled: None,
        }
    }

    pub fn for_recovery_job(policy: StreamedRecoveryPolicy) -> StreamedRecoveryJob {
        Self::for_recovery_job_with_deadline(policy, None)
    }

    /// Start one metadata-only namespace job with the existing 30-second
    /// request budget. Call once before queueing; clones and revocation probes
    /// retain this same deadline and cancellation state. This grants no
    /// directory dispatch, storage or native publication authority.
    pub fn for_metadata_job() -> StreamedRecoveryJob {
        StreamedRecoveryJob {
            cancellation: Self::new(),
        }
    }

    pub(crate) fn for_recovery_job_with_deadline(
        policy: StreamedRecoveryPolicy,
        original: Option<Instant>,
    ) -> StreamedRecoveryJob {
        let maximum = Instant::now() + policy.total_timeout;
        StreamedRecoveryJob {
            cancellation: Self {
                cancelled: Arc::new(AtomicBool::new(false)),
                deadline: original.map_or(maximum, |deadline| deadline.min(maximum)),
                owner_cancelled: None,
            },
        }
    }

    /// One explicit background file job may span many bounded requests.
    /// This does not change the 30-second default for native callbacks.
    pub fn for_offline_job() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            deadline: Instant::now() + Duration::from_secs(60 * 60),
            owner_cancelled: None,
        }
    }

    /// A single chunk's metadata and HTTP reads retain the callback-sized
    /// request budget even when its enclosing background job lasts longer.
    #[cfg(any(windows, test))]
    pub(crate) fn request_deadline(&self) -> Instant {
        self.deadline.min(Instant::now() + DEFAULT_FETCH_TIMEOUT)
    }

    /// One bounded metadata phase sharing the original cancellation/currentness.
    /// Only the clone's deadline changes; the original total job stays intact.
    #[cfg(any(windows, test))]
    pub(crate) fn bounded_request(&self) -> Self {
        let mut request = self.clone();
        request.deadline = self.request_deadline();
        request
    }

    /// Mark the request cancelled. Repeated calls are harmless.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// Check cancellation before starting or continuing backend work.
    pub fn is_cancelled(&self) -> bool {
        if self.owner_cancelled.as_ref().is_some_and(|check| check()) {
            // Revocation is sticky: a later reconnect/resume cannot revive it.
            self.cancel();
        }
        self.cancelled.load(Ordering::Acquire)
    }

    /// Whether the fixed total request budget has elapsed.
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.deadline
    }

    /// Remaining time for the next blocking operation, if any.
    pub fn remaining(&self) -> Option<Duration> {
        self.deadline.checked_duration_since(Instant::now())
    }

    /// Deadline passed into OpenCloud so every HTTP step shares one budget.
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }
}

const REQUEST_CANCELLED: u8 = 1;
const REQUEST_PUBLISHING: u8 = 2;

/// Linearizes one request's cancellation with synchronous native publication.
/// A publication whose permit was acquired first may finish; cancellation
/// prevents any later slice from starting.
#[derive(Debug, Default)]
pub struct RequestPublicationGate {
    state: AtomicU8,
}

impl RequestPublicationGate {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn begin_publish(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<RequestPublicationPermit<'_>, BackendError> {
        loop {
            if cancellation.is_cancelled() {
                return Err(BackendError::Cancelled);
            }
            if cancellation.is_expired() {
                return Err(BackendError::Unavailable);
            }
            let state = self.state.load(Ordering::Acquire);
            if state & REQUEST_CANCELLED != 0 {
                return Err(BackendError::Cancelled);
            }
            if state & REQUEST_PUBLISHING != 0 {
                return Err(BackendError::Unavailable);
            }
            if self
                .state
                .compare_exchange_weak(
                    state,
                    state | REQUEST_PUBLISHING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                let permit = RequestPublicationPermit { gate: self };
                if cancellation.is_cancelled() {
                    drop(permit);
                    return Err(BackendError::Cancelled);
                }
                if cancellation.is_expired() {
                    drop(permit);
                    return Err(BackendError::Unavailable);
                }
                return Ok(permit);
            }
        }
    }

    /// Mark the request cancelled without blocking the native callback.
    pub fn cancel(&self, cancellation: &CancellationToken) {
        self.state.fetch_or(REQUEST_CANCELLED, Ordering::AcqRel);
        cancellation.cancel();
    }
}

pub struct RequestPublicationPermit<'a> {
    gate: &'a RequestPublicationGate,
}

impl Drop for RequestPublicationPermit<'_> {
    fn drop(&mut self) {
        self.gate
            .state
            .fetch_and(!REQUEST_PUBLISHING, Ordering::AcqRel);
    }
}

/// Nonblocking bound for callback work with larger staging footprints than
/// ordinary range reads.
pub struct BoundedPermitPool {
    limit: usize,
    active: AtomicUsize,
}

impl BoundedPermitPool {
    pub fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            limit,
            active: AtomicUsize::new(0),
        })
    }

    pub fn try_acquire(self: &Arc<Self>) -> Option<BoundedPermit> {
        let mut active = self.active.load(Ordering::Acquire);
        loop {
            if active >= self.limit {
                return None;
            }
            match self.active.compare_exchange_weak(
                active,
                active + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(BoundedPermit {
                        pool: Arc::clone(self),
                    });
                }
                Err(actual) => active = actual,
            }
        }
    }
}

pub struct BoundedPermit {
    pool: Arc<BoundedPermitPool>,
}

impl Drop for BoundedPermit {
    fn drop(&mut self) {
        self.pool.active.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

/// One exact file binding retained across bounded callback windows.
/// A prepared window borrows this session so its binding lease cannot end
/// while any validated bytes are being published.
pub trait PreparedFetchSession {
    fn metadata(&self) -> PlaceholderMetadata;
    fn prepare_window<'a>(
        &'a self,
        range: FetchRange,
        cancellation: &CancellationToken,
    ) -> Result<Box<dyn PreparedFetch + 'a>, BackendError>;
}

/// Identity-scoped backend used by the callback bridge.
///
/// Implementations must not accept paths or derive object identity from a
/// callback's normalized path. `read_range` must write at most `output.len()`
/// bytes, return the exact number written, and check cancellation while doing
/// expensive work. The callback bridge caps each staging window at
/// [`MAX_REQUEST_BYTES`] and transfers data in [`MAX_RANGE_BYTES`] slices.
pub trait PlaceholderBackend: Send + Sync + 'static {
    /// Historical retained-route metadata only; no active session or bearer is
    /// restored. Native code must independently pin every original identity.
    #[cfg(windows)]
    fn vault_cleanup_root_locator(
        &self,
        _route: &crate::vault_routes::VerifiedVaultRoute,
    ) -> Result<crate::VaultCleanupRootLocator, BackendError> {
        Err(BackendError::Unavailable)
    }

    /// Atomic-only, nonblocking owner fence for an ephemeral recovery job.
    fn recovery_job_revoked(&self) -> bool {
        true
    }
    /// Capture the original transfer cancellation epoch once at job creation.
    fn recovery_transfer_cancellation(&self) -> Option<Arc<dyn Fn() -> bool + Send + Sync>> {
        None
    }

    /// Native bookkeeping is mandatory before publishing decrypted vault bytes.
    /// This classifies an already owned opaque identity; it grants no unlock.
    fn requires_hydration_inventory(&self, _identity: &[u8]) -> Result<bool, BackendError> {
        Ok(false)
    }

    fn lookup(&self, identity: &[u8]) -> Result<Option<PlaceholderMetadata>, BackendError>;

    /// Synchronously invoke exactly one callback while the exact vault's live
    /// account/root/route/token/session fences remain held. The caller must have
    /// classified this as a vault identity; refusal must never fall through to
    /// ordinary edit dispatch. No network or coordinator/token reentry is allowed
    /// in the callback. Ok acknowledges one historical retention only.
    #[cfg(windows)]
    fn with_vault_edit_capture(
        &self,
        _identity: &[u8],
        _callback: &mut dyn FnMut(&dyn ExistingVaultEditCapture) -> Result<(), BackendError>,
    ) -> Result<(), BackendError> {
        Err(BackendError::Unavailable)
    }

    #[cfg(windows)]
    fn cached_vault_edit_mode(&self, _identity: &[u8]) -> Result<bool, BackendError> {
        Ok(false)
    }
    #[cfg(windows)]
    fn with_vault_edit_capture_context(
        &self,
        identity: &[u8],
        callback: &mut dyn FnMut(
            crate::vault_cached_edit::VaultEditCaptureContext<'_>,
        ) -> Result<(), BackendError>,
    ) -> Result<(), BackendError> {
        self.with_vault_edit_capture(identity, &mut |capture| {
            callback(crate::vault_cached_edit::VaultEditCaptureContext::Online(
                capture,
            ))
        })
    }

    /// Prepare an exact account-bound baseline for a user-edited placeholder.
    /// Backends that cannot prove the callback identity return an error; native
    /// code must then retain the dirty placeholder as unresolved.
    fn prepare_edit_binding<'a>(
        &'a self,
        _identity: &[u8],
    ) -> Result<Box<dyn PreparedEditBinding + 'a>, BackendError> {
        Err(BackendError::Unavailable)
    }

    /// Return a complete, bounded direct-child listing for a directory
    /// identity. Partial results are never published. Backends without
    /// directory support fail closed by default.
    fn enumerate(
        &self,
        _identity: &[u8],
        _cancellation: &CancellationToken,
    ) -> Result<Vec<PlaceholderChild>, BackendError> {
        Err(BackendError::Unavailable)
    }

    /// Prepare a complete bounded listing for one callback. Network backends
    /// should override this to retain an identity and authorization lease until
    /// Cloud Files accepts the names. The default serves synthetic/local
    /// backends whose lifetime is not revocable.
    fn prepare_enumeration<'a>(
        &'a self,
        identity: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<Box<dyn PreparedEnumeration + 'a>, BackendError> {
        if cancellation.is_cancelled() {
            return Err(BackendError::Cancelled);
        }
        if cancellation.is_expired() {
            return Err(BackendError::Unavailable);
        }
        let children = self.enumerate(identity, cancellation)?;
        if cancellation.is_cancelled() {
            return Err(BackendError::Cancelled);
        }
        if cancellation.is_expired() {
            return Err(BackendError::Unavailable);
        }
        Ok(Box::new(StagedEnumeration { children }))
    }

    fn read_range(
        &self,
        identity: &[u8],
        offset: u64,
        output: &mut [u8],
        cancellation: &CancellationToken,
    ) -> Result<usize, BackendError>;

    /// Capture a stable identity for a callback spanning multiple bounded
    /// windows. Unsupported backends fail closed rather than rebinding each
    /// window independently.
    fn prepare_fetch_session<'a>(
        &'a self,
        _identity: &[u8],
        _cancellation: &CancellationToken,
    ) -> Result<Box<dyn PreparedFetchSession + 'a>, BackendError> {
        Err(BackendError::Unavailable)
    }

    /// Prepare an entire bounded staging window before publishing its bytes.
    /// The default is intended for deterministic/local backends and reads in
    /// bounded chunks. Network backends should override this to bind one
    /// conditional request and post-validation to the callback as a whole.
    fn prepare_fetch<'a>(
        &'a self,
        identity: &[u8],
        range: FetchRange,
        cancellation: &CancellationToken,
    ) -> Result<Box<dyn PreparedFetch + 'a>, BackendError> {
        if cancellation.is_cancelled() {
            return Err(BackendError::Cancelled);
        }
        if cancellation.is_expired() || range.len() > MAX_REQUEST_BYTES {
            return Err(BackendError::Unavailable);
        }
        let metadata = self
            .lookup(identity)?
            .filter(|meta| !meta.is_directory && range.end <= meta.length)
            .ok_or(BackendError::NotFound)?;
        let capacity = usize::try_from(range.len()).map_err(|_| BackendError::InvalidRange)?;
        let mut bytes = vec![0; capacity];
        let mut copied = 0usize;
        while copied < capacity {
            if cancellation.is_cancelled() {
                return Err(BackendError::Cancelled);
            }
            if cancellation.is_expired() {
                return Err(BackendError::Unavailable);
            }
            let count = (capacity - copied).min(MAX_RANGE_BYTES);
            let offset = range
                .offset
                .checked_add(copied as u64)
                .ok_or(BackendError::InvalidRange)?;
            let read = self.read_range(
                identity,
                offset,
                &mut bytes[copied..copied + count],
                cancellation,
            )?;
            if read != count {
                return Err(BackendError::Unavailable);
            }
            copied += read;
        }
        Ok(Box::new(StagedFetch { metadata, bytes }))
    }
}

/// A checked total transfer request derived from a Cloud Files range.
/// Staging must still split this into windows no larger than MAX_REQUEST_BYTES.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FetchRange {
    pub offset: u64,
    pub end: u64,
}

impl FetchRange {
    pub fn len(self) -> u64 {
        self.end - self.offset
    }

    pub fn is_empty(self) -> bool {
        self.offset == self.end
    }
}

/// Validate and bound the required range supplied by a FETCH_DATA callback.
/// A length of -1 means through EOF. The returned range never extends beyond
/// the authenticated metadata size and the total file hard limit. Staging
/// windows retain their separate MAX_REQUEST_BYTES bound.
pub fn checked_fetch_range(
    file_len: u64,
    required_offset: i64,
    required_len: i64,
) -> Result<FetchRange, BackendError> {
    let offset = u64::try_from(required_offset).map_err(|_| BackendError::InvalidRange)?;
    if offset > file_len || (offset == file_len && required_len != 0 && required_len != -1) {
        return Err(BackendError::InvalidRange);
    }
    if required_len < 0 && required_len != -1 {
        return Err(BackendError::InvalidRange);
    }
    if required_len == 0 && offset != file_len {
        return Err(BackendError::InvalidRange);
    }
    if offset != file_len && offset % TRANSFER_ALIGNMENT != 0 {
        return Err(BackendError::InvalidRange);
    }
    let requested_end = if required_len == -1 {
        file_len
    } else {
        offset
            .checked_add(required_len as u64)
            .ok_or(BackendError::InvalidRange)?
            .min(file_len)
    };
    let len = requested_end
        .checked_sub(offset)
        .ok_or(BackendError::InvalidRange)?;
    if file_len > MAX_FILE_BYTES || len > MAX_FILE_BYTES {
        return Err(BackendError::InvalidRange);
    }
    if requested_end < file_len && len % TRANSFER_ALIGNMENT != 0 {
        return Err(BackendError::InvalidRange);
    }
    Ok(FetchRange {
        offset,
        end: requested_end,
    })
}

/// Return the next bounded transfer length for a previously checked range.
pub fn next_chunk_len(remaining: u64) -> usize {
    remaining.min(MAX_RANGE_BYTES as u64) as usize
}

#[cfg(test)]
mod tests {
    #[test]
    fn per_file_readonly_default_preserves_the_existing_listing_policy() {
        use super::*;
        let child = PlaceholderChild {
            name: "file".into(),
            identity: vec![1; 16],
            metadata: PlaceholderMetadata {
                is_directory: false,
                length: 4,
            },
            last_write_time: 0,
        };
        let ordinary = StagedEnumeration {
            children: vec![child.clone()],
        };
        assert!(!ordinary.file_read_only(&child));
        struct ReadOnly(Vec<PlaceholderChild>);
        impl PreparedEnumeration for ReadOnly {
            fn read_only(&self) -> bool {
                true
            }
            fn children(&self) -> &[PlaceholderChild] {
                &self.0
            }
        }
        assert!(ReadOnly(vec![child.clone()]).file_read_only(&child));
    }

    use super::{BackendError, MAX_RANGE_BYTES, checked_fetch_range, next_chunk_len};

    #[test]
    fn range_is_clamped_to_eof_and_chunked_with_a_bounded_buffer() {
        let range = checked_fetch_range(70_000, 0, -1).unwrap();
        assert_eq!(range.len(), 70_000);
        assert_eq!(next_chunk_len(range.len()), MAX_RANGE_BYTES);
        assert_eq!(next_chunk_len(range.len() - MAX_RANGE_BYTES as u64), 4_464);

        let tail = checked_fetch_range(70_000, 65_536, 64 * 1024).unwrap();
        assert_eq!(tail, range_for(65_536, 70_000));
    }

    fn range_for(offset: u64, end: u64) -> super::FetchRange {
        super::FetchRange { offset, end }
    }

    #[test]
    fn range_rejects_negative_misaligned_overflow_and_excessive_requests() {
        assert_eq!(
            checked_fetch_range(8192, -1, 4096),
            Err(BackendError::InvalidRange)
        );
        assert_eq!(
            checked_fetch_range(8192, 1, 4096),
            Err(BackendError::InvalidRange)
        );
        assert_eq!(
            checked_fetch_range(8192, 0, -2),
            Err(BackendError::InvalidRange)
        );
        assert_eq!(
            checked_fetch_range(8192, 8193, 1),
            Err(BackendError::InvalidRange)
        );
        assert_eq!(
            checked_fetch_range(u64::MAX, 0, i64::MAX),
            Err(BackendError::InvalidRange)
        );
        assert_eq!(
            checked_fetch_range(super::MAX_FILE_BYTES + 1, 0, -1),
            Err(BackendError::InvalidRange)
        );
    }

    #[test]
    fn large_total_ranges_are_checked_without_lifting_the_window_bound() {
        let length = 17 * 1024 * 1024 + 7;
        assert_eq!(checked_fetch_range(length, 0, -1).unwrap().len(), length);
        assert_eq!(super::MAX_REQUEST_BYTES, 16 * 1024 * 1024);
    }

    #[test]
    fn eof_ranges_are_empty_or_clamped_without_reading_past_the_file() {
        assert_eq!(checked_fetch_range(4096, 4096, 0).unwrap().len(), 0);
        assert_eq!(checked_fetch_range(4096, 0, -1).unwrap().len(), 4096);
        assert_eq!(checked_fetch_range(4096, 0, 8192).unwrap().len(), 4096);
        assert_eq!(checked_fetch_range(0, 0, -1).unwrap().len(), 0);
    }

    #[test]
    fn streamed_job_policy_is_validated_and_clones_never_reset_time() {
        use super::{CancellationToken, StreamedRecoveryJob, StreamedRecoveryPolicy};
        use std::time::Duration;
        assert!(StreamedRecoveryPolicy::new(Duration::from_secs(59)).is_err());
        assert!(StreamedRecoveryPolicy::new(Duration::from_secs(86401)).is_err());
        assert_eq!(
            StreamedRecoveryPolicy::default().total_timeout(),
            Duration::from_secs(21600)
        );
        let job = CancellationToken::for_recovery_job(StreamedRecoveryPolicy::default());
        assert_eq!(job.deadline(), job.clone().deadline());
        assert!(job.cancellation().remaining().unwrap() > Duration::from_secs(30));
        let expired = StreamedRecoveryJob::for_test_timeout(Duration::ZERO);
        assert!(expired.check().is_err());
        assert!(expired.is_stopped());
    }

    #[test]
    fn metadata_job_keeps_original_request_budget_and_shared_cancellation() {
        use super::{CancellationToken, DEFAULT_FETCH_TIMEOUT};
        use std::{
            sync::{
                Arc,
                atomic::{AtomicBool, Ordering},
            },
            time::Instant,
        };
        let before = Instant::now();
        let job = CancellationToken::for_metadata_job();
        let after = Instant::now();
        assert!(job.deadline() >= before + DEFAULT_FETCH_TIMEOUT);
        assert!(job.deadline() <= after + DEFAULT_FETCH_TIMEOUT);
        let original_deadline = job.deadline();
        let revoked = Arc::new(AtomicBool::new(false));
        let observed = revoked.clone();
        let queued = job.with_revocation_check(Arc::new(move || observed.load(Ordering::Acquire)));
        assert_eq!(queued.deadline(), original_deadline);
        assert!(!queued.is_stopped());
        revoked.store(true, Ordering::Release);
        assert!(queued.is_stopped());
        revoked.store(false, Ordering::Release);
        assert!(job.is_stopped());
        assert!(queued.clone().is_stopped());
        assert_eq!(job.deadline(), original_deadline);
    }

    #[test]
    fn streamed_job_owner_revocation_is_sticky_and_additive() {
        use super::{CancellationToken, StreamedRecoveryPolicy};
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        let first = Arc::new(AtomicBool::new(false));
        let second = Arc::new(AtomicBool::new(false));
        let job = CancellationToken::for_recovery_job(StreamedRecoveryPolicy::default());
        let observed = first.clone();
        let job = job.with_revocation_check(Arc::new(move || observed.load(Ordering::Acquire)));
        let observed = second.clone();
        let linked = job.with_revocation_check(Arc::new(move || observed.load(Ordering::Acquire)));
        assert_eq!(job.deadline(), linked.deadline());
        first.store(true, Ordering::Release);
        assert!(linked.is_stopped());
        first.store(false, Ordering::Release);
        assert!(job.is_stopped());
        assert!(linked.is_stopped());
    }

    #[test]
    fn cancellation_token_is_shared_and_idempotent() {
        let token = super::CancellationToken::new();
        let reader = token.clone();
        assert!(!reader.is_cancelled());
        token.cancel();
        assert!(reader.is_cancelled());
        reader.cancel();
        assert!(token.is_cancelled());
    }

    #[test]
    fn bounded_metadata_request_times_out_held_graph_and_preserves_original_job() {
        use super::{CancellationToken, StreamedRecoveryPolicy};
        use raiun_opencloud::{OpenCloudClient, ProxyConfig, RangeReadContext};
        use std::{
            io::Read,
            net::TcpListener,
            sync::{
                Arc,
                atomic::{AtomicBool, Ordering},
                mpsc,
            },
            thread,
            time::{Duration, Instant},
        };

        // Even a failed factual barrier/assertion releases the peer before either
        // thread joins. No detached client, kill, network retry or test timeout kill.
        struct HeldGraph {
            release: Option<mpsc::Sender<()>>,
            peer: Option<thread::JoinHandle<bool>>,
            client: Option<thread::JoinHandle<()>>,
        }
        impl HeldGraph {
            fn cleanup(&mut self) -> (bool, bool) {
                drop(self.release.take());
                let peer = self
                    .peer
                    .take()
                    .is_none_or(|peer| peer.join().unwrap_or(false));
                let client = self
                    .client
                    .take()
                    .is_none_or(|client| client.join().is_ok());
                (peer, client)
            }
        }
        impl Drop for HeldGraph {
            fn drop(&mut self) {
                let _ = self.cleanup();
            }
        }
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let client = OpenCloudClient::new_with_proxy(
            &format!("http://{address}"),
            "synthetic-metadata-cap".into(),
            &ProxyConfig::Direct,
        )
        .unwrap();
        let owner_revoked = Arc::new(AtomicBool::new(false));
        let probe = owner_revoked.clone();
        let original = CancellationToken::for_recovery_job(
            StreamedRecoveryPolicy::new(Duration::from_secs(60)).unwrap(),
        )
        .with_revocation_check(Arc::new(move || probe.load(Ordering::Acquire)));
        let original_deadline = original.deadline();
        let started = Instant::now();
        // This is the same production helper the owned file Prepare path uses.
        let metadata = original.cancellation().bounded_request();
        let bounded_at = Instant::now();
        let context = RangeReadContext {
            deadline: metadata.deadline(),
            token_generation: client.token_generation(),
        };
        let same_cancel = Arc::ptr_eq(&metadata.cancelled, &original.cancellation().cancelled);
        let same_owner = match (
            &metadata.owner_cancelled,
            &original.cancellation().owner_cancelled,
        ) {
            (Some(left), Some(right)) => Arc::ptr_eq(left, right),
            _ => false,
        };
        let (release, released) = mpsc::channel();
        let (accepted, accepted_request) = mpsc::channel();
        let peer_released = Arc::new(AtomicBool::new(false));
        let peer_done = peer_released.clone();
        let mut held = HeldGraph {
            release: Some(release),
            peer: None,
            client: None,
        };
        held.peer = Some(thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(40);
            let mut socket = loop {
                if !matches!(released.try_recv(), Err(mpsc::TryRecvError::Empty))
                    || Instant::now() >= deadline
                {
                    return false;
                }
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(_) => return false,
                }
            };
            if socket.set_nonblocking(false).is_err()
                || socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .is_err()
            {
                return false;
            }
            let mut bytes = Vec::new();
            let mut byte = [0];
            while !bytes.ends_with(b"\r\n\r\n") && bytes.len() < 32768 {
                if socket.read_exact(&mut byte).is_err() {
                    return false;
                }
                bytes.push(byte[0]);
            }
            let request = String::from_utf8_lossy(&bytes);
            let valid = bytes.ends_with(b"\r\n\r\n")
                && request.lines().next() == Some("GET /graph/v1.0/me/drives HTTP/1.1");
            if accepted.send(valid).is_err() {
                return false;
            }
            // No response headers/body are sent before the test releases this peer.
            // The finite safety bound is longer than the request/result assertion.
            let _ = released.recv_timeout(Duration::from_secs(40));
            peer_done.store(true, Ordering::Release);
            drop(socket);
            valid
        }));
        let (completed, result) = mpsc::channel();
        held.client = Some(thread::spawn(move || {
            let value = client.spaces_with_context_limited(context, 1);
            let _ = completed.send((value, started.elapsed()));
        }));
        let factual_request = accepted_request.recv_timeout(Duration::from_secs(5));
        original.cancel();
        let outcome = result.recv_timeout(Duration::from_secs(33));
        let terminal_while_peer_held = outcome.is_ok() && !peer_released.load(Ordering::Acquire);
        // These joins precede every assertion after threads were started. The
        // old long-context path is released at 33s and fails without hanging.
        let joined = held.cleanup();
        assert_eq!(joined, (true, true));
        assert_eq!(factual_request.ok(), Some(true));
        assert!(same_cancel && same_owner);
        assert_eq!(original.deadline(), original_deadline);
        assert!(metadata.deadline() <= original_deadline);
        assert!(metadata.deadline() <= bounded_at + Duration::from_secs(30));
        assert!(original.is_stopped() && metadata.is_cancelled());
        assert!(
            terminal_while_peer_held,
            "metadata must finish before peer release at the real production request cap"
        );
        let (value, elapsed) = outcome.expect("bounded metadata result before 33s");
        assert!(value.is_err());
        assert!((Duration::from_secs(25)..=Duration::from_secs(33)).contains(&elapsed));
    }

    #[test]
    fn cancellation_token_uses_one_bounded_monotonic_deadline() {
        let token = super::CancellationToken::with_timeout(std::time::Duration::ZERO);
        assert!(token.is_expired());
        assert!(token.remaining().is_none());
    }

    #[test]
    fn offline_job_deadline_is_longer_than_one_request_but_requests_stay_bounded() {
        use std::time::Duration;

        let default = super::CancellationToken::new();
        let default_remaining = default.remaining().unwrap();
        assert!(!default_remaining.is_zero());
        assert!(default_remaining <= Duration::from_secs(30));

        let capped = super::CancellationToken::with_timeout(Duration::from_secs(60 * 60));
        let capped_remaining = capped.remaining().unwrap();
        assert!(!capped_remaining.is_zero());
        assert!(capped_remaining <= Duration::from_secs(30));

        let job = super::CancellationToken::for_offline_job();
        let job_remaining = job.remaining().unwrap();
        assert!(job_remaining > Duration::from_secs(30));
        assert!(job_remaining <= Duration::from_secs(60 * 60));
        let job_deadline = job.deadline();
        let request_deadline = job.request_deadline();
        assert!(request_deadline <= job_deadline);
        assert!(request_deadline <= std::time::Instant::now() + Duration::from_secs(30));

        let observer = job.clone();
        job.cancel();
        assert!(observer.is_cancelled());
    }

    #[test]
    fn request_cancel_is_nonblocking_and_blocks_the_next_publication() {
        let gate = super::RequestPublicationGate::new();
        let token = super::CancellationToken::new();
        let publication = gate.begin_publish(&token).unwrap();
        gate.cancel(&token);
        assert!(token.is_cancelled());
        assert!(matches!(
            gate.begin_publish(&token),
            Err(super::BackendError::Cancelled)
        ));
        drop(publication);
        assert!(matches!(
            gate.begin_publish(&token),
            Err(super::BackendError::Cancelled)
        ));
    }

    #[test]
    fn bounded_permit_pool_caps_concurrent_work_and_releases_on_drop() {
        let pool = super::BoundedPermitPool::new(2);
        let first = pool.try_acquire().expect("first slot");
        let second = pool.try_acquire().expect("second slot");
        assert!(pool.try_acquire().is_none());
        drop(first);
        assert!(pool.try_acquire().is_some());
        drop(second);
    }

    #[test]
    fn placeholder_population_is_complete_only_when_every_entry_succeeded() {
        let successful = [0, 0];
        assert!(super::placeholder_population_completed(
            0,
            2,
            2,
            &successful
        ));
        assert!(!super::placeholder_population_completed(
            -1,
            2,
            2,
            &successful
        ));
        assert!(!super::placeholder_population_completed(
            0,
            2,
            1,
            &successful[..1]
        ));
        assert!(!super::placeholder_population_completed(0, 2, 2, &[0, -1]));
        assert!(!super::placeholder_population_completed(
            0,
            2,
            3,
            &successful
        ));
    }
}
