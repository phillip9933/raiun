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
#[derive(Clone, Debug)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
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
        }
    }

    /// One explicit background file job may span many bounded requests.
    /// This does not change the 30-second default for native callbacks.
    pub fn for_offline_job() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            deadline: Instant::now() + Duration::from_secs(60 * 60),
        }
    }

    /// A single chunk's metadata and HTTP reads retain the callback-sized
    /// request budget even when its enclosing background job lasts longer.
    #[cfg(any(windows, test))]
    pub(crate) fn request_deadline(&self) -> Instant {
        self.deadline.min(Instant::now() + DEFAULT_FETCH_TIMEOUT)
    }

    /// Mark the request cancelled. Repeated calls are harmless.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// Check cancellation before starting or continuing backend work.
    pub fn is_cancelled(&self) -> bool {
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
    /// Native bookkeeping is mandatory before publishing decrypted vault bytes.
    /// This classifies an already owned opaque identity; it grants no unlock.
    fn requires_hydration_inventory(&self, _identity: &[u8]) -> Result<bool, BackendError> {
        Ok(false)
    }

    fn lookup(&self, identity: &[u8]) -> Result<Option<PlaceholderMetadata>, BackendError>;

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
