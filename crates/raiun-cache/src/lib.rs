//! Private, version-scoped metadata and content cache primitives.
//!
//! This crate does not perform network requests or reconcile remote state. Its
//! callers publish only fully verified content and complete listings. Under a
//! ciphertext-only scope this crate stores ciphertext content, opaque
//! resource/version identifiers, and hashes of encrypted operation targets.
//! It never accepts decrypted paths or names; vault reads must never send
//! decrypted bytes to this crate.

mod folder_pin_roles;
#[cfg(test)]
mod folder_pin_roles_tests;
mod folder_policy;
#[cfg(unix)]
mod folder_policy_admission;
use folder_pin_roles::PinAdmission;
pub use folder_pin_roles::{FolderPinIntent, FolderPinRoles};
#[cfg(unix)]
pub use folder_policy_admission::FolderPolicyListing;
mod pin_readiness;
pub use pin_readiness::PinRefreshExpectation;
mod pin_recovery;
#[cfg(test)]
mod pin_recovery_tests;
mod pin_resume;
pub use pin_recovery::{RetainedPinManifest, RetainedPinSummary};

use raiun_core::backend::{CloudError, ErrorKind, RemoteEntry, WriteCondition};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::Builder;
use url::Url;

#[cfg(test)]
mod cancellable_content_reader_tests;
#[cfg(test)]
mod ciphertext_retry_tests;
mod content_reader;
#[cfg(test)]
mod listed_policy_tests;
#[cfg(test)]
mod pin_cancellation_tests;
#[cfg(test)]
mod pin_resume_tests;
#[cfg(test)]
mod pin_snapshot_tests;
#[cfg(test)]
mod policy_intent_revision_tests;
#[cfg(test)]
mod recent_budget_tests;
#[cfg(any(windows, test))]
mod stage_name;
pub use content_reader::CacheContentReader;
mod db_owner;
mod listing_publication;
mod schema;
use db_owner::DbOwner;

// This is an opt-in Windows storage adapter test fixture only. The production
// cache remains unavailable on non-Unix until all cache object paths have a
// handle-bound security implementation.
#[cfg(all(test, windows))]
mod private_windows;
#[cfg(windows)]
mod windows_backend;
#[cfg(windows)]
mod windows_blob;
#[cfg(all(windows, test))]
mod windows_cached_promotion_tests;
#[cfg(all(windows, test))]
mod windows_cancellable_verification_tests;
#[cfg(all(windows, test))]
mod windows_download_abort_tests;
#[cfg(windows)]
mod windows_download_stage;
#[cfg(all(windows, test))]
mod windows_download_stage_tests;
#[cfg(windows)]
mod windows_lock;
#[cfg(all(windows, test))]
mod windows_pin_download_tests;
#[cfg(windows)]
pub use windows_download_stage::{
    CachedPlaintextVerification, MAX_STAGED_PLAINTEXT_BYTES, PlaintextDownloadStage,
    VerifiedPlaintextDownload,
};

const CACHE_VERSION: u32 = 8;
const MAX_SCOPE_FIELD: usize = 1024;
const MAX_PATH_BYTES: usize = 32 * 1024;
const MAX_ENTRY_NAME_BYTES: usize = 4096;
const MAX_LISTING_ENTRIES: usize = 100_000;
const MAX_LISTING_BYTES: usize = 32 * 1024 * 1024;
const MAX_SCOPES: usize = 256;
const MAX_SNAPSHOTS: usize = 100_000;
const MAX_TOTAL_LISTING_ENTRIES: usize = 1_000_000;
const MAX_CONTENT_RECORDS: usize = 1_000_000;
const MAX_PIN_RECORDS: usize = 10_000;
const MAX_TOTAL_PIN_ITEMS: usize = 1_000_000;
const MAX_CONTENT_BYTES: u64 = 1 << 40;
const MAX_CIPHERTEXT_PINS: usize = 10_000;
const MAX_CIPHERTEXT_PIN_GENERATIONS: usize = 100_000;
const MAX_CIPHERTEXT_PIN_ITEMS: usize = 1_000_000;
const MAX_CIPHERTEXT_WRITES: usize = 10_000;
const MAX_CIPHERTEXT_WRITES_PER_PARENT: usize = 1_000;
/// Acknowledged local-cancel receipts are compact, metadata-only proofs.
/// Bound retained proofs per exact cache scope when a caller crashes before
/// removing its local cancellation WAL.
const MAX_CANCEL_ACK_RECEIPTS_PER_SCOPE: usize = 256;
const MAX_JOURNAL_ENTRIES: usize = 100_000;
const MAX_JOURNAL_RECORDS: usize = 100_000;
#[cfg(not(windows))]
const CONTENT_DIR: &str = "content";
#[cfg(any(not(windows), test))]
const DB_FILE: &str = "cache.sqlite3";
type PendingWriteRow = (
    i64,
    String,
    String,
    String,
    Option<String>,
    i64,
    String,
    String,
    i64,
    i64,
);
static JOURNAL_VERSION_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum ScopeProtection {
    PlaintextAllowed,
    CiphertextOnly,
}

/// Cache namespace identity. `origin` is normalized to a scheme/host/port
/// origin and is part of every metadata, content, pin, and journal key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheScope {
    origin: String,
    account_id: String,
    space_id: String,
    root_resource_id: String,
    protection: ScopeProtection,
    key: String,
}

impl CacheScope {
    pub fn new(
        origin: &str,
        account_id: &str,
        space_id: &str,
        root_resource_id: &str,
        protection: ScopeProtection,
    ) -> Result<Self, CacheError> {
        let parsed = Url::parse(origin).map_err(|_| CacheError::InvalidScope)?;
        if !matches!(parsed.scheme(), "https" | "http")
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.path() != "/"
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(CacheError::InvalidScope);
        }
        for value in [account_id, space_id, root_resource_id] {
            if value.trim().is_empty() || value.len() > MAX_SCOPE_FIELD {
                return Err(CacheError::InvalidScope);
            }
        }
        let origin = parsed.origin().ascii_serialization();
        let key = hash_fields(&[
            &origin,
            account_id,
            space_id,
            root_resource_id,
            &(protection as i64).to_string(),
        ]);
        Ok(Self {
            origin,
            account_id: account_id.to_owned(),
            space_id: space_id.to_owned(),
            root_resource_id: root_resource_id.to_owned(),
            protection,
            key,
        })
    }

    pub fn origin(&self) -> &str {
        &self.origin
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub fn space_id(&self) -> &str {
        &self.space_id
    }

    pub fn root_resource_id(&self) -> &str {
        &self.root_resource_id
    }

    pub fn protection(&self) -> ScopeProtection {
        self.protection
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedEntry {
    pub parent_resource_id: String,
    pub entry: RemoteEntry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedListing {
    pub generation: u64,
    pub fetched_at_unix: i64,
    /// Listings returned by this API are complete; partial responses are not
    /// accepted by `publish_listing`.
    pub complete: bool,
    pub entries: Vec<CachedEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum ContentProtection {
    Plaintext,
    Ciphertext,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum Retention {
    Recent,
    Dirty,
    Recovery,
}

#[derive(Clone)]
struct ContentPublishOptions {
    retention: Retention,
    recent_budget: bool,
    require_listed: bool,
    expected_ciphertext_epoch: Option<u64>,
    pin_build: Option<(String, u64, CiphertextPinItemKind)>,
    ciphertext_write: Option<CiphertextWritePublish>,
}

#[derive(Clone)]
struct CiphertextWritePublish {
    id: String,
    revision: u64,
    expected_revision: Option<u64>,
    target_key: String,
    plaintext_len: u64,
    operation: CiphertextWriteOperation,
    state: CiphertextWriteState,
    parent_key: String,
    parent_operation_key: String,
    dependency_key: String,
    expected_target_key: Option<String>,
    expected_state: Option<CiphertextWriteState>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum AvailabilityPolicy {
    Recent,
    AlwaysOffline,
    CloudOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentVersion {
    pub resource_id: String,
    pub etag: String,
    pub protection: ContentProtection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentRecord {
    pub version: ContentVersion,
    pub byte_len: u64,
    pub sha256: String,
    pub retention: Retention,
}

/// Opaque identity and monotonically increasing revision for one encrypted
/// pending write. It contains no path, resource ID, ETag, or plaintext name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiphertextWriteBuild {
    id: String,
    revision: u64,
    expected_revision: Option<u64>,
    target_key: String,
    plaintext_len: u64,
    operation: CiphertextWriteOperation,
    publish_state: CiphertextWriteState,
    parent_key: String,
    parent_operation_key: String,
    dependency_key: String,
    scope_key: String,
    root_resource_id: String,
    expected_target_key: Option<String>,
    expected_state: Option<CiphertextWriteState>,
    // Retargeted subtree envelopes are randomized before the database
    // transaction. A unique content ETag lets a retry after a crash-before-
    // commit publish a fresh immutable blob without colliding with an
    // inaccessible orphan from the prior attempt.
    content_etag: Option<String>,
}

/// One member of a bounded atomic retarget of a never-attempted directory
/// subtree. The identifiers and targets are opaque hashes; callers keep the
/// corresponding logical paths only inside authenticated envelopes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiphertextSubtreeRetarget {
    pub id: String,
    pub expected_revision: u64,
    pub expected_target: String,
    pub new_target: String,
    pub new_parent_path: String,
    pub new_parent_operation: Option<(String, u64)>,
    pub plaintext_len: u64,
    pub operation: CiphertextWriteOperation,
}

/// A fully encrypted revision awaiting publication as part of one subtree
/// transaction. Sources are consumed only after the entire batch passes its
/// size and row-count bounds.
pub struct CiphertextSubtreeRetargetContent<'a> {
    pub build: &'a CiphertextWriteBuild,
    pub source: &'a mut dyn Read,
    pub expected_len: u64,
}

/// Non-sensitive operation class stored beside an encrypted journal revision.
/// Paths, names, resource IDs, and base validators remain inside the encrypted
/// envelope; this field only lets a directory overlay query create records
/// without decrypting unrelated file-edit bodies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum CiphertextWriteOperation {
    Overwrite = 0,
    CreateFile = 1,
    RenameFile = 2,
    DeleteFile = 3,
    CreateDirectory = 4,
    /// A copy-specific create that generic file-create recovery must never
    /// retry or reconcile without its source identity and readback checks.
    CopyFile = 5,
}

impl CiphertextWriteBuild {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn content_version(&self) -> ContentVersion {
        ContentVersion {
            resource_id: format!("vault-write-{}", self.id),
            etag: self
                .content_etag
                .clone()
                .unwrap_or_else(|| format!("revision-{}", self.revision)),
            protection: ContentProtection::Ciphertext,
        }
    }

    pub fn operation(&self) -> CiphertextWriteOperation {
        self.operation
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum CiphertextWriteState {
    Pending = 0,
    Conflict = 1,
    Uncertain = 2,
    /// Initial encrypted CREATE intent whose FUSE working copy has not yet
    /// been flushed. It is durable for recovery, but must not be replayed or
    /// projected into the remote namespace.
    Building = 3,
    /// Verified MKCOL receipt kept as a parent-identity dependency for queued
    /// descendants. It is not retryable and is retired only when no journal
    /// rows still reference this exact operation generation.
    CommittedReceipt = 4,
    /// A newly-created directory intent that has never been handed to the
    /// network layer. Only this state may be canceled locally.
    NeverAttempted = 5,
    /// A directory-create attempt was durably claimed before dispatch. A
    /// process interruption leaves this unresolved and non-cancelable.
    Attempting = 6,
    /// A NeverAttempted local create was explicitly canceled by the user.
    /// Its sealed body remains retained until the caller durably retires the
    /// matching private recovery copy and acknowledges this receipt.
    CancelledReceipt = 7,
    /// Small authenticated terminal proof retained after local cancellation
    /// has been acknowledged, until the caller durably removes its WAL.
    AcknowledgedReceipt = 8,
    /// A user explicitly retried a crash-left CreateFile attempt. This state
    /// is excluded from automatic retries. Its alternating value provides a
    /// compare-and-set token for subsequent explicit retries.
    RecoveryAttempting = 9,
    /// Alternate CAS token for another explicit retry of an interrupted
    /// CreateFile. Like RecoveryAttempting, it is never automatically retried.
    RecoveryRetrying = 10,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiphertextWriteInfo {
    pub id: String,
    pub revision: u64,
    pub byte_len: u64,
    pub state: CiphertextWriteState,
    /// SHA-256 index of the encrypted DAV-relative target, never a plaintext path.
    pub target_key: String,
    pub plaintext_len: u64,
    pub operation: CiphertextWriteOperation,
    /// Monotonic explicit-retry attempt token. This cache CAS fence does not
    /// replace authentication of the sealed operation metadata.
    pub retry_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinManifestEntry {
    pub parent_resource_id: String,
    pub entry: RemoteEntry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinState {
    Building,
    Ready,
    /// A verified remote mutation may have changed this snapshot. Its bytes
    /// remain available and retained, but callers must not present it as the
    /// current tree until it has been explicitly rebuilt.
    Stale,
    /// The exact resource identity is no longer present at a verified path.
    /// Retained bytes are preserved, but offline lookup must not expose them.
    Unavailable,
}

/// A durable request for offline retention whose target is not marked complete.
/// No partial content or recovery objects are exposed or modified by this record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingOfflineIntent {
    pub resource_id: String,
    pub path: String,
    pub etag: String,
    pub revision: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum TargetState {
    Ready = 0,
    Stale = 1,
    Unavailable = 2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRefreshTarget {
    pub resource_id: String,
    pub path: String,
    pub etag: String,
    pub state: TargetState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinRefreshTarget {
    pub pin_id: String,
    pub root_resource_id: String,
    pub path: String,
    pub state: PinState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinInfo {
    pub id: String,
    pub root_resource_id: String,
    pub root_path: String,
    pub state: PinState,
    pub item_count: usize,
    pub ready_content_count: usize,
    pub required_content_count: usize,
}

/// Bounded page of opaque ciphertext-only scope identities for local offline
/// discovery. The cursor is the final `(space_id, root_resource_id)` pair from
/// the returned page, not a filesystem path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiphertextScopePage {
    pub items: Vec<CacheScope>,
    pub next_after: Option<(String, String)>,
    pub truncated: bool,
}

/// Opaque encrypted-tree pin state. The cache never stores decrypted paths or
/// display names for these pins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum CiphertextPinState {
    Building = 0,
    Ready = 1,
    Stale = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum CiphertextPinItemKind {
    RootListing = 0,
    ChildListing = 1,
    FileContent = 2,
}

/// Opaque generation handle. Fields are private so callers cannot forge a
/// generation for another cache scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiphertextPinBuild {
    id: String,
    generation: u64,
    scope_key: String,
    root_resource_id: String,
    epoch: u64,
}

impl CiphertextPinBuild {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn root_resource_id(&self) -> &str {
        &self.root_resource_id
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiphertextPinInfo {
    pub id: String,
    pub generation: u64,
    pub state: CiphertextPinState,
    pub item_count: usize,
    pub byte_len: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiphertextPinPage {
    pub items: Vec<CiphertextPinInfo>,
    pub next_after: Option<String>,
    pub truncated: bool,
}

struct CiphertextPinReference<'a> {
    pin_id: &'a str,
    generation: u64,
    version: &'a ContentVersion,
    content_key: &'a str,
    byte_len: u64,
    kind: CiphertextPinItemKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedWrite {
    pub id: i64,
    pub parent_resource_id: String,
    pub name: String,
    pub logical_path: String,
    pub resource_id: Option<String>,
    pub base: WriteCondition,
    pub content: ContentVersion,
    pub state: WriteState,
    pub created_at_unix: i64,
}

/// Bounded account-scoped view of locally retained pending/conflicted writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingWritePage {
    pub items: Vec<PendingWriteItem>,
    pub pending_count: u64,
    pub conflict_count: u64,
    pub next_after: Option<String>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingWriteItem {
    pub space_id: String,
    pub root_resource_id: String,
    pub write_id: i64,
    pub path: String,
    pub state: WriteState,
    pub bytes: u64,
    pub created_at_unix: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConditionalWriteRequest {
    pub parent_resource_id: String,
    pub name: String,
    pub logical_path: String,
    pub resource_id: Option<String>,
    pub base: WriteCondition,
    pub expected_len: u64,
    pub protection: ContentProtection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteState {
    Pending,
    Conflict,
    Verified,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EvictionReport {
    pub removed_bytes: u64,
    pub used_bytes: u64,
    pub protected_bytes: u64,
    pub over_quota: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CacheUsage {
    pub quota_bytes: u64,
    pub used_bytes: u64,
    pub pinned_bytes: u64,
    pub protected_bytes: u64,
    pub over_quota: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheError {
    Cancelled,
    InvalidScope,
    UnsafeDirectory,
    InvalidEntry,
    InvalidContentVersion,
    ProtectionMismatch,
    NotFound,
    Conflict,
    IncompleteListing,
    IncompleteManifest,
    PinNotFound,
    PolicyConflict,
    LimitExceeded,
    InsufficientSpace,
    Corrupt,
    Io(String),
    Database(String),
}

impl std::fmt::Display for CacheError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => write!(formatter, "cache verification was cancelled"),
            Self::InvalidScope => write!(formatter, "cache scope is invalid"),
            Self::UnsafeDirectory => write!(formatter, "cache directory is not private and safe"),
            Self::InvalidEntry => write!(formatter, "cached metadata entry is invalid"),
            Self::InvalidContentVersion => write!(formatter, "cached content version is invalid"),
            Self::ProtectionMismatch => {
                write!(formatter, "content protection does not match scope")
            }
            Self::NotFound => write!(formatter, "cached item was not found"),
            Self::Conflict => write!(formatter, "cached item changed during the operation"),
            Self::IncompleteListing => {
                write!(formatter, "a complete cached listing is unavailable")
            }
            Self::IncompleteManifest => write!(formatter, "offline pin manifest is incomplete"),
            Self::PinNotFound => write!(formatter, "offline pin was not found"),
            Self::PolicyConflict => write!(formatter, "cache policy conflicts with retained data"),
            Self::LimitExceeded => write!(formatter, "cache resource limit was exceeded"),
            Self::InsufficientSpace => write!(formatter, "private cache storage is full"),
            Self::Corrupt => write!(formatter, "cached metadata or content is corrupt"),
            Self::Io(error) => write!(formatter, "cache file operation failed: {error}"),
            Self::Database(error) => write!(formatter, "cache database operation failed: {error}"),
        }
    }
}

impl std::error::Error for CacheError {}

#[derive(Clone)]
pub struct Cache {
    inner: Arc<Inner>,
}

struct Inner {
    root: PathBuf,
    content_dir: PathBuf,
    db: Mutex<DbOwner>,
    quota_bytes: u64,
    #[cfg(windows)]
    windows_content: windows_blob::WindowsBlobStore,
    #[cfg(windows)]
    windows_root: raiun_control_windows::PrivateDirectory,
}

enum PinGenerationLease<'a> {
    #[cfg(not(windows))]
    Portable { _file: File, _cache: &'a Cache },
    #[cfg(windows)]
    Windows {
        _file: raiun_control_windows::PinnedPrivateFile<'a>,
    },
}

impl Cache {
    /// Opens a dedicated private cache beneath a trusted per-account state
    /// directory. Existing directories are validated and never chmodded.
    pub fn open(state_dir: &Path, quota_bytes: u64) -> Result<Self, CacheError> {
        #[cfg(windows)]
        {
            Self::open_windows(state_dir, quota_bytes)
        }
        #[cfg(not(windows))]
        {
            if !private_permissions_supported() {
                return Err(CacheError::UnsafeDirectory);
            }
            validate_private_dir(state_dir)?;
            let root = state_dir.join("cache-v1");
            match fs::create_dir(&root) {
                Ok(()) => set_private_dir(&root)?,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(CacheError::Io(error.to_string())),
            }
            validate_private_dir(&root)?;
            let content_dir = root.join(CONTENT_DIR);
            match fs::create_dir(&content_dir) {
                Ok(()) => set_private_dir(&content_dir)?,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(CacheError::Io(error.to_string())),
            }
            validate_private_dir(&content_dir)?;
            let db_path = root.join(DB_FILE);
            prepare_db_file(&db_path)?;
            let db = Connection::open(&db_path).map_err(db_error)?;
            schema::initialize(&db, schema::JournalMode::Wal)?;
            let cache = Self {
                inner: Arc::new(Inner {
                    root,
                    content_dir,
                    db: Mutex::new(DbOwner::Portable(db)),
                    quota_bytes,
                }),
            };
            cache.remove_unindexed_content()?;
            Ok(cache)
        }
    }

    pub fn root(&self) -> &Path {
        &self.inner.root
    }

    /// Resolve the unique previously verified plaintext scope for an account,
    /// origin, and Space. Multiple historical roots are ambiguous and fail
    /// closed; callers must never choose one based on path/name similarity.
    pub fn find_plaintext_scope(
        &self,
        origin: &str,
        account_id: &str,
        space_id: &str,
    ) -> Result<Option<CacheScope>, CacheError> {
        let db = self.lock_db()?;
        let mut statement = db
            .prepare("SELECT root_resource_id FROM scopes WHERE origin=?1 AND account_id=?2 AND space_id=?3 AND protection=?4")
            .map_err(db_error)?;
        let roots = statement
            .query_map(
                params![
                    Url::parse(origin)
                        .map_err(|_| CacheError::InvalidScope)?
                        .origin()
                        .ascii_serialization(),
                    account_id,
                    space_id,
                    ScopeProtection::PlaintextAllowed as i64
                ],
                |row| row.get::<_, String>(0),
            )
            .map_err(db_error)?
            .collect::<Result<BTreeSet<_>, _>>()
            .map_err(db_error)?;
        match roots.len() {
            0 => Ok(None),
            1 => roots
                .iter()
                .next()
                .map(|root| {
                    CacheScope::new(
                        origin,
                        account_id,
                        space_id,
                        root,
                        ScopeProtection::PlaintextAllowed,
                    )
                })
                .transpose(),
            _ => Err(CacheError::Conflict),
        }
    }

    /// Look up a directory identity from the most recently published complete
    /// parent listing. The root identity is supplied by the verified scope.
    pub fn resource_id_for_path(
        &self,
        scope: &CacheScope,
        path: &str,
    ) -> Result<Option<String>, CacheError> {
        if path == "/" {
            return Ok(Some(scope.root_resource_id.clone()));
        }
        validate_path(path)?;
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let mut statement = db
            .prepare("SELECT DISTINCT e.resource_id FROM listing_entries e JOIN listings l ON l.scope_key=e.scope_key AND l.parent_id=e.parent_id AND l.generation=e.generation WHERE e.scope_key=?1 AND e.path=?2 AND e.directory=1 AND l.complete=1")
            .map_err(db_error)?;
        let ids = statement
            .query_map(params![scope.key, path], |row| row.get::<_, String>(0))
            .map_err(db_error)?
            .collect::<Result<BTreeSet<_>, _>>()
            .map_err(db_error)?;
        match ids.len() {
            0 => Ok(None),
            1 => Ok(ids.into_iter().next()),
            _ => Err(CacheError::Conflict),
        }
    }

    /// Resolve an exact path from a complete cached parent snapshot. Ambiguous
    /// stale copies (for example, after an unobserved move) are not selected.
    pub fn entry_for_path(
        &self,
        scope: &CacheScope,
        path: &str,
    ) -> Result<Option<RemoteEntry>, CacheError> {
        if path == "/" {
            return Ok(None);
        }
        validate_path(path)?;
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let mut statement = db
            .prepare("SELECT DISTINCT e.resource_id,e.name,e.path,e.etag,e.size,e.directory,e.modified,e.writable,e.encrypted FROM listing_entries e JOIN listings l ON l.scope_key=e.scope_key AND l.parent_id=e.parent_id AND l.generation=e.generation WHERE e.scope_key=?1 AND e.path=?2 AND l.complete=1")
            .map_err(db_error)?;
        let entries = statement
            .query_map(params![scope.key, path], |row| {
                Ok(RemoteEntry {
                    id: row.get(0)?,
                    path: row.get(2)?,
                    etag: row.get(3)?,
                    size: u64::try_from(row.get::<_, i64>(4)?).unwrap_or(u64::MAX),
                    directory: row.get::<_, i64>(5)? != 0,
                    modified_unix: row.get(6)?,
                    writable: row.get::<_, i64>(7)? != 0,
                    encrypted: row.get::<_, i64>(8)? != 0,
                })
            })
            .map_err(db_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_error)?;
        match entries.as_slice() {
            [] => Ok(None),
            [entry] => Ok(Some(entry.clone())),
            _ => Err(CacheError::Conflict),
        }
    }

    /// Invalidate complete listings that could expose any of these paths or
    /// their descendants after a provider mutation. Content and pin records
    /// are retained; affected pins are marked stale so old snapshot bytes are
    /// never silently represented as the current remote tree.
    pub fn invalidate_paths(
        &self,
        scope: &CacheScope,
        paths: &[&str],
    ) -> Result<usize, CacheError> {
        if scope.protection == ScopeProtection::CiphertextOnly {
            return Err(CacheError::ProtectionMismatch);
        }
        if paths.is_empty() || paths.len() > 16 {
            return Err(CacheError::LimitExceeded);
        }
        let mut targets = BTreeSet::new();
        for path in paths {
            validate_path(path)?;
            targets.insert(*path);
        }

        let db = self.lock_db()?;
        // The caller resolved this exact live root identity before mutation.
        // Register it here so first-time mutations can invalidate safely too.
        register_scope(&db, scope)?;
        let tx = db.unchecked_transaction().map_err(db_error)?;
        let mut parent_ids = BTreeSet::new();
        for path in &targets {
            if *path == "/" {
                let mut statement = tx
                    .prepare("SELECT parent_id FROM listings WHERE scope_key=?1")
                    .map_err(db_error)?;
                parent_ids.extend(
                    statement
                        .query_map([&scope.key], |row| row.get::<_, String>(0))
                        .map_err(db_error)?
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(db_error)?,
                );
                parent_ids.insert(scope.root_resource_id.clone());
                continue;
            }

            let parent_path = path
                .rsplit_once('/')
                .map(|(parent, _)| if parent.is_empty() { "/" } else { parent })
                .ok_or(CacheError::InvalidEntry)?;
            if parent_path == "/" {
                parent_ids.insert(scope.root_resource_id.clone());
            } else {
                let mut statement = tx
                    .prepare("SELECT DISTINCT e.resource_id FROM listing_entries e JOIN listings l ON l.scope_key=e.scope_key AND l.parent_id=e.parent_id AND l.generation=e.generation WHERE e.scope_key=?1 AND e.path=?2 AND e.directory=1 AND l.complete=1")
                    .map_err(db_error)?;
                parent_ids.extend(
                    statement
                        .query_map(params![scope.key, parent_path], |row| {
                            row.get::<_, String>(0)
                        })
                        .map_err(db_error)?
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(db_error)?,
                );
            }

            let descendant_prefix = format!("{path}/");
            let mut statement = tx
                .prepare("SELECT DISTINCT e.parent_id,e.resource_id,e.directory FROM listing_entries e JOIN listings l ON l.scope_key=e.scope_key AND l.parent_id=e.parent_id AND l.generation=e.generation WHERE e.scope_key=?1 AND l.complete=1 AND (e.path=?2 OR substr(e.path,1,length(?3))=?3)")
                .map_err(db_error)?;
            let rows = statement
                .query_map(params![scope.key, path, descendant_prefix], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)? != 0,
                    ))
                })
                .map_err(db_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(db_error)?;
            for (listing_parent, resource_id, directory) in rows {
                parent_ids.insert(listing_parent);
                if directory {
                    parent_ids.insert(resource_id);
                }
            }
        }

        let changed_pins = tx
            .execute(
                "UPDATE pins SET state=2 WHERE scope_key=?1 AND state<>2",
                [&scope.key],
            )
            .map_err(db_error)?;
        // A mutation of one file must not make every unrelated offline file
        // stale. Paths and IDs from the affected cached subtree are both fenced;
        // complete listing invalidation below still gates offline reachability.
        for path in &targets {
            let prefix = format!("{path}/");
            tx.execute(
                "UPDATE policies SET target_state=1 WHERE scope_key=?1 AND policy=1 AND target_state=0 AND (?2='/' OR target_path=?2 OR substr(target_path,1,length(?3))=?3 OR resource_id IN (SELECT e.resource_id FROM listing_entries e JOIN listings l ON l.scope_key=e.scope_key AND l.parent_id=e.parent_id AND l.generation=e.generation WHERE e.scope_key=?1 AND l.complete=1 AND (e.path=?2 OR substr(e.path,1,length(?3))=?3)))",
                params![scope.key, path, prefix],
            )
            .map_err(db_error)?;
        }
        for parent_id in parent_ids {
            tx.execute(
                "DELETE FROM listing_entries WHERE scope_key=?1 AND parent_id=?2",
                params![scope.key, parent_id],
            )
            .map_err(db_error)?;
            tx.execute(
                "DELETE FROM listings WHERE scope_key=?1 AND parent_id=?2",
                params![scope.key, parent_id],
            )
            .map_err(db_error)?;
        }
        tx.commit().map_err(db_error)?;
        Ok(changed_pins)
    }

    /// Returns the durable generation for an exact encrypted cache scope.
    /// Callers capture this before network reads and pass it to ciphertext
    /// publication so a response started before invalidation cannot be
    /// published afterward.
    pub fn ciphertext_epoch(&self, scope: &CacheScope) -> Result<u64, CacheError> {
        require_ciphertext_scope(scope)?;
        let db = self.lock_db()?;
        register_scope(&db, scope)?;
        let epoch = ensure_ciphertext_epoch(&db, scope)?;
        u64::try_from(epoch).map_err(|_| CacheError::Corrupt)
    }

    /// Best-effort disk-space preflight for a bounded ciphertext publication.
    /// The subsequent write still handles ENOSPC because other processes may
    /// consume space after this check.
    pub fn preflight_ciphertext_space(&self, required_bytes: u64) -> Result<(), CacheError> {
        if required_bytes > MAX_CONTENT_BYTES {
            return Err(CacheError::LimitExceeded);
        }
        let available = fs2::available_space(&self.inner.content_dir).map_err(io_error)?;
        if available < required_bytes {
            return Err(CacheError::InsufficientSpace);
        }
        Ok(())
    }

    /// Allocate an opaque revision ticket for a new or existing encrypted
    /// write. Publication uses compare-and-swap on `expected_revision`, so a
    /// slow older encrypt cannot replace a newer durable edit.
    pub fn begin_ciphertext_write(
        &self,
        scope: &CacheScope,
        existing_id: Option<&str>,
        encrypted_target: &str,
        plaintext_len: u64,
    ) -> Result<CiphertextWriteBuild, CacheError> {
        self.begin_ciphertext_operation(
            scope,
            existing_id,
            encrypted_target,
            plaintext_len,
            CiphertextWriteOperation::Overwrite,
        )
    }

    /// Allocate a revision for an encrypted operation. The cache stores only
    /// the operation class and hashes of its encrypted target/parent. All
    /// logical names and base validators remain in the authenticated envelope.
    pub fn begin_ciphertext_operation(
        &self,
        scope: &CacheScope,
        existing_id: Option<&str>,
        encrypted_target: &str,
        plaintext_len: u64,
        operation: CiphertextWriteOperation,
    ) -> Result<CiphertextWriteBuild, CacheError> {
        self.begin_ciphertext_operation_with_state(
            scope,
            existing_id,
            encrypted_target,
            plaintext_len,
            operation,
            CiphertextWriteState::Pending,
        )
    }

    /// Allocate a revision with an explicit lifecycle state. `Building` is
    /// reserved for an initial CREATE working copy before its first flush;
    /// retryable states are published only after a complete immutable body is
    /// available.
    pub fn begin_ciphertext_operation_with_state(
        &self,
        scope: &CacheScope,
        existing_id: Option<&str>,
        encrypted_target: &str,
        plaintext_len: u64,
        operation: CiphertextWriteOperation,
        publish_state: CiphertextWriteState,
    ) -> Result<CiphertextWriteBuild, CacheError> {
        self.begin_ciphertext_operation_with_state_and_parent(
            scope,
            existing_id,
            encrypted_target,
            None,
            plaintext_len,
            operation,
            publish_state,
        )
    }

    /// Variant used by path-moving operations whose overlay parent differs
    /// from the indexed source target. The override is an encrypted DAV path;
    /// only its digest is persisted outside the sealed operation envelope.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_ciphertext_operation_with_state_and_parent(
        &self,
        scope: &CacheScope,
        existing_id: Option<&str>,
        encrypted_target: &str,
        encrypted_parent_for_index: Option<&str>,
        plaintext_len: u64,
        operation: CiphertextWriteOperation,
        publish_state: CiphertextWriteState,
    ) -> Result<CiphertextWriteBuild, CacheError> {
        self.begin_ciphertext_operation_with_state_parent_ref(
            scope,
            existing_id,
            encrypted_target,
            encrypted_parent_for_index,
            None,
            plaintext_len,
            operation,
            publish_state,
        )
    }

    /// Allocate a revision with an authenticated parent operation dependency.
    /// The cache stores only a keyed-format digest of the opaque parent id and
    /// revision; names and remote identifiers remain in the sealed envelope.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_ciphertext_operation_with_state_parent_ref(
        &self,
        scope: &CacheScope,
        existing_id: Option<&str>,
        encrypted_target: &str,
        encrypted_parent_for_index: Option<&str>,
        parent_operation: Option<(&str, u64)>,
        plaintext_len: u64,
        operation: CiphertextWriteOperation,
        publish_state: CiphertextWriteState,
    ) -> Result<CiphertextWriteBuild, CacheError> {
        require_ciphertext_scope(scope)?;
        if plaintext_len > MAX_CONTENT_BYTES {
            return Err(CacheError::LimitExceeded);
        }
        if publish_state == CiphertextWriteState::Building
            && operation != CiphertextWriteOperation::CreateFile
        {
            return Err(CacheError::Conflict);
        }
        if publish_state == CiphertextWriteState::CommittedReceipt
            && operation != CiphertextWriteOperation::CreateDirectory
        {
            return Err(CacheError::Conflict);
        }
        if publish_state == CiphertextWriteState::AcknowledgedReceipt {
            // Acknowledgement compaction has a dedicated CAS builder below;
            // general operation callers must not mint terminal receipts.
            return Err(CacheError::Conflict);
        }
        if matches!(
            publish_state,
            CiphertextWriteState::NeverAttempted | CiphertextWriteState::Attempting
        ) && !matches!(
            operation,
            CiphertextWriteOperation::CreateDirectory
                | CiphertextWriteOperation::CreateFile
                | CiphertextWriteOperation::CopyFile
        ) {
            return Err(CacheError::Conflict);
        }
        let target_key = ciphertext_target_key(encrypted_target)?;
        let parent_key = match encrypted_parent_for_index {
            Some(parent) => ciphertext_parent_path_key(parent)?,
            None => ciphertext_parent_key(encrypted_target)?,
        };
        let parent_operation_key = parent_operation
            .map(|(id, revision)| ciphertext_operation_key(id, revision))
            .transpose()?
            .unwrap_or_default();
        let db = self.lock_db()?;
        register_scope(&db, scope)?;
        if existing_id.is_none() && !parent_operation_key.is_empty() {
            let parent_available: bool = db
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM ciphertext_writes WHERE scope_key=?1 AND dependency_key=?2 AND operation=?3 AND state IN (?4,?5,?6,?7,?8))",
                    params![scope.key, parent_operation_key, CiphertextWriteOperation::CreateDirectory as i64, CiphertextWriteState::Pending as i64, CiphertextWriteState::Uncertain as i64, CiphertextWriteState::CommittedReceipt as i64, CiphertextWriteState::NeverAttempted as i64, CiphertextWriteState::Attempting as i64],
                    |row| row.get(0),
                )
                .map_err(db_error)?;
            if !parent_available {
                return Err(CacheError::Conflict);
            }
        }
        let (id, expected_revision, dependency_key) = if let Some(id) = existing_id {
            validate_ciphertext_write_id(id)?;
            let row: Option<(i64, String, i64, String, String, String, i64)> = db
                .query_row(
                    "SELECT revision,target_key,operation,parent_key,parent_operation_key,dependency_key,state FROM ciphertext_writes WHERE scope_key=?1 AND write_id=?2",
                    params![scope.key, id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
                )
                .optional()
                .map_err(db_error)?;
            let (
                revision,
                current_target,
                current_operation,
                current_parent,
                current_parent_operation,
                dependency_key,
                current_state,
            ) = row.ok_or(CacheError::NotFound)?;
            if matches!(
                decode_ciphertext_write_state(current_state)?,
                CiphertextWriteState::CancelledReceipt | CiphertextWriteState::AcknowledgedReceipt
            ) {
                return Err(CacheError::Conflict);
            }
            let verified_receipt_rebind = publish_state == CiphertextWriteState::CommittedReceipt
                && operation == CiphertextWriteOperation::CreateDirectory
                && parent_operation_key.is_empty()
                && !current_parent_operation.is_empty();
            if current_target != target_key
                || decode_ciphertext_write_operation(current_operation)? != operation
                || (!current_parent.is_empty() && current_parent != parent_key)
                || (!current_parent_operation.is_empty()
                    && current_parent_operation != parent_operation_key
                    && !verified_receipt_rebind)
            {
                return Err(CacheError::Conflict);
            }
            let dependency_key = if dependency_key.is_empty() {
                ciphertext_operation_key(id, 1)?
            } else {
                dependency_key
            };
            (id.to_owned(), Some(revision), dependency_key)
        } else {
            let target_exists: bool = db
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM ciphertext_writes WHERE scope_key=?1 AND target_key=?2)",
                    params![scope.key, target_key],
                    |row| row.get(0),
                )
                .map_err(db_error)?;
            if target_exists {
                return Err(CacheError::Conflict);
            }
            let count: i64 = db
                .query_row(
                    "SELECT COUNT(*) FROM ciphertext_writes WHERE scope_key=?1",
                    [&scope.key],
                    |row| row.get(0),
                )
                .map_err(db_error)?;
            if count < 0 || count as usize >= MAX_CIPHERTEXT_WRITES {
                return Err(CacheError::LimitExceeded);
            }
            if matches!(
                operation,
                CiphertextWriteOperation::CreateFile
                    | CiphertextWriteOperation::DeleteFile
                    | CiphertextWriteOperation::CreateDirectory
            ) {
                let parent_count: i64 = db
                    .query_row(
                        "SELECT COUNT(*) FROM ciphertext_writes WHERE scope_key=?1 AND parent_key=?2 AND operation=?3",
                        params![scope.key, parent_key, operation as i64],
                        |row| row.get(0),
                    )
                    .map_err(db_error)?;
                if parent_count < 0 || parent_count as usize >= MAX_CIPHERTEXT_WRITES_PER_PARENT {
                    return Err(CacheError::LimitExceeded);
                }
            }
            let mut random = [0u8; 16];
            getrandom::fill(&mut random)
                .map_err(|_| CacheError::Io("secure random generation failed".into()))?;
            let id = random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let dependency_key = ciphertext_operation_key(&id, 1)?;
            (id, None, dependency_key)
        };
        let revision = expected_revision
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(CacheError::LimitExceeded)?;
        Ok(CiphertextWriteBuild {
            id,
            revision: u64::try_from(revision).map_err(|_| CacheError::LimitExceeded)?,
            target_key,
            plaintext_len,
            operation,
            publish_state,
            parent_key,
            parent_operation_key,
            dependency_key,
            expected_revision: expected_revision
                .map(|revision| u64::try_from(revision).map_err(|_| CacheError::Corrupt))
                .transpose()?,
            scope_key: scope.key.clone(),
            root_resource_id: scope.root_resource_id.clone(),
            expected_target_key: None,
            expected_state: None,
            content_etag: None,
        })
    }

    /// Prepare a compact terminal cancellation receipt. Only a precise
    /// CancelledReceipt CreateFile row can transition; ordinary queue APIs
    /// cannot manufacture this state.
    pub fn begin_ciphertext_cancel_ack_compaction(
        &self,
        scope: &CacheScope,
        id: &str,
        expected_revision: u64,
        encrypted_target: &str,
    ) -> Result<CiphertextWriteBuild, CacheError> {
        require_ciphertext_scope(scope)?;
        validate_ciphertext_write_id(id)?;
        if expected_revision == 0 || expected_revision >= i64::MAX as u64 {
            return Err(CacheError::LimitExceeded);
        }
        let target_key = ciphertext_target_key(encrypted_target)?;
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let row: Option<(i64, String, i64, i64, String, String, String)> = db
            .query_row(
                "SELECT revision,target_key,operation,state,parent_key,parent_operation_key,dependency_key FROM ciphertext_writes WHERE scope_key=?1 AND write_id=?2",
                params![scope.key, id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
            )
            .optional()
            .map_err(db_error)?;
        let Some((
            revision,
            current_target,
            operation,
            state,
            parent_key,
            parent_operation_key,
            dependency_key,
        )) = row
        else {
            return Err(CacheError::NotFound);
        };
        if revision != i64_from_u64(expected_revision)?
            || current_target != target_key
            || decode_ciphertext_write_operation(operation)? != CiphertextWriteOperation::CreateFile
            || decode_ciphertext_write_state(state)? != CiphertextWriteState::CancelledReceipt
        {
            return Err(CacheError::Conflict);
        }
        let dependency_key = if dependency_key.is_empty() {
            ciphertext_operation_key(id, 1)?
        } else {
            dependency_key
        };
        Ok(CiphertextWriteBuild {
            id: id.to_owned(),
            revision: expected_revision + 1,
            expected_revision: Some(expected_revision),
            target_key: current_target.clone(),
            plaintext_len: 0,
            operation: CiphertextWriteOperation::CreateFile,
            publish_state: CiphertextWriteState::AcknowledgedReceipt,
            parent_key,
            parent_operation_key,
            dependency_key,
            scope_key: scope.key.clone(),
            root_resource_id: scope.root_resource_id.clone(),
            expected_target_key: Some(current_target),
            expected_state: Some(CiphertextWriteState::CancelledReceipt),
            content_etag: None,
        })
    }

    /// Prepare an atomic target/parent rebind for a local create operation
    /// that is provably new and has never been dispatched. Legacy Pending
    /// rows are intentionally not eligible: before NeverAttempted existed,
    /// Pending could already have reached the server.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_ciphertext_never_attempted_create_retarget(
        &self,
        scope: &CacheScope,
        id: &str,
        expected_revision: u64,
        old_encrypted_target: &str,
        new_encrypted_target: &str,
        new_encrypted_parent: Option<&str>,
        new_parent_operation: Option<(&str, u64)>,
        plaintext_len: u64,
    ) -> Result<CiphertextWriteBuild, CacheError> {
        self.begin_ciphertext_never_attempted_operation_retarget(
            scope,
            CiphertextWriteOperation::CreateFile,
            id,
            expected_revision,
            old_encrypted_target,
            new_encrypted_target,
            new_encrypted_parent,
            new_parent_operation,
            plaintext_len,
        )
    }

    /// Directory-create variant of the never-attempted retarget CAS. A
    /// directory's dependency key advances with its revision so a child that
    /// registered against the old parent generation cannot become a child of
    /// the moved directory. The no-child check and target/index update are
    /// repeated during publication in the same database transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_ciphertext_never_attempted_operation_retarget(
        &self,
        scope: &CacheScope,
        requested_operation: CiphertextWriteOperation,
        id: &str,
        expected_revision: u64,
        old_encrypted_target: &str,
        new_encrypted_target: &str,
        new_encrypted_parent: Option<&str>,
        new_parent_operation: Option<(&str, u64)>,
        plaintext_len: u64,
    ) -> Result<CiphertextWriteBuild, CacheError> {
        require_ciphertext_scope(scope)?;
        validate_ciphertext_write_id(id)?;
        if expected_revision == 0
            || expected_revision >= i64::MAX as u64
            || plaintext_len > MAX_CONTENT_BYTES
            || !matches!(
                requested_operation,
                CiphertextWriteOperation::CreateFile | CiphertextWriteOperation::CreateDirectory
            )
        {
            return Err(CacheError::LimitExceeded);
        }
        let old_target_key = ciphertext_target_key(old_encrypted_target)?;
        let target_key = ciphertext_target_key(new_encrypted_target)?;
        if old_target_key == target_key {
            return Err(CacheError::Conflict);
        }
        let parent_key = match new_encrypted_parent {
            Some(parent) => ciphertext_parent_path_key(parent)?,
            None => ciphertext_parent_key(new_encrypted_target)?,
        };
        let parent_operation_key = new_parent_operation
            .map(|(parent_id, revision)| ciphertext_operation_key(parent_id, revision))
            .transpose()?
            .unwrap_or_default();

        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let row: Option<(i64, String, i64, i64, String)> = db
            .query_row(
                "SELECT revision,target_key,operation,state,dependency_key FROM ciphertext_writes WHERE scope_key=?1 AND write_id=?2",
                params![scope.key, id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .optional()
            .map_err(db_error)?;
        let (revision, current_target, current_operation, state, current_dependency_key) =
            row.ok_or(CacheError::NotFound)?;
        if revision != i64_from_u64(expected_revision)?
            || current_target != old_target_key
            || decode_ciphertext_write_operation(current_operation)? != requested_operation
            || decode_ciphertext_write_state(state)? != CiphertextWriteState::NeverAttempted
        {
            return Err(CacheError::Conflict);
        }
        let has_children: bool = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM ciphertext_writes WHERE scope_key=?1 AND parent_operation_key=?2)",
                params![scope.key, current_dependency_key],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if has_children {
            return Err(CacheError::Conflict);
        }
        let target_exists: bool = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM ciphertext_writes WHERE scope_key=?1 AND target_key=?2 AND write_id<>?3)",
                    params![scope.key, target_key, id],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if target_exists {
            return Err(CacheError::Conflict);
        }
        if !parent_operation_key.is_empty() {
            let parent_available: bool = db
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM ciphertext_writes WHERE scope_key=?1 AND dependency_key=?2 AND operation=?3 AND state IN (?4,?5,?6,?7,?8))",
                    params![scope.key,parent_operation_key,CiphertextWriteOperation::CreateDirectory as i64,CiphertextWriteState::Pending as i64,CiphertextWriteState::Uncertain as i64,CiphertextWriteState::CommittedReceipt as i64,CiphertextWriteState::NeverAttempted as i64,CiphertextWriteState::Attempting as i64],
                    |row| row.get(0),
                )
                .map_err(db_error)?;
            if !parent_available {
                return Err(CacheError::Conflict);
            }
        }
        let parent_count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM ciphertext_writes WHERE scope_key=?1 AND parent_key=?2 AND operation=?3 AND write_id<>?4",
                params![scope.key,parent_key,requested_operation as i64,id],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if parent_count < 0 || parent_count as usize >= MAX_CIPHERTEXT_WRITES_PER_PARENT {
            return Err(CacheError::LimitExceeded);
        }
        Ok(CiphertextWriteBuild {
            id: id.to_owned(),
            revision: expected_revision + 1,
            expected_revision: Some(expected_revision),
            target_key,
            plaintext_len,
            operation: requested_operation,
            publish_state: CiphertextWriteState::NeverAttempted,
            parent_key,
            parent_operation_key,
            dependency_key: if requested_operation == CiphertextWriteOperation::CreateDirectory {
                ciphertext_operation_key(id, expected_revision + 1)?
            } else {
                current_dependency_key
            },
            scope_key: scope.key.clone(),
            root_resource_id: scope.root_resource_id.clone(),
            expected_target_key: Some(old_target_key),
            expected_state: Some(CiphertextWriteState::NeverAttempted),
            content_etag: None,
        })
    }

    /// Prepare a bounded all-or-none retarget for every operation below one
    /// queued directory. The caller supplies the complete, authenticated
    /// logical subtree after decrypting its envelopes; this method repeats
    /// the dependency-closure, state, revision, and target checks against the
    /// opaque SQLite index. Publication repeats them under one transaction.
    pub fn begin_ciphertext_never_attempted_subtree_retarget(
        &self,
        scope: &CacheScope,
        root_id: &str,
        root_revision: u64,
        members: &[CiphertextSubtreeRetarget],
    ) -> Result<Vec<CiphertextWriteBuild>, CacheError> {
        require_ciphertext_scope(scope)?;
        validate_ciphertext_write_id(root_id)?;
        if members.is_empty() || members.len() > 64 || root_revision == 0 {
            return Err(CacheError::LimitExceeded);
        }
        let mut ids = BTreeSet::new();
        let mut target_keys = BTreeSet::new();
        let mut builds = Vec::with_capacity(members.len());
        let mut member_by_id = BTreeMap::new();
        for member in members {
            validate_ciphertext_write_id(&member.id)?;
            if member.expected_revision == 0
                || member.expected_revision >= i64::MAX as u64
                || member.plaintext_len > 64 * 1024 * 1024
                || !matches!(
                    member.operation,
                    CiphertextWriteOperation::CreateFile
                        | CiphertextWriteOperation::CreateDirectory
                )
                || !ids.insert(member.id.as_str())
            {
                return Err(CacheError::InvalidScope);
            }
            let target_key = ciphertext_target_key(&member.new_target)?;
            if !target_keys.insert(target_key.clone()) {
                return Err(CacheError::Conflict);
            }
            let parent_key = ciphertext_parent_path_key(&member.new_parent_path)?;
            let parent_operation_key = member
                .new_parent_operation
                .as_ref()
                .map(|(id, revision)| ciphertext_operation_key(id, *revision))
                .transpose()?
                .unwrap_or_default();
            let next_revision = member.expected_revision + 1;
            let dependency_key = if member.operation == CiphertextWriteOperation::CreateDirectory {
                ciphertext_operation_key(&member.id, next_revision)?
            } else {
                // File creates are leaves. Their old dependency key is retained
                // for validation and their parent binding is updated below.
                String::new()
            };
            let current_dependency_key = {
                let db = self.lock_db()?;
                validate_registered_scope(&db, scope)?;
                db.query_row(
                    "SELECT dependency_key FROM ciphertext_writes WHERE scope_key=?1 AND write_id=?2",
                    params![scope.key, member.id],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(db_error)?
                .ok_or(CacheError::NotFound)?
            };
            let dependency_key = if dependency_key.is_empty() {
                current_dependency_key
            } else {
                dependency_key
            };
            let build = CiphertextWriteBuild {
                id: member.id.clone(),
                revision: next_revision,
                expected_revision: Some(member.expected_revision),
                target_key,
                plaintext_len: member.plaintext_len,
                operation: member.operation,
                publish_state: CiphertextWriteState::NeverAttempted,
                parent_key,
                parent_operation_key,
                dependency_key,
                scope_key: scope.key.clone(),
                root_resource_id: scope.root_resource_id.clone(),
                expected_target_key: Some(ciphertext_target_key(&member.expected_target)?),
                expected_state: Some(CiphertextWriteState::NeverAttempted),
                content_etag: Some(unique_ciphertext_retarget_etag(next_revision)?),
            };
            validate_ciphertext_write_build(scope, &build)?;
            member_by_id.insert(member.id.as_str(), member);
            builds.push(build);
        }
        if !member_by_id.contains_key(root_id)
            || member_by_id[root_id].operation != CiphertextWriteOperation::CreateDirectory
            || member_by_id[root_id].expected_revision != root_revision
        {
            return Err(CacheError::Conflict);
        }
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        validate_ciphertext_subtree_retarget_db(&db, scope, members, &builds, root_id)?;
        Ok(builds)
    }

    /// Publish all encrypted retargeted revisions as one SQLite transaction.
    /// Blob files are immutable and may be left as inaccessible orphans by a
    /// process crash before commit; journal rows are switched together, so a
    /// reader can observe only the complete old or complete new subtree.
    pub fn publish_ciphertext_subtree_retarget(
        &self,
        scope: &CacheScope,
        builds: &[CiphertextWriteBuild],
        contents: &mut [CiphertextSubtreeRetargetContent<'_>],
        root_id: &str,
    ) -> Result<Vec<CiphertextWriteInfo>, CacheError> {
        self.publish_ciphertext_subtree_retarget_with_ack(scope, builds, contents, root_id, || {
            Ok(())
        })
    }

    // Per-call injection models a lost commit acknowledgement without a global
    // failpoint that could affect concurrent publications.
    fn publish_ciphertext_subtree_retarget_with_ack(
        &self,
        scope: &CacheScope,
        builds: &[CiphertextWriteBuild],
        contents: &mut [CiphertextSubtreeRetargetContent<'_>],
        root_id: &str,
        acknowledge_commit: impl FnOnce() -> Result<(), CacheError>,
    ) -> Result<Vec<CiphertextWriteInfo>, CacheError> {
        #[cfg(windows)]
        let windows_store = Some(&self.inner.windows_content);
        #[cfg(windows)]
        let windows_lease = windows_store
            .map(|store| store.publication_lease())
            .transpose()?;
        #[cfg(windows)]
        let _publication_lease = if windows_store.is_some() {
            None
        } else {
            Some(self.lock_content_publication()?)
        };
        #[cfg(not(windows))]
        let _publication_lease = self.lock_content_publication()?;
        #[cfg(windows)]
        let mut windows_receipts = Vec::new();
        require_ciphertext_scope(scope)?;
        validate_ciphertext_write_id(root_id)?;
        if builds.is_empty() || builds.len() != contents.len() || builds.len() > 64 {
            return Err(CacheError::LimitExceeded);
        }
        let mut ids = BTreeSet::new();
        let mut total_bytes = 0u64;
        for (build, content) in builds.iter().zip(contents.iter()) {
            validate_ciphertext_write_build(scope, build)?;
            if !ids.insert(build.id.as_str())
                || content.build.id != build.id
                || content.expected_len > 64 * 1024 * 1024
            {
                return Err(CacheError::InvalidScope);
            }
            total_bytes = total_bytes
                .checked_add(content.expected_len)
                .filter(|bytes| *bytes <= 64 * 1024 * 1024)
                .ok_or(CacheError::LimitExceeded)?;
        }
        if !ids.contains(root_id) {
            return Err(CacheError::Conflict);
        }
        if !self.has_windows_content() {
            self.preflight_ciphertext_space(total_bytes)?;
        }

        let mut staged: Vec<(String, ContentVersion, PathBuf, u64, String, bool)> =
            Vec::with_capacity(builds.len());
        for content in contents.iter_mut() {
            let version = content.build.content_version();
            let key = content_key(scope, &version);
            let destination = self.inner.content_dir.join(format!("{key}.blob"));
            #[cfg(windows)]
            let windows_result = match (windows_store, windows_lease.as_ref()) {
                (Some(store), Some(lease)) => Some(
                    store
                        .publish_under_lease(
                            lease,
                            &format!("{key}.blob"),
                            content.source,
                            content.expected_len,
                        )
                        .map(|receipt| {
                            let metadata = (receipt.byte_len, receipt.digest.clone(), false);
                            windows_receipts.push(receipt);
                            metadata
                        }),
                ),
                _ => None,
            };
            #[cfg(not(windows))]
            let windows_result: Option<Result<(u64, String, bool), CacheError>> = None;
            let published = match windows_result {
                Some(result) => result,
                None => write_content_atomically(
                    &self.inner.content_dir,
                    &destination,
                    content.source,
                    content.expected_len,
                ),
            };
            let (byte_len, digest, created) = match published {
                Ok(published) => published,
                Err(error) => {
                    for (_, _, prior_destination, _, _, prior_created) in &staged {
                        if *prior_created {
                            let _ = remove_unreferenced_blob(
                                &self.inner.content_dir,
                                prior_destination,
                            );
                        }
                    }
                    return Err(error);
                }
            };
            staged.push((key, version, destination, byte_len, digest, created));
        }

        let publish_result = (|| {
            let mut db = self.lock_db()?;
            validate_registered_scope(&db, scope)?;
            let tx = db
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(db_error)?;
            validate_ciphertext_subtree_builds_db(&tx, scope, builds, root_id)?;

            // Temporarily release the unique target index so an atomic subtree
            // rename cannot observe an intermediate old/new mix.
            for build in builds {
                tx.execute(
                    "UPDATE ciphertext_writes SET target_key='' WHERE scope_key=?1 AND write_id=?2 AND revision=?3",
                    params![scope.key, build.id, i64_from_u64(build.expected_revision.ok_or(CacheError::Conflict)?)?],
                )
                .map_err(db_error)?;
            }
            let mut result = Vec::with_capacity(builds.len());
            for ((build, (key, version, destination, byte_len, digest, _)), content) in
                builds.iter().zip(staged.iter()).zip(contents.iter())
            {
                tx.execute(
                    "INSERT INTO contents(content_key,scope_key,resource_id,etag,protection,byte_len,sha256,relative_path,last_accessed,retention) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10) ON CONFLICT(content_key) DO UPDATE SET last_accessed=excluded.last_accessed,retention=MAX(contents.retention,excluded.retention)",
                    params![key,scope.key,version.resource_id,version.etag,version.protection as i64,i64_from_u64(*byte_len)?,digest,destination.file_name().and_then(|name| name.to_str()).ok_or(CacheError::Corrupt)?,now_unix(),Retention::Recent as i64],
                ).map_err(db_error)?;
                tx.execute(
                    "INSERT INTO ciphertext_writes(scope_key,write_id,revision,content_key,state,created_at,target_key,plaintext_len,operation,parent_key,parent_operation_key,dependency_key) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12) ON CONFLICT(scope_key,write_id) DO UPDATE SET revision=excluded.revision,content_key=excluded.content_key,state=excluded.state,created_at=excluded.created_at,target_key=excluded.target_key,plaintext_len=excluded.plaintext_len,operation=excluded.operation,parent_key=excluded.parent_key,parent_operation_key=excluded.parent_operation_key,dependency_key=excluded.dependency_key",
                    params![scope.key,build.id,i64_from_u64(build.revision)?,key,build.publish_state as i64,now_unix(),build.target_key,i64_from_u64(build.plaintext_len)?,build.operation as i64,build.parent_key,build.parent_operation_key,build.dependency_key],
                ).map_err(db_error)?;
                result.push(CiphertextWriteInfo {
                    id: build.id.clone(),
                    revision: build.revision,
                    byte_len: *byte_len,
                    state: build.publish_state,
                    target_key: build.target_key.clone(),
                    plaintext_len: build.plaintext_len,
                    operation: build.operation,
                    retry_generation: 0,
                });
                let _ = (digest, content);
            }
            tx.commit().map_err(db_error)?;
            acknowledge_commit()?;
            Ok(result)
        })();

        // A database/commit error can leave durability uncertain. Preserve
        // staged blobs in that case: deleting them could invalidate a journal
        // row that reached disk. Reopen reconciliation can reclaim proven
        // orphans; an extra blob is safer than missing recovery content.
        if publish_result.is_err() && !matches!(&publish_result, Err(CacheError::Database(_))) {
            for (_, _, destination, _, _, created) in &staged {
                if *created {
                    let _ = remove_unreferenced_blob(&self.inner.content_dir, destination);
                }
            }
        }
        publish_result
    }

    /// Publish a fully encrypted immutable revision and atomically swap its
    /// opaque journal reference. Pending journal references survive cache
    /// epoch invalidation and pin removal; only explicit verified retirement
    /// releases them.
    pub fn publish_ciphertext_write<R: Read>(
        &self,
        scope: &CacheScope,
        build: &CiphertextWriteBuild,
        source: &mut R,
        expected_len: u64,
    ) -> Result<CiphertextWriteInfo, CacheError> {
        require_ciphertext_scope(scope)?;
        validate_ciphertext_write_build(scope, build)?;
        let version = build.content_version();
        let record = self.publish_content_internal_with_hook(
            scope,
            &version,
            source,
            expected_len,
            ContentPublishOptions {
                retention: Retention::Recent,
                recent_budget: false,
                require_listed: false,
                expected_ciphertext_epoch: None,
                pin_build: None,
                ciphertext_write: Some(CiphertextWritePublish {
                    id: build.id.clone(),
                    revision: build.revision,
                    expected_revision: build.expected_revision,
                    target_key: build.target_key.clone(),
                    plaintext_len: build.plaintext_len,
                    operation: build.operation,
                    state: build.publish_state,
                    parent_key: build.parent_key.clone(),
                    parent_operation_key: build.parent_operation_key.clone(),
                    dependency_key: build.dependency_key.clone(),
                    expected_target_key: build.expected_target_key.clone(),
                    expected_state: build.expected_state,
                }),
            },
            || {},
        )?;
        Ok(CiphertextWriteInfo {
            id: build.id.clone(),
            revision: build.revision,
            byte_len: record.byte_len,
            state: build.publish_state,
            target_key: build.target_key.clone(),
            plaintext_len: build.plaintext_len,
            operation: build.operation,
            retry_generation: 0,
        })
    }

    pub fn ciphertext_writes(
        &self,
        scope: &CacheScope,
        after: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<CiphertextWriteInfo>, bool), CacheError> {
        require_ciphertext_scope(scope)?;
        if !(1..=100).contains(&limit) {
            return Err(CacheError::LimitExceeded);
        }
        if let Some(after) = after {
            validate_ciphertext_write_id(after)?;
        }
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let rows = {
            let mut statement = db.prepare(
                "SELECT write_id,revision,c.byte_len,w.state,w.target_key,w.plaintext_len,w.operation,w.retry_generation FROM ciphertext_writes w JOIN contents c ON c.content_key=w.content_key WHERE w.scope_key=?1 AND (?2 IS NULL OR write_id>?2) ORDER BY write_id LIMIT ?3",
            ).map_err(db_error)?;
            statement
                .query_map(params![scope.key, after, (limit + 1) as i64], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, i64>(7)?,
                    ))
                })
                .map_err(db_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(db_error)?
        };
        let truncated = rows.len() > limit;
        let items = rows
            .into_iter()
            .take(limit)
            .map(
                |(
                    id,
                    revision,
                    byte_len,
                    state,
                    target_key,
                    plaintext_len,
                    operation,
                    retry_generation,
                )| {
                    Ok(CiphertextWriteInfo {
                        id,
                        revision: u64::try_from(revision).map_err(|_| CacheError::Corrupt)?,
                        byte_len: u64::try_from(byte_len).map_err(|_| CacheError::Corrupt)?,
                        state: decode_ciphertext_write_state(state)?,
                        target_key,
                        plaintext_len: u64::try_from(plaintext_len)
                            .map_err(|_| CacheError::Corrupt)?,
                        operation: decode_ciphertext_write_operation(operation)?,
                        retry_generation: u64::try_from(retry_generation)
                            .map_err(|_| CacheError::Corrupt)?,
                    })
                },
            )
            .collect::<Result<Vec<_>, CacheError>>()?;
        Ok((items, truncated))
    }

    /// List only journal rows that are eligible for a retry. Conflicts stay
    /// visible through `ciphertext_writes`, but never consume a retry page;
    /// this keeps later Pending/Uncertain rows reachable across restarts.
    pub fn retryable_ciphertext_writes(
        &self,
        scope: &CacheScope,
        limit: usize,
    ) -> Result<(Vec<CiphertextWriteInfo>, bool), CacheError> {
        require_ciphertext_scope(scope)?;
        if !(1..=100).contains(&limit) {
            return Err(CacheError::LimitExceeded);
        }
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let rows = {
            let mut statement = db.prepare(
                "SELECT write_id,revision,c.byte_len,w.state,w.target_key,w.plaintext_len,w.operation FROM ciphertext_writes w JOIN contents c ON c.content_key=w.content_key WHERE w.scope_key=?1 AND w.operation BETWEEN 0 AND ?7 AND w.state IN (?2,?3,?4) AND (w.parent_operation_key='' OR EXISTS(SELECT 1 FROM ciphertext_writes p WHERE p.scope_key=w.scope_key AND p.dependency_key=w.parent_operation_key AND p.state=?5 AND p.operation=?6)) ORDER BY write_id LIMIT ?8",
            ).map_err(db_error)?;
            statement
                .query_map(
                    params![
                        scope.key,
                        CiphertextWriteState::Pending as i64,
                        CiphertextWriteState::Uncertain as i64,
                        CiphertextWriteState::NeverAttempted as i64,
                        CiphertextWriteState::CommittedReceipt as i64,
                        CiphertextWriteOperation::CreateDirectory as i64,
                        CiphertextWriteOperation::CreateDirectory as i64,
                        (limit + 1) as i64
                    ],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, i64>(5)?,
                            row.get::<_, i64>(6)?,
                        ))
                    },
                )
                .map_err(db_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(db_error)?
        };
        let truncated = rows.len() > limit;
        let items = rows
            .into_iter()
            .take(limit)
            .map(
                |(id, revision, byte_len, state, target_key, plaintext_len, operation)| {
                    Ok(CiphertextWriteInfo {
                        id,
                        revision: u64::try_from(revision).map_err(|_| CacheError::Corrupt)?,
                        byte_len: u64::try_from(byte_len).map_err(|_| CacheError::Corrupt)?,
                        state: decode_ciphertext_write_state(state)?,
                        target_key,
                        plaintext_len: u64::try_from(plaintext_len)
                            .map_err(|_| CacheError::Corrupt)?,
                        operation: decode_ciphertext_write_operation(operation)?,
                        retry_generation: 0,
                    })
                },
            )
            .collect::<Result<Vec<_>, CacheError>>()?;
        Ok((items, truncated))
    }

    /// Report whether a scope has retryable encrypted-write metadata without
    /// opening content objects or decrypting a journal envelope. Only the
    /// established generic operation codes 0 through CreateDirectory are
    /// eligible; copy, move and unknown future classes require their own
    /// admission/recovery flow and must not enter the generic retry queue.
    pub fn has_retryable_ciphertext_writes(&self, scope: &CacheScope) -> Result<bool, CacheError> {
        require_ciphertext_scope(scope)?;
        let db = self.lock_db()?;
        register_scope(&db, scope)?;
        db.query_row(
            "SELECT EXISTS(SELECT 1 FROM ciphertext_writes w WHERE w.scope_key=?1 AND w.operation BETWEEN 0 AND ?7 AND w.state IN (?2,?3,?4) AND (w.parent_operation_key='' OR EXISTS(SELECT 1 FROM ciphertext_writes p WHERE p.scope_key=w.scope_key AND p.dependency_key=w.parent_operation_key AND p.state=?5 AND p.operation=?6)))",
            params![
                scope.key,
                CiphertextWriteState::Pending as i64,
                CiphertextWriteState::Uncertain as i64,
                CiphertextWriteState::NeverAttempted as i64,
                CiphertextWriteState::CommittedReceipt as i64,
                CiphertextWriteOperation::CreateDirectory as i64,
                CiphertextWriteOperation::CreateDirectory as i64
            ],
            |row| row.get(0),
        )
        .map_err(db_error)
    }

    /// Return direct dependent journal rows for one exact parent operation
    /// generation. This includes blocked children; retry enumeration filters
    /// them until a committed parent receipt exists.
    pub fn ciphertext_operation_children(
        &self,
        scope: &CacheScope,
        parent_id: &str,
        parent_revision: u64,
        after: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<CiphertextWriteInfo>, bool), CacheError> {
        require_ciphertext_scope(scope)?;
        validate_ciphertext_write_id(parent_id)?;
        if !(1..=100).contains(&limit) {
            return Err(CacheError::LimitExceeded);
        }
        if let Some(after) = after {
            validate_ciphertext_write_id(after)?;
        }
        let parent_key = ciphertext_operation_key(parent_id, parent_revision)?;
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let rows = {
            let mut statement = db.prepare(
                "SELECT w.write_id,w.revision,c.byte_len,w.state,w.target_key,w.plaintext_len,w.operation FROM ciphertext_writes w JOIN contents c ON c.content_key=w.content_key WHERE w.scope_key=?1 AND w.parent_operation_key=?2 AND (?3 IS NULL OR w.write_id>?3) ORDER BY w.write_id LIMIT ?4",
            ).map_err(db_error)?;
            statement
                .query_map(
                    params![scope.key, parent_key, after, (limit + 1) as i64],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, i64>(5)?,
                            row.get::<_, i64>(6)?,
                        ))
                    },
                )
                .map_err(db_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(db_error)?
        };
        let truncated = rows.len() > limit;
        let items = rows
            .into_iter()
            .take(limit)
            .map(
                |(id, revision, byte_len, state, target_key, plaintext_len, operation)| {
                    Ok(CiphertextWriteInfo {
                        id,
                        revision: u64::try_from(revision).map_err(|_| CacheError::Corrupt)?,
                        byte_len: u64::try_from(byte_len).map_err(|_| CacheError::Corrupt)?,
                        state: decode_ciphertext_write_state(state)?,
                        target_key,
                        plaintext_len: u64::try_from(plaintext_len)
                            .map_err(|_| CacheError::Corrupt)?,
                        operation: decode_ciphertext_write_operation(operation)?,
                        retry_generation: 0,
                    })
                },
            )
            .collect::<Result<Vec<_>, CacheError>>()?;
        Ok((items, truncated))
    }

    /// Look up an authenticated-receipt candidate for the exact initial
    /// create generation. Callers must still open and authenticate its sealed
    /// metadata before trusting remote identity fields.
    pub fn ciphertext_directory_receipt(
        &self,
        scope: &CacheScope,
        operation_id: &str,
        operation_revision: u64,
    ) -> Result<Option<CiphertextWriteInfo>, CacheError> {
        require_ciphertext_scope(scope)?;
        validate_ciphertext_write_id(operation_id)?;
        let dependency_key = ciphertext_operation_key(operation_id, operation_revision)?;
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let row = db
            .query_row(
                "SELECT w.write_id,w.revision,c.byte_len,w.state,w.target_key,w.plaintext_len,w.operation FROM ciphertext_writes w JOIN contents c ON c.content_key=w.content_key WHERE w.scope_key=?1 AND w.dependency_key=?2 AND w.state=?3 AND w.operation=?4",
                params![scope.key, dependency_key, CiphertextWriteState::CommittedReceipt as i64, CiphertextWriteOperation::CreateDirectory as i64],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?, row.get::<_, i64>(3)?, row.get::<_, String>(4)?, row.get::<_, i64>(5)?, row.get::<_, i64>(6)?)),
            )
            .optional()
            .map_err(db_error)?;
        row.map(
            |(id, revision, byte_len, state, target_key, plaintext_len, operation)| {
                Ok(CiphertextWriteInfo {
                    id,
                    revision: u64::try_from(revision).map_err(|_| CacheError::Corrupt)?,
                    byte_len: u64::try_from(byte_len).map_err(|_| CacheError::Corrupt)?,
                    state: decode_ciphertext_write_state(state)?,
                    target_key,
                    plaintext_len: u64::try_from(plaintext_len).map_err(|_| CacheError::Corrupt)?,
                    operation: decode_ciphertext_write_operation(operation)?,
                    retry_generation: 0,
                })
            },
        )
        .transpose()
    }

    pub fn ciphertext_write_info(
        &self,
        scope: &CacheScope,
        id: &str,
    ) -> Result<CiphertextWriteInfo, CacheError> {
        require_ciphertext_scope(scope)?;
        validate_ciphertext_write_id(id)?;
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let row: Option<(i64, i64, i64, String, i64, i64, i64)> = db
            .query_row(
                "SELECT revision,c.byte_len,w.state,w.target_key,w.plaintext_len,w.operation,w.retry_generation FROM ciphertext_writes w JOIN contents c ON c.content_key=w.content_key WHERE w.scope_key=?1 AND w.write_id=?2",
                params![scope.key, id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .optional()
            .map_err(db_error)?;
        let (revision, byte_len, state, target_key, plaintext_len, operation, retry_generation) =
            row.ok_or(CacheError::NotFound)?;
        Ok(CiphertextWriteInfo {
            id: id.to_owned(),
            revision: u64::try_from(revision).map_err(|_| CacheError::Corrupt)?,
            byte_len: u64::try_from(byte_len).map_err(|_| CacheError::Corrupt)?,
            state: decode_ciphertext_write_state(state)?,
            target_key,
            plaintext_len: u64::try_from(plaintext_len).map_err(|_| CacheError::Corrupt)?,
            operation: decode_ciphertext_write_operation(operation)?,
            retry_generation: u64::try_from(retry_generation).map_err(|_| CacheError::Corrupt)?,
        })
    }

    /// Find one pending revision by its encrypted DAV target without opening
    /// the potentially large ciphertext body. The digest reveals equality
    /// between target records but never stores their raw path components.
    pub fn ciphertext_write_for_target(
        &self,
        scope: &CacheScope,
        encrypted_target: &str,
    ) -> Result<Option<CiphertextWriteInfo>, CacheError> {
        require_ciphertext_scope(scope)?;
        let target_key = ciphertext_target_key(encrypted_target)?;
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let row = db
            .query_row(
                "SELECT write_id,revision,c.byte_len,w.state,w.target_key,w.plaintext_len,w.operation FROM ciphertext_writes w JOIN contents c ON c.content_key=w.content_key WHERE w.scope_key=?1 AND w.target_key=?2",
                params![scope.key, target_key],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?, row.get::<_, i64>(3)?, row.get::<_, String>(4)?, row.get::<_, i64>(5)?, row.get::<_, i64>(6)?)),
            )
            .optional()
            .map_err(db_error)?;
        row.map(
            |(id, revision, byte_len, state, target_key, plaintext_len, operation)| {
                Ok(CiphertextWriteInfo {
                    id,
                    revision: u64::try_from(revision).map_err(|_| CacheError::Corrupt)?,
                    byte_len: u64::try_from(byte_len).map_err(|_| CacheError::Corrupt)?,
                    state: decode_ciphertext_write_state(state)?,
                    target_key,
                    plaintext_len: u64::try_from(plaintext_len).map_err(|_| CacheError::Corrupt)?,
                    operation: decode_ciphertext_write_operation(operation)?,
                    retry_generation: 0,
                })
            },
        )
        .transpose()
    }

    /// Return a page of encrypted file-creation operations for one encrypted
    /// parent path. Only hashes and ciphertext operation class are indexed;
    /// the decrypted name and base envelope are never stored in SQLite.
    pub fn ciphertext_creates_for_parent(
        &self,
        scope: &CacheScope,
        encrypted_parent: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<CiphertextWriteInfo>, bool), CacheError> {
        require_ciphertext_scope(scope)?;
        if !(1..=100).contains(&limit) {
            return Err(CacheError::LimitExceeded);
        }
        if let Some(after) = after {
            validate_ciphertext_write_id(after)?;
        }
        let parent_key = ciphertext_parent_path_key(encrypted_parent)?;
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let rows = {
            let mut statement = db.prepare(
                "SELECT write_id,revision,c.byte_len,w.state,w.target_key,w.plaintext_len,w.operation FROM ciphertext_writes w JOIN contents c ON c.content_key=w.content_key WHERE w.scope_key=?1 AND w.parent_key=?2 AND w.operation=?3 AND (?4 IS NULL OR w.write_id>?4) ORDER BY w.write_id LIMIT ?5",
            ).map_err(db_error)?;
            statement
                .query_map(
                    params![
                        scope.key,
                        parent_key,
                        CiphertextWriteOperation::CreateFile as i64,
                        after,
                        (limit + 1) as i64
                    ],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, i64>(5)?,
                            row.get::<_, i64>(6)?,
                        ))
                    },
                )
                .map_err(db_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(db_error)?
        };
        let truncated = rows.len() > limit;
        let items = rows
            .into_iter()
            .take(limit)
            .map(
                |(id, revision, byte_len, state, target_key, plaintext_len, operation)| {
                    Ok(CiphertextWriteInfo {
                        id,
                        revision: u64::try_from(revision).map_err(|_| CacheError::Corrupt)?,
                        byte_len: u64::try_from(byte_len).map_err(|_| CacheError::Corrupt)?,
                        state: decode_ciphertext_write_state(state)?,
                        target_key,
                        plaintext_len: u64::try_from(plaintext_len)
                            .map_err(|_| CacheError::Corrupt)?,
                        operation: decode_ciphertext_write_operation(operation)?,
                        retry_generation: 0,
                    })
                },
            )
            .collect::<Result<Vec<_>, CacheError>>()?;
        Ok((items, truncated))
    }

    /// Return encrypted directory-create operations indexed by encrypted
    /// parent-path hash. The child name remains only in the sealed envelope.
    pub fn ciphertext_directory_creates_for_parent(
        &self,
        scope: &CacheScope,
        encrypted_parent: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<CiphertextWriteInfo>, bool), CacheError> {
        require_ciphertext_scope(scope)?;
        if !(1..=100).contains(&limit) {
            return Err(CacheError::LimitExceeded);
        }
        if let Some(after) = after {
            validate_ciphertext_write_id(after)?;
        }
        let parent_key = ciphertext_parent_path_key(encrypted_parent)?;
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let rows = {
            let mut statement = db.prepare(
                "SELECT write_id,revision,c.byte_len,w.state,w.target_key,w.plaintext_len,w.operation FROM ciphertext_writes w JOIN contents c ON c.content_key=w.content_key WHERE w.scope_key=?1 AND w.parent_key=?2 AND w.operation=?3 AND (?4 IS NULL OR w.write_id>?4) ORDER BY w.write_id LIMIT ?5",
            ).map_err(db_error)?;
            statement
                .query_map(
                    params![
                        scope.key,
                        parent_key,
                        CiphertextWriteOperation::CreateDirectory as i64,
                        after,
                        (limit + 1) as i64
                    ],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, i64>(5)?,
                            row.get::<_, i64>(6)?,
                        ))
                    },
                )
                .map_err(db_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(db_error)?
        };
        let truncated = rows.len() > limit;
        let items = rows
            .into_iter()
            .take(limit)
            .map(
                |(id, revision, byte_len, state, target_key, plaintext_len, operation)| {
                    Ok(CiphertextWriteInfo {
                        id,
                        revision: u64::try_from(revision).map_err(|_| CacheError::Corrupt)?,
                        byte_len: u64::try_from(byte_len).map_err(|_| CacheError::Corrupt)?,
                        state: decode_ciphertext_write_state(state)?,
                        target_key,
                        plaintext_len: u64::try_from(plaintext_len)
                            .map_err(|_| CacheError::Corrupt)?,
                        operation: decode_ciphertext_write_operation(operation)?,
                        retry_generation: 0,
                    })
                },
            )
            .collect::<Result<Vec<_>, CacheError>>()?;
        Ok((items, truncated))
    }

    /// Return opaque RenameFile journal rows indexed by destination parent.
    /// The row's target key continues to identify the source path, while this
    /// parent key enables bounded namespace overlay without plaintext names.
    pub fn ciphertext_renames_for_parent(
        &self,
        scope: &CacheScope,
        encrypted_parent: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<CiphertextWriteInfo>, bool), CacheError> {
        require_ciphertext_scope(scope)?;
        if !(1..=100).contains(&limit) {
            return Err(CacheError::LimitExceeded);
        }
        if let Some(after) = after {
            validate_ciphertext_write_id(after)?;
        }
        let parent_key = ciphertext_parent_path_key(encrypted_parent)?;
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let rows = {
            let mut statement = db.prepare(
                "SELECT write_id,revision,c.byte_len,w.state,w.target_key,w.plaintext_len,w.operation FROM ciphertext_writes w JOIN contents c ON c.content_key=w.content_key WHERE w.scope_key=?1 AND w.parent_key=?2 AND w.operation=?3 AND (?4 IS NULL OR w.write_id>?4) ORDER BY w.write_id LIMIT ?5",
            ).map_err(db_error)?;
            statement
                .query_map(
                    params![
                        scope.key,
                        parent_key,
                        CiphertextWriteOperation::RenameFile as i64,
                        after,
                        (limit + 1) as i64
                    ],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, i64>(5)?,
                            row.get::<_, i64>(6)?,
                        ))
                    },
                )
                .map_err(db_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(db_error)?
        };
        let truncated = rows.len() > limit;
        let mut result = Vec::with_capacity(rows.len().min(limit));
        for (id, revision, byte_len, state, target_key, plaintext_len, operation) in
            rows.into_iter().take(limit)
        {
            result.push(CiphertextWriteInfo {
                id,
                revision: u64::try_from(revision).map_err(|_| CacheError::Corrupt)?,
                byte_len: u64::try_from(byte_len).map_err(|_| CacheError::Corrupt)?,
                state: decode_ciphertext_write_state(state)?,
                target_key,
                plaintext_len: u64::try_from(plaintext_len).map_err(|_| CacheError::Corrupt)?,
                operation: decode_ciphertext_write_operation(operation)?,
                retry_generation: 0,
            });
        }
        Ok((result, truncated))
    }

    /// Return opaque DeleteFile journal rows indexed by their source parent.
    /// Only the encrypted target hash and operation class are indexed; the
    /// logical source path and recovery metadata remain sealed in the body.
    pub fn ciphertext_deletes_for_parent(
        &self,
        scope: &CacheScope,
        encrypted_parent: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<CiphertextWriteInfo>, bool), CacheError> {
        require_ciphertext_scope(scope)?;
        if !(1..=100).contains(&limit) {
            return Err(CacheError::LimitExceeded);
        }
        if let Some(after) = after {
            validate_ciphertext_write_id(after)?;
        }
        let parent_key = ciphertext_parent_path_key(encrypted_parent)?;
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let rows = {
            let mut statement = db.prepare(
                "SELECT write_id,revision,c.byte_len,w.state,w.target_key,w.plaintext_len,w.operation FROM ciphertext_writes w JOIN contents c ON c.content_key=w.content_key WHERE w.scope_key=?1 AND w.parent_key=?2 AND w.operation=?3 AND (?4 IS NULL OR w.write_id>?4) ORDER BY w.write_id LIMIT ?5",
            ).map_err(db_error)?;
            statement
                .query_map(
                    params![
                        scope.key,
                        parent_key,
                        CiphertextWriteOperation::DeleteFile as i64,
                        after,
                        (limit + 1) as i64
                    ],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, i64>(5)?,
                            row.get::<_, i64>(6)?,
                        ))
                    },
                )
                .map_err(db_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(db_error)?
        };
        let truncated = rows.len() > limit;
        let result = rows
            .into_iter()
            .take(limit)
            .map(
                |(id, revision, byte_len, state, target_key, plaintext_len, operation)| {
                    Ok(CiphertextWriteInfo {
                        id,
                        revision: u64::try_from(revision).map_err(|_| CacheError::Corrupt)?,
                        byte_len: u64::try_from(byte_len).map_err(|_| CacheError::Corrupt)?,
                        state: decode_ciphertext_write_state(state)?,
                        target_key,
                        plaintext_len: u64::try_from(plaintext_len)
                            .map_err(|_| CacheError::Corrupt)?,
                        operation: decode_ciphertext_write_operation(operation)?,
                        retry_generation: 0,
                    })
                },
            )
            .collect::<Result<Vec<_>, CacheError>>()?;
        Ok((result, truncated))
    }

    pub fn open_ciphertext_write(
        &self,
        scope: &CacheScope,
        id: &str,
        revision: u64,
    ) -> Result<CacheContentReader, CacheError> {
        require_ciphertext_scope(scope)?;
        validate_ciphertext_write_id(id)?;
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let (resource_id, etag, protection): (String, String, i64) = db.query_row(
            "SELECT c.resource_id,c.etag,c.protection FROM ciphertext_writes w JOIN contents c ON c.content_key=w.content_key WHERE w.scope_key=?1 AND w.write_id=?2 AND w.revision=?3",
            params![scope.key, id, i64::try_from(revision).unwrap_or(-1)],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).optional().map_err(db_error)?.ok_or(CacheError::NotFound)?;
        let version = ContentVersion {
            resource_id,
            etag,
            protection: match protection {
                value if value == ContentProtection::Plaintext as i64 => {
                    ContentProtection::Plaintext
                }
                value if value == ContentProtection::Ciphertext as i64 => {
                    ContentProtection::Ciphertext
                }
                _ => return Err(CacheError::Corrupt),
            },
        };
        drop(db);
        self.open_content(scope, &version)
    }

    pub fn set_ciphertext_write_state(
        &self,
        scope: &CacheScope,
        id: &str,
        revision: u64,
        state: CiphertextWriteState,
    ) -> Result<(), CacheError> {
        require_ciphertext_scope(scope)?;
        validate_ciphertext_write_id(id)?;
        // These dispatch-boundary states may only be installed by the
        // initial atomic publish and the dedicated compare-and-set claim.
        // In particular, callers cannot turn an attempted operation back
        // into a locally cancelable NeverAttempted row.
        if matches!(
            state,
            CiphertextWriteState::NeverAttempted
                | CiphertextWriteState::Attempting
                | CiphertextWriteState::RecoveryAttempting
                | CiphertextWriteState::RecoveryRetrying
                | CiphertextWriteState::CancelledReceipt
                | CiphertextWriteState::AcknowledgedReceipt
        ) {
            return Err(CacheError::Conflict);
        }
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let changed = db.execute(
            "UPDATE ciphertext_writes SET state=?4 WHERE scope_key=?1 AND write_id=?2 AND revision=?3 AND state NOT IN (?9,?10) AND (state<>?5 OR ?4 IN (?6,?7,?8))",
            params![
                scope.key,
                id,
                i64::try_from(revision).unwrap_or(-1),
                state as i64,
                CiphertextWriteState::Attempting as i64,
                CiphertextWriteState::Conflict as i64,
                CiphertextWriteState::Uncertain as i64,
                CiphertextWriteState::CommittedReceipt as i64,
                CiphertextWriteState::CancelledReceipt as i64,
                CiphertextWriteState::AcknowledgedReceipt as i64,
            ],
        ).map_err(db_error)?;
        if changed == 0 {
            let exists: bool = db
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM ciphertext_writes WHERE scope_key=?1 AND write_id=?2 AND revision=?3)",
                    params![scope.key, id, i64::try_from(revision).unwrap_or(-1)],
                    |row| row.get(0),
                )
                .map_err(db_error)?;
            return Err(if exists {
                CacheError::Conflict
            } else {
                CacheError::NotFound
            });
        }
        Ok(())
    }

    /// Durably claim a directory-create attempt before dispatching MKCOL.
    /// Historical Pending rows are accepted for retry but remain
    /// non-cancelable; only new NeverAttempted rows can be removed locally.
    pub fn claim_ciphertext_directory_create_attempt(
        &self,
        scope: &CacheScope,
        id: &str,
        revision: u64,
    ) -> Result<(), CacheError> {
        require_ciphertext_scope(scope)?;
        validate_ciphertext_write_id(id)?;
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let changed = db
            .execute(
                "UPDATE ciphertext_writes SET state=?5 WHERE scope_key=?1 AND write_id=?2 AND revision=?3 AND operation=?4 AND state IN (?6,?7,?8)",
                params![
                    scope.key,
                    id,
                    i64::try_from(revision).unwrap_or(-1),
                    CiphertextWriteOperation::CreateDirectory as i64,
                    CiphertextWriteState::Attempting as i64,
                    CiphertextWriteState::NeverAttempted as i64,
                    CiphertextWriteState::Pending as i64,
                    CiphertextWriteState::Uncertain as i64
                ],
            )
            .map_err(db_error)?;
        if changed != 1 {
            return Err(CacheError::Conflict);
        }
        Ok(())
    }

    /// Durably claim a file-create revision before dispatching PUT. This is
    /// the only transition into Attempting for CreateFile and prevents a
    /// crash from making an uncertain request eligible for local retargeting.
    pub fn claim_ciphertext_file_create_attempt(
        &self,
        scope: &CacheScope,
        id: &str,
        revision: u64,
    ) -> Result<(), CacheError> {
        require_ciphertext_scope(scope)?;
        validate_ciphertext_write_id(id)?;
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let changed = db
            .execute(
                "UPDATE ciphertext_writes SET state=?5 WHERE scope_key=?1 AND write_id=?2 AND revision=?3 AND operation=?4 AND state IN (?6,?7,?8)",
                params![
                    scope.key,
                    id,
                    i64::try_from(revision).unwrap_or(-1),
                    CiphertextWriteOperation::CreateFile as i64,
                    CiphertextWriteState::Attempting as i64,
                    CiphertextWriteState::NeverAttempted as i64,
                    CiphertextWriteState::Pending as i64,
                    CiphertextWriteState::Uncertain as i64
                ],
            )
            .map_err(db_error)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(CacheError::Conflict)
        }
    }

    /// Claim a copy-specific create before conditional PUT. The durable
    /// operation tag survives restart and excludes the row from generic
    /// CreateFile retry and reconciliation paths.
    pub fn claim_ciphertext_copy_attempt(
        &self,
        scope: &CacheScope,
        id: &str,
        revision: u64,
    ) -> Result<(), CacheError> {
        require_ciphertext_scope(scope)?;
        validate_ciphertext_write_id(id)?;
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let changed = db
            .execute(
                "UPDATE ciphertext_writes SET state=?5 WHERE scope_key=?1 AND write_id=?2 AND revision=?3 AND operation=?4 AND state=?6",
                params![
                    scope.key,
                    id,
                    i64::try_from(revision).unwrap_or(-1),
                    CiphertextWriteOperation::CopyFile as i64,
                    CiphertextWriteState::Attempting as i64,
                    CiphertextWriteState::NeverAttempted as i64
                ],
            )
            .map_err(db_error)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(CacheError::Conflict)
        }
    }

    /// Remove only a never-dispatched directory-create row with no direct
    /// dependent operations. The test and delete share one SQLite transaction
    /// so a child publication cannot race cancellation.
    pub fn cancel_never_attempted_ciphertext_directory_create(
        &self,
        scope: &CacheScope,
        id: &str,
        revision: u64,
    ) -> Result<(), CacheError> {
        require_ciphertext_scope(scope)?;
        validate_ciphertext_write_id(id)?;
        let dependency_key = ciphertext_operation_key(id, revision)?;
        let mut db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let tx = db.transaction().map_err(db_error)?;
        let eligible: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM ciphertext_writes WHERE scope_key=?1 AND write_id=?2 AND revision=?3 AND operation=?4 AND state=?5 AND dependency_key=?6)",
                params![
                    scope.key,
                    id,
                    i64::try_from(revision).unwrap_or(-1),
                    CiphertextWriteOperation::CreateDirectory as i64,
                    CiphertextWriteState::NeverAttempted as i64,
                    dependency_key,
                ],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if !eligible {
            return Err(CacheError::Conflict);
        }
        let retained_receipts: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM ciphertext_writes WHERE scope_key=?1 AND state IN (?2,?3)",
                params![
                    scope.key,
                    CiphertextWriteState::CancelledReceipt as i64,
                    CiphertextWriteState::AcknowledgedReceipt as i64,
                ],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if retained_receipts < 0 || retained_receipts as usize >= MAX_CANCEL_ACK_RECEIPTS_PER_SCOPE
        {
            return Err(CacheError::LimitExceeded);
        }
        let has_dependents: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM ciphertext_writes WHERE scope_key=?1 AND parent_operation_key=?2)",
                params![scope.key, dependency_key],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if has_dependents {
            return Err(CacheError::Conflict);
        }
        let removed = tx
            .execute(
                "DELETE FROM ciphertext_writes WHERE scope_key=?1 AND write_id=?2 AND revision=?3 AND operation=?4 AND state=?5",
                params![
                    scope.key,
                    id,
                    i64::try_from(revision).unwrap_or(-1),
                    CiphertextWriteOperation::CreateDirectory as i64,
                    CiphertextWriteState::NeverAttempted as i64,
                ],
            )
            .map_err(db_error)?;
        if removed != 1 {
            return Err(CacheError::Conflict);
        }
        tx.commit().map_err(db_error)?;
        drop(db);
        let _ = self.evict_recent(self.quota_bytes());
        Ok(())
    }

    /// Atomically claim one explicit retry of a crash-left file create. The
    /// caller supplies both the state and monotonic generation it observed;
    /// neither can be replayed after another attempt, including after a full
    /// state cycle.
    pub fn claim_interrupted_ciphertext_file_create_retry(
        &self,
        scope: &CacheScope,
        id: &str,
        revision: u64,
        expected_state: CiphertextWriteState,
        expected_generation: u64,
    ) -> Result<u64, CacheError> {
        require_ciphertext_scope(scope)?;
        validate_ciphertext_write_id(id)?;
        let next_state = match expected_state {
            CiphertextWriteState::Attempting => CiphertextWriteState::RecoveryAttempting,
            CiphertextWriteState::RecoveryAttempting => CiphertextWriteState::RecoveryRetrying,
            CiphertextWriteState::RecoveryRetrying => CiphertextWriteState::RecoveryAttempting,
            _ => return Err(CacheError::Conflict),
        };
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let expected_generation =
            i64::try_from(expected_generation).map_err(|_| CacheError::Conflict)?;
        let next_generation = expected_generation
            .checked_add(1)
            .filter(|generation| *generation < i64::MAX)
            .ok_or(CacheError::LimitExceeded)?;
        let changed = db.execute(
            "UPDATE ciphertext_writes SET state=?5,retry_generation=?7 WHERE scope_key=?1 AND write_id=?2 AND revision=?3 AND operation=?4 AND state=?6 AND retry_generation=?8",
            params![
                scope.key,
                id,
                i64::try_from(revision).unwrap_or(-1),
                CiphertextWriteOperation::CreateFile as i64,
                next_state as i64,
                expected_state as i64,
                next_generation,
                expected_generation,
            ],
        ).map_err(db_error)?;
        if changed == 1 {
            Ok(u64::try_from(next_generation).map_err(|_| CacheError::Corrupt)?)
        } else {
            let exists: bool = db.query_row(
                "SELECT EXISTS(SELECT 1 FROM ciphertext_writes WHERE scope_key=?1 AND write_id=?2 AND revision=?3)",
                params![scope.key, id, i64::try_from(revision).unwrap_or(-1)],
                |row| row.get(0),
            ).map_err(db_error)?;
            Err(if exists {
                CacheError::Conflict
            } else {
                CacheError::NotFound
            })
        }
    }

    /// Complete an explicit retry only if it still owns the exact claimed
    /// generation. This prevents a late network completion from changing the
    /// state of a newer user-triggered attempt.
    pub fn set_interrupted_ciphertext_file_create_retry_state(
        &self,
        scope: &CacheScope,
        id: &str,
        revision: u64,
        expected_generation: u64,
        expected_state: CiphertextWriteState,
        next_state: CiphertextWriteState,
    ) -> Result<(), CacheError> {
        require_ciphertext_scope(scope)?;
        validate_ciphertext_write_id(id)?;
        if !matches!(
            expected_state,
            CiphertextWriteState::RecoveryAttempting | CiphertextWriteState::RecoveryRetrying
        ) || !matches!(
            next_state,
            CiphertextWriteState::Conflict | CiphertextWriteState::Uncertain
        ) {
            return Err(CacheError::Conflict);
        }
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let changed = db
            .execute(
                "UPDATE ciphertext_writes SET state=?7 WHERE scope_key=?1 AND write_id=?2 AND revision=?3 AND operation=?4 AND state=?5 AND retry_generation=?6",
                params![
                    scope.key,
                    id,
                    i64::try_from(revision).unwrap_or(-1),
                    CiphertextWriteOperation::CreateFile as i64,
                    expected_state as i64,
                    i64::try_from(expected_generation).unwrap_or(-1),
                    next_state as i64,
                ],
            )
            .map_err(db_error)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(CacheError::Conflict)
        }
    }

    /// Retire a verified interrupted create only while the exact retry claim
    /// still owns the row. Content is released only after the CAS succeeds.
    pub fn retire_interrupted_ciphertext_file_create_retry(
        &self,
        scope: &CacheScope,
        id: &str,
        revision: u64,
        expected_generation: u64,
        expected_state: CiphertextWriteState,
    ) -> Result<(), CacheError> {
        require_ciphertext_scope(scope)?;
        validate_ciphertext_write_id(id)?;
        if !matches!(
            expected_state,
            CiphertextWriteState::RecoveryAttempting | CiphertextWriteState::RecoveryRetrying
        ) {
            return Err(CacheError::Conflict);
        }
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let changed = db
            .execute(
                "DELETE FROM ciphertext_writes WHERE scope_key=?1 AND write_id=?2 AND revision=?3 AND operation=?4 AND state=?5 AND retry_generation=?6",
                params![
                    scope.key,
                    id,
                    i64::try_from(revision).unwrap_or(-1),
                    CiphertextWriteOperation::CreateFile as i64,
                    expected_state as i64,
                    i64::try_from(expected_generation).unwrap_or(-1),
                ],
            )
            .map_err(db_error)?;
        if changed != 1 {
            return Err(CacheError::Conflict);
        }
        drop(db);
        self.remove_unreferenced_ciphertext_write_content(scope, id, revision)
    }

    /// Replace only an exact NeverAttempted file-create revision with a
    /// retained cancellation receipt. The authenticated envelope and complete
    /// body must be validated by the caller first; this transaction fences
    /// that proof with the exact revision, target digest, length, operation,
    /// and state. The same SQLite transaction excludes the Attempting claim
    /// and any dependent operation. The sealed body remains protected until
    /// the caller durably retires its matching recovery copy and acknowledges
    /// the receipt.
    pub fn cancel_never_attempted_ciphertext_file_create(
        &self,
        scope: &CacheScope,
        id: &str,
        revision: u64,
        encrypted_target: &str,
        plaintext_len: u64,
    ) -> Result<(), CacheError> {
        require_ciphertext_scope(scope)?;
        validate_ciphertext_write_id(id)?;
        if revision == 0 || plaintext_len > MAX_CONTENT_BYTES {
            return Err(CacheError::Conflict);
        }
        let target_key = ciphertext_target_key(encrypted_target)?;
        let dependency_key = ciphertext_operation_key(id, revision)?;
        let mut db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let tx = db.transaction().map_err(db_error)?;
        let eligible: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM ciphertext_writes WHERE scope_key=?1 AND write_id=?2 AND revision=?3 AND operation=?4 AND state IN (?5,?6) AND target_key=?7 AND plaintext_len=?8)",
                params![
                    scope.key,
                    id,
                    i64::try_from(revision).unwrap_or(-1),
                    CiphertextWriteOperation::CreateFile as i64,
                    CiphertextWriteState::NeverAttempted as i64,
                    CiphertextWriteState::CancelledReceipt as i64,
                    target_key,
                    i64::try_from(plaintext_len).unwrap_or(-1),
                ],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if !eligible {
            return Err(CacheError::Conflict);
        }
        let retained_receipts: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM ciphertext_writes WHERE scope_key=?1 AND state IN (?2,?3)",
                params![
                    scope.key,
                    CiphertextWriteState::CancelledReceipt as i64,
                    CiphertextWriteState::AcknowledgedReceipt as i64,
                ],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if retained_receipts < 0 || retained_receipts as usize >= MAX_CANCEL_ACK_RECEIPTS_PER_SCOPE
        {
            return Err(CacheError::LimitExceeded);
        }
        let has_dependents: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM ciphertext_writes WHERE scope_key=?1 AND parent_operation_key=?2)",
                params![scope.key, dependency_key],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if has_dependents {
            return Err(CacheError::Conflict);
        }
        let changed = tx
            .execute(
                "UPDATE ciphertext_writes SET state=?8 WHERE scope_key=?1 AND write_id=?2 AND revision=?3 AND operation=?4 AND state=?5 AND target_key=?6 AND plaintext_len=?7",
                params![
                    scope.key,
                    id,
                    i64::try_from(revision).unwrap_or(-1),
                    CiphertextWriteOperation::CreateFile as i64,
                    CiphertextWriteState::NeverAttempted as i64,
                    target_key,
                    i64::try_from(plaintext_len).unwrap_or(-1),
                    CiphertextWriteState::CancelledReceipt as i64,
                ],
            )
            .map_err(db_error)?;
        if changed > 1 {
            return Err(CacheError::Conflict);
        }
        tx.commit().map_err(db_error)?;
        Ok(())
    }

    /// Remove the previous encrypted body after an exact cancellation row has
    /// been compacted to its metadata-only acknowledgement revision. If a
    /// crash left the blob unlinked, repeating this operation is harmless.
    pub fn remove_unreferenced_ciphertext_write_content(
        &self,
        scope: &CacheScope,
        id: &str,
        revision: u64,
    ) -> Result<(), CacheError> {
        require_ciphertext_scope(scope)?;
        #[cfg(windows)]
        let windows_store = Some(&self.inner.windows_content);
        #[cfg(windows)]
        let windows_lease = windows_store
            .map(|store| store.publication_lease())
            .transpose()?;
        let _deletion_lease = if self.has_windows_content() {
            None
        } else {
            Some(self.lock_content_deletion()?)
        };
        validate_ciphertext_write_id(id)?;
        if revision == 0 {
            return Err(CacheError::Conflict);
        }
        let version = ContentVersion {
            resource_id: format!("vault-write-{id}"),
            etag: format!("revision-{revision}"),
            protection: ContentProtection::Ciphertext,
        };
        let key = content_key(scope, &version);
        let mut db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let tx = db.transaction().map_err(db_error)?;
        let relative_path: Option<String> = tx
            .query_row(
                "SELECT relative_path FROM contents WHERE content_key=?1 AND scope_key=?2",
                params![key, scope.key],
                |row| row.get(0),
            )
            .optional()
            .map_err(db_error)?;
        let referenced: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM ciphertext_writes WHERE content_key=?1) OR EXISTS(SELECT 1 FROM ciphertext_pin_items WHERE content_key=?1) OR EXISTS(SELECT 1 FROM writes WHERE content_key=?1) OR EXISTS(SELECT 1 FROM pin_items pi JOIN pins p ON p.pin_id=pi.pin_id JOIN contents c ON c.scope_key=p.scope_key AND c.resource_id=pi.resource_id AND c.etag=pi.etag WHERE c.content_key=?1)",
                [&key],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if referenced {
            return Err(CacheError::Conflict);
        }
        #[cfg(windows)]
        if let (Some(store), Some(lease)) = (windows_store, windows_lease.as_ref()) {
            // Both indexed cleanup and a retry after committed metadata removal
            // use the same exact immutable identity under the publication lease.
            let name = relative_path
                .clone()
                .unwrap_or_else(|| format!("{key}.blob"));
            let candidate = store.prepare_eviction(lease, &name)?;
            if relative_path.is_some() {
                let removed = tx.execute(
                    "DELETE FROM contents WHERE content_key=?1 AND scope_key=?2 AND retention=0",
                    params![key, scope.key],
                ).map_err(db_error)?;
                if removed != 1 {
                    return Err(CacheError::Conflict);
                }
            }
            tx.commit().map_err(db_error)?;
            if let Some(file) = candidate {
                file.delete().map_err(io_error)?;
            }
            return Ok(());
        }
        if let Some(path) = relative_path {
            validate_object_filename(&path)?;
            let removed = tx
                .execute(
                    "DELETE FROM contents WHERE content_key=?1 AND scope_key=?2 AND retention=0",
                    params![key, scope.key],
                )
                .map_err(db_error)?;
            if removed != 1 {
                return Err(CacheError::Conflict);
            }
            tx.commit().map_err(db_error)?;
            drop(db);
            match fs::remove_file(self.inner.content_dir.join(path)) {
                Ok(()) => sync_directory(&self.inner.content_dir),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(io_error(error)),
            }
        } else {
            tx.commit().map_err(db_error)?;
            drop(db);
            // The deterministic immutable filename may remain if a crash
            // occurred after metadata deletion but before unlink.
            let path = self.inner.content_dir.join(format!("{key}.blob"));
            match fs::remove_file(path) {
                Ok(()) => sync_directory(&self.inner.content_dir),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(io_error(error)),
            }
        }
    }

    /// Delete only an exact metadata-only AcknowledgedReceipt after its caller
    /// has durably removed the corresponding local WAL. Missing rows are not
    /// considered success.
    pub fn finalize_cancelled_ciphertext_file_create_ack(
        &self,
        scope: &CacheScope,
        id: &str,
        original_revision: u64,
        current_revision: u64,
        encrypted_target: &str,
    ) -> Result<(), CacheError> {
        require_ciphertext_scope(scope)?;
        validate_ciphertext_write_id(id)?;
        if original_revision == 0
            || current_revision != original_revision.saturating_add(1)
            || current_revision >= i64::MAX as u64
        {
            return Err(CacheError::Conflict);
        }
        let target_key = ciphertext_target_key(encrypted_target)?;
        // Validate the exact compact receipt before removing any old content.
        // The OpenCloud caller also authenticates the sealed proof fields.
        let receipt = self.ciphertext_write_info(scope, id)?;
        if receipt.revision != current_revision
            || receipt.state != CiphertextWriteState::AcknowledgedReceipt
            || receipt.operation != CiphertextWriteOperation::CreateFile
            || receipt.target_key != target_key
            || receipt.plaintext_len != 0
        {
            return Err(CacheError::Conflict);
        }
        // Remove the large original body before dropping the compact receipt.
        // If cleanup fails, the exact receipt remains available for retry.
        self.remove_unreferenced_ciphertext_write_content(scope, id, original_revision)?;
        let mut db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let tx = db.transaction().map_err(db_error)?;
        let has_dependents: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM ciphertext_writes WHERE scope_key=?1 AND parent_operation_key=?2)",
                params![scope.key, ciphertext_operation_key(id, 1)?],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if has_dependents {
            return Err(CacheError::Conflict);
        }
        let removed = tx
            .execute(
                "DELETE FROM ciphertext_writes WHERE scope_key=?1 AND write_id=?2 AND revision=?3 AND operation=?4 AND state=?5 AND target_key=?6 AND plaintext_len=0",
                params![
                    scope.key,
                    id,
                    i64_from_u64(current_revision)?,
                    CiphertextWriteOperation::CreateFile as i64,
                    CiphertextWriteState::AcknowledgedReceipt as i64,
                    target_key,
                ],
            )
            .map_err(db_error)?;
        if removed != 1 {
            return Err(CacheError::Conflict);
        }
        tx.commit().map_err(db_error)?;
        drop(db);
        self.remove_unreferenced_ciphertext_write_content(scope, id, current_revision)
    }

    /// Retire exactly the revision whose remote identity and readback the
    /// caller has verified. Any later local revision remains referenced.
    pub fn retire_ciphertext_write(
        &self,
        scope: &CacheScope,
        id: &str,
        revision: u64,
    ) -> Result<(), CacheError> {
        require_ciphertext_scope(scope)?;
        validate_ciphertext_write_id(id)?;
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let changed = db
            .execute(
                "DELETE FROM ciphertext_writes WHERE scope_key=?1 AND write_id=?2 AND revision=?3 AND state NOT IN (?4,?5)",
                params![
                    scope.key,
                    id,
                    i64::try_from(revision).unwrap_or(-1),
                    CiphertextWriteState::CancelledReceipt as i64,
                    CiphertextWriteState::AcknowledgedReceipt as i64,
                ],
            )
            .map_err(db_error)?;
        if changed == 0 {
            let receipt_exists: bool = db
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM ciphertext_writes WHERE scope_key=?1 AND write_id=?2 AND revision=?3 AND state=?4)",
                    params![
                        scope.key,
                        id,
                        i64::try_from(revision).unwrap_or(-1),
                        CiphertextWriteState::CancelledReceipt as i64,
                    ],
                    |row| row.get(0),
                )
                .map_err(db_error)?;
            return Err(if receipt_exists {
                CacheError::Conflict
            } else {
                CacheError::NotFound
            });
        }
        drop(db);
        let _ = self.evict_recent(self.quota_bytes());
        Ok(())
    }

    /// Retire a copy-specific journal row only if its exact revision and
    /// unresolved state still match the resolver's verified snapshot. Generic
    /// retirement is intentionally broader; copy resolution must not delete a
    /// row that another actor has advanced or replaced while remote checks ran.
    pub fn retire_ciphertext_copy_write(
        &self,
        scope: &CacheScope,
        id: &str,
        revision: u64,
        expected_state: CiphertextWriteState,
    ) -> Result<(), CacheError> {
        require_ciphertext_scope(scope)?;
        validate_ciphertext_write_id(id)?;
        if !matches!(
            expected_state,
            CiphertextWriteState::Attempting | CiphertextWriteState::Uncertain
        ) {
            return Err(CacheError::Conflict);
        }
        let mut db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let tx = db.transaction().map_err(db_error)?;
        let changed = tx
            .execute(
                "DELETE FROM ciphertext_writes WHERE scope_key=?1 AND write_id=?2 AND revision=?3 AND operation=?4 AND state=?5",
                params![
                    scope.key,
                    id,
                    i64::try_from(revision).unwrap_or(-1),
                    CiphertextWriteOperation::CopyFile as i64,
                    expected_state as i64,
                ],
            )
            .map_err(db_error)?;
        if changed != 1 {
            return Err(CacheError::Conflict);
        }
        tx.commit().map_err(db_error)?;
        drop(db);
        let _ = self.evict_recent(self.quota_bytes());
        Ok(())
    }

    /// Retire a verified directory receipt only after all direct child
    /// operation references have been rebound or retired. The caller supplies
    /// the original operation revision represented by the receipt.
    pub fn retire_ciphertext_directory_receipt(
        &self,
        scope: &CacheScope,
        id: &str,
        receipt_revision: u64,
        referenced_revision: u64,
    ) -> Result<(), CacheError> {
        require_ciphertext_scope(scope)?;
        validate_ciphertext_write_id(id)?;
        let dependency_key = ciphertext_operation_key(id, referenced_revision)?;
        let mut db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let tx = db.transaction().map_err(db_error)?;
        let row_is_receipt: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM ciphertext_writes WHERE scope_key=?1 AND write_id=?2 AND revision=?3 AND state=?4 AND operation=?5 AND dependency_key=?6)",
                params![scope.key, id, i64::try_from(receipt_revision).unwrap_or(-1), CiphertextWriteState::CommittedReceipt as i64, CiphertextWriteOperation::CreateDirectory as i64, dependency_key],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if !row_is_receipt {
            return Err(CacheError::Conflict);
        }
        let has_children: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM ciphertext_writes WHERE scope_key=?1 AND parent_operation_key=?2)",
                params![scope.key, dependency_key],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if has_children {
            return Err(CacheError::Conflict);
        }
        let removed = tx
            .execute(
                "DELETE FROM ciphertext_writes WHERE scope_key=?1 AND write_id=?2 AND revision=?3",
                params![scope.key, id, i64::try_from(receipt_revision).unwrap_or(-1)],
            )
            .map_err(db_error)?;
        if removed != 1 {
            return Err(CacheError::Conflict);
        }
        tx.commit().map_err(db_error)?;
        drop(db);
        let _ = self.evict_recent(self.quota_bytes());
        Ok(())
    }

    /// Start a new encrypted pin, or a copy-on-write refresh of an existing
    /// pin, at the epoch captured before remote traversal. IDs are random and
    /// opaque; no decrypted path or name is accepted or stored.
    pub fn begin_ciphertext_pin(
        &self,
        scope: &CacheScope,
        expected_epoch: u64,
        existing_pin_id: Option<&str>,
    ) -> Result<CiphertextPinBuild, CacheError> {
        require_ciphertext_scope(scope)?;
        // All cache handles and cooperating processes use this advisory
        // lease before changing the active-manifest generation namespace.
        // Publication uses the same lease but releases SQLite before calling
        // into FUSE, avoiding a cache-DB -> route-lock inversion.
        let _pin_generation_lease = self.lock_pin_generation(scope)?;
        let mut db = self.lock_db()?;
        register_scope(&db, scope)?;
        let tx = db.transaction().map_err(db_error)?;
        if ensure_ciphertext_epoch(&tx, scope)? != i64::try_from(expected_epoch).unwrap_or(-1) {
            return Err(CacheError::Conflict);
        }
        let (pin_id, generation, root_exists) = if let Some(pin_id) = existing_pin_id {
            validate_ciphertext_pin_id(pin_id)?;
            let row: Option<(String, String, i64)> = tx
                .query_row(
                    "SELECT scope_key,root_resource_id,last_generation FROM ciphertext_pin_roots WHERE pin_id=?1",
                    [pin_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(db_error)?;
            let Some((scope_key, root_id, latest)) = row else {
                return Err(CacheError::PinNotFound);
            };
            if scope_key != scope.key || root_id != scope.root_resource_id {
                return Err(CacheError::InvalidScope);
            }
            let generation = latest.checked_add(1).ok_or(CacheError::LimitExceeded)?;
            (pin_id.to_owned(), generation, true)
        } else {
            let mut random = [0u8; 16];
            getrandom::fill(&mut random)
                .map_err(|_| CacheError::Io("secure random generation failed".into()))?;
            let pin_id = random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let count: i64 = tx
                .query_row("SELECT COUNT(*) FROM ciphertext_pin_roots", [], |row| {
                    row.get(0)
                })
                .map_err(db_error)?;
            if count < 0 || count as usize >= MAX_CIPHERTEXT_PINS {
                return Err(CacheError::LimitExceeded);
            }
            tx.execute(
                "INSERT INTO ciphertext_pin_roots(pin_id,scope_key,root_resource_id,created_at,last_generation) VALUES(?1,?2,?3,?4,1)",
                params![pin_id, scope.key, scope.root_resource_id, now_unix()],
            ).map_err(db_error)?;
            (pin_id, 1, false)
        };
        let generation_count: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM ciphertext_pin_generations",
                [],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if generation_count < 0 || generation_count as usize >= MAX_CIPHERTEXT_PIN_GENERATIONS {
            if !root_exists {
                tx.execute(
                    "DELETE FROM ciphertext_pin_roots WHERE pin_id=?1",
                    [&pin_id],
                )
                .map_err(db_error)?;
            }
            return Err(CacheError::LimitExceeded);
        }
        tx.execute(
            "UPDATE ciphertext_pin_roots SET last_generation=?2 WHERE pin_id=?1 AND scope_key=?3",
            params![pin_id, generation, scope.key],
        )
        .map_err(db_error)?;
        tx.execute(
            "INSERT INTO ciphertext_pin_generations(pin_id,generation,epoch,state,item_count,byte_len,created_at) VALUES(?1,?2,?3,0,0,0,?4)",
            params![pin_id, generation, expected_epoch, now_unix()],
        ).map_err(db_error)?;
        tx.commit().map_err(db_error)?;
        Ok(CiphertextPinBuild {
            id: pin_id,
            generation: u64::try_from(generation).map_err(|_| CacheError::Corrupt)?,
            scope_key: scope.key.clone(),
            root_resource_id: scope.root_resource_id.clone(),
            epoch: expected_epoch,
        })
    }

    /// Make a complete staged generation current atomically. At least the root
    /// sealed listing must be present; callers must only invoke this after a
    /// complete traversal and their final root/session validation. Only after
    /// that commit succeeds are older generations for this pin retired. Their
    /// blob rows remain ordinary recent content and can be evicted later; this
    /// leaves already-open file handles readable while dropping stale pin refs.
    pub fn finish_ciphertext_pin(
        &self,
        scope: &CacheScope,
        build: &CiphertextPinBuild,
    ) -> Result<CiphertextPinInfo, CacheError> {
        validate_ciphertext_pin_build(scope, build)?;
        let _pin_generation_lease = self.lock_pin_generation(scope)?;
        let mut db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let tx = db.transaction().map_err(db_error)?;
        if ensure_ciphertext_epoch(&tx, scope)? != i64::try_from(build.epoch).unwrap_or(-1) {
            return Err(CacheError::Conflict);
        }
        let root_id: String = tx.query_row(
            "SELECT root_resource_id FROM ciphertext_pin_roots WHERE pin_id=?1 AND scope_key=?2",
            params![build.id, scope.key],
            |row| row.get(0),
        ).optional().map_err(db_error)?.ok_or(CacheError::PinNotFound)?;
        if root_id != scope.root_resource_id || root_id != build.root_resource_id {
            return Err(CacheError::InvalidScope);
        }
        let (state, item_count, byte_len, root_listing_count): (i64, i64, i64, i64) = tx.query_row(
            "SELECT g.state,g.item_count,g.byte_len,(SELECT COUNT(*) FROM ciphertext_pin_items i WHERE i.pin_id=g.pin_id AND i.generation=g.generation AND i.kind=0) FROM ciphertext_pin_generations g WHERE g.pin_id=?1 AND g.generation=?2 AND g.epoch=?3",
            params![build.id, build.generation, build.epoch],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
        ).optional().map_err(db_error)?.ok_or(CacheError::PinNotFound)?;
        if state != CiphertextPinState::Building as i64 {
            return Err(CacheError::Conflict);
        }
        if item_count <= 0 || root_listing_count != 1 {
            return Err(CacheError::IncompleteManifest);
        }
        tx.execute(
            "UPDATE ciphertext_pin_generations SET state=?3 WHERE pin_id=?1 AND generation<?2 AND state=?4",
            params![build.id, build.generation, CiphertextPinState::Stale as i64, CiphertextPinState::Ready as i64],
        ).map_err(db_error)?;
        tx.execute(
            "UPDATE ciphertext_pin_generations SET state=?3 WHERE pin_id=?1 AND generation=?2 AND state=?4",
            params![build.id, build.generation, CiphertextPinState::Ready as i64, CiphertextPinState::Building as i64],
        ).map_err(db_error)?;
        // Retire only earlier generations once the new complete manifest is
        // Ready in this same transaction. A later concurrent build remains
        // intact, and a failed build never reaches this deletion. Cascading
        // removes only this pin's references, not content rows that may be
        // shared or held by already-open readers.
        tx.execute(
            "DELETE FROM ciphertext_pin_generations WHERE pin_id=?1 AND generation<?2",
            params![build.id, build.generation],
        )
        .map_err(db_error)?;
        tx.commit().map_err(db_error)?;
        Ok(CiphertextPinInfo {
            id: build.id.clone(),
            generation: build.generation,
            state: CiphertextPinState::Ready,
            item_count: usize::try_from(item_count).map_err(|_| CacheError::Corrupt)?,
            byte_len: u64::try_from(byte_len).map_err(|_| CacheError::Corrupt)?,
        })
    }

    /// Discard only this incomplete generation. Existing ready/stale
    /// generations and their protected ciphertext remain untouched.
    pub fn abandon_ciphertext_pin(
        &self,
        scope: &CacheScope,
        build: &CiphertextPinBuild,
    ) -> Result<(), CacheError> {
        validate_ciphertext_pin_build(scope, build)?;
        let _pin_generation_lease = self.lock_pin_generation(scope)?;
        let mut db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let tx = db.transaction().map_err(db_error)?;
        let deleted = tx.execute(
            "DELETE FROM ciphertext_pin_generations WHERE pin_id=?1 AND generation=?2 AND state IN (0,3) AND EXISTS(SELECT 1 FROM ciphertext_pin_roots r WHERE r.pin_id=?1 AND r.scope_key=?3)",
            params![build.id, build.generation, scope.key],
        ).map_err(db_error)?;
        if deleted == 0 {
            return Err(CacheError::Conflict);
        }
        let any_generation: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM ciphertext_pin_generations WHERE pin_id=?1)",
                [&build.id],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if !any_generation {
            tx.execute(
                "DELETE FROM ciphertext_pin_roots WHERE pin_id=?1",
                [&build.id],
            )
            .map_err(db_error)?;
        }
        tx.commit().map_err(db_error)
    }

    pub fn ciphertext_pin_info(
        &self,
        scope: &CacheScope,
        pin_id: &str,
    ) -> Result<CiphertextPinInfo, CacheError> {
        require_ciphertext_scope(scope)?;
        validate_ciphertext_pin_id(pin_id)?;
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let row: Option<(i64, i64, i64, i64, i64)> = db.query_row(
            "SELECT g.generation,g.state,g.item_count,g.byte_len,g.epoch FROM ciphertext_pin_generations g JOIN ciphertext_pin_roots r ON r.pin_id=g.pin_id WHERE g.pin_id=?1 AND r.scope_key=?2 ORDER BY g.generation DESC LIMIT 1",
            params![pin_id, scope.key],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
        ).optional().map_err(db_error)?;
        let Some((generation, state, item_count, byte_len, epoch)) = row else {
            return Err(CacheError::PinNotFound);
        };
        let current_epoch: i64 = db
            .query_row(
                "SELECT epoch FROM ciphertext_epochs WHERE scope_key=?1",
                [&scope.key],
                |row| row.get(0),
            )
            .optional()
            .map_err(db_error)?
            .ok_or(CacheError::Corrupt)?;
        let state = if epoch != current_epoch {
            CiphertextPinState::Stale
        } else {
            decode_ciphertext_pin_state(state)?
        };
        Ok(CiphertextPinInfo {
            id: pin_id.to_owned(),
            generation: u64::try_from(generation).map_err(|_| CacheError::Corrupt)?,
            state,
            item_count: usize::try_from(item_count).map_err(|_| CacheError::Corrupt)?,
            byte_len: u64::try_from(byte_len).map_err(|_| CacheError::Corrupt)?,
        })
    }

    /// Return the latest complete Ready generation that is still in the
    /// current ciphertext epoch. A concurrently staged Building generation
    /// does not hide the previously committed snapshot; `finish_ciphertext_pin`
    /// swaps the active generation atomically.
    pub fn active_ciphertext_pin_info(
        &self,
        scope: &CacheScope,
        pin_id: &str,
    ) -> Result<CiphertextPinInfo, CacheError> {
        require_ciphertext_scope(scope)?;
        validate_ciphertext_pin_id(pin_id)?;
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let row: Option<(i64, i64, i64, i64)> = db.query_row(
            "SELECT g.generation,g.item_count,g.byte_len,g.epoch FROM ciphertext_pin_generations g JOIN ciphertext_pin_roots r ON r.pin_id=g.pin_id JOIN ciphertext_epochs e ON e.scope_key=r.scope_key AND e.epoch=g.epoch WHERE g.pin_id=?1 AND r.scope_key=?2 AND g.state=?3 ORDER BY g.generation DESC LIMIT 1",
            params![pin_id, scope.key, CiphertextPinState::Ready as i64],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ).optional().map_err(db_error)?;
        let Some((generation, item_count, byte_len, _epoch)) = row else {
            return Err(CacheError::PinNotFound);
        };
        Ok(CiphertextPinInfo {
            id: pin_id.to_owned(),
            generation: u64::try_from(generation).map_err(|_| CacheError::Corrupt)?,
            state: CiphertextPinState::Ready,
            item_count: usize::try_from(item_count).map_err(|_| CacheError::Corrupt)?,
            byte_len: u64::try_from(byte_len).map_err(|_| CacheError::Corrupt)?,
        })
    }

    /// Run a publication step while the exact ready pin generation is fenced
    /// against refresh/removal. The cross-handle advisory lease remains held
    /// through `operation`, but SQLite is committed and unlocked first. The
    /// closure must not publish content, evict, invalidate, or otherwise take
    /// the content lease: deletion takes content before the pin lease.
    /// It may take route/FUSE locks and read the cache without
    /// creating a SQLite-to-route lock inversion. The cache is process-owned:
    /// every cooperating process must use this lock-file protocol; external
    /// tools that edit the SQLite database directly are unsupported.
    pub fn with_active_ciphertext_pin_generation<T>(
        &self,
        scope: &CacheScope,
        pin_id: &str,
        expected_generation: u64,
        operation: impl FnOnce() -> T,
    ) -> Result<T, CacheError> {
        require_ciphertext_scope(scope)?;
        validate_ciphertext_pin_id(pin_id)?;
        let _pin_generation_lease = self.lock_pin_generation(scope)?;
        {
            let mut db = self.lock_db()?;
            validate_registered_scope(&db, scope)?;
            let tx = db
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(db_error)?;
            let generation: Option<i64> = tx
                .query_row(
                    "SELECT g.generation FROM ciphertext_pin_generations g \
                     JOIN ciphertext_pin_roots r ON r.pin_id=g.pin_id \
                     JOIN ciphertext_epochs e ON e.scope_key=r.scope_key AND e.epoch=g.epoch \
                     WHERE g.pin_id=?1 AND r.scope_key=?2 AND g.state=?3 \
                     ORDER BY g.generation DESC LIMIT 1",
                    params![pin_id, scope.key, CiphertextPinState::Ready as i64],
                    |row| row.get(0),
                )
                .optional()
                .map_err(db_error)?;
            if generation != Some(i64::try_from(expected_generation).unwrap_or(-1)) {
                return Err(CacheError::Conflict);
            }
            tx.commit().map_err(db_error)?;
        }
        let result = operation();
        Ok(result)
    }

    pub fn ciphertext_pins(
        &self,
        scope: &CacheScope,
        after: Option<&str>,
        limit: usize,
    ) -> Result<CiphertextPinPage, CacheError> {
        require_ciphertext_scope(scope)?;
        if !(1..=100).contains(&limit) {
            return Err(CacheError::LimitExceeded);
        }
        if let Some(after) = after {
            validate_ciphertext_pin_id(after)?;
        }
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let rows = {
            let mut statement = db.prepare(
                "SELECT r.pin_id,g.generation,g.state,g.item_count,g.byte_len,g.epoch FROM ciphertext_pin_roots r JOIN ciphertext_pin_generations g ON g.pin_id=r.pin_id WHERE r.scope_key=?1 AND (?2 IS NULL OR r.pin_id>?2) AND g.generation=(SELECT MAX(g2.generation) FROM ciphertext_pin_generations g2 WHERE g2.pin_id=r.pin_id) ORDER BY r.pin_id LIMIT ?3",
            ).map_err(db_error)?;
            statement
                .query_map(params![scope.key, after, (limit + 1) as i64], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                })
                .map_err(db_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(db_error)?
        };
        let truncated = rows.len() > limit;
        let rows = rows.into_iter().take(limit).collect::<Vec<_>>();
        let next_after = truncated
            .then(|| rows.last().map(|row| row.0.clone()))
            .flatten();
        let current_epoch: i64 = db
            .query_row(
                "SELECT epoch FROM ciphertext_epochs WHERE scope_key=?1",
                [&scope.key],
                |row| row.get(0),
            )
            .optional()
            .map_err(db_error)?
            .ok_or(CacheError::Corrupt)?;
        let items = rows
            .into_iter()
            .map(|(id, generation, state, item_count, byte_len, epoch)| {
                let state = if epoch != current_epoch {
                    CiphertextPinState::Stale
                } else {
                    decode_ciphertext_pin_state(state)?
                };
                Ok(CiphertextPinInfo {
                    id,
                    generation: u64::try_from(generation).map_err(|_| CacheError::Corrupt)?,
                    state,
                    item_count: usize::try_from(item_count).map_err(|_| CacheError::Corrupt)?,
                    byte_len: u64::try_from(byte_len).map_err(|_| CacheError::Corrupt)?,
                })
            })
            .collect::<Result<Vec<_>, CacheError>>()?;
        Ok(CiphertextPinPage {
            items,
            next_after,
            truncated,
        })
    }

    /// Open content only when it is referenced by the active ready generation
    /// for this exact encrypted scope. The returned file is rehashed by the
    /// ordinary content-open path before use.
    pub fn open_ciphertext_pin_content(
        &self,
        scope: &CacheScope,
        pin_id: &str,
        version: &ContentVersion,
    ) -> Result<CacheContentReader, CacheError> {
        require_ciphertext_scope(scope)?;
        validate_ciphertext_pin_id(pin_id)?;
        if version.protection != ContentProtection::Ciphertext {
            return Err(CacheError::ProtectionMismatch);
        }
        let key = content_key(scope, version);
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let referenced: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM ciphertext_pin_roots r JOIN ciphertext_pin_generations g ON g.pin_id=r.pin_id JOIN ciphertext_pin_items i ON i.pin_id=g.pin_id AND i.generation=g.generation WHERE r.pin_id=?1 AND r.scope_key=?2 AND g.state=?3 AND g.epoch=(SELECT epoch FROM ciphertext_epochs WHERE scope_key=?2) AND i.content_key=?4 AND i.resource_id=?5 AND i.etag=?6)",
            params![pin_id,scope.key,CiphertextPinState::Ready as i64,key,version.resource_id,version.etag],
            |row| row.get(0),
        ).map_err(db_error)?;
        if !referenced {
            return Err(CacheError::NotFound);
        }
        drop(db);
        self.open_content(scope, version)
    }

    /// Remove one encrypted pin and its generations. Blob cleanup is deferred
    /// to normal recent-content eviction and never follows database paths.
    pub fn remove_ciphertext_pin(
        &self,
        scope: &CacheScope,
        pin_id: &str,
    ) -> Result<(), CacheError> {
        require_ciphertext_scope(scope)?;
        validate_ciphertext_pin_id(pin_id)?;
        let _pin_generation_lease = self.lock_pin_generation(scope)?;
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let changed = db
            .execute(
                "DELETE FROM ciphertext_pin_roots WHERE pin_id=?1 AND scope_key=?2",
                params![pin_id, scope.key],
            )
            .map_err(db_error)?;
        if changed == 0 {
            return Err(CacheError::PinNotFound);
        }
        Ok(())
    }

    /// Enumerate only opaque encrypted scope identities for one exact origin
    /// and account. This does not expose cached paths or names and never
    /// considers plaintext scopes. Callers must still open and authenticate
    /// the matching sealed root envelope before presenting any decrypted
    /// metadata.
    pub fn ciphertext_scopes_for_account(
        &self,
        origin: &str,
        account_id: &str,
        after: Option<(&str, &str)>,
        limit: usize,
    ) -> Result<CiphertextScopePage, CacheError> {
        if !(1..=100).contains(&limit) {
            return Err(CacheError::LimitExceeded);
        }
        // Reuse CacheScope validation and canonicalization for the public
        // identity fields without registering a synthetic scope.
        let validated = CacheScope::new(
            origin,
            account_id,
            "scope-space",
            "scope-root",
            ScopeProtection::CiphertextOnly,
        )?;
        if let Some((space_id, root_resource_id)) = after {
            CacheScope::new(
                &validated.origin,
                &validated.account_id,
                space_id,
                root_resource_id,
                ScopeProtection::CiphertextOnly,
            )?;
        }
        let db = self.lock_db()?;
        let mut statement = db
            .prepare(
                "SELECT space_id,root_resource_id FROM scopes WHERE origin=?1 AND account_id=?2 AND protection=?3 AND (?4 IS NULL OR space_id>?4 OR (space_id=?4 AND root_resource_id>?5)) ORDER BY space_id,root_resource_id LIMIT ?6",
            )
            .map_err(db_error)?;
        let rows = statement
            .query_map(
                params![
                    validated.origin,
                    validated.account_id,
                    ScopeProtection::CiphertextOnly as i64,
                    after.map(|cursor| cursor.0),
                    after.map(|cursor| cursor.1),
                    (limit + 1) as i64,
                ],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .map_err(db_error)?;
        let identities = rows.collect::<Result<Vec<_>, _>>().map_err(db_error)?;
        let truncated = identities.len() > limit;
        let mut identities = identities;
        if truncated {
            identities.pop();
        }
        let next_after = truncated.then(|| identities.last().cloned()).flatten();
        let items = identities
            .into_iter()
            .map(|(space_id, root_resource_id)| {
                CacheScope::new(
                    &validated.origin,
                    &validated.account_id,
                    &space_id,
                    &root_resource_id,
                    ScopeProtection::CiphertextOnly,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(CiphertextScopePage {
            items,
            next_after,
            truncated,
        })
    }

    /// Revokes cached authority for one encrypted scope before a remote
    /// mutation. Dirty/recovery records and content referenced by pins or
    /// pending writes are retained. Recent unprotected content and cached
    /// listings are removed from the index; file cleanup follows the
    /// committed revocation and never follows symlinks.
    pub fn invalidate_ciphertext_scope(&self, scope: &CacheScope) -> Result<u64, CacheError> {
        require_ciphertext_scope(scope)?;
        #[cfg(windows)]
        let windows_store = Some(&self.inner.windows_content);
        #[cfg(windows)]
        let windows_lease = windows_store
            .map(|store| store.publication_lease())
            .transpose()?;
        let _deletion_lease = if self.has_windows_content() {
            None
        } else {
            Some(self.lock_content_deletion()?)
        };
        let _pin_generation_lease = self.lock_pin_generation(scope)?;
        let mut db = self.lock_db()?;
        register_scope(&db, scope)?;
        let tx = db.transaction().map_err(db_error)?;
        let current = ensure_ciphertext_epoch(&tx, scope)?;
        let next = current.checked_add(1).ok_or(CacheError::LimitExceeded)?;
        tx.execute(
            "UPDATE ciphertext_epochs SET epoch=?2 WHERE scope_key=?1",
            params![scope.key, next],
        )
        .map_err(db_error)?;

        // Cached listings are authority-bearing metadata; pins retain their
        // durable snapshot rows but become stale and cannot be presented as
        // current after a remote mutation.
        tx.execute("DELETE FROM listings WHERE scope_key=?1", [&scope.key])
            .map_err(db_error)?;
        tx.execute(
            "DELETE FROM listing_entries WHERE scope_key=?1",
            [&scope.key],
        )
        .map_err(db_error)?;
        tx.execute(
            "UPDATE pins SET state=2 WHERE scope_key=?1 AND state<>3",
            [&scope.key],
        )
        .map_err(db_error)?;
        tx.execute(
            "UPDATE ciphertext_pin_generations SET state=CASE state WHEN 0 THEN 3 ELSE 2 END WHERE pin_id IN (SELECT pin_id FROM ciphertext_pin_roots WHERE scope_key=?1) AND state IN (0,1)",
            [&scope.key],
        ).map_err(db_error)?;

        let stale_recent = {
            let mut statement = tx
                .prepare(
                    "SELECT c.content_key,c.relative_path FROM contents c WHERE c.scope_key=?1 AND c.retention=0 AND NOT EXISTS(SELECT 1 FROM pin_items pi JOIN pins p ON p.pin_id=pi.pin_id WHERE p.scope_key=c.scope_key AND pi.resource_id=c.resource_id AND pi.etag=c.etag) AND NOT EXISTS(SELECT 1 FROM ciphertext_pin_items cpi WHERE cpi.content_key=c.content_key) AND NOT EXISTS(SELECT 1 FROM ciphertext_writes cw WHERE cw.content_key=c.content_key) AND NOT EXISTS(SELECT 1 FROM writes w WHERE w.content_key=c.content_key AND w.state IN (0,1))",
                )
                .map_err(db_error)?;
            let rows = statement
                .query_map([&scope.key], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(db_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(db_error)?;
            drop(statement);
            rows
        };
        // Prepare all identity-bound deletions before revoking the index. A
        // sharing conflict leaves the epoch, pins and metadata unchanged, so
        // the caller must not proceed with its remote mutation yet.
        #[cfg(windows)]
        let windows_candidates = match (windows_store, windows_lease.as_ref()) {
            (Some(store), Some(lease)) => Some(
                stale_recent
                    .iter()
                    .map(|(_, name)| store.prepare_eviction(lease, name))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            _ => None,
        };
        for (key, relative) in &stale_recent {
            validate_object_filename(relative)?;
            tx.execute(
                "DELETE FROM contents WHERE content_key=?1 AND scope_key=?2 AND retention=0",
                params![key, scope.key],
            )
            .map_err(db_error)?;
        }
        tx.commit().map_err(db_error)?;

        #[cfg(windows)]
        if let Some(candidates) = windows_candidates {
            for file in candidates.into_iter().flatten() {
                file.delete().map_err(io_error)?;
            }
            return u64::try_from(next).map_err(|_| CacheError::Corrupt);
        }

        // The epoch and index deletion are already durable. Failure to remove
        // a blob leaves only an inaccessible orphan and is reported so the
        // caller can surface cleanup trouble without restoring stale data.
        for (_, relative) in stale_recent {
            let path = self.inner.content_dir.join(relative);
            match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.file_type().is_file() => {
                    fs::remove_file(path).map_err(io_error)?;
                }
                Ok(_) => return Err(CacheError::UnsafeDirectory),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(io_error(error)),
            }
        }
        sync_directory(&self.inner.content_dir)?;
        u64::try_from(next).map_err(|_| CacheError::Corrupt)
    }

    pub fn quota_bytes(&self) -> u64 {
        self.inner.quota_bytes
    }

    /// Read-only usage accounting. This does not trigger eviction or remove
    /// pinned, policy-protected, dirty, or recovery content.
    pub fn usage(&self) -> Result<CacheUsage, CacheError> {
        #[cfg(windows)]
        let windows_store = Some(&self.inner.windows_content);
        #[cfg(windows)]
        let windows_lease = windows_store
            .map(|store| store.publication_lease())
            .transpose()?;
        let db = self.lock_db()?;
        let used_bytes = total_content_bytes(&db)?;
        let pinned_bytes = pinned_content_bytes(&db)?;
        let protected_bytes = protected_content_bytes(&db)?;
        #[cfg(windows)]
        let (used_bytes, protected_bytes) = match (windows_store, windows_lease.as_ref()) {
            (Some(store), Some(lease)) => {
                let inventory = windows_content_inventory(&db, store, lease)?;
                (
                    used_bytes
                        .saturating_add(inventory.unindexed_bytes)
                        .max(inventory.physical_bytes),
                    protected_bytes.saturating_add(inventory.unindexed_bytes),
                )
            }
            _ => (used_bytes, protected_bytes),
        };
        Ok(CacheUsage {
            quota_bytes: self.inner.quota_bytes,
            used_bytes,
            pinned_bytes,
            protected_bytes,
            over_quota: used_bytes > self.inner.quota_bytes,
        })
    }

    pub fn publish_listing(
        &self,
        scope: &CacheScope,
        parent_resource_id: &str,
        entries: &[CachedEntry],
        fetched_at_unix: i64,
    ) -> Result<CachedListing, CacheError> {
        if scope.protection == ScopeProtection::CiphertextOnly {
            return Err(CacheError::ProtectionMismatch);
        }
        validate_id(parent_resource_id)?;
        validate_listing(entries)?;
        if entries
            .iter()
            .any(|item| item.parent_resource_id != parent_resource_id)
        {
            return Err(CacheError::InvalidEntry);
        }
        let db = self.lock_db()?;
        register_scope(&db, scope)?;
        let tx = db.unchecked_transaction().map_err(db_error)?;
        let listing = listing_publication::publish_listing_in_transaction(
            &tx,
            scope,
            parent_resource_id,
            entries,
            fetched_at_unix,
        )?;
        tx.commit().map_err(db_error)?;
        Ok(listing)
    }

    pub fn listing(
        &self,
        scope: &CacheScope,
        parent_resource_id: &str,
    ) -> Result<CachedListing, CacheError> {
        if scope.protection == ScopeProtection::CiphertextOnly {
            return Err(CacheError::ProtectionMismatch);
        }
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        load_listing(&db, scope, parent_resource_id)
    }

    pub fn list_with_offline_fallback<F>(
        &self,
        scope: &CacheScope,
        parent_resource_id: &str,
        online: F,
    ) -> Result<CachedListing, CloudError>
    where
        F: FnOnce() -> Result<Vec<CachedEntry>, CloudError>,
    {
        match online() {
            Ok(entries) => self
                .publish_listing(scope, parent_resource_id, &entries, now_unix())
                .map_err(cache_cloud_error),
            Err(error) if error.kind == ErrorKind::Offline => self
                .listing(scope, parent_resource_id)
                .map_err(|cache_error| {
                    if cache_error == CacheError::IncompleteListing
                        || cache_error == CacheError::NotFound
                    {
                        error
                    } else {
                        cache_cloud_error(cache_error)
                    }
                }),
            Err(error) => Err(error),
        }
    }

    /// Fetch and publish one verified immutable content version online, using
    /// cached bytes only when the transport explicitly reports offline.
    pub fn content_with_offline_fallback<F, R>(
        &self,
        scope: &CacheScope,
        version: &ContentVersion,
        expected_len: u64,
        online: F,
    ) -> Result<CacheContentReader, CloudError>
    where
        F: FnOnce() -> Result<R, CloudError>,
        R: Read,
    {
        match online() {
            Ok(mut reader) => {
                self.publish_content(scope, version, &mut reader, expected_len, Retention::Recent)
                    .map_err(cache_cloud_error)?;
                self.open_content(scope, version).map_err(cache_cloud_error)
            }
            Err(error) if error.kind == ErrorKind::Offline => self
                .open_content(scope, version)
                .map_err(|cache_error| match cache_error {
                    CacheError::NotFound => error,
                    other => cache_cloud_error(other),
                }),
            Err(error) => Err(error),
        }
    }

    /// CloudOnly removes indexed recent cache files and rejects new cache
    /// opens. It cannot revoke bytes already handed to an open file handle or
    /// copied into another process; callers must not present it as secure
    /// erasure.
    pub fn set_policy(
        &self,
        scope: &CacheScope,
        resource_id: &str,
        policy: AvailabilityPolicy,
    ) -> Result<(), CacheError> {
        let target = {
            let db = self.lock_db()?;
            validate_registered_scope(&db, scope)?;
            db.query_row(
                "SELECT e.path,e.etag FROM listing_entries e JOIN listings l ON l.scope_key=e.scope_key AND l.parent_id=e.parent_id AND l.generation=e.generation WHERE e.scope_key=?1 AND e.resource_id=?2 AND e.directory=0 AND l.complete=1 ORDER BY l.fetched_at DESC LIMIT 1",
                params![scope.key, resource_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            ).optional().map_err(db_error)?
        };
        let (path, etag) = target.unwrap_or_else(|| ("/".into(), String::new()));
        self.set_policy_at(scope, resource_id, &path, &etag, policy)
    }

    /// Store a resource-based policy and its last verified path/version. The
    /// refresh worker may update path only after a complete listing observes
    /// the same stable resource ID.
    pub fn set_policy_at(
        &self,
        scope: &CacheScope,
        resource_id: &str,
        path: &str,
        etag: &str,
        policy: AvailabilityPolicy,
    ) -> Result<(), CacheError> {
        self.set_policy_at_inner(scope, (resource_id, path, etag), policy, None)
    }

    /// Change policy only while the exact ordinary file remains present in a
    /// complete cached listing. This checks local metadata atomically with the
    /// policy update; it neither refreshes the server nor downloads content.
    pub fn set_listed_file_policy(
        &self,
        scope: &CacheScope,
        entry: &RemoteEntry,
        policy: AvailabilityPolicy,
    ) -> Result<(), CacheError> {
        if policy == AvailabilityPolicy::AlwaysOffline
            || entry.directory
            || entry.encrypted
            || scope.protection != ScopeProtection::PlaintextAllowed
            || entry.etag.trim().is_empty()
            || entry.etag.trim() != entry.etag
            || entry.etag.chars().any(char::is_control)
            || entry.etag.starts_with("W/")
        {
            return Err(CacheError::PolicyConflict);
        }
        let size = i64::try_from(entry.size).map_err(|_| CacheError::PolicyConflict)?;
        self.set_policy_at_inner(
            scope,
            (&entry.id, &entry.path, &entry.etag),
            policy,
            Some(size),
        )
    }

    fn set_policy_at_inner(
        &self,
        scope: &CacheScope,
        target: (&str, &str, &str),
        policy: AvailabilityPolicy,
        listed_size: Option<i64>,
    ) -> Result<(), CacheError> {
        let (resource_id, path, etag) = target;
        validate_id(resource_id)?;
        validate_path(path)?;
        if etag.len() > MAX_SCOPE_FIELD {
            return Err(CacheError::InvalidContentVersion);
        }
        #[cfg(windows)]
        let windows_store = Some(&self.inner.windows_content);
        #[cfg(windows)]
        let windows_lease = if policy == AvailabilityPolicy::CloudOnly {
            windows_store
                .map(|store| store.publication_lease())
                .transpose()?
        } else {
            None
        };
        let _deletion_lease =
            if policy == AvailabilityPolicy::CloudOnly && !self.has_windows_content() {
                Some(self.lock_content_deletion()?)
            } else {
                None
            };
        let db = self.lock_db()?;
        if listed_size.is_some() {
            validate_registered_scope(&db, scope)?;
        } else {
            register_scope(&db, scope)?;
        }
        let tx = db.unchecked_transaction().map_err(db_error)?;
        if let Some(size) = listed_size {
            // Reject an ambiguous stable ID or path as well as a stale version.
            // No policy/index mutation occurs before this transaction-local fence.
            let listed: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM listing_entries e JOIN listings l ON l.scope_key=e.scope_key AND l.parent_id=e.parent_id AND l.generation=e.generation WHERE e.scope_key=?1 AND e.resource_id=?2 AND e.path=?3 AND e.etag=?4 AND e.size=?5 AND e.directory=0 AND e.encrypted=0 AND l.complete=1) AND NOT EXISTS(SELECT 1 FROM listing_entries e JOIN listings l ON l.scope_key=e.scope_key AND l.parent_id=e.parent_id AND l.generation=e.generation WHERE e.scope_key=?1 AND l.complete=1 AND (e.resource_id=?2 OR e.path=?3) AND (e.resource_id<>?2 OR e.path<>?3 OR e.etag<>?4 OR e.size<>?5 OR e.directory<>0 OR e.encrypted<>0))",
                params![scope.key, resource_id, path, etag, size], |row| row.get(0),
            ).map_err(db_error)?;
            if !listed {
                return Err(CacheError::PolicyConflict);
            }
        }
        if policy == AvailabilityPolicy::AlwaysOffline {
            if folder_policy::inherited_cloud_only(&tx, scope, resource_id)? {
                return Err(CacheError::PolicyConflict);
            }
            if etag.trim().is_empty() || scope.protection == ScopeProtection::CiphertextOnly {
                return Err(CacheError::PolicyConflict);
            }
            // The download may have been evicted since the engine verified it.
            // Admit Ready only with the exact complete version still indexed
            // in this same policy transaction; later eviction observes policy.
            let listed: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM listing_entries e JOIN listings l ON l.scope_key=e.scope_key AND l.parent_id=e.parent_id AND l.generation=e.generation WHERE e.scope_key=?1 AND e.resource_id=?2 AND e.path=?3 AND e.etag=?4 AND e.directory=0 AND e.encrypted=0 AND l.complete=1 AND EXISTS(SELECT 1 FROM contents c WHERE c.scope_key=e.scope_key AND c.resource_id=e.resource_id AND c.etag=e.etag AND c.protection=0 AND c.byte_len=e.size))",
                params![scope.key,resource_id,path,etag], |row| row.get(0),
            ).map_err(db_error)?;
            if !listed {
                return Err(CacheError::PolicyConflict);
            }
        }
        if policy == AvailabilityPolicy::CloudOnly {
            let retained: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM contents WHERE scope_key=?1 AND resource_id=?2 AND retention IN (1,2)) OR EXISTS(SELECT 1 FROM pin_items pi JOIN pins p ON p.pin_id=pi.pin_id WHERE p.scope_key=?1 AND pi.resource_id=?2)",
                params![scope.key,resource_id], |row| row.get(0),
            ).map_err(db_error)?;
            let journal_or_ciphertext_pin: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM contents c WHERE c.scope_key=?1 AND c.resource_id=?2 AND (EXISTS(SELECT 1 FROM writes w WHERE w.content_key=c.content_key AND w.state IN (0,1)) OR EXISTS(SELECT 1 FROM ciphertext_writes w WHERE w.content_key=c.content_key) OR EXISTS(SELECT 1 FROM ciphertext_pin_items i WHERE i.content_key=c.content_key)))",
                params![scope.key, resource_id], |row| row.get(0),
            ).map_err(db_error)?;
            if retained || journal_or_ciphertext_pin {
                return Err(CacheError::PolicyConflict);
            }
            let removed = remove_recent_content(&tx, &scope.key, resource_id)?;
            // Acquire every exact deletion handle before committing the policy.
            // A live reader or invalid object rolls back both policy and index.
            #[cfg(windows)]
            let windows_candidates = match (windows_store, windows_lease.as_ref()) {
                (Some(store), Some(lease)) => Some(
                    removed
                        .iter()
                        .map(|name| store.prepare_eviction(lease, name))
                        .collect::<Result<Vec<_>, _>>()?,
                ),
                _ => None,
            };
            tx.execute(
                "INSERT INTO policies(scope_key,resource_id,policy,target_path,target_etag,target_state) VALUES(?1,?2,?3,?4,?5,2) ON CONFLICT(scope_key,resource_id) DO UPDATE SET policy=excluded.policy,target_path=excluded.target_path,target_etag=excluded.target_etag,target_state=excluded.target_state",
                params![scope.key,resource_id,policy as i64,path,etag],
            ).map_err(db_error)?;
            // Do not delete bytes until the policy and index removal are
            // durable. A failed COMMIT rolls back both and must leave the
            // still-indexed content readable. Keep the DB mutex through
            // cleanup so a publisher cannot repopulate these names locally.
            tx.commit().map_err(db_error)?;
            #[cfg(windows)]
            if let Some(candidates) = windows_candidates {
                for file in candidates.into_iter().flatten() {
                    file.delete()
                        .map_err(|error| CacheError::Io(error.to_string()))?;
                }
                return Ok(());
            }
            for filename in &removed {
                match fs::remove_file(self.inner.content_dir.join(filename)) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(CacheError::Io(error.to_string())),
                }
            }
            sync_directory(&self.inner.content_dir)?;
            return Ok(());
        }
        tx.execute(
            "INSERT INTO policies(scope_key,resource_id,policy,target_path,target_etag,target_state) VALUES(?1,?2,?3,?4,?5,0) ON CONFLICT(scope_key,resource_id) DO UPDATE SET policy=excluded.policy,target_path=excluded.target_path,target_etag=excluded.target_etag,target_state=0",
            params![scope.key,resource_id,policy as i64,path,etag],
        ).map_err(db_error)?;
        tx.commit().map_err(db_error)
    }

    /// Clear only the exact folder's inherited CloudOnly intent. Its stable
    /// identity may no longer appear in a current listing; clearing must still
    /// work without rebinding the intent to another folder at the same path.
    /// This does not download content or alter individual file policies, pins,
    /// dirty edits, recovery data, or the cloud.
    #[cfg(unix)]
    pub fn clear_folder_cloud_only(
        &self,
        scope: &CacheScope,
        root_resource_id: &str,
    ) -> Result<bool, CacheError> {
        validate_id(root_resource_id)?;
        if scope.protection != ScopeProtection::PlaintextAllowed {
            return Err(CacheError::ProtectionMismatch);
        }
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let removed = db
            .execute(
                "DELETE FROM folder_cloud_only_intents WHERE scope_key=?1 AND root_id=?2",
                params![scope.key, root_resource_id],
            )
            .map_err(db_error)?;
        Ok(removed != 0)
    }

    pub fn refresh_targets(
        &self,
        scope: &CacheScope,
    ) -> Result<(Vec<PolicyRefreshTarget>, Vec<PinRefreshTarget>), CacheError> {
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let policies = {
            let mut stmt = db.prepare("SELECT resource_id,target_path,target_etag,target_state FROM policies WHERE scope_key=?1 AND policy=1 ORDER BY resource_id").map_err(db_error)?;
            stmt.query_map([&scope.key], |row| {
                Ok(PolicyRefreshTarget {
                    resource_id: row.get(0)?,
                    path: row.get(1)?,
                    etag: row.get(2)?,
                    state: decode_target_state(row.get(3)?)?,
                })
            })
            .map_err(db_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_error)?
        };
        let pins = {
            let mut stmt = db.prepare("SELECT pin_id,root_id,root_path,state FROM pins WHERE scope_key=?1 ORDER BY created_at,pin_id").map_err(db_error)?;
            stmt.query_map([&scope.key], |row| {
                Ok(PinRefreshTarget {
                    pin_id: row.get(0)?,
                    root_resource_id: row.get(1)?,
                    path: row.get(2)?,
                    state: decode_pin_state(row.get(3)?)?,
                })
            })
            .map_err(db_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_error)?
        };
        Ok((policies, pins))
    }

    pub fn set_policy_refresh_state(
        &self,
        scope: &CacheScope,
        resource_id: &str,
        path: &str,
        etag: &str,
        state: TargetState,
    ) -> Result<(), CacheError> {
        validate_id(resource_id)?;
        validate_path(path)?;
        if etag.len() > MAX_SCOPE_FIELD {
            return Err(CacheError::InvalidContentVersion);
        }
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        if state == TargetState::Ready {
            let verified_target: bool = db
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM contents c WHERE c.scope_key=?1 AND c.resource_id=?2 AND c.etag=?4 AND c.protection=0) AND EXISTS(SELECT 1 FROM listing_entries e JOIN listings l ON l.scope_key=e.scope_key AND l.parent_id=e.parent_id AND l.generation=e.generation WHERE e.scope_key=?1 AND e.resource_id=?2 AND e.path=?3 AND e.etag=?4 AND e.directory=0 AND e.encrypted=0 AND l.complete=1)",
                    params![scope.key, resource_id, path, etag],
                    |row| row.get(0),
                )
                .map_err(db_error)?;
            if !verified_target {
                return Err(CacheError::PolicyConflict);
            }
        }
        let changed = db.execute(
            "UPDATE policies SET target_path=?3,target_etag=?4,target_state=?5 WHERE scope_key=?1 AND resource_id=?2 AND policy=1",
            params![scope.key,resource_id,path,etag,state as i64],
        ).map_err(db_error)?;
        if changed == 0 {
            Err(CacheError::NotFound)
        } else {
            Ok(())
        }
    }

    pub fn set_pin_refresh_state(
        &self,
        scope: &CacheScope,
        pin_id: &str,
        state: PinState,
    ) -> Result<PinInfo, CacheError> {
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let changed = db
            .execute(
                "UPDATE pins SET state=?3 WHERE scope_key=?1 AND pin_id=?2",
                params![scope.key, pin_id, encode_pin_state(state)],
            )
            .map_err(db_error)?;
        if changed == 0 {
            return Err(CacheError::PinNotFound);
        }
        drop(db);
        self.refresh_pin(pin_id)
    }

    /// Update the stable-ID pin target only when the caller has freshly
    /// resolved that same ID from complete metadata. A missing target may be
    /// marked unavailable while preserving its last known path for recovery.
    pub fn set_pin_refresh_target(
        &self,
        scope: &CacheScope,
        pin_id: &str,
        root_resource_id: &str,
        path: &str,
        state: PinState,
    ) -> Result<PinInfo, CacheError> {
        validate_id(root_resource_id)?;
        validate_path(path)?;
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let changed = db.execute(
            "UPDATE pins SET root_path=?4,state=?5 WHERE scope_key=?1 AND pin_id=?2 AND root_id=?3",
            params![scope.key, pin_id, root_resource_id, path, encode_pin_state(state)],
        ).map_err(db_error)?;
        if changed == 0 {
            return Err(CacheError::PinNotFound);
        }
        drop(db);
        self.refresh_pin(pin_id)
    }

    /// Atomically replace an existing pin manifest only after its staging copy
    /// is complete. The old pin keeps its versions protected on every failure.
    pub fn replace_pin_snapshot(
        &self,
        scope: &CacheScope,
        active_pin_id: &str,
        staging_pin_id: &str,
    ) -> Result<PinInfo, CacheError> {
        self.replace_pin_snapshot_cancellable(scope, active_pin_id, staging_pin_id, || false)
    }

    pub fn mark_policy_unavailable(
        &self,
        scope: &CacheScope,
        resource_id: &str,
    ) -> Result<(), CacheError> {
        let (path, etag) = {
            let db = self.lock_db()?;
            validate_registered_scope(&db, scope)?;
            db.query_row("SELECT target_path,target_etag FROM policies WHERE scope_key=?1 AND resource_id=?2 AND policy=1",
                params![scope.key,resource_id], |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?)))
                .optional().map_err(db_error)?.ok_or(CacheError::NotFound)?
        };
        self.set_policy_refresh_state(scope, resource_id, &path, &etag, TargetState::Unavailable)
    }

    pub fn policy(
        &self,
        scope: &CacheScope,
        resource_id: &str,
    ) -> Result<AvailabilityPolicy, CacheError> {
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let value = db
            .query_row(
                "SELECT policy FROM policies WHERE scope_key=?1 AND resource_id=?2",
                params![scope.key, resource_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(db_error)?;
        let own = match value.unwrap_or(0) {
            0 => AvailabilityPolicy::Recent,
            1 => AvailabilityPolicy::AlwaysOffline,
            2 => AvailabilityPolicy::CloudOnly,
            _ => return Err(CacheError::Corrupt),
        };
        if folder_policy::inherited_cloud_only(&db, scope, resource_id)? {
            if own == AvailabilityPolicy::AlwaysOffline {
                return Err(CacheError::PolicyConflict);
            }
            return Ok(AvailabilityPolicy::CloudOnly);
        }
        Ok(own)
    }

    /// Read one bounded page of unfinished ordinary-file retention intents.
    /// This is saved intent, not proof of content readiness or resumable stage bytes.
    /// Callers must resolve current authenticated metadata before starting new work.
    pub fn pending_plaintext_offline_intents(
        &self,
        scope: &CacheScope,
        after_resource_id: Option<&str>,
    ) -> Result<Vec<PendingOfflineIntent>, CacheError> {
        if scope.protection != ScopeProtection::PlaintextAllowed {
            return Err(CacheError::ProtectionMismatch);
        }
        if let Some(after) = after_resource_id {
            validate_id(after)?;
        }
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let mut stmt = db.prepare(
            "SELECT p.resource_id,p.target_path,p.target_etag,r.revision,p.target_state FROM policies p LEFT JOIN policy_intent_revisions r ON r.scope_key=p.scope_key AND r.resource_id=p.resource_id WHERE p.scope_key=?1 AND p.policy=1 AND p.target_state<>0 AND (?2 IS NULL OR p.resource_id>?2) ORDER BY p.resource_id LIMIT 8",
        ).map_err(db_error)?;
        let rows = stmt
            .query_map(params![scope.key, after_resource_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })
            .map_err(db_error)?;
        let mut result = Vec::new();
        for row in rows {
            let (resource_id, path, etag, revision, target_state) = row.map_err(db_error)?;
            decode_target_state(target_state).map_err(db_error)?;
            validate_id(&resource_id)?;
            validate_path(&path)?;
            validate_id(&etag)?;
            let revision = revision
                .filter(|value| *value > 0)
                .ok_or(CacheError::Corrupt)?;
            result.push(PendingOfflineIntent {
                resource_id,
                path,
                etag,
                revision,
            });
        }
        Ok(result)
    }

    /// Inspect saved unfinished intent for one exact ordinary resource. This does
    /// not establish current remote metadata, content readiness or resumable bytes.
    pub fn pending_plaintext_offline_intent(
        &self,
        scope: &CacheScope,
        resource_id: &str,
    ) -> Result<Option<PendingOfflineIntent>, CacheError> {
        if scope.protection != ScopeProtection::PlaintextAllowed {
            return Err(CacheError::ProtectionMismatch);
        }
        validate_id(resource_id)?;
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let row = db.query_row(
            "SELECT p.target_path,p.target_etag,r.revision,p.target_state FROM policies p LEFT JOIN policy_intent_revisions r ON r.scope_key=p.scope_key AND r.resource_id=p.resource_id WHERE p.scope_key=?1 AND p.resource_id=?2 AND p.policy=1 AND p.target_state<>0",
            params![scope.key, resource_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Option<i64>>(2)?, row.get::<_, i64>(3)?)),
        ).optional().map_err(db_error)?;
        let Some((path, etag, revision, state)) = row else {
            return Ok(None);
        };
        decode_target_state(state).map_err(db_error)?;
        validate_path(&path)?;
        validate_id(&etag)?;
        let revision = revision
            .filter(|value| *value > 0)
            .ok_or(CacheError::Corrupt)?;
        Ok(Some(PendingOfflineIntent {
            resource_id: resource_id.to_owned(),
            path,
            etag,
            revision,
        }))
    }

    pub fn policy_target_state(
        &self,
        scope: &CacheScope,
        resource_id: &str,
    ) -> Result<Option<TargetState>, CacheError> {
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let value = db.query_row(
            "SELECT target_state FROM policies WHERE scope_key=?1 AND resource_id=?2 AND policy=1",
            params![scope.key,resource_id], |row| row.get::<_,i64>(0),
        ).optional().map_err(db_error)?;
        value.map(decode_target_state).transpose().map_err(db_error)
    }

    pub fn publish_content<R: Read>(
        &self,
        scope: &CacheScope,
        version: &ContentVersion,
        source: &mut R,
        expected_len: u64,
        retention: Retention,
    ) -> Result<ContentRecord, CacheError> {
        self.publish_content_internal(
            scope,
            version,
            source,
            expected_len,
            retention,
            scope.protection == ScopeProtection::PlaintextAllowed,
        )
    }

    /// Publish an ordinary Recent version only if its additional allocation
    /// fits this cache's configured quota. This never evicts protected data.
    /// Callers may attempt clean eviction first, but admission is rechecked
    /// under the publication lease so concurrent writers cannot oversubscribe.
    /// The source must already be locally verified; do not perform network
    /// requests while this short publication operation holds its lease.
    pub fn publish_recent_content_with_budget<R: Read>(
        &self,
        scope: &CacheScope,
        version: &ContentVersion,
        source: &mut R,
        expected_len: u64,
    ) -> Result<ContentRecord, CacheError> {
        if scope.protection != ScopeProtection::PlaintextAllowed
            || version.protection != ContentProtection::Plaintext
        {
            return Err(CacheError::ProtectionMismatch);
        }
        validate_content_version(version)?;
        if expected_len > MAX_CONTENT_BYTES || expected_len > i64::MAX as u64 {
            return Err(CacheError::LimitExceeded);
        }
        self.publish_content_internal_with_hook(
            scope,
            version,
            source,
            expected_len,
            ContentPublishOptions {
                retention: Retention::Recent,
                recent_budget: true,
                require_listed: true,
                expected_ciphertext_epoch: None,
                pin_build: None,
                ciphertext_write: None,
            },
            || {},
        )
    }

    fn publish_content_internal<R: Read>(
        &self,
        scope: &CacheScope,
        version: &ContentVersion,
        source: &mut R,
        expected_len: u64,
        retention: Retention,
        require_listed: bool,
    ) -> Result<ContentRecord, CacheError> {
        validate_content_version(version)?;
        if expected_len > MAX_CONTENT_BYTES || expected_len > i64::MAX as u64 {
            return Err(CacheError::LimitExceeded);
        }
        validate_protection(scope, version.protection)?;
        self.publish_content_internal_with_hook(
            scope,
            version,
            source,
            expected_len,
            ContentPublishOptions {
                retention,
                recent_budget: false,
                require_listed,
                expected_ciphertext_epoch: None,
                pin_build: None,
                ciphertext_write: None,
            },
            || {},
        )
    }

    /// Publishes an encrypted blob only if the scope has not been invalidated
    /// since the caller captured `expected_epoch` before its network read.
    pub fn publish_ciphertext_if_epoch<R: Read>(
        &self,
        scope: &CacheScope,
        version: &ContentVersion,
        source: &mut R,
        expected_len: u64,
        retention: Retention,
        expected_epoch: u64,
    ) -> Result<ContentRecord, CacheError> {
        require_ciphertext_scope(scope)?;
        validate_content_version(version)?;
        if expected_len > MAX_CONTENT_BYTES || expected_len > i64::MAX as u64 {
            return Err(CacheError::LimitExceeded);
        }
        validate_protection(scope, version.protection)?;
        self.publish_content_internal_with_hook(
            scope,
            version,
            source,
            expected_len,
            ContentPublishOptions {
                retention,
                recent_budget: false,
                require_listed: false,
                expected_ciphertext_epoch: Some(expected_epoch),
                pin_build: None,
                ciphertext_write: None,
            },
            || {},
        )
    }

    /// Atomically publishes verified encrypted content and links it to an
    /// in-progress encrypted pin generation. This prevents recent-cache LRU
    /// eviction from racing a pin traversal between blob publication and its
    /// durable pin reference.
    pub fn publish_ciphertext_for_pin_if_epoch<R: Read>(
        &self,
        scope: &CacheScope,
        version: &ContentVersion,
        source: &mut R,
        expected_len: u64,
        build: &CiphertextPinBuild,
        kind: CiphertextPinItemKind,
    ) -> Result<ContentRecord, CacheError> {
        require_ciphertext_scope(scope)?;
        validate_content_version(version)?;
        validate_ciphertext_pin_build(scope, build)?;
        if expected_len > MAX_CONTENT_BYTES || expected_len > i64::MAX as u64 {
            return Err(CacheError::LimitExceeded);
        }
        if version.protection != ContentProtection::Ciphertext {
            return Err(CacheError::ProtectionMismatch);
        }
        self.publish_content_internal_with_hook(
            scope,
            version,
            source,
            expected_len,
            ContentPublishOptions {
                retention: Retention::Recent,
                recent_budget: false,
                require_listed: false,
                expected_ciphertext_epoch: Some(build.epoch),
                pin_build: Some((build.id.clone(), build.generation, kind)),
                ciphertext_write: None,
            },
            || {},
        )
    }

    fn publish_content_internal_with_hook<R: Read, H: FnOnce()>(
        &self,
        scope: &CacheScope,
        version: &ContentVersion,
        source: &mut R,
        expected_len: u64,
        options: ContentPublishOptions,
        after_blob_publish: H,
    ) -> Result<ContentRecord, CacheError> {
        #[cfg(windows)]
        let windows_store = Some(&self.inner.windows_content);
        #[cfg(windows)]
        let windows_lease = windows_store
            .map(|store| store.publication_lease())
            .transpose()?;
        #[cfg(windows)]
        let _publication_lease = if windows_store.is_some() {
            None
        } else {
            Some(self.lock_content_publication()?)
        };
        #[cfg(not(windows))]
        let _publication_lease = if options.recent_budget {
            // Budget admission must serialize with all other publications and
            // eviction, including independent Cache handles/processes.
            self.lock_content_deletion()?
        } else {
            self.lock_content_publication()?
        };
        {
            let db = self.lock_db()?;
            register_scope(&db, scope)?;
            if let Some(expected) = options.expected_ciphertext_epoch {
                if ensure_ciphertext_epoch(&db, scope)? != i64::try_from(expected).unwrap_or(-1) {
                    return Err(CacheError::Conflict);
                }
            }
            if let Some((pin_id, generation, _)) = &options.pin_build {
                let expected = options
                    .expected_ciphertext_epoch
                    .ok_or(CacheError::InvalidScope)?;
                validate_ciphertext_pin_build_fields(scope, pin_id, *generation, expected)?;
                ensure_ciphertext_pin_build_db(&db, scope, pin_id, *generation, expected)?;
            }
            if let Some(write) = &options.ciphertext_write {
                validate_ciphertext_write_publish(scope, write)?;
                ensure_ciphertext_write_revision_db(&db, scope, write)?;
            }
            if options.recent_budget {
                let existing = match load_content_record(&db, scope, version) {
                    Ok(record) if record.byte_len == expected_len => true,
                    Ok(_) => return Err(CacheError::Corrupt),
                    Err(CacheError::NotFound) => false,
                    Err(error) => return Err(error),
                };
                let used = total_content_bytes(&db)?;
                #[cfg(windows)]
                let used = {
                    let store = windows_store.ok_or(CacheError::UnsafeDirectory)?;
                    let lease = windows_lease.as_ref().ok_or(CacheError::UnsafeDirectory)?;
                    let inventory = windows_content_inventory(&db, store, lease)?;
                    used.saturating_add(inventory.unindexed_bytes)
                        .max(inventory.physical_bytes)
                };
                // Reusing an indexed immutable version allocates no new bytes.
                // Existing Dirty/Recovery content may legitimately exceed quota.
                if !existing
                    && used
                        .checked_add(expected_len)
                        .is_none_or(|total| total > self.inner.quota_bytes)
                {
                    return Err(CacheError::InsufficientSpace);
                }
            }
            let content_count: i64 = db
                .query_row(
                    "SELECT COUNT(*) FROM contents WHERE content_key=?1 OR scope_key=?2",
                    params![content_key(scope, version), scope.key],
                    |row| row.get(0),
                )
                .map_err(db_error)?;
            if content_count as usize >= MAX_CONTENT_RECORDS {
                return Err(CacheError::LimitExceeded);
            }
            if options.require_listed && scope.protection == ScopeProtection::PlaintextAllowed {
                validate_version_in_metadata(&db, scope, version, expected_len)?;
            }
            let policy: Option<i64> = db
                .query_row(
                    "SELECT policy FROM policies WHERE scope_key=?1 AND resource_id=?2",
                    params![scope.key, version.resource_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(db_error)?;
            if options.retention == Retention::Recent
                && (policy == Some(AvailabilityPolicy::CloudOnly as i64)
                    || folder_policy::inherited_cloud_only(&db, scope, &version.resource_id)?)
            {
                return Err(CacheError::PolicyConflict);
            }
        }
        let content_key = content_key(scope, version);
        let relative_path = format!("{content_key}.blob");
        let destination = self.inner.content_dir.join(&relative_path);
        if scope.protection == ScopeProtection::CiphertextOnly && !self.has_windows_content() {
            self.preflight_ciphertext_space(expected_len)?;
        }
        // Keep the exact immutable Windows receipt alive through metadata commit.
        // Failed publication/commit preserves bytes for recovery, never path-unlinks.
        #[cfg(windows)]
        let windows_receipt = match (windows_store, windows_lease.as_ref()) {
            (Some(store), Some(lease)) => {
                Some(store.publish_under_lease(lease, &relative_path, source, expected_len)?)
            }
            _ => None,
        };
        #[cfg(windows)]
        let published = windows_receipt
            .as_ref()
            .map(|receipt| (receipt.byte_len, receipt.digest.clone(), false));
        #[cfg(not(windows))]
        let published: Option<(u64, String, bool)> = None;
        let (byte_len, digest, cleanup_new_portable_blob) = match published {
            Some(metadata) => metadata,
            None => write_content_atomically(
                &self.inner.content_dir,
                &destination,
                source,
                expected_len,
            )?,
        };
        after_blob_publish();
        let mut db = self.lock_db()?;
        register_scope(&db, scope)?;
        if let Some(expected) = options.expected_ciphertext_epoch {
            if ensure_ciphertext_epoch(&db, scope)? != i64::try_from(expected).unwrap_or(-1) {
                let referenced: bool = db
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM contents WHERE content_key=?1)",
                        [content_key.as_str()],
                        |row| row.get(0),
                    )
                    .map_err(db_error)?;
                if cleanup_new_portable_blob && !referenced {
                    remove_unreferenced_blob(&self.inner.content_dir, &destination)?;
                }
                return Err(CacheError::Conflict);
            }
        }
        let policy: Option<i64> = db
            .query_row(
                "SELECT policy FROM policies WHERE scope_key=?1 AND resource_id=?2",
                params![scope.key, version.resource_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(db_error)?;
        let inherited_policy = if options.retention == Retention::Recent
            && policy != Some(AvailabilityPolicy::CloudOnly as i64)
        {
            folder_policy::inherited_cloud_only(&db, scope, &version.resource_id)
        } else {
            Ok(false)
        };
        if options.retention == Retention::Recent
            && (policy == Some(AvailabilityPolicy::CloudOnly as i64)
                || !matches!(&inherited_policy, Ok(false)))
        {
            // This check shares the DB lock with CloudOnly publication. Remove
            // only an unreferenced blob this call created; existing immutable
            // versions and protected records belong to other cache users.
            let referenced: bool = db
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM contents WHERE content_key=?1)",
                    [content_key.as_str()],
                    |row| row.get(0),
                )
                .map_err(db_error)?;
            if cleanup_new_portable_blob && !referenced {
                match fs::remove_file(&destination) {
                    Ok(()) => sync_directory(&self.inner.content_dir)?,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => {
                        // Keep a retryable accounting row if cleanup fails.
                        // CloudOnly blocks new opens, and a later CloudOnly
                        // request can retry unlinking this Recent record.
                        db.execute(
                            "INSERT INTO contents(content_key,scope_key,resource_id,etag,protection,byte_len,sha256,relative_path,last_accessed,retention) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,0)",
                            params![content_key,scope.key,version.resource_id,version.etag,version.protection as i64,i64_from_u64(byte_len)?,digest,relative_path,now_unix()],
                        )
                        .map_err(db_error)?;
                        return Err(CacheError::Io(error.to_string()));
                    }
                }
            }
            return Err(inherited_policy.err().unwrap_or(CacheError::PolicyConflict));
        }
        let tx = db.transaction().map_err(db_error)?;
        if options.require_listed && scope.protection == ScopeProtection::PlaintextAllowed {
            // The source may block while a fresh listing replaces or invalidates
            // the admitted version. Recheck under the index transaction, after
            // staging, so those bytes cannot become a newly usable cache entry.
            if let Err(error) = validate_version_in_metadata(&tx, scope, version, expected_len) {
                tx.rollback().map_err(db_error)?;
                if cleanup_new_portable_blob {
                    let referenced: bool = db
                        .query_row(
                            "SELECT EXISTS(SELECT 1 FROM contents WHERE content_key=?1)",
                            [content_key.as_str()],
                            |row| row.get(0),
                        )
                        .map_err(db_error)?;
                    if !referenced {
                        remove_unreferenced_blob(&self.inner.content_dir, &destination)?;
                    }
                }
                return Err(error);
            }
        }
        if let Some(write) = &options.ciphertext_write {
            if let Err(error) = ensure_ciphertext_write_revision_db(&tx, scope, write) {
                tx.rollback().map_err(db_error)?;
                if cleanup_new_portable_blob {
                    remove_unreferenced_blob(&self.inner.content_dir, &destination)?;
                }
                return Err(error);
            }
        }
        if let Some((pin_id, generation, _)) = &options.pin_build {
            ensure_ciphertext_pin_build_db(
                &tx,
                scope,
                pin_id,
                *generation,
                options
                    .expected_ciphertext_epoch
                    .ok_or(CacheError::InvalidScope)?,
            )?;
        }
        tx.execute(
            "INSERT INTO contents(content_key,scope_key,resource_id,etag,protection,byte_len,sha256,relative_path,last_accessed,retention) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10) ON CONFLICT(content_key) DO UPDATE SET last_accessed=excluded.last_accessed,retention=MAX(contents.retention,excluded.retention)",
            params![content_key,scope.key,version.resource_id,version.etag,version.protection as i64,i64_from_u64(byte_len)?,digest,relative_path,now_unix(),options.retention as i64],
        ).map_err(db_error)?;
        if let Some((pin_id, generation, kind)) = &options.pin_build {
            insert_ciphertext_pin_reference(
                &tx,
                scope,
                CiphertextPinReference {
                    pin_id,
                    generation: *generation,
                    version,
                    content_key: &content_key,
                    byte_len,
                    kind: *kind,
                },
            )?;
        }
        if let Some(write) = &options.ciphertext_write {
            tx.execute(
                "INSERT INTO ciphertext_writes(scope_key,write_id,revision,content_key,state,created_at,target_key,plaintext_len,operation,parent_key,parent_operation_key,dependency_key) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12) ON CONFLICT(scope_key,write_id) DO UPDATE SET revision=excluded.revision,content_key=excluded.content_key,state=excluded.state,created_at=excluded.created_at,target_key=excluded.target_key,plaintext_len=excluded.plaintext_len,operation=excluded.operation,parent_key=excluded.parent_key,parent_operation_key=excluded.parent_operation_key,dependency_key=excluded.dependency_key",
                params![scope.key,write.id,i64_from_u64(write.revision)?,content_key,write.state as i64,now_unix(),write.target_key,i64_from_u64(write.plaintext_len)?,write.operation as i64,write.parent_key,write.parent_operation_key,write.dependency_key],
            ).map_err(db_error)?;
        }
        tx.commit().map_err(db_error)?;
        Ok(ContentRecord {
            version: version.clone(),
            byte_len,
            sha256: digest,
            retention: options.retention,
        })
    }

    pub fn open_content(
        &self,
        scope: &CacheScope,
        version: &ContentVersion,
    ) -> Result<CacheContentReader, CacheError> {
        self.open_content_cancellable(scope, version, || false)
    }

    /// Verify a complete immutable object without holding database/publication
    /// guards during readback. No reader is exposed after observed cancellation.
    pub fn open_content_cancellable(
        &self,
        scope: &CacheScope,
        version: &ContentVersion,
        mut cancelled: impl FnMut() -> bool,
    ) -> Result<CacheContentReader, CacheError> {
        if cancelled() {
            return Err(CacheError::Cancelled);
        }
        validate_content_version(version)?;
        validate_protection(scope, version.protection)?;
        let key = content_key(scope, version);
        let path: Option<String> = {
            let db = self.lock_db()?;
            validate_registered_scope(&db, scope)?;
            db.query_row(
                "SELECT relative_path FROM contents WHERE content_key=?1 AND scope_key=?2 AND resource_id=?3 AND etag=?4 AND protection=?5",
                params![key,scope.key,version.resource_id,version.etag,version.protection as i64],
                |row| row.get(0),
            ).optional().map_err(db_error)?
        };
        let relative_path = path.ok_or(CacheError::NotFound)?;
        validate_object_filename(&relative_path)?;
        let full_path = self.inner.content_dir.join(&relative_path);
        let portable_file = if self.has_windows_content() {
            None
        } else {
            Some(open_private_file(&full_path)?)
        };
        let (expected_len, expected_digest, policy, retention): (i64, String, i64, i64) = {
            let db = self.lock_db()?;
            validate_registered_scope(&db, scope)?;
            let mut row: (i64, String, i64, i64) = db
                .query_row(
                    "SELECT c.byte_len,c.sha256,COALESCE(p.policy,0),c.retention FROM contents c LEFT JOIN policies p ON p.scope_key=c.scope_key AND p.resource_id=c.resource_id WHERE c.content_key=?1",
                    params![key],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()
                .map_err(db_error)?
                .ok_or(CacheError::NotFound)?;
            if row.3 == Retention::Recent as i64
                && folder_policy::inherited_cloud_only(&db, scope, &version.resource_id)?
            {
                row.2 = AvailabilityPolicy::CloudOnly as i64;
            }
            row
        };
        if policy == AvailabilityPolicy::CloudOnly as i64 && retention == Retention::Recent as i64 {
            return Err(CacheError::PolicyConflict);
        }
        let file = match portable_file {
            Some(mut file) => {
                let (actual_len, actual_digest) = hash_file_cancellable(&mut file, &mut cancelled)?;
                if actual_len != expected_len as u64 || actual_digest != expected_digest {
                    return Err(CacheError::Corrupt);
                }
                file.rewind().map_err(io_error)?;
                CacheContentReader::portable(file)
            }
            None => {
                #[cfg(windows)]
                {
                    self.inner
                        .windows_content
                        .open_verified_cancellable(
                            &relative_path,
                            u64::try_from(expected_len).map_err(|_| CacheError::Corrupt)?,
                            &expected_digest,
                            &mut cancelled,
                        )?
                        .into()
                }
                #[cfg(not(windows))]
                {
                    return Err(CacheError::UnsafeDirectory);
                }
            }
        };
        if cancelled() {
            return Err(CacheError::Cancelled);
        }
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        // Hashing is deliberately outside the DB lock. Re-admit the reader
        // against any intent committed while verification was in flight.
        // Ordinary LRU eviction alone does not revoke an already opened FD;
        // its absent row retains the original protection for this decision.
        let current_retention: i64 = db
            .query_row(
                "SELECT retention FROM contents WHERE content_key=?1",
                [&key],
                |row| row.get(0),
            )
            .optional()
            .map_err(db_error)?
            .unwrap_or(retention);
        let current_policy: i64 = db
            .query_row(
                "SELECT policy FROM policies WHERE scope_key=?1 AND resource_id=?2",
                params![scope.key, version.resource_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(db_error)?
            .unwrap_or(AvailabilityPolicy::Recent as i64);
        if current_retention == Retention::Recent as i64
            && (current_policy == AvailabilityPolicy::CloudOnly as i64
                || folder_policy::inherited_cloud_only(&db, scope, &version.resource_id)?)
        {
            return Err(CacheError::PolicyConflict);
        }
        db.execute(
            "UPDATE contents SET last_accessed=?2 WHERE content_key=?1",
            params![key, now_unix()],
        )
        .map_err(db_error)?;
        Ok(file)
    }

    pub fn content_record(
        &self,
        scope: &CacheScope,
        version: &ContentVersion,
    ) -> Result<ContentRecord, CacheError> {
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        load_content_record(&db, scope, version)
    }

    pub fn evict_recent(&self, target_quota: u64) -> Result<EvictionReport, CacheError> {
        self.evict_recent_with_hook(target_quota, || {})
    }

    /// Attempt a small Recent-only eviction pass. Protected content is never
    /// removed, and the result may still be above the requested target.
    /// The candidate cap bounds deletion work, not total inventory-scan time.
    pub fn evict_recent_bounded(
        &self,
        target_quota: u64,
        max_candidates: usize,
    ) -> Result<EvictionReport, CacheError> {
        if max_candidates == 0 || max_candidates > 64 {
            return Err(CacheError::LimitExceeded);
        }
        self.evict_recent_with_limits(target_quota, max_candidates, || {})
    }

    fn evict_recent_with_hook(
        &self,
        target_quota: u64,
        after_commit: impl FnMut(),
    ) -> Result<EvictionReport, CacheError> {
        self.evict_recent_with_limits(target_quota, MAX_CONTENT_RECORDS, after_commit)
    }

    fn evict_recent_with_limits(
        &self,
        target_quota: u64,
        max_candidates: usize,
        mut after_commit: impl FnMut(),
    ) -> Result<EvictionReport, CacheError> {
        #[cfg(windows)]
        let windows_store = Some(&self.inner.windows_content);
        #[cfg(windows)]
        let windows_lease = windows_store
            .map(|store| store.publication_lease())
            .transpose()?;
        #[cfg(windows)]
        let _deletion_lease = if windows_store.is_some() {
            None
        } else {
            Some(self.lock_content_deletion()?)
        };
        #[cfg(not(windows))]
        let _deletion_lease = self.lock_content_deletion()?;
        let mut db = self.lock_db()?;
        let mut used = total_content_bytes(&db)?;
        #[cfg(windows)]
        if let (Some(store), Some(lease)) = (windows_store, windows_lease.as_ref()) {
            let inventory = windows_content_inventory(&db, store, lease)?;
            used = used
                .saturating_add(inventory.unindexed_bytes)
                .max(inventory.physical_bytes);
        }
        let mut removed = 0_u64;
        if used > target_quota {
            let mut statement = db
                .prepare(
                    "SELECT c.content_key,c.relative_path,c.byte_len FROM contents c WHERE c.retention=0 AND NOT EXISTS(SELECT 1 FROM policies pol WHERE pol.scope_key=c.scope_key AND pol.resource_id=c.resource_id AND pol.policy=1 AND pol.target_etag=c.etag) AND NOT EXISTS(SELECT 1 FROM pin_items pi JOIN pins p ON p.pin_id=pi.pin_id WHERE p.scope_key=c.scope_key AND pi.resource_id=c.resource_id AND pi.etag=c.etag) AND NOT EXISTS(SELECT 1 FROM ciphertext_pin_items cpi WHERE cpi.content_key=c.content_key) AND NOT EXISTS(SELECT 1 FROM ciphertext_writes cw WHERE cw.content_key=c.content_key) AND NOT EXISTS(SELECT 1 FROM writes w WHERE w.content_key=c.content_key AND w.state IN (0,1)) ORDER BY c.last_accessed ASC,c.content_key ASC LIMIT ?1",
                )
                .map_err(db_error)?;
            let records = statement
                .query_map(params![max_candidates as i64], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })
                .map_err(db_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(db_error)?;
            drop(statement);
            for (key, relative, bytes) in records {
                if used <= target_quota {
                    break;
                }
                validate_object_filename(&relative)?;
                let tx = db.transaction().map_err(db_error)?;
                let referenced = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM pin_items pi JOIN pins p ON p.pin_id=pi.pin_id JOIN contents c ON c.scope_key=p.scope_key AND c.resource_id=pi.resource_id AND c.etag=pi.etag WHERE c.content_key=?1) OR EXISTS(SELECT 1 FROM ciphertext_pin_items i WHERE i.content_key=?1) OR EXISTS(SELECT 1 FROM ciphertext_writes cw WHERE cw.content_key=?1) OR EXISTS(SELECT 1 FROM writes WHERE content_key=?1 AND state IN (0,1)) OR EXISTS(SELECT 1 FROM contents c JOIN policies p ON p.scope_key=c.scope_key AND p.resource_id=c.resource_id WHERE c.content_key=?1 AND p.policy=1 AND p.target_etag=c.etag)",
                    params![key],
                    |row| row.get::<_, bool>(0),
                ).map_err(db_error)?;
                if !referenced {
                    #[cfg(windows)]
                    let windows_candidate = match (windows_store, windows_lease.as_ref()) {
                        (Some(store), Some(lease)) => {
                            match store.prepare_eviction(lease, &relative) {
                                Ok(candidate) => Some(candidate),
                                Err(CacheError::Conflict) => {
                                    tx.rollback().map_err(db_error)?;
                                    continue;
                                }
                                Err(error) => return Err(error),
                            }
                        }
                        _ => None,
                    };
                    let deleted = tx
                        .execute(
                            "DELETE FROM contents WHERE content_key=?1 AND retention=0",
                            [key.as_str()],
                        )
                        .map_err(db_error)?;
                    tx.commit().map_err(db_error)?;
                    if deleted != 1 {
                        continue;
                    }
                    after_commit();
                    #[cfg(windows)]
                    let removal = match windows_candidate {
                        Some(Some(file)) => file.delete(),
                        Some(None) => Err(io::Error::from(io::ErrorKind::NotFound)),
                        None => fs::remove_file(self.inner.content_dir.join(relative)),
                    };
                    #[cfg(not(windows))]
                    let removal = fs::remove_file(self.inner.content_dir.join(relative));
                    match removal {
                        Ok(()) => {
                            let count = bytes.max(0) as u64;
                            removed = removed.saturating_add(count);
                            used = used.saturating_sub(count);
                        }
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {
                            used = used.saturating_sub(bytes.max(0) as u64);
                        }
                        Err(error) => return Err(CacheError::Io(error.to_string())),
                    }
                } else {
                    tx.rollback().map_err(db_error)?;
                }
            }
        }
        if !self.has_windows_content() {
            sync_directory(&self.inner.content_dir)?;
        }
        let protected = protected_content_bytes(&db)?;
        #[cfg(windows)]
        let (used, protected) = match (windows_store, windows_lease.as_ref()) {
            (Some(store), Some(lease)) => {
                let inventory = windows_content_inventory(&db, store, lease)?;
                (
                    total_content_bytes(&db)?
                        .saturating_add(inventory.unindexed_bytes)
                        .max(inventory.physical_bytes),
                    protected.saturating_add(inventory.unindexed_bytes),
                )
            }
            _ => (used, protected),
        };
        Ok(EvictionReport {
            removed_bytes: removed,
            used_bytes: used,
            protected_bytes: protected,
            over_quota: used > target_quota,
        })
    }

    pub fn evict_to_quota(&self) -> Result<EvictionReport, CacheError> {
        self.evict_recent(self.inner.quota_bytes)
    }

    /// Pin a complete recursive metadata manifest. Every directory snapshot in
    /// the tree must be complete and represented exactly; files become ready
    /// only after their matching verified content versions are cached.
    pub fn begin_pin(
        &self,
        scope: &CacheScope,
        root_resource_id: &str,
        manifest: &[PinManifestEntry],
    ) -> Result<PinInfo, CacheError> {
        let path = if root_resource_id == scope.root_resource_id {
            "/".to_owned()
        } else {
            let db = self.lock_db()?;
            validate_registered_scope(&db, scope)?;
            db.query_row(
                "SELECT e.path FROM listing_entries e JOIN listings l ON l.scope_key=e.scope_key AND l.parent_id=e.parent_id AND l.generation=e.generation WHERE e.scope_key=?1 AND e.resource_id=?2 AND e.directory=1 AND l.complete=1 ORDER BY l.fetched_at DESC LIMIT 1",
                params![scope.key,root_resource_id], |row| row.get::<_,String>(0),
            ).optional().map_err(db_error)?.ok_or(CacheError::IncompleteManifest)?
        };
        self.begin_pin_at(scope, root_resource_id, &path, manifest)
    }

    pub fn begin_pin_at(
        &self,
        scope: &CacheScope,
        root_resource_id: &str,
        root_path: &str,
        manifest: &[PinManifestEntry],
    ) -> Result<PinInfo, CacheError> {
        let pin = self.begin_pin_manifest_at_cancellable(
            scope,
            root_resource_id,
            root_path,
            manifest,
            || false,
        )?;
        self.refresh_pin(&pin.id)
    }

    /// Persist a complete metadata manifest without hashing cached content.
    /// The returned pin is Building until an explicit readiness refresh succeeds.
    /// Cancellation before the commit rolls back admission. After the final probe,
    /// commit wins and returns the durable ID so callers can preserve/reconcile it.
    /// The probe must not block or reenter this cache. Metadata validation remains
    /// bounded by the existing manifest limits; no content I/O occurs here.
    pub fn begin_pin_manifest_at_cancellable(
        &self,
        scope: &CacheScope,
        root_resource_id: &str,
        root_path: &str,
        manifest: &[PinManifestEntry],
        cancelled: impl FnMut() -> bool,
    ) -> Result<PinInfo, CacheError> {
        self.persist_pin_manifest(
            scope,
            (root_resource_id, root_path, PinAdmission::Generic),
            manifest,
            cancelled,
        )
    }

    /// Admit an initial ordinary-folder pin only if no saved pin already owns
    /// this exact scope/root identity or path. This check and insertion share
    /// one immediate transaction, including across independent cache handles.
    /// Existing saved intent must be explicitly resumed/refreshed, not duplicated.
    pub fn begin_initial_pin_manifest_at_cancellable(
        &self,
        scope: &CacheScope,
        root_resource_id: &str,
        root_path: &str,
        manifest: &[PinManifestEntry],
        cancelled: impl FnMut() -> bool,
    ) -> Result<PinInfo, CacheError> {
        self.persist_pin_manifest(
            scope,
            (root_resource_id, root_path, PinAdmission::Initial),
            manifest,
            cancelled,
        )
    }

    fn persist_pin_manifest(
        &self,
        scope: &CacheScope,
        target: (&str, &str, PinAdmission<'_>),
        manifest: &[PinManifestEntry],
        mut cancelled: impl FnMut() -> bool,
    ) -> Result<PinInfo, CacheError> {
        let (root_resource_id, root_path, admission) = target;
        let initial = matches!(admission, PinAdmission::Initial);
        if cancelled() {
            return Err(CacheError::Cancelled);
        }
        if scope.protection == ScopeProtection::CiphertextOnly {
            return Err(CacheError::ProtectionMismatch);
        }
        validate_id(root_resource_id)?;
        validate_path(root_path)?;
        if manifest.len() > MAX_LISTING_ENTRIES {
            return Err(CacheError::IncompleteManifest);
        }
        validate_manifest(root_resource_id, manifest)?;
        if cancelled() {
            return Err(CacheError::Cancelled);
        }
        if initial && manifest.iter().any(|item| item.entry.encrypted) {
            return Err(CacheError::ProtectionMismatch);
        }
        let mut db = self.pin_db(&mut cancelled)?;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        validate_registered_scope(&tx, scope)?;
        if initial {
            let existing: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM pins WHERE scope_key=?1 AND (root_id=?2 OR root_path=?3))",
                params![scope.key, root_resource_id, root_path], |row| row.get(0),
            ).map_err(db_error)?;
            if existing {
                return Err(CacheError::Conflict);
            }
        }
        if root_resource_id != scope.root_resource_id {
            let known_directory: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM listing_entries e JOIN listings l ON l.scope_key=e.scope_key AND l.parent_id=e.parent_id AND l.generation=e.generation WHERE e.scope_key=?1 AND e.resource_id=?2 AND e.path=?3 AND e.directory=1 AND e.encrypted=0 AND l.complete=1)",
                    params![scope.key, root_resource_id, root_path],
                    |row| row.get(0),
                )
                .map_err(db_error)?;
            if !known_directory {
                return Err(CacheError::IncompleteManifest);
            }
        }
        validate_complete_manifest_in_db(&tx, scope, root_resource_id, manifest)?;
        // A pin above a CloudOnly folder can include that folder in its
        // manifest even when the pin root itself has no inherited intent.
        // Check every member before admitting any pin rows or roles.
        if folder_policy::has_intents(&tx, scope)? {
            if folder_policy::inherited_cloud_only(&tx, scope, root_resource_id)? {
                return Err(CacheError::PolicyConflict);
            }
            for item in manifest {
                if cancelled() {
                    return Err(CacheError::Cancelled);
                }
                if folder_policy::inherited_cloud_only(&tx, scope, &item.entry.id)? {
                    return Err(CacheError::PolicyConflict);
                }
            }
        }
        let pin_count: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM pins WHERE scope_key=?1",
                params![scope.key],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if pin_count as usize >= MAX_PIN_RECORDS {
            return Err(CacheError::LimitExceeded);
        }
        let total_pin_items: i64 = tx
            .query_row("SELECT COUNT(*) FROM pin_items", [], |row| row.get(0))
            .map_err(db_error)?;
        if (total_pin_items.max(0) as usize).saturating_add(manifest.len()) > MAX_TOTAL_PIN_ITEMS {
            return Err(CacheError::LimitExceeded);
        }
        // A process-local counter and second-resolution clock can repeat after
        // a restart or in another cache owner. Keep the existing 64-hex opaque
        // ID format without depending on process lifetime or wall-clock time.
        let mut random = [0u8; 32];
        getrandom::fill(&mut random)
            .map_err(|_| CacheError::Io("secure random generation failed".into()))?;
        let pin_id = random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        tx.execute(
            "INSERT INTO pins(pin_id,scope_key,root_id,root_path,state,created_at) VALUES(?1,?2,?3,?4,0,?5)",
            params![pin_id, scope.key, root_resource_id, root_path, now_unix()],
        )
        .map_err(db_error)?;
        for item in manifest {
            if cancelled() {
                return Err(CacheError::Cancelled);
            }
            tx.execute(
                "INSERT INTO pin_items(pin_id,resource_id,parent_id,name,path,etag,size,directory,encrypted) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![pin_id,item.entry.id,item.parent_resource_id,leaf_name(&item.entry.path)?,item.entry.path,item.entry.etag,i64_from_u64(item.entry.size)?,item.entry.directory as i64,item.entry.encrypted as i64],
            ).map_err(db_error)?;
        }
        folder_pin_roles::admit_role(&tx, scope, root_resource_id, root_path, &pin_id, admission)?;
        if cancelled() {
            return Err(CacheError::Cancelled);
        }
        tx.commit().map_err(db_error)?;
        Ok(PinInfo {
            id: pin_id,
            root_resource_id: root_resource_id.to_owned(),
            root_path: root_path.to_owned(),
            state: PinState::Building,
            item_count: manifest.len(),
            ready_content_count: 0,
            required_content_count: manifest.iter().filter(|item| !item.entry.directory).count(),
        })
    }

    pub fn refresh_pin(&self, pin_id: &str) -> Result<PinInfo, CacheError> {
        self.refresh_pin_cancellable(pin_id, || false)
    }

    /// Recompute and return durable pin progress. `refresh_pin` verifies every
    /// referenced file version before reporting Ready.
    pub fn pin_info(&self, pin_id: &str) -> Result<PinInfo, CacheError> {
        self.refresh_pin(pin_id)
    }

    pub fn pin_info_for_scope(
        &self,
        scope: &CacheScope,
        pin_id: &str,
    ) -> Result<PinInfo, CacheError> {
        {
            let db = self.lock_db()?;
            validate_registered_scope(&db, scope)?;
            let matches: bool = db
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM pins WHERE pin_id=?1 AND scope_key=?2)",
                    params![pin_id, scope.key],
                    |row| row.get(0),
                )
                .map_err(db_error)?;
            if !matches {
                return Err(CacheError::PinNotFound);
            }
        }
        self.refresh_pin(pin_id)
    }

    pub fn pins(&self, scope: &CacheScope) -> Result<Vec<PinInfo>, CacheError> {
        let ids = {
            let db = self.lock_db()?;
            validate_registered_scope(&db, scope)?;
            let mut statement = db
                .prepare("SELECT pin_id FROM pins WHERE scope_key=?1 ORDER BY created_at,pin_id")
                .map_err(db_error)?;
            statement
                .query_map(params![scope.key], |row| row.get::<_, String>(0))
                .map_err(db_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(db_error)?
        };
        ids.iter()
            .map(|id| self.refresh_pin(id))
            .collect::<Result<Vec<_>, _>>()
    }

    pub fn cancel_pin(&self, pin_id: &str) -> Result<(), CacheError> {
        let db = self.lock_db()?;
        let changed = db
            .execute("DELETE FROM pins WHERE pin_id=?1", params![pin_id])
            .map_err(db_error)?;
        if changed == 0 {
            Err(CacheError::PinNotFound)
        } else {
            Ok(())
        }
    }

    pub fn cancel_pin_for_scope(&self, scope: &CacheScope, pin_id: &str) -> Result<(), CacheError> {
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let changed = db
            .execute(
                "DELETE FROM pins WHERE pin_id=?1 AND scope_key=?2",
                params![pin_id, scope.key],
            )
            .map_err(db_error)?;
        if changed == 0 {
            Err(CacheError::PinNotFound)
        } else {
            Ok(())
        }
    }

    /// Persist an explicit conditional file write for later reconciliation.
    /// Deletion is deliberately absent: cache eviction is never a delete plan.
    pub fn queue_conditional_write<R: Read>(
        &self,
        scope: &CacheScope,
        request: ConditionalWriteRequest,
        source: &mut R,
    ) -> Result<QueuedWrite, CacheError> {
        #[cfg(windows)]
        let windows_store = Some(&self.inner.windows_content);
        #[cfg(windows)]
        let windows_lease = windows_store
            .map(|store| store.publication_lease())
            .transpose()?;
        #[cfg(windows)]
        let publication_lease = if windows_store.is_some() {
            None
        } else {
            Some(self.lock_content_publication()?)
        };
        #[cfg(not(windows))]
        let publication_lease = self.lock_content_publication()?;
        if scope.protection == ScopeProtection::CiphertextOnly {
            return Err(CacheError::ProtectionMismatch);
        }
        let ConditionalWriteRequest {
            parent_resource_id,
            name,
            logical_path,
            resource_id,
            base,
            expected_len,
            protection,
        } = request;
        validate_id(&parent_resource_id)?;
        validate_name(&name)?;
        validate_path(&logical_path)?;
        if leaf_name(&logical_path)? != name {
            return Err(CacheError::InvalidEntry);
        }
        if expected_len > MAX_CONTENT_BYTES || expected_len > i64::MAX as u64 {
            return Err(CacheError::LimitExceeded);
        }
        validate_protection(scope, protection)?;
        if let Some(resource_id) = &resource_id {
            validate_id(resource_id)?;
        }
        if let WriteCondition::Match(etag) = &base
            && (etag.is_empty() || etag.len() > MAX_SCOPE_FIELD)
        {
            return Err(CacheError::Conflict);
        }
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let (generation,): (i64,) = db
            .query_row(
                "SELECT generation FROM listings WHERE scope_key=?1 AND parent_id=?2 AND complete=1",
                params![scope.key,parent_resource_id],
                |row| Ok((row.get(0)?,)),
            )
            .optional()
            .map_err(db_error)?
            .ok_or(CacheError::IncompleteListing)?;
        let listed: Option<(String, String, bool, bool)> = db
            .query_row(
                "SELECT resource_id,etag,directory,writable FROM listing_entries WHERE scope_key=?1 AND parent_id=?2 AND generation=?3 AND name=?4",
                params![scope.key,parent_resource_id,generation,name],
                |row| Ok((row.get(0)?,row.get(1)?,row.get::<_,i64>(2)? != 0,row.get::<_,i64>(3)? != 0)),
            )
            .optional()
            .map_err(db_error)?;
        match (&base, resource_id.as_deref(), listed) {
            (WriteCondition::Absent, None, None) => {}
            (
                WriteCondition::Match(expected),
                Some(resource),
                Some((found_resource, found_etag, directory, writable)),
            ) if expected == &found_etag
                && resource == found_resource
                && !directory
                && writable => {}
            _ => return Err(CacheError::Conflict),
        }
        let pending_count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM writes WHERE scope_key=?1 AND state IN (0,1)",
                params![scope.key],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        let record_count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM writes WHERE scope_key=?1",
                params![scope.key],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        let same_target_pending: bool = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM writes WHERE scope_key=?1 AND parent_id=?2 AND name=?3 AND state IN (0,1))",
                params![scope.key, parent_resource_id, name],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if pending_count as usize >= MAX_JOURNAL_ENTRIES
            || record_count as usize >= MAX_JOURNAL_RECORDS
            || same_target_pending
        {
            return Err(CacheError::LimitExceeded);
        }
        drop(db);
        let content_version = ContentVersion {
            resource_id: resource_id.clone().unwrap_or_else(|| {
                hash_fields(&[&scope.key, &parent_resource_id, &name, &logical_path])
            }),
            // Journal bytes are a distinct immutable version. Reusing the
            // base ETag here would overwrite the cached remote snapshot that
            // the conditional write is based on.
            etag: next_journal_etag(scope, &logical_path),
            protection,
        };
        let key = content_key(scope, &content_version);
        let relative_path = format!("{key}.blob");
        let destination = self.inner.content_dir.join(&relative_path);
        #[cfg(windows)]
        let windows_receipt = match (windows_store, windows_lease.as_ref()) {
            (Some(store), Some(lease)) => {
                Some(store.publish_under_lease(lease, &relative_path, source, expected_len)?)
            }
            _ => None,
        };
        #[cfg(windows)]
        let published = windows_receipt
            .as_ref()
            .map(|receipt| (receipt.byte_len, receipt.digest.clone()));
        #[cfg(not(windows))]
        let published: Option<(u64, String)> = None;
        let (byte_len, digest) = match published {
            Some(metadata) => metadata,
            None => {
                let (length, digest, _) = write_content_atomically(
                    &self.inner.content_dir,
                    &destination,
                    source,
                    expected_len,
                )?;
                (length, digest)
            }
        };
        let db = self.lock_db()?;
        let tx = db.unchecked_transaction().map_err(db_error)?;
        let pending_count: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM writes WHERE scope_key=?1 AND state IN (0,1)",
                params![scope.key],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        let record_count: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM writes WHERE scope_key=?1",
                params![scope.key],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        let same_target_pending: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM writes WHERE scope_key=?1 AND parent_id=?2 AND name=?3 AND state IN (0,1))",
                params![scope.key, parent_resource_id, name],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if same_target_pending
            || pending_count as usize >= MAX_JOURNAL_ENTRIES
            || record_count as usize >= MAX_JOURNAL_RECORDS
        {
            tx.rollback().map_err(db_error)?;
            drop(db);
            drop(publication_lease);
            if !self.has_windows_content() {
                self.remove_unindexed_content()?;
            }
            return Err(CacheError::LimitExceeded);
        }
        tx.execute(
            "INSERT INTO contents(content_key,scope_key,resource_id,etag,protection,byte_len,sha256,relative_path,last_accessed,retention) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10) ON CONFLICT(content_key) DO UPDATE SET last_accessed=excluded.last_accessed,retention=MAX(contents.retention,excluded.retention)",
            params![key,scope.key,content_version.resource_id,content_version.etag,content_version.protection as i64,i64_from_u64(byte_len)?,digest,relative_path,now_unix(),Retention::Dirty as i64],
        )
        .map_err(db_error)?;
        let (base_kind, base_etag) = match &base {
            WriteCondition::Absent => (0, String::new()),
            WriteCondition::Match(etag) => (1, etag.clone()),
        };
        let created_at_unix = now_unix();
        tx.execute(
            "INSERT INTO writes(scope_key,parent_id,name,path,resource_id,base_kind,base_etag,content_key,state,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,0,?9)",
            params![scope.key,parent_resource_id,name,logical_path,resource_id,base_kind,base_etag,key,created_at_unix],
        ).map_err(db_error)?;
        let id = tx.last_insert_rowid();
        tx.commit().map_err(db_error)?;
        Ok(QueuedWrite {
            id,
            parent_resource_id,
            name,
            logical_path,
            resource_id,
            base,
            content: content_version,
            state: WriteState::Pending,
            created_at_unix,
        })
    }

    pub fn pending_writes(&self, scope: &CacheScope) -> Result<Vec<QueuedWrite>, CacheError> {
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let mut statement = db.prepare(
            "SELECT id,parent_id,name,path,resource_id,base_kind,base_etag,content_key,state,created_at FROM writes WHERE scope_key=?1 ORDER BY id",
        ).map_err(db_error)?;
        let rows = statement
            .query_map(params![scope.key], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                ))
            })
            .map_err(db_error)?;
        let mut out = Vec::new();
        for row in rows {
            let (id, parent, name, path, resource, base_kind, base_etag, key, state, created) =
                row.map_err(db_error)?;
            let (resource_id, etag, protection): (String, String, i64) = db
                .query_row(
                    "SELECT resource_id,etag,protection FROM contents WHERE content_key=?1",
                    params![key],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(db_error)?;
            out.push(QueuedWrite {
                id,
                parent_resource_id: parent,
                name,
                logical_path: path,
                resource_id: resource,
                base: if base_kind == 0 {
                    WriteCondition::Absent
                } else if base_kind == 1 {
                    WriteCondition::Match(base_etag)
                } else {
                    return Err(CacheError::Corrupt);
                },
                content: ContentVersion {
                    resource_id,
                    etag,
                    protection: decode_content_protection(protection)?,
                },
                state: decode_write_state(state)?,
                created_at_unix: created,
            });
        }
        Ok(out)
    }

    /// Replace the bytes for an existing pending/conflicted target without
    /// changing its original conditional base. The replacement is published
    /// as a new immutable content version before the row is switched, so a
    /// failed copy or database transaction leaves the previous dirty version
    /// recoverable.
    pub fn replace_pending_conditional_write<R: Read>(
        &self,
        scope: &CacheScope,
        request: ConditionalWriteRequest,
        source: &mut R,
    ) -> Result<QueuedWrite, CacheError> {
        #[cfg(windows)]
        let windows_store = Some(&self.inner.windows_content);
        #[cfg(windows)]
        let windows_lease = windows_store
            .map(|store| store.publication_lease())
            .transpose()?;
        #[cfg(windows)]
        let publication_lease = if windows_store.is_some() {
            None
        } else {
            Some(self.lock_content_publication()?)
        };
        #[cfg(not(windows))]
        let publication_lease = self.lock_content_publication()?;
        if scope.protection == ScopeProtection::CiphertextOnly {
            return Err(CacheError::ProtectionMismatch);
        }
        let ConditionalWriteRequest {
            parent_resource_id,
            name,
            logical_path,
            resource_id,
            base,
            expected_len,
            protection,
        } = request;
        validate_id(&parent_resource_id)?;
        validate_name(&name)?;
        validate_path(&logical_path)?;
        if leaf_name(&logical_path)? != name
            || expected_len > MAX_CONTENT_BYTES
            || expected_len > i64::MAX as u64
        {
            return Err(CacheError::LimitExceeded);
        }
        validate_protection(scope, protection)?;
        if let Some(resource_id) = &resource_id {
            validate_id(resource_id)?;
        }
        if let WriteCondition::Match(etag) = &base
            && (etag.is_empty() || etag.len() > MAX_SCOPE_FIELD)
        {
            return Err(CacheError::Conflict);
        }
        let (id, old_state, old_content_key, created_at_unix) = {
            let db = self.lock_db()?;
            validate_registered_scope(&db, scope)?;
            let existing: (i64, i64, String, Option<String>, i64, String, i64) = db
                .query_row(
                    "SELECT id,base_kind,base_etag,resource_id,state,content_key,created_at FROM writes WHERE scope_key=?1 AND parent_id=?2 AND name=?3 AND state IN (0,1)",
                    params![scope.key,parent_resource_id,name],
                    |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?)),
                )
                .optional()
                .map_err(db_error)?
                .ok_or(CacheError::NotFound)?;
            let (id, base_kind, base_etag, old_resource, state, old_content_key, created_at_unix) =
                existing;
            let base_matches = match (&base, base_kind) {
                (WriteCondition::Absent, 0) => base_etag.is_empty(),
                (WriteCondition::Match(expected), 1) => expected == &base_etag,
                _ => false,
            };
            if !base_matches || old_resource.as_deref() != resource_id.as_deref() {
                return Err(CacheError::Conflict);
            }
            (id, state, old_content_key, created_at_unix)
        };
        let content_version = ContentVersion {
            resource_id: resource_id.clone().unwrap_or_else(|| {
                hash_fields(&[&scope.key, &parent_resource_id, &name, &logical_path])
            }),
            etag: next_journal_etag(scope, &logical_path),
            protection,
        };
        let key = content_key(scope, &content_version);
        let relative_path = format!("{key}.blob");
        let destination = self.inner.content_dir.join(&relative_path);
        #[cfg(windows)]
        let windows_receipt = match (windows_store, windows_lease.as_ref()) {
            (Some(store), Some(lease)) => {
                Some(store.publish_under_lease(lease, &relative_path, source, expected_len)?)
            }
            _ => None,
        };
        #[cfg(windows)]
        let published = windows_receipt
            .as_ref()
            .map(|receipt| (receipt.byte_len, receipt.digest.clone()));
        #[cfg(not(windows))]
        let published: Option<(u64, String)> = None;
        let (byte_len, digest) = match published {
            Some(metadata) => metadata,
            None => {
                let (length, digest, _) = write_content_atomically(
                    &self.inner.content_dir,
                    &destination,
                    source,
                    expected_len,
                )?;
                (length, digest)
            }
        };
        let db = self.lock_db()?;
        let tx = db.unchecked_transaction().map_err(db_error)?;
        let still_same: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM writes WHERE id=?1 AND scope_key=?2 AND parent_id=?3 AND name=?4 AND resource_id IS ?5 AND state=?6 AND content_key=?7)",
                params![id,scope.key,parent_resource_id,name,resource_id,old_state,old_content_key],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if !still_same {
            tx.rollback().map_err(db_error)?;
            drop(db);
            drop(publication_lease);
            if !self.has_windows_content() {
                self.remove_unindexed_content()?;
            }
            return Err(CacheError::Conflict);
        }
        tx.execute(
            "INSERT INTO contents(content_key,scope_key,resource_id,etag,protection,byte_len,sha256,relative_path,last_accessed,retention) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![key,scope.key,content_version.resource_id,content_version.etag,content_version.protection as i64,i64_from_u64(byte_len)?,digest,relative_path,now_unix(),Retention::Dirty as i64],
        )
        .map_err(db_error)?;
        tx.execute(
            "UPDATE writes SET content_key=?3 WHERE id=?1 AND scope_key=?2",
            params![id, scope.key, key],
        )
        .map_err(db_error)?;
        if old_content_key != key {
            if self.has_windows_content() {
                // Keep superseded bytes indexed for recovery until identity-bound
                // orphan retirement is implemented. Never forget their quota use.
                tx.execute(
                    "UPDATE contents SET retention=2 WHERE content_key=?1 AND etag LIKE 'journal-%' AND NOT EXISTS(SELECT 1 FROM writes WHERE content_key=?1)",
                    params![old_content_key],
                ).map_err(db_error)?;
            } else {
                tx.execute(
                    "DELETE FROM contents WHERE content_key=?1 AND etag LIKE 'journal-%' AND NOT EXISTS(SELECT 1 FROM writes WHERE content_key=?1)",
                    params![old_content_key],
                ).map_err(db_error)?;
            }
        }
        tx.commit().map_err(db_error)?;
        drop(db);
        drop(publication_lease);
        if !self.has_windows_content() {
            self.remove_unindexed_content()?;
        }
        Ok(QueuedWrite {
            id,
            parent_resource_id,
            name,
            logical_path,
            resource_id,
            base,
            content: content_version,
            state: decode_write_state(old_state)?,
            created_at_unix,
        })
    }

    /// Return a single pending/conflicted journal item by exact logical path.
    /// Verified rows are retained for recovery history but do not shadow the
    /// server version.
    pub fn pending_write_for_path(
        &self,
        scope: &CacheScope,
        path: &str,
    ) -> Result<Option<QueuedWrite>, CacheError> {
        validate_path(path)?;
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let row: Option<PendingWriteRow> = db.query_row(
                "SELECT w.id,w.parent_id,w.name,w.path,w.resource_id,w.base_kind,w.base_etag,w.content_key,w.state,w.created_at FROM writes w WHERE w.scope_key=?1 AND w.path=?2 AND w.state IN (0,1) ORDER BY w.id DESC LIMIT 1",
                params![scope.key,path],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?)),
            )
            .optional()
            .map_err(db_error)?;
        let Some((
            id,
            parent_id,
            name,
            logical_path,
            resource_id,
            base_kind,
            base_etag,
            key,
            state,
            created,
        )) = row
        else {
            return Ok(None);
        };
        let (content_resource, etag, protection): (String, String, i64) = db
            .query_row(
                "SELECT resource_id,etag,protection FROM contents WHERE content_key=?1 AND scope_key=?2",
                params![key,scope.key],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
            )
            .optional()
            .map_err(db_error)?
            .ok_or(CacheError::Corrupt)?;
        Ok(Some(QueuedWrite {
            id,
            parent_resource_id: parent_id,
            name,
            logical_path,
            resource_id,
            base: if base_kind == 0 {
                WriteCondition::Absent
            } else if base_kind == 1 {
                WriteCondition::Match(base_etag)
            } else {
                return Err(CacheError::Corrupt);
            },
            content: ContentVersion {
                resource_id: content_resource,
                etag,
                protection: decode_content_protection(protection)?,
            },
            state: decode_write_state(state)?,
            created_at_unix: created,
        }))
    }

    pub fn pending_writes_for_parent(
        &self,
        scope: &CacheScope,
        parent_resource_id: &str,
    ) -> Result<Vec<QueuedWrite>, CacheError> {
        validate_id(parent_resource_id)?;
        Ok(self
            .pending_writes(scope)?
            .into_iter()
            .filter(|write| write.parent_resource_id == parent_resource_id)
            .collect())
    }

    /// Page the active account's ordinary pending-write journal without
    /// network access. Ciphertext-only scopes are excluded because decrypted
    /// paths and names must never be projected through this API.
    pub fn pending_write_page(
        &self,
        origin: &str,
        account_id: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<PendingWritePage, CacheError> {
        let origin = Url::parse(origin)
            .map_err(|_| CacheError::InvalidScope)?
            .origin()
            .ascii_serialization();
        self.pending_write_page_inner(Some(&origin), account_id, after, limit)
    }

    /// The local journal view remains available after sign-out when this
    /// profile still has a stable account identity but no live Engine.
    pub fn pending_write_page_for_account(
        &self,
        account_id: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<PendingWritePage, CacheError> {
        self.pending_write_page_inner(None, account_id, after, limit)
    }

    fn pending_write_page_inner(
        &self,
        origin: Option<&str>,
        account_id: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<PendingWritePage, CacheError> {
        if account_id.is_empty()
            || account_id.len() > MAX_SCOPE_FIELD
            || !(1..=100).contains(&limit)
        {
            return Err(CacheError::InvalidScope);
        }
        let after = after
            .map(|cursor| cursor.parse::<i64>().map_err(|_| CacheError::InvalidScope))
            .transpose()?
            .unwrap_or(0);
        if after < 0 {
            return Err(CacheError::InvalidScope);
        }
        let db = self.lock_db()?;
        let (pending_count, conflict_count): (i64, i64) = match origin {
            Some(origin) => db.query_row(
                "SELECT COALESCE(SUM(CASE WHEN w.state=0 THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN w.state=1 THEN 1 ELSE 0 END),0) FROM writes w JOIN scopes s ON s.scope_key=w.scope_key WHERE s.origin=?1 AND s.account_id=?2 AND s.protection=?3 AND w.state IN (0,1)",
                params![origin, account_id, ScopeProtection::PlaintextAllowed as i64],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ),
            None => db.query_row(
                "SELECT COALESCE(SUM(CASE WHEN w.state=0 THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN w.state=1 THEN 1 ELSE 0 END),0) FROM writes w JOIN scopes s ON s.scope_key=w.scope_key WHERE s.account_id=?1 AND s.protection=?2 AND w.state IN (0,1)",
                params![account_id, ScopeProtection::PlaintextAllowed as i64],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ),
        }.map_err(db_error)?;
        let mut statement = match origin {
            Some(_) => db.prepare(
                "SELECT s.space_id,s.root_resource_id,w.id,w.path,w.state,c.byte_len,w.created_at FROM writes w JOIN scopes s ON s.scope_key=w.scope_key JOIN contents c ON c.content_key=w.content_key AND c.scope_key=w.scope_key WHERE s.origin=?1 AND s.account_id=?2 AND s.protection=?3 AND w.state IN (0,1) AND w.id>?4 ORDER BY w.id LIMIT ?5",
            ),
            None => db.prepare(
                "SELECT s.space_id,s.root_resource_id,w.id,w.path,w.state,c.byte_len,w.created_at FROM writes w JOIN scopes s ON s.scope_key=w.scope_key JOIN contents c ON c.content_key=w.content_key AND c.scope_key=w.scope_key WHERE s.account_id=?1 AND s.protection=?2 AND w.state IN (0,1) AND w.id>?3 ORDER BY w.id LIMIT ?4",
            ),
        }.map_err(db_error)?;
        let rows = match origin {
            Some(origin) => statement.query_map(
                params![
                    origin,
                    account_id,
                    ScopeProtection::PlaintextAllowed as i64,
                    after,
                    (limit + 1) as i64
                ],
                pending_write_item_from_row,
            ),
            None => statement.query_map(
                params![
                    account_id,
                    ScopeProtection::PlaintextAllowed as i64,
                    after,
                    (limit + 1) as i64
                ],
                pending_write_item_from_row,
            ),
        }
        .map_err(db_error)?;
        let mut items = rows.collect::<Result<Vec<_>, _>>().map_err(db_error)?;
        let truncated = items.len() > limit;
        if truncated {
            items.pop();
        }
        let next_after = truncated
            .then(|| items.last().map(|item| item.write_id.to_string()))
            .flatten();
        Ok(PendingWritePage {
            items,
            pending_count: pending_count.max(0) as u64,
            conflict_count: conflict_count.max(0) as u64,
            next_after,
            truncated,
        })
    }

    /// Copy one still-conflicted ordinary journal record for the exact account
    /// and Space into a caller-owned staging writer. This never changes journal
    /// state and never exposes ciphertext-only scopes. The caller must publish
    /// its staging writer only after this method succeeds.
    pub fn copy_conflict_write_for_account<W: Write>(
        &self,
        account_id: &str,
        space_id: &str,
        write_id: i64,
        output: &mut W,
    ) -> Result<PendingWriteItem, CacheError> {
        self.copy_unresolved_write_for_account(account_id, space_id, write_id, None, true, output)
    }

    /// Copy an unresolved ordinary saved edit under its exact persisted scope.
    /// This does not consult listings, make a network request, or retire a write.
    /// Output is staging-only until success; a failed integrity check may have
    /// written partial bytes, which the caller must never publish.
    pub fn copy_saved_write<W: Write>(
        &self,
        scope: &CacheScope,
        write_id: i64,
        output: &mut W,
    ) -> Result<PendingWriteItem, CacheError> {
        if scope.protection != ScopeProtection::PlaintextAllowed {
            return Err(CacheError::InvalidScope);
        }
        self.copy_unresolved_write_for_account(
            &scope.account_id,
            &scope.space_id,
            write_id,
            Some(scope),
            false,
            output,
        )
    }

    fn copy_unresolved_write_for_account<W: Write>(
        &self,
        account_id: &str,
        space_id: &str,
        write_id: i64,
        expected_scope: Option<&CacheScope>,
        conflict_only: bool,
        output: &mut W,
    ) -> Result<PendingWriteItem, CacheError> {
        if account_id.is_empty()
            || account_id.len() > MAX_SCOPE_FIELD
            || space_id.trim().is_empty()
            || space_id.len() > MAX_SCOPE_FIELD
            || write_id <= 0
        {
            return Err(CacheError::InvalidScope);
        }
        let (origin, stored_account, stored_space, root_id, path, state, referenced_content_key) = {
            let db = self.lock_db()?;
            let row: Option<(String, String, String, String, String, i64, String)> = db
                .query_row(
                    "SELECT s.origin,s.account_id,s.space_id,s.root_resource_id,w.path,w.state,w.content_key FROM writes w JOIN scopes s ON s.scope_key=w.scope_key WHERE w.id=?1 AND s.account_id=?2 AND s.space_id=?3 AND s.protection=?4",
                    params![write_id, account_id, space_id, ScopeProtection::PlaintextAllowed as i64],
                    |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?)),
                )
                .optional()
                .map_err(db_error)?;
            row.ok_or(CacheError::NotFound)?
        };
        if stored_account != account_id
            || stored_space != space_id
            || expected_scope.is_some_and(|expected| {
                expected.origin != origin || expected.root_resource_id != root_id
            })
        {
            return Err(CacheError::NotFound);
        }
        let write_state = decode_write_state(state)?;
        if !matches!(write_state, WriteState::Pending | WriteState::Conflict)
            || (conflict_only && write_state != WriteState::Conflict)
        {
            return Err(CacheError::Conflict);
        }
        validate_path(&path).map_err(|_| CacheError::Corrupt)?;
        let scope = CacheScope::new(
            &origin,
            &stored_account,
            &stored_space,
            &root_id,
            ScopeProtection::PlaintextAllowed,
        )?;
        let (resource_id, etag, protection, byte_len, retention): (String, String, i64, i64, i64) = {
            let db = self.lock_db()?;
            validate_registered_scope(&db, &scope)?;
            db.query_row(
                "SELECT resource_id,etag,protection,byte_len,retention FROM contents WHERE content_key=?1 AND scope_key=?2",
                params![referenced_content_key, scope.key],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
            )
            .optional()
            .map_err(db_error)?
            .ok_or(CacheError::NotFound)?
        };
        if decode_content_protection(protection)? != ContentProtection::Plaintext
            || decode_retention(retention)? != Retention::Dirty
            || byte_len < 0
            || byte_len as u64 > MAX_CONTENT_BYTES
        {
            return Err(CacheError::Corrupt);
        }
        let version = ContentVersion {
            resource_id,
            etag,
            protection: ContentProtection::Plaintext,
        };
        if content_key(&scope, &version) != referenced_content_key {
            return Err(CacheError::Corrupt);
        }
        let mut source = self.open_content(&scope, &version)?;
        let mut copied = 0_u64;
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = source.read(&mut buffer).map_err(io_error)?;
            if count == 0 {
                break;
            }
            copied = copied
                .checked_add(count as u64)
                .ok_or(CacheError::LimitExceeded)?;
            if copied > byte_len as u64 || copied > MAX_CONTENT_BYTES {
                return Err(CacheError::Corrupt);
            }
            output.write_all(&buffer[..count]).map_err(io_error)?;
            digest.update(&buffer[..count]);
        }
        if copied != byte_len as u64 {
            return Err(CacheError::Corrupt);
        }
        let digest = digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let expected_digest = self.content_record(&scope, &version)?.sha256;
        if digest != expected_digest {
            return Err(CacheError::Corrupt);
        }
        let still_unresolved: bool = {
            let db = self.lock_db()?;
            db.query_row(
                "SELECT EXISTS(SELECT 1 FROM writes w JOIN scopes s ON s.scope_key=w.scope_key WHERE w.id=?1 AND w.content_key=?2 AND w.state=?3 AND s.account_id=?4 AND s.space_id=?5 AND s.root_resource_id=?6 AND s.origin=?7 AND s.protection=?8)",
                params![write_id,referenced_content_key,state,account_id,space_id,root_id,origin,ScopeProtection::PlaintextAllowed as i64],
                |row| row.get(0),
            )
            .map_err(db_error)?
        };
        if !still_unresolved {
            return Err(CacheError::Conflict);
        }
        Ok(PendingWriteItem {
            space_id: stored_space,
            root_resource_id: root_id,
            write_id,
            path,
            state: write_state,
            bytes: copied,
            created_at_unix: {
                let db = self.lock_db()?;
                db.query_row(
                    "SELECT created_at FROM writes WHERE id=?1 AND content_key=?2 AND state=?3",
                    params![write_id, referenced_content_key, state],
                    |row| row.get::<_, i64>(0),
                )
                .optional()
                .map_err(db_error)?
                .ok_or(CacheError::Conflict)?
            },
        })
    }

    pub fn mark_write_conflict(&self, scope: &CacheScope, id: i64) -> Result<(), CacheError> {
        self.set_write_state(scope, id, WriteState::Conflict)
    }

    /// Mark a journal entry verified after the caller has conditionally
    /// uploaded and read back the exact new server version. Content remains
    /// retained until explicit recovery/cleanup policy is implemented.
    pub fn mark_write_verified(&self, scope: &CacheScope, id: i64) -> Result<(), CacheError> {
        self.set_write_state(scope, id, WriteState::Verified)
    }

    fn set_write_state(
        &self,
        scope: &CacheScope,
        id: i64,
        state: WriteState,
    ) -> Result<(), CacheError> {
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let changed = db
            .execute(
                "UPDATE writes SET state=?3 WHERE scope_key=?1 AND id=?2",
                params![scope.key, id, state as i64],
            )
            .map_err(db_error)?;
        if changed == 0 {
            Err(CacheError::NotFound)
        } else {
            Ok(())
        }
    }

    fn has_windows_content(&self) -> bool {
        #[cfg(windows)]
        {
            true
        }
        #[cfg(not(windows))]
        {
            false
        }
    }

    fn lock_db(&self) -> Result<std::sync::MutexGuard<'_, DbOwner>, CacheError> {
        self.inner
            .db
            .lock()
            .map_err(|_| CacheError::Database("cache lock is poisoned".into()))
    }

    fn lock_pin_generation(
        &self,
        scope: &CacheScope,
    ) -> Result<PinGenerationLease<'_>, CacheError> {
        #[cfg(windows)]
        {
            Ok(PinGenerationLease::Windows {
                _file: windows_lock::try_generation_lock(&self.inner.windows_root, scope)?,
            })
        }
        #[cfg(not(windows))]
        {
            let path = self
                .inner
                .root
                .join(format!("ciphertext-pin-generation-{}.lock", scope.key));
            prepare_db_file(&path)?;
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .map_err(io_error)?;
            fs2::FileExt::lock_exclusive(&file).map_err(io_error)?;
            Ok(PinGenerationLease::Portable {
                _file: file,
                _cache: self,
            })
        }
    }

    // A persistent per-directory lock fences orphan scans against every blob
    // writer, including writers using another Cache instance or process. Never
    // unlink this file: replacement would split the coordination domain.
    fn content_publication_lock_file(&self) -> Result<File, CacheError> {
        // Unported deletion/orphan paths must not enter a different lock domain.
        if self.has_windows_content() {
            return Err(CacheError::UnsafeDirectory);
        }
        let path = self.inner.root.join("content-publication.lock");
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => {
                set_private_file(&file)?;
                file.sync_all().map_err(io_error)?;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(io_error(error)),
        }
        open_private_file(&path)
    }

    fn lock_content_deletion(&self) -> Result<File, CacheError> {
        let file = self.content_publication_lock_file()?;
        fs2::FileExt::lock_exclusive(&file).map_err(io_error)?;
        Ok(file)
    }

    fn lock_content_publication(&self) -> Result<File, CacheError> {
        let file = self.content_publication_lock_file()?;
        fs2::FileExt::lock_shared(&file).map_err(io_error)?;
        Ok(file)
    }

    fn remove_unindexed_content(&self) -> Result<(), CacheError> {
        #[cfg(windows)]
        if let Some(store) = Some(&self.inner.windows_content) {
            let lease = store.publication_lease()?;
            let db = self.lock_db()?;
            // Crash ambiguity cannot establish that an unindexed body is safe
            // to discard. Validate and account it, but preserve it for recovery.
            windows_content_inventory(&db, store, &lease)?;
            return Ok(());
        }
        let lease = self.content_publication_lock_file()?;
        match fs2::FileExt::try_lock_exclusive(&lease) {
            Ok(()) => {}
            // Cleanup is optional. Never wait while a caller may hold a pin
            // lease or be inside a publication callback. A later scan can
            // reclaim orphans; deleting live staging bytes is not recoverable.
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) => return Err(io_error(error)),
        }
        let known = {
            let db = self.lock_db()?;
            let mut statement = db
                .prepare("SELECT relative_path FROM contents")
                .map_err(db_error)?;
            statement
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(db_error)?
                .collect::<Result<BTreeSet<_>, _>>()
                .map_err(db_error)?
        };
        for name in &known {
            validate_object_filename(name)?;
        }
        for entry in fs::read_dir(&self.inner.content_dir).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| CacheError::Corrupt)?;
            let metadata = fs::symlink_metadata(entry.path()).map_err(io_error)?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(CacheError::UnsafeDirectory);
            }
            if name.starts_with(".stage-") {
                validate_private_file(&entry.path())?;
                fs::remove_file(entry.path()).map_err(io_error)?;
                continue;
            }
            validate_object_filename(&name)?;
            if !known.contains(&name) {
                fs::remove_file(entry.path()).map_err(io_error)?;
            }
        }
        Ok(())
    }
}

fn validate_complete_manifest_in_db(
    db: &Connection,
    scope: &CacheScope,
    root_resource_id: &str,
    manifest: &[PinManifestEntry],
) -> Result<(), CacheError> {
    let by_parent = manifest.iter().fold(
        BTreeMap::<String, BTreeSet<(String, String)>>::new(),
        |mut map, item| {
            map.entry(item.parent_resource_id.clone())
                .or_default()
                .insert((item.entry.id.clone(), item.entry.etag.clone()));
            map
        },
    );
    let directories = manifest
        .iter()
        .filter(|item| item.entry.directory)
        .map(|item| item.entry.id.clone())
        .chain(std::iter::once(root_resource_id.to_owned()));
    for parent in directories {
        let snapshot =
            load_listing(db, scope, &parent).map_err(|_| CacheError::IncompleteManifest)?;
        let observed: BTreeSet<_> = snapshot
            .entries
            .iter()
            .map(|item| (item.entry.id.clone(), item.entry.etag.clone()))
            .collect();
        let declared = by_parent.get(&parent).cloned().unwrap_or_default();
        if !snapshot.complete || observed != declared {
            return Err(CacheError::IncompleteManifest);
        }
        for item in manifest
            .iter()
            .filter(|item| item.parent_resource_id == parent)
        {
            let found = snapshot.entries.iter().any(|cached| {
                cached.entry.id == item.entry.id
                    && cached.entry == item.entry
                    && cached.parent_resource_id == item.parent_resource_id
            });
            if !found {
                return Err(CacheError::IncompleteManifest);
            }
        }
    }
    Ok(())
}

fn validate_manifest(
    root_resource_id: &str,
    manifest: &[PinManifestEntry],
) -> Result<(), CacheError> {
    let mut resource_ids = BTreeSet::new();
    let mut total = 0usize;
    for item in manifest {
        validate_id(&item.parent_resource_id)?;
        validate_entry(&item.entry)?;
        if item.entry.id == root_resource_id {
            return Err(CacheError::IncompleteManifest);
        }
        total = total
            .saturating_add(item.entry.id.len())
            .saturating_add(item.entry.path.len())
            .saturating_add(item.entry.etag.len());
        if total > MAX_LISTING_BYTES || !resource_ids.insert(item.entry.id.as_str()) {
            return Err(CacheError::IncompleteManifest);
        }
    }
    let directories: BTreeSet<_> = manifest
        .iter()
        .filter(|item| item.entry.directory)
        .map(|item| item.entry.id.as_str())
        .collect();
    if manifest.iter().any(|item| {
        item.parent_resource_id != root_resource_id
            && !directories.contains(item.parent_resource_id.as_str())
    }) {
        return Err(CacheError::IncompleteManifest);
    }
    let mut reachable = BTreeSet::from([root_resource_id]);
    loop {
        let before = reachable.len();
        for item in manifest {
            if reachable.contains(item.parent_resource_id.as_str()) && item.entry.directory {
                reachable.insert(item.entry.id.as_str());
            }
        }
        if before == reachable.len() {
            break;
        }
    }
    if manifest
        .iter()
        .any(|item| !reachable.contains(item.parent_resource_id.as_str()))
    {
        return Err(CacheError::IncompleteManifest);
    }
    Ok(())
}

fn validate_listing(entries: &[CachedEntry]) -> Result<(), CacheError> {
    if entries.len() > MAX_LISTING_ENTRIES {
        return Err(CacheError::LimitExceeded);
    }
    let mut ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    let mut bytes = 0usize;
    for item in entries {
        validate_id(&item.parent_resource_id)?;
        validate_entry(&item.entry)?;
        bytes = bytes
            .saturating_add(item.parent_resource_id.len())
            .saturating_add(item.entry.id.len())
            .saturating_add(item.entry.path.len())
            .saturating_add(item.entry.etag.len());
        if bytes > MAX_LISTING_BYTES
            || !ids.insert(item.entry.id.as_str())
            || !names.insert(leaf_name(&item.entry.path)?)
        {
            return Err(CacheError::InvalidEntry);
        }
    }
    Ok(())
}

fn validate_entry(entry: &RemoteEntry) -> Result<(), CacheError> {
    validate_id(&entry.id)?;
    validate_path(&entry.path)?;
    if entry.etag.len() > MAX_SCOPE_FIELD
        || entry.size > MAX_CONTENT_BYTES
        || leaf_name(&entry.path)?.len() > MAX_ENTRY_NAME_BYTES
    {
        return Err(CacheError::InvalidEntry);
    }
    Ok(())
}

fn validate_content_version(version: &ContentVersion) -> Result<(), CacheError> {
    validate_id(&version.resource_id)?;
    if version.etag.trim().is_empty() || version.etag.len() > MAX_SCOPE_FIELD {
        return Err(CacheError::InvalidContentVersion);
    }
    Ok(())
}

fn unique_ciphertext_retarget_etag(revision: u64) -> Result<String, CacheError> {
    let mut random = [0u8; 16];
    getrandom::fill(&mut random)
        .map_err(|_| CacheError::Io("secure random generation failed".into()))?;
    let suffix = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(format!("retarget-{revision}-{suffix}"))
}

fn validate_protection(
    scope: &CacheScope,
    protection: ContentProtection,
) -> Result<(), CacheError> {
    if ContentProtection::from(scope.protection) != protection {
        return Err(CacheError::ProtectionMismatch);
    }
    Ok(())
}

fn validate_id(value: &str) -> Result<(), CacheError> {
    if value.is_empty() || value.len() > MAX_SCOPE_FIELD || value.contains('\0') {
        Err(CacheError::InvalidEntry)
    } else {
        Ok(())
    }
}

fn validate_name(value: &str) -> Result<(), CacheError> {
    if value.is_empty()
        || value.len() > MAX_ENTRY_NAME_BYTES
        || value == "."
        || value == ".."
        || value.contains('/')
        || value.contains('\\')
        || value.contains('\0')
    {
        Err(CacheError::InvalidEntry)
    } else {
        Ok(())
    }
}

fn validate_path(value: &str) -> Result<(), CacheError> {
    if value == "/" {
        return Ok(());
    }
    if value.is_empty()
        || value.len() > MAX_PATH_BYTES
        || !value.starts_with('/')
        || value.contains('\0')
        || value
            .split('/')
            .skip(1)
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(CacheError::InvalidEntry);
    }
    Ok(())
}

fn leaf_name(path: &str) -> Result<&str, CacheError> {
    validate_path(path)?;
    let name = path.trim_end_matches('/').rsplit('/').next().unwrap_or("");
    if name.is_empty() {
        return Err(CacheError::InvalidEntry);
    }
    validate_name(name)?;
    Ok(name)
}

fn register_scope(db: &Connection, scope: &CacheScope) -> Result<(), CacheError> {
    let protection = scope.protection as i64;
    let existing: Option<(String,String,String,String,i64)> = db.query_row(
        "SELECT origin,account_id,space_id,root_resource_id,protection FROM scopes WHERE scope_key=?1",
        params![scope.key],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
    ).optional().map_err(db_error)?;
    if let Some((origin, account, space, root, found_protection)) = existing {
        if origin != scope.origin
            || account != scope.account_id
            || space != scope.space_id
            || root != scope.root_resource_id
            || found_protection != protection
        {
            return Err(CacheError::Conflict);
        }
        return Ok(());
    }
    let count: i64 = db
        .query_row("SELECT COUNT(*) FROM scopes", [], |row| row.get(0))
        .map_err(db_error)?;
    if count as usize >= MAX_SCOPES {
        return Err(CacheError::LimitExceeded);
    }
    db.execute(
        "INSERT INTO scopes(scope_key,origin,account_id,space_id,root_resource_id,protection) VALUES(?1,?2,?3,?4,?5,?6)",
        params![scope.key,scope.origin,scope.account_id,scope.space_id,scope.root_resource_id,protection],
    ).map_err(db_error)?;
    Ok(())
}

fn validate_ciphertext_pin_build_fields(
    scope: &CacheScope,
    pin_id: &str,
    generation: u64,
    _epoch: u64,
) -> Result<(), CacheError> {
    require_ciphertext_scope(scope)?;
    validate_ciphertext_pin_id(pin_id)?;
    if generation == 0 || generation > i64::MAX as u64 {
        return Err(CacheError::InvalidScope);
    }
    Ok(())
}

fn validate_ciphertext_pin_build(
    scope: &CacheScope,
    build: &CiphertextPinBuild,
) -> Result<(), CacheError> {
    validate_ciphertext_pin_build_fields(scope, &build.id, build.generation, build.epoch)?;
    if build.scope_key != scope.key || build.root_resource_id != scope.root_resource_id {
        return Err(CacheError::InvalidScope);
    }
    Ok(())
}

fn validate_ciphertext_pin_id(pin_id: &str) -> Result<(), CacheError> {
    if pin_id.len() != 32
        || !pin_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CacheError::InvalidScope);
    }
    Ok(())
}

fn validate_ciphertext_write_id(id: &str) -> Result<(), CacheError> {
    if id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(CacheError::InvalidEntry)
    }
}

fn ciphertext_target_key(encrypted_target: &str) -> Result<String, CacheError> {
    if encrypted_target.is_empty()
        || encrypted_target.len() > MAX_PATH_BYTES
        || encrypted_target.bytes().any(|byte| byte == 0)
    {
        return Err(CacheError::InvalidEntry);
    }
    let digest = Sha256::digest(encrypted_target.as_bytes());
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Return the opaque SHA-256 index used for one encrypted DAV-relative target.
/// The input must already be encrypted; plaintext paths must never be passed.
pub fn ciphertext_target_hash(encrypted_target: &str) -> Result<String, CacheError> {
    ciphertext_target_key(encrypted_target)
}

fn ciphertext_parent_key(encrypted_target: &str) -> Result<String, CacheError> {
    if encrypted_target.is_empty()
        || encrypted_target.len() > MAX_PATH_BYTES
        || encrypted_target.bytes().any(|byte| byte == 0)
        || encrypted_target.starts_with('/')
        || encrypted_target.ends_with('/')
        || encrypted_target.split('/').any(str::is_empty)
    {
        return Err(CacheError::InvalidEntry);
    }
    let parent = encrypted_target
        .rsplit_once('/')
        .map_or("", |(parent, _)| parent);
    ciphertext_parent_path_key(parent)
}

fn ciphertext_parent_path_key(encrypted_parent: &str) -> Result<String, CacheError> {
    if encrypted_parent.len() > MAX_PATH_BYTES
        || encrypted_parent.bytes().any(|byte| byte == 0)
        || encrypted_parent.starts_with('/')
        || encrypted_parent.ends_with('/')
        || (!encrypted_parent.is_empty() && encrypted_parent.split('/').any(str::is_empty))
    {
        return Err(CacheError::InvalidEntry);
    }
    let digest = Sha256::digest(encrypted_parent.as_bytes());
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn ciphertext_operation_key(id: &str, revision: u64) -> Result<String, CacheError> {
    validate_ciphertext_write_id(id)?;
    if revision == 0 || revision > i64::MAX as u64 {
        return Err(CacheError::LimitExceeded);
    }
    let revision = revision.to_string();
    let digest = Sha256::new();
    let mut hash = digest;
    hash.update(b"raiun-ciphertext-operation-v1\0");
    hash.update(id.as_bytes());
    hash.update(b"\0");
    hash.update(revision.as_bytes());
    let digest = hash.finalize();
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn decode_ciphertext_write_operation(value: i64) -> Result<CiphertextWriteOperation, CacheError> {
    match value {
        0 => Ok(CiphertextWriteOperation::Overwrite),
        1 => Ok(CiphertextWriteOperation::CreateFile),
        2 => Ok(CiphertextWriteOperation::RenameFile),
        3 => Ok(CiphertextWriteOperation::DeleteFile),
        4 => Ok(CiphertextWriteOperation::CreateDirectory),
        5 => Ok(CiphertextWriteOperation::CopyFile),
        _ => Err(CacheError::Corrupt),
    }
}

fn validate_ciphertext_write_build(
    scope: &CacheScope,
    build: &CiphertextWriteBuild,
) -> Result<(), CacheError> {
    require_ciphertext_scope(scope)?;
    validate_ciphertext_write_id(&build.id)?;
    if build.scope_key != scope.key
        || build.root_resource_id != scope.root_resource_id
        || build.revision == 0
        || build.revision > i64::MAX as u64
        || build.target_key.len() != 64
        || build.parent_key.len() != 64
        || build.dependency_key.len() != 64
        || (!build.parent_operation_key.is_empty() && build.parent_operation_key.len() != 64)
        || !build
            .target_key
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || !build
            .parent_key
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || !build
            .dependency_key
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || !build.parent_operation_key.is_empty()
            && !build
                .parent_operation_key
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        || build.expected_revision.is_some_and(|revision| {
            revision >= i64::MAX as u64 || build.revision != revision.saturating_add(1)
        })
        || (build.expected_revision.is_none() && build.revision != 1)
        || build.expected_target_key.is_some() != build.expected_state.is_some()
        || build
            .expected_target_key
            .as_ref()
            .is_some_and(|key| key.len() != 64 || !key.bytes().all(|byte| byte.is_ascii_hexdigit()))
        || (build.expected_target_key.is_some()
            && (build.expected_revision.is_none()
                || !matches!(
                    build.operation,
                    CiphertextWriteOperation::CreateFile
                        | CiphertextWriteOperation::CreateDirectory
                )
                || !matches!(
                    (build.publish_state, build.expected_state),
                    (
                        CiphertextWriteState::NeverAttempted,
                        Some(CiphertextWriteState::NeverAttempted)
                    ) | (
                        CiphertextWriteState::AcknowledgedReceipt,
                        Some(CiphertextWriteState::CancelledReceipt)
                    )
                )))
    {
        return Err(CacheError::InvalidScope);
    }
    Ok(())
}

fn validate_ciphertext_write_publish(
    scope: &CacheScope,
    write: &CiphertextWritePublish,
) -> Result<(), CacheError> {
    validate_ciphertext_write_id(&write.id)?;
    if write.revision == 0
        || write.revision > i64::MAX as u64
        || write.target_key.len() != 64
        || write.parent_key.len() != 64
        || write.dependency_key.len() != 64
        || (!write.parent_operation_key.is_empty() && write.parent_operation_key.len() != 64)
        || !write
            .target_key
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || !write
            .parent_key
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || !write
            .dependency_key
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || !write.parent_operation_key.is_empty()
            && !write
                .parent_operation_key
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        || write.expected_revision.is_some_and(|revision| {
            revision >= i64::MAX as u64 || write.revision != revision.saturating_add(1)
        })
        || (write.expected_revision.is_none() && write.revision != 1)
        || write.expected_target_key.is_some() != write.expected_state.is_some()
        || write
            .expected_target_key
            .as_ref()
            .is_some_and(|key| key.len() != 64 || !key.bytes().all(|byte| byte.is_ascii_hexdigit()))
        || (write.expected_target_key.is_some()
            && (write.expected_revision.is_none()
                || !matches!(
                    write.operation,
                    CiphertextWriteOperation::CreateFile
                        | CiphertextWriteOperation::CreateDirectory
                )
                || !matches!(
                    (write.state, write.expected_state),
                    (
                        CiphertextWriteState::NeverAttempted,
                        Some(CiphertextWriteState::NeverAttempted)
                    ) | (
                        CiphertextWriteState::AcknowledgedReceipt,
                        Some(CiphertextWriteState::CancelledReceipt)
                    )
                )))
    {
        return Err(CacheError::InvalidScope);
    }
    require_ciphertext_scope(scope)
}

fn ensure_ciphertext_write_revision_db(
    db: &Connection,
    scope: &CacheScope,
    write: &CiphertextWritePublish,
) -> Result<(), CacheError> {
    if write.expected_revision.is_none() && !write.parent_operation_key.is_empty() {
        let parent_available: bool = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM ciphertext_writes WHERE scope_key=?1 AND dependency_key=?2 AND operation=?3 AND state IN (?4,?5,?6,?7,?8))",
                params![
                    scope.key,
                    write.parent_operation_key,
                    CiphertextWriteOperation::CreateDirectory as i64,
                    CiphertextWriteState::Pending as i64,
                    CiphertextWriteState::Uncertain as i64,
                    CiphertextWriteState::CommittedReceipt as i64,
                    CiphertextWriteState::NeverAttempted as i64,
                    CiphertextWriteState::Attempting as i64
                ],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if !parent_available {
            return Err(CacheError::Conflict);
        }
    }
    if write.expected_revision.is_none() {
        let count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM ciphertext_writes WHERE scope_key=?1",
                [&scope.key],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if count < 0 || count as usize >= MAX_CIPHERTEXT_WRITES {
            return Err(CacheError::LimitExceeded);
        }
        if matches!(
            write.operation,
            CiphertextWriteOperation::CreateFile
                | CiphertextWriteOperation::DeleteFile
                | CiphertextWriteOperation::CreateDirectory
        ) {
            let parent_count: i64 = db
                .query_row(
                    "SELECT COUNT(*) FROM ciphertext_writes WHERE scope_key=?1 AND parent_key=?2 AND operation=?3",
                    params![scope.key, write.parent_key, write.operation as i64],
                    |row| row.get(0),
                )
                .map_err(db_error)?;
            if parent_count < 0 || parent_count as usize >= MAX_CIPHERTEXT_WRITES_PER_PARENT {
                return Err(CacheError::LimitExceeded);
            }
        }
    }
    let current: Option<(i64, String, i64, i64, String)> = db
        .query_row(
            "SELECT revision,target_key,operation,state,dependency_key FROM ciphertext_writes WHERE scope_key=?1 AND write_id=?2",
            params![scope.key, write.id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .optional()
        .map_err(db_error)?;
    if let (Some(expected_target), Some(expected_state)) =
        (&write.expected_target_key, write.expected_state)
    {
        match &current {
            Some((revision, target, operation, state, _))
                if write
                    .expected_revision
                    .and_then(|value| i64::try_from(value).ok())
                    == Some(*revision)
                    && target == expected_target
                    && decode_ciphertext_write_operation(*operation)? == write.operation
                    && decode_ciphertext_write_state(*state)? == expected_state => {}
            _ => return Err(CacheError::Conflict),
        }
        let dependency_key = current
            .as_ref()
            .map(|row| row.4.as_str())
            .ok_or(CacheError::Conflict)?;
        let has_children: bool = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM ciphertext_writes WHERE scope_key=?1 AND parent_operation_key=?2)",
                params![scope.key, dependency_key],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if has_children {
            return Err(CacheError::Conflict);
        }
        if write.state == CiphertextWriteState::AcknowledgedReceipt {
            let other_receipts: i64 = db
                .query_row(
                    "SELECT COUNT(*) FROM ciphertext_writes WHERE scope_key=?1 AND write_id<>?2 AND state IN (?3,?4)",
                    params![
                        scope.key,
                        write.id,
                        CiphertextWriteState::CancelledReceipt as i64,
                        CiphertextWriteState::AcknowledgedReceipt as i64,
                    ],
                    |row| row.get(0),
                )
                .map_err(db_error)?;
            if other_receipts < 0 || other_receipts as usize >= MAX_CANCEL_ACK_RECEIPTS_PER_SCOPE {
                return Err(CacheError::LimitExceeded);
            }
        }
        let target_exists: bool = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM ciphertext_writes WHERE scope_key=?1 AND target_key=?2 AND write_id<>?3)",
                params![scope.key, write.target_key, write.id],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if target_exists {
            return Err(CacheError::Conflict);
        }
        if !write.parent_operation_key.is_empty() {
            let parent_available: bool = db
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM ciphertext_writes WHERE scope_key=?1 AND dependency_key=?2 AND operation=?3 AND state IN (?4,?5,?6,?7,?8))",
                    params![scope.key,write.parent_operation_key,CiphertextWriteOperation::CreateDirectory as i64,CiphertextWriteState::Pending as i64,CiphertextWriteState::Uncertain as i64,CiphertextWriteState::CommittedReceipt as i64,CiphertextWriteState::NeverAttempted as i64,CiphertextWriteState::Attempting as i64],
                    |row| row.get(0),
                )
                .map_err(db_error)?;
            if !parent_available {
                return Err(CacheError::Conflict);
            }
        }
        let parent_count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM ciphertext_writes WHERE scope_key=?1 AND parent_key=?2 AND operation=?3 AND write_id<>?4",
                params![scope.key,write.parent_key,write.operation as i64,write.id],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if parent_count < 0 || parent_count as usize >= MAX_CIPHERTEXT_WRITES_PER_PARENT {
            return Err(CacheError::LimitExceeded);
        }
    }
    match (write.expected_revision, current.map(|row| row.0)) {
        (None, None) => {
            let count: i64 = db
                .query_row(
                    "SELECT COUNT(*) FROM ciphertext_writes WHERE scope_key=?1",
                    [&scope.key],
                    |row| row.get(0),
                )
                .map_err(db_error)?;
            if count < 0 || count as usize >= MAX_CIPHERTEXT_WRITES {
                Err(CacheError::LimitExceeded)
            } else {
                Ok(())
            }
        }
        (Some(expected), Some(current)) if i64::try_from(expected).ok() == Some(current) => Ok(()),
        (Some(_), None) => Err(CacheError::NotFound),
        _ => Err(CacheError::Conflict),
    }
}

fn validate_ciphertext_subtree_retarget_db(
    db: &Connection,
    scope: &CacheScope,
    members: &[CiphertextSubtreeRetarget],
    builds: &[CiphertextWriteBuild],
    root_id: &str,
) -> Result<(), CacheError> {
    let by_id = builds
        .iter()
        .map(|build| (build.id.as_str(), build))
        .collect::<BTreeMap<_, _>>();
    if by_id.len() != members.len() || !by_id.contains_key(root_id) {
        return Err(CacheError::Conflict);
    }
    let mut current_rows = BTreeMap::new();
    for member in members {
        let row: Option<(i64, String, i64, i64, String)> = db
            .query_row(
                "SELECT revision,target_key,operation,state,dependency_key FROM ciphertext_writes WHERE scope_key=?1 AND write_id=?2",
                params![scope.key, member.id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .optional()
            .map_err(db_error)?;
        let (revision, target, operation, state, dependency) = row.ok_or(CacheError::NotFound)?;
        let build = by_id[member.id.as_str()];
        if revision != i64_from_u64(member.expected_revision)?
            || target
                != build
                    .expected_target_key
                    .as_deref()
                    .ok_or(CacheError::Conflict)?
            || decode_ciphertext_write_operation(operation)? != member.operation
            || !matches!(
                member.operation,
                CiphertextWriteOperation::CreateFile | CiphertextWriteOperation::CreateDirectory
            )
            || decode_ciphertext_write_state(state)? != CiphertextWriteState::NeverAttempted
            || build.expected_state != Some(CiphertextWriteState::NeverAttempted)
        {
            return Err(CacheError::Conflict);
        }
        if member.operation == CiphertextWriteOperation::CreateDirectory
            && member.plaintext_len != 0
        {
            return Err(CacheError::Conflict);
        }
        current_rows.insert(member.id.as_str(), dependency);
    }

    // Prove the supplied IDs are exactly the indexed dependency closure of
    // the root. This catches omitted children and newly registered children
    // at both prepare and publish time.
    let mut pending = vec![current_rows[root_id].clone()];
    let mut visited = BTreeSet::<String>::new();
    while let Some(parent_dependency) = pending.pop() {
        let mut statement = db
            .prepare("SELECT write_id,revision,operation,state,target_key FROM ciphertext_writes WHERE scope_key=?1 AND parent_operation_key=?2")
            .map_err(db_error)?;
        let rows = statement
            .query_map(params![scope.key, parent_dependency], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .map_err(db_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_error)?;
        drop(statement);
        for (child_id, revision, operation, state, target) in rows {
            let build = by_id.get(child_id.as_str()).ok_or(CacheError::Conflict)?;
            if revision != i64_from_u64(build.expected_revision.ok_or(CacheError::Conflict)?)?
                || target
                    != build
                        .expected_target_key
                        .as_deref()
                        .ok_or(CacheError::Conflict)?
                || decode_ciphertext_write_operation(operation)? != build.operation
                || decode_ciphertext_write_state(state)? != CiphertextWriteState::NeverAttempted
                || !visited.insert(child_id.clone())
            {
                return Err(CacheError::Conflict);
            }
            if build.operation == CiphertextWriteOperation::CreateDirectory {
                pending.push(
                    current_rows
                        .get(child_id.as_str())
                        .ok_or(CacheError::Conflict)?
                        .clone(),
                );
            }
        }
    }
    visited.insert(root_id.to_owned());
    if visited.len() != by_id.len() {
        return Err(CacheError::Conflict);
    }

    let included = by_id
        .keys()
        .map(|id| (*id).to_owned())
        .collect::<BTreeSet<_>>();
    let mut new_targets = BTreeSet::new();
    let mut parent_additions = BTreeMap::<String, usize>::new();
    for build in builds {
        if !new_targets.insert(build.target_key.as_str()) {
            return Err(CacheError::Conflict);
        }
        let target_owner: Option<String> = db
            .query_row(
                "SELECT write_id FROM ciphertext_writes WHERE scope_key=?1 AND target_key=?2",
                params![scope.key, build.target_key],
                |row| row.get(0),
            )
            .optional()
            .map_err(db_error)?;
        if target_owner
            .as_ref()
            .is_some_and(|owner| !included.contains(owner))
        {
            return Err(CacheError::Conflict);
        }
        *parent_additions
            .entry(build.parent_key.clone())
            .or_default() += 1;
        if !build.parent_operation_key.is_empty()
            && !builds.iter().any(|parent| {
                parent.operation == CiphertextWriteOperation::CreateDirectory
                    && parent.dependency_key == build.parent_operation_key
            })
        {
            let available: bool = db
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM ciphertext_writes WHERE scope_key=?1 AND dependency_key=?2 AND operation=?3 AND state IN (?4,?5,?6,?7,?8))",
                    params![scope.key,build.parent_operation_key,CiphertextWriteOperation::CreateDirectory as i64,CiphertextWriteState::Pending as i64,CiphertextWriteState::Uncertain as i64,CiphertextWriteState::CommittedReceipt as i64,CiphertextWriteState::NeverAttempted as i64,CiphertextWriteState::Attempting as i64],
                    |row| row.get(0),
                )
                .map_err(db_error)?;
            if !available {
                return Err(CacheError::Conflict);
            }
        }
    }
    for (parent_key, additions) in parent_additions {
        let mut statement = db
            .prepare(
                "SELECT write_id FROM ciphertext_writes WHERE scope_key=?1 AND parent_key=?2 AND operation IN (?3,?4)",
            )
            .map_err(db_error)?;
        let existing = statement
            .query_map(
                params![
                    scope.key,
                    parent_key,
                    CiphertextWriteOperation::CreateFile as i64,
                    CiphertextWriteOperation::CreateDirectory as i64
                ],
                |row| row.get::<_, String>(0),
            )
            .map_err(db_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_error)?;
        drop(statement);
        let remaining = existing
            .iter()
            .filter(|id| !included.contains(id.as_str()))
            .count();
        if remaining.saturating_add(additions) > MAX_CIPHERTEXT_WRITES_PER_PARENT {
            return Err(CacheError::LimitExceeded);
        }
    }
    Ok(())
}

fn validate_ciphertext_subtree_builds_db(
    db: &Connection,
    scope: &CacheScope,
    builds: &[CiphertextWriteBuild],
    root_id: &str,
) -> Result<(), CacheError> {
    let mut members = Vec::with_capacity(builds.len());
    for build in builds {
        members.push(CiphertextSubtreeRetarget {
            id: build.id.clone(),
            expected_revision: build.expected_revision.ok_or(CacheError::Conflict)?,
            expected_target: String::new(),
            new_target: String::new(),
            new_parent_path: String::new(),
            new_parent_operation: None,
            plaintext_len: build.plaintext_len,
            operation: build.operation,
        });
    }
    // The expected target is already an opaque, authenticated index value in
    // the immutable build, so reuse it directly for the publication check.
    for member in &mut members {
        let build = builds
            .iter()
            .find(|build| build.id == member.id)
            .ok_or(CacheError::Conflict)?;
        member.expected_target = build
            .expected_target_key
            .clone()
            .ok_or(CacheError::Conflict)?;
    }
    validate_ciphertext_subtree_retarget_db(db, scope, &members, builds, root_id)?;
    for build in builds {
        if build.publish_state != CiphertextWriteState::NeverAttempted
            || !matches!(
                build.operation,
                CiphertextWriteOperation::CreateFile | CiphertextWriteOperation::CreateDirectory
            )
        {
            return Err(CacheError::Conflict);
        }
    }
    Ok(())
}

fn decode_ciphertext_write_state(value: i64) -> Result<CiphertextWriteState, CacheError> {
    match value {
        0 => Ok(CiphertextWriteState::Pending),
        1 => Ok(CiphertextWriteState::Conflict),
        2 => Ok(CiphertextWriteState::Uncertain),
        3 => Ok(CiphertextWriteState::Building),
        4 => Ok(CiphertextWriteState::CommittedReceipt),
        5 => Ok(CiphertextWriteState::NeverAttempted),
        6 => Ok(CiphertextWriteState::Attempting),
        7 => Ok(CiphertextWriteState::CancelledReceipt),
        8 => Ok(CiphertextWriteState::AcknowledgedReceipt),
        9 => Ok(CiphertextWriteState::RecoveryAttempting),
        10 => Ok(CiphertextWriteState::RecoveryRetrying),
        _ => Err(CacheError::Corrupt),
    }
}

fn ensure_ciphertext_pin_build_db(
    db: &Connection,
    scope: &CacheScope,
    pin_id: &str,
    generation: u64,
    epoch: u64,
) -> Result<(), CacheError> {
    let valid: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM ciphertext_pin_generations g JOIN ciphertext_pin_roots r ON r.pin_id=g.pin_id WHERE g.pin_id=?1 AND g.generation=?2 AND g.epoch=?3 AND g.state=?4 AND r.scope_key=?5 AND r.root_resource_id=?6)",
            params![pin_id, generation, epoch, CiphertextPinState::Building as i64, scope.key, scope.root_resource_id],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    if valid {
        Ok(())
    } else {
        Err(CacheError::Conflict)
    }
}

fn insert_ciphertext_pin_reference(
    db: &Connection,
    scope: &CacheScope,
    reference: CiphertextPinReference<'_>,
) -> Result<(), CacheError> {
    let CiphertextPinReference {
        pin_id,
        generation,
        version,
        content_key: key,
        byte_len,
        kind,
    } = reference;
    let stored: Option<(String, String, i64, i64)> = db
        .query_row(
            "SELECT scope_key,etag,protection,byte_len FROM contents WHERE content_key=?1",
            [key],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(db_error)?;
    let Some((scope_key, etag, protection, stored_len)) = stored else {
        return Err(CacheError::NotFound);
    };
    if scope_key != scope.key
        || etag != version.etag
        || protection != ContentProtection::Ciphertext as i64
        || u64::try_from(stored_len).map_err(|_| CacheError::Corrupt)? != byte_len
        || version.protection != ContentProtection::Ciphertext
    {
        return Err(CacheError::ProtectionMismatch);
    }
    let existing: Option<(String, String, i64, i64)> = db
        .query_row(
            "SELECT resource_id,etag,byte_len,kind FROM ciphertext_pin_items WHERE pin_id=?1 AND generation=?2 AND content_key=?3",
            params![pin_id, generation, key],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
        )
        .optional()
        .map_err(db_error)?;
    if let Some((resource_id, etag, stored_len, stored_kind)) = existing {
        if resource_id != version.resource_id
            || etag != version.etag
            || u64::try_from(stored_len).map_err(|_| CacheError::Corrupt)? != byte_len
            || stored_kind != kind as i64
        {
            return Err(CacheError::Corrupt);
        }
        return Ok(());
    }
    let count: i64 = db
        .query_row(
            "SELECT item_count FROM ciphertext_pin_generations WHERE pin_id=?1 AND generation=?2 AND state=?3",
            params![pin_id,generation,CiphertextPinState::Building as i64],
            |row| row.get(0),
        )
        .optional()
        .map_err(db_error)?
        .ok_or(CacheError::Conflict)?;
    if count < 0 || count as usize >= MAX_CIPHERTEXT_PIN_ITEMS {
        return Err(CacheError::LimitExceeded);
    }
    db.execute(
        "INSERT INTO ciphertext_pin_items(pin_id,generation,content_key,resource_id,etag,byte_len,kind) VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![pin_id,generation,key,version.resource_id,version.etag,i64_from_u64(byte_len)?,kind as i64],
    ).map_err(db_error)?;
    db.execute(
        "UPDATE ciphertext_pin_generations SET item_count=item_count+1,byte_len=byte_len+?3 WHERE pin_id=?1 AND generation=?2 AND state=?4",
        params![pin_id,generation,i64_from_u64(byte_len)?,CiphertextPinState::Building as i64],
    ).map_err(db_error)?;
    Ok(())
}

fn decode_ciphertext_pin_state(value: i64) -> Result<CiphertextPinState, CacheError> {
    match value {
        0 => Ok(CiphertextPinState::Building),
        1 => Ok(CiphertextPinState::Ready),
        2 | 3 => Ok(CiphertextPinState::Stale),
        _ => Err(CacheError::Corrupt),
    }
}

fn require_ciphertext_scope(scope: &CacheScope) -> Result<(), CacheError> {
    if scope.protection == ScopeProtection::CiphertextOnly {
        Ok(())
    } else {
        Err(CacheError::ProtectionMismatch)
    }
}

fn ensure_ciphertext_epoch(db: &Connection, scope: &CacheScope) -> Result<i64, CacheError> {
    require_ciphertext_scope(scope)?;
    db.execute(
        "INSERT OR IGNORE INTO ciphertext_epochs(scope_key,epoch) VALUES(?1,0)",
        [&scope.key],
    )
    .map_err(db_error)?;
    db.query_row(
        "SELECT epoch FROM ciphertext_epochs WHERE scope_key=?1",
        [&scope.key],
        |row| row.get(0),
    )
    .map_err(db_error)
}

fn remove_unreferenced_blob(content_dir: &Path, path: &Path) -> Result<(), CacheError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            fs::remove_file(path).map_err(io_error)?;
            sync_directory(content_dir)
        }
        Ok(_) => Err(CacheError::UnsafeDirectory),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(error)),
    }
}

fn validate_registered_scope(db: &Connection, scope: &CacheScope) -> Result<(), CacheError> {
    let existing: Option<(String,String,String,String,i64)> = db.query_row(
        "SELECT origin,account_id,space_id,root_resource_id,protection FROM scopes WHERE scope_key=?1",
        params![scope.key],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
    ).optional().map_err(db_error)?;
    match existing {
        Some((origin, account, space, root, protection))
            if origin == scope.origin
                && account == scope.account_id
                && space == scope.space_id
                && root == scope.root_resource_id
                && protection == scope.protection as i64 =>
        {
            Ok(())
        }
        Some(_) => Err(CacheError::Conflict),
        None => Err(CacheError::NotFound),
    }
}

fn load_listing(
    db: &Connection,
    scope: &CacheScope,
    parent: &str,
) -> Result<CachedListing, CacheError> {
    let (generation,fetched_at,complete): (i64,i64,i64) = db.query_row(
        "SELECT generation,fetched_at,complete FROM listings WHERE scope_key=?1 AND parent_id=?2",
        params![scope.key,parent],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
    ).optional().map_err(db_error)?.ok_or(CacheError::IncompleteListing)?;
    if complete != 1 {
        return Err(CacheError::IncompleteListing);
    }
    let mut statement = db.prepare(
        "SELECT parent_id,resource_id,path,etag,size,directory,modified,writable,encrypted FROM listing_entries WHERE scope_key=?1 AND parent_id=?2 AND generation=?3 ORDER BY name COLLATE BINARY",
    ).map_err(db_error)?;
    let rows = statement
        .query_map(params![scope.key, parent, generation], |row| {
            let size: i64 = row.get(4)?;
            Ok(CachedEntry {
                parent_resource_id: row.get(0)?,
                entry: RemoteEntry {
                    id: row.get(1)?,
                    path: row.get(2)?,
                    etag: row.get(3)?,
                    size: size.max(0) as u64,
                    directory: row.get::<_, i64>(5)? != 0,
                    modified_unix: row.get(6)?,
                    writable: row.get::<_, i64>(7)? != 0,
                    encrypted: row.get::<_, i64>(8)? != 0,
                },
            })
        })
        .map_err(db_error)?;
    let entries = rows.collect::<Result<Vec<_>, _>>().map_err(db_error)?;
    Ok(CachedListing {
        generation: generation.max(0) as u64,
        fetched_at_unix: fetched_at,
        complete: true,
        entries,
    })
}

fn validate_version_in_metadata(
    db: &Connection,
    scope: &CacheScope,
    version: &ContentVersion,
    expected_len: u64,
) -> Result<(), CacheError> {
    let found: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM listing_entries e JOIN listings l ON l.scope_key=e.scope_key AND l.parent_id=e.parent_id AND l.generation=e.generation WHERE e.scope_key=?1 AND e.resource_id=?2 AND e.etag=?3 AND e.size=?4 AND e.directory=0 AND e.encrypted=0 AND l.complete=1)",
        params![scope.key,version.resource_id,version.etag,i64_from_u64(expected_len)?],
        |row| row.get(0),
    ).map_err(db_error)?;
    if found {
        Ok(())
    } else {
        Err(CacheError::Conflict)
    }
}

fn load_content_record(
    db: &Connection,
    scope: &CacheScope,
    version: &ContentVersion,
) -> Result<ContentRecord, CacheError> {
    load_content_record_by_identity(db, scope, &version.resource_id, &version.etag)?
        .filter(|record| record.version.protection == version.protection)
        .ok_or(CacheError::NotFound)
}

fn load_content_record_by_identity(
    db: &Connection,
    scope: &CacheScope,
    resource_id: &str,
    etag: &str,
) -> Result<Option<ContentRecord>, CacheError> {
    let row: Option<(i64,String,i64)> = db.query_row(
        "SELECT byte_len,sha256,retention FROM contents WHERE scope_key=?1 AND resource_id=?2 AND etag=?3",
        params![scope.key,resource_id,etag],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
    ).optional().map_err(db_error)?;
    row.map(|(len, sha, retention)| {
        Ok(ContentRecord {
            version: ContentVersion {
                resource_id: resource_id.into(),
                etag: etag.into(),
                protection: scope.protection.into(),
            },
            byte_len: len.max(0) as u64,
            sha256: sha,
            retention: decode_retention(retention)?,
        })
    })
    .transpose()
}

impl From<ScopeProtection> for ContentProtection {
    fn from(value: ScopeProtection) -> Self {
        match value {
            ScopeProtection::PlaintextAllowed => Self::Plaintext,
            ScopeProtection::CiphertextOnly => Self::Ciphertext,
        }
    }
}

fn content_key(scope: &CacheScope, version: &ContentVersion) -> String {
    hash_fields(&[
        &scope.key,
        &version.resource_id,
        &version.etag,
        &(version.protection as i64).to_string(),
    ])
}

fn hash_fields(fields: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for field in fields {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

fn next_journal_etag(scope: &CacheScope, path: &str) -> String {
    let sequence = JOURNAL_VERSION_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .to_string();
    format!(
        "journal-{}",
        hash_fields(&[&scope.key, path, &nanos, &sequence.to_string()])
    )
}

fn write_content_atomically<R: Read + ?Sized>(
    dir: &Path,
    destination: &Path,
    source: &mut R,
    expected_len: u64,
) -> Result<(u64, String, bool), CacheError> {
    if let Ok(metadata) = fs::symlink_metadata(destination) {
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(CacheError::UnsafeDirectory);
        }
        let mut file = open_private_file(destination)?;
        let (existing_len, existing_digest) = hash_file(&mut file)?;
        let mut source_hasher = Sha256::new();
        let mut source_len = 0_u64;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let count = source.read(&mut buffer).map_err(io_error)?;
            if count == 0 {
                break;
            }
            source_len = source_len
                .checked_add(count as u64)
                .ok_or(CacheError::LimitExceeded)?;
            if source_len > expected_len || source_len > MAX_CONTENT_BYTES {
                return Err(CacheError::Corrupt);
            }
            source_hasher.update(&buffer[..count]);
        }
        let source_digest = format!("{:x}", source_hasher.finalize());
        if existing_len != expected_len
            || source_len != expected_len
            || existing_digest != source_digest
        {
            return Err(CacheError::Corrupt);
        }
        return Ok((existing_len, existing_digest, false));
    }
    let mut temp = Builder::new()
        .prefix(".stage-")
        .tempfile_in(dir)
        .map_err(io_error)?;
    set_private_file(temp.as_file())?;
    let mut hasher = Sha256::new();
    let mut len = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = source.read(&mut buffer).map_err(io_error)?;
        if count == 0 {
            break;
        }
        len = len
            .checked_add(count as u64)
            .ok_or(CacheError::LimitExceeded)?;
        if len > expected_len || len > MAX_CONTENT_BYTES {
            return Err(CacheError::Corrupt);
        }
        temp.write_all(&buffer[..count]).map_err(io_error)?;
        hasher.update(&buffer[..count]);
    }
    if len != expected_len {
        return Err(CacheError::Corrupt);
    }
    temp.as_file().sync_all().map_err(io_error)?;
    let digest = format!("{:x}", hasher.finalize());
    let created = match temp.persist_noclobber(destination) {
        Ok(_) => {
            sync_directory(dir)?;
            true
        }
        Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
            drop(error.file);
            let mut existing = open_private_file(destination)?;
            let (old_len, old_digest) = hash_file(&mut existing)?;
            if old_len != len || old_digest != digest {
                return Err(CacheError::Corrupt);
            }
            false
        }
        Err(error) => return Err(io_error(error.error)),
    };
    Ok((len, digest, created))
}

fn hash_file(file: &mut File) -> Result<(u64, String), CacheError> {
    hash_file_cancellable(file, || false)
}

fn hash_file_cancellable(
    file: &mut File,
    mut cancelled: impl FnMut() -> bool,
) -> Result<(u64, String), CacheError> {
    use std::io::Seek;
    file.rewind().map_err(io_error)?;
    let mut hasher = Sha256::new();
    let mut len = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        if cancelled() {
            return Err(CacheError::Cancelled);
        }
        let count = file.read(&mut buffer).map_err(io_error)?;
        if cancelled() {
            return Err(CacheError::Cancelled);
        }
        if count == 0 {
            break;
        }
        len = len
            .checked_add(count as u64)
            .ok_or(CacheError::LimitExceeded)?;
        if len > MAX_CONTENT_BYTES {
            return Err(CacheError::LimitExceeded);
        }
        hasher.update(&buffer[..count]);
    }
    Ok((len, format!("{:x}", hasher.finalize())))
}

fn remove_recent_content(
    tx: &Transaction<'_>,
    scope_key: &str,
    resource_id: &str,
) -> Result<Vec<String>, CacheError> {
    let mut statement=tx.prepare("SELECT content_key,relative_path FROM contents WHERE scope_key=?1 AND resource_id=?2 AND retention=0").map_err(db_error)?;
    let rows = statement
        .query_map(params![scope_key, resource_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(db_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(db_error)?;
    drop(statement);
    let mut removed = Vec::with_capacity(rows.len());
    for (key, path) in rows {
        validate_object_filename(&path)?;
        tx.execute("DELETE FROM contents WHERE content_key=?1", [key])
            .map_err(db_error)?;
        removed.push(path);
    }
    Ok(removed)
}

#[cfg(windows)]
fn windows_content_inventory(
    db: &Connection,
    store: &windows_blob::WindowsBlobStore,
    lease: &windows_blob::PublicationLease<'_>,
) -> Result<windows_blob::StorageInventory, CacheError> {
    let mut statement = db
        .prepare("SELECT relative_path FROM contents")
        .map_err(db_error)?;
    let known = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(db_error)?
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(db_error)?;
    for name in &known {
        validate_object_filename(name)?;
    }
    store.inventory(lease, &known)
}

fn total_content_bytes(db: &Connection) -> Result<u64, CacheError> {
    let value: i64 = db
        .query_row(
            "SELECT COALESCE(SUM(byte_len),0) FROM contents",
            [],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    Ok(value.max(0) as u64)
}

fn protected_content_bytes(db: &Connection) -> Result<u64, CacheError> {
    let value: i64=db.query_row("SELECT COALESCE(SUM(c.byte_len),0) FROM contents c WHERE c.retention IN (1,2) OR EXISTS(SELECT 1 FROM policies pol WHERE pol.scope_key=c.scope_key AND pol.resource_id=c.resource_id AND pol.policy=1 AND pol.target_etag=c.etag) OR EXISTS(SELECT 1 FROM pin_items pi JOIN pins p ON p.pin_id=pi.pin_id WHERE p.scope_key=c.scope_key AND pi.resource_id=c.resource_id AND pi.etag=c.etag) OR EXISTS(SELECT 1 FROM ciphertext_pin_items cpi WHERE cpi.content_key=c.content_key) OR EXISTS(SELECT 1 FROM ciphertext_writes cw WHERE cw.content_key=c.content_key)",[],|row|row.get(0)).map_err(db_error)?;
    Ok(value.max(0) as u64)
}

fn pinned_content_bytes(db: &Connection) -> Result<u64, CacheError> {
    let value: i64 = db
        .query_row(
            "SELECT COALESCE(SUM(c.byte_len),0) FROM contents c WHERE EXISTS(SELECT 1 FROM pin_items pi JOIN pins p ON p.pin_id=pi.pin_id WHERE p.scope_key=c.scope_key AND pi.resource_id=c.resource_id AND pi.etag=c.etag) OR EXISTS(SELECT 1 FROM ciphertext_pin_items i WHERE i.content_key=c.content_key) OR EXISTS(SELECT 1 FROM ciphertext_writes cw WHERE cw.content_key=c.content_key)",
            [],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    Ok(value.max(0) as u64)
}

fn decode_retention(value: i64) -> Result<Retention, CacheError> {
    match value {
        0 => Ok(Retention::Recent),
        1 => Ok(Retention::Dirty),
        2 => Ok(Retention::Recovery),
        _ => Err(CacheError::Corrupt),
    }
}
fn decode_content_protection(value: i64) -> Result<ContentProtection, CacheError> {
    match value {
        0 => Ok(ContentProtection::Plaintext),
        1 => Ok(ContentProtection::Ciphertext),
        _ => Err(CacheError::Corrupt),
    }
}
fn decode_write_state(value: i64) -> Result<WriteState, CacheError> {
    match value {
        0 => Ok(WriteState::Pending),
        1 => Ok(WriteState::Conflict),
        2 => Ok(WriteState::Verified),
        _ => Err(CacheError::Corrupt),
    }
}
fn pending_write_item_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PendingWriteItem> {
    let state: i64 = row.get(4)?;
    let bytes: i64 = row.get(5)?;
    Ok(PendingWriteItem {
        space_id: row.get(0)?,
        root_resource_id: row.get(1)?,
        write_id: row.get(2)?,
        path: row.get(3)?,
        state: decode_write_state(state).map_err(|_| rusqlite::Error::InvalidQuery)?,
        bytes: bytes.max(0) as u64,
        created_at_unix: row.get(6)?,
    })
}
fn i64_from_u64(value: u64) -> Result<i64, CacheError> {
    i64::try_from(value).map_err(|_| CacheError::LimitExceeded)
}
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or(0)
}
fn db_error(error: rusqlite::Error) -> CacheError {
    CacheError::Database(error.to_string())
}
fn io_error(error: io::Error) -> CacheError {
    CacheError::Io(error.to_string())
}
fn cache_cloud_error(error: CacheError) -> CloudError {
    CloudError::new(ErrorKind::Io, error.to_string())
}

#[cfg(not(windows))]
fn prepare_db_file(path: &Path) -> Result<(), CacheError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(CacheError::UnsafeDirectory);
        }
        Ok(_) => validate_private_file(path)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let file = options.open(path).map_err(io_error)?;
            set_private_file(&file)?;
            file.sync_all().map_err(io_error)?;
        }
        Err(error) => return Err(io_error(error)),
    }
    Ok(())
}
fn open_private_file(path: &Path) -> Result<File, CacheError> {
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(CacheError::UnsafeDirectory);
    }
    validate_private_file(path)?;
    OpenOptions::new().read(true).open(path).map_err(io_error)
}
fn validate_private_file(path: &Path) -> Result<(), CacheError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path).map_err(io_error)?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(CacheError::UnsafeDirectory);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}
fn set_private_file(file: &File) -> Result<(), CacheError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(io_error)?;
    }
    #[cfg(not(unix))]
    {
        let _ = file;
    }
    Ok(())
}
#[cfg(not(windows))]
fn set_private_dir(path: &Path) -> Result<(), CacheError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(io_error)?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}
#[cfg(not(windows))]
fn validate_private_dir(path: &Path) -> Result<(), CacheError> {
    if !private_permissions_supported() {
        return Err(CacheError::UnsafeDirectory);
    }
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(CacheError::UnsafeDirectory);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(CacheError::UnsafeDirectory);
        }
    }
    Ok(())
}
fn sync_directory(path: &Path) -> Result<(), CacheError> {
    #[cfg(unix)]
    {
        File::open(path)
            .and_then(|file| file.sync_all())
            .map_err(io_error)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}
#[cfg(unix)]
fn private_permissions_supported() -> bool {
    true
}
#[cfg(not(any(unix, windows)))]
fn private_permissions_supported() -> bool {
    false
}
fn validate_object_filename(name: &str) -> Result<(), CacheError> {
    if name.len() != 69
        || !name.ends_with(".blob")
        || !name[..64].bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(CacheError::Corrupt);
    }
    Ok(())
}
fn ensure_column(
    db: &Connection,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<(), CacheError> {
    // Table/column names are compile-time constants at every call site.
    let mut statement = db
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(db_error)?;
    let names = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(db_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(db_error)?;
    if !names.iter().any(|name| name == column) {
        db.execute_batch(&format!(
            "ALTER TABLE {table} ADD COLUMN {column} {definition}"
        ))
        .map_err(db_error)?;
    }
    Ok(())
}

fn decode_target_state(value: i64) -> Result<TargetState, rusqlite::Error> {
    match value {
        0 => Ok(TargetState::Ready),
        1 => Ok(TargetState::Stale),
        2 => Ok(TargetState::Unavailable),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}
fn decode_pin_state(value: i64) -> Result<PinState, rusqlite::Error> {
    match value {
        0 => Ok(PinState::Building),
        1 => Ok(PinState::Ready),
        2 => Ok(PinState::Stale),
        3 => Ok(PinState::Unavailable),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}
fn encode_pin_state(value: PinState) -> i64 {
    match value {
        PinState::Building => 0,
        PinState::Ready => 1,
        PinState::Stale => 2,
        PinState::Unavailable => 3,
    }
}

fn validate_cache_schema(db: &Connection) -> Result<(), CacheError> {
    let version: i64 = db
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(db_error)?;
    if version != CACHE_VERSION as i64 {
        Err(CacheError::Corrupt)
    } else {
        Ok(())
    }
}

/// Offline fallback is permitted only for a transport-level offline error.
/// Authentication, permission, conflict, and identity failures must surface.
pub fn may_use_offline_snapshot(error: &CloudError) -> bool {
    error.kind == ErrorKind::Offline
}

#[cfg(all(test, unix))]
mod tests {
    include!("saved_write_export_tests.rs");
    mod listing_publication_tests {
        include!("listing_publication_tests.rs");
    }
    mod folder_policy_tests {
        include!("folder_policy_tests.rs");
    }
    mod open_policy_race_tests {
        include!("open_policy_race_tests.rs");
    }
    mod folder_policy_conflict_tests {
        include!("folder_policy_conflict_tests.rs");
    }
    mod folder_policy_clear_tests {
        include!("folder_policy_clear_tests.rs");
    }
    mod folder_policy_admission_tests {
        include!("folder_policy_admission_tests.rs");
    }

    use super::*;
    use std::io::Cursor;
    use std::sync::{Arc, Barrier};

    fn scope(protection: ScopeProtection) -> CacheScope {
        CacheScope::new(
            "https://cloud.example.test/",
            "account-a",
            "space-a",
            "root-a",
            protection,
        )
        .unwrap()
    }
    fn entry(
        id: &str,
        _name: &str,
        path: &str,
        etag: &str,
        size: u64,
        directory: bool,
    ) -> CachedEntry {
        CachedEntry {
            parent_resource_id: "root-a".into(),
            entry: RemoteEntry {
                id: id.into(),
                path: path.into(),
                etag: etag.into(),
                size,
                directory,
                modified_unix: 1,
                writable: true,
                encrypted: false,
            },
        }
    }
    fn cache() -> (tempfile::TempDir, Cache) {
        let temp = tempfile::tempdir().unwrap();
        set_private_dir(temp.path()).unwrap();
        let cache = Cache::open(temp.path(), 1024).unwrap();
        (temp, cache)
    }

    #[test]
    fn listing_is_complete_atomic_and_identity_scoped() {
        let (_temp, cache) = cache();
        let scope = scope(ScopeProtection::PlaintextAllowed);
        let entries = vec![entry("file-1", "a.txt", "/a.txt", "v1", 3, false)];
        let listing = cache
            .publish_listing(&scope, "root-a", &entries, 10)
            .unwrap();
        assert!(listing.complete);
        assert_eq!(listing.generation, 1);
        let other = CacheScope::new(
            "https://cloud.example.test/",
            "account-b",
            "space-a",
            "root-a",
            ScopeProtection::PlaintextAllowed,
        )
        .unwrap();
        assert_eq!(cache.listing(&other, "root-a"), Err(CacheError::NotFound));
        assert!(
            cache
                .publish_listing(
                    &scope,
                    "root-a",
                    &[entries[0].clone(), entries[0].clone()],
                    11
                )
                .is_err()
        );
        assert_eq!(cache.listing(&scope, "root-a").unwrap().entries, entries);
    }

    #[test]
    fn only_offline_transport_errors_use_cached_listing() {
        let (_temp, cache) = cache();
        let scope = scope(ScopeProtection::PlaintextAllowed);
        cache
            .publish_listing(
                &scope,
                "root-a",
                &[entry("f", "a.txt", "/a.txt", "v1", 3, false)],
                1,
            )
            .unwrap();
        let cached = cache
            .list_with_offline_fallback(&scope, "root-a", || {
                Err(CloudError::new(ErrorKind::Offline, "offline"))
            })
            .unwrap();
        assert_eq!(cached.entries.len(), 1);
        for kind in [
            ErrorKind::Unauthorized,
            ErrorKind::Forbidden,
            ErrorKind::Conflict,
        ] {
            let error = CloudError::new(kind, "must surface");
            assert_eq!(
                cache
                    .list_with_offline_fallback(&scope, "root-a", || Err(error.clone()))
                    .unwrap_err(),
                error
            );
        }
    }

    #[test]
    fn offline_content_fallback_is_limited_to_transport_offline() {
        let (_temp, cache) = cache();
        let scope = scope(ScopeProtection::PlaintextAllowed);
        cache
            .publish_listing(
                &scope,
                "root-a",
                &[entry("f", "a.txt", "/a.txt", "v1", 3, false)],
                1,
            )
            .unwrap();
        let version = ContentVersion {
            resource_id: "f".into(),
            etag: "v1".into(),
            protection: ContentProtection::Plaintext,
        };
        let mut online_called = false;
        let mut file = cache
            .content_with_offline_fallback(&scope, &version, 3, || {
                online_called = true;
                Ok(Cursor::new(b"abc"))
            })
            .unwrap();
        assert!(online_called);
        let mut content = Vec::new();
        file.read_to_end(&mut content).unwrap();
        assert_eq!(content, b"abc");
        let mut file = cache
            .content_with_offline_fallback(&scope, &version, 3, || {
                Err::<Cursor<&[u8]>, _>(CloudError::new(ErrorKind::Offline, "offline"))
            })
            .unwrap();
        content.clear();
        file.read_to_end(&mut content).unwrap();
        assert_eq!(content, b"abc");
        let auth = CloudError::new(ErrorKind::Unauthorized, "login required");
        assert_eq!(
            cache
                .content_with_offline_fallback(&scope, &version, 3, || {
                    Err::<Cursor<&[u8]>, _>(auth.clone())
                })
                .unwrap_err(),
            auth
        );
    }

    #[test]
    fn immutable_content_is_versioned_private_and_protection_checked() {
        let (temp, cache) = cache();
        let scope = scope(ScopeProtection::CiphertextOnly);
        let item = entry("file", "x", "/x", "etag-1", 4, false);
        assert_eq!(
            cache.publish_listing(&scope, "root-a", &[item], 1),
            Err(CacheError::ProtectionMismatch)
        );
        let bad = ContentVersion {
            resource_id: "file".into(),
            etag: "etag-1".into(),
            protection: ContentProtection::Plaintext,
        };
        assert_eq!(
            cache.publish_content(
                &scope,
                &bad,
                &mut Cursor::new(b"data"),
                4,
                Retention::Recent
            ),
            Err(CacheError::ProtectionMismatch)
        );
        let version = ContentVersion {
            protection: ContentProtection::Ciphertext,
            ..bad
        };
        let record = cache
            .publish_content(
                &scope,
                &version,
                &mut Cursor::new(b"data"),
                4,
                Retention::Recent,
            )
            .unwrap();
        assert_eq!(record.byte_len, 4);
        assert_eq!(
            cache
                .open_content(&scope, &version)
                .unwrap()
                .metadata()
                .unwrap()
                .len(),
            4
        );
        let object = cache
            .inner
            .content_dir
            .join(format!("{}.blob", content_key(&scope, &version)));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(object).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(Cache::open(temp.path(), 1024).is_ok());
    }

    #[test]
    fn recursive_pin_is_not_ready_until_exact_content_versions_are_cached() {
        let (_temp, cache) = cache();
        let scope = scope(ScopeProtection::PlaintextAllowed);
        let root_listing = vec![CachedEntry {
            parent_resource_id: "root-a".into(),
            entry: RemoteEntry {
                id: "dir".into(),
                path: "/dir".into(),
                etag: "d1".into(),
                size: 0,
                directory: true,
                modified_unix: 1,
                writable: true,
                encrypted: false,
            },
        }];
        cache
            .publish_listing(&scope, "root-a", &root_listing, 1)
            .unwrap();
        let child = CachedEntry {
            parent_resource_id: "dir".into(),
            entry: RemoteEntry {
                id: "file".into(),
                path: "/dir/file".into(),
                etag: "f1".into(),
                size: 3,
                directory: false,
                modified_unix: 1,
                writable: true,
                encrypted: false,
            },
        };
        cache
            .publish_listing(&scope, "dir", std::slice::from_ref(&child), 2)
            .unwrap();
        let manifest = vec![
            PinManifestEntry {
                parent_resource_id: "root-a".into(),
                entry: root_listing[0].entry.clone(),
            },
            PinManifestEntry {
                parent_resource_id: "dir".into(),
                entry: child.entry.clone(),
            },
        ];
        let pin = cache.begin_pin(&scope, "root-a", &manifest).unwrap();
        assert_eq!(pin.state, PinState::Building);
        let version = ContentVersion {
            resource_id: "file".into(),
            etag: "f1".into(),
            protection: ContentProtection::Plaintext,
        };
        cache
            .publish_content(
                &scope,
                &version,
                &mut Cursor::new(b"abc"),
                3,
                Retention::Recent,
            )
            .unwrap();
        let ready = cache.refresh_pin(&pin.id).unwrap();
        assert_eq!(ready.state, PinState::Ready);
        assert_eq!(ready.required_content_count, 1);
        let object = cache
            .inner
            .content_dir
            .join(format!("{}.blob", content_key(&scope, &version)));
        fs::write(object, b"bad").unwrap();
        assert_eq!(
            cache.refresh_pin(&pin.id).unwrap().state,
            PinState::Building
        );
    }

    #[test]
    fn path_invalidation_blocks_resurrection_and_marks_pins_stale_without_deleting_bytes() {
        let (_temp, cache) = cache();
        let scope = scope(ScopeProtection::PlaintextAllowed);
        let directory = entry("dir", "dir", "/dir", "d1", 0, true);
        cache
            .publish_listing(&scope, "root-a", std::slice::from_ref(&directory), 1)
            .unwrap();
        let file = CachedEntry {
            parent_resource_id: "dir".into(),
            entry: RemoteEntry {
                id: "file".into(),
                path: "/dir/file.txt".into(),
                etag: "f1".into(),
                size: 3,
                directory: false,
                modified_unix: 1,
                writable: true,
                encrypted: false,
            },
        };
        cache
            .publish_listing(&scope, "dir", std::slice::from_ref(&file), 2)
            .unwrap();
        let pin = cache
            .begin_pin(
                &scope,
                "dir",
                &[PinManifestEntry {
                    parent_resource_id: "dir".into(),
                    entry: file.entry.clone(),
                }],
            )
            .unwrap();
        let version = ContentVersion {
            resource_id: "file".into(),
            etag: "f1".into(),
            protection: ContentProtection::Plaintext,
        };
        cache
            .publish_content(
                &scope,
                &version,
                &mut Cursor::new(b"old"),
                3,
                Retention::Recent,
            )
            .unwrap();
        assert_eq!(cache.refresh_pin(&pin.id).unwrap().state, PinState::Ready);

        assert_eq!(
            cache.invalidate_paths(&scope, &["/dir/file.txt"]).unwrap(),
            1
        );
        assert_eq!(cache.refresh_pin(&pin.id).unwrap().state, PinState::Stale);
        assert_eq!(cache.entry_for_path(&scope, "/dir/file.txt").unwrap(), None);
        assert_eq!(cache.listing(&scope, "root-a").unwrap().entries.len(), 1);
        assert_eq!(
            cache.listing(&scope, "dir"),
            Err(CacheError::IncompleteListing)
        );
        // Invalidation is metadata-only: it must never delete the retained
        // immutable snapshot or turn it into a remote delete/recovery action.
        let mut old = cache.open_content(&scope, &version).unwrap();
        let mut bytes = Vec::new();
        old.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"old");
    }

    #[test]
    fn eviction_never_removes_pinned_dirty_or_recovery_content() {
        let (_temp, cache) = cache();
        let scope = scope(ScopeProtection::PlaintextAllowed);
        let items = vec![
            entry("recent", "r", "/r", "r1", 3, false),
            entry("dirty", "d", "/d", "d1", 3, false),
            entry("recovery", "x", "/x", "x1", 3, false),
        ];
        cache.publish_listing(&scope, "root-a", &items, 1).unwrap();
        let recent = ContentVersion {
            resource_id: "recent".into(),
            etag: "r1".into(),
            protection: ContentProtection::Plaintext,
        };
        let dirty = ContentVersion {
            resource_id: "dirty".into(),
            etag: "d1".into(),
            protection: ContentProtection::Plaintext,
        };
        let recovery = ContentVersion {
            resource_id: "recovery".into(),
            etag: "x1".into(),
            protection: ContentProtection::Plaintext,
        };
        cache
            .publish_content(
                &scope,
                &recent,
                &mut Cursor::new(b"aaa"),
                3,
                Retention::Recent,
            )
            .unwrap();
        cache
            .publish_content(
                &scope,
                &dirty,
                &mut Cursor::new(b"bbb"),
                3,
                Retention::Dirty,
            )
            .unwrap();
        cache
            .publish_content(
                &scope,
                &dirty,
                &mut Cursor::new(b"bbb"),
                3,
                Retention::Recent,
            )
            .unwrap();
        cache
            .publish_content(
                &scope,
                &recovery,
                &mut Cursor::new(b"ccc"),
                3,
                Retention::Recovery,
            )
            .unwrap();
        cache.evict_recent(0).unwrap();
        assert!(matches!(
            cache.open_content(&scope, &recent),
            Err(CacheError::NotFound)
        ));
        assert!(cache.open_content(&scope, &dirty).is_ok());
        assert!(cache.open_content(&scope, &recovery).is_ok());
    }

    #[test]
    fn offline_policy_pins_content_and_cloud_only_removes_it() {
        let (_temp, cache) = cache();
        let scope = scope(ScopeProtection::PlaintextAllowed);
        let listed = vec![
            entry("always", "a.txt", "/a.txt", "a1", 3, false),
            entry("cloud", "b.txt", "/b.txt", "b1", 3, false),
        ];
        cache.publish_listing(&scope, "root-a", &listed, 1).unwrap();
        let always = ContentVersion {
            resource_id: "always".into(),
            etag: "a1".into(),
            protection: ContentProtection::Plaintext,
        };
        let cloud = ContentVersion {
            resource_id: "cloud".into(),
            etag: "b1".into(),
            protection: ContentProtection::Plaintext,
        };
        cache
            .publish_content(
                &scope,
                &always,
                &mut Cursor::new(b"aaa"),
                3,
                Retention::Recent,
            )
            .unwrap();
        cache
            .publish_content(
                &scope,
                &cloud,
                &mut Cursor::new(b"bbb"),
                3,
                Retention::Recent,
            )
            .unwrap();
        cache
            .set_policy(&scope, "always", AvailabilityPolicy::AlwaysOffline)
            .unwrap();
        cache.evict_recent(0).unwrap();
        assert!(cache.open_content(&scope, &always).is_ok());
        assert!(matches!(
            cache.open_content(&scope, &cloud),
            Err(CacheError::NotFound)
        ));
        cache
            .set_policy(&scope, "always", AvailabilityPolicy::CloudOnly)
            .unwrap();
        assert!(matches!(
            cache.open_content(&scope, &always),
            Err(CacheError::NotFound)
        ));
        assert_eq!(
            cache.policy(&scope, "always").unwrap(),
            AvailabilityPolicy::CloudOnly
        );
    }

    #[test]
    fn cloud_only_failed_commit_preserves_indexed_bytes_across_reopen() {
        let (state, cache) = cache();
        let scope = scope(ScopeProtection::PlaintextAllowed);
        let version = ContentVersion {
            resource_id: "file".into(),
            etag: "revision-1".into(),
            protection: ContentProtection::Plaintext,
        };
        cache
            .publish_listing(
                &scope,
                "root-a",
                &[entry(
                    "file",
                    "file.txt",
                    "/file.txt",
                    "revision-1",
                    4,
                    false,
                )],
                1,
            )
            .unwrap();
        cache
            .publish_content(
                &scope,
                &version,
                &mut Cursor::new(b"keep"),
                4,
                Retention::Recent,
            )
            .unwrap();
        {
            let db = cache.lock_db().unwrap();
            // Defer this violation until COMMIT, after all policy statements
            // succeed. This exercises a real SQLite rollback, not an early
            // validation failure or a hook replacing transaction semantics.
            db.execute_batch(
                "CREATE TABLE commit_failure_guard (
                scope_key TEXT REFERENCES scopes(scope_key) DEFERRABLE INITIALLY DEFERRED
            );
            CREATE TRIGGER reject_policy_commit AFTER INSERT ON policies BEGIN
                INSERT INTO commit_failure_guard VALUES('missing-synthetic-scope');
            END;",
            )
            .unwrap();
        }
        assert!(matches!(
            cache.set_policy(&scope, "file", AvailabilityPolicy::CloudOnly),
            Err(CacheError::Database(_))
        ));
        let mut bytes = Vec::new();
        cache
            .open_content(&scope, &version)
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes, b"keep");
        assert_ne!(
            cache.policy(&scope, "file").unwrap(),
            AvailabilityPolicy::CloudOnly
        );
        cache
            .lock_db()
            .unwrap()
            .execute_batch("DROP TRIGGER reject_policy_commit; DROP TABLE commit_failure_guard;")
            .unwrap();
        drop(cache);
        let reopened = Cache::open(state.path(), 1024 * 1024).unwrap();
        let mut bytes = Vec::new();
        reopened
            .open_content(&scope, &version)
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes, b"keep");
        reopened
            .set_policy(&scope, "file", AvailabilityPolicy::CloudOnly)
            .unwrap();
        assert!(matches!(
            reopened.open_content(&scope, &version),
            Err(CacheError::NotFound)
        ));
    }

    #[test]
    fn eviction_fences_same_version_publication_from_another_cache() {
        let (temp, cache) = cache();
        let other = Cache::open(temp.path(), 1024).unwrap();
        let scope = scope(ScopeProtection::PlaintextAllowed);
        let version = ContentVersion {
            resource_id: "file".into(),
            etag: "v1".into(),
            protection: ContentProtection::Plaintext,
        };
        cache
            .publish_listing(
                &scope,
                "root-a",
                &[entry("file", "file.txt", "/file.txt", "v1", 3, false)],
                1,
            )
            .unwrap();
        cache
            .publish_content(
                &scope,
                &version,
                &mut Cursor::new(b"abc"),
                3,
                Retention::Recent,
            )
            .unwrap();
        let mut publisher = None;
        cache
            .evict_recent_with_hook(0, || {
                // Probe through a separate Cache and file description after DB
                // commit, before unlink. This proves actual lock contention,
                // without relying on sleeps or the worker's scheduling.
                let probe = other.content_publication_lock_file().unwrap();
                assert_eq!(
                    fs2::FileExt::try_lock_shared(&probe).unwrap_err().kind(),
                    io::ErrorKind::WouldBlock
                );
                let other = other.clone();
                let scope = scope.clone();
                let version = version.clone();
                publisher = Some(std::thread::spawn(move || {
                    other.publish_content(
                        &scope,
                        &version,
                        &mut Cursor::new(b"abc"),
                        3,
                        Retention::Dirty,
                    )
                }));
            })
            .unwrap();
        publisher.unwrap().join().unwrap().unwrap();
        let mut bytes = Vec::new();
        other
            .open_content(&scope, &version)
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes, b"abc");
        assert_eq!(
            other.content_record(&scope, &version).unwrap().retention,
            Retention::Dirty
        );
    }

    #[test]
    fn eviction_does_not_unlink_when_database_declines_deletion() {
        let (_temp, cache) = cache();
        let scope = scope(ScopeProtection::PlaintextAllowed);
        let version = ContentVersion {
            resource_id: "file".into(),
            etag: "v1".into(),
            protection: ContentProtection::Plaintext,
        };
        cache
            .publish_listing(
                &scope,
                "root-a",
                &[entry("file", "file.txt", "/file.txt", "v1", 3, false)],
                1,
            )
            .unwrap();
        cache
            .publish_content(
                &scope,
                &version,
                &mut Cursor::new(b"abc"),
                3,
                Retention::Recent,
            )
            .unwrap();
        cache.lock_db().unwrap().execute_batch("CREATE TRIGGER retain_content BEFORE DELETE ON contents BEGIN SELECT RAISE(IGNORE); END;").unwrap();
        assert_eq!(cache.evict_recent(0).unwrap().removed_bytes, 0);
        let mut bytes = Vec::new();
        cache
            .open_content(&scope, &version)
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes, b"abc");
    }

    #[test]
    fn content_publication_rechecks_listing_after_source_staging() {
        for (invalidate, existing) in [(false, false), (true, false), (true, true)] {
            let (_temp, cache) = cache();
            let scope = scope(ScopeProtection::PlaintextAllowed);
            let version = ContentVersion {
                resource_id: "file".into(),
                etag: "etag-1".into(),
                protection: ContentProtection::Plaintext,
            };
            cache
                .publish_listing(
                    &scope,
                    "root-a",
                    &[entry("file", "file.txt", "/file.txt", "etag-1", 3, false)],
                    1,
                )
                .unwrap();
            if existing {
                cache
                    .publish_content(
                        &scope,
                        &version,
                        &mut Cursor::new(b"abc"),
                        3,
                        Retention::Dirty,
                    )
                    .unwrap();
            }
            let result = cache.publish_content_internal_with_hook(
                &scope,
                &version,
                &mut Cursor::new(b"abc"),
                3,
                ContentPublishOptions {
                    retention: Retention::Recent,
                    recent_budget: false,
                    require_listed: true,
                    expected_ciphertext_epoch: None,
                    pin_build: None,
                    ciphertext_write: None,
                },
                || {
                    if invalidate {
                        cache.invalidate_paths(&scope, &["/file.txt"]).unwrap();
                    } else {
                        cache
                            .publish_listing(
                                &scope,
                                "root-a",
                                &[entry("file", "file.txt", "/file.txt", "etag-2", 3, false)],
                                2,
                            )
                            .unwrap();
                    }
                },
            );
            assert!(matches!(result, Err(CacheError::Conflict)));
            let record = cache.content_record(&scope, &version);
            let blob = cache
                .inner
                .content_dir
                .join(format!("{}.blob", content_key(&scope, &version)));
            if existing {
                assert_eq!(record.unwrap().retention, Retention::Dirty);
                assert_eq!(fs::read(blob).unwrap(), b"abc");
            } else {
                assert!(matches!(record, Err(CacheError::NotFound)));
                assert!(!blob.exists());
            }
        }
    }

    #[test]
    fn concurrent_open_preserves_unindexed_in_flight_publication() {
        let (temp, cache) = cache();
        let scope = scope(ScopeProtection::PlaintextAllowed);
        let version = ContentVersion {
            resource_id: "file".into(),
            etag: "etag-1".into(),
            protection: ContentProtection::Plaintext,
        };
        cache
            .publish_listing(
                &scope,
                "root-a",
                &[entry("file", "file.txt", "/file.txt", "etag-1", 3, false)],
                1,
            )
            .unwrap();
        cache
            .publish_content_internal_with_hook(
                &scope,
                &version,
                &mut Cursor::new(b"abc"),
                3,
                ContentPublishOptions {
                    retention: Retention::Recent,
                    recent_budget: false,
                    require_listed: true,
                    expected_ciphertext_epoch: None,
                    pin_build: None,
                    ciphertext_write: None,
                },
                || {
                    // A separate cache connection performs startup reconciliation
                    // while this publication has bytes but no committed index row.
                    let other = Cache::open(temp.path(), 1024).unwrap();
                    drop(other);
                },
            )
            .unwrap();
        let reopened = Cache::open(temp.path(), 1024).unwrap();
        let mut bytes = Vec::new();
        reopened
            .open_content(&scope, &version)
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes, b"abc");
    }

    #[test]
    fn cloud_only_wins_when_content_publication_is_already_staged() {
        let (_temp, cache) = cache();
        let scope = scope(ScopeProtection::PlaintextAllowed);
        let file_entry = entry("file", "file.txt", "/file.txt", "etag-1", 3, false);
        cache
            .publish_listing(&scope, "root-a", &[file_entry], 1)
            .unwrap();
        let version = ContentVersion {
            resource_id: "file".into(),
            etag: "etag-1".into(),
            protection: ContentProtection::Plaintext,
        };

        let staged = Arc::new(Barrier::new(2));
        let resume = Arc::new(Barrier::new(2));
        let worker_cache = cache.clone();
        let worker_scope = scope.clone();
        let worker_version = version.clone();
        let worker_staged = staged.clone();
        let worker_resume = resume.clone();
        let publisher = std::thread::spawn(move || {
            let mut source = Cursor::new(b"abc");
            worker_cache.publish_content_internal_with_hook(
                &worker_scope,
                &worker_version,
                &mut source,
                3,
                ContentPublishOptions {
                    retention: Retention::Recent,
                    recent_budget: false,
                    require_listed: true,
                    expected_ciphertext_epoch: None,
                    pin_build: None,
                    ciphertext_write: None,
                },
                || {
                    worker_staged.wait();
                    worker_resume.wait();
                },
            )
        });

        // Publication owns the shared lease first. CloudOnly follows it and
        // removes the committed recent bytes under the exclusive lease.
        staged.wait();
        resume.wait();
        cache
            .set_policy(&scope, "file", AvailabilityPolicy::CloudOnly)
            .unwrap();
        assert!(publisher.join().unwrap().is_ok());
        assert_eq!(
            cache.policy(&scope, "file").unwrap(),
            AvailabilityPolicy::CloudOnly
        );
        assert_eq!(cache.usage().unwrap().used_bytes, 0);
        assert_eq!(
            fs::read_dir(cache.inner.content_dir.as_path())
                .unwrap()
                .count(),
            0
        );
        assert!(matches!(
            cache.open_content(&scope, &version),
            Err(CacheError::NotFound)
        ));
    }

    #[test]
    fn offline_write_keeps_explicit_base_and_is_not_a_delete() {
        let (_temp, cache) = cache();
        let scope = scope(ScopeProtection::PlaintextAllowed);
        let existing = entry("file", "a.txt", "/a.txt", "base-etag", 4, false);
        cache
            .publish_listing(&scope, "root-a", std::slice::from_ref(&existing), 1)
            .unwrap();
        let write = cache
            .queue_conditional_write(
                &scope,
                ConditionalWriteRequest {
                    parent_resource_id: "root-a".into(),
                    name: "a.txt".into(),
                    logical_path: "/a.txt".into(),
                    resource_id: Some("file".into()),
                    base: WriteCondition::Match("base-etag".into()),
                    expected_len: 4,
                    protection: ContentProtection::Plaintext,
                },
                &mut Cursor::new(b"edit"),
            )
            .unwrap();
        assert_eq!(write.base, WriteCondition::Match("base-etag".into()));
        assert_eq!(cache.pending_writes(&scope).unwrap(), vec![write.clone()]);
        cache.mark_write_conflict(&scope, write.id).unwrap();
        assert_eq!(
            cache.pending_writes(&scope).unwrap()[0].state,
            WriteState::Conflict
        );
        assert!(cache.open_content(&scope, &write.content).is_ok());
    }

    #[test]
    fn cloud_only_preserves_recent_content_referenced_by_pending_write() {
        let (_temp, cache) = cache();
        let scope = scope(ScopeProtection::PlaintextAllowed);
        cache.publish_listing(&scope, "root-a", &[], 1).unwrap();
        let write = cache
            .queue_conditional_write(
                &scope,
                ConditionalWriteRequest {
                    parent_resource_id: "root-a".into(),
                    name: "new.txt".into(),
                    logical_path: "/new.txt".into(),
                    resource_id: None,
                    base: WriteCondition::Absent,
                    expected_len: 4,
                    protection: ContentProtection::Plaintext,
                },
                &mut Cursor::new(b"edit"),
            )
            .unwrap();
        // References must protect bytes independently of the retention label.
        cache
            .lock_db()
            .unwrap()
            .execute(
                "UPDATE contents SET retention=0 WHERE scope_key=?1 AND resource_id=?2",
                params![scope.key, write.content.resource_id],
            )
            .unwrap();
        assert_eq!(
            cache.set_policy(
                &scope,
                &write.content.resource_id,
                AvailabilityPolicy::CloudOnly
            ),
            Err(CacheError::PolicyConflict)
        );
        assert_eq!(cache.pending_writes(&scope).unwrap(), vec![write.clone()]);
        let mut bytes = Vec::new();
        cache
            .open_content(&scope, &write.content)
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes, b"edit");
    }

    #[test]
    fn conflict_copy_is_exact_account_scoped_and_leaves_journal_conflicted() {
        let (_temp, cache) = cache();
        let scope = scope(ScopeProtection::PlaintextAllowed);
        let item = entry("file", "a.txt", "/a.txt", "base-etag", 4, false);
        cache.publish_listing(&scope, "root-a", &[item], 1).unwrap();
        let write = cache
            .queue_conditional_write(
                &scope,
                ConditionalWriteRequest {
                    parent_resource_id: "root-a".into(),
                    name: "a.txt".into(),
                    logical_path: "/a.txt".into(),
                    resource_id: Some("file".into()),
                    base: WriteCondition::Match("base-etag".into()),
                    expected_len: 4,
                    protection: ContentProtection::Plaintext,
                },
                &mut Cursor::new(b"edit"),
            )
            .unwrap();
        cache.mark_write_conflict(&scope, write.id).unwrap();

        let mut copied = Vec::new();
        let item = cache
            .copy_conflict_write_for_account("account-a", "space-a", write.id, &mut copied)
            .unwrap();
        assert_eq!(copied, b"edit");
        assert_eq!(item.write_id, write.id);
        assert_eq!(item.path, "/a.txt");
        assert_eq!(item.bytes, 4);
        assert_eq!(item.state, WriteState::Conflict);
        assert_eq!(
            cache.pending_writes(&scope).unwrap()[0].state,
            WriteState::Conflict
        );

        assert_eq!(
            cache.copy_conflict_write_for_account(
                "other-account",
                "space-a",
                write.id,
                &mut Vec::new()
            ),
            Err(CacheError::NotFound)
        );
        assert_eq!(
            cache.copy_conflict_write_for_account(
                "account-a",
                "other-space",
                write.id,
                &mut Vec::new()
            ),
            Err(CacheError::NotFound)
        );
        assert_eq!(
            cache.copy_conflict_write_for_account(
                "account-a",
                "space-a",
                i64::MAX,
                &mut Vec::new()
            ),
            Err(CacheError::NotFound)
        );
    }

    #[test]
    fn conflict_copy_rejects_nonconflict_and_detects_content_corruption() {
        let (_temp, cache) = cache();
        let scope = scope(ScopeProtection::PlaintextAllowed);
        let item = entry("file", "a.txt", "/a.txt", "base-etag", 4, false);
        cache.publish_listing(&scope, "root-a", &[item], 1).unwrap();
        let write = cache
            .queue_conditional_write(
                &scope,
                ConditionalWriteRequest {
                    parent_resource_id: "root-a".into(),
                    name: "a.txt".into(),
                    logical_path: "/a.txt".into(),
                    resource_id: Some("file".into()),
                    base: WriteCondition::Match("base-etag".into()),
                    expected_len: 4,
                    protection: ContentProtection::Plaintext,
                },
                &mut Cursor::new(b"edit"),
            )
            .unwrap();
        assert_eq!(
            cache.copy_conflict_write_for_account(
                "account-a",
                "space-a",
                write.id,
                &mut Vec::new()
            ),
            Err(CacheError::Conflict)
        );
        cache.mark_write_conflict(&scope, write.id).unwrap();
        let record = cache.content_record(&scope, &write.content).unwrap();
        let blob = cache
            .inner
            .content_dir
            .join(format!("{}.blob", content_key(&scope, &write.content)));
        fs::write(blob, b"evil").unwrap();
        let mut copied = Vec::new();
        assert_eq!(
            cache.copy_conflict_write_for_account("account-a", "space-a", write.id, &mut copied),
            Err(CacheError::Corrupt)
        );
        assert!(copied.is_empty());
        assert_eq!(
            cache.content_record(&scope, &write.content).unwrap(),
            record
        );
    }

    #[test]
    fn journal_versions_do_not_overwrite_base_and_replacements_keep_base_condition() {
        let (_temp, cache) = cache();
        let scope = scope(ScopeProtection::PlaintextAllowed);
        let existing = entry("file", "a.txt", "/a.txt", "base-etag", 4, false);
        cache
            .publish_listing(&scope, "root-a", std::slice::from_ref(&existing), 1)
            .unwrap();
        let base_version = ContentVersion {
            resource_id: "file".into(),
            etag: "base-etag".into(),
            protection: ContentProtection::Plaintext,
        };
        cache
            .publish_content(
                &scope,
                &base_version,
                &mut Cursor::new(b"base"),
                4,
                Retention::Recent,
            )
            .unwrap();
        let request = |expected_len| ConditionalWriteRequest {
            parent_resource_id: "root-a".into(),
            name: "a.txt".into(),
            logical_path: "/a.txt".into(),
            resource_id: Some("file".into()),
            base: WriteCondition::Match("base-etag".into()),
            expected_len,
            protection: ContentProtection::Plaintext,
        };
        let first = cache
            .queue_conditional_write(&scope, request(4), &mut Cursor::new(b"edit"))
            .unwrap();
        assert_ne!(first.content.etag, "base-etag");
        assert_eq!(first.base, WriteCondition::Match("base-etag".into()));
        let mut base = cache.open_content(&scope, &base_version).unwrap();
        let mut bytes = Vec::new();
        base.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"base");

        let replaced = cache
            .replace_pending_conditional_write(&scope, request(5), &mut Cursor::new(b"edit2"))
            .unwrap();
        assert_eq!(replaced.id, first.id);
        assert_eq!(replaced.base, first.base);
        assert_ne!(replaced.content.etag, first.content.etag);
        let mut pending = cache.open_content(&scope, &replaced.content).unwrap();
        bytes.clear();
        pending.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"edit2");
        assert_eq!(
            cache.pending_write_for_path(&scope, "/a.txt").unwrap(),
            Some(replaced)
        );
        let mut base = cache.open_content(&scope, &base_version).unwrap();
        bytes.clear();
        base.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"base");
    }

    #[test]
    fn pending_write_page_is_account_scoped_bounded_and_offline_safe() {
        let (_temp, cache) = cache();
        let scope = scope(ScopeProtection::PlaintextAllowed);
        for (name, path, id) in [("a.txt", "/a.txt", "file-a"), ("b.txt", "/b.txt", "file-b")] {
            let item = entry(id, name, path, "base-etag", 4, false);
            cache.publish_listing(&scope, "root-a", &[item], 1).unwrap();
            cache
                .queue_conditional_write(
                    &scope,
                    ConditionalWriteRequest {
                        parent_resource_id: "root-a".into(),
                        name: name.into(),
                        logical_path: path.into(),
                        resource_id: Some(id.into()),
                        base: WriteCondition::Match("base-etag".into()),
                        expected_len: 4,
                        protection: ContentProtection::Plaintext,
                    },
                    &mut Cursor::new(b"edit"),
                )
                .unwrap();
        }
        let first = cache
            .pending_write_page_for_account("account-a", None, 1)
            .unwrap();
        assert_eq!(first.pending_count, 2);
        assert_eq!(first.conflict_count, 0);
        assert_eq!(first.items.len(), 1);
        assert!(first.truncated);
        let cursor = first.next_after.as_deref().unwrap();
        let second = cache
            .pending_write_page_for_account("account-a", Some(cursor), 1)
            .unwrap();
        assert_eq!(second.items.len(), 1);
        assert!(!second.truncated);
        assert_ne!(first.items[0].path, second.items[0].path);
        assert!(
            cache
                .pending_write_page_for_account("account-b", None, 10)
                .unwrap()
                .items
                .is_empty()
        );
    }

    #[test]
    fn absent_offline_write_is_conditional_and_protected() {
        let (_temp, cache) = cache();
        let scope = scope(ScopeProtection::PlaintextAllowed);
        cache.publish_listing(&scope, "root-a", &[], 1).unwrap();
        let write = cache
            .queue_conditional_write(
                &scope,
                ConditionalWriteRequest {
                    parent_resource_id: "root-a".into(),
                    name: "new.txt".into(),
                    logical_path: "/new.txt".into(),
                    resource_id: None,
                    base: WriteCondition::Absent,
                    expected_len: 4,
                    protection: ContentProtection::Plaintext,
                },
                &mut Cursor::new(b"data"),
            )
            .unwrap();
        assert_eq!(write.base, WriteCondition::Absent);
        cache.evict_recent(0).unwrap();
        let mut recovered = cache.open_content(&scope, &write.content).unwrap();
        let mut bytes = Vec::new();
        recovered.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"data");
    }

    #[test]
    fn encrypted_scope_discovery_is_exact_and_paged_without_paths() {
        let (_temp, cache) = cache();
        let first = scope(ScopeProtection::CiphertextOnly);
        let second = CacheScope::new(
            first.origin(),
            first.account_id(),
            "space-b",
            "root-b",
            ScopeProtection::CiphertextOnly,
        )
        .unwrap();
        let other_account = CacheScope::new(
            first.origin(),
            "account-b",
            "space-a",
            "root-c",
            ScopeProtection::CiphertextOnly,
        )
        .unwrap();
        let other_origin = CacheScope::new(
            "https://other.example.test",
            first.account_id(),
            "space-a",
            "root-d",
            ScopeProtection::CiphertextOnly,
        )
        .unwrap();
        let plain = CacheScope::new(
            first.origin(),
            first.account_id(),
            "space-c",
            "root-e",
            ScopeProtection::PlaintextAllowed,
        )
        .unwrap();
        for registered in [&first, &second, &other_account, &other_origin] {
            cache.ciphertext_epoch(registered).unwrap();
        }
        cache.publish_listing(&plain, "root-e", &[], 1).unwrap();

        let first_page = cache
            .ciphertext_scopes_for_account(first.origin(), first.account_id(), None, 1)
            .unwrap();
        assert_eq!(first_page.items, vec![first.clone()]);
        assert!(first_page.truncated);
        let second_page = cache
            .ciphertext_scopes_for_account(
                first.origin(),
                first.account_id(),
                first_page
                    .next_after
                    .as_ref()
                    .map(|(space, root)| (space.as_str(), root.as_str())),
                1,
            )
            .unwrap();
        assert_eq!(second_page.items, vec![second]);
        assert!(!second_page.truncated);
        assert!(second_page.next_after.is_none());
    }

    #[test]
    fn ciphertext_invalidation_is_exact_and_preserves_protected_records() {
        let (_temp, cache) = cache();
        let target = scope(ScopeProtection::CiphertextOnly);
        let other = CacheScope::new(
            "https://cloud.example.test/",
            "account-a",
            "space-a",
            "other-root",
            ScopeProtection::CiphertextOnly,
        )
        .unwrap();
        let recent = ContentVersion {
            resource_id: "recent-file".into(),
            etag: "v1".into(),
            protection: ContentProtection::Ciphertext,
        };
        let dirty = ContentVersion {
            resource_id: "dirty-file".into(),
            etag: "v1".into(),
            protection: ContentProtection::Ciphertext,
        };
        let pinned = ContentVersion {
            resource_id: "pinned-file".into(),
            etag: "v1".into(),
            protection: ContentProtection::Ciphertext,
        };
        for (which_scope, version, retention) in [
            (&target, &recent, Retention::Recent),
            (&target, &dirty, Retention::Dirty),
            (&target, &pinned, Retention::Recent),
            (&other, &recent, Retention::Recent),
        ] {
            cache
                .publish_content(
                    which_scope,
                    version,
                    &mut Cursor::new(b"cipher"),
                    6,
                    retention,
                )
                .unwrap();
        }
        {
            let db = cache.lock_db().unwrap();
            db.execute(
                "INSERT INTO pins(pin_id,scope_key,root_id,root_path,state,created_at) VALUES('pin-a',?1,'root-a','/',1,1)",
                [&target.key],
            )
            .unwrap();
            db.execute(
                "INSERT INTO pin_items(pin_id,resource_id,parent_id,name,path,etag,size,directory,encrypted) VALUES('pin-a','pinned-file','root-a','pinned','/pinned','v1',6,0,1)",
                [],
            )
            .unwrap();
        }

        assert_eq!(cache.ciphertext_epoch(&target).unwrap(), 0);
        assert_eq!(cache.invalidate_ciphertext_scope(&target).unwrap(), 1);
        assert_eq!(cache.ciphertext_epoch(&target).unwrap(), 1);
        assert!(matches!(
            cache.content_record(&target, &recent),
            Err(CacheError::NotFound)
        ));
        assert!(cache.open_content(&target, &dirty).is_ok());
        assert!(cache.open_content(&target, &pinned).is_ok());
        assert!(cache.open_content(&other, &recent).is_ok());
        let pins = cache.pins(&target).unwrap();
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].state, PinState::Stale);
        assert!(matches!(
            cache.invalidate_ciphertext_scope(&scope(ScopeProtection::PlaintextAllowed)),
            Err(CacheError::ProtectionMismatch)
        ));
    }

    #[test]
    fn ciphertext_publication_is_serialized_before_invalidation() {
        let (_temp, cache) = cache();
        let target = scope(ScopeProtection::CiphertextOnly);
        let epoch = cache.ciphertext_epoch(&target).unwrap();
        let version = ContentVersion {
            resource_id: "file".into(),
            etag: "v1".into(),
            protection: ContentProtection::Ciphertext,
        };
        let staged = Arc::new(Barrier::new(2));
        let resume = Arc::new(Barrier::new(2));
        let worker_cache = cache.clone();
        let worker_scope = target.clone();
        let worker_version = version.clone();
        let worker_staged = staged.clone();
        let worker_resume = resume.clone();
        let publisher = std::thread::spawn(move || {
            worker_cache.publish_content_internal_with_hook(
                &worker_scope,
                &worker_version,
                &mut Cursor::new(b"cipher"),
                6,
                ContentPublishOptions {
                    retention: Retention::Recent,
                    recent_budget: false,
                    require_listed: false,
                    expected_ciphertext_epoch: Some(epoch),
                    pin_build: None,
                    ciphertext_write: None,
                },
                || {
                    worker_staged.wait();
                    worker_resume.wait();
                },
            )
        });
        staged.wait();
        resume.wait();
        cache.invalidate_ciphertext_scope(&target).unwrap();
        assert!(publisher.join().unwrap().is_ok());
        assert!(matches!(
            cache.publish_ciphertext_if_epoch(
                &target,
                &version,
                &mut Cursor::new(b"cipher"),
                6,
                Retention::Recent,
                epoch,
            ),
            Err(CacheError::Conflict)
        ));
        assert!(matches!(
            cache.open_content(&target, &version),
            Err(CacheError::NotFound)
        ));
    }

    #[test]
    fn ciphertext_pin_generation_is_atomic_protected_and_epoch_fenced() {
        let (_temp, cache) = cache();
        let target = scope(ScopeProtection::CiphertextOnly);
        let epoch = cache.ciphertext_epoch(&target).unwrap();
        let build = cache.begin_ciphertext_pin(&target, epoch, None).unwrap();
        let root = ContentVersion {
            resource_id: "raiun-vault-listing-v1:root-a".into(),
            etag: "raiun-vault-sealed-metadata-v2:0".into(),
            protection: ContentProtection::Ciphertext,
        };
        let file = ContentVersion {
            resource_id: "remote-file-id".into(),
            etag: "raiun-vault-file-ciphertext-v1:0:strong-etag".into(),
            protection: ContentProtection::Ciphertext,
        };
        cache
            .publish_ciphertext_for_pin_if_epoch(
                &target,
                &root,
                &mut Cursor::new(b"sealed root snapshot"),
                20,
                &build,
                CiphertextPinItemKind::RootListing,
            )
            .unwrap();
        cache
            .publish_ciphertext_for_pin_if_epoch(
                &target,
                &file,
                &mut Cursor::new(b"ciphertext block"),
                16,
                &build,
                CiphertextPinItemKind::FileContent,
            )
            .unwrap();
        assert_eq!(
            cache
                .ciphertext_pin_info(&target, build.id())
                .unwrap()
                .state,
            CiphertextPinState::Building
        );
        assert!(matches!(
            cache.open_ciphertext_pin_content(&target, build.id(), &file),
            Err(CacheError::NotFound)
        ));
        let ready = cache.finish_ciphertext_pin(&target, &build).unwrap();
        assert_eq!(ready.state, CiphertextPinState::Ready);
        assert_eq!(ready.item_count, 2);
        assert_eq!(ready.byte_len, 36);
        let usage = cache.usage().unwrap();
        assert_eq!(usage.pinned_bytes, 36);
        assert_eq!(usage.protected_bytes, 36);

        let refresh = cache
            .begin_ciphertext_pin(&target, epoch, Some(build.id()))
            .unwrap();
        assert_eq!(refresh.generation(), build.generation() + 1);
        // A staged refresh cannot hide or replace the last complete generation.
        assert_eq!(
            cache
                .active_ciphertext_pin_info(&target, build.id())
                .unwrap()
                .generation,
            build.generation()
        );
        assert!(
            cache
                .open_ciphertext_pin_content(&target, build.id(), &file)
                .is_ok()
        );
        cache.abandon_ciphertext_pin(&target, &refresh).unwrap();
        assert_eq!(
            cache
                .active_ciphertext_pin_info(&target, build.id())
                .unwrap()
                .generation,
            build.generation()
        );
        assert!(
            cache
                .open_ciphertext_pin_content(&target, build.id(), &file)
                .is_ok(),
            "aborting a refresh must preserve the last complete snapshot"
        );

        cache.invalidate_ciphertext_scope(&target).unwrap();
        assert_eq!(
            cache
                .ciphertext_pin_info(&target, build.id())
                .unwrap()
                .state,
            CiphertextPinState::Stale
        );
        assert!(matches!(
            cache.open_ciphertext_pin_content(&target, build.id(), &file),
            Err(CacheError::NotFound)
        ));
        assert!(cache.open_content(&target, &file).is_ok());
        assert!(cache.usage().unwrap().protected_bytes >= 36);
        cache.remove_ciphertext_pin(&target, build.id()).unwrap();
        cache.evict_recent(0).unwrap();
        assert!(matches!(
            cache.open_content(&target, &file),
            Err(CacheError::NotFound)
        ));
    }

    #[test]
    fn active_pin_generation_publication_releases_db_but_fences_refresh() {
        let (_temp, cache) = cache();
        let target = scope(ScopeProtection::CiphertextOnly);
        let epoch = cache.ciphertext_epoch(&target).unwrap();
        let build = cache.begin_ciphertext_pin(&target, epoch, None).unwrap();
        let root = ContentVersion {
            resource_id: "raiun-vault-listing-v1:root-a".into(),
            etag: "raiun-vault-sealed-metadata-v2:0".into(),
            protection: ContentProtection::Ciphertext,
        };
        cache
            .publish_ciphertext_for_pin_if_epoch(
                &target,
                &root,
                &mut Cursor::new(b"sealed root"),
                11,
                &build,
                CiphertextPinItemKind::RootListing,
            )
            .unwrap();
        let ready = cache.finish_ciphertext_pin(&target, &build).unwrap();

        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let lease_cache = cache.clone();
        let lease_scope = target.clone();
        let lease_pin_id = ready.id.clone();
        let ready_generation = ready.generation;
        let lease_entered = entered.clone();
        let lease_release = release.clone();
        let lease = std::thread::spawn(move || {
            lease_cache.with_active_ciphertext_pin_generation(
                &lease_scope,
                &lease_pin_id,
                ready_generation,
                || {
                    // Simulate route publication hooks that need to inspect
                    // cache state while FUSE locks are held. This must not
                    // deadlock behind a SQLite transaction retained by the
                    // publication lease.
                    assert_eq!(
                        lease_cache
                            .active_ciphertext_pin_info(&lease_scope, &lease_pin_id)
                            .unwrap()
                            .generation,
                        ready_generation
                    );
                    lease_entered.wait();
                    lease_release.wait();
                    17
                },
            )
        });
        entered.wait();

        let (refresh_started_tx, refresh_started_rx) = std::sync::mpsc::channel();
        let (refresh_tx, refresh_rx) = std::sync::mpsc::channel();
        // Reopen the same on-disk cache to ensure the lease is shared across
        // independent Cache handles, not only `Cache::clone()` instances.
        let refresh_cache = Cache::open(_temp.path(), 10 * 1024 * 1024).unwrap();
        let refresh_scope = target.clone();
        let refresh_pin_id = ready.id.clone();
        let refresh = std::thread::spawn(move || {
            refresh_started_tx.send(()).unwrap();
            let result =
                refresh_cache.begin_ciphertext_pin(&refresh_scope, epoch, Some(&refresh_pin_id));
            refresh_tx.send(result).unwrap();
        });
        refresh_started_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        assert!(matches!(
            refresh_rx.recv_timeout(std::time::Duration::from_millis(50)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));

        let (reader_tx, reader_rx) = std::sync::mpsc::channel();
        let reader_cache = cache.clone();
        let reader_scope = target.clone();
        let reader_pin_id = ready.id.clone();
        let reader = std::thread::spawn(move || {
            let info = reader_cache
                .active_ciphertext_pin_info(&reader_scope, &reader_pin_id)
                .unwrap();
            reader_tx.send(info.generation).unwrap();
        });
        assert_eq!(
            reader_rx
                .recv_timeout(std::time::Duration::from_secs(1))
                .expect("reader should not wait for publication's SQLite lock"),
            ready.generation
        );
        reader.join().unwrap();

        let other_scope = CacheScope::new(
            target.origin(),
            target.account_id(),
            "another-space",
            "another-root",
            ScopeProtection::CiphertextOnly,
        )
        .unwrap();
        let other_cache = Cache::open(_temp.path(), 10 * 1024 * 1024).unwrap();
        let (other_invalidation_tx, other_invalidation_rx) = std::sync::mpsc::channel();
        let other_invalidation = std::thread::spawn(move || {
            other_invalidation_tx
                .send(other_cache.invalidate_ciphertext_scope(&other_scope))
                .unwrap();
        });
        assert_eq!(
            other_invalidation_rx
                .recv_timeout(std::time::Duration::from_secs(1))
                .expect("another scope must not wait on this route's pin publication")
                .unwrap(),
            1
        );
        other_invalidation.join().unwrap();

        release.wait();
        assert_eq!(lease.join().unwrap().unwrap(), 17);
        let refreshed = refresh_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap()
            .unwrap();
        refresh.join().unwrap();
        assert_eq!(refreshed.generation(), ready.generation + 1);
    }

    #[test]
    fn successful_ciphertext_refresh_retires_only_superseded_pin_references() {
        let (_temp, cache) = cache();
        let target = scope(ScopeProtection::CiphertextOnly);
        let epoch = cache.ciphertext_epoch(&target).unwrap();
        let mut previous_pin_id: Option<String> = None;
        let mut first_reader = None;
        let mut first_version = None;

        for generation_index in 0..24 {
            let build = cache
                .begin_ciphertext_pin(&target, epoch, previous_pin_id.as_deref())
                .unwrap();
            let root = ContentVersion {
                resource_id: "raiun-vault-listing-v1:root-a".into(),
                etag: format!("raiun-vault-sealed-metadata-v2:{generation_index}"),
                protection: ContentProtection::Ciphertext,
            };
            let file = ContentVersion {
                resource_id: "remote-file-id".into(),
                etag: format!("raiun-vault-file-ciphertext-v1:0:version-{generation_index}"),
                protection: ContentProtection::Ciphertext,
            };
            let root_bytes = format!("sealed root {generation_index}");
            cache
                .publish_ciphertext_for_pin_if_epoch(
                    &target,
                    &root,
                    &mut Cursor::new(root_bytes.as_bytes()),
                    root_bytes.len() as u64,
                    &build,
                    CiphertextPinItemKind::RootListing,
                )
                .unwrap();
            let file_bytes = format!("verified ciphertext {generation_index}");
            cache
                .publish_ciphertext_for_pin_if_epoch(
                    &target,
                    &file,
                    &mut Cursor::new(file_bytes.as_bytes()),
                    file_bytes.len() as u64,
                    &build,
                    CiphertextPinItemKind::FileContent,
                )
                .unwrap();
            let ready = cache.finish_ciphertext_pin(&target, &build).unwrap();
            assert_eq!(ready.generation, build.generation());
            assert_eq!(cache.usage().unwrap().pinned_bytes, ready.byte_len);
            if generation_index == 0 {
                first_reader = Some(
                    cache
                        .open_ciphertext_pin_content(&target, build.id(), &file)
                        .unwrap(),
                );
                first_version = Some(file);
            }
            let generation_count: i64 = cache
                .lock_db()
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM ciphertext_pin_generations WHERE pin_id=?1",
                    [build.id()],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(generation_count, 1, "old generations must not accumulate");
            previous_pin_id = Some(build.id().to_owned());
        }

        let mut already_open = first_reader.take().unwrap();
        let mut bytes = Vec::new();
        already_open.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"verified ciphertext 0");
        let old_version = first_version.unwrap();
        assert!(matches!(
            cache.open_ciphertext_pin_content(
                &target,
                previous_pin_id.as_deref().unwrap(),
                &old_version
            ),
            Err(CacheError::NotFound)
        ));
        drop(already_open);
        cache.evict_recent(0).unwrap();
        assert!(matches!(
            cache.open_content(&target, &old_version),
            Err(CacheError::NotFound)
        ));
        assert_eq!(
            cache.usage().unwrap().protected_bytes,
            cache.usage().unwrap().pinned_bytes
        );
    }

    #[test]
    fn ciphertext_pin_rejects_incomplete_and_stale_builds() {
        let (_temp, cache) = cache();
        let target = scope(ScopeProtection::CiphertextOnly);
        let epoch = cache.ciphertext_epoch(&target).unwrap();
        let build = cache.begin_ciphertext_pin(&target, epoch, None).unwrap();
        let file = ContentVersion {
            resource_id: "remote-file-id".into(),
            etag: "raiun-vault-file-ciphertext-v1:0:strong-etag".into(),
            protection: ContentProtection::Ciphertext,
        };
        cache
            .publish_ciphertext_for_pin_if_epoch(
                &target,
                &file,
                &mut Cursor::new(b"ciphertext"),
                10,
                &build,
                CiphertextPinItemKind::FileContent,
            )
            .unwrap();
        assert_eq!(
            cache.finish_ciphertext_pin(&target, &build),
            Err(CacheError::IncompleteManifest)
        );
        cache.invalidate_ciphertext_scope(&target).unwrap();
        let root = ContentVersion {
            resource_id: "raiun-vault-listing-v1:root-a".into(),
            etag: "raiun-vault-sealed-metadata-v2:0".into(),
            protection: ContentProtection::Ciphertext,
        };
        assert_eq!(
            cache.publish_ciphertext_for_pin_if_epoch(
                &target,
                &root,
                &mut Cursor::new(b"sealed"),
                6,
                &build,
                CiphertextPinItemKind::RootListing,
            ),
            Err(CacheError::Conflict)
        );
        cache.abandon_ciphertext_pin(&target, &build).unwrap();
        let other = CacheScope::new(
            target.origin(),
            "other-account",
            target.space_id(),
            target.root_resource_id(),
            ScopeProtection::CiphertextOnly,
        )
        .unwrap();
        assert_eq!(
            cache.finish_ciphertext_pin(&other, &build),
            Err(CacheError::InvalidScope)
        );
    }

    #[test]
    fn ciphertext_write_revisions_survive_epoch_invalidation_and_preserve_old_revision_on_race() {
        let (_temp, cache) = cache();
        let target = scope(ScopeProtection::CiphertextOnly);
        let build = cache
            .begin_ciphertext_write(&target, None, "encrypted/path/name", 15)
            .unwrap();
        let first = cache
            .publish_ciphertext_write(&target, &build, &mut Cursor::new(b"sealed edit one"), 15)
            .unwrap();
        assert_eq!(first.revision, 1);
        assert_eq!(first.state, CiphertextWriteState::Pending);

        let mut first_open = cache
            .open_ciphertext_write(&target, &first.id, first.revision)
            .unwrap();
        let next = cache
            .begin_ciphertext_write(&target, Some(&first.id), "encrypted/path/name", 15)
            .unwrap();
        // A competing revision cannot replace the current durable record.
        let competitor = cache
            .begin_ciphertext_write(&target, Some(&first.id), "encrypted/path/name", 15)
            .unwrap();
        let second = cache
            .publish_ciphertext_write(&target, &next, &mut Cursor::new(b"sealed edit two"), 15)
            .unwrap();
        assert_eq!(second.revision, 2);
        assert_eq!(second.target_key.len(), 64);
        assert_eq!(
            cache
                .ciphertext_write_for_target(&target, "encrypted/path/name")
                .unwrap(),
            Some(second.clone())
        );
        assert_eq!(
            cache.publish_ciphertext_write(
                &target,
                &competitor,
                &mut Cursor::new(b"stale edit"),
                10
            ),
            Err(CacheError::Conflict)
        );

        cache.invalidate_ciphertext_scope(&target).unwrap();
        let mut bytes = Vec::new();
        first_open.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"sealed edit one");
        let (writes, truncated) = cache.ciphertext_writes(&target, None, 10).unwrap();
        assert!(!truncated);
        assert_eq!(writes, vec![second.clone()]);
        let mut current = cache
            .open_ciphertext_write(&target, &second.id, second.revision)
            .unwrap();
        let mut current_bytes = Vec::new();
        current.read_to_end(&mut current_bytes).unwrap();
        assert_eq!(current_bytes, b"sealed edit two");
        assert!(
            cache
                .retire_ciphertext_write(&target, &first.id, first.revision)
                .is_err()
        );
        cache
            .retire_ciphertext_write(&target, &second.id, second.revision)
            .unwrap();
        assert!(
            cache
                .ciphertext_writes(&target, None, 10)
                .unwrap()
                .0
                .is_empty()
        );
    }

    #[test]
    fn copy_retirement_compares_operation_revision_and_unresolved_state() {
        let (_temp, cache) = cache();
        let target = scope(ScopeProtection::CiphertextOnly);
        let build = cache
            .begin_ciphertext_operation_with_state_and_parent(
                &target,
                None,
                "encrypted-parent/encrypted-copy",
                Some("encrypted-parent"),
                6,
                CiphertextWriteOperation::CopyFile,
                CiphertextWriteState::NeverAttempted,
            )
            .unwrap();
        let row = cache
            .publish_ciphertext_write(&target, &build, &mut Cursor::new(b"sealed"), 6)
            .unwrap();
        cache
            .claim_ciphertext_copy_attempt(&target, &row.id, row.revision)
            .unwrap();
        assert!(matches!(
            cache.retire_ciphertext_copy_write(
                &target,
                &row.id,
                row.revision,
                CiphertextWriteState::Uncertain,
            ),
            Err(CacheError::Conflict)
        ));

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let cache = cache.clone();
            let target = target.clone();
            let barrier = barrier.clone();
            let id = row.id.clone();
            let revision = row.revision;
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                cache.retire_ciphertext_copy_write(
                    &target,
                    &id,
                    revision,
                    CiphertextWriteState::Attempting,
                )
            }));
        }
        barrier.wait();
        let results = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(CacheError::Conflict)))
                .count(),
            1
        );
        assert!(cache.ciphertext_write_info(&target, &row.id).is_err());
    }

    #[test]
    fn ciphertext_rename_index_uses_encrypted_source_and_destination_parent() {
        let (_temp, cache) = cache();
        let target = scope(ScopeProtection::CiphertextOnly);
        let build = cache
            .begin_ciphertext_operation_with_state_and_parent(
                &target,
                None,
                "encrypted/source-name",
                Some("encrypted/destination-parent"),
                0,
                CiphertextWriteOperation::RenameFile,
                CiphertextWriteState::Pending,
            )
            .unwrap();
        let info = cache
            .publish_ciphertext_write(&target, &build, &mut Cursor::new([]), 0)
            .unwrap();
        assert_eq!(info.operation, CiphertextWriteOperation::RenameFile);
        assert_eq!(
            cache
                .ciphertext_write_for_target(&target, "encrypted/source-name")
                .unwrap(),
            Some(info.clone())
        );
        let (renames, truncated) = cache
            .ciphertext_renames_for_parent(&target, "encrypted/destination-parent", None, 10)
            .unwrap();
        assert!(!truncated);
        assert_eq!(renames, vec![info]);
        let (wrong_parent, _) = cache
            .ciphertext_renames_for_parent(&target, "encrypted/source-parent", None, 10)
            .unwrap();
        assert!(wrong_parent.is_empty());
    }

    #[test]
    fn ciphertext_create_operations_are_parent_indexed_and_revision_kind_is_fixed() {
        let (_temp, cache) = cache();
        let target = scope(ScopeProtection::CiphertextOnly);
        let create = cache
            .begin_ciphertext_operation_with_state(
                &target,
                None,
                "encrypted-parent/new-child",
                0,
                CiphertextWriteOperation::CreateFile,
                CiphertextWriteState::Building,
            )
            .unwrap();
        let created = cache
            .publish_ciphertext_write(&target, &create, &mut Cursor::new(b""), 0)
            .unwrap();
        assert_eq!(created.operation, CiphertextWriteOperation::CreateFile);
        assert_eq!(created.state, CiphertextWriteState::Building);
        assert!(
            cache
                .retryable_ciphertext_writes(&target, 10)
                .unwrap()
                .0
                .is_empty()
        );

        let revision = cache
            .begin_ciphertext_operation_with_state(
                &target,
                Some(&created.id),
                "encrypted-parent/new-child",
                8,
                CiphertextWriteOperation::CreateFile,
                CiphertextWriteState::Pending,
            )
            .unwrap();
        assert_eq!(revision.revision(), 2);
        assert!(matches!(
            cache.begin_ciphertext_operation(
                &target,
                Some(&created.id),
                "encrypted-parent/new-child",
                7,
                CiphertextWriteOperation::Overwrite,
            ),
            Err(CacheError::Conflict)
        ));
        let latest = cache
            .publish_ciphertext_write(&target, &revision, &mut Cursor::new(b"created"), 7)
            .unwrap();
        assert_eq!(latest.operation, CiphertextWriteOperation::CreateFile);
        assert_eq!(latest.state, CiphertextWriteState::Pending);

        let _other_parent = cache
            .begin_ciphertext_operation(
                &target,
                None,
                "another-parent/child",
                1,
                CiphertextWriteOperation::CreateFile,
            )
            .unwrap();
        let (children, truncated) = cache
            .ciphertext_creates_for_parent(&target, "encrypted-parent", None, 10)
            .unwrap();
        assert!(!truncated);
        assert_eq!(children, vec![latest]);
        assert!(
            cache
                .ciphertext_creates_for_parent(&target, "", None, 10)
                .unwrap()
                .0
                .is_empty()
        );
    }

    #[test]
    fn never_attempted_file_create_retarget_is_atomic_and_legacy_pending_is_not_eligible() {
        let (_temp, cache) = cache();
        let target = scope(ScopeProtection::CiphertextOnly);
        let old_target = "enc-parent/enc-old";
        let new_target = "enc-parent/enc-new";
        let initial = cache
            .begin_ciphertext_operation_with_state_parent_ref(
                &target,
                None,
                old_target,
                Some("enc-parent"),
                None,
                9,
                CiphertextWriteOperation::CreateFile,
                CiphertextWriteState::NeverAttempted,
            )
            .unwrap();
        let first = cache
            .publish_ciphertext_write(&target, &initial, &mut Cursor::new(b"sealed-v1"), 9)
            .unwrap();
        let retarget = cache
            .begin_ciphertext_never_attempted_create_retarget(
                &target,
                &first.id,
                first.revision,
                old_target,
                new_target,
                Some("enc-parent"),
                None,
                9,
            )
            .unwrap();
        let second = cache
            .publish_ciphertext_write(&target, &retarget, &mut Cursor::new(b"sealed-v2"), 9)
            .unwrap();
        assert_eq!(second.id, first.id);
        assert_eq!(second.revision, first.revision + 1);
        assert_eq!(second.state, CiphertextWriteState::NeverAttempted);
        assert!(
            cache
                .ciphertext_write_for_target(&target, old_target)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            cache
                .ciphertext_write_for_target(&target, new_target)
                .unwrap(),
            Some(second.clone())
        );
        let mut opened = cache
            .open_ciphertext_write(&target, &second.id, second.revision)
            .unwrap();
        let mut bytes = Vec::new();
        opened.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"sealed-v2");

        // Claiming the current row wins against an already-prepared rename.
        let stale = cache
            .begin_ciphertext_never_attempted_create_retarget(
                &target,
                &second.id,
                second.revision,
                new_target,
                "enc-parent/enc-stale",
                Some("enc-parent"),
                None,
                9,
            )
            .unwrap();
        cache
            .claim_ciphertext_file_create_attempt(&target, &second.id, second.revision)
            .unwrap();
        assert_eq!(
            cache.publish_ciphertext_write(&target, &stale, &mut Cursor::new(b"stale-v2"), 9,),
            Err(CacheError::Conflict)
        );
        assert_eq!(
            cache
                .ciphertext_write_for_target(&target, new_target)
                .unwrap()
                .unwrap()
                .state,
            CiphertextWriteState::Attempting
        );
    }

    #[test]
    fn never_attempted_directory_retarget_is_atomic_and_revision_fences_children() {
        let (_temp, cache) = cache();
        let target = scope(ScopeProtection::CiphertextOnly);
        let old_target = "encrypted-parent/old-dir";
        let new_target = "encrypted-parent/new-dir";
        let initial = cache
            .begin_ciphertext_operation_with_state_parent_ref(
                &target,
                None,
                old_target,
                Some("encrypted-parent"),
                None,
                0,
                CiphertextWriteOperation::CreateDirectory,
                CiphertextWriteState::NeverAttempted,
            )
            .unwrap();
        let first = cache
            .publish_ciphertext_write(&target, &initial, &mut Cursor::new([]), 0)
            .unwrap();

        let retarget = cache
            .begin_ciphertext_never_attempted_operation_retarget(
                &target,
                CiphertextWriteOperation::CreateDirectory,
                &first.id,
                first.revision,
                old_target,
                new_target,
                Some("encrypted-parent"),
                None,
                0,
            )
            .unwrap();
        let second = cache
            .publish_ciphertext_write(&target, &retarget, &mut Cursor::new([]), 0)
            .unwrap();
        assert_eq!(second.id, first.id);
        assert_eq!(second.revision, first.revision + 1);
        assert_eq!(second.state, CiphertextWriteState::NeverAttempted);
        assert!(
            cache
                .ciphertext_write_for_target(&target, old_target)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            cache
                .ciphertext_write_for_target(&target, new_target)
                .unwrap(),
            Some(second.clone())
        );

        // A child prepared against the prior parent revision cannot publish
        // after the retarget has advanced the parent's dependency key.
        assert_eq!(
            cache.begin_ciphertext_operation_with_state_parent_ref(
                &target,
                None,
                "encrypted-parent/old-dir/child",
                Some("encrypted-parent/old-dir"),
                Some((&first.id, first.revision)),
                0,
                CiphertextWriteOperation::CreateDirectory,
                CiphertextWriteState::NeverAttempted,
            ),
            Err(CacheError::Conflict)
        );
    }

    #[test]
    fn populated_never_attempted_directory_retarget_publishes_complete_subtree_atomically() {
        let (_temp, cache) = cache();
        let target = scope(ScopeProtection::CiphertextOnly);
        let root_old_target = "old-root";
        let child_old_target = "old-root/child-dir";
        let file_old_target = "old-root/child-dir/file";
        let root = cache
            .begin_ciphertext_operation_with_state_and_parent(
                &target,
                None,
                root_old_target,
                Some(""),
                0,
                CiphertextWriteOperation::CreateDirectory,
                CiphertextWriteState::NeverAttempted,
            )
            .unwrap();
        let root_id = root.id().to_owned();
        let root_row = cache
            .publish_ciphertext_write(&target, &root, &mut Cursor::new([]), 0)
            .unwrap();
        let child = cache
            .begin_ciphertext_operation_with_state_parent_ref(
                &target,
                None,
                child_old_target,
                Some("old-root"),
                Some((&root_id, root_row.revision)),
                0,
                CiphertextWriteOperation::CreateDirectory,
                CiphertextWriteState::NeverAttempted,
            )
            .unwrap();
        let child_id = child.id().to_owned();
        let child_row = cache
            .publish_ciphertext_write(&target, &child, &mut Cursor::new([]), 0)
            .unwrap();
        let file = cache
            .begin_ciphertext_operation_with_state_parent_ref(
                &target,
                None,
                file_old_target,
                Some("old-root/child-dir"),
                Some((&child_id, child_row.revision)),
                7,
                CiphertextWriteOperation::CreateFile,
                CiphertextWriteState::NeverAttempted,
            )
            .unwrap();
        let file_id = file.id().to_owned();
        let file_row = cache
            .publish_ciphertext_write(&target, &file, &mut Cursor::new(b"payload"), 7)
            .unwrap();

        let members = vec![
            CiphertextSubtreeRetarget {
                id: root_id.clone(),
                expected_revision: root_row.revision,
                expected_target: root_old_target.into(),
                new_target: "new-root".into(),
                new_parent_path: "".into(),
                new_parent_operation: None,
                plaintext_len: 0,
                operation: CiphertextWriteOperation::CreateDirectory,
            },
            CiphertextSubtreeRetarget {
                id: child_id.clone(),
                expected_revision: child_row.revision,
                expected_target: child_old_target.into(),
                new_target: "new-root/child-dir".into(),
                new_parent_path: "new-root".into(),
                new_parent_operation: Some((root_id.clone(), root_row.revision + 1)),
                plaintext_len: 0,
                operation: CiphertextWriteOperation::CreateDirectory,
            },
            CiphertextSubtreeRetarget {
                id: file_id.clone(),
                expected_revision: file_row.revision,
                expected_target: file_old_target.into(),
                new_target: "new-root/child-dir/file".into(),
                new_parent_path: "new-root/child-dir".into(),
                new_parent_operation: Some((child_id.clone(), child_row.revision + 1)),
                plaintext_len: 7,
                operation: CiphertextWriteOperation::CreateFile,
            },
        ];
        let builds = cache
            .begin_ciphertext_never_attempted_subtree_retarget(
                &target,
                &root_id,
                root_row.revision,
                &members,
            )
            .unwrap();
        let mut bodies = [
            Cursor::new(Vec::<u8>::new()),
            Cursor::new(Vec::<u8>::new()),
            Cursor::new(b"payload".to_vec()),
        ];
        let mut contents = builds
            .iter()
            .zip(bodies.iter_mut())
            .map(|(build, source)| CiphertextSubtreeRetargetContent {
                build,
                source,
                expected_len: if build.operation == CiphertextWriteOperation::CreateDirectory {
                    0
                } else {
                    7
                },
            })
            .collect::<Vec<_>>();
        let result = cache
            .publish_ciphertext_subtree_retarget(&target, &builds, &mut contents, &root_id)
            .unwrap();
        assert_eq!(result.len(), 3);
        for old in [&root_row, &child_row, &file_row] {
            let current = cache.ciphertext_write_info(&target, &old.id).unwrap();
            assert_eq!(current.revision, old.revision + 1);
            assert_ne!(current.target_key, old.target_key);
            assert_eq!(current.state, CiphertextWriteState::NeverAttempted);
        }
        let file_content = cache
            .open_ciphertext_write(&target, &file_id, file_row.revision + 1)
            .unwrap();
        assert_eq!(
            file_content.metadata().unwrap().len(),
            b"payload".len() as u64
        );
    }

    #[test]
    fn populated_subtree_retarget_rechecks_complete_closure_and_attempt_race() {
        let (_temp, cache) = cache();
        let target = scope(ScopeProtection::CiphertextOnly);
        let root = cache
            .begin_ciphertext_operation_with_state_and_parent(
                &target,
                None,
                "old-root",
                Some(""),
                0,
                CiphertextWriteOperation::CreateDirectory,
                CiphertextWriteState::NeverAttempted,
            )
            .unwrap();
        let root_id = root.id().to_owned();
        let root_row = cache
            .publish_ciphertext_write(&target, &root, &mut Cursor::new([]), 0)
            .unwrap();
        let child = cache
            .begin_ciphertext_operation_with_state_parent_ref(
                &target,
                None,
                "old-root/child",
                Some("old-root"),
                Some((&root_id, root_row.revision)),
                0,
                CiphertextWriteOperation::CreateDirectory,
                CiphertextWriteState::NeverAttempted,
            )
            .unwrap();
        let child_id = child.id().to_owned();
        let child_row = cache
            .publish_ciphertext_write(&target, &child, &mut Cursor::new([]), 0)
            .unwrap();
        let members = vec![
            CiphertextSubtreeRetarget {
                id: root_id.clone(),
                expected_revision: root_row.revision,
                expected_target: "old-root".into(),
                new_target: "new-root".into(),
                new_parent_path: "".into(),
                new_parent_operation: None,
                plaintext_len: 0,
                operation: CiphertextWriteOperation::CreateDirectory,
            },
            CiphertextSubtreeRetarget {
                id: child_id.clone(),
                expected_revision: child_row.revision,
                expected_target: "old-root/child".into(),
                new_target: "new-root/child".into(),
                new_parent_path: "new-root".into(),
                new_parent_operation: Some((root_id.clone(), root_row.revision + 1)),
                plaintext_len: 0,
                operation: CiphertextWriteOperation::CreateDirectory,
            },
        ];
        assert!(matches!(
            cache.begin_ciphertext_never_attempted_subtree_retarget(
                &target,
                &root_id,
                root_row.revision,
                &members[..1],
            ),
            Err(CacheError::Conflict)
        ));
        let builds = cache
            .begin_ciphertext_never_attempted_subtree_retarget(
                &target,
                &root_id,
                root_row.revision,
                &members,
            )
            .unwrap();
        cache
            .claim_ciphertext_directory_create_attempt(&target, &child_id, child_row.revision)
            .unwrap();
        let mut bodies = [Cursor::new(Vec::<u8>::new()), Cursor::new(Vec::<u8>::new())];
        let mut contents = builds
            .iter()
            .zip(bodies.iter_mut())
            .map(|(build, source)| CiphertextSubtreeRetargetContent {
                build,
                source,
                expected_len: 0,
            })
            .collect::<Vec<_>>();
        assert!(matches!(
            cache.publish_ciphertext_subtree_retarget(&target, &builds, &mut contents, &root_id),
            Err(CacheError::Conflict)
        ));
        assert_eq!(
            cache
                .ciphertext_write_info(&target, &root_id)
                .unwrap()
                .revision,
            root_row.revision
        );
        assert_eq!(
            cache
                .ciphertext_write_info(&target, &child_id)
                .unwrap()
                .state,
            CiphertextWriteState::Attempting
        );
    }

    #[test]
    fn subtree_retarget_lost_commit_ack_preserves_recovery_after_reopen() {
        let (temp, cache) = cache();
        let target = scope(ScopeProtection::CiphertextOnly);
        let root = cache
            .begin_ciphertext_operation_with_state_and_parent(
                &target,
                None,
                "old-root",
                Some(""),
                0,
                CiphertextWriteOperation::CreateDirectory,
                CiphertextWriteState::NeverAttempted,
            )
            .unwrap();
        let root_id = root.id().to_owned();
        let root_row = cache
            .publish_ciphertext_write(&target, &root, &mut Cursor::new([]), 0)
            .unwrap();
        let members = [CiphertextSubtreeRetarget {
            id: root_id.clone(),
            expected_revision: root_row.revision,
            expected_target: "old-root".into(),
            new_target: "new-root".into(),
            new_parent_path: "".into(),
            new_parent_operation: None,
            plaintext_len: 0,
            operation: CiphertextWriteOperation::CreateDirectory,
        }];
        let builds = cache
            .begin_ciphertext_never_attempted_subtree_retarget(
                &target,
                &root_id,
                root_row.revision,
                &members,
            )
            .unwrap();
        let body = b"sealed retarget recovery";
        let mut source = Cursor::new(body);
        let mut contents = [CiphertextSubtreeRetargetContent {
            build: &builds[0],
            source: &mut source,
            expected_len: body.len() as u64,
        }];
        assert!(matches!(
            cache.publish_ciphertext_subtree_retarget_with_ack(
                &target,
                &builds,
                &mut contents,
                &root_id,
                || Err(CacheError::Database(
                    "simulated lost commit acknowledgement".into()
                )),
            ),
            Err(CacheError::Database(_))
        ));
        drop(cache);
        let reopened = Cache::open(temp.path(), 1024).unwrap();
        let row = reopened.ciphertext_write_info(&target, &root_id).unwrap();
        assert_eq!(row.revision, root_row.revision + 1);
        assert_eq!(row.state, CiphertextWriteState::NeverAttempted);
        let mut recovered = Vec::new();
        reopened
            .open_ciphertext_write(&target, &root_id, row.revision)
            .unwrap()
            .read_to_end(&mut recovered)
            .unwrap();
        assert_eq!(recovered, body);
    }

    #[test]
    fn subtree_retarget_retry_uses_new_blob_identity_after_crash_orphan() {
        let (_temp, cache) = cache();
        let target = scope(ScopeProtection::CiphertextOnly);
        let root = cache
            .begin_ciphertext_operation_with_state_and_parent(
                &target,
                None,
                "old-root",
                Some(""),
                0,
                CiphertextWriteOperation::CreateDirectory,
                CiphertextWriteState::NeverAttempted,
            )
            .unwrap();
        let root_id = root.id().to_owned();
        let root_row = cache
            .publish_ciphertext_write(&target, &root, &mut Cursor::new([]), 0)
            .unwrap();
        let members = [CiphertextSubtreeRetarget {
            id: root_id.clone(),
            expected_revision: root_row.revision,
            expected_target: "old-root".into(),
            new_target: "new-root".into(),
            new_parent_path: "".into(),
            new_parent_operation: None,
            plaintext_len: 0,
            operation: CiphertextWriteOperation::CreateDirectory,
        }];
        let first = cache
            .begin_ciphertext_never_attempted_subtree_retarget(
                &target,
                &root_id,
                root_row.revision,
                &members,
            )
            .unwrap();
        let orphan_version = first[0].content_version();
        let orphan_path = cache
            .inner
            .content_dir
            .join(format!("{}.blob", content_key(&target, &orphan_version)));
        std::fs::write(&orphan_path, b"pre-commit orphan").unwrap();

        let retry = cache
            .begin_ciphertext_never_attempted_subtree_retarget(
                &target,
                &root_id,
                root_row.revision,
                &members,
            )
            .unwrap();
        assert_ne!(first[0].content_version(), retry[0].content_version());
        let mut bodies = [Cursor::new(Vec::<u8>::new())];
        let mut contents = retry
            .iter()
            .zip(bodies.iter_mut())
            .map(|(build, source)| CiphertextSubtreeRetargetContent {
                build,
                source,
                expected_len: 0,
            })
            .collect::<Vec<_>>();
        cache
            .publish_ciphertext_subtree_retarget(&target, &retry, &mut contents, &root_id)
            .unwrap();
        assert_eq!(std::fs::read(&orphan_path).unwrap(), b"pre-commit orphan");
        assert_eq!(
            cache
                .ciphertext_write_info(&target, &root_id)
                .unwrap()
                .revision,
            root_row.revision + 1
        );
    }

    #[test]
    fn subtree_retarget_and_new_child_publication_are_mutually_exclusive() {
        let (_temp, cache) = cache();
        let cache = Arc::new(cache);
        let target = scope(ScopeProtection::CiphertextOnly);
        let root = cache
            .begin_ciphertext_operation_with_state_and_parent(
                &target,
                None,
                "old-root",
                Some(""),
                0,
                CiphertextWriteOperation::CreateDirectory,
                CiphertextWriteState::NeverAttempted,
            )
            .unwrap();
        let root_id = root.id().to_owned();
        let root_row = cache
            .publish_ciphertext_write(&target, &root, &mut Cursor::new([]), 0)
            .unwrap();
        let existing = cache
            .begin_ciphertext_operation_with_state_parent_ref(
                &target,
                None,
                "old-root/existing",
                Some("old-root"),
                Some((&root_id, root_row.revision)),
                1,
                CiphertextWriteOperation::CreateFile,
                CiphertextWriteState::NeverAttempted,
            )
            .unwrap();
        let existing_id = existing.id().to_owned();
        let existing_row = cache
            .publish_ciphertext_write(&target, &existing, &mut Cursor::new(b"x"), 1)
            .unwrap();
        let late_child = cache
            .begin_ciphertext_operation_with_state_parent_ref(
                &target,
                None,
                "old-root/late-child",
                Some("old-root"),
                Some((&root_id, root_row.revision)),
                1,
                CiphertextWriteOperation::CreateFile,
                CiphertextWriteState::NeverAttempted,
            )
            .unwrap();
        let late_child_id = late_child.id().to_owned();
        let members = vec![
            CiphertextSubtreeRetarget {
                id: root_id.clone(),
                expected_revision: root_row.revision,
                expected_target: "old-root".into(),
                new_target: "new-root".into(),
                new_parent_path: "".into(),
                new_parent_operation: None,
                plaintext_len: 0,
                operation: CiphertextWriteOperation::CreateDirectory,
            },
            CiphertextSubtreeRetarget {
                id: existing_id.clone(),
                expected_revision: existing_row.revision,
                expected_target: "old-root/existing".into(),
                new_target: "new-root/existing".into(),
                new_parent_path: "new-root".into(),
                new_parent_operation: Some((root_id.clone(), root_row.revision + 1)),
                plaintext_len: 1,
                operation: CiphertextWriteOperation::CreateFile,
            },
        ];
        let builds = cache
            .begin_ciphertext_never_attempted_subtree_retarget(
                &target,
                &root_id,
                root_row.revision,
                &members,
            )
            .unwrap();
        let barrier = Arc::new(Barrier::new(3));

        let retarget_cache = Arc::clone(&cache);
        let retarget_scope = target.clone();
        let retarget_barrier = Arc::clone(&barrier);
        let retarget_builds = builds.clone();
        let retarget_root_id = root_id.clone();
        let retarget = std::thread::spawn(move || {
            let mut bodies = [Cursor::new(Vec::<u8>::new()), Cursor::new(b"x".to_vec())];
            let mut contents = retarget_builds
                .iter()
                .zip(bodies.iter_mut())
                .map(|(build, source)| CiphertextSubtreeRetargetContent {
                    build,
                    source,
                    expected_len: build.plaintext_len,
                })
                .collect::<Vec<_>>();
            retarget_barrier.wait();
            retarget_cache.publish_ciphertext_subtree_retarget(
                &retarget_scope,
                &retarget_builds,
                &mut contents,
                &retarget_root_id,
            )
        });

        let child_cache = Arc::clone(&cache);
        let child_scope = target.clone();
        let child_barrier = Arc::clone(&barrier);
        let child = std::thread::spawn(move || {
            child_barrier.wait();
            child_cache.publish_ciphertext_write(
                &child_scope,
                &late_child,
                &mut Cursor::new(b"y"),
                1,
            )
        });
        barrier.wait();
        let retarget_result = retarget.join().unwrap();
        let child_result = child.join().unwrap();
        assert_ne!(retarget_result.is_ok(), child_result.is_ok());
        if retarget_result.is_ok() {
            assert_eq!(
                cache
                    .ciphertext_write_info(&target, &root_id)
                    .unwrap()
                    .revision,
                root_row.revision + 1
            );
            assert!(matches!(child_result, Err(CacheError::Conflict)));
            assert!(matches!(
                cache.ciphertext_write_info(&target, &late_child_id),
                Err(CacheError::NotFound)
            ));
        } else {
            assert!(matches!(retarget_result, Err(CacheError::Conflict)));
            assert_eq!(
                cache
                    .ciphertext_write_info(&target, &root_id)
                    .unwrap()
                    .revision,
                root_row.revision
            );
            assert!(child_result.is_ok());
            assert_eq!(
                cache
                    .ciphertext_write_info(&target, &existing_id)
                    .unwrap()
                    .revision,
                existing_row.revision
            );
        }
    }

    #[test]
    fn directory_child_registration_and_attempt_claim_fence_retarget_publish() {
        let (_temp, cache_a) = cache();
        let target = scope(ScopeProtection::CiphertextOnly);
        let old_target = "encrypted-parent/old-dir";
        let initial = cache_a
            .begin_ciphertext_operation_with_state_parent_ref(
                &target,
                None,
                old_target,
                Some("encrypted-parent"),
                None,
                0,
                CiphertextWriteOperation::CreateDirectory,
                CiphertextWriteState::NeverAttempted,
            )
            .unwrap();
        let first = cache_a
            .publish_ciphertext_write(&target, &initial, &mut Cursor::new([]), 0)
            .unwrap();
        let stale_retarget = cache_a
            .begin_ciphertext_never_attempted_operation_retarget(
                &target,
                CiphertextWriteOperation::CreateDirectory,
                &first.id,
                first.revision,
                old_target,
                "encrypted-parent/new-dir",
                Some("encrypted-parent"),
                None,
                0,
            )
            .unwrap();
        let child = cache_a
            .begin_ciphertext_operation_with_state_parent_ref(
                &target,
                None,
                "encrypted-parent/old-dir/child",
                Some("encrypted-parent/old-dir"),
                Some((&first.id, first.revision)),
                0,
                CiphertextWriteOperation::CreateDirectory,
                CiphertextWriteState::NeverAttempted,
            )
            .unwrap();
        cache_a
            .publish_ciphertext_write(&target, &child, &mut Cursor::new([]), 0)
            .unwrap();
        assert_eq!(
            cache_a.publish_ciphertext_write(&target, &stale_retarget, &mut Cursor::new([]), 0),
            Err(CacheError::Conflict)
        );

        // With no child row, the durable attempt claim wins the same CAS.
        let (_temp2, cache2) = cache();
        let initial = cache2
            .begin_ciphertext_operation_with_state_parent_ref(
                &target,
                None,
                old_target,
                Some("encrypted-parent"),
                None,
                0,
                CiphertextWriteOperation::CreateDirectory,
                CiphertextWriteState::NeverAttempted,
            )
            .unwrap();
        let first = cache2
            .publish_ciphertext_write(&target, &initial, &mut Cursor::new([]), 0)
            .unwrap();
        let stale_retarget = cache2
            .begin_ciphertext_never_attempted_operation_retarget(
                &target,
                CiphertextWriteOperation::CreateDirectory,
                &first.id,
                first.revision,
                old_target,
                "encrypted-parent/new-dir",
                Some("encrypted-parent"),
                None,
                0,
            )
            .unwrap();
        cache2
            .claim_ciphertext_directory_create_attempt(&target, &first.id, first.revision)
            .unwrap();
        assert_eq!(
            cache2.publish_ciphertext_write(&target, &stale_retarget, &mut Cursor::new([]), 0),
            Err(CacheError::Conflict)
        );
    }

    #[test]
    fn legacy_pending_file_create_cannot_be_retargeted_as_never_attempted() {
        let (_temp, cache) = cache();
        let target = scope(ScopeProtection::CiphertextOnly);
        let old_target = "enc-parent/enc-old";
        let initial = cache
            .begin_ciphertext_operation_with_state_parent_ref(
                &target,
                None,
                old_target,
                Some("enc-parent"),
                None,
                3,
                CiphertextWriteOperation::CreateFile,
                CiphertextWriteState::Pending,
            )
            .unwrap();
        let pending = cache
            .publish_ciphertext_write(&target, &initial, &mut Cursor::new(b"old"), 3)
            .unwrap();
        assert_eq!(
            cache.begin_ciphertext_never_attempted_create_retarget(
                &target,
                &pending.id,
                pending.revision,
                old_target,
                "enc-parent/enc-new",
                Some("enc-parent"),
                None,
                3,
            ),
            Err(CacheError::Conflict)
        );
        assert_eq!(
            cache
                .ciphertext_write_for_target(&target, old_target)
                .unwrap(),
            Some(pending)
        );
    }

    #[test]
    fn ciphertext_directory_create_operations_keep_only_parent_hash_indexed() {
        let (_temp, cache) = cache();
        let target = scope(ScopeProtection::CiphertextOnly);
        let build = cache
            .begin_ciphertext_operation_with_state_and_parent(
                &target,
                None,
                "encrypted-parent/encrypted-child",
                Some("encrypted-parent"),
                0,
                CiphertextWriteOperation::CreateDirectory,
                CiphertextWriteState::Pending,
            )
            .unwrap();
        let info = cache
            .publish_ciphertext_write(&target, &build, &mut Cursor::new([]), 0)
            .unwrap();
        assert_eq!(info.operation, CiphertextWriteOperation::CreateDirectory);
        let (found, truncated) = cache
            .ciphertext_directory_creates_for_parent(&target, "encrypted-parent", None, 10)
            .unwrap();
        assert!(!truncated);
        assert_eq!(found, vec![info]);
        assert!(
            cache
                .ciphertext_directory_creates_for_parent(&target, "other-parent", None, 10)
                .unwrap()
                .0
                .is_empty()
        );
    }

    #[test]
    fn never_attempted_directory_cancel_requires_exact_unreferenced_revision() {
        let (_temp, cache) = cache();
        let target = scope(ScopeProtection::CiphertextOnly);
        let parent_target = "encrypted-parent";
        let path = "encrypted-parent/encrypted-child";
        let build = cache
            .begin_ciphertext_operation_with_state_and_parent(
                &target,
                None,
                path,
                Some(parent_target),
                0,
                CiphertextWriteOperation::CreateDirectory,
                CiphertextWriteState::NeverAttempted,
            )
            .unwrap();
        let row = cache
            .publish_ciphertext_write(&target, &build, &mut Cursor::new([]), 0)
            .unwrap();
        assert_eq!(row.state, CiphertextWriteState::NeverAttempted);

        assert!(matches!(
            cache.cancel_never_attempted_ciphertext_directory_create(
                &target,
                &row.id,
                row.revision + 1,
            ),
            Err(CacheError::Conflict)
        ));

        let child_build = cache
            .begin_ciphertext_operation_with_state_parent_ref(
                &target,
                None,
                "encrypted-parent/encrypted-child/encrypted-grandchild",
                Some(path),
                Some((&row.id, row.revision)),
                0,
                CiphertextWriteOperation::CreateDirectory,
                CiphertextWriteState::NeverAttempted,
            )
            .unwrap();
        let child = cache
            .publish_ciphertext_write(&target, &child_build, &mut Cursor::new([]), 0)
            .unwrap();
        assert!(matches!(
            cache.cancel_never_attempted_ciphertext_directory_create(
                &target,
                &row.id,
                row.revision,
            ),
            Err(CacheError::Conflict)
        ));
        assert_eq!(
            cache.ciphertext_write_info(&target, &row.id).unwrap().state,
            CiphertextWriteState::NeverAttempted
        );
        assert_eq!(
            cache
                .ciphertext_write_info(&target, &child.id)
                .unwrap()
                .state,
            CiphertextWriteState::NeverAttempted
        );
    }

    #[test]
    fn never_attempted_file_create_cancel_requires_exact_body_target_and_revision() {
        let (_temp, cache) = cache();
        let target = scope(ScopeProtection::CiphertextOnly);
        let encoded_target = "encrypted-parent/encrypted-file";
        let body = b"recovery bytes remain until explicit cancellation";
        let build = cache
            .begin_ciphertext_operation_with_state_and_parent(
                &target,
                None,
                encoded_target,
                Some("encrypted-parent"),
                body.len() as u64,
                CiphertextWriteOperation::CreateFile,
                CiphertextWriteState::NeverAttempted,
            )
            .unwrap();
        let row = cache
            .publish_ciphertext_write(&target, &build, &mut Cursor::new(body), body.len() as u64)
            .unwrap();
        assert_eq!(row.state, CiphertextWriteState::NeverAttempted);
        assert!(matches!(
            cache.cancel_never_attempted_ciphertext_file_create(
                &target,
                &row.id,
                row.revision + 1,
                encoded_target,
                body.len() as u64,
            ),
            Err(CacheError::Conflict)
        ));
        assert!(matches!(
            cache.cancel_never_attempted_ciphertext_file_create(
                &target,
                &row.id,
                row.revision,
                "encrypted-parent/other-file",
                body.len() as u64,
            ),
            Err(CacheError::Conflict)
        ));
        assert!(matches!(
            cache.cancel_never_attempted_ciphertext_file_create(
                &target,
                &row.id,
                row.revision,
                encoded_target,
                body.len() as u64 + 1,
            ),
            Err(CacheError::Conflict)
        ));
        cache
            .cancel_never_attempted_ciphertext_file_create(
                &target,
                &row.id,
                row.revision,
                encoded_target,
                body.len() as u64,
            )
            .unwrap();
        assert_eq!(
            cache.ciphertext_write_info(&target, &row.id).unwrap().state,
            CiphertextWriteState::CancelledReceipt
        );
        // The receipt is idempotent and survives until the caller confirms
        // that its exact recovery copy has been retired.
        cache
            .cancel_never_attempted_ciphertext_file_create(
                &target,
                &row.id,
                row.revision,
                encoded_target,
                body.len() as u64,
            )
            .unwrap();
        assert_eq!(
            cache.ciphertext_write_info(&target, &row.id).unwrap().state,
            CiphertextWriteState::CancelledReceipt
        );
        assert!(matches!(
            cache.retire_ciphertext_write(&target, &row.id, row.revision),
            Err(CacheError::Conflict)
        ));
        assert!(matches!(
            cache.set_ciphertext_write_state(
                &target,
                &row.id,
                row.revision,
                CiphertextWriteState::Pending,
            ),
            Err(CacheError::Conflict)
        ));
        assert!(matches!(
            cache.begin_ciphertext_cancel_ack_compaction(
                &target,
                &row.id,
                row.revision,
                "encrypted-parent/other-file",
            ),
            Err(CacheError::Conflict)
        ));
        assert!(matches!(
            cache.begin_ciphertext_operation_with_state_and_parent(
                &target,
                Some(&row.id),
                encoded_target,
                Some("encrypted-parent"),
                body.len() as u64,
                CiphertextWriteOperation::CreateFile,
                CiphertextWriteState::NeverAttempted,
            ),
            Err(CacheError::Conflict)
        ));
        assert_eq!(
            cache.ciphertext_write_info(&target, &row.id).unwrap().state,
            CiphertextWriteState::CancelledReceipt
        );
        let ack = cache
            .begin_ciphertext_cancel_ack_compaction(&target, &row.id, row.revision, encoded_target)
            .unwrap();
        let compact = b"compact acknowledgement envelope";
        let ack_info = cache
            .publish_ciphertext_write(
                &target,
                &ack,
                &mut Cursor::new(compact),
                compact.len() as u64,
            )
            .unwrap();
        assert_eq!(ack_info.state, CiphertextWriteState::AcknowledgedReceipt);
        assert_eq!(ack_info.revision, row.revision + 1);
        assert!(
            matches!(
                cache.open_ciphertext_write(&target, &row.id, row.revision),
                Err(CacheError::NotFound)
            ),
            "the normal compaction path retires the old body immediately"
        );
        assert!(matches!(
            cache.finalize_cancelled_ciphertext_file_create_ack(
                &target,
                &row.id,
                row.revision,
                ack_info.revision,
                "encrypted-parent/other-file",
            ),
            Err(CacheError::Conflict)
        ));
        cache
            .finalize_cancelled_ciphertext_file_create_ack(
                &target,
                &row.id,
                row.revision,
                ack_info.revision,
                encoded_target,
            )
            .unwrap();
        assert!(matches!(
            cache.ciphertext_write_info(&target, &row.id),
            Err(CacheError::NotFound)
        ));
        assert!(matches!(
            cache.open_ciphertext_write(&target, &row.id, row.revision),
            Err(CacheError::NotFound)
        ));
    }

    #[test]
    fn cancellation_receipts_are_bounded_per_scope_and_count_compacted_receipts() {
        let (_temp, cache) = cache();
        let target = scope(ScopeProtection::CiphertextOnly);
        let total = MAX_CANCEL_ACK_RECEIPTS_PER_SCOPE + 1;
        for index in 0..total {
            let encoded_target = format!("encrypted-parent/file-{index}");
            let body = [index as u8];
            let build = cache
                .begin_ciphertext_operation_with_state_and_parent(
                    &target,
                    None,
                    &encoded_target,
                    Some("encrypted-parent"),
                    body.len() as u64,
                    CiphertextWriteOperation::CreateFile,
                    CiphertextWriteState::NeverAttempted,
                )
                .unwrap();
            let row = cache
                .publish_ciphertext_write(
                    &target,
                    &build,
                    &mut Cursor::new(body),
                    body.len() as u64,
                )
                .unwrap();
            if index == MAX_CANCEL_ACK_RECEIPTS_PER_SCOPE {
                assert!(matches!(
                    cache.cancel_never_attempted_ciphertext_file_create(
                        &target,
                        &row.id,
                        row.revision,
                        &encoded_target,
                        body.len() as u64,
                    ),
                    Err(CacheError::LimitExceeded)
                ));
                assert_eq!(
                    cache.ciphertext_write_info(&target, &row.id).unwrap().state,
                    CiphertextWriteState::NeverAttempted,
                    "quota refusal leaves the source row and body intact"
                );
                continue;
            }
            cache
                .cancel_never_attempted_ciphertext_file_create(
                    &target,
                    &row.id,
                    row.revision,
                    &encoded_target,
                    body.len() as u64,
                )
                .unwrap();
            if index == 0 {
                let ack = cache
                    .begin_ciphertext_cancel_ack_compaction(
                        &target,
                        &row.id,
                        row.revision,
                        &encoded_target,
                    )
                    .unwrap();
                let compact = b"bounded compact receipt";
                let ack_info = cache
                    .publish_ciphertext_write(
                        &target,
                        &ack,
                        &mut Cursor::new(compact),
                        compact.len() as u64,
                    )
                    .unwrap();
                cache
                    .remove_unreferenced_ciphertext_write_content(&target, &row.id, row.revision)
                    .unwrap();
                assert_eq!(ack_info.state, CiphertextWriteState::AcknowledgedReceipt);
            }
        }
    }

    #[test]
    fn file_create_attempt_claim_and_local_cancel_are_mutually_exclusive() {
        let (temp, cache) = cache();
        let cache = Arc::new(cache);
        let target = scope(ScopeProtection::CiphertextOnly);
        let encoded_target = "encrypted-parent/encrypted-file";
        let body = b"local encrypted create";
        let build = cache
            .begin_ciphertext_operation_with_state_and_parent(
                &target,
                None,
                encoded_target,
                Some("encrypted-parent"),
                body.len() as u64,
                CiphertextWriteOperation::CreateFile,
                CiphertextWriteState::NeverAttempted,
            )
            .unwrap();
        let row = cache
            .publish_ciphertext_write(&target, &build, &mut Cursor::new(body), body.len() as u64)
            .unwrap();
        let barrier = Arc::new(Barrier::new(3));

        let claim_cache = Arc::clone(&cache);
        let claim_scope = target.clone();
        let claim_barrier = Arc::clone(&barrier);
        let claim_id = row.id.clone();
        let revision = row.revision;
        let claimant = std::thread::spawn(move || {
            claim_barrier.wait();
            claim_cache.claim_ciphertext_file_create_attempt(&claim_scope, &claim_id, revision)
        });

        let cancel_cache = Arc::clone(&cache);
        let cancel_scope = target.clone();
        let cancel_barrier = Arc::clone(&barrier);
        let cancel_id = row.id.clone();
        let canceler = std::thread::spawn(move || {
            cancel_barrier.wait();
            cancel_cache.cancel_never_attempted_ciphertext_file_create(
                &cancel_scope,
                &cancel_id,
                revision,
                encoded_target,
                body.len() as u64,
            )
        });

        barrier.wait();
        let claim = claimant.join().unwrap();
        let cancel = canceler.join().unwrap();
        assert_ne!(claim.is_ok(), cancel.is_ok());
        if claim.is_ok() {
            assert!(matches!(cancel, Err(CacheError::Conflict)));
            assert_eq!(
                cache.ciphertext_write_info(&target, &row.id).unwrap().state,
                CiphertextWriteState::Attempting
            );
        } else {
            assert!(matches!(cancel, Ok(())));
            assert_eq!(
                cache.ciphertext_write_info(&target, &row.id).unwrap().state,
                CiphertextWriteState::CancelledReceipt
            );

            // Simulate process restart between cancellation CAS and local
            // recovery-copy retirement. The receipt survives reopening.
            let reopened = Cache::open(temp.path(), 1024).unwrap();
            assert_eq!(
                reopened
                    .ciphertext_write_info(&target, &row.id)
                    .unwrap()
                    .state,
                CiphertextWriteState::CancelledReceipt
            );
            let ack = reopened
                .begin_ciphertext_cancel_ack_compaction(
                    &target,
                    &row.id,
                    row.revision,
                    encoded_target,
                )
                .unwrap();
            let compact = b"compact acknowledgement envelope";
            let ack_info = reopened
                .publish_ciphertext_write(
                    &target,
                    &ack,
                    &mut Cursor::new(compact),
                    compact.len() as u64,
                )
                .unwrap();
            reopened
                .remove_unreferenced_ciphertext_write_content(&target, &row.id, row.revision)
                .unwrap();
            reopened
                .finalize_cancelled_ciphertext_file_create_ack(
                    &target,
                    &row.id,
                    row.revision,
                    ack_info.revision,
                    encoded_target,
                )
                .unwrap();
            assert!(matches!(
                reopened.ciphertext_write_info(&target, &row.id),
                Err(CacheError::NotFound)
            ));
        }
    }

    #[test]
    fn interrupted_file_create_retry_generation_survives_reopen_and_fences_stale_completion() {
        let (temp, cache) = cache();
        let target = scope(ScopeProtection::CiphertextOnly);
        let encoded_target = "encrypted-parent/encrypted-file";
        let body = b"retain until verified readback";
        let build = cache
            .begin_ciphertext_operation_with_state_and_parent(
                &target,
                None,
                encoded_target,
                Some("encrypted-parent"),
                body.len() as u64,
                CiphertextWriteOperation::CreateFile,
                CiphertextWriteState::NeverAttempted,
            )
            .unwrap();
        let row = cache
            .publish_ciphertext_write(&target, &build, &mut Cursor::new(body), body.len() as u64)
            .unwrap();
        cache
            .claim_ciphertext_file_create_attempt(&target, &row.id, row.revision)
            .unwrap();
        assert_eq!(
            cache.ciphertext_write_info(&target, &row.id).unwrap().state,
            CiphertextWriteState::Attempting
        );

        let generation_one = cache
            .claim_interrupted_ciphertext_file_create_retry(
                &target,
                &row.id,
                row.revision,
                CiphertextWriteState::Attempting,
                0,
            )
            .unwrap();
        assert_eq!(generation_one, 1);
        assert!(matches!(
            cache.claim_interrupted_ciphertext_file_create_retry(
                &target,
                &row.id,
                row.revision,
                CiphertextWriteState::Attempting,
                0,
            ),
            Err(CacheError::Conflict)
        ));
        let reopened = Cache::open(temp.path(), 1024).unwrap();
        assert_eq!(
            reopened
                .ciphertext_write_info(&target, &row.id)
                .unwrap()
                .retry_generation,
            generation_one
        );
        let generation_two = reopened
            .claim_interrupted_ciphertext_file_create_retry(
                &target,
                &row.id,
                row.revision,
                CiphertextWriteState::RecoveryAttempting,
                generation_one,
            )
            .unwrap();
        assert_eq!(generation_two, 2);
        assert!(matches!(
            reopened.claim_interrupted_ciphertext_file_create_retry(
                &target,
                &row.id,
                row.revision,
                CiphertextWriteState::RecoveryAttempting,
                generation_one,
            ),
            Err(CacheError::Conflict)
        ));
        let generation_three = reopened
            .claim_interrupted_ciphertext_file_create_retry(
                &target,
                &row.id,
                row.revision,
                CiphertextWriteState::RecoveryRetrying,
                generation_two,
            )
            .unwrap();
        assert_eq!(generation_three, 3);
        let listed = reopened.ciphertext_writes(&target, None, 10).unwrap().0;
        assert_eq!(
            listed
                .iter()
                .find(|candidate| candidate.id == row.id)
                .unwrap()
                .retry_generation,
            generation_three,
            "metadata-only status exposes the durable opaque retry fence"
        );
        assert!(matches!(
            reopened.set_interrupted_ciphertext_file_create_retry_state(
                &target,
                &row.id,
                row.revision,
                generation_two,
                CiphertextWriteState::RecoveryRetrying,
                CiphertextWriteState::Conflict,
            ),
            Err(CacheError::Conflict)
        ));
        assert!(matches!(
            reopened.retire_interrupted_ciphertext_file_create_retry(
                &target,
                &row.id,
                row.revision,
                generation_two,
                CiphertextWriteState::RecoveryRetrying,
            ),
            Err(CacheError::Conflict)
        ));
        assert_eq!(
            cache
                .retryable_ciphertext_writes(&target, 100)
                .unwrap()
                .0
                .into_iter()
                .find(|candidate| candidate.id == row.id),
            None,
            "interrupted retries never enter the automatic retry page"
        );
        let mut content = reopened
            .open_ciphertext_write(&target, &row.id, row.revision)
            .unwrap();
        let mut retained = Vec::new();
        content.read_to_end(&mut retained).unwrap();
        assert_eq!(retained, body);
    }

    #[test]
    fn historical_pending_file_create_is_not_locally_cancellable() {
        let (_temp, cache) = cache();
        let target = scope(ScopeProtection::CiphertextOnly);
        let encoded_target = "encrypted-parent/encrypted-file";
        let body = b"a request might already have reached the server";
        let build = cache
            .begin_ciphertext_operation_with_state_and_parent(
                &target,
                None,
                encoded_target,
                Some("encrypted-parent"),
                body.len() as u64,
                CiphertextWriteOperation::CreateFile,
                CiphertextWriteState::Pending,
            )
            .unwrap();
        let row = cache
            .publish_ciphertext_write(&target, &build, &mut Cursor::new(body), body.len() as u64)
            .unwrap();
        assert!(matches!(
            cache.cancel_never_attempted_ciphertext_file_create(
                &target,
                &row.id,
                row.revision,
                encoded_target,
                body.len() as u64,
            ),
            Err(CacheError::Conflict)
        ));
        assert_eq!(
            cache.ciphertext_write_info(&target, &row.id).unwrap().state,
            CiphertextWriteState::Pending
        );
    }

    #[test]
    fn directory_attempt_claim_and_local_cancel_are_mutually_exclusive() {
        let (_temp, cache) = cache();
        let cache = Arc::new(cache);
        let target = scope(ScopeProtection::CiphertextOnly);
        let build = cache
            .begin_ciphertext_operation_with_state_and_parent(
                &target,
                None,
                "encrypted-parent/encrypted-child",
                Some("encrypted-parent"),
                0,
                CiphertextWriteOperation::CreateDirectory,
                CiphertextWriteState::NeverAttempted,
            )
            .unwrap();
        let row = cache
            .publish_ciphertext_write(&target, &build, &mut Cursor::new([]), 0)
            .unwrap();
        let barrier = Arc::new(Barrier::new(3));

        let claim_cache = Arc::clone(&cache);
        let claim_scope = target.clone();
        let claim_barrier = Arc::clone(&barrier);
        let claim_id = row.id.clone();
        let revision = row.revision;
        let claimant = std::thread::spawn(move || {
            claim_barrier.wait();
            claim_cache.claim_ciphertext_directory_create_attempt(&claim_scope, &claim_id, revision)
        });

        let cancel_cache = Arc::clone(&cache);
        let cancel_scope = target.clone();
        let cancel_barrier = Arc::clone(&barrier);
        let cancel_id = row.id.clone();
        let canceler = std::thread::spawn(move || {
            cancel_barrier.wait();
            cancel_cache.cancel_never_attempted_ciphertext_directory_create(
                &cancel_scope,
                &cancel_id,
                revision,
            )
        });

        barrier.wait();
        let claim = claimant.join().unwrap();
        let cancel = canceler.join().unwrap();
        assert_ne!(claim.is_ok(), cancel.is_ok());
        if claim.is_ok() {
            assert_eq!(
                cache.ciphertext_write_info(&target, &row.id).unwrap().state,
                CiphertextWriteState::Attempting
            );
        } else {
            assert!(matches!(cancel, Ok(())));
            assert!(matches!(
                cache.ciphertext_write_info(&target, &row.id),
                Err(CacheError::NotFound)
            ));
        }
    }

    #[test]
    fn legacy_pending_directory_is_never_cancelable() {
        let (_temp, cache) = cache();
        let target = scope(ScopeProtection::CiphertextOnly);
        let build = cache
            .begin_ciphertext_operation_with_state_and_parent(
                &target,
                None,
                "encrypted-parent/legacy-directory",
                Some("encrypted-parent"),
                0,
                CiphertextWriteOperation::CreateDirectory,
                CiphertextWriteState::Pending,
            )
            .unwrap();
        let row = cache
            .publish_ciphertext_write(&target, &build, &mut Cursor::new([]), 0)
            .unwrap();
        assert!(matches!(
            cache.cancel_never_attempted_ciphertext_directory_create(
                &target,
                &row.id,
                row.revision,
            ),
            Err(CacheError::Conflict)
        ));
        cache
            .claim_ciphertext_directory_create_attempt(&target, &row.id, row.revision)
            .unwrap();
        assert!(matches!(
            cache.cancel_never_attempted_ciphertext_directory_create(
                &target,
                &row.id,
                row.revision,
            ),
            Err(CacheError::Conflict)
        ));
    }

    #[test]
    fn interrupted_directory_attempt_remains_unresolved_after_reopen() {
        let (temp, cache) = cache();
        let target = scope(ScopeProtection::CiphertextOnly);
        let build = cache
            .begin_ciphertext_operation_with_state_and_parent(
                &target,
                None,
                "encrypted-parent/interrupted-directory",
                Some("encrypted-parent"),
                0,
                CiphertextWriteOperation::CreateDirectory,
                CiphertextWriteState::NeverAttempted,
            )
            .unwrap();
        let row = cache
            .publish_ciphertext_write(&target, &build, &mut Cursor::new([]), 0)
            .unwrap();
        cache
            .claim_ciphertext_directory_create_attempt(&target, &row.id, row.revision)
            .unwrap();
        drop(cache);

        // Simulate process interruption after the durable pre-dispatch claim.
        let reopened = Cache::open(temp.path(), 16 * 1024 * 1024).unwrap();
        assert_eq!(
            reopened
                .ciphertext_write_info(&target, &row.id)
                .unwrap()
                .state,
            CiphertextWriteState::Attempting
        );
        assert!(
            reopened
                .retryable_ciphertext_writes(&target, 10)
                .unwrap()
                .0
                .is_empty()
        );
        assert!(matches!(
            reopened.set_ciphertext_write_state(
                &target,
                &row.id,
                row.revision,
                CiphertextWriteState::NeverAttempted,
            ),
            Err(CacheError::Conflict)
        ));
        assert!(matches!(
            reopened.set_ciphertext_write_state(
                &target,
                &row.id,
                row.revision,
                CiphertextWriteState::Pending,
            ),
            Err(CacheError::Conflict)
        ));
        assert!(matches!(
            reopened.cancel_never_attempted_ciphertext_directory_create(
                &target,
                &row.id,
                row.revision,
            ),
            Err(CacheError::Conflict)
        ));
    }

    #[test]
    fn pending_parent_children_wait_for_receipt_and_keep_receipt_until_rebound() {
        let (_temp, cache) = cache();
        let target = scope(ScopeProtection::CiphertextOnly);
        let parent_target = "enc-root/enc-parent";
        let parent_build = cache
            .begin_ciphertext_operation_with_state_and_parent(
                &target,
                None,
                parent_target,
                Some("enc-root"),
                0,
                CiphertextWriteOperation::CreateDirectory,
                CiphertextWriteState::Pending,
            )
            .unwrap();
        let parent = cache
            .publish_ciphertext_write(&target, &parent_build, &mut Cursor::new([]), 0)
            .unwrap();

        let nested_build = cache
            .begin_ciphertext_operation_with_state_parent_ref(
                &target,
                None,
                "enc-root/enc-parent/enc-nested",
                Some("enc-root/enc-parent"),
                Some((&parent.id, parent.revision)),
                0,
                CiphertextWriteOperation::CreateDirectory,
                CiphertextWriteState::Pending,
            )
            .unwrap();
        let nested = cache
            .publish_ciphertext_write(&target, &nested_build, &mut Cursor::new([]), 0)
            .unwrap();
        assert!(
            cache
                .retryable_ciphertext_writes(&target, 10)
                .unwrap()
                .0
                .iter()
                .all(|operation| operation.id != nested.id),
            "a nested directory is blocked until its parent has a receipt"
        );
        let (children, truncated) = cache
            .ciphertext_operation_children(&target, &parent.id, parent.revision, None, 10)
            .unwrap();
        assert!(!truncated);
        assert_eq!(children, vec![nested.clone()]);

        let receipt_build = cache
            .begin_ciphertext_operation_with_state_and_parent(
                &target,
                Some(&parent.id),
                parent_target,
                Some("enc-root"),
                0,
                CiphertextWriteOperation::CreateDirectory,
                CiphertextWriteState::CommittedReceipt,
            )
            .unwrap();
        let receipt = cache
            .publish_ciphertext_write(&target, &receipt_build, &mut Cursor::new(b"sealed"), 6)
            .unwrap();
        assert_eq!(
            cache
                .ciphertext_directory_receipt(&target, &parent.id, parent.revision)
                .unwrap(),
            Some(receipt.clone())
        );
        let (retryable, truncated) = cache.retryable_ciphertext_writes(&target, 10).unwrap();
        assert!(!truncated);
        assert_eq!(retryable, vec![nested.clone()]);

        let nested_receipt_build = cache
            .begin_ciphertext_operation_with_state_parent_ref(
                &target,
                Some(&nested.id),
                "enc-root/enc-parent/enc-nested",
                Some("enc-root/enc-parent"),
                None,
                0,
                CiphertextWriteOperation::CreateDirectory,
                CiphertextWriteState::CommittedReceipt,
            )
            .unwrap();
        let nested_receipt = cache
            .publish_ciphertext_write(
                &target,
                &nested_receipt_build,
                &mut Cursor::new(b"nested"),
                6,
            )
            .unwrap();
        cache
            .retire_ciphertext_directory_receipt(
                &target,
                &parent.id,
                receipt.revision,
                parent.revision,
            )
            .unwrap();

        let child_build = cache
            .begin_ciphertext_operation_with_state_parent_ref(
                &target,
                None,
                "enc-root/enc-parent/enc-nested/enc-child",
                Some("enc-root/enc-parent/enc-nested"),
                Some((&nested.id, nested.revision)),
                1,
                CiphertextWriteOperation::CreateFile,
                CiphertextWriteState::Pending,
            )
            .unwrap();
        let child = cache
            .publish_ciphertext_write(&target, &child_build, &mut Cursor::new(b"x"), 1)
            .unwrap();
        assert_eq!(
            cache.retryable_ciphertext_writes(&target, 10).unwrap().0,
            vec![child.clone()]
        );
        assert!(matches!(
            cache.retire_ciphertext_directory_receipt(
                &target,
                &nested.id,
                nested_receipt.revision,
                nested.revision,
            ),
            Err(CacheError::Conflict)
        ));
        cache
            .retire_ciphertext_write(&target, &child.id, child.revision)
            .unwrap();
        cache
            .retire_ciphertext_directory_receipt(
                &target,
                &nested.id,
                nested_receipt.revision,
                nested.revision,
            )
            .unwrap();
        assert!(
            cache
                .ciphertext_directory_receipt(&target, &nested.id, nested.revision)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn dependent_child_publish_races_receipt_retirement_atomically() {
        let (_temp, cache) = cache();
        let cache = Arc::new(cache);
        let target = scope(ScopeProtection::CiphertextOnly);
        let parent_target = "enc-root/enc-parent";
        let parent_build = cache
            .begin_ciphertext_operation_with_state_and_parent(
                &target,
                None,
                parent_target,
                Some("enc-root"),
                0,
                CiphertextWriteOperation::CreateDirectory,
                CiphertextWriteState::Pending,
            )
            .unwrap();
        let parent = cache
            .publish_ciphertext_write(&target, &parent_build, &mut Cursor::new([]), 0)
            .unwrap();
        let receipt_build = cache
            .begin_ciphertext_operation_with_state_and_parent(
                &target,
                Some(&parent.id),
                parent_target,
                Some("enc-root"),
                0,
                CiphertextWriteOperation::CreateDirectory,
                CiphertextWriteState::CommittedReceipt,
            )
            .unwrap();
        let receipt = cache
            .publish_ciphertext_write(&target, &receipt_build, &mut Cursor::new(b"sealed"), 6)
            .unwrap();
        let child_build = cache
            .begin_ciphertext_operation_with_state_parent_ref(
                &target,
                None,
                "enc-root/enc-parent/enc-child",
                Some(parent_target),
                Some((&parent.id, parent.revision)),
                1,
                CiphertextWriteOperation::CreateFile,
                CiphertextWriteState::Pending,
            )
            .unwrap();

        let start = Arc::new(Barrier::new(3));
        let publish_cache = Arc::clone(&cache);
        let publish_scope = target.clone();
        let publish_start = Arc::clone(&start);
        let publish = std::thread::spawn(move || {
            publish_start.wait();
            publish_cache.publish_ciphertext_write(
                &publish_scope,
                &child_build,
                &mut Cursor::new(b"x"),
                1,
            )
        });
        let retire_cache = Arc::clone(&cache);
        let retire_scope = target.clone();
        let retire_start = Arc::clone(&start);
        let retire = std::thread::spawn(move || {
            retire_start.wait();
            retire_cache.retire_ciphertext_directory_receipt(
                &retire_scope,
                &parent.id,
                receipt.revision,
                parent.revision,
            )
        });
        start.wait();
        let published = publish.join().unwrap();
        let retired = retire.join().unwrap();

        match published {
            Ok(child) => {
                assert!(matches!(retired, Err(CacheError::Conflict)));
                assert_eq!(
                    cache
                        .ciphertext_directory_receipt(
                            &target,
                            &parent_build.id,
                            parent_build.revision
                        )
                        .unwrap()
                        .map(|row| row.state),
                    Some(CiphertextWriteState::CommittedReceipt)
                );
                assert_eq!(
                    cache
                        .ciphertext_operation_children(
                            &target,
                            &parent_build.id,
                            parent_build.revision,
                            None,
                            10,
                        )
                        .unwrap()
                        .0,
                    vec![child]
                );
            }
            Err(CacheError::Conflict) => {
                retired.unwrap();
                assert!(
                    cache
                        .ciphertext_directory_receipt(
                            &target,
                            &parent_build.id,
                            parent_build.revision,
                        )
                        .unwrap()
                        .is_none()
                );
            }
            Err(error) => panic!("unexpected child publication error: {error}"),
        }
    }

    #[test]
    fn dirty_dependent_child_can_advance_after_parent_becomes_conflicted() {
        let (_temp, cache) = cache();
        let target = scope(ScopeProtection::CiphertextOnly);
        let parent_build = cache
            .begin_ciphertext_operation_with_state_and_parent(
                &target,
                None,
                "enc-root/enc-parent",
                Some("enc-root"),
                0,
                CiphertextWriteOperation::CreateDirectory,
                CiphertextWriteState::Pending,
            )
            .unwrap();
        let parent = cache
            .publish_ciphertext_write(&target, &parent_build, &mut Cursor::new([]), 0)
            .unwrap();
        let child_target = "enc-root/enc-parent/enc-child";
        let child_build = cache
            .begin_ciphertext_operation_with_state_parent_ref(
                &target,
                None,
                child_target,
                Some("enc-root/enc-parent"),
                Some((&parent.id, parent.revision)),
                3,
                CiphertextWriteOperation::CreateFile,
                CiphertextWriteState::Pending,
            )
            .unwrap();
        let first = cache
            .publish_ciphertext_write(&target, &child_build, &mut Cursor::new(b"old"), 3)
            .unwrap();

        cache
            .set_ciphertext_write_state(
                &target,
                &parent.id,
                parent.revision,
                CiphertextWriteState::Conflict,
            )
            .unwrap();
        let next_build = cache
            .begin_ciphertext_operation_with_state_parent_ref(
                &target,
                Some(&first.id),
                child_target,
                Some("enc-root/enc-parent"),
                Some((&parent.id, parent.revision)),
                7,
                CiphertextWriteOperation::CreateFile,
                CiphertextWriteState::Pending,
            )
            .unwrap();
        let updated = cache
            .publish_ciphertext_write(&target, &next_build, &mut Cursor::new(b"new data"), 8)
            .unwrap();
        assert_eq!(updated.revision, first.revision + 1);
        let mut body = cache
            .open_ciphertext_write(&target, &updated.id, updated.revision)
            .unwrap();
        let mut bytes = Vec::new();
        body.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"new data");
        assert!(
            cache
                .retryable_ciphertext_writes(&target, 10)
                .unwrap()
                .0
                .is_empty(),
            "the newer local child data remains preserved but blocked"
        );
    }

    #[test]
    fn per_parent_quota_is_rechecked_when_builds_publish() {
        let temp = tempfile::tempdir().unwrap();
        set_private_dir(temp.path()).unwrap();
        let cache = Cache::open(temp.path(), 64 * 1024 * 1024).unwrap();
        let target = scope(ScopeProtection::CiphertextOnly);

        // Build rows before publishing any of them. This models competing
        // callers that all pass the begin-time quota check; publication must
        // serialize and enforce the same per-parent bound again.
        let builds = (0..=MAX_CIPHERTEXT_WRITES_PER_PARENT)
            .map(|index| {
                cache
                    .begin_ciphertext_operation_with_state_and_parent(
                        &target,
                        None,
                        &format!("enc-root/child-{index}"),
                        Some("enc-root"),
                        0,
                        CiphertextWriteOperation::CreateDirectory,
                        CiphertextWriteState::Pending,
                    )
                    .unwrap()
            })
            .collect::<Vec<_>>();

        for build in &builds[..MAX_CIPHERTEXT_WRITES_PER_PARENT] {
            cache
                .publish_ciphertext_write(&target, build, &mut Cursor::new([]), 0)
                .unwrap();
        }
        assert!(matches!(
            cache.publish_ciphertext_write(
                &target,
                &builds[MAX_CIPHERTEXT_WRITES_PER_PARENT],
                &mut Cursor::new([]),
                0,
            ),
            Err(CacheError::LimitExceeded)
        ));
        let (first_page, truncated) = cache.ciphertext_writes(&target, None, 100).unwrap();
        assert_eq!(first_page.len(), 100);
        assert!(truncated);
    }

    #[test]
    fn retryable_ciphertext_writes_skip_large_conflict_prefix_after_restart() {
        let temp = tempfile::tempdir().unwrap();
        set_private_dir(temp.path()).unwrap();
        let target = scope(ScopeProtection::CiphertextOnly);
        let cache = Cache::open(temp.path(), 16 * 1024 * 1024).unwrap();
        let mut conflict_ids = BTreeSet::new();
        for index in 0..129 {
            let build = cache
                .begin_ciphertext_write(&target, None, &format!("encrypted/target-{index}"), 1)
                .unwrap();
            let row = cache
                .publish_ciphertext_write(&target, &build, &mut Cursor::new(b"x"), 1)
                .unwrap();
            cache
                .set_ciphertext_write_state(
                    &target,
                    &row.id,
                    row.revision,
                    CiphertextWriteState::Conflict,
                )
                .unwrap();
            conflict_ids.insert(row.id);
        }
        let pending_build = cache
            .begin_ciphertext_write(&target, None, "encrypted/last-target", 1)
            .unwrap();
        let pending = cache
            .publish_ciphertext_write(&target, &pending_build, &mut Cursor::new(b"p"), 1)
            .unwrap();
        let pending_id = pending.id.clone();
        drop(cache);

        let reopened = Cache::open(temp.path(), 16 * 1024 * 1024).unwrap();
        let (retryable, truncated) = reopened.retryable_ciphertext_writes(&target, 32).unwrap();
        assert!(!truncated);
        assert_eq!(retryable, vec![pending]);
        assert!(retryable.iter().all(|row| !conflict_ids.contains(&row.id)));

        let (first_page, truncated) = reopened.ciphertext_writes(&target, None, 100).unwrap();
        assert!(truncated);
        let after = first_page.last().unwrap().id.clone();
        let (second_page, truncated) = reopened
            .ciphertext_writes(&target, Some(&after), 100)
            .unwrap();
        assert!(!truncated);
        let all = first_page
            .into_iter()
            .chain(second_page)
            .collect::<Vec<_>>();
        assert_eq!(all.len(), 130);
        assert_eq!(
            all.iter()
                .filter(|row| row.state == CiphertextWriteState::Conflict)
                .count(),
            129
        );
        assert!(all.iter().any(|row| row.id == pending_id));
    }

    #[test]
    fn rejects_unknown_database_schema_and_recovers_staging_files() {
        let (temp, cache) = cache();
        let content_dir = cache.inner.content_dir.clone();
        drop(cache);
        let stage = content_dir.join(".stage-left-by-interruption");
        fs::write(&stage, b"partial").unwrap();
        set_private_file(&File::open(&stage).unwrap()).unwrap();
        let reopened = Cache::open(temp.path(), 1024).unwrap();
        assert!(!stage.exists());
        let db_path = reopened.root().join(DB_FILE);
        drop(reopened);
        let connection = Connection::open(db_path).unwrap();
        connection.pragma_update(None, "user_version", 99).unwrap();
        drop(connection);
        assert!(matches!(
            Cache::open(temp.path(), 1024),
            Err(CacheError::Corrupt)
        ));
    }
}

#[cfg(all(test, not(unix), not(windows)))]
mod unsupported_platform_tests {
    use super::*;

    #[test]
    fn refuses_cache_until_private_acl_support_is_available() {
        let temp = tempfile::tempdir().unwrap();
        assert!(matches!(
            Cache::open(temp.path(), 1024),
            Err(CacheError::UnsafeDirectory)
        ));
    }
}
