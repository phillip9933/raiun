//! Persistent, conservative folder-pair reconciliation.
//!
//! Inventories and transfer history live in SQLite. Directory walks and cloud
//! listings are staged incrementally; a failed scan never advances a baseline.
//! The first implementation serializes mutations through one engine mutex.

use raiun_cache::{
    AvailabilityPolicy, Cache, CacheScope, CacheUsage, CachedEntry, ConditionalWriteRequest,
    ContentProtection, ContentVersion, PinInfo, PinManifestEntry, PinState, QueuedWrite, Retention,
    ScopeProtection, TargetState, WriteState,
};
use raiun_core::backend::{
    CloudBackend, CloudError, CloudSpace, ErrorKind, RemoteEntry, WriteCondition,
};
use raiun_core::{
    FolderExclusion, FolderPair, MediaFilter, SyncMode, VaultBinding, validate_remote_path,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex, MutexGuard, RwLock,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::{Builder as TempBuilder, NamedTempFile};

mod db_owner;
mod folder_pair_document;
pub mod folder_pairs;
use db_owner::DbOwner;

#[cfg(unix)]
mod folder_cloud_only;
pub mod media_import;
pub use media_import::{
    MAX_MEDIA_RECEIPTS_PER_ACCOUNT, MAX_MEDIA_RECOVERY_PAGE, MEDIA_STABLE_FILE_SECONDS,
    MediaImportReceipt, MediaImportRecoveryCursor, MediaImportRecoveryItem,
    MediaImportRecoveryPage, MediaImportRunReport, MediaImportRunStatus,
};

#[derive(Clone)]
pub struct Engine {
    inner: Arc<Inner>,
    backend: Arc<dyn CloudBackend>,
    vault_binding: Option<(String, VaultBinding)>,
    offline_cache: Option<Arc<OfflineCache>>,
    account_scope: Option<AccountScope>,
    offline_namespace: Arc<OfflineNamespace>,
}

/// A one-way cancellation handle that can cross a worker boundary without
/// transferring the database/VFS owner. Revocation stops subsequent sync steps;
/// the caller must still drain the worker before replacing account credentials.
#[derive(Clone)]
pub struct SyncRevocationHandle {
    paused: Arc<AtomicBool>,
}
impl SyncRevocationHandle {
    pub fn is_revoked(&self) -> bool {
        self.paused.load(Ordering::Acquire)
    }

    pub fn revoke(&self) {
        self.paused.store(true, Ordering::Release);
    }
}

/// Holds the engine dispatch fence while a caller durably persists an updated
/// profile policy. The caller publishes this in-memory policy only after the
/// settings write succeeds; dropping the guard rolls back by doing nothing.
pub struct PairPolicyPublication<'a> {
    inner: &'a Inner,
    pair_id: String,
    policy: Option<PairSyncPolicy>,
    _execution: MutexGuard<'a, ()>,
}

impl PairPolicyPublication<'_> {
    /// Make the prepared policy visible to subsequent sync dispatches. This is
    /// infallible after validation; a poisoned map mutex is recovered while
    /// still holding the execution gate.
    pub fn publish(self) {
        let mut policies = self
            .inner
            .pair_policies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        policies.insert(self.pair_id.clone(), self.policy.clone());
    }
}

/// Retire several connections under one dispatch fence after durable settings
/// publication. Dropping this guard leaves every existing connection unchanged.
pub struct PairRetirementPublication<'a> {
    inner: &'a Inner,
    pair_ids: Vec<String>,
    _execution: MutexGuard<'a, ()>,
}

impl PairRetirementPublication<'_> {
    pub fn publish(self) {
        let mut policies = self
            .inner
            .pair_policies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for id in self.pair_ids {
            policies.insert(id, None);
        }
    }
}

#[derive(Clone)]
struct AccountScope {
    account_id: String,
    origin: String,
}

/// An immutable authority boundary shared only by clones of one account-bound
/// Engine. Rebinding an Engine creates a fresh namespace handle, even when the
/// visible account and origin strings happen to be identical.
struct OfflineNamespace {
    binding: Option<OfflineNamespaceBinding>,
    binding_token: Arc<()>,
    probe_gate: Mutex<()>,
    next_probe: AtomicU64,
    transport_unavailable: AtomicBool,
    spaces: RwLock<Option<Arc<Vec<CloudSpace>>>>,
    published_live_spaces: RwLock<Option<Vec<CloudSpace>>>,
}

#[derive(Debug, PartialEq, Eq)]
struct OfflineNamespaceBinding {
    account_id: String,
    origin: String,
    backend_identity: usize,
}

impl OfflineNamespace {
    fn unbound() -> Arc<Self> {
        Arc::new(Self {
            binding: None,
            binding_token: Arc::new(()),
            probe_gate: Mutex::new(()),
            next_probe: AtomicU64::new(0),
            transport_unavailable: AtomicBool::new(false),
            spaces: RwLock::new(None),
            published_live_spaces: RwLock::new(None),
        })
    }

    fn for_account(scope: &AccountScope, backend: &Arc<dyn CloudBackend>) -> Arc<Self> {
        Arc::new(Self {
            binding: Some(OfflineNamespaceBinding {
                account_id: scope.account_id.clone(),
                origin: scope.origin.clone(),
                backend_identity: Arc::as_ptr(backend) as *const () as usize,
            }),
            binding_token: Arc::new(()),
            probe_gate: Mutex::new(()),
            next_probe: AtomicU64::new(0),
            transport_unavailable: AtomicBool::new(false),
            spaces: RwLock::new(None),
            published_live_spaces: RwLock::new(None),
        })
    }
}

/// A live namespace response tied to one immutable Engine account/backend
/// binding. Callers may inspect it for application-specific account checks,
/// but cannot construct or alter the proof before publishing it.
#[derive(Debug)]
pub struct LiveNamespaceSnapshot {
    binding: OfflineNamespaceBinding,
    binding_token: Arc<()>,
    probe_generation: u64,
    spaces: Vec<CloudSpace>,
}

impl LiveNamespaceSnapshot {
    pub fn spaces(&self) -> &[CloudSpace] {
        &self.spaces
    }
}

struct OfflineCache {
    cache: Cache,
    account_id: String,
    origin: String,
}

struct CacheMutation {
    scope: CacheScope,
    parent_paths: Vec<String>,
}

#[derive(Default)]
struct RefreshTree {
    by_id: BTreeMap<String, (String, RemoteEntry)>,
    directories: usize,
}

struct Inner {
    state_dir: PathBuf,
    cache_dir: PathBuf,
    db: Mutex<DbOwner>,
    execution: Mutex<()>,
    /// Last published exclusion policy for each pair. `None` is a retired
    /// pair ID and prevents a stale scheduler snapshot from reactivating it.
    /// Access is serialized by `execution` with every sync dispatch.
    pair_policies: Mutex<BTreeMap<String, Option<PairSyncPolicy>>>,
    metadata_gate: Mutex<()>,
    sync_paused: Arc<AtomicBool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PairSyncPolicy {
    mode: SyncMode,
    content_filter: MediaFilter,
    excluded_paths: Vec<String>,
    exclusions: Vec<FolderExclusion>,
}

impl From<&FolderPair> for PairSyncPolicy {
    fn from(pair: &FolderPair) -> Self {
        Self {
            mode: pair.mode,
            content_filter: pair.content_filter,
            excluded_paths: pair.excluded_paths.clone(),
            exclusions: pair.exclusions.clone(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncReport {
    pub pair_id: String,
    pub uploaded: u64,
    pub downloaded: u64,
    pub conflicts: u64,
    pub needs_attention: u64,
    pub unchanged: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConflictChoice {
    KeepLocal,
    KeepRemote,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileConflict {
    pub pair_id: String,
    pub path: String,
    pub local_hash: String,
    pub remote_etag: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConflictPage {
    pub items: Vec<FileConflict>,
    pub next_after: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConflictResolution {
    pub pair_id: String,
    pub path: String,
    pub choice: ConflictChoice,
    pub recovery_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransferRecord {
    pub id: i64,
    pub origin: String,
    pub space_id: String,
    pub path: String,
    pub direction: String,
    pub state: String,
    pub bytes_total: u64,
    pub bytes_done: u64,
    pub error: Option<String>,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OfflineRefreshReport {
    pub files_checked: usize,
    pub files_downloaded: usize,
    pub folders_refreshed: usize,
    pub unavailable: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileWriteOutcome {
    Uploaded(RemoteEntry),
    Queued(RemoteEntry),
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteReconcileReport {
    pub uploaded: u64,
    pub conflicts: u64,
    pub remaining: u64,
}

/// A verified download whose temporary file is removed when the snapshot is
/// dropped. Use this for short-lived provider reads that should not accumulate
/// in the persistent engine cache.
pub struct FetchSnapshot {
    // The download helper rebuilds this owner from the published file handle,
    // so the path and `file` refer to the same downloaded contents.
    _temp: Option<NamedTempFile>,
    file: SnapshotReader,
}

enum SnapshotReader {
    Download(File),
    Cached(raiun_cache::CacheContentReader),
}

impl Read for SnapshotReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Download(file) => file.read(buffer),
            Self::Cached(file) => file.read(buffer),
        }
    }
}

impl Seek for SnapshotReader {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        match self {
            Self::Download(file) => file.seek(position),
            Self::Cached(file) => file.seek(position),
        }
    }
}

impl Read for FetchSnapshot {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buffer)
    }
}

impl Seek for FetchSnapshot {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        self.file.seek(position)
    }
}

#[derive(Debug, Clone)]
struct LocalEntry {
    path: PathBuf,
    size: u64,
    mtime: i64,
    hash: String,
    directory: bool,
    fingerprint: Option<LocalFingerprint>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LocalFingerprint {
    device: i64,
    inode: i64,
    size: i64,
    mtime_seconds: i64,
    mtime_nanoseconds: i64,
    ctime_seconds: i64,
    ctime_nanoseconds: i64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct LocalScanMetrics {
    hashed_files: u64,
    reused_hashes: u64,
}

const MAX_LIST_ENTRIES: usize = 100_000;
const MAX_REFRESH_DEPTH: usize = 64;
const MAX_REFRESH_PATH_BYTES: usize = 32 * 1024 * 1024;
// The bound is cumulative over all entries found locally and remotely for one
// pair scan; it prevents a many-directory tree from bypassing per-list limits.
const MAX_TOTAL_SCAN_ENTRIES: usize = 10_000_000;
const STAGE_BATCH_SIZE: usize = 256;
const LOCAL_HASH_AUDIT_INTERVAL: i64 = 120;

#[derive(Debug, Clone)]
struct Baseline {
    local_hash: String,
    local_size: u64,
    local_mtime: i64,
    remote_etag: String,
    remote_hash: Option<String>,
    remote_size: u64,
}

impl Engine {
    /// Load opaque settings only for the exact caller-authenticated scope.
    pub fn load_folder_pair_document(&self, scope: &[u8]) -> Result<Option<Vec<u8>>, CloudError> {
        let database = self.db()?;
        folder_pair_document::load(&database, scope)
    }

    /// Atomically publish exact expected bytes; account/root authorization is caller-owned.
    pub fn compare_exchange_folder_pair_document(
        &self,
        scope: &[u8],
        expected: Option<&[u8]>,
        next: &[u8],
    ) -> Result<(), CloudError> {
        let database = self.db()?;
        folder_pair_document::compare_exchange(&database, scope, expected, next)
    }

    pub fn open(state_dir: &Path, backend: Arc<dyn CloudBackend>) -> Result<Self, CloudError> {
        fs::create_dir_all(state_dir).map_err(io_error)?;
        let state_dir = fs::canonicalize(state_dir).map_err(io_error)?;
        let cache_dir = state_dir.join("cache");
        fs::create_dir_all(&cache_dir).map_err(io_error)?;
        let db_path = state_dir.join("engine.sqlite3");
        let db = Connection::open(db_path).map_err(db_error)?;
        db.busy_timeout(std::time::Duration::from_secs(10))
            .map_err(db_error)?;
        db.execute_batch("PRAGMA journal_mode=WAL;")
            .map_err(db_error)?;
        Self::initialize(state_dir, cache_dir, DbOwner::Portable(db), backend)
    }

    /// Open the fixed Windows engine database through a held private-directory
    /// and rollback VFS. The agent must derive this directory from the exact
    /// authenticated account, and separately fence roots and remote writes.
    /// No native provider, scheduler, or account capability is enabled here.
    #[cfg(windows)]
    pub fn open_private_windows(
        directory: raiun_control_windows::PrivateDirectory,
        backend: Arc<dyn CloudBackend>,
    ) -> Result<Self, CloudError> {
        use raiun_control_windows::{PinnedDirectory, PrivateDirectory};
        directory.verify_path().map_err(io_error)?;
        let state_dir = directory.path().to_path_buf();
        let parent = PinnedDirectory::open(&state_dir).map_err(io_error)?;
        let cache_directory =
            PrivateDirectory::create_or_open_under(&parent, std::ffi::OsStr::new("cache"))
                .map_err(io_error)?;
        let cache_dir = cache_directory.path().to_path_buf();
        // Retain the private staging root alongside the guarded database. No
        // legacy directory ACL is repaired or accepted implicitly.
        let media_directory = Arc::new(
            PrivateDirectory::create_or_open_under(&parent, std::ffi::OsStr::new("media-staging"))
                .map_err(io_error)?,
        );
        let database =
            raiun_sqlite_windows::RegisteredRollbackDb::open_engine(directory).map_err(db_error)?;
        let owner = DbOwner::PrivateWindows {
            database,
            _cache_directory: cache_directory,
            media_directory,
        };
        Self::initialize(state_dir, cache_dir, owner, backend)
    }

    fn initialize(
        state_dir: PathBuf,
        cache_dir: PathBuf,
        db: DbOwner,
        backend: Arc<dyn CloudBackend>,
    ) -> Result<Self, CloudError> {
        db.busy_timeout(std::time::Duration::from_secs(10))
            .map_err(db_error)?;
        db.execute_batch(folder_pair_document::SCHEMA)
            .map_err(db_error)?;
        db.execute_batch(
            "PRAGMA foreign_keys=ON;
             CREATE TABLE IF NOT EXISTS transfers (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               pair_id TEXT, space_id TEXT NOT NULL, path TEXT NOT NULL,
               operation TEXT NOT NULL, status TEXT NOT NULL,
               bytes INTEGER NOT NULL DEFAULT 0, message TEXT,
               created_unix INTEGER NOT NULL, finished_unix INTEGER
             );
             CREATE INDEX IF NOT EXISTS transfers_created ON transfers(id DESC);
             CREATE TABLE IF NOT EXISTS baselines (
               pair_id TEXT NOT NULL, rel_path TEXT NOT NULL,
               local_hash TEXT NOT NULL, local_size INTEGER NOT NULL,
               local_mtime INTEGER NOT NULL, remote_etag TEXT NOT NULL,
               remote_hash TEXT, remote_size INTEGER NOT NULL,
               PRIMARY KEY(pair_id, rel_path)
             );
             CREATE TABLE IF NOT EXISTS local_stage (
               pair_id TEXT NOT NULL, rel_path TEXT NOT NULL, local_path TEXT NOT NULL,
               size INTEGER NOT NULL, mtime INTEGER NOT NULL, hash TEXT,
               directory INTEGER NOT NULL, PRIMARY KEY(pair_id, rel_path)
             );
             CREATE TABLE IF NOT EXISTS local_hash_generation (
               pair_id TEXT PRIMARY KEY, generation INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS local_hash_cache (
               pair_id TEXT NOT NULL, rel_path TEXT NOT NULL,
               device INTEGER NOT NULL, inode INTEGER NOT NULL, size INTEGER NOT NULL,
               mtime_seconds INTEGER NOT NULL, mtime_nanoseconds INTEGER NOT NULL,
               ctime_seconds INTEGER NOT NULL, ctime_nanoseconds INTEGER NOT NULL,
               hash TEXT NOT NULL, seen_generation INTEGER NOT NULL,
               PRIMARY KEY(pair_id, rel_path)
             );
             CREATE TABLE IF NOT EXISTS remote_stage (
               pair_id TEXT NOT NULL, rel_path TEXT NOT NULL, remote_path TEXT NOT NULL,
               etag TEXT NOT NULL, size INTEGER NOT NULL,
               directory INTEGER NOT NULL, PRIMARY KEY(pair_id, rel_path)
             );
             CREATE TABLE IF NOT EXISTS scan_dirs (
               pair_id TEXT NOT NULL, side TEXT NOT NULL, remote_path TEXT NOT NULL,
               PRIMARY KEY(pair_id, side, remote_path)
             );
             CREATE TABLE IF NOT EXISTS media_job_runs (
               job_id TEXT PRIMARY KEY, generation INTEGER NOT NULL, state TEXT NOT NULL,
               scanned INTEGER NOT NULL DEFAULT 0, waiting INTEGER NOT NULL DEFAULT 0,
               uploaded INTEGER NOT NULL DEFAULT 0, unchanged INTEGER NOT NULL DEFAULT 0,
               conflicts INTEGER NOT NULL DEFAULT 0, attention INTEGER NOT NULL DEFAULT 0,
               last_error TEXT, updated_unix INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS media_candidates (
               job_id TEXT NOT NULL, account_id TEXT NOT NULL, origin TEXT NOT NULL,
               space_id TEXT NOT NULL, source_root TEXT NOT NULL, relative_path TEXT NOT NULL,
               destination_path TEXT NOT NULL, source_size INTEGER NOT NULL,
               mtime_seconds INTEGER NOT NULL, mtime_nanoseconds INTEGER NOT NULL,
               source_sha256 TEXT NOT NULL, first_seen_unix INTEGER NOT NULL,
               last_seen_unix INTEGER NOT NULL, state TEXT NOT NULL, message TEXT,
               PRIMARY KEY(job_id,account_id,origin,space_id,source_root,relative_path,destination_path)
             );
             CREATE TABLE IF NOT EXISTS media_upload_attempts (
               job_id TEXT NOT NULL, account_id TEXT NOT NULL, origin TEXT NOT NULL,
               space_id TEXT NOT NULL, source_root TEXT NOT NULL, relative_path TEXT NOT NULL,
               destination_path TEXT NOT NULL, generation INTEGER NOT NULL,
               job_revision INTEGER NOT NULL DEFAULT 0, destination_root_id TEXT,
               run_generation INTEGER NOT NULL,
               state TEXT NOT NULL, source_size INTEGER NOT NULL,
               mtime_seconds INTEGER NOT NULL, mtime_nanoseconds INTEGER NOT NULL,
               source_sha256 TEXT NOT NULL, base_remote_id TEXT, base_etag TEXT,
               message TEXT, updated_unix INTEGER NOT NULL,
               PRIMARY KEY(job_id,account_id,origin,space_id,source_root,relative_path,destination_path)
             );
             CREATE TABLE IF NOT EXISTS media_upload_stages (
               job_id TEXT NOT NULL, account_id TEXT NOT NULL, origin TEXT NOT NULL,
               space_id TEXT NOT NULL, source_root TEXT NOT NULL, relative_path TEXT NOT NULL,
               destination_path TEXT NOT NULL, attempt_generation INTEGER NOT NULL,
               staged_path TEXT NOT NULL, staged_size INTEGER NOT NULL,
               PRIMARY KEY(job_id,account_id,origin,space_id,source_root,relative_path,destination_path)
             );
             CREATE TABLE IF NOT EXISTS media_import_receipts (
               job_id TEXT NOT NULL, account_id TEXT NOT NULL, origin TEXT NOT NULL,
               space_id TEXT NOT NULL, source_root TEXT NOT NULL, relative_path TEXT NOT NULL,
               destination_path TEXT NOT NULL, destination_root_id TEXT NOT NULL,
               source_size INTEGER NOT NULL,
               mtime_seconds INTEGER NOT NULL, source_sha256 TEXT NOT NULL,
               remote_resource_id TEXT NOT NULL, remote_etag TEXT NOT NULL,
               uploaded_unix INTEGER NOT NULL,
               PRIMARY KEY(job_id,account_id,origin,space_id,source_root,relative_path,destination_path)
             );
             PRAGMA user_version=2;",
        )
        .map_err(db_error)?;
        ensure_media_job_revision_column(&db)?;
        ensure_media_attempt_destination_root_column(&db)?;
        // An operation that was still running at process death has an unknown
        // remote outcome. Keep it visible as failed; a later reconciliation
        // must inspect the destination before attempting another mutation.
        db.execute("UPDATE transfers SET status='failed',message='engine stopped while operation was running',finished_unix=?1 WHERE status='running'", [now_unix()]).map_err(db_error)?;
        db.execute("UPDATE media_upload_attempts SET state='uncertain',message='engine stopped while media upload was in flight',updated_unix=?1 WHERE state='running'", [now_unix()]).map_err(db_error)?;
        db.execute("UPDATE media_candidates SET state='attention',message='engine stopped while media upload was in flight',last_seen_unix=?1 WHERE state='uploading'", [now_unix()]).map_err(db_error)?;
        db.execute("UPDATE media_job_runs SET state='interrupted',last_error='engine stopped while media job was running',updated_unix=?1 WHERE state='running'", [now_unix()]).map_err(db_error)?;
        Ok(Self {
            backend,
            vault_binding: None,
            offline_cache: None,
            account_scope: None,
            offline_namespace: OfflineNamespace::unbound(),
            inner: Arc::new(Inner {
                state_dir,
                cache_dir,
                db: Mutex::new(db),
                execution: Mutex::new(()),
                pair_policies: Mutex::new(BTreeMap::new()),
                metadata_gate: Mutex::new(()),
                sync_paused: Arc::new(AtomicBool::new(false)),
            }),
        })
    }

    /// Bind a backend to one encrypted collection while retaining this account's
    /// database, execution gate and pause flag. The caller supplies a verified
    /// vault adapter; ordinary engines reject vault-bound pairs before scanning.
    pub fn with_vault_backend(
        &self,
        space_id: String,
        binding: VaultBinding,
        backend: Arc<dyn CloudBackend>,
    ) -> Self {
        Self {
            inner: self.inner.clone(),
            backend,
            vault_binding: Some((space_id, binding)),
            // Vault engines never inherit the ordinary plaintext cache.
            offline_cache: None,
            account_scope: None,
            offline_namespace: OfflineNamespace::unbound(),
        }
    }

    /// Bind the authenticated account identity even when the optional cache
    /// could not be opened. This keeps provider recovery manifests scoped
    /// without making an otherwise online-capable Engine depend on the cache.
    pub fn with_account_scope(
        &self,
        account_id: String,
        origin: String,
    ) -> Result<Self, CloudError> {
        let scope = CacheScope::new(
            &origin,
            &account_id,
            "scope-check-space",
            "scope-check-root",
            ScopeProtection::PlaintextAllowed,
        )
        .map_err(cache_cloud_error)?;
        if self.backend.server_origin().as_deref() != Some(scope.origin()) {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "account scope origin does not match the configured cloud server",
            ));
        }
        let account_scope = AccountScope {
            account_id,
            origin: scope.origin().to_owned(),
        };
        let offline_namespace = if self.vault_binding.is_none() {
            OfflineNamespace::for_account(&account_scope, &self.backend)
        } else {
            OfflineNamespace::unbound()
        };
        // Account rebinding creates a new authority boundary. Retain cached
        // data only for the same already-bound account and canonical origin;
        // the old account's cache remains owned by its original Engine.
        let offline_cache = self
            .offline_cache
            .as_ref()
            .filter(|cache| {
                cache.account_id == account_scope.account_id
                    && self.account_scope.as_ref().is_some_and(|previous| {
                        previous.account_id == account_scope.account_id
                            && previous.origin == account_scope.origin
                    })
            })
            .cloned();
        Ok(Self {
            inner: self.inner.clone(),
            backend: self.backend.clone(),
            vault_binding: self.vault_binding.clone(),
            offline_cache,
            account_scope: Some(account_scope),
            // Rebinding creates a fresh authority handle, even if account
            // labels match an earlier Engine.
            offline_namespace,
        })
    }

    /// Enable the ordinary, account-scoped persistent cache. The caller must
    /// supply the selected profile/account identity and the configured server
    /// origin; each Space root is then verified online before its cache scope
    /// is used. Vault-bound engines deliberately discard this configuration.
    pub fn with_offline_cache(
        &self,
        cache: Cache,
        account_id: String,
        origin: String,
    ) -> Result<Self, CloudError> {
        let validated_scope = CacheScope::new(
            &origin,
            &account_id,
            "cache-origin-check",
            "cache-root-check",
            ScopeProtection::PlaintextAllowed,
        )
        .map_err(cache_cloud_error)?;
        if self.backend.server_origin().as_deref() != Some(validated_scope.origin()) {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "offline cache origin does not match the configured cloud server",
            ));
        }
        let account_scope = AccountScope {
            account_id: account_id.clone(),
            origin: validated_scope.origin().to_owned(),
        };
        let offline_namespace = if self.vault_binding.is_none() {
            OfflineNamespace::for_account(&account_scope, &self.backend)
        } else {
            OfflineNamespace::unbound()
        };
        Ok(Self {
            inner: self.inner.clone(),
            backend: self.backend.clone(),
            vault_binding: self.vault_binding.clone(),
            account_scope: Some(account_scope),
            offline_namespace,
            offline_cache: if self.vault_binding.is_none() {
                Some(Arc::new(OfflineCache {
                    cache,
                    account_id,
                    origin,
                }))
            } else {
                None
            },
        })
    }

    /// Attach a bounded, private last-known namespace snapshot for this
    /// account and server. `spaces()` uses it only when the live backend
    /// reports a transport outage. Cached entries are exposed as read-only
    /// while disconnected; authorization and server errors are never hidden.
    ///
    /// Call this only after the owning profile layer has loaded a snapshot
    /// whose persisted account and origin match the selected identity.
    pub fn with_offline_spaces(&self, spaces: Vec<CloudSpace>) -> Result<Self, CloudError> {
        let spaces = self.validate_offline_spaces(spaces)?;
        self.publish_offline_spaces(spaces)?;
        Ok(self.clone())
    }

    /// Mark this account-bound Engine as transport-offline when the profile
    /// layer restored a previously verified namespace after a failed network
    /// probe. This hint is shared by Engine clones, so mounted filesystem
    /// listings can use cached metadata immediately instead of repeating a
    /// long transport timeout. It never grants write authority.
    pub fn mark_namespace_transport_unavailable(&self) -> Result<(), CloudError> {
        self.validate_offline_namespace_binding()?;
        let has_snapshot = self
            .offline_namespace
            .spaces
            .read()
            .map_err(|_| CloudError::new(ErrorKind::Io, "offline namespace state is unavailable"))?
            .is_some();
        if !has_snapshot {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "cannot mark a namespace offline without a verified snapshot",
            ));
        }
        self.offline_namespace
            .transport_unavailable
            .store(true, Ordering::Release);
        Ok(())
    }

    /// Whether the bound profile has already established that its namespace
    /// transport is unavailable. This is a read-only fast-path hint, not a
    /// replacement for fresh authorization checks when the server is online.
    pub fn namespace_transport_unavailable(&self) -> bool {
        self.offline_namespace
            .transport_unavailable
            .load(Ordering::Acquire)
    }

    /// Probe the live namespace without publishing it. The returned opaque
    /// proof can be inspected for additional identity checks, then published
    /// only into clones sharing this exact account/backend binding.
    pub fn probe_live_namespace(&self) -> Result<LiveNamespaceSnapshot, CloudError> {
        self.validate_offline_namespace_binding()?;
        let _probe_guard = self.offline_namespace.probe_gate.lock().map_err(|_| {
            CloudError::new(ErrorKind::Io, "offline namespace state is unavailable")
        })?;
        let mut previous_generation = self.offline_namespace.next_probe.load(Ordering::Acquire);
        let probe_generation = loop {
            let next_generation = previous_generation.checked_add(1).ok_or_else(|| {
                CloudError::new(
                    ErrorKind::Conflict,
                    "offline namespace probe generation is exhausted",
                )
            })?;
            match self.offline_namespace.next_probe.compare_exchange_weak(
                previous_generation,
                next_generation,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break next_generation,
                Err(current_generation) => previous_generation = current_generation,
            }
        };
        drop(_probe_guard);
        let spaces = match self.live_spaces() {
            Ok(spaces) => spaces,
            Err(error) if error.kind == ErrorKind::Offline => {
                if self
                    .offline_namespace
                    .spaces
                    .read()
                    .map_err(|_| {
                        CloudError::new(ErrorKind::Io, "offline namespace state is unavailable")
                    })?
                    .is_some()
                {
                    self.offline_namespace
                        .transport_unavailable
                        .store(true, Ordering::Release);
                }
                return Err(error);
            }
            Err(error) => {
                self.revoke_mount_permissions(probe_generation)?;
                return Err(error);
            }
        };
        if let Err(error) = self.validate_offline_spaces(spaces.clone()) {
            self.revoke_mount_permissions(probe_generation)?;
            return Err(error);
        }
        let binding = self.offline_namespace.binding.as_ref().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Conflict,
                "offline namespace handle is not account-bound",
            )
        })?;
        Ok(LiveNamespaceSnapshot {
            binding: OfflineNamespaceBinding {
                account_id: binding.account_id.clone(),
                origin: binding.origin.clone(),
                backend_identity: binding.backend_identity,
            },
            binding_token: self.offline_namespace.binding_token.clone(),
            probe_generation,
            spaces,
        })
    }

    /// Publish a previously probed live namespace after the owning profile
    /// layer has completed its authenticated account-identity checks. The
    /// proof cannot be used on a rebound or different Engine.
    pub fn publish_live_namespace(
        &self,
        snapshot: LiveNamespaceSnapshot,
    ) -> Result<Vec<CloudSpace>, CloudError> {
        self.validate_offline_namespace_binding()?;
        let binding = self.offline_namespace.binding.as_ref().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Conflict,
                "offline namespace handle is not account-bound",
            )
        })?;
        if binding != &snapshot.binding {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "live namespace proof belongs to a different Engine binding",
            ));
        }
        if !Arc::ptr_eq(
            &self.offline_namespace.binding_token,
            &snapshot.binding_token,
        ) {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "live namespace proof belongs to a different Engine handle",
            ));
        }
        let _probe_guard = self.offline_namespace.probe_gate.lock().map_err(|_| {
            CloudError::new(ErrorKind::Io, "offline namespace state is unavailable")
        })?;
        if self.offline_namespace.next_probe.load(Ordering::Acquire) != snapshot.probe_generation {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "a newer live namespace probe superseded this proof",
            ));
        }
        let sanitized = self.validate_offline_spaces(snapshot.spaces.clone())?;
        // Block permission readers until both namespace views are published.
        let mut live_permissions = self
            .offline_namespace
            .published_live_spaces
            .write()
            .map_err(|_| {
                CloudError::new(ErrorKind::Io, "live namespace permissions are unavailable")
            })?;
        if let Err(error) = self.store_offline_spaces(sanitized) {
            *live_permissions = Some(Vec::new());
            return Err(error);
        }
        *live_permissions = Some(snapshot.spaces.clone());
        self.offline_namespace
            .transport_unavailable
            .store(false, Ordering::Release);
        Ok(snapshot.spaces)
    }

    /// Reject an otherwise well-formed proof after application account checks.
    /// A proof from another handle cannot revoke this mount's permissions.
    pub fn reject_live_namespace(&self, snapshot: LiveNamespaceSnapshot) -> Result<(), CloudError> {
        if self.offline_namespace.binding.as_ref() != Some(&snapshot.binding)
            || !Arc::ptr_eq(
                &self.offline_namespace.binding_token,
                &snapshot.binding_token,
            )
        {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "namespace rejection belongs to a different Engine handle",
            ));
        }
        self.revoke_mount_permissions(snapshot.probe_generation)
    }

    fn revoke_mount_permissions(&self, probe_generation: u64) -> Result<(), CloudError> {
        let _probe_guard =
            self.offline_namespace.probe_gate.lock().map_err(|_| {
                CloudError::new(ErrorKind::Io, "namespace probe gate is unavailable")
            })?;
        if self.offline_namespace.next_probe.load(Ordering::Acquire) == probe_generation {
            *self
                .offline_namespace
                .published_live_spaces
                .write()
                .map_err(|_| {
                    CloudError::new(ErrorKind::Io, "live namespace permissions are unavailable")
                })? = Some(Vec::new());
            self.offline_namespace
                .transport_unavailable
                .store(false, Ordering::Release);
        }
        Ok(())
    }

    /// Last application-validated live permission for an existing mount mapping.
    /// None means no live proof has been published into this exact Engine handle;
    /// callers may retain their startup permissions. Removed or rebound roots and
    /// poisoned state fail closed. This is not a substitute for write-time server
    /// preconditions, and does not make the saved offline namespace writable.
    pub fn published_mount_permission(&self, mounted: &CloudSpace) -> Option<bool> {
        let published = match self.offline_namespace.published_live_spaces.read() {
            Ok(published) => published,
            Err(_) => return Some(false),
        };
        published.as_ref().map(|spaces| {
            spaces.iter().any(|space| {
                space.id == mounted.id
                    && space.dav_url == mounted.dav_url
                    && space.encrypted == mounted.encrypted
                    && space.personal == mounted.personal
                    && space.writable
            })
        })
    }

    fn validate_offline_namespace_binding(&self) -> Result<(), CloudError> {
        let account_scope = self.account_scope.as_ref().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Conflict,
                "offline namespace requires an account-scoped engine",
            )
        })?;
        let backend_origin = self.backend.server_origin().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Conflict,
                "offline namespace requires a server-bound backend",
            )
        })?;
        if self.vault_binding.is_some() || backend_origin != account_scope.origin {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "offline namespace binding does not match this ordinary account engine",
            ));
        }
        let expected = OfflineNamespaceBinding {
            account_id: account_scope.account_id.clone(),
            origin: account_scope.origin.clone(),
            backend_identity: Arc::as_ptr(&self.backend) as *const () as usize,
        };
        if self.offline_namespace.binding.as_ref() != Some(&expected) {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "offline namespace handle does not match this account and backend",
            ));
        }
        Ok(())
    }

    fn validate_offline_spaces(
        &self,
        mut spaces: Vec<CloudSpace>,
    ) -> Result<Vec<CloudSpace>, CloudError> {
        const MAX_SNAPSHOT_SPACES: usize = 2048;
        const MAX_SPACE_FIELD_BYTES: usize = 16 * 1024;

        self.validate_offline_namespace_binding()?;
        if spaces.is_empty() || spaces.len() > MAX_SNAPSHOT_SPACES {
            return Err(CloudError::new(
                ErrorKind::InvalidResponse,
                "offline namespace is empty or exceeds its limit",
            ));
        }

        let mut space_ids = std::collections::BTreeSet::new();
        for space in &spaces {
            if space.id.is_empty()
                || space.id.len() > MAX_SPACE_FIELD_BYTES
                || space.id.chars().any(char::is_control)
                || !space_ids.insert(space.id.as_str())
                || space.name.is_empty()
                || space.name.len() > MAX_SPACE_FIELD_BYTES
                || space.name.chars().any(char::is_control)
                || space.dav_url.is_empty()
                || space.dav_url.len() > MAX_SPACE_FIELD_BYTES
            {
                return Err(CloudError::new(
                    ErrorKind::InvalidResponse,
                    "offline namespace contains invalid or duplicate Space metadata",
                ));
            }
            let dav_url = url::Url::parse(&space.dav_url).map_err(|_| {
                CloudError::new(
                    ErrorKind::InvalidResponse,
                    "offline namespace contains an invalid DAV URL",
                )
            })?;
            if !matches!(dav_url.scheme(), "http" | "https")
                || !dav_url.username().is_empty()
                || dav_url.password().is_some()
                || dav_url.query().is_some()
                || dav_url.fragment().is_some()
                || dav_url.origin().ascii_serialization()
                    != self.account_scope.as_ref().expect("validated scope").origin
            {
                return Err(CloudError::new(
                    ErrorKind::InvalidResponse,
                    "offline namespace DAV URL is outside the selected server",
                ));
            }
        }

        for space in &mut spaces {
            // The snapshot discovers names and roots only. It does not grant
            // current write permission while the server is unreachable.
            space.writable = false;
        }
        Ok(spaces)
    }

    fn publish_offline_spaces(&self, spaces: Vec<CloudSpace>) -> Result<(), CloudError> {
        self.validate_offline_namespace_binding()?;
        let _probe_guard = self.offline_namespace.probe_gate.lock().map_err(|_| {
            CloudError::new(ErrorKind::Io, "offline namespace state is unavailable")
        })?;
        let next_generation = self
            .offline_namespace
            .next_probe
            .load(Ordering::Acquire)
            .checked_add(1)
            .ok_or_else(|| {
                CloudError::new(
                    ErrorKind::Conflict,
                    "offline namespace probe generation is exhausted",
                )
            })?;
        self.offline_namespace
            .next_probe
            .store(next_generation, Ordering::Release);
        self.store_offline_spaces(spaces)
    }

    fn store_offline_spaces(&self, spaces: Vec<CloudSpace>) -> Result<(), CloudError> {
        *self.offline_namespace.spaces.write().map_err(|_| {
            CloudError::new(ErrorKind::Io, "offline namespace state is unavailable")
        })? = Some(Arc::new(spaces));
        Ok(())
    }

    fn validate_backend_binding(&self, pair: &FolderPair) -> Result<(), CloudError> {
        let matches = match (&self.vault_binding, &pair.vault) {
            (None, None) => true,
            (Some((space, binding)), Some(pair_binding)) => {
                space == &pair.space_id && binding == pair_binding
            }
            _ => false,
        };
        if !matches {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "folder pair requires its explicitly bound unlocked vault backend",
            ));
        }
        Ok(())
    }

    /// Pause or resume folder-pair reconciliation. An in-flight sync stops at
    /// its next local-entry, remote-entry, or reconciliation boundary.
    pub fn revocation_handle(&self) -> SyncRevocationHandle {
        SyncRevocationHandle {
            paused: Arc::clone(&self.inner.sync_paused),
        }
    }

    pub fn set_sync_paused(&self, paused: bool) {
        self.inner.sync_paused.store(paused, Ordering::Release);
    }

    /// Return the namespace reported by the live backend without consulting
    /// the persisted offline snapshot. Reconnect/authentication flows should
    /// use this to prove the server is reachable before refreshing cached
    /// namespace metadata.
    pub fn live_spaces(&self) -> Result<Vec<CloudSpace>, CloudError> {
        self.backend.spaces()
    }

    /// Query one ordinary-cloud entry without consulting the offline cache or
    /// pending-operation overlay. Use only for fresh identity validation.
    pub fn live_stat(&self, space: &str, path: &str) -> Result<RemoteEntry, CloudError> {
        if self.vault_binding.is_some() {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "live ordinary-cloud lookup is unavailable for a vault route",
            ));
        }
        validate_remote_path(path).map_err(|error| {
            CloudError::new(
                ErrorKind::Unsupported,
                format!("invalid remote path: {error}"),
            )
        })?;
        self.backend.stat(space, path)
    }

    /// Return live namespace metadata, falling back to the validated,
    /// read-only snapshot only for transport-offline failures.
    pub fn spaces(&self) -> Result<Vec<CloudSpace>, CloudError> {
        if self.namespace_transport_unavailable() {
            return self.offline_namespace_spaces();
        }
        match self.live_spaces() {
            Ok(spaces) => Ok(spaces),
            Err(error) if error.kind == ErrorKind::Offline => {
                if self
                    .offline_namespace
                    .spaces
                    .read()
                    .map_err(|_| {
                        CloudError::new(ErrorKind::Io, "offline namespace state is unavailable")
                    })?
                    .is_some()
                {
                    self.offline_namespace
                        .transport_unavailable
                        .store(true, Ordering::Release);
                }
                self.offline_namespace_spaces().or(Err(error))
            }
            Err(error) => Err(error),
        }
    }

    fn offline_namespace_spaces(&self) -> Result<Vec<CloudSpace>, CloudError> {
        self.offline_namespace
            .spaces
            .read()
            .map_err(|_| CloudError::new(ErrorKind::Io, "offline namespace state is unavailable"))?
            .as_ref()
            .map(|spaces| spaces.as_ref().clone())
            .ok_or_else(|| CloudError::new(ErrorKind::Offline, "saved namespace is unavailable"))
    }

    pub fn list(&self, space: &str, path: &str) -> Result<Vec<RemoteEntry>, CloudError> {
        if self.namespace_transport_unavailable() {
            return self.cached_list_without_probe(space, path);
        }
        if self.offline_cache.is_some() {
            return self.cached_list(space, path);
        }
        let mut entries = Vec::new();
        let mut metadata_bytes = 0usize;
        let result = self.backend.list(space, path, &mut |entry| {
            if entries.len() >= MAX_LIST_ENTRIES {
                return Err(CloudError::new(
                    ErrorKind::InvalidResponse,
                    "cloud listing exceeds the 100,000-entry limit",
                ));
            }
            metadata_bytes = metadata_bytes
                .saturating_add(entry.id.len())
                .saturating_add(entry.etag.len())
                .saturating_add(entry.path.len());
            if metadata_bytes > MAX_REFRESH_PATH_BYTES {
                return Err(CloudError::new(
                    ErrorKind::InvalidResponse,
                    "cloud listing metadata exceeds the 32 MiB limit",
                ));
            }
            entries.push(entry);
            Ok(())
        });
        match result {
            Ok(()) => Ok(entries),
            Err(error) if error.kind == ErrorKind::Offline => {
                if self
                    .offline_namespace
                    .spaces
                    .read()
                    .map_err(|_| {
                        CloudError::new(ErrorKind::Io, "offline namespace state is unavailable")
                    })?
                    .is_some()
                {
                    self.offline_namespace
                        .transport_unavailable
                        .store(true, Ordering::Release);
                }
                Err(error)
            }
            Err(error) => Err(error),
        }
    }

    fn cached_list_without_probe(
        &self,
        space: &str,
        path: &str,
    ) -> Result<Vec<RemoteEntry>, CloudError> {
        let Some(context) = &self.offline_cache else {
            return Err(CloudError::new(
                ErrorKind::Offline,
                "cloud listing is unavailable while the saved namespace is offline",
            ));
        };
        let offline = CloudError::new(
            ErrorKind::Offline,
            "cloud listing is unavailable while the saved namespace is offline",
        );
        let scope = self
            .cached_scope(space, context)
            .map_err(|error| offline_cache_error(error, offline.clone()))?;
        self.cached_listing(context, &scope, path, offline)
    }

    pub fn stat(&self, space: &str, path: &str) -> Result<RemoteEntry, CloudError> {
        let Some(context) = &self.offline_cache else {
            return self.backend.stat(space, path);
        };
        match self.online_plaintext_scope(space) {
            Ok((scope, root)) => {
                if path == "/" {
                    return Ok(root);
                }
                match self.backend.stat(space, path) {
                    Ok(entry) if entry.encrypted => Err(unsupported_encrypted_cache()),
                    Ok(entry) => self.overlay_pending_stat(&scope, path, entry),
                    Err(error) if error.kind == ErrorKind::Offline => {
                        if let Some(write) = context
                            .cache
                            .pending_write_for_path(&scope, path)
                            .map_err(cache_cloud_error)?
                        {
                            return self.remote_entry_for_pending(space, &write);
                        }
                        self.cached_entry_or_error(context, &scope, path, error)
                    }
                    Err(error) => Err(error),
                }
            }
            Err(error) if error.kind == ErrorKind::Offline => {
                let scope = self
                    .cached_scope(space, context)
                    .map_err(|cache_error| offline_cache_error(cache_error, error.clone()))?;
                if let Some(write) = context
                    .cache
                    .pending_write_for_path(&scope, path)
                    .map_err(cache_cloud_error)?
                {
                    return self.remote_entry_for_pending(space, &write);
                }
                self.cached_entry_or_error(context, &scope, path, error)
            }
            Err(error) => Err(error),
        }
    }

    fn cached_list(&self, space: &str, path: &str) -> Result<Vec<RemoteEntry>, CloudError> {
        let _metadata = self.metadata_publication()?;
        let context = self
            .offline_cache
            .as_ref()
            .expect("cached list requires a cache context");
        let (scope, root) = match self.online_plaintext_scope(space) {
            Ok(scope_root) => scope_root,
            Err(error) if error.kind == ErrorKind::Offline => {
                let scope = self
                    .cached_scope(space, context)
                    .map_err(|cache_error| offline_cache_error(cache_error, error.clone()))?;
                return self.cached_listing(context, &scope, path, error);
            }
            Err(error) => return Err(error),
        };
        let parent_id = if path == "/" {
            root.id.clone()
        } else {
            match self.backend.stat(space, path) {
                Ok(parent) if parent.encrypted => return Err(unsupported_encrypted_cache()),
                Ok(parent) if !parent.directory => {
                    return Err(CloudError::new(
                        ErrorKind::Unsupported,
                        "cloud item is not a directory",
                    ));
                }
                Ok(parent) => parent.id,
                Err(error) if error.kind == ErrorKind::Offline => {
                    return self.cached_listing(context, &scope, path, error);
                }
                Err(error) => return Err(error),
            }
        };
        let mut entries = Vec::new();
        let mut metadata_bytes = 0usize;
        let result = self.backend.list(space, path, &mut |entry| {
            if entries.len() >= MAX_LIST_ENTRIES {
                return Err(CloudError::new(
                    ErrorKind::InvalidResponse,
                    "cloud listing exceeds the 100,000-entry limit",
                ));
            }
            metadata_bytes = metadata_bytes
                .saturating_add(entry.id.len())
                .saturating_add(entry.etag.len())
                .saturating_add(entry.path.len());
            if metadata_bytes > MAX_REFRESH_PATH_BYTES {
                return Err(CloudError::new(
                    ErrorKind::InvalidResponse,
                    "cloud listing metadata exceeds the 32 MiB limit",
                ));
            }
            entries.push(entry);
            Ok(())
        });
        match result {
            Ok(()) => {
                let cache_entries = entries
                    .iter()
                    .filter(|entry| !entry.encrypted)
                    .cloned()
                    .map(|entry| CachedEntry {
                        parent_resource_id: parent_id.clone(),
                        entry,
                    })
                    .collect::<Vec<_>>();
                // Cache failures must not turn a successful online listing into
                // an error. A later offline read will fail closed if no full
                // verified snapshot was committed.
                if context
                    .cache
                    .publish_listing(&scope, &parent_id, &cache_entries, now_unix())
                    .is_ok()
                {
                    let _ = context.cache.evict_recent(context.cache.quota_bytes());
                }
                self.overlay_pending_entries(&scope, &parent_id, &mut entries)?;
                Ok(entries)
            }
            Err(error) if error.kind == ErrorKind::Offline => {
                self.cached_listing(context, &scope, path, error)
            }
            Err(error) => Err(error),
        }
    }

    fn online_plaintext_scope(
        &self,
        space_id: &str,
    ) -> Result<(CacheScope, RemoteEntry), CloudError> {
        let context = self
            .offline_cache
            .as_ref()
            .expect("online cache scope requires a cache context");
        let space = self
            .backend
            .spaces()?
            .into_iter()
            .find(|space| space.id == space_id)
            .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "cloud Space was not found"))?;
        if space.encrypted {
            return Err(unsupported_encrypted_cache());
        }
        let root = self.backend.stat(space_id, "/")?;
        if root.encrypted || !root.directory || root.path != "/" {
            return Err(CloudError::new(
                ErrorKind::InvalidResponse,
                "cloud Space root identity is invalid for the ordinary cache",
            ));
        }
        let scope = CacheScope::new(
            &context.origin,
            &context.account_id,
            space_id,
            &root.id,
            ScopeProtection::PlaintextAllowed,
        )
        .map_err(cache_cloud_error)?;
        Ok((scope, root))
    }

    fn cached_scope(
        &self,
        space_id: &str,
        context: &OfflineCache,
    ) -> Result<CacheScope, raiun_cache::CacheError> {
        context
            .cache
            .find_plaintext_scope(&context.origin, &context.account_id, space_id)?
            .ok_or(raiun_cache::CacheError::NotFound)
    }

    /// Invalidate affected snapshots before sending a remote mutation. If the
    /// server operation then fails ambiguously, stale metadata is still not
    /// available to an offline read. Immutable content and recovery records
    /// are retained; only listing reachability and pin freshness change.
    fn begin_cache_mutation(
        &self,
        space_id: &str,
        paths: &[&str],
    ) -> Result<Option<CacheMutation>, CloudError> {
        let Some(context) = &self.offline_cache else {
            return Ok(None);
        };
        let (scope, _) = self.online_plaintext_scope(space_id)?;
        context
            .cache
            .invalidate_paths(&scope, paths)
            .map_err(cache_cloud_error)?;
        let mut parent_paths = paths
            .iter()
            .map(|path| {
                if *path == "/" {
                    Ok("/".to_owned())
                } else {
                    parent_path(path)
                }
            })
            .collect::<Result<Vec<_>, CloudError>>()?;
        parent_paths.sort();
        parent_paths.dedup();
        Ok(Some(CacheMutation {
            scope,
            parent_paths,
        }))
    }

    /// Republish exact complete parent listings after a mutation attempt.
    /// This reads the current server tree even when the mutation failed; it
    /// never restores the invalidated snapshot or verifies an unacknowledged write.
    /// A failed/uncertain refresh leaves the prior listing invalidated, so the
    /// next offline request fails closed instead of resurrecting old entries.
    fn finish_cache_mutation(&self, space_id: &str, mutation: Option<CacheMutation>) {
        let (Some(context), Some(mutation)) = (&self.offline_cache, mutation) else {
            return;
        };
        for parent_path in mutation.parent_paths {
            let refreshed = (|| {
                let (current_scope, root) = self.online_plaintext_scope(space_id)?;
                if current_scope != mutation.scope {
                    return Err(CloudError::new(
                        ErrorKind::Conflict,
                        "cloud Space root changed during a provider mutation",
                    ));
                }
                let parent = if parent_path == "/" {
                    root
                } else {
                    self.backend.stat(space_id, &parent_path)?
                };
                if !parent.directory || parent.encrypted {
                    return Err(unsupported_encrypted_cache());
                }
                let mut entries = Vec::new();
                self.backend.list(space_id, &parent_path, &mut |entry| {
                    if entries.len() >= MAX_LIST_ENTRIES {
                        return Err(CloudError::new(
                            ErrorKind::InvalidResponse,
                            "cloud listing exceeds the 100,000-entry limit",
                        ));
                    }
                    entries.push(entry);
                    Ok(())
                })?;
                let cached_entries = entries
                    .iter()
                    .filter(|entry| !entry.encrypted)
                    .cloned()
                    .map(|entry| CachedEntry {
                        parent_resource_id: parent.id.clone(),
                        entry,
                    })
                    .collect::<Vec<_>>();
                context
                    .cache
                    .publish_listing(&mutation.scope, &parent.id, &cached_entries, now_unix())
                    .map_err(cache_cloud_error)?;
                Ok(())
            })();
            // Preserve the mutation's own result independently of metadata
            // refresh. Invalidation remains in place if refresh fails, and
            // offline browsing will fail
            // closed until a later complete listing succeeds.
            let _ = refreshed;
        }
    }

    fn cached_listing(
        &self,
        context: &OfflineCache,
        scope: &CacheScope,
        path: &str,
        offline: CloudError,
    ) -> Result<Vec<RemoteEntry>, CloudError> {
        let parent_id = context
            .cache
            .resource_id_for_path(scope, path)
            .map_err(|error| offline_cache_error(error, offline.clone()))?
            .ok_or_else(|| offline.clone())?;
        let listing = context
            .cache
            .listing(scope, &parent_id)
            .map_err(|error| offline_cache_error(error, offline))?;
        if listing.entries.iter().any(|item| item.entry.encrypted) {
            return Err(unsupported_encrypted_cache());
        }
        let mut entries = listing
            .entries
            .into_iter()
            .map(|item| item.entry)
            .collect::<Vec<_>>();
        self.overlay_pending_entries(scope, &parent_id, &mut entries)?;
        Ok(entries)
    }

    fn overlay_pending_stat(
        &self,
        scope: &CacheScope,
        path: &str,
        remote: RemoteEntry,
    ) -> Result<RemoteEntry, CloudError> {
        let Some(context) = &self.offline_cache else {
            return Ok(remote);
        };
        let Some(write) = context
            .cache
            .pending_write_for_path(scope, path)
            .map_err(cache_cloud_error)?
        else {
            return Ok(remote);
        };
        if remote.encrypted {
            context
                .cache
                .mark_write_conflict(scope, write.id)
                .map_err(cache_cloud_error)?;
            return Err(unsupported_encrypted_cache());
        }
        if remote.id != write.resource_id.as_deref().unwrap_or_default()
            || !matches!(&write.base, WriteCondition::Match(etag) if etag == &remote.etag)
            || !remote.writable
        {
            context
                .cache
                .mark_write_conflict(scope, write.id)
                .map_err(cache_cloud_error)?;
        }
        self.remote_entry_for_pending_in_scope(scope, &write)
    }

    fn overlay_pending_entries(
        &self,
        scope: &CacheScope,
        parent_id: &str,
        entries: &mut Vec<RemoteEntry>,
    ) -> Result<(), CloudError> {
        let Some(context) = &self.offline_cache else {
            return Ok(());
        };
        let writes = context
            .cache
            .pending_writes_for_parent(scope, parent_id)
            .map_err(cache_cloud_error)?;
        for write in writes {
            if write.state == WriteState::Verified {
                continue;
            }
            let existing = entries
                .iter()
                .position(|entry| entry.path == write.logical_path);
            if let Some(index) = existing {
                let remote = &entries[index];
                if remote.encrypted {
                    context
                        .cache
                        .mark_write_conflict(scope, write.id)
                        .map_err(cache_cloud_error)?;
                    continue;
                }
                if remote.id != write.resource_id.as_deref().unwrap_or_default()
                    || !matches!(&write.base, WriteCondition::Match(etag) if etag == &remote.etag)
                    || !remote.writable
                {
                    context
                        .cache
                        .mark_write_conflict(scope, write.id)
                        .map_err(cache_cloud_error)?;
                }
            } else {
                // The last complete online listing proves this target is no
                // longer present. Keep the user copy visible as a conflict;
                // never translate that absence into a delete operation.
                context
                    .cache
                    .mark_write_conflict(scope, write.id)
                    .map_err(cache_cloud_error)?;
            }
            let mut local = self.remote_entry_for_pending_in_scope(scope, &write)?;
            if let Some(index) = existing {
                entries[index] = local;
            } else {
                local.encrypted = false;
                entries.push(local);
            }
        }
        Ok(())
    }

    fn cached_entry_or_error(
        &self,
        context: &OfflineCache,
        scope: &CacheScope,
        path: &str,
        offline: CloudError,
    ) -> Result<RemoteEntry, CloudError> {
        let entry = context
            .cache
            .entry_for_path(scope, path)
            .map_err(|error| offline_cache_error(error, offline.clone()))?
            .ok_or_else(|| offline.clone())?;
        if entry.encrypted {
            return Err(unsupported_encrypted_cache());
        }
        if context
            .cache
            .policy_target_state(scope, &entry.id)
            .map_err(cache_cloud_error)?
            .is_some_and(|state| state != TargetState::Ready)
        {
            return Err(offline);
        }
        Ok(entry)
    }

    /// Set path-level availability after fresh server metadata validation.
    /// Unix folders use bounded atomic CloudOnly admission or clear only their
    /// own folder intent. AlwaysOffline files first stage their exact ETag;
    /// recursive folder retention continues through the folder pin workflow.
    pub fn set_availability_policy(
        &self,
        space: &str,
        path: &str,
        policy: AvailabilityPolicy,
    ) -> Result<(), CloudError> {
        let context = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(ErrorKind::Unsupported, "offline cache is unavailable")
        })?;
        let (scope, _) = self.online_plaintext_scope(space)?;
        let entry = self.backend.stat(space, path)?;
        if entry.encrypted {
            return Err(unsupported_encrypted_cache());
        }
        if entry.directory {
            #[cfg(unix)]
            match policy {
                AvailabilityPolicy::CloudOnly => {
                    return self.set_folder_cloud_only_live(space, &scope, &entry);
                }
                AvailabilityPolicy::Recent => {
                    let _metadata = self.metadata_publication()?;
                    let (current_scope, _) = self.online_plaintext_scope(space)?;
                    if current_scope != scope || self.backend.stat(space, path)? != entry {
                        return Err(CloudError::new(
                            ErrorKind::Conflict,
                            "folder identity changed while clearing availability",
                        ));
                    }
                    return context
                        .cache
                        .clear_folder_cloud_only(&scope, &entry.id)
                        .map(|_| ())
                        .map_err(cache_cloud_error);
                }
                AvailabilityPolicy::AlwaysOffline => {}
            }
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "availability policy applies to files; pin a folder recursively",
            ));
        }
        let parent = parent_path(path)?;
        let listing = self.list(space, &parent)?;
        if !listing.iter().any(|listed| {
            listed.id == entry.id
                && listed.path == entry.path
                && listed.etag == entry.etag
                && listed.size == entry.size
                && !listed.encrypted
        }) {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "file changed while its availability policy was being updated",
            ));
        }
        if policy == AvailabilityPolicy::AlwaysOffline {
            let _snapshot = self.fetch_snapshot(space, path)?;
            let version = ContentVersion {
                resource_id: entry.id.clone(),
                etag: entry.etag.clone(),
                protection: ContentProtection::Plaintext,
            };
            context
                .cache
                .content_record(&scope, &version)
                .map_err(cache_cloud_error)?;
        }
        context
            .cache
            .set_policy_at(&scope, &entry.id, &entry.path, &entry.etag, policy)
            .map_err(cache_cloud_error)
    }

    /// Read the policy for a freshly verified ordinary file path.
    pub fn availability_policy(
        &self,
        space: &str,
        path: &str,
    ) -> Result<AvailabilityPolicy, CloudError> {
        self.availability_status(space, path)
            .map(|(policy, _)| policy)
    }

    /// Read policy and refresh state from one identity-checked metadata pass.
    pub fn availability_status(
        &self,
        space: &str,
        path: &str,
    ) -> Result<(AvailabilityPolicy, Option<TargetState>), CloudError> {
        let context = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(ErrorKind::Unsupported, "offline cache is unavailable")
        })?;
        let (scope, _) = self.online_plaintext_scope(space)?;
        let entry = self.backend.stat(space, path)?;
        if entry.encrypted || (entry.directory && !cfg!(unix)) {
            return Err(unsupported_encrypted_cache());
        }
        let policy = context
            .cache
            .policy(&scope, &entry.id)
            .map_err(cache_cloud_error)?;
        if entry.directory {
            return Ok((policy, None));
        }
        let state = context
            .cache
            .policy_target_state(&scope, &entry.id)
            .map_err(cache_cloud_error)?;
        Ok((policy, state))
    }

    /// Return the state of the exact stable resource's AlwaysOffline target.
    /// A missing policy has no refresh state; callers must not infer that a
    /// cache entry is protected merely because some Recent bytes exist.
    pub fn availability_state(
        &self,
        space: &str,
        path: &str,
    ) -> Result<Option<TargetState>, CloudError> {
        self.availability_status(space, path)
            .map(|(_, state)| state)
    }

    /// Read cache accounting without triggering eviction.
    pub fn offline_cache_usage(&self) -> Result<CacheUsage, CloudError> {
        let context = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(ErrorKind::Unsupported, "offline cache is unavailable")
        })?;
        context.cache.usage().map_err(cache_cloud_error)
    }

    /// Enumerate retained ordinary file edits for the active account entirely
    /// from the local journal, so the transfer view remains available offline.
    pub fn pending_file_writes(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<raiun_cache::PendingWritePage, CloudError> {
        let context = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Unsupported,
                "offline write journal is unavailable",
            )
        })?;
        context
            .cache
            .pending_write_page(&context.origin, &context.account_id, after, limit)
            .map_err(cache_cloud_error)
    }

    /// Return the current exact ordinary scope used for write-recovery
    /// manifests. With a cache this permits the existing offline scope only
    /// after a transport-offline error; without one, the Runtime-supplied
    /// account identity still binds online writes.
    pub fn ordinary_write_scope(&self, space_id: &str) -> Result<CacheScope, CloudError> {
        if self.vault_binding.is_some() {
            return Err(unsupported_encrypted_cache());
        }
        if let Some(context) = &self.offline_cache {
            return match self.online_plaintext_scope(space_id) {
                Ok((scope, _)) => Ok(scope),
                Err(error) if error.kind == ErrorKind::Offline => self
                    .cached_scope(space_id, context)
                    .map_err(cache_cloud_error),
                Err(error) => Err(error),
            };
        }
        let identity = self.account_scope.as_ref().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Unsupported,
                "authenticated account scope is unavailable",
            )
        })?;
        let space = self
            .backend
            .spaces()?
            .into_iter()
            .find(|space| space.id == space_id)
            .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "cloud Space was not found"))?;
        if space.encrypted {
            return Err(unsupported_encrypted_cache());
        }
        let root = self.backend.stat(space_id, "/")?;
        if root.encrypted || !root.directory || root.path != "/" {
            return Err(CloudError::new(
                ErrorKind::InvalidResponse,
                "cloud Space root identity is invalid for ordinary writes",
            ));
        }
        CacheScope::new(
            &identity.origin,
            &identity.account_id,
            space_id,
            &root.id,
            ScopeProtection::PlaintextAllowed,
        )
        .map_err(cache_cloud_error)
    }

    /// Save an edit to a previously cached regular file. The durable journal
    /// keeps the original ETag as its conditional base and stores the new
    /// bytes under a separate immutable version.
    pub fn queue_offline_file_write(
        &self,
        space: &str,
        path: &str,
        source: &Path,
        base: WriteCondition,
    ) -> Result<QueuedWrite, CloudError> {
        let _guard = self.execution()?;
        let _metadata = self.metadata_publication()?;
        let context = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Unsupported,
                "offline write journal is unavailable",
            )
        })?;
        let scope = match self.online_plaintext_scope(space) {
            Ok((scope, _)) => scope,
            Err(error) if error.kind == ErrorKind::Offline => self
                .cached_scope(space, context)
                .map_err(cache_cloud_error)?,
            Err(error) => return Err(error),
        };
        let metadata = fs::metadata(source).map_err(io_error)?;
        if !metadata.is_file() {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "offline edits require a regular local file",
            ));
        }
        let expected_len = metadata.len();
        let parent = parent_path(path)?;
        let existing = context
            .cache
            .pending_write_for_path(&scope, path)
            .map_err(cache_cloud_error)?;
        let (parent_id, resource_id) = if let Some(write) = &existing {
            if write.base != base {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "open file does not match the pending write base",
                ));
            }
            let resource_id = write.resource_id.clone().ok_or_else(|| {
                CloudError::new(
                    ErrorKind::Unsupported,
                    "offline file creation is not enabled",
                )
            })?;
            (write.parent_resource_id.clone(), resource_id)
        } else {
            let parent_id = context
                .cache
                .resource_id_for_path(&scope, &parent)
                .map_err(cache_cloud_error)?
                .ok_or_else(|| {
                    CloudError::new(ErrorKind::Offline, "cached parent is unavailable")
                })?;
            let cached = context
                .cache
                .entry_for_path(&scope, path)
                .map_err(cache_cloud_error)?
                .ok_or_else(|| CloudError::new(ErrorKind::Offline, "cached file is unavailable"))?;
            if cached.directory
                || cached.encrypted
                || !cached.writable
                || cached.path != path
                || !matches!(&base, WriteCondition::Match(etag) if etag == &cached.etag)
            {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "cached file identity, permission, or base version changed",
                ));
            }
            (parent_id, cached.id)
        };
        let request = ConditionalWriteRequest {
            parent_resource_id: parent_id,
            name: path.rsplit('/').next().unwrap_or_default().to_owned(),
            logical_path: path.to_owned(),
            resource_id: Some(resource_id),
            base,
            expected_len,
            protection: ContentProtection::Plaintext,
        };
        let mut input = File::open(source).map_err(io_error)?;
        let queued = if existing.is_some() {
            context
                .cache
                .replace_pending_conditional_write(&scope, request, &mut input)
        } else {
            context
                .cache
                .queue_conditional_write(&scope, request, &mut input)
        }
        .map_err(cache_cloud_error)?;
        Ok(queued)
    }

    /// Commit an online edit immediately when possible, otherwise durably
    /// queue it. If this path already has a journal record, updates remain
    /// conditional on its original ETag and are never implicitly rebased.
    pub fn commit_file_write(
        &self,
        space: &str,
        path: &str,
        source: &Path,
        base: WriteCondition,
    ) -> Result<FileWriteOutcome, CloudError> {
        if self.offline_cache.is_none() {
            return self
                .put(space, path, source, base)
                .map(FileWriteOutcome::Uploaded);
        }
        if let Some(write) = self.pending_write(space, path)? {
            if base != write.base {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "open file was based on a different pending-write version",
                ));
            }
            let updated = self.queue_offline_file_write(space, path, source, write.base.clone())?;
            if updated.state == WriteState::Conflict {
                return Ok(FileWriteOutcome::Queued(
                    self.remote_entry_for_pending(space, &updated)?,
                ));
            }
            return match self.reconcile_one_pending_write(space, updated.id) {
                Ok(entry) => Ok(FileWriteOutcome::Uploaded(entry)),
                Err(error) if error.kind == ErrorKind::Offline => Ok(FileWriteOutcome::Queued(
                    self.remote_entry_for_pending(space, &updated)?,
                )),
                Err(error) => Err(error),
            };
        }
        if matches!(&base, WriteCondition::Absent) {
            // The ordinary offline journal only supports edits to an existing
            // resource. An online create must still reach conditional PUT;
            // routing it through that journal rejects every uncached new file.
            // On transport failure the caller's FUSE spool/manifest remains
            // the recovery owner; never claim an offline create was queued.
            return self
                .put(space, path, source, base)
                .map(FileWriteOutcome::Uploaded);
        }
        let queued = self.queue_offline_file_write(space, path, source, base)?;
        match self.reconcile_one_pending_write(space, queued.id) {
            Ok(entry) => Ok(FileWriteOutcome::Uploaded(entry)),
            Err(error) if error.kind == ErrorKind::Offline => Ok(FileWriteOutcome::Queued(
                self.remote_entry_for_pending(space, &queued)?,
            )),
            Err(error) => Err(error),
        }
    }

    /// Commit a FUSE write only while the exact account/Space-root and remote
    /// file identities captured at open remain current. Offline fallback is
    /// allowed only when an ordinary cache scope proves the same root; the
    /// cache journal then retains the original resource and ETag conditions.
    pub fn commit_file_write_scoped(
        &self,
        space: &str,
        path: &str,
        source: &Path,
        base: WriteCondition,
        expected_scope: &CacheScope,
        expected_resource_id: Option<&str>,
    ) -> Result<FileWriteOutcome, CloudError> {
        let current_scope = self.ordinary_write_scope(space)?;
        if &current_scope != expected_scope {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "account or Space root changed since the file was opened; local bytes were preserved",
            ));
        }
        match self.backend.stat(space, path) {
            Ok(current) => {
                if current.encrypted
                    || current.directory
                    || Some(current.id.as_str()) != expected_resource_id
                    || matches!(&base, WriteCondition::Match(etag) if etag != &current.etag)
                    || matches!(&base, WriteCondition::Absent)
                {
                    return Err(CloudError::new(
                        ErrorKind::Conflict,
                        "remote file identity or base version changed; local bytes were preserved",
                    ));
                }
            }
            Err(error)
                if error.kind == ErrorKind::NotFound
                    && expected_resource_id.is_none()
                    && matches!(&base, WriteCondition::Absent) => {}
            Err(error) if error.kind == ErrorKind::Offline && self.offline_cache.is_some() => {}
            Err(error) => return Err(error),
        }
        if matches!(&base, WriteCondition::Absent)
            && (self.offline_cache.is_none() || self.pending_write(space, path)?.is_none())
        {
            let _guard = self.execution()?;
            return self
                .upload_inner_with_root(
                    None,
                    space,
                    path,
                    source,
                    base,
                    Some(expected_scope.root_resource_id()),
                )
                .map(FileWriteOutcome::Uploaded);
        }
        self.commit_file_write(space, path, source, base)
    }

    /// Attempt conditional reconciliation for every pending ordinary file
    /// write in one Space. Conflicts and bytes are retained; deletions are not
    /// inferred from missing or evicted content.
    pub fn reconcile_pending_file_writes(
        &self,
        space: &str,
    ) -> Result<WriteReconcileReport, CloudError> {
        self.reconcile_pending_file_writes_cancellable(space, usize::MAX, || false)
    }

    /// Reconcile at most `limit` pending writes, stopping between remote
    /// operations when the caller's profile generation, cancellation, or
    /// pause state changes. Unattempted and conflicted rows remain in the
    /// local journal and are counted in `remaining`.
    pub fn reconcile_pending_file_writes_cancellable(
        &self,
        space: &str,
        limit: usize,
        mut should_stop: impl FnMut() -> bool,
    ) -> Result<WriteReconcileReport, CloudError> {
        if limit == 0 {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "write reconciliation limit must be positive",
            ));
        }
        let context = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Unsupported,
                "offline write journal is unavailable",
            )
        })?;
        let scope = match self.online_plaintext_scope(space) {
            Ok((scope, _)) => scope,
            Err(error) => return Err(error),
        };
        let writes = context
            .cache
            .pending_writes(&scope)
            .map_err(cache_cloud_error)?;
        let mut report = WriteReconcileReport::default();
        let mut attempted = 0usize;
        for write in writes {
            if write.state == WriteState::Verified {
                continue;
            }
            if attempted >= limit || should_stop() {
                break;
            }
            // Already-conflicted writes require explicit user resolution and
            // must never be retried by automatic reconciliation.
            if write.state == WriteState::Conflict {
                report.conflicts = report.conflicts.saturating_add(1);
                continue;
            }
            attempted += 1;
            match self.reconcile_one_pending_write(space, write.id) {
                Ok(_) => report.uploaded = report.uploaded.saturating_add(1),
                Err(error) if error.kind == ErrorKind::Conflict => {
                    report.conflicts = report.conflicts.saturating_add(1)
                }
                Err(error) if error.kind == ErrorKind::Offline => {
                    break;
                }
                Err(error)
                    if error.kind == ErrorKind::Unsupported
                        && error.message.contains("Folder sync paused") =>
                {
                    break;
                }
                Err(error) => return Err(error),
            }
        }
        report.remaining = context
            .cache
            .pending_writes(&scope)
            .map_err(cache_cloud_error)?
            .into_iter()
            // Conflicts are reported separately and need explicit user
            // attention; `remaining` is the count of uploads still eligible
            // for a conditional retry.
            .filter(|write| write.state == WriteState::Pending)
            .count() as u64;
        Ok(report)
    }

    fn pending_write(&self, space: &str, path: &str) -> Result<Option<QueuedWrite>, CloudError> {
        let Some(context) = &self.offline_cache else {
            return Ok(None);
        };
        let scope = match self.online_plaintext_scope(space) {
            Ok((scope, _)) => scope,
            Err(error) if error.kind == ErrorKind::Offline => self
                .cached_scope(space, context)
                .map_err(cache_cloud_error)?,
            Err(error) => return Err(error),
        };
        context
            .cache
            .pending_write_for_path(&scope, path)
            .map_err(cache_cloud_error)
    }

    fn remote_entry_for_pending(
        &self,
        space: &str,
        write: &QueuedWrite,
    ) -> Result<RemoteEntry, CloudError> {
        let context = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(ErrorKind::Unsupported, "offline cache is unavailable")
        })?;
        let scope = match self.online_plaintext_scope(space) {
            Ok((scope, _)) => scope,
            Err(error) if error.kind == ErrorKind::Offline => self
                .cached_scope(space, context)
                .map_err(cache_cloud_error)?,
            Err(error) => return Err(error),
        };
        self.remote_entry_for_pending_in_scope(&scope, write)
    }

    fn remote_entry_for_pending_in_scope(
        &self,
        scope: &CacheScope,
        write: &QueuedWrite,
    ) -> Result<RemoteEntry, CloudError> {
        let context = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(ErrorKind::Unsupported, "offline cache is unavailable")
        })?;
        if write.content.protection != ContentProtection::Plaintext {
            return Err(unsupported_encrypted_cache());
        }
        let content = context
            .cache
            .content_record(scope, &write.content)
            .map_err(cache_cloud_error)?;
        Ok(RemoteEntry {
            id: write
                .resource_id
                .clone()
                .unwrap_or_else(|| write.content.resource_id.clone()),
            path: write.logical_path.clone(),
            directory: false,
            size: content.byte_len,
            etag: match &write.base {
                WriteCondition::Match(etag) => etag.clone(),
                WriteCondition::Absent => write.content.etag.clone(),
            },
            modified_unix: write.created_at_unix,
            writable: true,
            encrypted: false,
        })
    }

    fn reconcile_one_pending_write(
        &self,
        space: &str,
        write_id: i64,
    ) -> Result<RemoteEntry, CloudError> {
        let _guard = self.execution()?;
        self.check_sync_paused()?;
        let context = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Unsupported,
                "offline write journal is unavailable",
            )
        })?;
        let (scope, _) = self.online_plaintext_scope(space)?;
        let write = context
            .cache
            .pending_writes(&scope)
            .map_err(cache_cloud_error)?
            .into_iter()
            .find(|write| write.id == write_id)
            .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "pending write was not found"))?;
        if write.state == WriteState::Verified {
            return Err(CloudError::new(
                ErrorKind::NotFound,
                "pending write has already been verified",
            ));
        }
        if write.state == WriteState::Conflict {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "pending write is marked conflicted; user action is required",
            ));
        }
        if write.content.protection != ContentProtection::Plaintext {
            return Err(unsupported_encrypted_cache());
        }
        let current_scope = self.online_plaintext_scope(space)?.0;
        if current_scope != scope {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "cloud account or Space root changed; pending bytes were preserved",
            ));
        }
        let current = match self.backend.stat(space, &write.logical_path) {
            Ok(entry) => entry,
            Err(error) if error.kind == ErrorKind::NotFound => {
                context
                    .cache
                    .mark_write_conflict(&scope, write.id)
                    .map_err(cache_cloud_error)?;
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "remote file was removed; pending bytes were preserved",
                ));
            }
            Err(error) => return Err(error),
        };
        let expected_etag = match &write.base {
            WriteCondition::Match(etag) => etag.as_str(),
            WriteCondition::Absent => {
                context
                    .cache
                    .mark_write_conflict(&scope, write.id)
                    .map_err(cache_cloud_error)?;
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "offline creation is not enabled for this write journal",
                ));
            }
        };
        if current.id != write.resource_id.as_deref().unwrap_or_default()
            || current.encrypted
            || current.directory
            || !current.writable
            || current.etag != expected_etag
        {
            context
                .cache
                .mark_write_conflict(&scope, write.id)
                .map_err(cache_cloud_error)?;
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "remote identity, permissions, or base version changed; pending bytes were preserved",
            ));
        }
        let content = context
            .cache
            .open_content(&scope, &write.content)
            .map_err(cache_cloud_error)?;
        let staged = NamedTempFile::new_in(self.cache_dir()).map_err(io_error)?;
        let mut staged = staged;
        let mut input = content;
        std::io::copy(&mut input, staged.as_file_mut()).map_err(io_error)?;
        staged.as_file().sync_all().map_err(io_error)?;
        let staged_path = staged.path().to_path_buf();
        #[cfg(windows)]
        let _staged_path_owner = staged.into_temp_path();
        let uploaded = match self.upload_inner(
            None,
            space,
            &write.logical_path,
            &staged_path,
            write.base.clone(),
        ) {
            Ok(entry) => entry,
            Err(error) if error.kind == ErrorKind::Conflict => {
                context
                    .cache
                    .mark_write_conflict(&scope, write.id)
                    .map_err(cache_cloud_error)?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        let version = ContentVersion {
            resource_id: uploaded.id.clone(),
            etag: uploaded.etag.clone(),
            protection: ContentProtection::Plaintext,
        };
        let mut verified_bytes = File::open(&staged_path).map_err(io_error)?;
        context
            .cache
            .publish_content(
                &scope,
                &version,
                &mut verified_bytes,
                uploaded.size,
                Retention::Recent,
            )
            .map_err(cache_cloud_error)?;
        context
            .cache
            .mark_write_verified(&scope, write.id)
            .map_err(cache_cloud_error)?;
        Ok(uploaded)
    }

    /// Build a durable recursive pin from fresh online listings. The callback
    /// receives persisted counts after the manifest is committed and after
    /// each exact file version is verified. Failures leave a Building pin and
    /// already downloaded recent content intact for inspection or cancellation.
    pub fn pin_offline_tree<F>(
        &self,
        space: &str,
        path: &str,
        progress: F,
    ) -> Result<PinInfo, CloudError>
    where
        F: FnMut(PinInfo),
    {
        self.pin_offline_tree_cancellable(space, path, || false, progress)
    }

    /// As `pin_offline_tree`, with cooperative cancellation points between
    /// directory listings and verified file downloads. An in-flight blocking
    /// network request is allowed to finish before cancellation takes effect.
    pub fn pin_offline_tree_cancellable<F, C>(
        &self,
        space: &str,
        path: &str,
        mut cancelled: C,
        mut progress: F,
    ) -> Result<PinInfo, CloudError>
    where
        F: FnMut(PinInfo),
        C: FnMut() -> bool,
    {
        if cancelled() {
            return Err(CloudError::new(ErrorKind::Offline, "offline pin cancelled"));
        }
        let context = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(ErrorKind::Unsupported, "offline cache is unavailable")
        })?;
        let (scope, space_root) = self.online_plaintext_scope(space)?;
        if cancelled() {
            return Err(CloudError::new(ErrorKind::Offline, "offline pin cancelled"));
        }
        let selected = if path == "/" {
            space_root.clone()
        } else {
            self.backend.stat(space, path)?
        };
        if !selected.directory || selected.encrypted {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "offline folder availability requires an unencrypted directory",
            ));
        }
        let root_resource_id = selected.id.clone();
        if path != "/" {
            let parent = parent_path(path)?;
            let parent_entry = if parent == "/" {
                space_root.clone()
            } else {
                self.backend.stat(space, &parent)?
            };
            if !parent_entry.directory || parent_entry.encrypted {
                return Err(unsupported_encrypted_cache());
            }
            let _metadata = self.metadata_publication()?;
            let siblings = self.list_live(space, &parent)?;
            if !siblings.iter().any(|entry| {
                entry.id == selected.id
                    && entry.path == selected.path
                    && entry.etag == selected.etag
                    && entry.directory
                    && !entry.encrypted
            }) {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "folder changed while preparing offline availability",
                ));
            }
            context
                .cache
                .publish_listing(
                    &scope,
                    &parent_entry.id,
                    &siblings
                        .iter()
                        .filter(|entry| !entry.encrypted)
                        .cloned()
                        .map(|entry| CachedEntry {
                            parent_resource_id: parent_entry.id.clone(),
                            entry,
                        })
                        .collect::<Vec<_>>(),
                    now_unix(),
                )
                .map_err(cache_cloud_error)?;
        }
        let mut pending = vec![(path.to_owned(), root_resource_id.clone())];
        let mut manifest = Vec::new();
        let mut files = Vec::new();
        while let Some((directory_path, parent_id)) = pending.pop() {
            if cancelled() {
                return Err(CloudError::new(ErrorKind::Offline, "offline pin cancelled"));
            }
            let _metadata = self.metadata_publication()?;
            let entries = self.list_live(space, &directory_path)?;
            if entries.len() > MAX_LIST_ENTRIES
                || manifest.len().saturating_add(entries.len()) > MAX_LIST_ENTRIES
            {
                return Err(CloudError::new(
                    ErrorKind::Unsupported,
                    "offline folder manifest exceeds the 100,000-entry limit",
                ));
            }
            for entry in entries {
                if cancelled() {
                    return Err(CloudError::new(ErrorKind::Offline, "offline pin cancelled"));
                }
                if entry.encrypted || !is_direct_child_path(&directory_path, &entry.path) {
                    return Err(unsupported_encrypted_cache());
                }
                manifest.push(PinManifestEntry {
                    parent_resource_id: parent_id.clone(),
                    entry: entry.clone(),
                });
                if entry.directory {
                    pending.push((entry.path.clone(), entry.id.clone()));
                } else {
                    files.push(entry);
                }
            }
            context
                .cache
                .publish_listing(
                    &scope,
                    &parent_id,
                    &manifest
                        .iter()
                        .filter(|item| item.parent_resource_id == parent_id)
                        .cloned()
                        .map(|item| CachedEntry {
                            parent_resource_id: item.parent_resource_id,
                            entry: item.entry,
                        })
                        .collect::<Vec<_>>(),
                    now_unix(),
                )
                .map_err(cache_cloud_error)?;
        }
        if cancelled() {
            return Err(CloudError::new(ErrorKind::Offline, "offline pin cancelled"));
        }
        let pin = context
            .cache
            .begin_pin_at(&scope, &root_resource_id, path, &manifest)
            .map_err(cache_cloud_error)?;
        progress(pin.clone());
        for file_entry in files {
            if cancelled() {
                return Err(CloudError::new(ErrorKind::Offline, "offline pin cancelled"));
            }
            let (current_scope, _) = self.online_plaintext_scope(space)?;
            if current_scope != scope {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "cloud Space root changed while preparing offline availability",
                ));
            }
            let version = ContentVersion {
                resource_id: file_entry.id.clone(),
                etag: file_entry.etag.clone(),
                protection: ContentProtection::Plaintext,
            };
            let already_cached = context.cache.open_content(&scope, &version).is_ok();
            if !already_cached {
                let snapshot = self.fetch_snapshot(space, &file_entry.path)?;
                drop(snapshot);
                context
                    .cache
                    .open_content(&scope, &version)
                    .map_err(cache_cloud_error)?;
            }
            let current = context
                .cache
                .refresh_pin(&pin.id)
                .map_err(cache_cloud_error)?;
            progress(current);
        }
        let completed = context
            .cache
            .refresh_pin(&pin.id)
            .map_err(cache_cloud_error)?;
        let _ = context.cache.evict_recent(context.cache.quota_bytes());
        Ok(completed)
    }

    /// Refresh every persisted AlwaysOffline file and folder snapshot for one
    /// verified ordinary Space. Targets are resolved by stable resource ID,
    /// never by reusing whatever happens to occupy their previous path. A
    /// complete bounded traversal is required before a missing target becomes
    /// unavailable. Folder pins are rebuilt under a temporary ID and swapped
    /// only after the new full snapshot is ready.
    pub fn refresh_offline_availability_cancellable<C>(
        &self,
        space: &str,
        mut cancelled: C,
    ) -> Result<OfflineRefreshReport, CloudError>
    where
        C: FnMut() -> bool,
    {
        if cancelled() {
            return Err(CloudError::new(
                ErrorKind::Offline,
                "offline refresh cancelled",
            ));
        }
        let context = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(ErrorKind::Unsupported, "offline cache is unavailable")
        })?;
        let (scope, root) = self.online_plaintext_scope(space)?;
        let (policies, pins) = context
            .cache
            .refresh_targets(&scope)
            .map_err(cache_cloud_error)?;
        if policies.is_empty() && pins.is_empty() {
            return Ok(OfflineRefreshReport::default());
        }
        let tree = self.refresh_live_tree(space, &scope, &root, &mut cancelled)?;
        // Do not apply any target status if the account/root binding changed
        // while the bounded traversal was in progress.
        let (current_scope, _) = self.online_plaintext_scope(space)?;
        if current_scope != scope {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "cloud Space root changed during offline refresh",
            ));
        }
        let mut report = OfflineRefreshReport {
            folders_refreshed: tree.directories,
            ..OfflineRefreshReport::default()
        };
        for target in policies {
            if cancelled() {
                return Err(CloudError::new(
                    ErrorKind::Offline,
                    "offline refresh cancelled",
                ));
            }
            report.files_checked += 1;
            let Some((path, entry)) = tree.by_id.get(&target.resource_id) else {
                context
                    .cache
                    .mark_policy_unavailable(&scope, &target.resource_id)
                    .map_err(cache_cloud_error)?;
                report.unavailable += 1;
                continue;
            };
            if entry.directory || entry.encrypted {
                context
                    .cache
                    .set_policy_refresh_state(
                        &scope,
                        &target.resource_id,
                        &target.path,
                        &target.etag,
                        TargetState::Unavailable,
                    )
                    .map_err(cache_cloud_error)?;
                report.unavailable += 1;
                continue;
            }
            // Mark a new revision stale before fetching it so no offline read
            // can expose the old protected bytes if the transfer fails.
            if target.etag != entry.etag
                || target.path != *path
                || target.state != TargetState::Ready
            {
                context
                    .cache
                    .set_policy_refresh_state(
                        &scope,
                        &target.resource_id,
                        path,
                        &target.etag,
                        TargetState::Stale,
                    )
                    .map_err(cache_cloud_error)?;
            }
            let version = ContentVersion {
                resource_id: entry.id.clone(),
                etag: entry.etag.clone(),
                protection: ContentProtection::Plaintext,
            };
            let cached = context.cache.open_content(&scope, &version).is_ok();
            if !cached {
                // `fetch_snapshot` validates the live ID/ETag/size and
                // publishes this exact immutable version as Recent. The
                // policy row is promoted only after the cache verifies it.
                let _snapshot = self.fetch_snapshot(space, path)?;
                report.files_downloaded += 1;
                context
                    .cache
                    .open_content(&scope, &version)
                    .map_err(cache_cloud_error)?;
            }
            context
                .cache
                .set_policy_refresh_state(
                    &scope,
                    &target.resource_id,
                    path,
                    &entry.etag,
                    TargetState::Ready,
                )
                .map_err(cache_cloud_error)?;
        }
        for target in pins {
            if cancelled() {
                return Err(CloudError::new(
                    ErrorKind::Offline,
                    "offline refresh cancelled",
                ));
            }
            let Some((path, entry)) = tree.by_id.get(&target.root_resource_id) else {
                context
                    .cache
                    .set_pin_refresh_target(
                        &scope,
                        &target.pin_id,
                        &target.root_resource_id,
                        &target.path,
                        PinState::Unavailable,
                    )
                    .map_err(cache_cloud_error)?;
                report.unavailable += 1;
                continue;
            };
            if !entry.directory || entry.encrypted {
                context
                    .cache
                    .set_pin_refresh_target(
                        &scope,
                        &target.pin_id,
                        &target.root_resource_id,
                        path,
                        PinState::Unavailable,
                    )
                    .map_err(cache_cloud_error)?;
                report.unavailable += 1;
                continue;
            }
            context
                .cache
                .set_pin_refresh_target(
                    &scope,
                    &target.pin_id,
                    &target.root_resource_id,
                    path,
                    PinState::Stale,
                )
                .map_err(cache_cloud_error)?;
            let mut staging_id = None;
            let staged = self.pin_offline_tree_cancellable(space, path, &mut cancelled, |info| {
                staging_id = Some(info.id.clone())
            });
            match staged {
                Ok(info) => {
                    if cancelled() {
                        let _ = context.cache.cancel_pin_for_scope(&scope, &info.id);
                        return Err(CloudError::new(
                            ErrorKind::Offline,
                            "offline refresh cancelled",
                        ));
                    }
                    let (live_scope, live_root) = self.online_plaintext_scope(space)?;
                    if live_scope != scope || live_root.id != scope.root_resource_id() {
                        let _ = context.cache.cancel_pin_for_scope(&scope, &info.id);
                        return Err(CloudError::new(
                            ErrorKind::Conflict,
                            "cloud Space root changed during pin refresh",
                        ));
                    }
                    context
                        .cache
                        .replace_pin_snapshot(&scope, &target.pin_id, &info.id)
                        .map_err(cache_cloud_error)?;
                }
                Err(error) => {
                    if let Some(id) = staging_id {
                        let _ = context.cache.cancel_pin_for_scope(&scope, &id);
                    }
                    return Err(error);
                }
            }
        }
        let _ = context.cache.evict_recent(context.cache.quota_bytes());
        Ok(report)
    }

    fn refresh_live_tree<C>(
        &self,
        space: &str,
        scope: &CacheScope,
        root: &RemoteEntry,
        cancelled: &mut C,
    ) -> Result<RefreshTree, CloudError>
    where
        C: FnMut() -> bool,
    {
        if root.id != scope.root_resource_id()
            || root.path != "/"
            || !root.directory
            || root.encrypted
        {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "cloud Space root identity changed",
            ));
        }
        let context = self.offline_cache.as_ref().expect("refresh requires cache");
        let mut tree = RefreshTree::default();
        tree.by_id
            .insert(root.id.clone(), ("/".into(), root.clone()));
        let mut pending = vec![("/".to_owned(), root.id.clone(), 0usize)];
        let mut total_entries = 0usize;
        let mut path_bytes = 1usize;
        while let Some((parent_path, parent_id, depth)) = pending.pop() {
            if cancelled() {
                return Err(CloudError::new(
                    ErrorKind::Offline,
                    "offline refresh cancelled",
                ));
            }
            if depth > MAX_REFRESH_DEPTH {
                return Err(CloudError::new(
                    ErrorKind::Unsupported,
                    "offline refresh exceeds the directory-depth limit",
                ));
            }
            let _metadata = self.metadata_publication()?;
            let entries = self.list_live(space, &parent_path)?;
            total_entries = total_entries.saturating_add(entries.len());
            if total_entries > MAX_LIST_ENTRIES {
                return Err(CloudError::new(
                    ErrorKind::Unsupported,
                    "offline refresh exceeds the 100,000-entry limit",
                ));
            }
            let mut cache_entries = Vec::with_capacity(entries.len());
            for entry in entries {
                if cancelled() {
                    return Err(CloudError::new(
                        ErrorKind::Offline,
                        "offline refresh cancelled",
                    ));
                }
                // The ordinary cache intentionally omits encrypted entries.
                // They are outside this refresh's plaintext authority and
                // must never block or be copied into an ordinary snapshot.
                if entry.encrypted {
                    continue;
                }
                if !is_direct_child_path(&parent_path, &entry.path) {
                    return Err(unsupported_encrypted_cache());
                }
                path_bytes = path_bytes
                    .saturating_add(entry.id.len())
                    .saturating_add(entry.etag.len())
                    .saturating_add(entry.path.len());
                if path_bytes > MAX_REFRESH_PATH_BYTES {
                    return Err(CloudError::new(
                        ErrorKind::Unsupported,
                        "offline refresh exceeds the metadata-size limit",
                    ));
                }
                if tree
                    .by_id
                    .insert(entry.id.clone(), (entry.path.clone(), entry.clone()))
                    .is_some()
                {
                    return Err(CloudError::new(
                        ErrorKind::InvalidResponse,
                        "cloud returned a duplicate resource identity",
                    ));
                }
                if entry.directory {
                    pending.push((entry.path.clone(), entry.id.clone(), depth + 1));
                }
                cache_entries.push(CachedEntry {
                    parent_resource_id: parent_id.clone(),
                    entry,
                });
            }
            context
                .cache
                .publish_listing(scope, &parent_id, &cache_entries, now_unix())
                .map_err(cache_cloud_error)?;
            tree.directories += 1;
        }
        Ok(tree)
    }

    /// Read persisted pin progress scoped to this profile and Space. This does
    /// not touch the network and verifies the pin manifest before reporting.
    pub fn offline_pin_status(&self, space: &str, pin_id: &str) -> Result<PinInfo, CloudError> {
        let context = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(ErrorKind::Unsupported, "offline cache is unavailable")
        })?;
        let scope = self
            .cached_scope(space, context)
            .map_err(cache_cloud_error)?;
        context
            .cache
            .pin_info_for_scope(&scope, pin_id)
            .map_err(cache_cloud_error)
    }

    /// Read historical pin metadata for an explicit recovery view. This never
    /// becomes a complete/current listing and grants no write or delete authority.
    pub fn offline_pin_recovery_manifest(
        &self,
        space: &str,
        pin_id: &str,
    ) -> Result<raiun_cache::RetainedPinManifest, CloudError> {
        let (context, scope) = self.offline_recovery_context(space)?;
        context
            .cache
            .retained_pin_manifest(&scope, pin_id)
            .map_err(cache_cloud_error)
    }

    /// Bounded historical snapshot roots; this is not a current cloud listing.
    pub fn offline_pin_recovery_catalog(
        &self,
        space: &str,
    ) -> Result<Vec<raiun_cache::RetainedPinSummary>, CloudError> {
        let (context, scope) = self.offline_recovery_context(space)?;
        context
            .cache
            .retained_pin_catalog(&scope)
            .map_err(cache_cloud_error)
    }

    fn offline_recovery_context(
        &self,
        space: &str,
    ) -> Result<(&OfflineCache, CacheScope), CloudError> {
        self.validate_offline_namespace_binding()?;
        let context = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(ErrorKind::Unsupported, "offline cache is unavailable")
        })?;
        let account = self
            .account_scope
            .as_ref()
            .expect("validated account scope");
        if context.account_id != account.account_id {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "recovery cache belongs to another account",
            ));
        }
        let scope = self
            .cached_scope(space, context)
            .map_err(cache_cloud_error)?;
        if scope.origin() != account.origin {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "recovery cache belongs to another server",
            ));
        }
        Ok((context, scope))
    }

    /// Open one exact retained pin member for read-only recovery. The caller
    /// must retain its account/root revocation lease for the reader lifetime.
    /// This never resolves the historical path through live stat or fetch.
    pub fn open_offline_pin_recovery_content(
        &self,
        space: &str,
        pin_id: &str,
        expected: &PinManifestEntry,
    ) -> Result<raiun_cache::CacheContentReader, CloudError> {
        let manifest = self.offline_pin_recovery_manifest(space, pin_id)?;
        if expected.entry.directory
            || expected.entry.encrypted
            || expected.entry.writable
            || !manifest.entries.iter().any(|entry| entry == expected)
        {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "retained pin member changed",
            ));
        }
        let context = self
            .offline_cache
            .as_ref()
            .expect("validated recovery cache");
        let scope = self
            .cached_scope(space, context)
            .map_err(cache_cloud_error)?;
        let reader = context
            .cache
            .open_content(
                &scope,
                &ContentVersion {
                    resource_id: expected.entry.id.clone(),
                    etag: expected.entry.etag.clone(),
                    protection: ContentProtection::Plaintext,
                },
            )
            .map_err(cache_cloud_error)?;
        if reader
            .metadata()
            .map_err(|_| {
                CloudError::new(ErrorKind::Io, "retained content metadata is unavailable")
            })?
            .len()
            != expected.entry.size
        {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "retained content length changed",
            ));
        }
        // Content verification may take time. Recheck exact membership/state
        // afterward so a replaced or removed pin cannot retarget this open.
        if self.offline_pin_recovery_manifest(space, pin_id)? != manifest {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "retained pin changed during open",
            ));
        }
        Ok(reader)
    }

    /// List persisted pin manifests for a Space without network access.
    pub fn offline_pins(&self, space: &str) -> Result<Vec<PinInfo>, CloudError> {
        let context = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(ErrorKind::Unsupported, "offline cache is unavailable")
        })?;
        let scope = self
            .cached_scope(space, context)
            .map_err(cache_cloud_error)?;
        context.cache.pins(&scope).map_err(cache_cloud_error)
    }

    /// Cancel a pin for this profile/Space only. Cached Recent content remains
    /// eligible for ordinary quota eviction; pinned or dirty data is not
    /// deleted as a side effect of cancellation.
    pub fn cancel_offline_pin(&self, space: &str, pin_id: &str) -> Result<(), CloudError> {
        let context = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(ErrorKind::Unsupported, "offline cache is unavailable")
        })?;
        let scope = self
            .cached_scope(space, context)
            .map_err(cache_cloud_error)?;
        context
            .cache
            .cancel_pin_for_scope(&scope, pin_id)
            .map_err(cache_cloud_error)
    }

    fn list_live(&self, space: &str, path: &str) -> Result<Vec<RemoteEntry>, CloudError> {
        let mut entries = Vec::new();
        let mut metadata_bytes = 0usize;
        self.backend.list(space, path, &mut |entry| {
            if entries.len() >= MAX_LIST_ENTRIES {
                return Err(CloudError::new(
                    ErrorKind::InvalidResponse,
                    "cloud listing exceeds the 100,000-entry limit",
                ));
            }
            metadata_bytes = metadata_bytes
                .saturating_add(entry.id.len())
                .saturating_add(entry.etag.len())
                .saturating_add(entry.path.len());
            if metadata_bytes > MAX_REFRESH_PATH_BYTES {
                return Err(CloudError::new(
                    ErrorKind::InvalidResponse,
                    "cloud listing metadata exceeds the 32 MiB limit",
                ));
            }
            entries.push(entry);
            Ok(())
        })?;
        Ok(entries)
    }

    /// Download one file into the engine cache, checking both its advertised
    /// size and revision before atomically publishing the cache path.
    pub fn fetch(&self, space: &str, path: &str) -> Result<PathBuf, CloudError> {
        let _guard = self.execution()?;
        let record = self.begin_transfer(None, space, path, "download")?;
        let result = self.fetch_inner(space, path);
        match result {
            Ok((dest, bytes)) => {
                self.finish_transfer(record, "completed", bytes, None)?;
                Ok(dest)
            }
            Err(error) => {
                self.finish_transfer(record, "failed", 0, Some(&error.message))?;
                Err(error)
            }
        }
    }

    /// Fetch and verify one file into an owned temporary snapshot. Unlike
    /// `fetch`, this does not leave a persistent cache entry; the bytes remain
    /// available through the returned handle until it is dropped.
    pub fn fetch_snapshot(&self, space: &str, path: &str) -> Result<FetchSnapshot, CloudError> {
        let _guard = self.execution()?;
        let record = self.begin_transfer(None, space, path, "download")?;
        let result = if self.offline_cache.is_some() {
            self.fetch_snapshot_cached(space, path)
        } else {
            (|| {
                let before = self.backend.stat(space, path)?;
                if before.directory {
                    return Err(CloudError::new(
                        ErrorKind::Unsupported,
                        "cannot fetch a directory as a file",
                    ));
                }
                let snapshot = NamedTempFile::new_in(self.cache_dir()).map_err(io_error)?;
                let (snapshot, entry) = download_to_named_temp(
                    self.backend.as_ref(),
                    space,
                    path,
                    Some(&before.etag),
                    snapshot,
                )?;
                let size = snapshot.as_file().metadata().map_err(io_error)?.len();
                if entry.etag != before.etag || size != entry.size || size != before.size {
                    return Err(CloudError::new(
                        ErrorKind::InvalidResponse,
                        "download revision or size failed verification",
                    ));
                }
                snapshot.as_file().sync_all().map_err(io_error)?;
                let mut file = snapshot.reopen().map_err(io_error)?;
                file.seek(SeekFrom::Start(0)).map_err(io_error)?;
                Ok((
                    FetchSnapshot {
                        _temp: Some(snapshot),
                        file: SnapshotReader::Download(file),
                    },
                    size,
                ))
            })()
        };
        match result {
            Ok((snapshot, bytes)) => {
                self.finish_transfer(record, "completed", bytes, None)?;
                Ok(snapshot)
            }
            Err(error) => {
                self.finish_transfer(record, "failed", 0, Some(&error.message))?;
                Err(error)
            }
        }
    }

    fn fetch_snapshot_cached(
        &self,
        space: &str,
        path: &str,
    ) -> Result<(FetchSnapshot, u64), CloudError> {
        let context = self
            .offline_cache
            .as_ref()
            .expect("cached snapshot requires a cache context");
        let (scope, online_root) = match self.online_plaintext_scope(space) {
            Ok(result) => result,
            Err(error) if error.kind == ErrorKind::Offline => {
                let scope = self
                    .cached_scope(space, context)
                    .map_err(|cache_error| offline_cache_error(cache_error, error.clone()))?;
                if let Some(write) = context
                    .cache
                    .pending_write_for_path(&scope, path)
                    .map_err(cache_cloud_error)?
                {
                    let mut file = context
                        .cache
                        .open_content(&scope, &write.content)
                        .map_err(cache_cloud_error)?;
                    let bytes = file.metadata().map_err(io_error)?.len();
                    file.seek(SeekFrom::Start(0)).map_err(io_error)?;
                    return Ok((
                        FetchSnapshot {
                            _temp: None,
                            file: SnapshotReader::Cached(file),
                        },
                        bytes,
                    ));
                }
                let entry = self.cached_entry_or_error(context, &scope, path, error.clone())?;
                let size = entry.size;
                return self
                    .open_cached_snapshot(context, &scope, &entry, error)
                    .map(|snapshot| (snapshot, size));
            }
            Err(error) => return Err(error),
        };
        if path != "/" {
            if let Some(write) = context
                .cache
                .pending_write_for_path(&scope, path)
                .map_err(cache_cloud_error)?
            {
                let mut file = context
                    .cache
                    .open_content(&scope, &write.content)
                    .map_err(cache_cloud_error)?;
                let bytes = file.metadata().map_err(io_error)?.len();
                file.seek(SeekFrom::Start(0)).map_err(io_error)?;
                return Ok((
                    FetchSnapshot {
                        _temp: None,
                        file: SnapshotReader::Cached(file),
                    },
                    bytes,
                ));
            }
        }
        let before = if path == "/" {
            online_root
        } else {
            match self.backend.stat(space, path) {
                Ok(entry) => entry,
                Err(error) if error.kind == ErrorKind::Offline => {
                    let entry = self.cached_entry_or_error(context, &scope, path, error.clone())?;
                    let size = entry.size;
                    return self
                        .open_cached_snapshot(context, &scope, &entry, error)
                        .map(|snapshot| (snapshot, size));
                }
                Err(error) => return Err(error),
            }
        };
        if before.directory {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "cannot fetch a directory as a file",
            ));
        }
        if before.encrypted {
            return Err(unsupported_encrypted_cache());
        }
        let downloaded = (|| {
            let snapshot = NamedTempFile::new_in(self.cache_dir()).map_err(io_error)?;
            let (snapshot, entry) = download_to_named_temp(
                self.backend.as_ref(),
                space,
                path,
                Some(&before.etag),
                snapshot,
            )?;
            let size = snapshot.as_file().metadata().map_err(io_error)?.len();
            if entry.directory
                || entry.encrypted
                || entry.id != before.id
                || entry.etag != before.etag
                || size != entry.size
                || size != before.size
            {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "download revision, identity, or size failed verification",
                ));
            }
            snapshot.as_file().sync_all().map_err(io_error)?;
            if let Ok(mut source) = snapshot.reopen() {
                let version = ContentVersion {
                    resource_id: before.id.clone(),
                    etag: before.etag.clone(),
                    protection: ContentProtection::Plaintext,
                };
                if context
                    .cache
                    .publish_content(&scope, &version, &mut source, size, Retention::Recent)
                    .is_ok()
                {
                    let _ = context.cache.evict_recent(context.cache.quota_bytes());
                }
            }
            let mut file = snapshot.reopen().map_err(io_error)?;
            file.seek(SeekFrom::Start(0)).map_err(io_error)?;
            Ok((
                FetchSnapshot {
                    _temp: Some(snapshot),
                    file: SnapshotReader::Download(file),
                },
                size,
            ))
        })();
        match downloaded {
            Err(error) if error.kind == ErrorKind::Offline => {
                let size = before.size;
                self.open_cached_snapshot(context, &scope, &before, error)
                    .map(|snapshot| (snapshot, size))
            }
            result => result,
        }
    }

    fn open_cached_snapshot(
        &self,
        context: &OfflineCache,
        scope: &CacheScope,
        entry: &RemoteEntry,
        offline: CloudError,
    ) -> Result<FetchSnapshot, CloudError> {
        if entry.directory || entry.encrypted {
            return Err(unsupported_encrypted_cache());
        }
        let version = ContentVersion {
            resource_id: entry.id.clone(),
            etag: entry.etag.clone(),
            protection: ContentProtection::Plaintext,
        };
        let mut file = context
            .cache
            .open_content(scope, &version)
            .map_err(|error| offline_cache_error(error, offline))?;
        if file.metadata().map_err(io_error)?.len() != entry.size {
            return Err(CloudError::new(
                ErrorKind::InvalidResponse,
                "cached file version does not match its metadata size",
            ));
        }
        file.seek(SeekFrom::Start(0)).map_err(io_error)?;
        Ok(FetchSnapshot {
            _temp: None,
            file: SnapshotReader::Cached(file),
        })
    }

    pub fn put(
        &self,
        space: &str,
        path: &str,
        source: &Path,
        condition: WriteCondition,
    ) -> Result<RemoteEntry, CloudError> {
        let _guard = self.execution()?;
        self.upload_inner(None, space, path, source, condition)
    }

    pub fn mkdir(&self, space: &str, path: &str) -> Result<RemoteEntry, CloudError> {
        let _guard = self.execution()?;
        let _metadata = self.metadata_publication()?;
        let cache_mutation = self.begin_cache_mutation(space, &[path])?;
        let id = self.begin_transfer(None, space, path, "mkdir")?;
        match self.backend.mkdir(space, path) {
            Ok(entry) => match self.backend.stat(space, path) {
                Ok(verified) if verified.directory && verified.etag == entry.etag => {
                    self.finish_cache_mutation(space, cache_mutation);
                    self.finish_transfer(id, "completed", 0, None)?;
                    Ok(verified)
                }
                Ok(_) => {
                    let error = CloudError::new(
                        ErrorKind::InvalidResponse,
                        "created directory could not be verified",
                    );
                    self.finish_transfer(id, "failed", 0, Some(&error.message))?;
                    Err(error)
                }
                Err(error) => {
                    self.finish_transfer(id, "failed", 0, Some(&error.message))?;
                    Err(error)
                }
            },
            Err(error) => {
                self.finish_transfer(id, "failed", 0, Some(&error.message))?;
                Err(error)
            }
        }
    }

    pub fn delete(&self, space: &str, path: &str, expected_etag: &str) -> Result<(), CloudError> {
        // Slash-only aliases resolve to the same DAV root. Reject them before
        // cache invalidation or any backend operation, even for direct callers.
        if path.is_empty() || path.bytes().all(|byte| byte == b'/') {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "cannot delete a cloud Space root",
            ));
        }
        let _guard = self.execution()?;
        let _metadata = self.metadata_publication()?;
        let cache_mutation = self.begin_cache_mutation(space, &[path])?;
        let id = self.begin_transfer(None, space, path, "delete")?;
        match self.backend.delete(space, path, expected_etag) {
            Ok(()) => match self.backend.stat(space, path) {
                Err(error) if error.kind == ErrorKind::NotFound => {
                    self.finish_cache_mutation(space, cache_mutation);
                    self.finish_transfer(id, "completed", 0, None)?;
                    Ok(())
                }
                Ok(_) => {
                    let error = CloudError::new(
                        ErrorKind::InvalidResponse,
                        "deleted item is still present",
                    );
                    self.finish_transfer(id, "failed", 0, Some(&error.message))?;
                    Err(error)
                }
                Err(error) => {
                    self.finish_transfer(id, "failed", 0, Some(&error.message))?;
                    Err(error)
                }
            },
            Err(error) => {
                self.finish_transfer(id, "failed", 0, Some(&error.message))?;
                Err(error)
            }
        }
    }

    pub fn rename(
        &self,
        space: &str,
        from: &str,
        to: &str,
        expected_etag: &str,
    ) -> Result<RemoteEntry, CloudError> {
        let _guard = self.execution()?;
        let _metadata = self.metadata_publication()?;
        // FUSE may retire its spool after transferring ownership to the
        // durable write journal. A move must protect those edits as well.
        if let Some(context) = &self.offline_cache {
            let (scope, _) = self.online_plaintext_scope(space)?;
            let writes = context
                .cache
                .pending_writes(&scope)
                .map_err(cache_cloud_error)?;
            if writes.iter().any(|write| {
                write.state != WriteState::Verified
                    && [from, to].iter().any(|target| {
                        let path = write.logical_path.as_str();
                        path == *target
                            || *target == "/"
                            || path == "/"
                            || path
                                .strip_prefix(target)
                                .is_some_and(|suffix| suffix.starts_with('/'))
                            || target
                                .strip_prefix(path)
                                .is_some_and(|suffix| suffix.starts_with('/'))
                    })
            }) {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "rename subtree has pending local journal edits; local bytes were preserved",
                ));
            }
        }
        let cache_mutation = self.begin_cache_mutation(space, &[from, to])?;
        let id = self.begin_transfer(None, space, from, "rename")?;
        match self.backend.rename(space, from, to, expected_etag) {
            Ok(entry) => match self.backend.stat(space, to) {
                Ok(verified) if verified.etag == entry.etag => {
                    self.finish_cache_mutation(space, cache_mutation);
                    self.finish_transfer(id, "completed", 0, None)?;
                    Ok(verified)
                }
                Ok(_) => {
                    let error = CloudError::new(
                        ErrorKind::InvalidResponse,
                        "renamed item could not be verified",
                    );
                    self.finish_transfer(id, "failed", 0, Some(&error.message))?;
                    Err(error)
                }
                Err(error) => {
                    self.finish_transfer(id, "failed", 0, Some(&error.message))?;
                    Err(error)
                }
            },
            Err(error) => {
                self.finish_transfer(id, "failed", 0, Some(&error.message))?;
                Err(error)
            }
        }
    }

    pub fn transfers(&self, limit: usize) -> Result<Vec<TransferRecord>, CloudError> {
        let db = self.db()?;
        let mut statement = db.prepare("SELECT id,pair_id,space_id,path,operation,status,bytes,message,COALESCE(finished_unix,created_unix) FROM transfers ORDER BY id DESC LIMIT ?1").map_err(db_error)?;
        let rows = statement
            .query_map([limit.min(i64::MAX as usize) as i64], |row| {
                let pair_id: Option<String> = row.get(1)?;
                let operation: String = row.get(4)?;
                let bytes = row.get::<_, i64>(6)?.max(0) as u64;
                Ok(TransferRecord {
                    id: row.get(0)?,
                    origin: if pair_id.is_some() {
                        "folder_pair"
                    } else {
                        "provider"
                    }
                    .into(),
                    space_id: row.get(2)?,
                    path: row.get(3)?,
                    direction: match operation.as_str() {
                        "upload" | "mkdir" => "upload",
                        "download" | "conflict_backup" => "download",
                        _ => "cloud",
                    }
                    .into(),
                    state: row.get(5)?,
                    bytes_total: bytes,
                    bytes_done: bytes,
                    error: row.get(7)?,
                    updated_at: row.get(8)?,
                })
            })
            .map_err(db_error)?;
        rows.map(|r| r.map_err(db_error)).collect()
    }

    /// Return a bounded page of current file conflicts for a pair. `after` is
    /// the last path from the previous page, or `None` for the first page.
    /// The listing rescans both sides so the returned ETag and local hash are
    /// fresh preconditions suitable for `resolve_conflict`.
    pub fn conflicts(
        &self,
        pair: &FolderPair,
        after: Option<&str>,
        limit: usize,
    ) -> Result<ConflictPage, CloudError> {
        let _guard = self.execution()?;
        self.validate_backend_binding(pair)?;
        validate_pair_runtime(pair)?;
        #[cfg(windows)]
        let _root_pin = raiun_control_windows::PinnedDirectory::open(Path::new(&pair.local_path))
            .map_err(io_error)?;
        self.check_pair_policy(pair)?;
        let pair = self.normalize_pair_root(pair)?;
        self.clear_stage(&pair.id)?;
        let mut scanned_entries = 0;
        self.scan_local(&pair, &mut scanned_entries, true, None)?;
        self.scan_remote_for_conflicts(&pair, &mut scanned_entries)?;

        let limit = limit.clamp(1, 1000);
        let mut page = ConflictPage::default();
        let mut cursor = after.map(str::to_owned);
        loop {
            let paths = self.staged_path_batch(&pair.id, cursor.as_deref())?;
            if paths.is_empty() {
                break;
            }
            cursor = paths.last().cloned();
            for rel in paths {
                if let (Some(local), Some(remote)) = (
                    self.local_stage(&pair.id, &rel)?,
                    self.remote_stage(&pair.id, &rel)?,
                ) {
                    if local.directory || remote.directory {
                        continue;
                    }
                    if pair.excludes_file_path(&rel) {
                        continue;
                    }
                    if remote.encrypted {
                        continue;
                    }
                    let remote_hash = if self.conflict_needs_content_compare(
                        &pair,
                        &rel,
                        &local.hash,
                        &remote,
                    )? {
                        Some(hash_for_remote(self, &pair.space_id, &remote.path)?)
                    } else {
                        None
                    };
                    if self.is_conflict_state(
                        &pair,
                        &rel,
                        &local.hash,
                        &remote,
                        remote_hash.as_deref(),
                    )? {
                        if page.items.len() == limit {
                            page.next_after = page.items.last().map(|item| item.path.clone());
                            return Ok(page);
                        }
                        page.items.push(FileConflict {
                            pair_id: pair.id.clone(),
                            path: rel,
                            local_hash: local.hash,
                            remote_etag: remote.etag,
                        });
                    }
                }
            }
        }
        Ok(page)
    }

    /// Resolve one current file conflict with an explicit side choice. The
    /// caller must pass the exact local hash and remote ETag from the conflict
    /// page; stale preconditions fail without advancing the baseline.
    pub fn resolve_conflict(
        &self,
        pair: &FolderPair,
        rel: &str,
        choice: ConflictChoice,
        expected_local_hash: &str,
        expected_remote_etag: &str,
    ) -> Result<ConflictResolution, CloudError> {
        let _guard = self.execution()?;
        self.validate_backend_binding(pair)?;
        validate_pair_runtime(pair)?;
        self.check_pair_policy(pair)?;
        let pair = self.normalize_pair_root(pair)?;
        validate_conflict_path(rel)?;
        if pair.excludes_file_path(rel) {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "excluded paths cannot be resolved through the folder conflict action",
            ));
        }
        match (choice, pair.mode) {
            (ConflictChoice::KeepLocal, SyncMode::DownloadOnly)
            | (ConflictChoice::KeepRemote, SyncMode::UploadOnly) => {
                return Err(CloudError::new(
                    ErrorKind::Unsupported,
                    "the selected conflict choice is disabled by this folder pair's sync mode",
                ));
            }
            _ => {}
        }

        let local_path = pair.local_path.join(rel);
        ensure_safe_pair_path(&pair.local_path, &local_path, false)?;
        let local_hash = hash_file(&local_path)?;
        if local_hash != expected_local_hash {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "local file changed since the conflict was listed; refresh conflicts and retry",
            ));
        }
        let remote_path = join_remote(&pair.remote_path, rel);
        let remote = self.backend.stat(&pair.space_id, &remote_path)?;
        if remote.directory || remote.etag != expected_remote_etag {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "remote file changed since the conflict was listed; refresh conflicts and retry",
            ));
        }
        if remote.encrypted {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "conflicts in encrypted remote areas cannot be resolved by the engine",
            ));
        }
        if choice == ConflictChoice::KeepLocal && !remote.writable {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "remote file is read-only; choose the remote version",
            ));
        }
        let remote_hash = hash_for_remote(self, &pair.space_id, &remote.path)?;
        if !self.is_conflict_state(&pair, rel, &local_hash, &remote, Some(&remote_hash))? {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "file is no longer in conflict; sync or refresh conflicts before resolving",
            ));
        }

        let recovery_path = match choice {
            ConflictChoice::KeepLocal => {
                let recovery = preserve_remote_version(
                    self,
                    &pair.id,
                    &local_path,
                    &pair.space_id,
                    &remote.path,
                    &remote,
                    &remote_hash,
                )?;
                let snapshot =
                    snapshot_local_file(&local_path, expected_local_hash, self.cache_dir())?;
                let snapshot_path = snapshot.path().to_path_buf();
                #[cfg(windows)]
                let _snapshot_path_owner = snapshot.into_temp_path();
                let uploaded = self.upload_inner(
                    Some(&pair.id),
                    &pair.space_id,
                    &remote.path,
                    &snapshot_path,
                    WriteCondition::Match(expected_remote_etag.to_owned()),
                )?;
                // Do not bless the uploaded snapshot if the live local file
                // changed while the network request was in progress. The next
                // sync will compare it with the old baseline and retain it.
                if hash_file(&local_path)? != expected_local_hash {
                    return Err(CloudError::new(
                        ErrorKind::Conflict,
                        format!(
                            "local file changed during conflict resolution; remote content was updated, recovery copy kept at {}",
                            recovery.display()
                        ),
                    ));
                }
                let metadata = fs::metadata(&local_path).map_err(io_error)?;
                let local = LocalEntry {
                    path: local_path.clone(),
                    size: metadata.len(),
                    mtime: modified_unix(&metadata),
                    hash: expected_local_hash.to_owned(),
                    directory: false,
                    fingerprint: None,
                };
                self.save_baseline(&pair.id, rel, &local, &uploaded, Some(expected_local_hash))?;
                recovery
            }
            ConflictChoice::KeepRemote => {
                let recovery =
                    preserve_local_version(&pair.local_path, &local_path, expected_local_hash)?;
                let parent = local_path.parent().ok_or_else(|| {
                    CloudError::new(ErrorKind::Io, "local destination has no parent folder")
                })?;
                let transfer =
                    self.begin_transfer(Some(&pair.id), &pair.space_id, &remote.path, "download")?;
                let staged = match download_to_temp(
                    &self.backend,
                    &pair.space_id,
                    &remote.path,
                    &remote,
                    parent,
                ) {
                    Ok(staged) => staged,
                    Err(error) => {
                        self.finish_transfer(transfer, "failed", 0, Some(&error.message))?;
                        return Err(error);
                    }
                };
                if let Err(error) =
                    replace_existing_download(staged, &local_path, expected_local_hash)
                {
                    self.finish_transfer(transfer, "failed", 0, Some(&error.message))?;
                    return Err(error);
                }
                self.finish_transfer(transfer, "completed", remote.size, None)?;
                let installed_hash = hash_file(&local_path)?;
                if installed_hash != remote_hash {
                    return Err(CloudError::new(
                        ErrorKind::Conflict,
                        format!(
                            "local file changed during conflict resolution; preserved the displaced version at {}",
                            recovery.display()
                        ),
                    ));
                }
                let metadata = fs::metadata(&local_path).map_err(io_error)?;
                let local = LocalEntry {
                    path: local_path,
                    size: metadata.len(),
                    mtime: modified_unix(&metadata),
                    hash: installed_hash.clone(),
                    directory: false,
                    fingerprint: None,
                };
                self.save_baseline(&pair.id, rel, &local, &remote, Some(&installed_hash))?;
                recovery
            }
        };

        Ok(ConflictResolution {
            pair_id: pair.id.clone(),
            path: rel.to_owned(),
            choice,
            recovery_path,
        })
    }

    /// Reconcile a pair without propagating deletions. Every directory listing
    /// and local scan must finish before content decisions are applied.
    pub fn sync_pair(&self, pair: &FolderPair) -> Result<SyncReport, CloudError> {
        let _guard = self.execution()?;
        self.check_sync_paused()?;
        self.validate_backend_binding(pair)?;
        validate_pair_runtime(pair)?;
        #[cfg(windows)]
        let _root_pin = raiun_control_windows::PinnedDirectory::open(Path::new(&pair.local_path))
            .map_err(io_error)?;
        self.check_pair_policy(pair)?;
        let pair = self.normalize_pair_root(pair)?;
        self.clear_stage(&pair.id)?;
        let mut scanned_entries = 0;
        self.scan_local(&pair, &mut scanned_entries, false, None)?;
        self.scan_remote(&pair, &mut scanned_entries)?;
        let mut report = SyncReport {
            pair_id: pair.id.clone(),
            ..SyncReport::default()
        };
        let mut after: Option<String> = None;
        loop {
            let paths = self.staged_path_batch(&pair.id, after.as_deref())?;
            if paths.is_empty() {
                break;
            }
            after = paths.last().cloned();
            for rel in paths {
                self.check_sync_paused()?;
                let local = self.local_stage(&pair.id, &rel)?;
                let remote = self.remote_stage(&pair.id, &rel)?;
                if !local.as_ref().is_some_and(|entry| entry.directory)
                    && !remote.as_ref().is_some_and(|entry| entry.directory)
                    && pair.excludes_file_path(&rel)
                {
                    continue;
                }
                let baseline = self.baseline(&pair.id, &rel)?;
                match (local, remote) {
                    (Some(l), Some(r)) if l.directory && r.directory => {
                        report.unchanged += 1;
                    }
                    (Some(l), Some(r)) if !l.directory && !r.directory => {
                        self.reconcile_file(&pair, &rel, l, r, baseline, &mut report)?;
                    }
                    (Some(l), None) if l.directory => {
                        if baseline.is_some() {
                            report.needs_attention += 1;
                        } else if pair.mode != SyncMode::DownloadOnly {
                            self.upload_directory(&pair, &rel, &mut report)?;
                        }
                    }
                    (Some(l), None) if !l.directory => {
                        if baseline.is_some() {
                            report.needs_attention += 1;
                        } else if pair.mode != SyncMode::DownloadOnly {
                            self.upload_file(&pair, &rel, &l.path, None, &mut report)?;
                        }
                    }
                    (None, Some(r)) if r.directory => {
                        if baseline.is_some() {
                            report.needs_attention += 1;
                        } else if pair.mode != SyncMode::UploadOnly {
                            self.create_local_dir(&pair, &rel)?;
                        }
                    }
                    (None, Some(r)) if !r.directory => {
                        if baseline.is_some() {
                            report.needs_attention += 1;
                        } else if pair.mode != SyncMode::UploadOnly {
                            self.download_file(&pair, &rel, &r, &mut report)?;
                        }
                    }
                    (None, None) => {}
                    _ => {
                        report.conflicts += 1;
                    }
                }
            }
        }
        Ok(report)
    }

    /// Publish a pair's exclusion policy before persisting a profile update.
    /// The shared execution gate waits for an active reconciliation to finish,
    /// then makes any stale queued scheduler snapshot fail before dispatch.
    pub fn publish_pair_policy(&self, pair: &FolderPair) -> Result<(), CloudError> {
        self.prepare_pair_policy(pair)?.publish();
        Ok(())
    }

    /// Prepare a publication while retaining the dispatch fence. The caller
    /// should persist the matching profile settings, then call `publish`; if
    /// persistence fails, simply drop the guard and the old policy remains.
    pub fn prepare_pair_policy(
        &self,
        pair: &FolderPair,
    ) -> Result<PairPolicyPublication<'_>, CloudError> {
        let guard = self.execution()?;
        validate_pair_runtime(pair)?;
        let policies = self
            .inner
            .pair_policies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if matches!(policies.get(&pair.id), Some(None)) {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "folder pair ID has been retired and cannot be reused",
            ));
        }
        drop(policies);
        Ok(PairPolicyPublication {
            inner: &self.inner,
            pair_id: pair.id.clone(),
            policy: Some(PairSyncPolicy::from(pair)),
            _execution: guard,
        })
    }

    /// Prepare pair retirement while retaining the same dispatch fence used
    /// for policy changes and sync admission.
    pub fn prepare_pair_retirement(
        &self,
        pair_id: &str,
    ) -> Result<PairPolicyPublication<'_>, CloudError> {
        if pair_id.is_empty() || pair_id.len() > 128 {
            return Err(CloudError::new(
                ErrorKind::InvalidResponse,
                "invalid folder pair ID",
            ));
        }
        let guard = self.execution()?;
        Ok(PairPolicyPublication {
            inner: &self.inner,
            pair_id: pair_id.to_owned(),
            policy: None,
            _execution: guard,
        })
    }

    /// Prepare atomic policy retirement for a bounded set of connections.
    /// The caller must durably remove these exact IDs before publishing; never
    /// acquire individual retirement guards recursively for a group.
    pub fn prepare_pair_retirements(
        &self,
        pair_ids: &[String],
    ) -> Result<PairRetirementPublication<'_>, CloudError> {
        if pair_ids.len() > 100_000 || pair_ids.iter().any(|id| id.is_empty() || id.len() > 128) {
            return Err(CloudError::new(
                ErrorKind::InvalidResponse,
                "invalid folder pair retirement set",
            ));
        }
        let unique = pair_ids.iter().collect::<std::collections::BTreeSet<_>>();
        if unique.len() != pair_ids.len() {
            return Err(CloudError::new(
                ErrorKind::InvalidResponse,
                "duplicate folder pair retirement ID",
            ));
        }
        Ok(PairRetirementPublication {
            inner: &self.inner,
            pair_ids: pair_ids.to_vec(),
            _execution: self.execution()?,
        })
    }

    /// Permanently retire a pair ID before profile settings remove it. IDs are
    /// not reusable, so a delayed scheduler snapshot must remain rejected.
    pub fn retire_pair_policy(&self, pair_id: &str) -> Result<(), CloudError> {
        if pair_id.is_empty() || pair_id.len() > 128 {
            return Err(CloudError::new(
                ErrorKind::InvalidResponse,
                "invalid folder pair ID",
            ));
        }
        self.prepare_pair_retirement(pair_id)?.publish();
        Ok(())
    }

    fn check_pair_policy(&self, pair: &FolderPair) -> Result<(), CloudError> {
        let mut policies = self
            .inner
            .pair_policies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let policy = PairSyncPolicy::from(pair);
        match policies.get(&pair.id) {
            Some(Some(current)) if current == &policy => Ok(()),
            Some(Some(_)) => Err(CloudError::new(
                ErrorKind::Conflict,
                "folder pair policy changed; refresh the profile snapshot before syncing",
            )),
            Some(None) => Err(CloudError::new(
                ErrorKind::Conflict,
                "folder pair has been removed",
            )),
            None => {
                // Legacy callers and first startup establish the initial
                // policy on first dispatch. Subsequent changes require the
                // explicit publication API above.
                policies.insert(pair.id.clone(), Some(policy));
                Ok(())
            }
        }
    }

    fn reconcile_file(
        &self,
        pair: &FolderPair,
        rel: &str,
        local: LocalEntry,
        remote: RemoteEntry,
        baseline: Option<Baseline>,
        report: &mut SyncReport,
    ) -> Result<(), CloudError> {
        let Some(base) = baseline else {
            if local.hash == hash_for_remote(self, &pair.space_id, &remote.path)? {
                self.save_baseline(&pair.id, rel, &local, &remote, Some(&local.hash))?;
                report.unchanged += 1;
            } else {
                report.conflicts += 1;
            }
            return Ok(());
        };
        let local_changed = local.hash != base.local_hash;
        let remote_changed = remote.etag != base.remote_etag || remote.size != base.remote_size;
        if !local_changed && !remote_changed {
            if local.size != base.local_size || local.mtime != base.local_mtime {
                self.save_baseline(&pair.id, rel, &local, &remote, base.remote_hash.as_deref())?;
            }
            report.unchanged += 1;
            return Ok(());
        }
        let remote_hash = if remote_changed || base.remote_hash.is_none() {
            Some(hash_for_remote(self, &pair.space_id, &remote.path)?)
        } else {
            base.remote_hash.clone()
        };
        if local_changed && remote_changed {
            if remote_hash.as_deref() == Some(&local.hash) {
                self.save_baseline(&pair.id, rel, &local, &remote, remote_hash.as_deref())?;
                report.unchanged += 1;
            } else {
                report.conflicts += 1;
            }
        } else if local_changed {
            if pair.mode == SyncMode::DownloadOnly {
                report.conflicts += 1;
            } else {
                self.upload_file(
                    pair,
                    rel,
                    &local.path,
                    Some(WriteCondition::Match(remote.etag.clone())),
                    report,
                )?;
            }
        } else {
            if pair.mode == SyncMode::UploadOnly {
                report.conflicts += 1;
            } else {
                self.download_file(pair, rel, &remote, report)?;
            }
        }
        Ok(())
    }

    fn scan_local(
        &self,
        pair: &FolderPair,
        scanned_entries: &mut usize,
        force_full_hash: bool,
        cache_policy_override: Option<bool>,
    ) -> Result<LocalScanMetrics, CloudError> {
        let root = ensure_pair_root_is_real_directory(&pair.local_path)?;
        let root_path = root.to_str().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Unsupported,
                "local pair root contains non-UTF-8 path bytes",
            )
        })?;
        if !root.is_dir() {
            return Err(CloudError::new(
                ErrorKind::Io,
                "local pair root is unavailable or is not a directory",
            ));
        }
        let generation = self.begin_local_hash_scan(&pair.id)?;
        let audit = should_force_hash_audit(generation);
        let force_full_hash = force_full_hash || audit;
        let mut metrics = LocalScanMetrics::default();
        self.db()?
            .execute(
                "INSERT OR IGNORE INTO scan_dirs(pair_id,side,remote_path) VALUES(?1,'local',?2)",
                params![pair.id, root_path],
            )
            .map_err(db_error)?;
        loop {
            let dir: Option<String> = self.db()?.query_row(
                "SELECT remote_path FROM scan_dirs WHERE pair_id=?1 AND side='local' ORDER BY remote_path LIMIT 1",
                [&pair.id],
                |r| r.get(0),
            ).optional().map_err(db_error)?;
            let Some(dir) = dir else { break };
            self.db()?
                .execute(
                    "DELETE FROM scan_dirs WHERE pair_id=?1 AND side='local' AND remote_path=?2",
                    params![pair.id, dir],
                )
                .map_err(db_error)?;
            let dir = PathBuf::from(dir);
            let mut batch = Vec::with_capacity(STAGE_BATCH_SIZE);
            #[cfg(windows)]
            let _directory_pin =
                raiun_control_windows::PinnedDirectory::open(&dir).map_err(io_error)?;
            for item in fs::read_dir(&dir).map_err(io_error)? {
                self.check_sync_paused()?;
                let item = item.map_err(io_error)?;
                charge_scan_budget(scanned_entries, 1, MAX_TOTAL_SCAN_ENTRIES)?;
                let path = item.path();
                // This prefix is reserved for displaced local files retained
                // after a failed no-clobber replacement. Never upload those
                // recovery copies as ordinary pair contents.
                if path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(".raiun-preserve-"))
                {
                    continue;
                }
                let rel_path = path.strip_prefix(&root).map_err(io_error)?;
                let rel = rel_path
                    .to_str()
                    .ok_or_else(|| {
                        CloudError::new(
                            ErrorKind::Unsupported,
                            "local path contains a non-UTF-8 name",
                        )
                    })?
                    .replace(std::path::MAIN_SEPARATOR, "/");
                if pair.excludes_relative_path(&rel) {
                    continue;
                }
                let meta = fs::symlink_metadata(&path).map_err(io_error)?;
                if is_link_or_reparse(&meta) {
                    return Err(CloudError::new(
                        ErrorKind::Unsupported,
                        format!("symlink is unsupported in folder pair: {}", path.display()),
                    ));
                }
                let local_path = path.to_str().ok_or_else(|| {
                    CloudError::new(
                        ErrorKind::Unsupported,
                        "local path contains non-UTF-8 path bytes",
                    )
                })?;
                let directory = meta.is_dir();
                if directory && pair.excludes_directory_path(&rel) {
                    continue;
                }
                if !directory && pair.excludes_file_path(&rel) {
                    continue;
                }
                let (size, mtime, hash, fingerprint) = if directory {
                    (0, modified_unix(&meta), None, None)
                } else if meta.is_file() {
                    let fingerprint = local_fingerprint(&meta);
                    let cache_allowed = cache_policy_override
                        .unwrap_or_else(|| filesystem_supports_hash_cache(&path));
                    let hash = if may_reuse_local_hash(cache_allowed, force_full_hash, fingerprint)
                    {
                        if let (Some(before), Some(cached)) = (
                            fingerprint,
                            self.cached_local_hash(&pair.id, &rel, fingerprint)?,
                        ) {
                            let after = fs::symlink_metadata(&path).map_err(io_error)?;
                            if local_fingerprint(&after) != Some(before) || !after.is_file() {
                                return Err(CloudError::new(
                                    ErrorKind::Conflict,
                                    format!(
                                        "local file changed while scanning: {}",
                                        path.display()
                                    ),
                                ));
                            }
                            metrics.reused_hashes += 1;
                            cached
                        } else {
                            let hash = hash_file(&path)?;
                            verify_local_fingerprint(&path, fingerprint)?;
                            metrics.hashed_files += 1;
                            hash
                        }
                    } else {
                        let hash = hash_file(&path)?;
                        verify_local_fingerprint(&path, fingerprint)?;
                        metrics.hashed_files += 1;
                        hash
                    };
                    (meta.len(), modified_unix(&meta), Some(hash), fingerprint)
                } else {
                    return Err(CloudError::new(
                        ErrorKind::Unsupported,
                        format!("special file is unsupported: {}", path.display()),
                    ));
                };
                batch.push((
                    rel,
                    LocalEntry {
                        path: PathBuf::from(local_path),
                        size,
                        mtime,
                        hash: hash.unwrap_or_default(),
                        directory,
                        fingerprint,
                    },
                ));
                if batch.len() == STAGE_BATCH_SIZE {
                    self.insert_local_batch(&pair.id, &batch)?;
                    batch.clear();
                }
            }
            if !batch.is_empty() {
                self.insert_local_batch(&pair.id, &batch)?;
            }
        }
        self.finish_local_hash_scan(&pair.id, generation)?;
        Ok(metrics)
    }

    fn begin_local_hash_scan(&self, pair: &str) -> Result<i64, CloudError> {
        let db = self.db()?;
        db.execute(
            "INSERT INTO local_hash_generation(pair_id,generation) VALUES(?1,1) \
             ON CONFLICT(pair_id) DO UPDATE SET generation=generation+1",
            [pair],
        )
        .map_err(db_error)?;
        db.query_row(
            "SELECT generation FROM local_hash_generation WHERE pair_id=?1",
            [pair],
            |row| row.get(0),
        )
        .map_err(db_error)
    }

    fn cached_local_hash(
        &self,
        pair: &str,
        rel: &str,
        fingerprint: Option<LocalFingerprint>,
    ) -> Result<Option<String>, CloudError> {
        let Some(fingerprint) = fingerprint else {
            return Ok(None);
        };
        self.db()?
            .query_row(
                "SELECT hash FROM local_hash_cache WHERE pair_id=?1 AND rel_path=?2 \
                 AND device=?3 AND inode=?4 AND size=?5 AND mtime_seconds=?6 \
                 AND mtime_nanoseconds=?7 AND ctime_seconds=?8 AND ctime_nanoseconds=?9",
                params![
                    pair,
                    rel,
                    fingerprint.device,
                    fingerprint.inode,
                    fingerprint.size,
                    fingerprint.mtime_seconds,
                    fingerprint.mtime_nanoseconds,
                    fingerprint.ctime_seconds,
                    fingerprint.ctime_nanoseconds,
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(db_error)
    }

    fn finish_local_hash_scan(&self, pair: &str, generation: i64) -> Result<(), CloudError> {
        self.db()?
            .execute(
                "DELETE FROM local_hash_cache WHERE pair_id=?1 AND seen_generation<>?2",
                params![pair, generation],
            )
            .map_err(db_error)?;
        Ok(())
    }

    fn insert_local_batch(
        &self,
        pair: &str,
        batch: &[(String, LocalEntry)],
    ) -> Result<(), CloudError> {
        let mut db = self.db()?;
        let tx = db.transaction().map_err(db_error)?;
        {
            let mut stage = tx
                .prepare("INSERT OR REPLACE INTO local_stage(pair_id,rel_path,local_path,size,mtime,hash,directory) VALUES(?1,?2,?3,?4,?5,?6,?7)")
                .map_err(db_error)?;
            let mut directories = tx
                .prepare("INSERT OR IGNORE INTO scan_dirs(pair_id,side,remote_path) VALUES(?1,'local',?2)")
                .map_err(db_error)?;
            let mut cache = tx.prepare(
                "INSERT INTO local_hash_cache(pair_id,rel_path,device,inode,size,mtime_seconds,mtime_nanoseconds,ctime_seconds,ctime_nanoseconds,hash,seen_generation) \
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,(SELECT generation FROM local_hash_generation WHERE pair_id=?1)) \
                 ON CONFLICT(pair_id,rel_path) DO UPDATE SET device=excluded.device,inode=excluded.inode,size=excluded.size,mtime_seconds=excluded.mtime_seconds,mtime_nanoseconds=excluded.mtime_nanoseconds,ctime_seconds=excluded.ctime_seconds,ctime_nanoseconds=excluded.ctime_nanoseconds,hash=excluded.hash,seen_generation=excluded.seen_generation"
            ).map_err(db_error)?;
            for (rel, entry) in batch {
                let path = entry.path.to_str().ok_or_else(|| {
                    CloudError::new(
                        ErrorKind::Unsupported,
                        "local path contains non-UTF-8 path bytes",
                    )
                })?;
                stage
                    .execute(params![
                        pair,
                        rel,
                        path,
                        entry.size as i64,
                        entry.mtime,
                        entry.hash,
                        entry.directory as i64
                    ])
                    .map_err(db_error)?;
                if entry.directory {
                    directories.execute(params![pair, path]).map_err(db_error)?;
                }
                if let Some(fingerprint) = entry.fingerprint {
                    cache
                        .execute(params![
                            pair,
                            rel,
                            fingerprint.device,
                            fingerprint.inode,
                            fingerprint.size,
                            fingerprint.mtime_seconds,
                            fingerprint.mtime_nanoseconds,
                            fingerprint.ctime_seconds,
                            fingerprint.ctime_nanoseconds,
                            entry.hash,
                        ])
                        .map_err(db_error)?;
                }
            }
        }
        tx.commit().map_err(db_error)
    }

    fn scan_remote(
        &self,
        pair: &FolderPair,
        scanned_entries: &mut usize,
    ) -> Result<(), CloudError> {
        self.scan_remote_with_encrypted_policy(pair, false, scanned_entries)
    }

    fn scan_remote_for_conflicts(
        &self,
        pair: &FolderPair,
        scanned_entries: &mut usize,
    ) -> Result<(), CloudError> {
        self.scan_remote_with_encrypted_policy(pair, true, scanned_entries)
    }

    fn scan_remote_with_encrypted_policy(
        &self,
        pair: &FolderPair,
        skip_encrypted: bool,
        scanned_entries: &mut usize,
    ) -> Result<(), CloudError> {
        let root = pair.remote_path.trim_end_matches('/');
        self.db()?
            .execute(
                "INSERT OR IGNORE INTO scan_dirs(pair_id,side,remote_path) VALUES(?1,'remote',?2)",
                params![pair.id, if root.is_empty() { "/" } else { root }],
            )
            .map_err(db_error)?;
        loop {
            let next: Option<String> = self.db()?.query_row("SELECT remote_path FROM scan_dirs WHERE pair_id=?1 AND side='remote' ORDER BY remote_path LIMIT 1", [&pair.id], |r| r.get(0)).optional().map_err(db_error)?;
            let Some(dir) = next else { break };
            self.db()?
                .execute(
                    "DELETE FROM scan_dirs WHERE pair_id=?1 AND side='remote' AND remote_path=?2",
                    params![pair.id, dir],
                )
                .map_err(db_error)?;
            let mut failure = None;
            let mut emitted = 0_usize;
            let mut batch = Vec::with_capacity(STAGE_BATCH_SIZE);
            self.backend.list(&pair.space_id, &dir, &mut |entry| {
                self.check_sync_paused()?;
                emitted += 1;
                if emitted > MAX_LIST_ENTRIES {
                    let error = CloudError::new(
                        ErrorKind::InvalidResponse,
                        "remote folder exceeds the 100,000-entry limit",
                    );
                    failure = Some(error.clone());
                    return Err(error);
                }
                if let Err(error) = charge_scan_budget(scanned_entries, 1, MAX_TOTAL_SCAN_ENTRIES) {
                    failure = Some(error.clone());
                    return Err(error);
                }
                if skip_encrypted && entry.encrypted {
                    return Ok(());
                }
                let relative = match remote_relative(&pair.remote_path, &entry.path) {
                    Ok(relative) => relative,
                    Err(error) => {
                        failure = Some(error.clone());
                        return Err(error);
                    }
                };
                if pair.excludes_relative_path(&relative)
                    || (entry.directory && pair.excludes_directory_path(&relative))
                    || (!entry.directory && pair.excludes_file_path(&relative))
                {
                    return Ok(());
                }
                match self.prepare_remote_entry(pair, &dir, entry) {
                    Ok(entry) => batch.push(entry),
                    Err(error) => {
                        failure = Some(error.clone());
                        return Err(error);
                    }
                }
                if batch.len() == STAGE_BATCH_SIZE {
                    if let Err(error) = self.insert_remote_batch(pair, &batch) {
                        failure = Some(error.clone());
                        return Err(error);
                    }
                    batch.clear();
                }
                Ok(())
            })?;
            if let Some(error) = failure {
                return Err(error);
            }
            if !batch.is_empty() {
                self.insert_remote_batch(pair, &batch)?;
            }
        }
        Ok(())
    }

    fn prepare_remote_entry(
        &self,
        pair: &FolderPair,
        parent: &str,
        entry: RemoteEntry,
    ) -> Result<(String, RemoteEntry), CloudError> {
        if entry.encrypted {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                format!("encrypted remote entry is unsupported: {}", entry.path),
            ));
        }
        let prefix = if parent == "/" {
            "/".to_string()
        } else {
            format!("{}/", parent.trim_end_matches('/'))
        };
        let tail = entry.path.strip_prefix(&prefix).ok_or_else(|| {
            CloudError::new(
                ErrorKind::InvalidResponse,
                "listing returned an entry outside the requested directory",
            )
        })?;
        if tail.is_empty() || tail.contains('/') || tail == "." || tail == ".." {
            return Err(CloudError::new(
                ErrorKind::InvalidResponse,
                "listing returned a non-child path",
            ));
        }
        let relative = remote_relative(&pair.remote_path, &entry.path)?;
        Ok((relative, entry))
    }

    fn insert_remote_batch(
        &self,
        pair: &FolderPair,
        batch: &[(String, RemoteEntry)],
    ) -> Result<(), CloudError> {
        let mut db = self.db()?;
        let tx = db.transaction().map_err(db_error)?;
        {
            let mut stage = tx
                .prepare("INSERT OR REPLACE INTO remote_stage(pair_id,rel_path,remote_path,etag,size,directory) VALUES(?1,?2,?3,?4,?5,?6)")
                .map_err(db_error)?;
            let mut directories = tx
                .prepare("INSERT OR IGNORE INTO scan_dirs(pair_id,side,remote_path) VALUES(?1,'remote',?2)")
                .map_err(db_error)?;
            for (rel, entry) in batch {
                stage
                    .execute(params![
                        pair.id,
                        rel,
                        entry.path,
                        entry.etag,
                        entry.size as i64,
                        entry.directory as i64
                    ])
                    .map_err(db_error)?;
                if entry.directory {
                    directories
                        .execute(params![pair.id, entry.path])
                        .map_err(db_error)?;
                }
            }
        }
        tx.commit().map_err(db_error)
    }

    fn upload_directory(
        &self,
        pair: &FolderPair,
        rel: &str,
        report: &mut SyncReport,
    ) -> Result<(), CloudError> {
        let remote = join_remote(&pair.remote_path, rel);
        let id = self.begin_transfer(Some(&pair.id), &pair.space_id, &remote, "mkdir")?;
        match self.backend.mkdir(&pair.space_id, &remote) {
            Ok(_) => {
                self.finish_transfer(id, "completed", 0, None)?;
                report.uploaded += 1;
            }
            Err(e) => {
                self.finish_transfer(id, "failed", 0, Some(&e.message))?;
                return Err(e);
            }
        }
        Ok(())
    }

    fn create_local_dir(&self, pair: &FolderPair, rel: &str) -> Result<(), CloudError> {
        let path = pair.local_path.join(rel);
        ensure_safe_pair_path(&pair.local_path, &path, true)?;
        #[cfg(windows)]
        let _created_pin = pin_or_create_pair_directory(&pair.local_path, &path)?;
        #[cfg(not(windows))]
        fs::create_dir_all(&path).map_err(io_error)?;
        ensure_safe_pair_path(&pair.local_path, &path, false)
    }

    fn upload_file(
        &self,
        pair: &FolderPair,
        rel: &str,
        source: &Path,
        condition: Option<WriteCondition>,
        report: &mut SyncReport,
    ) -> Result<(), CloudError> {
        ensure_safe_pair_path(&pair.local_path, source, false)?;
        let remote_path = join_remote(&pair.remote_path, rel);
        let remote = self.upload_inner(
            Some(&pair.id),
            &pair.space_id,
            &remote_path,
            source,
            condition.unwrap_or(WriteCondition::Absent),
        )?;
        ensure_safe_pair_path(&pair.local_path, source, false)?;
        let hash = hash_file(source)?;
        let remote_hash = hash_for_remote(self, &pair.space_id, &remote.path)?;
        if hash != remote_hash {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "local file changed after upload verification; preserving the local edit",
            ));
        }
        let metadata = fs::metadata(source).map_err(io_error)?;
        let local = LocalEntry {
            path: source.to_path_buf(),
            size: metadata.len(),
            mtime: modified_unix(&metadata),
            hash,
            directory: false,
            fingerprint: None,
        };
        self.save_baseline(&pair.id, rel, &local, &remote, Some(&local.hash))?;
        report.uploaded += 1;
        Ok(())
    }

    fn download_file(
        &self,
        pair: &FolderPair,
        rel: &str,
        remote: &RemoteEntry,
        report: &mut SyncReport,
    ) -> Result<(), CloudError> {
        let destination = pair.local_path.join(rel);
        ensure_safe_pair_path(&pair.local_path, &destination, true)?;
        let parent = destination.parent().ok_or_else(|| {
            CloudError::new(ErrorKind::Io, "local destination has no parent folder")
        })?;
        #[cfg(windows)]
        let _parent_pin = pin_or_create_pair_directory(&pair.local_path, parent)?;
        #[cfg(not(windows))]
        fs::create_dir_all(parent).map_err(io_error)?;
        ensure_safe_pair_path(&pair.local_path, &destination, true)?;
        let staged = NamedTempFile::new_in(parent).map_err(io_error)?;
        let id = self.begin_transfer(Some(&pair.id), &pair.space_id, &remote.path, "download")?;
        let result = download_to_named_temp(
            self.backend.as_ref(),
            &pair.space_id,
            &remote.path,
            Some(&remote.etag),
            staged,
        )
        .and_then(|(staged, entry)| {
            if entry.etag != remote.etag {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "remote revision changed during download",
                ));
            }
            staged.as_file().sync_all().map_err(io_error)?;
            let size = staged.as_file().metadata().map_err(io_error)?.len();
            if size != entry.size {
                return Err(CloudError::new(
                    ErrorKind::InvalidResponse,
                    "download size does not match the server response",
                ));
            }
            Ok((entry, size, hash_file(staged.path())?, staged))
        });
        match result {
            Ok((entry, size, hash, staged)) => {
                // Only replace if the destination still has the scanned version (or is absent).
                let expected = self.local_stage(&pair.id, rel)?;
                if let Some(old) = &expected {
                    let unchanged = destination.exists()
                        && ensure_safe_pair_path(&pair.local_path, &destination, false).is_ok()
                        && hash_file(&destination).is_ok_and(|current| current == old.hash);
                    if !unchanged {
                        self.finish_transfer(
                            id,
                            "conflict",
                            0,
                            Some("local file changed during sync"),
                        )?;
                        report.conflicts += 1;
                        return Ok(());
                    }
                } else if path_exists(&destination)? {
                    self.finish_transfer(
                        id,
                        "conflict",
                        0,
                        Some("local destination appeared during sync"),
                    )?;
                    report.conflicts += 1;
                    return Ok(());
                }

                let install = match expected.as_ref() {
                    Some(old) => replace_existing_download(
                        staged,
                        &destination,
                        &old.hash,
                    ),
                    None => staged
                        .persist_noclobber(&destination)
                        .map(|_| ())
                        .map_err(|error| {
                            if error.error.kind() == std::io::ErrorKind::AlreadyExists {
                                CloudError::new(
                                    ErrorKind::Conflict,
                                    "local destination appeared while the download was being installed",
                                )
                            } else {
                                io_error(error.error)
                            }
                        }),
                };
                if let Err(error) = install {
                    if error.kind == ErrorKind::Conflict {
                        self.finish_transfer(id, "conflict", 0, Some(&error.message))?;
                        report.conflicts += 1;
                        return Ok(());
                    }
                    self.finish_transfer(id, "failed", 0, Some(&error.message))?;
                    return Err(error);
                }
                self.finish_transfer(id, "completed", size, None)?;
                let local_path = pair.local_path.join(rel);
                let metadata = fs::metadata(&local_path).map_err(io_error)?;
                let local = LocalEntry {
                    path: local_path,
                    size,
                    mtime: modified_unix(&metadata),
                    hash: hash.clone(),
                    directory: false,
                    fingerprint: None,
                };
                self.save_baseline(&pair.id, rel, &local, &entry, Some(&hash))?;
                report.downloaded += 1;
            }
            Err(error) => {
                self.finish_transfer(id, "failed", 0, Some(&error.message))?;
                return Err(error);
            }
        }
        Ok(())
    }

    fn upload_inner(
        &self,
        pair_id: Option<&str>,
        space: &str,
        path: &str,
        source: &Path,
        condition: WriteCondition,
    ) -> Result<RemoteEntry, CloudError> {
        self.upload_inner_with_root(pair_id, space, path, source, condition, None)
    }

    fn upload_inner_with_root(
        &self,
        pair_id: Option<&str>,
        space: &str,
        path: &str,
        source: &Path,
        condition: WriteCondition,
        expected_root: Option<&str>,
    ) -> Result<RemoteEntry, CloudError> {
        // Keep the exact Windows source and all ancestors stable through the
        // backend's path reopen, upload and readback verification.
        #[cfg(windows)]
        let _source_pin = {
            let parent = source.parent().ok_or_else(|| {
                CloudError::new(ErrorKind::Unsupported, "upload source has no parent")
            })?;
            let name = source.file_name().ok_or_else(|| {
                CloudError::new(ErrorKind::Unsupported, "upload source has no filename")
            })?;
            let parent = raiun_control_windows::PinnedDirectory::open(parent).map_err(io_error)?;
            let (file, _) = parent.open_immutable_regular_file(name).map_err(io_error)?;
            (file, parent)
        };
        let before_hash = hash_file(source)?;
        let bytes = fs::metadata(source).map_err(io_error)?.len();
        let _metadata = self.metadata_publication()?;
        let cache_mutation = self.begin_cache_mutation(space, &[path])?;
        let id = self.begin_transfer(pair_id, space, path, "upload")?;
        let upload = self.check_sync_paused().and_then(|()| match expected_root {
            Some(root) => self
                .backend
                .upload_in_root(space, path, source, condition, root),
            None => self.backend.upload(space, path, source, condition),
        });
        let result = upload.and_then(|uploaded| {
            let remote_temp = self.unique_temp("verify")?;
            let download = match expected_root {
                Some(root) => self.backend.download_in_root(
                    space,
                    path,
                    Some(&uploaded.etag),
                    &remote_temp,
                    root,
                ),
                None => self
                    .backend
                    .download(space, path, Some(&uploaded.etag), &remote_temp),
            };
            let checked = download.and_then(|verified| {
                let actual_hash = hash_file(&remote_temp)?;
                let actual_size = fs::metadata(&remote_temp).map_err(io_error)?.len();
                if (expected_root.is_some()
                    && (verified.id != uploaded.id
                        || verified.path != uploaded.path
                        || verified.directory
                        || verified.encrypted))
                    || verified.etag != uploaded.etag
                    || actual_hash != before_hash
                    || actual_size != bytes
                {
                    return Err(CloudError::new(
                        ErrorKind::InvalidResponse,
                        "uploaded content could not be verified",
                    ));
                }
                Ok(verified)
            });
            let _ = fs::remove_file(remote_temp);
            let after_hash = hash_file(source)?;
            if after_hash != before_hash {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "local source changed while upload was running",
                ));
            }
            checked
        });
        match result {
            Ok(entry) => {
                self.finish_cache_mutation(space, cache_mutation);
                self.finish_transfer(id, "completed", bytes, None)?;
                Ok(entry)
            }
            Err(error) => {
                // A rejected or unacknowledged PUT must not permanently hide
                // unrelated cached files when fresh metadata is still reachable.
                // Only a complete listing under the same verified root can
                // restore reachability; the write and its recovery stay failed.
                self.finish_cache_mutation(space, cache_mutation);
                self.finish_transfer(id, "failed", 0, Some(&error.message))?;
                Err(error)
            }
        }
    }

    fn fetch_inner(&self, space: &str, path: &str) -> Result<(PathBuf, u64), CloudError> {
        let before = self.backend.stat(space, path)?;
        if before.directory {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "cannot fetch a directory as a file",
            ));
        }
        let cache_scope = match &self.vault_binding {
            Some((_, binding)) => format!(
                "{space}\0{}\0{}",
                binding.root_path, binding.root_resource_id
            ),
            None => space.to_owned(),
        };
        let dest = self.cache_dir().join(cache_key(&cache_scope, path));
        let tmp = self.unique_temp("fetch")?;
        let entry = match self.backend.download(space, path, Some(&before.etag), &tmp) {
            Ok(entry) => entry,
            Err(error) => {
                let _ = fs::remove_file(&tmp);
                return Err(error);
            }
        };
        let size = fs::metadata(&tmp).map_err(io_error)?.len();
        if entry.etag != before.etag || size != entry.size || size != before.size {
            let _ = fs::remove_file(&tmp);
            return Err(CloudError::new(
                ErrorKind::InvalidResponse,
                "download revision or size failed verification",
            ));
        }
        fs::rename(tmp, &dest).map_err(io_error)?;
        Ok((dest, size))
    }

    fn save_baseline(
        &self,
        pair: &str,
        rel: &str,
        local: &LocalEntry,
        remote: &RemoteEntry,
        remote_hash: Option<&str>,
    ) -> Result<(), CloudError> {
        self.db()?.execute("INSERT INTO baselines(pair_id,rel_path,local_hash,local_size,local_mtime,remote_etag,remote_hash,remote_size) VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(pair_id,rel_path) DO UPDATE SET local_hash=excluded.local_hash,local_size=excluded.local_size,local_mtime=excluded.local_mtime,remote_etag=excluded.remote_etag,remote_hash=excluded.remote_hash,remote_size=excluded.remote_size", params![pair, rel, local.hash, local.size as i64, local.mtime, remote.etag, remote_hash, remote.size as i64]).map_err(db_error)?;
        Ok(())
    }

    fn baseline(&self, pair: &str, rel: &str) -> Result<Option<Baseline>, CloudError> {
        self.db()?.query_row("SELECT local_hash,local_size,local_mtime,remote_etag,remote_hash,remote_size FROM baselines WHERE pair_id=?1 AND rel_path=?2", params![pair,rel], |r| Ok(Baseline { local_hash:r.get(0)?,local_size:r.get::<_,i64>(1)?.max(0) as u64,local_mtime:r.get(2)?,remote_etag:r.get(3)?,remote_hash:r.get(4)?,remote_size:r.get::<_,i64>(5)?.max(0) as u64 })).optional().map_err(db_error)
    }

    fn is_conflict_state(
        &self,
        pair: &FolderPair,
        rel: &str,
        local_hash: &str,
        remote: &RemoteEntry,
        remote_hash: Option<&str>,
    ) -> Result<bool, CloudError> {
        let Some(base) = self.baseline(&pair.id, rel)? else {
            return Ok(remote_hash.is_some_and(|hash| local_hash != hash));
        };
        let local_changed = local_hash != base.local_hash;
        let remote_changed = remote.etag != base.remote_etag || remote.size != base.remote_size;
        if local_changed && remote_changed {
            Ok(remote_hash.is_some_and(|hash| local_hash != hash))
        } else {
            Ok((local_changed && pair.mode == SyncMode::DownloadOnly)
                || (remote_changed && pair.mode == SyncMode::UploadOnly))
        }
    }

    fn conflict_needs_content_compare(
        &self,
        pair: &FolderPair,
        rel: &str,
        local_hash: &str,
        remote: &RemoteEntry,
    ) -> Result<bool, CloudError> {
        let Some(base) = self.baseline(&pair.id, rel)? else {
            return Ok(true);
        };
        let local_changed = local_hash != base.local_hash;
        let remote_changed = remote.etag != base.remote_etag || remote.size != base.remote_size;
        Ok(local_changed && remote_changed)
    }

    fn normalize_pair_root(&self, pair: &FolderPair) -> Result<FolderPair, CloudError> {
        let mut normalized = pair.clone();
        normalized.local_path = self.validate_pair_root(pair)?;
        Ok(normalized)
    }

    fn validate_pair_root(&self, pair: &FolderPair) -> Result<PathBuf, CloudError> {
        let local_root = ensure_pair_root_is_real_directory(&pair.local_path)?;
        if local_root.starts_with(&self.inner.state_dir)
            || self.inner.state_dir.starts_with(&local_root)
        {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "folder pair overlaps engine state or cache storage",
            ));
        }
        Ok(local_root)
    }

    fn local_stage(&self, pair: &str, rel: &str) -> Result<Option<LocalEntry>, CloudError> {
        self.db()?.query_row("SELECT local_path,size,mtime,hash,directory FROM local_stage WHERE pair_id=?1 AND rel_path=?2", params![pair,rel], |r| {
            let directory: i64 = r.get(4)?;
            Ok(LocalEntry { path: PathBuf::from(r.get::<_,String>(0)?), size:r.get::<_,i64>(1)?.max(0) as u64, mtime:r.get(2)?, hash:r.get::<_,Option<String>>(3)?.unwrap_or_default(), directory:directory != 0, fingerprint: None })
        }).optional().map_err(db_error)
    }

    fn remote_stage(&self, pair: &str, rel: &str) -> Result<Option<RemoteEntry>, CloudError> {
        self.db()?.query_row("SELECT remote_path,etag,size,directory FROM remote_stage WHERE pair_id=?1 AND rel_path=?2", params![pair,rel], |r| Ok(RemoteEntry { id:String::new(), path:r.get(0)?, directory:r.get::<_,i64>(3)? != 0, size:r.get::<_,i64>(2)?.max(0) as u64, etag:r.get(1)?, modified_unix:0, writable:true, encrypted:false })).optional().map_err(db_error)
    }

    fn staged_path_batch(
        &self,
        pair: &str,
        after: Option<&str>,
    ) -> Result<Vec<String>, CloudError> {
        let db = self.db()?;
        let mut paths = Vec::with_capacity(512);
        for table in ["local_stage", "remote_stage"] {
            let sql = format!(
                "SELECT rel_path FROM {table} WHERE pair_id=?1 AND rel_path>?2 ORDER BY rel_path LIMIT 256"
            );
            let mut statement = db.prepare(&sql).map_err(db_error)?;
            let rows = statement
                .query_map(params![pair, after.unwrap_or("")], |row| row.get(0))
                .map_err(db_error)?;
            paths.extend(
                rows.map(|row| row.map_err(db_error))
                    .collect::<Result<Vec<_>, _>>()?,
            );
        }
        paths.sort_unstable();
        paths.dedup();
        paths.truncate(256);
        Ok(paths)
    }

    fn clear_stage(&self, pair: &str) -> Result<(), CloudError> {
        let db = self.db()?;
        db.execute("DELETE FROM local_stage WHERE pair_id=?1", [pair])
            .map_err(db_error)?;
        db.execute("DELETE FROM remote_stage WHERE pair_id=?1", [pair])
            .map_err(db_error)?;
        db.execute("DELETE FROM scan_dirs WHERE pair_id=?1", [pair])
            .map_err(db_error)?;
        Ok(())
    }

    fn begin_transfer(
        &self,
        pair: Option<&str>,
        space: &str,
        path: &str,
        operation: &str,
    ) -> Result<i64, CloudError> {
        let now = now_unix();
        self.db()?.execute("INSERT INTO transfers(pair_id,space_id,path,operation,status,created_unix) VALUES(?1,?2,?3,?4,'running',?5)", params![pair,space,path,operation,now]).map_err(db_error)?;
        Ok(self.db()?.last_insert_rowid())
    }

    fn finish_transfer(
        &self,
        id: i64,
        status: &str,
        bytes: u64,
        message: Option<&str>,
    ) -> Result<(), CloudError> {
        self.db()?
            .execute(
                "UPDATE transfers SET status=?1,bytes=?2,message=?3,finished_unix=?4 WHERE id=?5",
                params![
                    status,
                    bytes.min(i64::MAX as u64) as i64,
                    message,
                    now_unix(),
                    id
                ],
            )
            .map_err(db_error)?;
        Ok(())
    }

    fn unique_temp(&self, label: &str) -> Result<PathBuf, CloudError> {
        for n in 0..1000u32 {
            let path = self
                .cache_dir()
                .join(format!(".{label}-{}-{n}.part", now_unix_nanos()));
            if !path.exists() {
                return Ok(path);
            }
        }
        Err(CloudError::new(
            ErrorKind::Io,
            "could not allocate a temporary cache file",
        ))
    }

    fn cache_dir(&self) -> &Path {
        &self.inner.cache_dir
    }
    fn db(&self) -> Result<MutexGuard<'_, DbOwner>, CloudError> {
        self.inner
            .db
            .lock()
            .map_err(|_| CloudError::new(ErrorKind::Io, "engine database lock was poisoned"))
    }
    fn execution(&self) -> Result<MutexGuard<'_, ()>, CloudError> {
        self.inner
            .execution
            .lock()
            .map_err(|_| CloudError::new(ErrorKind::Io, "engine execution lock was poisoned"))
    }
    fn metadata_publication(&self) -> Result<MutexGuard<'_, ()>, CloudError> {
        self.inner.metadata_gate.lock().map_err(|_| {
            CloudError::new(
                ErrorKind::Io,
                "engine metadata publication lock was poisoned",
            )
        })
    }

    fn check_sync_paused(&self) -> Result<(), CloudError> {
        if self.inner.sync_paused.load(Ordering::Acquire) {
            Err(CloudError::new(
                ErrorKind::Unsupported,
                "Folder sync paused",
            ))
        } else {
            Ok(())
        }
    }
}

fn path_exists(path: &Path) -> Result<bool, CloudError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io_error(error)),
    }
}

#[cfg(windows)]
fn pin_or_create_pair_directory(
    root: &Path,
    directory: &Path,
) -> Result<raiun_control_windows::PinnedDirectory, CloudError> {
    let relative = directory.strip_prefix(root).map_err(|_| {
        CloudError::new(
            ErrorKind::Unsupported,
            "local directory is outside the folder pair",
        )
    })?;
    let mut pin = raiun_control_windows::PinnedDirectory::open(root).map_err(io_error)?;
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "local directory is not canonical",
            ));
        };
        pin = pin.create_child_directory(name).map_err(io_error)?;
    }
    Ok(pin)
}

fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0 // FILE_ATTRIBUTE_REPARSE_POINT
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

fn ensure_pair_root_is_real_directory(path: &Path) -> Result<PathBuf, CloudError> {
    let before = fs::symlink_metadata(path).map_err(io_error)?;
    if is_link_or_reparse(&before) {
        return Err(CloudError::new(
            ErrorKind::Unsupported,
            "folder pair root must not be a symlink",
        ));
    }
    if !before.is_dir() {
        return Err(CloudError::new(
            ErrorKind::Io,
            "local pair root is unavailable or is not a directory",
        ));
    }
    let canonical = fs::canonicalize(path).map_err(io_error)?;
    let after = fs::symlink_metadata(path).map_err(io_error)?;
    if is_link_or_reparse(&after) || !same_file(&before, &after) {
        return Err(CloudError::new(
            ErrorKind::Conflict,
            "folder pair root changed while it was being validated",
        ));
    }
    Ok(canonical)
}

fn charge_scan_budget(total: &mut usize, amount: usize, maximum: usize) -> Result<(), CloudError> {
    let next = total.checked_add(amount).ok_or_else(|| {
        CloudError::new(
            ErrorKind::InvalidResponse,
            format!("folder-pair scan exceeds the {maximum}-entry total limit"),
        )
    })?;
    if next > maximum {
        return Err(CloudError::new(
            ErrorKind::InvalidResponse,
            format!("folder-pair scan exceeds the {maximum}-entry total limit"),
        ));
    }
    *total = next;
    Ok(())
}

fn open_owned_file_for_sync(path: &Path) -> std::io::Result<File> {
    #[cfg(windows)]
    {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
    }
    #[cfg(not(windows))]
    {
        File::open(path)
    }
}

/// Download to a temporary path without keeping its file handle open.
///
/// Some backends publish downloads by atomically renaming a completed file
/// over the destination. Windows denies that replacement while the
/// `NamedTempFile` handle remains open. `TempPath` retains cleanup ownership
/// while closing the handle; reopening the published path restores the
/// existing `NamedTempFile` ownership and caller flow.
fn download_to_named_temp(
    backend: &dyn CloudBackend,
    space: &str,
    path: &str,
    expected_etag: Option<&str>,
    staged: NamedTempFile,
) -> Result<(NamedTempFile, RemoteEntry), CloudError> {
    let staged_path = staged.into_temp_path();
    let entry = backend.download(space, path, expected_etag, &staged_path)?;
    if !fs::symlink_metadata(&staged_path)
        .map_err(io_error)?
        .is_file()
    {
        return Err(CloudError::new(
            ErrorKind::InvalidResponse,
            "download did not publish a regular local file",
        ));
    }
    let file = open_owned_file_for_sync(&staged_path).map_err(io_error)?;
    Ok((NamedTempFile::from_parts(file, staged_path), entry))
}

fn sync_owned_file(path: &Path) -> Result<(), CloudError> {
    open_owned_file_for_sync(path)
        .and_then(|file| file.sync_all())
        .map_err(io_error)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), CloudError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(io_error)
}

// Rust's portable std API cannot fsync directories on Windows. File contents
// are still synced there; directory syncing is enabled on Unix platforms.
#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), CloudError> {
    Ok(())
}

fn validate_conflict_path(rel: &str) -> Result<(), CloudError> {
    let path = Path::new(rel);
    if rel.is_empty()
        || rel.contains('\\')
        || path.is_absolute()
        || path.components().any(|component| {
            !matches!(component, std::path::Component::Normal(name)
                if !name.to_string_lossy().starts_with(".raiun-preserve-"))
        })
    {
        return Err(CloudError::new(
            ErrorKind::Unsupported,
            "conflict path is not a safe relative file path",
        ));
    }
    Ok(())
}

fn snapshot_local_file(
    source: &Path,
    expected_hash: &str,
    directory: &Path,
) -> Result<NamedTempFile, CloudError> {
    if hash_file(source)? != expected_hash {
        return Err(CloudError::new(
            ErrorKind::Conflict,
            "local file changed before its conflict snapshot was created",
        ));
    }
    let snapshot = NamedTempFile::new_in(directory).map_err(io_error)?;
    fs::copy(source, snapshot.path()).map_err(io_error)?;
    snapshot.as_file().sync_all().map_err(io_error)?;
    if hash_file(source)? != expected_hash || hash_file(snapshot.path())? != expected_hash {
        return Err(CloudError::new(
            ErrorKind::Conflict,
            "local file changed while its conflict snapshot was created",
        ));
    }
    Ok(snapshot)
}

fn preserve_local_version(
    root: &Path,
    source: &Path,
    expected_hash: &str,
) -> Result<PathBuf, CloudError> {
    let parent = source.parent().ok_or_else(|| {
        CloudError::new(
            ErrorKind::Io,
            "local file has no parent for its recovery copy",
        )
    })?;
    let recovery_dir = TempBuilder::new()
        .prefix(".raiun-preserve-")
        .tempdir_in(parent)
        .map_err(io_error)?;
    let recovery_file = recovery_dir.path().join("previous-version");
    if hash_file(source)? != expected_hash {
        return Err(CloudError::new(
            ErrorKind::Conflict,
            "local file changed before its recovery copy was created",
        ));
    }
    fs::copy(source, &recovery_file).map_err(io_error)?;
    sync_owned_file(&recovery_file)?;
    if hash_file(source)? != expected_hash || hash_file(&recovery_file)? != expected_hash {
        return Err(CloudError::new(
            ErrorKind::Conflict,
            "local file changed while its recovery copy was created",
        ));
    }
    sync_directory(recovery_dir.path())?;
    sync_directory(parent)?;
    let directory = recovery_dir.keep();
    let preserved = directory.join("previous-version");
    if !preserved.starts_with(root) {
        return Err(CloudError::new(
            ErrorKind::Unsupported,
            "recovery copy escaped the folder pair",
        ));
    }
    Ok(preserved)
}

fn preserve_remote_version(
    engine: &Engine,
    pair_id: &str,
    local_path: &Path,
    space: &str,
    remote_path: &str,
    expected: &RemoteEntry,
    expected_hash: &str,
) -> Result<PathBuf, CloudError> {
    let parent = local_path.parent().ok_or_else(|| {
        CloudError::new(
            ErrorKind::Io,
            "remote file has no local parent for its recovery copy",
        )
    })?;
    let recovery_dir = TempBuilder::new()
        .prefix(".raiun-preserve-")
        .tempdir_in(parent)
        .map_err(io_error)?;
    let staged = NamedTempFile::new_in(recovery_dir.path()).map_err(io_error)?;
    let transfer = engine.begin_transfer(Some(pair_id), space, remote_path, "conflict_backup")?;
    let downloaded = download_to_named_temp(
        engine.backend.as_ref(),
        space,
        remote_path,
        Some(&expected.etag),
        staged,
    );
    let result = downloaded.and_then(|(staged, entry)| {
        if entry.etag != expected.etag || entry.size != expected.size {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "remote file changed while its recovery copy was created",
            ));
        }
        let file = open_owned_file_for_sync(staged.path()).map_err(io_error)?;
        let size = file.metadata().map_err(io_error)?.len();
        file.sync_all().map_err(io_error)?;
        if size != entry.size || hash_file(staged.path())? != expected_hash {
            return Err(CloudError::new(
                ErrorKind::InvalidResponse,
                "remote recovery copy failed content or size verification",
            ));
        }
        Ok((size, entry, staged))
    });
    let (size, _entry, staged) = match result {
        Ok(result) => result,
        Err(error) => {
            engine.finish_transfer(transfer, "failed", 0, Some(&error.message))?;
            return Err(error);
        }
    };
    let recovery_file = recovery_dir.path().join("previous-version");
    let (staged_file, staged_path) = match staged.keep() {
        Ok(result) => result,
        Err(error) => {
            let error = io_error(error.error);
            engine.finish_transfer(transfer, "failed", 0, Some(&error.message))?;
            return Err(error);
        }
    };
    drop(staged_file);
    // The backend may have atomically replaced the NamedTempFile path. Rename
    // that published file into the durable, scanner-excluded recovery folder.
    if let Err(error) = fs::rename(&staged_path, &recovery_file) {
        let error = io_error(error);
        engine.finish_transfer(transfer, "failed", 0, Some(&error.message))?;
        return Err(error);
    }
    if let Err(error) = sync_owned_file(&recovery_file)
        .and_then(|()| sync_directory(recovery_dir.path()))
        .and_then(|()| sync_directory(parent))
    {
        let preserved = recovery_dir.keep().join("previous-version");
        engine.finish_transfer(transfer, "failed", 0, Some(&error.message))?;
        return Err(CloudError::new(
            error.kind,
            format!(
                "could not make remote recovery copy durable at {}: {}",
                preserved.display(),
                error.message
            ),
        ));
    }
    let directory = recovery_dir.keep();
    let preserved = directory.join("previous-version");
    engine.finish_transfer(transfer, "completed", size, None)?;
    Ok(preserved)
}

fn download_to_temp(
    backend: &Arc<dyn CloudBackend>,
    space: &str,
    path: &str,
    expected: &RemoteEntry,
    parent: &Path,
) -> Result<NamedTempFile, CloudError> {
    let staged = NamedTempFile::new_in(parent).map_err(io_error)?;
    let (staged, entry) =
        download_to_named_temp(backend.as_ref(), space, path, Some(&expected.etag), staged)?;
    if entry.etag != expected.etag || entry.size != expected.size {
        return Err(CloudError::new(
            ErrorKind::Conflict,
            "remote file changed while the conflict was being resolved",
        ));
    }
    if !fs::symlink_metadata(staged.path())
        .map_err(io_error)?
        .is_file()
    {
        return Err(CloudError::new(
            ErrorKind::InvalidResponse,
            "download did not publish a regular local file",
        ));
    }
    let file = open_owned_file_for_sync(staged.path()).map_err(io_error)?;
    let size = file.metadata().map_err(io_error)?.len();
    file.sync_all().map_err(io_error)?;
    if size != entry.size {
        return Err(CloudError::new(
            ErrorKind::InvalidResponse,
            "download size does not match the server response",
        ));
    }
    Ok(staged)
}

#[cfg(unix)]
fn preserve_unix_permissions(staged: &NamedTempFile, destination: &Path) -> Result<(), CloudError> {
    use std::os::unix::fs::PermissionsExt;
    let destination_metadata = fs::symlink_metadata(destination).map_err(io_error)?;
    if !destination_metadata.is_file() {
        return Err(CloudError::new(
            ErrorKind::Conflict,
            "download destination changed type before replacement",
        ));
    }
    let mode = destination_metadata.permissions().mode() & 0o777;
    if !fs::symlink_metadata(staged.path())
        .map_err(io_error)?
        .is_file()
    {
        return Err(CloudError::new(
            ErrorKind::InvalidResponse,
            "download did not publish a regular local file",
        ));
    }
    let mut permissions = fs::metadata(staged.path()).map_err(io_error)?.permissions();
    permissions.set_mode(mode);
    fs::set_permissions(staged.path(), permissions).map_err(io_error)
}

#[cfg(not(unix))]
fn preserve_unix_permissions(
    _staged: &NamedTempFile,
    _destination: &Path,
) -> Result<(), CloudError> {
    Ok(())
}

fn replace_existing_download(
    staged: NamedTempFile,
    destination: &Path,
    expected_hash: &str,
) -> Result<(), CloudError> {
    let parent = destination
        .parent()
        .ok_or_else(|| CloudError::new(ErrorKind::Io, "local destination has no parent folder"))?;
    #[cfg(windows)]
    let _parent_pin = raiun_control_windows::PinnedDirectory::open(parent).map_err(io_error)?;
    let backup_dir = TempBuilder::new()
        .prefix(".raiun-preserve-")
        .tempdir_in(parent)
        .map_err(io_error)?;
    #[cfg(windows)]
    let _backup_pin =
        raiun_control_windows::PinnedDirectory::open(backup_dir.path()).map_err(io_error)?;
    let backup = backup_dir.path().join("previous-version");

    preserve_unix_permissions(&staged, destination)?;
    sync_owned_file(staged.path())?;

    // Moving the old path into a private same-volume directory closes the
    // check/replace window. The staged download is installed with no-clobber;
    // an application that recreates the destination wins and is preserved.
    if let Err(error) = fs::rename(destination, &backup) {
        if error.kind() == std::io::ErrorKind::NotFound {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "local destination changed during sync; download was not installed",
            ));
        }
        return Err(io_error(error));
    }
    let backup_is_regular = fs::symlink_metadata(&backup)
        .map(|metadata| metadata.is_file())
        .unwrap_or(false);
    let unchanged = backup_is_regular && hash_file(&backup).is_ok_and(|hash| hash == expected_hash);
    if !unchanged {
        if !path_exists(destination)? {
            if let Err(error) = fs::rename(&backup, destination) {
                let preserved = backup_dir.keep().join("previous-version");
                return Err(CloudError::new(
                    ErrorKind::Io,
                    format!(
                        "could not restore the local file; preserved it at {}: {error}",
                        preserved.display()
                    ),
                ));
            }
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "local file changed during sync; the local version was restored",
            ));
        }
        let preserved = backup_dir.keep().join("previous-version");
        return Err(CloudError::new(
            ErrorKind::Conflict,
            format!(
                "local file changed during sync; preserved the displaced copy at {}",
                preserved.display()
            ),
        ));
    }

    match staged.persist_noclobber(destination) {
        Ok(_) => {
            // An open writer may still hold the displaced inode. If it changed
            // while the destination was installed, retain it for recovery.
            if !hash_file(&backup).is_ok_and(|hash| hash == expected_hash) {
                let preserved = backup_dir.keep().join("previous-version");
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    format!(
                        "local file changed while sync finished; preserved the displaced copy at {}",
                        preserved.display()
                    ),
                ));
            }
            Ok(())
        }
        Err(error) => {
            let reason = error.error;
            drop(error.file);
            if path_exists(destination)? {
                let preserved = backup_dir.keep().join("previous-version");
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    format!(
                        "local destination changed during sync; preserved the displaced copy at {}",
                        preserved.display()
                    ),
                ));
            }
            if let Err(restore_error) = fs::rename(&backup, destination) {
                let preserved = backup_dir.keep().join("previous-version");
                return Err(CloudError::new(
                    ErrorKind::Io,
                    format!(
                        "could not restore the local file; preserved it at {}: {restore_error}",
                        preserved.display()
                    ),
                ));
            }
            if reason.kind() == std::io::ErrorKind::AlreadyExists {
                Err(CloudError::new(
                    ErrorKind::Conflict,
                    "local destination appeared during sync; the local version was restored",
                ))
            } else {
                Err(io_error(reason))
            }
        }
    }
}

fn hash_for_remote(engine: &Engine, space: &str, path: &str) -> Result<String, CloudError> {
    let tmp = engine.unique_temp("hash")?;
    let entry = engine.backend.stat(space, path)?;
    let downloaded = engine
        .backend
        .download(space, path, Some(&entry.etag), &tmp);
    let result = downloaded.and_then(|actual| {
        if actual.etag != entry.etag || fs::metadata(&tmp).map_err(io_error)?.len() != entry.size {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "remote file changed while hashing",
            ));
        }
        hash_file(&tmp)
    });
    let _ = fs::remove_file(tmp);
    result
}

fn validate_pair_runtime(pair: &FolderPair) -> Result<(), CloudError> {
    if pair.id.trim().is_empty()
        || pair.space_id.trim().is_empty()
        || pair.remote_path.is_empty()
        || !pair.remote_path.starts_with('/')
        || pair.remote_path.contains("..")
    {
        return Err(CloudError::new(
            ErrorKind::Unsupported,
            "folder pair identity or remote path is invalid",
        ));
    }
    pair.validate_exclusions().map_err(|_| {
        CloudError::new(
            ErrorKind::Unsupported,
            "folder pair exclusion paths are invalid",
        )
    })?;
    if !pair.local_path.is_absolute() {
        return Err(CloudError::new(
            ErrorKind::Unsupported,
            "folder pair local path must be absolute",
        ));
    }
    Ok(())
}

fn remote_relative(root: &str, remote: &str) -> Result<String, CloudError> {
    let root = root.trim_end_matches('/');
    let prefix = if root.is_empty() { "/" } else { root };
    if remote == prefix {
        return Ok(String::new());
    }
    remote
        .strip_prefix(&format!("{}/", prefix.trim_end_matches('/')))
        .map(str::to_string)
        .ok_or_else(|| {
            CloudError::new(
                ErrorKind::InvalidResponse,
                "remote entry is outside pair root",
            )
        })
}

fn join_remote(root: &str, rel: &str) -> String {
    let root = root.trim_end_matches('/');
    let rel = rel.replace('\\', "/");
    if root.is_empty() {
        format!("/{rel}")
    } else {
        format!("{root}/{rel}")
    }
}
fn parent_path(path: &str) -> Result<String, CloudError> {
    if !path.starts_with('/') || path == "/" || path.ends_with('/') || path.contains('\0') {
        return Err(CloudError::new(
            ErrorKind::Unsupported,
            "cloud item path is not a canonical non-root path",
        ));
    }
    let (parent, leaf) = path
        .rsplit_once('/')
        .ok_or_else(|| CloudError::new(ErrorKind::Unsupported, "cloud item path is invalid"))?;
    if leaf.is_empty() || leaf == "." || leaf == ".." {
        return Err(CloudError::new(
            ErrorKind::Unsupported,
            "cloud item path is not a safe path",
        ));
    }
    Ok(if parent.is_empty() {
        "/".into()
    } else {
        parent.into()
    })
}
fn is_direct_child_path(parent: &str, child: &str) -> bool {
    if !child.starts_with('/') || child.ends_with('/') || child.contains('\0') {
        return false;
    }
    let prefix = if parent == "/" {
        "/".to_owned()
    } else {
        format!("{}/", parent.trim_end_matches('/'))
    };
    let Some(leaf) = child.strip_prefix(&prefix) else {
        return false;
    };
    !leaf.is_empty() && !leaf.contains('/') && leaf != "." && leaf != ".." && !leaf.contains('\\')
}
fn cache_key(space: &str, path: &str) -> String {
    hex(&Sha256::digest(format!("{space}\0{path}").as_bytes()))
}
fn hash_file(path: &Path) -> Result<String, CloudError> {
    #[cfg(windows)]
    let parent_pin = raiun_control_windows::PinnedDirectory::open(
        path.parent()
            .ok_or_else(|| CloudError::new(ErrorKind::Unsupported, "hash source has no parent"))?,
    )
    .map_err(io_error)?;
    #[cfg(windows)]
    let (mut file, _) = parent_pin
        .open_regular_file(path.file_name().ok_or_else(|| {
            CloudError::new(ErrorKind::Unsupported, "hash source has no filename")
        })?)
        .map_err(io_error)?;
    #[cfg(not(windows))]
    let mut file = File::open(path).map_err(io_error)?;
    let before = file.metadata().map_err(io_error)?;
    if !before.is_file() {
        return Err(CloudError::new(
            ErrorKind::Unsupported,
            "only regular files can be hashed",
        ));
    }
    let mut hash = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(io_error)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    let after = file.metadata().map_err(io_error)?;
    let current_path = fs::symlink_metadata(path).map_err(io_error)?;
    if !same_file(&before, &after)
        || !same_file(&after, &current_path)
        || !after.is_file()
        || after.len() != before.len()
        || after.modified().ok() != before.modified().ok()
    {
        return Err(CloudError::new(
            ErrorKind::Conflict,
            format!("file changed while hashing: {}", path.display()),
        ));
    }
    Ok(hex(&hash.finalize()))
}

fn should_force_hash_audit(generation: i64) -> bool {
    generation > 0 && generation % LOCAL_HASH_AUDIT_INTERVAL == 0
}

#[cfg(target_os = "linux")]
fn local_fingerprint(metadata: &fs::Metadata) -> Option<LocalFingerprint> {
    use std::os::unix::fs::MetadataExt;
    Some(LocalFingerprint {
        device: metadata.dev() as i64,
        inode: metadata.ino() as i64,
        size: metadata.size() as i64,
        mtime_seconds: metadata.mtime(),
        mtime_nanoseconds: metadata.mtime_nsec(),
        ctime_seconds: metadata.ctime(),
        ctime_nanoseconds: metadata.ctime_nsec(),
    })
}

#[cfg(not(target_os = "linux"))]
fn local_fingerprint(_metadata: &fs::Metadata) -> Option<LocalFingerprint> {
    None
}

#[cfg(target_os = "linux")]
fn fingerprint_supports_hash_cache(fingerprint: Option<LocalFingerprint>) -> bool {
    // ext2/ext3 may report the same statfs magic as ext4 but only second
    // resolution timestamps. Treat an observed zero ctime nanosecond field as
    // unreliable and fall back to hashing, including on whitelisted mounts.
    fingerprint.is_some_and(|value| value.ctime_nanoseconds != 0)
}

#[cfg(not(target_os = "linux"))]
fn fingerprint_supports_hash_cache(_fingerprint: Option<LocalFingerprint>) -> bool {
    false
}

#[cfg(target_os = "linux")]
fn filesystem_supports_hash_cache(path: &Path) -> bool {
    rustix::fs::statfs(path).is_ok_and(|stat| trusted_hash_cache_filesystem(stat.f_type as u32))
}

#[cfg(not(target_os = "linux"))]
fn filesystem_supports_hash_cache(_path: &Path) -> bool {
    false
}

#[cfg(target_os = "linux")]
fn trusted_hash_cache_filesystem(fs_type: u32) -> bool {
    // Linux magic values from the respective kernel filesystem headers. Keep
    // this allowlist narrow: unknown, network, FUSE, and overlay filesystems
    // always use a fresh content hash.
    matches!(fs_type, 0xEF53 | 0x9123_683E | 0x5846_5342 | 0x0102_1994)
}

fn verify_local_fingerprint(
    path: &Path,
    expected: Option<LocalFingerprint>,
) -> Result<(), CloudError> {
    if let Some(expected) = expected {
        let actual = fs::symlink_metadata(path).map_err(io_error)?;
        if !actual.is_file() || local_fingerprint(&actual) != Some(expected) {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                format!("local file changed while scanning: {}", path.display()),
            ));
        }
    }
    Ok(())
}

fn may_reuse_local_hash(
    cache_allowed: bool,
    force_full_hash: bool,
    fingerprint: Option<LocalFingerprint>,
) -> bool {
    cache_allowed && !force_full_hash && fingerprint_supports_hash_cache(fingerprint)
}

fn ensure_safe_pair_path(
    root: &Path,
    target: &Path,
    allow_missing: bool,
) -> Result<(), CloudError> {
    let canonical_root = fs::canonicalize(root).map_err(io_error)?;
    if !canonical_root.is_dir() || canonical_root != root {
        return Err(CloudError::new(
            ErrorKind::Conflict,
            "folder pair root changed identity during synchronization",
        ));
    }
    let relative = target.strip_prefix(&canonical_root).map_err(|_| {
        CloudError::new(
            ErrorKind::Unsupported,
            "local operation escaped the folder pair root",
        )
    })?;
    let mut current = canonical_root;
    for component in relative.components() {
        match component {
            std::path::Component::Normal(name) => current.push(name),
            _ => {
                return Err(CloudError::new(
                    ErrorKind::Unsupported,
                    "local path is not canonical",
                ));
            }
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) if is_link_or_reparse(&metadata) => {
                return Err(CloudError::new(
                    ErrorKind::Unsupported,
                    format!("symlink traversal is unsupported: {}", current.display()),
                ));
            }
            Ok(metadata) if current != target && !metadata.is_dir() => {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "a parent path changed from directory to file",
                ));
            }
            Ok(_) => {}
            Err(error) if allow_missing && error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(io_error(error)),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len() && left.modified().ok() == right.modified().ok()
}
fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char);
    }
    s
}
fn modified_unix(meta: &fs::Metadata) -> i64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or(0)
}
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or(0)
}
fn now_unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}
fn io_error(error: impl std::fmt::Display) -> CloudError {
    CloudError::new(ErrorKind::Io, error.to_string())
}

fn unsupported_encrypted_cache() -> CloudError {
    CloudError::new(
        ErrorKind::Unsupported,
        "encrypted cloud locations are unavailable to the ordinary cache",
    )
}

fn cache_cloud_error(error: raiun_cache::CacheError) -> CloudError {
    use raiun_cache::CacheError;
    let kind = match error {
        CacheError::Cancelled => ErrorKind::Io,
        CacheError::Conflict | CacheError::PolicyConflict => ErrorKind::Conflict,
        CacheError::NotFound | CacheError::IncompleteListing | CacheError::PinNotFound => {
            ErrorKind::NotFound
        }
        CacheError::InvalidScope
        | CacheError::InvalidEntry
        | CacheError::InvalidContentVersion
        | CacheError::ProtectionMismatch
        | CacheError::LimitExceeded
        | CacheError::Corrupt
        | CacheError::UnsafeDirectory
        | CacheError::InsufficientSpace
        | CacheError::Io(_)
        | CacheError::Database(_)
        | CacheError::IncompleteManifest => ErrorKind::Io,
    };
    CloudError::new(kind, error.to_string())
}

fn offline_cache_error(error: raiun_cache::CacheError, offline: CloudError) -> CloudError {
    match error {
        raiun_cache::CacheError::NotFound | raiun_cache::CacheError::IncompleteListing => offline,
        other => cache_cloud_error(other),
    }
}
fn db_error(error: rusqlite::Error) -> CloudError {
    CloudError::new(ErrorKind::Io, format!("engine database error: {error}"))
}

fn ensure_media_job_revision_column(db: &Connection) -> Result<(), CloudError> {
    let mut statement = db
        .prepare("PRAGMA table_info(media_upload_attempts)")
        .map_err(db_error)?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(db_error)?;
    let mut has_revision = false;
    for column in columns {
        if column.map_err(db_error)? == "job_revision" {
            has_revision = true;
            break;
        }
    }
    drop(statement);
    if !has_revision {
        db.execute_batch(
            "ALTER TABLE media_upload_attempts ADD COLUMN job_revision INTEGER NOT NULL DEFAULT 0",
        )
        .map_err(db_error)?;
    }
    db.execute_batch("PRAGMA user_version=3").map_err(db_error)
}

// Legacy attempts deliberately remain unbound: a path or current configuration
// cannot establish the destination identity used by an earlier upload.
fn ensure_media_attempt_destination_root_column(db: &Connection) -> Result<(), CloudError> {
    let mut statement = db
        .prepare("PRAGMA table_info(media_upload_attempts)")
        .map_err(db_error)?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(db_error)?;
    let mut has_root = false;
    for column in columns {
        if column.map_err(db_error)? == "destination_root_id" {
            has_root = true;
            break;
        }
    }
    drop(statement);
    if !has_root {
        db.execute_batch("ALTER TABLE media_upload_attempts ADD COLUMN destination_root_id TEXT")
            .map_err(db_error)?;
    }
    db.execute_batch("PRAGMA user_version=4").map_err(db_error)
}

#[cfg(test)]
mod tests {
    mod media_job_store_tests {
        include!("media_job_store_tests.rs");
    }
    mod folder_pair_pause_tests {
        include!("folder_pair_pause_tests.rs");
    }
    mod revocation_handle_test {
        include!("revocation_handle_test.rs");
    }
    mod folder_pair_store_tests {
        include!("folder_pair_store_tests.rs");
    }
    #[cfg(unix)]
    mod folder_cloud_only_tests {
        include!("folder_cloud_only_tests.rs");
    }
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::mpsc::{self, Receiver, SyncSender};

    #[test]
    fn media_attempt_revision_migration_is_idempotent_and_legacy_rows_are_unbound() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE media_upload_attempts (job_id TEXT NOT NULL, state TEXT NOT NULL)",
        )
        .unwrap();
        ensure_media_job_revision_column(&db).unwrap();
        ensure_media_job_revision_column(&db).unwrap();
        db.execute(
            "INSERT INTO media_upload_attempts(job_id,state) VALUES('legacy','uncertain')",
            [],
        )
        .unwrap();
        let default_revision: i64 = db
            .query_row(
                "SELECT job_revision FROM media_upload_attempts LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .unwrap()
            .unwrap_or(0);
        assert_eq!(default_revision, 0);
        let user_version: i64 = db
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(user_version, 3);
    }

    #[test]
    fn media_attempt_root_migration_preserves_legacy_uncertainty() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE media_upload_attempts (job_id TEXT NOT NULL, state TEXT NOT NULL);
             INSERT INTO media_upload_attempts VALUES('legacy','uncertain');",
        )
        .unwrap();
        ensure_media_attempt_destination_root_column(&db).unwrap();
        ensure_media_attempt_destination_root_column(&db).unwrap();
        let row: (String, Option<String>) = db
            .query_row(
                "SELECT state,destination_root_id FROM media_upload_attempts WHERE job_id='legacy'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(row, ("uncertain".into(), None));
    }

    #[derive(Default)]
    struct FakeCloud {
        entries: Mutex<BTreeMap<String, (RemoteEntry, Vec<u8>)>>,
        spaces_calls: Mutex<usize>,
        list_calls: Mutex<usize>,
        next_etag: Mutex<u64>,
        delete_calls: Mutex<usize>,
        downloads: Mutex<usize>,
        fail_download_after_write: Mutex<bool>,
        fail_listing: Mutex<bool>,
        fail_upload: Mutex<bool>,
        fail_upload_after_commit: Mutex<bool>,
        replace_root_before_scoped_upload: Mutex<bool>,
        fail_all: Mutex<Option<ErrorKind>>,
        space_encrypted: Mutex<bool>,
        spaces_override: Mutex<Option<Vec<CloudSpace>>>,
        spaces_gate: Mutex<Option<(SyncSender<()>, Receiver<()>)>>,
        list_repeat: Mutex<usize>,
        list_gate: Mutex<Option<(SyncSender<()>, Receiver<()>)>>,
    }

    impl FakeCloud {
        fn new() -> Self {
            let cloud = Self::default();
            cloud.insert_dir("/");
            cloud.insert_dir("/sync");
            cloud
        }

        fn insert_dir(&self, path: &str) {
            self.insert(path, true, Vec::new());
        }

        fn insert_file(&self, path: &str, data: &[u8]) {
            self.insert(path, false, data.to_vec());
        }

        fn replace_file(&self, path: &str, data: &[u8]) {
            let mut counter = self.next_etag.lock().expect("etag mutex");
            *counter += 1;
            let mut entries = self.entries.lock().expect("entries mutex");
            let (entry, _) = entries.get(path).expect("fixture file exists");
            assert!(!entry.directory);
            let mut updated = entry.clone();
            updated.etag = counter.to_string();
            updated.size = data.len() as u64;
            updated.modified_unix = now_unix();
            entries.insert(path.to_owned(), (updated, data.to_vec()));
        }

        fn move_prefix(&self, old: &str, new: &str) {
            let mut entries = self.entries.lock().expect("entries mutex");
            let matching = entries
                .iter()
                .filter(|(path, _)| *path == old || path.starts_with(&format!("{old}/")))
                .map(|(path, value)| (path.clone(), value.clone()))
                .collect::<Vec<_>>();
            assert!(!matching.is_empty());
            for (path, _) in &matching {
                entries.remove(path);
            }
            for (path, (mut entry, bytes)) in matching {
                let suffix = &path[old.len()..];
                let new_path = format!("{new}{suffix}");
                entry.path = new_path.clone();
                entries.insert(new_path, (entry, bytes));
            }
        }

        fn insert(&self, path: &str, directory: bool, bytes: Vec<u8>) {
            let mut counter = self.next_etag.lock().expect("etag mutex");
            *counter += 1;
            let entry = RemoteEntry {
                id: path.to_string(),
                path: path.to_string(),
                directory,
                size: bytes.len() as u64,
                etag: counter.to_string(),
                modified_unix: now_unix(),
                writable: true,
                encrypted: false,
            };
            self.entries
                .lock()
                .expect("entries mutex")
                .insert(path.to_string(), (entry, bytes));
        }

        fn bytes(&self, path: &str) -> Option<Vec<u8>> {
            self.entries
                .lock()
                .expect("entries mutex")
                .get(path)
                .map(|(_, bytes)| bytes.clone())
        }

        fn remote_entry(&self, path: &str) -> Result<RemoteEntry, CloudError> {
            self.entries
                .lock()
                .map_err(|_| CloudError::new(ErrorKind::Io, "poisoned"))?
                .get(path)
                .map(|(entry, _)| entry.clone())
                .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "not found"))
        }
    }

    impl CloudBackend for FakeCloud {
        fn server_origin(&self) -> Option<String> {
            Some("https://example.invalid".into())
        }

        fn spaces(&self) -> Result<Vec<CloudSpace>, CloudError> {
            *self
                .spaces_calls
                .lock()
                .map_err(|_| CloudError::new(ErrorKind::Io, "poisoned"))? += 1;
            if let Some(kind) = *self
                .fail_all
                .lock()
                .map_err(|_| CloudError::new(ErrorKind::Io, "poisoned"))?
            {
                return Err(CloudError::new(kind, "fixture transport unavailable"));
            }
            let spaces_gate = self
                .spaces_gate
                .lock()
                .map_err(|_| CloudError::new(ErrorKind::Io, "poisoned"))?
                .take();
            if let Some((started, release)) = spaces_gate {
                started
                    .send(())
                    .map_err(|_| CloudError::new(ErrorKind::Io, "namespace test ended"))?;
                release
                    .recv()
                    .map_err(|_| CloudError::new(ErrorKind::Io, "namespace test ended"))?;
            }
            if let Some(spaces) = self
                .spaces_override
                .lock()
                .map_err(|_| CloudError::new(ErrorKind::Io, "poisoned"))?
                .clone()
            {
                return Ok(spaces);
            }
            Ok(vec![CloudSpace {
                id: "space".into(),
                name: "Fixture".into(),
                dav_url: "https://example.invalid/dav".into(),
                personal: false,
                writable: true,
                encrypted: *self
                    .space_encrypted
                    .lock()
                    .map_err(|_| CloudError::new(ErrorKind::Io, "poisoned"))?,
            }])
        }

        fn list(
            &self,
            _space: &str,
            path: &str,
            visit: &mut dyn FnMut(RemoteEntry) -> Result<(), CloudError>,
        ) -> Result<(), CloudError> {
            *self
                .list_calls
                .lock()
                .map_err(|_| CloudError::new(ErrorKind::Io, "poisoned"))? += 1;
            if let Some(kind) = *self
                .fail_all
                .lock()
                .map_err(|_| CloudError::new(ErrorKind::Io, "poisoned"))?
            {
                return Err(CloudError::new(kind, "fixture transport unavailable"));
            }
            if *self
                .fail_listing
                .lock()
                .map_err(|_| CloudError::new(ErrorKind::Io, "poisoned"))?
            {
                return Err(CloudError::new(
                    ErrorKind::Offline,
                    "fixture listing failed",
                ));
            }
            let entries = self
                .entries
                .lock()
                .map_err(|_| CloudError::new(ErrorKind::Io, "poisoned"))?;
            let prefix = if path == "/" {
                "/".to_string()
            } else {
                format!("{}/", path.trim_end_matches('/'))
            };
            let direct = entries
                .values()
                .filter_map(|(entry, _)| {
                    let tail = entry.path.strip_prefix(&prefix)?;
                    (!tail.is_empty() && !tail.contains('/')).then(|| entry.clone())
                })
                .collect::<Vec<_>>();
            drop(entries);
            let repeat = *self
                .list_repeat
                .lock()
                .map_err(|_| CloudError::new(ErrorKind::Io, "poisoned"))?;
            if repeat > 0 {
                let entry = direct
                    .first()
                    .cloned()
                    .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "fixture entry missing"))?;
                for _ in 0..repeat {
                    visit(entry.clone())?;
                }
                return Ok(());
            }
            for entry in direct {
                visit(entry)?;
                let gate = self.list_gate.lock().expect("list gate lock").take();
                if let Some((started, resume)) = gate {
                    started
                        .send(())
                        .map_err(|_| CloudError::new(ErrorKind::Offline, "list gate closed"))?;
                    resume
                        .recv()
                        .map_err(|_| CloudError::new(ErrorKind::Offline, "list gate closed"))?;
                }
            }
            Ok(())
        }

        fn stat(&self, _space: &str, path: &str) -> Result<RemoteEntry, CloudError> {
            if let Some(kind) = *self
                .fail_all
                .lock()
                .map_err(|_| CloudError::new(ErrorKind::Io, "poisoned"))?
            {
                return Err(CloudError::new(kind, "fixture transport unavailable"));
            }
            self.remote_entry(path)
        }

        fn download(
            &self,
            _space: &str,
            path: &str,
            expected_etag: Option<&str>,
            destination: &Path,
        ) -> Result<RemoteEntry, CloudError> {
            if let Some(kind) = *self
                .fail_all
                .lock()
                .map_err(|_| CloudError::new(ErrorKind::Io, "poisoned"))?
            {
                return Err(CloudError::new(kind, "fixture transport unavailable"));
            }
            *self
                .downloads
                .lock()
                .map_err(|_| CloudError::new(ErrorKind::Io, "poisoned"))? += 1;
            let (entry, bytes) = self
                .entries
                .lock()
                .map_err(|_| CloudError::new(ErrorKind::Io, "poisoned"))?
                .get(path)
                .cloned()
                .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "not found"))?;
            if expected_etag.is_some_and(|etag| etag != entry.etag) {
                return Err(CloudError::new(ErrorKind::Conflict, "revision changed"));
            }
            fs::write(destination, bytes).map_err(io_error)?;
            if *self
                .fail_download_after_write
                .lock()
                .map_err(|_| CloudError::new(ErrorKind::Io, "poisoned"))?
            {
                return Err(CloudError::new(
                    ErrorKind::Offline,
                    "fixture download failed after writing staged bytes",
                ));
            }
            Ok(entry)
        }

        fn upload(
            &self,
            _space: &str,
            path: &str,
            source: &Path,
            condition: WriteCondition,
        ) -> Result<RemoteEntry, CloudError> {
            if *self
                .fail_upload
                .lock()
                .map_err(|_| CloudError::new(ErrorKind::Io, "poisoned"))?
            {
                return Err(CloudError::new(ErrorKind::Offline, "fixture upload failed"));
            }
            let current = self.remote_entry(path).ok();
            match condition {
                WriteCondition::Absent if current.is_some() => {
                    return Err(CloudError::new(ErrorKind::Conflict, "already exists"));
                }
                WriteCondition::Match(ref etag)
                    if current.as_ref().is_none_or(|entry| &entry.etag != etag) =>
                {
                    return Err(CloudError::new(ErrorKind::Conflict, "revision changed"));
                }
                _ => {}
            }
            let bytes = fs::read(source).map_err(io_error)?;
            self.insert_file(path, &bytes);
            if *self.fail_upload_after_commit.lock().unwrap() {
                return Err(CloudError::new(
                    ErrorKind::Offline,
                    "fixture lost upload acknowledgement",
                ));
            }
            self.remote_entry(path)
        }

        fn upload_in_root(
            &self,
            space: &str,
            path: &str,
            source: &Path,
            condition: WriteCondition,
            expected_root: &str,
        ) -> Result<RemoteEntry, CloudError> {
            if *self.replace_root_before_scoped_upload.lock().unwrap() {
                self.entries.lock().unwrap().get_mut("/").unwrap().0.id = "replacement-root".into();
            }
            if self.remote_entry("/")?.id != expected_root {
                return Err(CloudError::new(ErrorKind::Conflict, "fixture root changed"));
            }
            self.upload(space, path, source, condition)
        }
        fn download_in_root(
            &self,
            space: &str,
            path: &str,
            etag: Option<&str>,
            destination: &Path,
            expected_root: &str,
        ) -> Result<RemoteEntry, CloudError> {
            if self.remote_entry("/")?.id != expected_root {
                return Err(CloudError::new(ErrorKind::Conflict, "fixture root changed"));
            }
            self.download(space, path, etag, destination)
        }
        fn mkdir(&self, _space: &str, path: &str) -> Result<RemoteEntry, CloudError> {
            self.insert_dir(path);
            self.remote_entry(path)
        }

        fn delete(&self, _space: &str, path: &str, expected_etag: &str) -> Result<(), CloudError> {
            let entry = self.remote_entry(path)?;
            if entry.etag != expected_etag {
                return Err(CloudError::new(ErrorKind::Conflict, "revision changed"));
            }
            *self
                .delete_calls
                .lock()
                .map_err(|_| CloudError::new(ErrorKind::Io, "poisoned"))? += 1;
            self.entries
                .lock()
                .map_err(|_| CloudError::new(ErrorKind::Io, "poisoned"))?
                .remove(path);
            Ok(())
        }

        fn rename(
            &self,
            _space: &str,
            from: &str,
            to: &str,
            expected_etag: &str,
        ) -> Result<RemoteEntry, CloudError> {
            let mut entries = self
                .entries
                .lock()
                .map_err(|_| CloudError::new(ErrorKind::Io, "poisoned"))?;
            let (mut entry, bytes) = entries
                .get(from)
                .cloned()
                .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "not found"))?;
            if entry.etag != expected_etag || entries.contains_key(to) {
                return Err(CloudError::new(ErrorKind::Conflict, "rename conflict"));
            }
            entries.remove(from);
            entry.path = to.into();
            entry.id = to.into();
            *self
                .next_etag
                .lock()
                .map_err(|_| CloudError::new(ErrorKind::Io, "poisoned"))? += 1;
            entry.etag = self
                .next_etag
                .lock()
                .map_err(|_| CloudError::new(ErrorKind::Io, "poisoned"))?
                .to_string();
            entries.insert(to.into(), (entry.clone(), bytes));
            Ok(entry)
        }
    }

    #[test]
    fn failed_download_cleans_up_owned_temporary_path() {
        let cloud = FakeCloud::new();
        cloud.insert_file("/sync/file.txt", b"staged bytes");
        *cloud
            .fail_download_after_write
            .lock()
            .expect("download failure mutex") = true;
        let directory = tempfile::tempdir().expect("temporary directory");
        let staged = NamedTempFile::new_in(directory.path()).expect("staged temp file");
        let path = staged.path().to_path_buf();

        let result = download_to_named_temp(&cloud, "space", "/sync/file.txt", None, staged);

        assert!(result.is_err(), "the fixture download should fail");
        assert!(
            !path.exists(),
            "failed download should clean up its staged path"
        );
    }

    fn setup() -> (
        tempfile::TempDir,
        tempfile::TempDir,
        Arc<FakeCloud>,
        Engine,
        FolderPair,
    ) {
        let state = tempfile::tempdir().expect("state dir");
        let local_parent = tempfile::tempdir().expect("local parent");
        let local = local_parent.path().join("pair");
        fs::create_dir_all(&local).expect("local root");
        let cloud = Arc::new(FakeCloud::new());
        let engine = Engine::open(state.path(), cloud.clone()).expect("open engine");
        let pair = FolderPair {
            id: "pair".into(),
            local_path: local,
            space_id: "space".into(),
            vault: None,
            remote_path: "/sync".into(),
            mode: SyncMode::TwoWay,
            excluded_paths: Vec::new(),
            content_filter: raiun_core::MediaFilter::All,
            exclusions: Vec::new(),
        };
        (state, local_parent, cloud, engine, pair)
    }

    #[test]
    fn published_pair_policy_fences_stale_sync_and_retired_ids() {
        let (_state, _local, _cloud, engine, pair) = setup();
        engine
            .publish_pair_policy(&pair)
            .expect("publish initial policy");

        let mut updated = pair.clone();
        updated.excluded_paths = vec!["private/cache".into()];
        updated.content_filter = MediaFilter::Photos;
        updated.exclusions = vec![FolderExclusion {
            kind: raiun_core::FolderExclusionKind::Path,
            pattern: "private/**/secret?.txt".into(),
        }];

        // Dropping a prepared policy models settings persistence failure: no
        // new exclusion is published and the prior snapshot stays runnable.
        drop(
            engine
                .prepare_pair_policy(&updated)
                .expect("prepare policy"),
        );
        engine
            .sync_pair(&pair)
            .expect("old policy remains after failed persistence");

        engine
            .prepare_pair_policy(&updated)
            .expect("prepare policy")
            .publish();
        assert_eq!(
            engine.sync_pair(&pair).unwrap_err().kind,
            ErrorKind::Conflict,
            "an old queued pair snapshot must not dispatch after publication"
        );
        engine
            .sync_pair(&updated)
            .expect("the durably published policy is dispatchable");

        engine
            .prepare_pair_retirement(&pair.id)
            .expect("prepare retirement")
            .publish();
        assert_eq!(
            engine.sync_pair(&updated).unwrap_err().kind,
            ErrorKind::Conflict,
            "a delayed snapshot cannot reactivate a removed pair"
        );
        assert!(
            engine.publish_pair_policy(&updated).is_err(),
            "retired pair IDs cannot be explicitly published again"
        );
    }

    #[test]
    fn encrypted_pairs_require_exact_backend_binding_and_share_pause_state() {
        let (_state, _local, cloud, engine, mut pair) = setup();
        let binding = VaultBinding {
            root_path: "/Synthetic.vault".into(),
            root_resource_id: "vault-id".into(),
        };
        pair.vault = Some(binding.clone());
        assert!(engine.sync_pair(&pair).is_err());
        assert!(engine.conflicts(&pair, None, 10).is_err());
        let encrypted = engine.with_vault_backend(pair.space_id.clone(), binding, cloud);
        assert!(encrypted.sync_pair(&pair).is_ok());
        engine.set_sync_paused(true);
        assert!(encrypted.sync_pair(&pair).is_err());
        engine.set_sync_paused(false);
        assert!(encrypted.sync_pair(&pair).is_ok());
        pair.vault.as_mut().unwrap().root_resource_id = "replacement-vault".into();
        assert!(encrypted.sync_pair(&pair).is_err());
        pair.vault = None;
        assert!(encrypted.sync_pair(&pair).is_err());
    }

    #[test]
    fn excluded_changes_preserve_both_copies_and_baseline_until_reincluded() {
        let (_state, _parent, cloud, engine, mut pair) = setup();
        let nested = pair.local_path.join("nested");
        fs::create_dir(&nested).expect("nested directory");
        let local_file = nested.join("shared.txt");
        fs::write(&local_file, b"baseline").expect("initial local file");
        let initial = engine.sync_pair(&pair).expect("initial sync");
        assert!(initial.uploaded >= 2);
        assert_eq!(cloud.bytes("/sync/nested/shared.txt").unwrap(), b"baseline");
        let baseline = engine
            .baseline(&pair.id, "nested/shared.txt")
            .expect("read baseline")
            .expect("initial baseline");

        fs::write(&local_file, b"local edit").expect("edit local file");
        cloud.replace_file("/sync/nested/shared.txt", b"remote edit");
        pair.excluded_paths = vec!["nested".into()];
        engine
            .publish_pair_policy(&pair)
            .expect("publish exclusion policy before sync");
        let excluded = engine.sync_pair(&pair).expect("excluded sync");
        assert_eq!(excluded.uploaded, 0);
        assert_eq!(excluded.downloaded, 0);
        assert_eq!(excluded.conflicts, 0);
        assert_eq!(fs::read(&local_file).unwrap(), b"local edit");
        assert_eq!(
            cloud.bytes("/sync/nested/shared.txt").unwrap(),
            b"remote edit"
        );
        assert_eq!(*cloud.delete_calls.lock().unwrap(), 0);
        let excluded_baseline = engine
            .baseline(&pair.id, "nested/shared.txt")
            .unwrap()
            .expect("excluded baseline remains available");
        assert_eq!(excluded_baseline.local_hash, baseline.local_hash);
        assert_eq!(excluded_baseline.remote_etag, baseline.remote_etag);

        pair.excluded_paths.clear();
        engine
            .publish_pair_policy(&pair)
            .expect("publish re-inclusion before sync");
        let included = engine.sync_pair(&pair).expect("reconcile after inclusion");
        assert_eq!(included.conflicts, 1);
        assert_eq!(fs::read(&local_file).unwrap(), b"local edit");
        assert_eq!(
            cloud.bytes("/sync/nested/shared.txt").unwrap(),
            b"remote edit"
        );
        assert_eq!(*cloud.delete_calls.lock().unwrap(), 0);
    }

    #[test]
    fn media_filter_preserves_filtered_files_and_their_reconciliation_baseline() {
        let (_state, _parent, cloud, engine, mut pair) = setup();
        let local_file = pair.local_path.join("notes.txt");
        fs::write(&local_file, b"original").expect("write source");
        engine.sync_pair(&pair).expect("initial upload");
        assert_eq!(cloud.bytes("/sync/notes.txt").unwrap(), b"original");
        let baseline = engine.baseline(&pair.id, "notes.txt").unwrap().unwrap();

        fs::write(&local_file, b"local edit").expect("edit source");
        cloud.replace_file("/sync/notes.txt", b"remote edit");
        pair.content_filter = MediaFilter::Photos;
        engine.publish_pair_policy(&pair).expect("publish filter");
        let report = engine.sync_pair(&pair).expect("filtered sync");
        assert_eq!(report.uploaded, 0);
        assert_eq!(report.downloaded, 0);
        assert_eq!(report.conflicts, 0);
        assert_eq!(fs::read(&local_file).unwrap(), b"local edit");
        assert_eq!(cloud.bytes("/sync/notes.txt").unwrap(), b"remote edit");
        let retained = engine.baseline(&pair.id, "notes.txt").unwrap().unwrap();
        assert_eq!(retained.local_hash, baseline.local_hash);
        assert_eq!(retained.remote_etag, baseline.remote_etag);
    }

    #[test]
    fn media_filters_keep_directories_traversable_in_both_directions() {
        let (_state, _parent, cloud, engine, mut pair) = setup();
        let photo_dir = pair.local_path.join("albums/2024");
        fs::create_dir_all(&photo_dir).expect("create nested local folders");
        fs::write(photo_dir.join("photo.JPG"), b"photo bytes").expect("write photo");
        pair.content_filter = MediaFilter::Photos;
        engine
            .publish_pair_policy(&pair)
            .expect("publish photo filter");
        let upload = engine.sync_pair(&pair).expect("sync nested photo");
        assert!(upload.uploaded >= 1);
        assert_eq!(
            cloud.bytes("/sync/albums/2024/photo.JPG").unwrap(),
            b"photo bytes"
        );

        let (_state2, _parent2, cloud2, engine2, mut pair2) = setup();
        cloud2.insert_dir("/sync/downloads");
        cloud2.insert_dir("/sync/downloads/2026");
        cloud2.insert_file("/sync/downloads/2026/clip.MP4", b"video bytes");
        pair2.content_filter = MediaFilter::Videos;
        engine2
            .publish_pair_policy(&pair2)
            .expect("publish video filter");
        let download = engine2.sync_pair(&pair2).expect("sync nested video");
        assert!(download.downloaded >= 1);
        assert_eq!(
            fs::read(pair2.local_path.join("downloads/2026/clip.MP4")).unwrap(),
            b"video bytes"
        );
    }

    #[test]
    fn cached_namespace_is_used_only_for_transport_offline_and_read_only() {
        let (_state, _local, cloud, engine, _pair) = setup();
        let engine = engine
            .with_account_scope("profile-a".into(), "https://example.invalid".into())
            .expect("bind account scope");
        let snapshot = CloudSpace {
            id: "cached-space".into(),
            name: "Last known Space".into(),
            dav_url: "https://example.invalid/remote.php/dav/spaces/cached-space/".into(),
            personal: true,
            writable: true,
            encrypted: false,
        };
        let engine = engine
            .with_offline_spaces(vec![snapshot.clone()])
            .expect("attach matching snapshot");

        // A live response always wins over the snapshot.
        assert_eq!(engine.spaces().unwrap()[0].id, "space");
        *cloud.fail_all.lock().expect("failure mutex") = Some(ErrorKind::Offline);
        let spaces = engine.spaces().expect("offline snapshot");
        assert_eq!(
            spaces,
            vec![CloudSpace {
                writable: false,
                ..snapshot
            }]
        );
        assert_eq!(
            engine.live_spaces().unwrap_err().kind,
            ErrorKind::Offline,
            "live-only probes must never use the offline snapshot"
        );

        // Authentication and authorization failures are not transport
        // outages, so stale namespace metadata must not conceal them.
        for kind in [ErrorKind::Forbidden, ErrorKind::InvalidResponse] {
            *cloud.fail_all.lock().expect("failure mutex") = Some(kind);
            assert_eq!(
                engine.probe_live_namespace().unwrap_err().kind,
                kind,
                "a bounded recovery probe must distinguish non-transport failures"
            );
            assert_eq!(engine.spaces().unwrap_err().kind, kind);
        }

        *cloud.fail_all.lock().expect("failure mutex") = Some(ErrorKind::Offline);
        let rebound = engine
            .with_account_scope("profile-b".into(), "https://example.invalid".into())
            .expect("bind another profile");
        assert_eq!(
            rebound.spaces().unwrap_err().kind,
            ErrorKind::Offline,
            "a namespace snapshot must not cross profile identities"
        );
    }

    #[test]
    fn published_mount_permissions_follow_validated_identity_and_revocation() {
        let (_state, _local, cloud, engine, _pair) = setup();
        let engine = engine
            .with_account_scope("profile-a".into(), "https://example.invalid".into())
            .unwrap();
        let mounted = engine.spaces().unwrap()[0].clone();
        let clone = engine.clone();
        assert_eq!(clone.published_mount_permission(&mounted), None);
        let publish = |spaces| {
            *cloud.spaces_override.lock().unwrap() = Some(spaces);
            engine
                .publish_live_namespace(engine.probe_live_namespace().unwrap())
                .unwrap();
        };
        publish(vec![mounted.clone()]);
        assert_eq!(clone.published_mount_permission(&mounted), Some(true));
        *cloud.fail_all.lock().unwrap() = Some(ErrorKind::Offline);
        assert!(engine.probe_live_namespace().is_err());
        assert_eq!(clone.published_mount_permission(&mounted), Some(true));
        *cloud.fail_all.lock().unwrap() = Some(ErrorKind::Forbidden);
        assert!(engine.probe_live_namespace().is_err());
        assert_eq!(clone.published_mount_permission(&mounted), Some(false));
        *cloud.fail_all.lock().unwrap() = None;
        publish(vec![mounted.clone()]);
        *cloud.spaces_override.lock().unwrap() = Some(Vec::new());
        assert_eq!(
            engine.probe_live_namespace().unwrap_err().kind,
            ErrorKind::InvalidResponse
        );
        assert_eq!(clone.published_mount_permission(&mounted), Some(false));
        publish(vec![mounted.clone()]);
        engine
            .reject_live_namespace(engine.probe_live_namespace().unwrap())
            .unwrap();
        assert_eq!(clone.published_mount_permission(&mounted), Some(false));
        publish(vec![mounted.clone()]);
        let mut revoked = mounted.clone();
        revoked.writable = false;
        publish(vec![revoked]);
        assert_eq!(clone.published_mount_permission(&mounted), Some(false));
        for change in 0..3 {
            let mut replaced = mounted.clone();
            match change {
                0 => replaced.dav_url.push_str("different/"),
                1 => replaced.encrypted = !replaced.encrypted,
                _ => replaced.personal = !replaced.personal,
            }
            publish(vec![replaced]);
            assert_eq!(clone.published_mount_permission(&mounted), Some(false));
        }
        let mut other = mounted.clone();
        other.id = "different-space".into();
        publish(vec![other]);
        assert_eq!(clone.published_mount_permission(&mounted), Some(false));
        publish(vec![mounted.clone()]);
        let rebound = engine
            .clone()
            .with_account_scope("profile-a".into(), "https://example.invalid".into())
            .unwrap();
        assert_eq!(rebound.published_mount_permission(&mounted), None);
        let foreign = engine.probe_live_namespace().unwrap();
        assert!(rebound.publish_live_namespace(foreign).is_err());
        assert_eq!(rebound.published_mount_permission(&mounted), None);
    }

    #[test]
    fn refreshed_namespace_updates_only_clones_of_the_same_account_engine() {
        let (_state, _local, cloud, engine, _pair) = setup();
        let engine = engine
            .with_account_scope("profile-a".into(), "https://example.invalid".into())
            .expect("bind account scope");
        let initial = engine.spaces().expect("initial live namespace");
        let engine = engine
            .with_offline_spaces(initial)
            .expect("attach initial fallback");
        let mounted_clone = engine.clone();

        let replacement = CloudSpace {
            id: "refreshed-space".into(),
            name: "Refreshed Space".into(),
            dav_url: "https://example.invalid/remote.php/dav/refreshed/".into(),
            personal: false,
            writable: true,
            encrypted: false,
        };
        *cloud
            .spaces_override
            .lock()
            .expect("namespace override lock") = Some(vec![replacement.clone()]);
        let proof = engine.probe_live_namespace().expect("probe live namespace");
        assert_eq!(proof.spaces(), std::slice::from_ref(&replacement));
        assert_eq!(
            mounted_clone
                .publish_live_namespace(proof)
                .expect("publish to the same account handle"),
            vec![replacement.clone()]
        );

        // A refresh failure does not replace the last verified live snapshot.
        *cloud.fail_all.lock().expect("failure mutex") = Some(ErrorKind::Forbidden);
        assert_eq!(
            engine.probe_live_namespace().unwrap_err().kind,
            ErrorKind::Forbidden
        );

        // A probe already in flight supersedes an earlier proof before that
        // proof can publish, even while the newer network request is blocked.
        *cloud.fail_all.lock().expect("failure mutex") = None;
        let older_proof = engine.probe_live_namespace().expect("older probe");
        let (started_tx, started_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        *cloud.spaces_gate.lock().expect("space gate lock") = Some((started_tx, release_rx));
        let probing_engine = engine.clone();
        let newer_probe = std::thread::spawn(move || probing_engine.probe_live_namespace());
        started_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("newer probe reached live backend");
        assert_eq!(
            engine.publish_live_namespace(older_proof).unwrap_err().kind,
            ErrorKind::Conflict
        );
        release_tx.send(()).expect("release newer probe");
        let newer_proof = newer_probe
            .join()
            .expect("newer probe thread")
            .expect("newer live namespace proof");
        engine
            .publish_live_namespace(newer_proof)
            .expect("publish newest probe");
        let foreign_proof = engine.probe_live_namespace().expect("foreign proof");

        *cloud.fail_all.lock().expect("failure mutex") = Some(ErrorKind::Offline);
        let mounted_spaces = mounted_clone
            .spaces()
            .expect("mounted Engine clone sees refreshed fallback");
        assert_eq!(mounted_spaces[0].id, "refreshed-space");
        assert!(!mounted_spaces[0].writable);

        // Rebinding creates a fresh authority handle, even with identical
        // visible labels and backend. The old fallback cannot cross it.
        let rebound = engine
            .with_account_scope("profile-a".into(), "https://example.invalid".into())
            .expect("same-label account rebind");
        assert_eq!(rebound.spaces().unwrap_err().kind, ErrorKind::Offline);
        assert_eq!(
            rebound
                .publish_live_namespace(foreign_proof)
                .unwrap_err()
                .kind,
            ErrorKind::Conflict,
            "a proof from the previous handle cannot publish after rebind"
        );

        let cache_dir = tempfile::tempdir().expect("create private cache directory");
        #[cfg(unix)]
        fs::set_permissions(
            cache_dir.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("make cache directory private");
        let cache = Cache::open(cache_dir.path(), 1024 * 1024).expect("open fresh cache");
        let cache_rebound = engine
            .with_offline_cache(cache, "profile-a".into(), "https://example.invalid".into())
            .expect("rebind cache identity");
        assert_eq!(cache_rebound.spaces().unwrap_err().kind, ErrorKind::Offline);

        let vault_rebound = engine.with_vault_backend(
            "space".into(),
            VaultBinding {
                root_path: "/Encrypted.vault".into(),
                root_resource_id: "vault-root".into(),
            },
            cloud,
        );
        assert_eq!(vault_rebound.spaces().unwrap_err().kind, ErrorKind::Offline);
    }

    #[test]
    fn cached_namespace_requires_the_bound_account_and_server_origin() {
        let (_state, _local, _cloud, engine, _pair) = setup();
        let snapshot = CloudSpace {
            id: "cached-space".into(),
            name: "Last known Space".into(),
            dav_url: "https://example.invalid/dav/".into(),
            personal: false,
            writable: false,
            encrypted: false,
        };
        assert!(
            engine
                .clone()
                .with_offline_spaces(vec![snapshot.clone()])
                .is_err()
        );

        let account_engine = engine
            .with_account_scope("profile-a".into(), "https://example.invalid".into())
            .expect("bind matching account");
        let foreign = CloudSpace {
            dav_url: "https://elsewhere.invalid/dav/".into(),
            ..snapshot.clone()
        };
        assert!(account_engine.with_offline_spaces(vec![foreign]).is_err());
        assert!(
            account_engine
                .with_offline_spaces(vec![snapshot.clone(), snapshot])
                .is_err()
        );
        assert!(
            engine
                .with_account_scope("profile-a".into(), "https://elsewhere.invalid".into())
                .is_err()
        );
    }

    #[test]
    fn engine_accepts_the_persisted_namespace_size_limits() {
        let (_state, _local, cloud, engine, _pair) = setup();
        let engine = engine
            .with_account_scope("profile-a".into(), "https://example.invalid".into())
            .expect("bind account scope");
        let spaces = (0..257)
            .map(|index| CloudSpace {
                id: if index == 0 {
                    "i".repeat(600)
                } else {
                    format!("space-{index}")
                },
                name: if index == 1 {
                    "n".repeat(1500)
                } else {
                    format!("Space {index}")
                },
                dav_url: if index == 2 {
                    format!("https://example.invalid/{}", "d".repeat(5000))
                } else {
                    format!("https://example.invalid/dav/{index}")
                },
                personal: false,
                writable: true,
                encrypted: false,
            })
            .collect::<Vec<_>>();
        engine
            .with_offline_spaces(spaces)
            .expect("Engine limits match persisted namespace bounds");
        *cloud.fail_all.lock().expect("failure mutex") = Some(ErrorKind::Offline);
        assert_eq!(
            engine.spaces().expect("offline namespace").len(),
            257,
            "snapshots above the old in-memory cap remain usable after restart"
        );
    }

    #[cfg(target_os = "linux")]
    fn scan_local_with_cache_override(
        engine: &Engine,
        pair: &FolderPair,
        allow_cache: bool,
        force_full_hash: bool,
    ) -> Result<LocalScanMetrics, CloudError> {
        engine.clear_stage(&pair.id)?;
        let mut scanned_entries = 0;
        engine.scan_local(
            pair,
            &mut scanned_entries,
            force_full_hash,
            Some(allow_cache),
        )
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn local_hash_cache_survives_engine_restart() {
        let (state, _parent, cloud, engine, pair) = setup();
        let file = pair.local_path.join("photo.bin");
        fs::write(&file, b"unchanged photo bytes").expect("write file");
        let first = scan_local_with_cache_override(&engine, &pair, true, false).unwrap();
        assert_eq!(first.hashed_files, 1);
        assert_eq!(first.reused_hashes, 0);
        drop(engine);

        let restarted = Engine::open(state.path(), cloud).expect("reopen engine");
        let second = scan_local_with_cache_override(&restarted, &pair, true, false).unwrap();
        assert_eq!(second.hashed_files, 0);
        assert_eq!(second.reused_hashes, 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn local_hash_cache_detects_same_size_edit_with_restored_mtime() {
        use std::fs::FileTimes;

        let (_state, _parent, _cloud, engine, pair) = setup();
        let file = pair.local_path.join("same-size.bin");
        fs::write(&file, b"before").expect("write original");
        scan_local_with_cache_override(&engine, &pair, true, false).unwrap();
        let original_modified = fs::metadata(&file)
            .expect("metadata")
            .modified()
            .expect("mtime");
        std::thread::sleep(std::time::Duration::from_millis(10));
        fs::write(&file, b"after!").expect("write edited");
        File::open(&file)
            .expect("open edited")
            .set_times(FileTimes::new().set_modified(original_modified))
            .expect("restore mtime");

        let metrics = scan_local_with_cache_override(&engine, &pair, true, false).unwrap();
        assert_eq!(metrics.hashed_files, 1);
        assert_eq!(metrics.reused_hashes, 0);
        assert_eq!(
            engine
                .local_stage(&pair.id, "same-size.bin")
                .unwrap()
                .unwrap()
                .hash,
            hash_file(&file).unwrap()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn local_hash_cache_detects_atomic_inode_replacement() {
        use std::os::unix::fs::MetadataExt;

        let (_state, _parent, _cloud, engine, pair) = setup();
        let file = pair.local_path.join("replace.bin");
        let temp = pair.local_path.join("replacement.tmp");
        fs::write(&file, b"stable bytes").expect("write original");
        let original_inode = fs::metadata(&file).expect("original metadata").ino();
        scan_local_with_cache_override(&engine, &pair, true, false).unwrap();
        fs::write(&temp, b"stable bytes").expect("write replacement");
        fs::rename(&temp, &file).expect("replace file atomically");
        assert_ne!(
            fs::metadata(&file).expect("replacement metadata").ino(),
            original_inode
        );

        let metrics = scan_local_with_cache_override(&engine, &pair, true, false).unwrap();
        assert_eq!(metrics.hashed_files, 1);
        assert_eq!(metrics.reused_hashes, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn failed_local_scan_does_not_prune_hash_cache_rows() {
        use std::os::unix::fs::symlink;

        let (_state, _parent, _cloud, engine, pair) = setup();
        fs::write(pair.local_path.join("stale.bin"), b"cached").expect("write stale");
        fs::write(pair.local_path.join("kept.bin"), b"also cached").expect("write kept");
        scan_local_with_cache_override(&engine, &pair, true, false).unwrap();
        fs::remove_file(pair.local_path.join("stale.bin")).expect("remove stale");
        symlink(
            pair.local_path.join("kept.bin"),
            pair.local_path.join("bad-link"),
        )
        .expect("create symlink");

        assert_eq!(
            scan_local_with_cache_override(&engine, &pair, true, false)
                .unwrap_err()
                .kind,
            ErrorKind::Unsupported
        );
        let still_cached: bool = engine
            .db()
            .unwrap()
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM local_hash_cache WHERE pair_id=?1 AND rel_path='stale.bin')",
                [&pair.id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(still_cached);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn conflict_scans_force_fresh_local_hashes_even_with_cache_entries() {
        let (_state, _parent, _cloud, engine, pair) = setup();
        fs::write(pair.local_path.join("conflict.bin"), b"content").expect("write file");
        scan_local_with_cache_override(&engine, &pair, true, false).unwrap();
        let metrics = scan_local_with_cache_override(&engine, &pair, true, true).unwrap();
        assert_eq!(metrics.hashed_files, 1);
        assert_eq!(metrics.reused_hashes, 0);
    }

    #[test]
    fn engine_list_stops_at_its_bounded_entry_limit() {
        let (_state, _parent, cloud, engine, _pair) = setup();
        cloud.insert_file("/sync/entry.txt", b"x");
        *cloud.list_repeat.lock().expect("repeat") = MAX_LIST_ENTRIES + 1;
        let error = engine.list("space", "/sync").unwrap_err();
        assert_eq!(error.kind, ErrorKind::InvalidResponse);
        assert!(error.message.contains("100,000-entry limit"));
    }

    #[test]
    fn staged_path_batches_merge_both_indexed_sides_without_gaps() {
        let (_state, _parent, _cloud, engine, _pair) = setup();
        {
            let db = engine.db().expect("database");
            for index in 0..600 {
                let local_path = format!("/local/{index:06}");
                db.execute(
                    "INSERT INTO local_stage(pair_id,rel_path,local_path,size,mtime,hash,directory) VALUES('pair',?1,?2,0,0,'',0)",
                    params![format!("item-{index:06}"), local_path],
                )
                .expect("seed local path");
                if index >= 300 {
                    db.execute(
                        "INSERT INTO remote_stage(pair_id,rel_path,remote_path,etag,size,directory) VALUES('pair',?1,?2,'etag',0,0)",
                        params![format!("item-{index:06}"), format!("/remote/{index:06}")],
                    )
                    .expect("seed remote path");
                }
                if index < 300 {
                    db.execute(
                        "INSERT INTO remote_stage(pair_id,rel_path,remote_path,etag,size,directory) VALUES('pair',?1,?2,'etag',0,0)",
                        params![format!("item-{:06}", index + 600), format!("/remote/{:06}", index + 600)],
                    )
                    .expect("seed remote-only path");
                }
            }
        }
        let mut all = Vec::new();
        let mut after = None;
        loop {
            let batch = engine
                .staged_path_batch("pair", after.as_deref())
                .expect("staged batch");
            if batch.is_empty() {
                break;
            }
            after = batch.last().cloned();
            all.extend(batch);
        }
        let expected: Vec<_> = (0..900).map(|index| format!("item-{index:06}")).collect();
        assert_eq!(all, expected);
    }

    #[test]
    fn staged_path_branch_queries_use_keyset_indexes_without_temp_sort() {
        let (_state, _parent, _cloud, engine, _pair) = setup();
        let db = engine.db().expect("database");
        for table in ["local_stage", "remote_stage"] {
            let query = format!(
                "EXPLAIN QUERY PLAN SELECT rel_path FROM {table} WHERE pair_id=?1 AND rel_path>?2 ORDER BY rel_path LIMIT 256"
            );
            let mut statement = db.prepare(&query).expect("query plan");
            let rows = statement
                .query_map(params!["pair", ""], |row| row.get::<_, String>(3))
                .expect("plan rows");
            let details = rows.map(|row| row.expect("plan row")).collect::<Vec<_>>();
            let detail = details.join("; ");
            assert!(detail.contains("USING COVERING INDEX"), "{table}: {detail}");
            assert!(
                detail.contains("pair_id=? AND rel_path>?"),
                "{table}: {detail}"
            );
            assert!(!detail.contains("TEMP B-TREE"), "{table}: {detail}");
        }
    }

    #[test]
    fn pause_during_remote_listing_stops_writes_and_can_resume() {
        let state = tempfile::tempdir().expect("state dir");
        let local_parent = tempfile::tempdir().expect("local parent");
        let local = local_parent.path().join("pair");
        fs::create_dir(&local).expect("local root");
        fs::write(local.join("local.txt"), b"local bytes").expect("local fixture");
        let cloud = Arc::new(FakeCloud::new());
        cloud.insert_file("/sync/remote.txt", b"remote bytes");
        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let (resume_tx, resume_rx) = mpsc::sync_channel(1);
        *cloud.list_gate.lock().expect("list gate lock") = Some((started_tx, resume_rx));
        let engine = Engine::open(state.path(), cloud.clone()).expect("open engine");
        let pair = FolderPair {
            id: "pause-test".into(),
            local_path: local,
            space_id: "space".into(),
            vault: None,
            remote_path: "/sync".into(),
            mode: SyncMode::TwoWay,
            excluded_paths: Vec::new(),
            content_filter: raiun_core::MediaFilter::All,
            exclusions: Vec::new(),
        };
        let sync_engine = engine.clone();
        let sync_pair = pair.clone();
        let worker = std::thread::spawn(move || sync_engine.sync_pair(&sync_pair));
        started_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("remote list reached pause gate");
        engine.set_sync_paused(true);
        resume_tx.send(()).expect("release remote list");
        let error = worker
            .join()
            .expect("sync worker panicked")
            .expect_err("paused sync should stop");
        assert_eq!(error.kind, ErrorKind::Unsupported);
        assert_eq!(error.message, "Folder sync paused");
        assert!(cloud.bytes("/sync/local.txt").is_none());

        engine.set_sync_paused(false);
        let report = engine.sync_pair(&pair).expect("resumed sync");
        assert_eq!(report.uploaded, 1);
        assert_eq!(report.downloaded, 1);
        assert_eq!(
            cloud.bytes("/sync/local.txt").as_deref(),
            Some(&b"local bytes"[..])
        );
    }

    #[cfg(unix)]
    #[test]
    fn sync_owned_read_only_file_does_not_require_write_access() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("read-only");
        fs::write(&path, b"durable recovery contents").expect("write fixture");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).expect("make read-only");

        sync_owned_file(&path).expect("sync read-only owned file");

        assert_eq!(
            fs::read(&path).expect("read fixture"),
            b"durable recovery contents"
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o444
        );
    }

    #[test]
    fn verified_snapshots_are_readable_and_removed_after_each_open() {
        let (_state, _parent, cloud, engine, _pair) = setup();
        cloud.insert_file("/sync/read-me.txt", b"snapshot contents");
        for _ in 0..20 {
            let mut snapshot = engine
                .fetch_snapshot("space", "/sync/read-me.txt")
                .expect("verified snapshot");
            let mut body = Vec::new();
            snapshot.read_to_end(&mut body).expect("read snapshot");
            assert_eq!(body, b"snapshot contents");
            assert_eq!(fs::read_dir(engine.cache_dir()).unwrap().count(), 1);
            drop(snapshot);
            assert_eq!(fs::read_dir(engine.cache_dir()).unwrap().count(), 0);
        }
    }

    #[test]
    fn ordinary_listing_and_verified_content_survive_restart_for_transport_offline_reads() {
        let state = tempfile::tempdir().expect("state dir");
        #[cfg(unix)]
        fs::set_permissions(
            state.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("private state directory");
        let cloud = Arc::new(FakeCloud::new());
        cloud.insert_file("/offline.txt", b"verified cached bytes");
        cloud.insert_file("/sync/nested.txt", b"nested cached bytes");
        let cache = Cache::open(state.path(), 64 * 1024 * 1024).expect("open cache");
        let engine = Engine::open(state.path(), cloud.clone())
            .expect("open engine")
            .with_offline_cache(
                cache,
                "profile-account-1".into(),
                "https://example.invalid/".into(),
            )
            .expect("bind cache identity");
        let namespace_snapshot = engine.spaces().expect("capture online namespace");
        let engine = engine
            .with_offline_spaces(namespace_snapshot.clone())
            .expect("attach account-bound namespace snapshot");

        let online = engine.list("space", "/").expect("online listing");
        let nested_online = engine.list("space", "/sync").expect("nested listing");
        assert!(
            nested_online
                .iter()
                .any(|entry| entry.path == "/sync/nested.txt")
        );
        let item = online
            .iter()
            .find(|entry| entry.path == "/offline.txt")
            .expect("fixture file listed");
        let mut snapshot = engine
            .fetch_snapshot("space", &item.path)
            .expect("online version download");
        let mut online_bytes = Vec::new();
        snapshot
            .read_to_end(&mut online_bytes)
            .expect("read online snapshot");
        assert_eq!(online_bytes, b"verified cached bytes");
        drop(snapshot);
        drop(engine);

        *cloud.fail_all.lock().expect("offline mode lock") = Some(ErrorKind::Offline);
        let cache = Cache::open(state.path(), 64 * 1024 * 1024).expect("reopen cache");
        let engine = Engine::open(state.path(), cloud.clone())
            .expect("reopen engine")
            .with_offline_cache(
                cache,
                "profile-account-1".into(),
                "https://example.invalid/".into(),
            )
            .expect("rebind cache identity")
            .with_offline_spaces(namespace_snapshot.clone())
            .expect("rebind saved namespace");
        engine
            .mark_namespace_transport_unavailable()
            .expect("restore known offline state");
        let spaces_calls_before = *cloud.spaces_calls.lock().expect("spaces call count");
        let list_calls_before = *cloud.list_calls.lock().expect("list call count");
        let offline_spaces = engine.spaces().expect("cached namespace after restart");
        assert_eq!(offline_spaces.len(), namespace_snapshot.len());
        assert_eq!(offline_spaces[0].id, namespace_snapshot[0].id);
        assert!(!offline_spaces[0].writable);
        let offline = engine.list("space", "/").expect("cached offline listing");
        assert!(offline.iter().any(|entry| entry == item));
        let nested_offline = engine
            .list("space", "/sync")
            .expect("cached nested listing");
        assert!(
            nested_offline
                .iter()
                .any(|entry| entry.path == "/sync/nested.txt")
        );
        assert_eq!(
            *cloud.spaces_calls.lock().expect("spaces call count"),
            spaces_calls_before,
            "known-offline namespace reads must not probe the network"
        );
        assert_eq!(
            *cloud.list_calls.lock().expect("list call count"),
            list_calls_before,
            "a cached offline parent listing must not wait for the transport deadline"
        );
        let mut snapshot = engine
            .fetch_snapshot("space", "/offline.txt")
            .expect("cached offline content");
        let mut offline_bytes = Vec::new();
        snapshot
            .read_to_end(&mut offline_bytes)
            .expect("read cached snapshot");
        assert_eq!(offline_bytes, b"verified cached bytes");

        *cloud.fail_all.lock().expect("offline mode lock") = Some(ErrorKind::Unauthorized);
        assert_eq!(
            engine.probe_live_namespace().unwrap_err().kind,
            ErrorKind::Unauthorized,
            "bounded recovery probes must surface auth errors and clear the offline fast path"
        );
        assert!(!engine.namespace_transport_unavailable());
        let error = engine
            .list("space", "/")
            .expect_err("authorization failure must not fall back");
        assert_eq!(error.kind, ErrorKind::Unauthorized);

        *cloud.fail_all.lock().expect("offline mode lock") = None;
        *cloud.space_encrypted.lock().expect("space metadata lock") = true;
        let error = engine
            .list("space", "/")
            .expect_err("encrypted Space must not use ordinary cache");
        assert_eq!(error.kind, ErrorKind::Unsupported);

        *cloud.space_encrypted.lock().expect("space metadata lock") = false;
        if let Some((root, _)) = cloud
            .entries
            .lock()
            .expect("remote entries lock")
            .get_mut("/")
        {
            root.id = "replacement-root-id".into();
        }
        *cloud.fail_listing.lock().expect("listing flag") = true;
        let error = engine
            .list("space", "/")
            .expect_err("a replacement root cannot reuse the previous root cache");
        assert_eq!(error.kind, ErrorKind::Offline);
    }

    #[test]
    fn cached_online_create_uploads_conditionally_and_failed_create_keeps_local_bytes() {
        let state = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        fs::set_permissions(
            state.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let cloud = Arc::new(FakeCloud::new());
        let cache = Cache::open(state.path(), 64 * 1024 * 1024).unwrap();
        let engine = Engine::open(state.path(), cloud.clone())
            .unwrap()
            .with_offline_cache(
                cache,
                "profile-account-1".into(),
                "https://example.invalid/".into(),
            )
            .unwrap();
        engine.list("space", "/").unwrap();
        let scope = engine.ordinary_write_scope("space").unwrap();
        let source = state.path().join("new-file-spool.bin");
        fs::write(&source, b"new ordinary file").unwrap();
        let result = engine
            .commit_file_write_scoped(
                "space",
                "/new.txt",
                &source,
                WriteCondition::Absent,
                &scope,
                None,
            )
            .expect("online create must not require a cached existing file");
        assert!(matches!(result, FileWriteOutcome::Uploaded(_)));
        assert_eq!(
            cloud.bytes("/new.txt").as_deref(),
            Some(b"new ordinary file".as_slice())
        );
        assert_eq!(
            engine.pending_file_writes(None, 10).unwrap().pending_count,
            0
        );

        fs::write(&source, b"must not replace remote").unwrap();
        let error = engine
            .commit_file_write_scoped(
                "space",
                "/new.txt",
                &source,
                WriteCondition::Absent,
                &scope,
                None,
            )
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Conflict);
        assert_eq!(
            cloud.bytes("/new.txt").as_deref(),
            Some(b"new ordinary file".as_slice())
        );

        *cloud.fail_upload.lock().unwrap() = true;
        let error = engine
            .commit_file_write_scoped(
                "space",
                "/offline-new.txt",
                &source,
                WriteCondition::Absent,
                &scope,
                None,
            )
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Offline);
        assert!(cloud.bytes("/offline-new.txt").is_none());
        assert_eq!(fs::read(&source).unwrap(), b"must not replace remote");
        assert_eq!(
            engine.pending_file_writes(None, 10).unwrap().pending_count,
            0
        );
        *cloud.fail_upload.lock().unwrap() = false;
        *cloud.fail_upload_after_commit.lock().unwrap() = true;
        let error = engine
            .commit_file_write_scoped(
                "space",
                "/ambiguous.txt",
                &source,
                WriteCondition::Absent,
                &scope,
                None,
            )
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Offline);
        assert_eq!(
            cloud.bytes("/ambiguous.txt").as_deref(),
            Some(b"must not replace remote".as_slice())
        );
        assert_eq!(fs::read(&source).unwrap(), b"must not replace remote");
        *cloud.fail_upload_after_commit.lock().unwrap() = false;
        fs::write(&source, b"newer retained local revision").unwrap();
        let error = engine
            .commit_file_write_scoped(
                "space",
                "/ambiguous.txt",
                &source,
                WriteCondition::Absent,
                &scope,
                None,
            )
            .unwrap_err();
        assert_eq!(
            error.kind,
            ErrorKind::Conflict,
            "lost acknowledgement cannot authorize replay"
        );
        assert_eq!(
            cloud.bytes("/ambiguous.txt").as_deref(),
            Some(b"must not replace remote".as_slice())
        );
        assert_eq!(fs::read(&source).unwrap(), b"newer retained local revision");
        assert_eq!(
            engine.pending_file_writes(None, 10).unwrap().pending_count,
            0
        );
        *cloud.replace_root_before_scoped_upload.lock().unwrap() = true;
        let error = engine
            .commit_file_write_scoped(
                "space",
                "/root-race.txt",
                &source,
                WriteCondition::Absent,
                &scope,
                None,
            )
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Conflict);
        assert!(cloud.bytes("/root-race.txt").is_none());
        assert_eq!(fs::read(&source).unwrap(), b"newer retained local revision");
    }

    #[test]
    fn offline_cached_edit_reads_locally_after_restart_and_reconciles_conditionally() {
        let state = tempfile::tempdir().expect("state dir");
        #[cfg(unix)]
        fs::set_permissions(
            state.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("private state directory");
        let cloud = Arc::new(FakeCloud::new());
        cloud.insert_file("/offline.txt", b"base bytes");
        let cache = Cache::open(state.path(), 64 * 1024 * 1024).expect("open cache");
        let engine = Engine::open(state.path(), cloud.clone())
            .expect("open engine")
            .with_offline_cache(
                cache,
                "profile-account-1".into(),
                "https://example.invalid/".into(),
            )
            .expect("bind cache identity");
        let listed = engine.list("space", "/").expect("cache listing");
        let base = listed
            .iter()
            .find(|entry| entry.path == "/offline.txt")
            .expect("listed file")
            .etag
            .clone();
        let mut original = engine
            .fetch_snapshot("space", "/offline.txt")
            .expect("cache base bytes");
        let mut original_bytes = Vec::new();
        original.read_to_end(&mut original_bytes).unwrap();
        assert_eq!(original_bytes, b"base bytes");

        let edit = state.path().join("working-copy.bin");
        fs::write(&edit, b"local edit").unwrap();
        *cloud.fail_all.lock().expect("offline mode lock") = Some(ErrorKind::Offline);
        let queued = engine
            .commit_file_write(
                "space",
                "/offline.txt",
                &edit,
                WriteCondition::Match(base.clone()),
            )
            .expect("offline edit should be durably queued");
        assert!(matches!(queued, FileWriteOutcome::Queued(_)));
        let offline_entries = engine
            .list("space", "/")
            .expect("offline listing with pending overlay");
        let pending = offline_entries
            .iter()
            .find(|entry| entry.path == "/offline.txt")
            .expect("pending file stays visible");
        assert_eq!(pending.size, b"local edit".len() as u64);
        assert_eq!(pending.etag, base);
        let queued_page = engine
            .pending_file_writes(None, 10)
            .expect("local journal page");
        assert_eq!(queued_page.pending_count, 1);
        assert_eq!(queued_page.items[0].path, "/offline.txt");
        assert_eq!(queued_page.items[0].bytes, b"local edit".len() as u64);
        let mut local = engine
            .fetch_snapshot("space", "/offline.txt")
            .expect("read your offline write");
        let mut local_bytes = Vec::new();
        local.read_to_end(&mut local_bytes).unwrap();
        assert_eq!(local_bytes, b"local edit");

        drop(engine);
        let reopened_cache = Cache::open(state.path(), 64 * 1024 * 1024).expect("reopen cache");
        let reopened = Engine::open(state.path(), cloud.clone())
            .expect("reopen engine")
            .with_offline_cache(
                reopened_cache,
                "profile-account-1".into(),
                "https://example.invalid/".into(),
            )
            .expect("rebind cache identity");
        let mut after_restart = reopened
            .fetch_snapshot("space", "/offline.txt")
            .expect("read pending write after restart");
        let mut bytes = Vec::new();
        after_restart.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"local edit");

        *cloud.fail_all.lock().expect("online mode lock") = None;
        let cancelled = reopened
            .reconcile_pending_file_writes_cancellable("space", 8, || true)
            .expect("cancel should stop before first upload");
        assert_eq!(cancelled.uploaded, 0);
        assert_eq!(cancelled.remaining, 1);
        assert_eq!(
            cloud.bytes("/offline.txt").as_deref(),
            Some(&b"base bytes"[..])
        );
        reopened.set_sync_paused(true);
        let paused = reopened
            .reconcile_pending_file_writes_cancellable("space", 8, || false)
            .expect("pause should preserve journal without failing it");
        assert_eq!(paused.uploaded, 0);
        assert_eq!(paused.remaining, 1);
        assert_eq!(
            cloud.bytes("/offline.txt").as_deref(),
            Some(&b"base bytes"[..])
        );
        reopened.set_sync_paused(false);
        let report = reopened
            .reconcile_pending_file_writes("space")
            .expect("reconcile pending edit");
        assert_eq!(report.uploaded, 1);
        assert_eq!(
            cloud.bytes("/offline.txt").as_deref(),
            Some(&b"local edit"[..])
        );
        let refreshed = reopened.stat("space", "/offline.txt").unwrap();
        assert_ne!(refreshed.etag, base);
        let mut verified = reopened
            .fetch_snapshot("space", "/offline.txt")
            .expect("read verified remote version");
        bytes.clear();
        verified.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"local edit");
    }

    #[test]
    fn offline_edit_conflict_preserves_remote_and_local_bytes_after_restart() {
        let state = tempfile::tempdir().expect("state dir");
        #[cfg(unix)]
        fs::set_permissions(
            state.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("private state directory");
        let cloud = Arc::new(FakeCloud::new());
        cloud.insert_file("/offline.txt", b"base bytes");
        let cache = Cache::open(state.path(), 64 * 1024 * 1024).expect("open cache");
        let engine = Engine::open(state.path(), cloud.clone())
            .expect("open engine")
            .with_offline_cache(
                cache,
                "profile-account-1".into(),
                "https://example.invalid/".into(),
            )
            .expect("bind cache identity");
        let base = engine.list("space", "/").unwrap()[0].etag.clone();
        let mut cached = engine.fetch_snapshot("space", "/offline.txt").unwrap();
        let mut discarded = Vec::new();
        cached.read_to_end(&mut discarded).unwrap();
        let edit = state.path().join("working-copy.bin");
        fs::write(&edit, b"local version").unwrap();
        *cloud.fail_all.lock().expect("offline mode lock") = Some(ErrorKind::Offline);
        engine
            .commit_file_write("space", "/offline.txt", &edit, WriteCondition::Match(base))
            .expect("queue offline edit");
        cloud.replace_file("/offline.txt", b"remote version");
        *cloud.fail_all.lock().expect("online mode lock") = None;
        let report = engine
            .reconcile_pending_file_writes("space")
            .expect("conflict report");
        assert_eq!(report.conflicts, 1);
        assert_eq!(report.remaining, 0);
        assert_eq!(
            cloud.bytes("/offline.txt").as_deref(),
            Some(&b"remote version"[..])
        );
        let displayed = engine.stat("space", "/offline.txt").unwrap();
        assert_eq!(displayed.size, b"local version".len() as u64);
        drop(engine);

        *cloud.fail_all.lock().expect("offline mode lock") = Some(ErrorKind::Offline);
        let cache = Cache::open(state.path(), 64 * 1024 * 1024).unwrap();
        let reopened = Engine::open(state.path(), cloud)
            .unwrap()
            .with_offline_cache(
                cache,
                "profile-account-1".into(),
                "https://example.invalid/".into(),
            )
            .unwrap();
        let mut local = reopened
            .fetch_snapshot("space", "/offline.txt")
            .expect("conflicted bytes remain readable after restart");
        let mut bytes = Vec::new();
        local.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"local version");
    }

    #[test]
    fn reconciliation_reports_pending_uploads_separately_from_conflicts() {
        let state = tempfile::tempdir().expect("state dir");
        #[cfg(unix)]
        fs::set_permissions(
            state.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("private state directory");
        let cloud = Arc::new(FakeCloud::new());
        cloud.insert_file("/a-conflict.txt", b"base a");
        cloud.insert_file("/b-pending.txt", b"base b");
        let cache = Cache::open(state.path(), 64 * 1024 * 1024).expect("open cache");
        let engine = Engine::open(state.path(), cloud.clone())
            .expect("open engine")
            .with_offline_cache(
                cache,
                "profile-account-1".into(),
                "https://example.invalid/".into(),
            )
            .expect("bind cache identity");
        let listed = engine.list("space", "/").expect("prime listing");
        let base_a = listed
            .iter()
            .find(|entry| entry.path == "/a-conflict.txt")
            .unwrap()
            .etag
            .clone();
        let base_b = listed
            .iter()
            .find(|entry| entry.path == "/b-pending.txt")
            .unwrap()
            .etag
            .clone();
        for path in ["/a-conflict.txt", "/b-pending.txt"] {
            let mut cached = engine.fetch_snapshot("space", path).unwrap();
            std::io::copy(&mut cached, &mut std::io::sink()).unwrap();
        }
        *cloud.fail_all.lock().unwrap() = Some(ErrorKind::Offline);
        for (path, base, name, bytes) in [
            ("/a-conflict.txt", base_a, "a-edit", b"local a".as_slice()),
            ("/b-pending.txt", base_b, "b-edit", b"local b".as_slice()),
        ] {
            let edit = state.path().join(name);
            fs::write(&edit, bytes).unwrap();
            engine
                .commit_file_write("space", path, &edit, WriteCondition::Match(base))
                .expect("queue offline edit");
        }
        // The first queued item now conflicts. The bounded pass leaves the
        // later pending item untouched, and reports the two counts separately.
        cloud.replace_file("/a-conflict.txt", b"remote a");
        *cloud.fail_all.lock().unwrap() = None;
        let first = engine
            .reconcile_pending_file_writes_cancellable("space", 1, || false)
            .expect("one-item reconciliation");
        assert_eq!(first.uploaded, 0);
        assert_eq!(first.conflicts, 1);
        assert_eq!(first.remaining, 1);

        let second = engine
            .reconcile_pending_file_writes_cancellable("space", 1, || false)
            .expect("retry remaining pending item");
        assert_eq!(second.uploaded, 1);
        assert_eq!(second.conflicts, 1);
        assert_eq!(second.remaining, 0);
        assert_eq!(
            cloud.bytes("/a-conflict.txt").as_deref(),
            Some(&b"remote a"[..])
        );
        assert_eq!(
            cloud.bytes("/b-pending.txt").as_deref(),
            Some(&b"local b"[..])
        );
        let journal = engine.pending_file_writes(None, 10).unwrap();
        assert_eq!(journal.conflict_count, 1);
        assert_eq!(journal.pending_count, 0);
        assert_eq!(journal.items[0].state, WriteState::Conflict);
    }

    #[test]
    fn delete_rejects_space_root_aliases_before_backend_operations() {
        let state = tempfile::tempdir().unwrap();
        let cloud = Arc::new(FakeCloud::new());
        cloud.insert_file("/item.txt", b"keep");
        let engine = Engine::open(state.path(), cloud.clone()).unwrap();
        let root = cloud.remote_entry("/").unwrap();
        for path in ["", "/", "//", "///"] {
            let error = engine.delete("space", path, &root.etag).unwrap_err();
            assert_eq!(error.kind, ErrorKind::Unsupported);
            assert!(error.message.contains("Space root"));
        }
        assert_eq!(*cloud.delete_calls.lock().unwrap(), 0);
        assert_eq!(*cloud.spaces_calls.lock().unwrap(), 0);
        assert_eq!(*cloud.list_calls.lock().unwrap(), 0);
        assert_eq!(cloud.remote_entry("/").unwrap().etag, root.etag);
        assert_eq!(cloud.bytes("/item.txt").unwrap(), b"keep");
        // Ordinary conditional deletion must remain available.
        let item = cloud.remote_entry("/item.txt").unwrap();
        engine.delete("space", "/item.txt", &item.etag).unwrap();
        assert_eq!(*cloud.delete_calls.lock().unwrap(), 1);
        assert!(cloud.bytes("/item.txt").is_none());
    }

    #[test]
    fn ordinary_delete_retains_journal_without_cloud_resurrection() {
        for conflicted in [false, true] {
            let state = tempfile::tempdir().unwrap();
            #[cfg(unix)]
            fs::set_permissions(
                state.path(),
                std::os::unix::fs::PermissionsExt::from_mode(0o700),
            )
            .unwrap();
            let cloud = Arc::new(FakeCloud::new());
            cloud.insert_file("/item.txt", b"original");
            let cache = Cache::open(state.path(), 64 * 1024 * 1024).unwrap();
            let engine = Engine::open(state.path(), cloud.clone())
                .unwrap()
                .with_offline_cache(
                    cache.clone(),
                    "profile-account-1".into(),
                    "https://example.invalid/".into(),
                )
                .unwrap();
            engine.list("space", "/").unwrap();
            let original = cloud.remote_entry("/item.txt").unwrap();
            let source = state.path().join("local-edit");
            fs::write(&source, b"retained journal edit").unwrap();
            *cloud.fail_upload.lock().unwrap() = true;
            assert!(matches!(
                engine
                    .commit_file_write(
                        "space",
                        "/item.txt",
                        &source,
                        WriteCondition::Match(original.etag.clone())
                    )
                    .unwrap(),
                FileWriteOutcome::Queued(_)
            ));
            *cloud.fail_upload.lock().unwrap() = false;
            let scope = engine.online_plaintext_scope("space").unwrap().0;
            let queued = cache.pending_writes(&scope).unwrap().remove(0);
            if conflicted {
                cache.mark_write_conflict(&scope, queued.id).unwrap();
            }
            engine.delete("space", "/item.txt", &original.etag).unwrap();
            assert!(cloud.bytes("/item.txt").is_none());
            assert_eq!(*cloud.delete_calls.lock().unwrap(), 1);
            let report = engine.reconcile_pending_file_writes("space").unwrap();
            assert_eq!(report.uploaded, 0);
            assert_eq!(report.conflicts, 1);
            assert_eq!(report.remaining, 0);
            let entries = engine.list("space", "/").unwrap();
            assert!(entries.iter().any(|entry| entry.path == "/item.txt"));
            let reopened = Cache::open(state.path(), 64 * 1024 * 1024).unwrap();
            let retained = reopened.pending_writes(&scope).unwrap();
            assert_eq!(retained.len(), 1);
            assert_eq!(retained[0].id, queued.id);
            assert_eq!(retained[0].state, WriteState::Conflict);
            let mut stored = reopened.open_content(&scope, &retained[0].content).unwrap();
            let mut bytes = Vec::new();
            stored.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, b"retained journal edit");
            let retry = engine.reconcile_pending_file_writes("space").unwrap();
            assert_eq!(retry.uploaded, 0);
            assert_eq!(retry.conflicts, 1);
            assert!(cloud.bytes("/item.txt").is_none());
        }
    }

    #[test]
    fn rename_rejects_subtrees_with_journal_edits_before_remote_mutation() {
        for conflicted in [false, true] {
            let state = tempfile::tempdir().unwrap();
            #[cfg(unix)]
            fs::set_permissions(
                state.path(),
                std::os::unix::fs::PermissionsExt::from_mode(0o700),
            )
            .unwrap();
            let cloud = Arc::new(FakeCloud::new());
            cloud.insert_file("/sync/item.txt", b"original");
            cloud.insert_file("/sync2.txt", b"independent");
            let cache = Cache::open(state.path(), 64 * 1024 * 1024).unwrap();
            let engine = Engine::open(state.path(), cloud.clone())
                .unwrap()
                .with_offline_cache(
                    cache.clone(),
                    "profile-account-1".into(),
                    "https://example.invalid/".into(),
                )
                .unwrap();
            engine.list("space", "/").unwrap();
            engine.list("space", "/sync").unwrap();
            let original = cloud.remote_entry("/sync/item.txt").unwrap();
            let source = state.path().join("local-edit");
            fs::write(&source, b"retained journal edit").unwrap();
            *cloud.fail_upload.lock().unwrap() = true;
            assert!(matches!(
                engine
                    .commit_file_write(
                        "space",
                        "/sync/item.txt",
                        &source,
                        WriteCondition::Match(original.etag.clone())
                    )
                    .unwrap(),
                FileWriteOutcome::Queued(_)
            ));
            *cloud.fail_upload.lock().unwrap() = false;
            let scope = engine.online_plaintext_scope("space").unwrap().0;
            let queued = cache.pending_writes(&scope).unwrap().remove(0);
            if conflicted {
                cache.mark_write_conflict(&scope, queued.id).unwrap();
            }

            for (from, to) in [
                ("/sync", "/moved"),
                ("/other", "/sync"),
                ("/sync/item.txt", "/other.txt"),
            ] {
                let error = engine.rename("space", from, to, "unused").unwrap_err();
                assert_eq!(error.kind, ErrorKind::Conflict);
                assert!(error.message.contains("pending local journal edits"));
            }
            assert_eq!(cloud.bytes("/sync/item.txt").unwrap(), b"original");
            assert_eq!(
                engine.pending_file_writes(None, 10).unwrap().pending_count,
                if conflicted { 0 } else { 1 }
            );
            let reopened = Cache::open(state.path(), 64 * 1024 * 1024).unwrap();
            let retained = reopened.pending_writes(&scope).unwrap();
            assert_eq!(retained.len(), 1);
            assert_eq!(retained[0].logical_path, "/sync/item.txt");
            assert_eq!(
                retained[0].state,
                if conflicted {
                    WriteState::Conflict
                } else {
                    WriteState::Pending
                }
            );
            let mut stored = reopened.open_content(&scope, &retained[0].content).unwrap();
            let mut stored_bytes = Vec::new();
            stored.read_to_end(&mut stored_bytes).unwrap();
            assert_eq!(stored_bytes, b"retained journal edit");
            let mut snapshot = engine.fetch_snapshot("space", "/sync/item.txt").unwrap();
            let mut bytes = Vec::new();
            snapshot.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, b"retained journal edit");
            let sibling = cloud.remote_entry("/sync2.txt").unwrap();
            engine
                .rename("space", "/sync2.txt", "/sibling-moved.txt", &sibling.etag)
                .unwrap();
            if !conflicted {
                engine.reconcile_pending_file_writes("space").unwrap();
                let verified = cloud.remote_entry("/sync/item.txt").unwrap();
                engine
                    .rename("space", "/sync/item.txt", "/uploaded.txt", &verified.etag)
                    .unwrap();
                assert_eq!(
                    cloud.bytes("/uploaded.txt").unwrap(),
                    b"retained journal edit"
                );
            }
        }
    }

    #[test]
    fn failed_upload_refreshes_only_fresh_metadata_and_retains_dirty_bytes_after_restart() {
        for committed in [false, true] {
            for listing_available in [false, true] {
                let state = tempfile::tempdir().unwrap();
                #[cfg(unix)]
                fs::set_permissions(
                    state.path(),
                    std::os::unix::fs::PermissionsExt::from_mode(0o700),
                )
                .unwrap();
                let cloud = Arc::new(FakeCloud::new());
                cloud.insert_file("/edited.txt", b"original");
                cloud.insert_file("/unrelated.txt", b"retained");
                let cache = Cache::open(state.path(), 64 * 1024 * 1024).unwrap();
                let engine = Engine::open(state.path(), cloud.clone())
                    .unwrap()
                    .with_offline_cache(
                        cache.clone(),
                        "profile-account-1".into(),
                        "https://example.invalid/".into(),
                    )
                    .unwrap();
                engine.list("space", "/").unwrap();
                let original = cloud.remote_entry("/edited.txt").unwrap();
                for path in ["/edited.txt", "/unrelated.txt"] {
                    let mut snapshot = engine.fetch_snapshot("space", path).unwrap();
                    std::io::copy(&mut snapshot, &mut std::io::sink()).unwrap();
                }
                engine
                    .set_availability_policy(
                        "space",
                        "/unrelated.txt",
                        AvailabilityPolicy::AlwaysOffline,
                    )
                    .unwrap();
                let scope = engine.online_plaintext_scope("space").unwrap().0;
                let edit = state.path().join("edit");
                fs::write(&edit, b"local dirty bytes").unwrap();
                *cloud.fail_upload.lock().unwrap() = !committed;
                *cloud.fail_upload_after_commit.lock().unwrap() = committed;
                *cloud.fail_listing.lock().unwrap() = !listing_available;
                assert!(matches!(
                    engine
                        .commit_file_write(
                            "space",
                            "/edited.txt",
                            &edit,
                            WriteCondition::Match(original.etag)
                        )
                        .unwrap(),
                    FileWriteOutcome::Queued(_)
                ));
                let before = cache.pending_writes(&scope).unwrap();
                assert_eq!(before.len(), 1);
                assert_eq!(before[0].state, WriteState::Pending);
                drop(engine);
                drop(cache);
                *cloud.fail_all.lock().unwrap() = Some(ErrorKind::Offline);
                let reopened_cache = Cache::open(state.path(), 64 * 1024 * 1024).unwrap();
                let reopened = Engine::open(state.path(), cloud.clone())
                    .unwrap()
                    .with_offline_cache(
                        reopened_cache.clone(),
                        "profile-account-1".into(),
                        "https://example.invalid/".into(),
                    )
                    .unwrap();
                let listed = reopened.list("space", "/");
                if listing_available {
                    let entries = listed.unwrap();
                    assert!(entries.iter().any(|entry| entry.path == "/unrelated.txt"));
                    let mut snapshot = reopened.fetch_snapshot("space", "/unrelated.txt").unwrap();
                    let mut bytes = Vec::new();
                    snapshot.read_to_end(&mut bytes).unwrap();
                    assert_eq!(bytes, b"retained");
                } else {
                    assert_eq!(listed.unwrap_err().kind, ErrorKind::Offline);
                }
                let after = reopened_cache.pending_writes(&scope).unwrap();
                assert_eq!(after.len(), 1);
                assert_eq!(after[0].id, before[0].id);
                // A fresh listing of an acknowledged-differently server
                // version must surface the retained edit as a conflict.
                let expected_state = if committed && listing_available {
                    WriteState::Conflict
                } else {
                    WriteState::Pending
                };
                assert_eq!(after[0].state, expected_state);
                let mut bytes = Vec::new();
                reopened_cache
                    .open_content(&scope, &after[0].content)
                    .unwrap()
                    .read_to_end(&mut bytes)
                    .unwrap();
                assert_eq!(bytes, b"local dirty bytes");
                assert_eq!(fs::read(&edit).unwrap(), b"local dirty bytes");
            }
        }
    }

    #[test]
    fn failed_upload_refresh_cannot_rebind_invalidated_listing_to_replaced_root() {
        let state = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        fs::set_permissions(
            state.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let cloud = Arc::new(FakeCloud::new());
        cloud.insert_file("/item.txt", b"original");
        let cache = Cache::open(state.path(), 64 * 1024 * 1024).unwrap();
        let engine = Engine::open(state.path(), cloud.clone())
            .unwrap()
            .with_offline_cache(
                cache.clone(),
                "profile-account-1".into(),
                "https://example.invalid/".into(),
            )
            .unwrap();
        engine.list("space", "/").unwrap();
        let scope = engine.online_plaintext_scope("space").unwrap().0;
        let source = state.path().join("source");
        fs::write(&source, b"replacement").unwrap();
        *cloud.replace_root_before_scoped_upload.lock().unwrap() = true;
        let error = engine
            .upload_inner_with_root(
                None,
                "space",
                "/item.txt",
                &source,
                WriteCondition::Match(cloud.remote_entry("/item.txt").unwrap().etag),
                Some(scope.root_resource_id()),
            )
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Conflict);
        assert_eq!(error.message, "fixture root changed");
        assert_eq!(
            cache.listing(&scope, scope.root_resource_id()).unwrap_err(),
            raiun_cache::CacheError::IncompleteListing
        );
        assert_eq!(cloud.bytes("/item.txt").unwrap(), b"original");
        assert_eq!(fs::read(&source).unwrap(), b"replacement");
    }

    #[test]
    fn verified_mutations_refresh_offline_tree_and_uncertain_mutation_stays_invalidated() {
        let state = tempfile::tempdir().expect("state dir");
        #[cfg(unix)]
        fs::set_permissions(
            state.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("private state directory");
        let cloud = Arc::new(FakeCloud::new());
        cloud.insert_file("/sync/item.txt", b"old revision");
        let cache = Cache::open(state.path(), 64 * 1024 * 1024).expect("open cache");
        let engine = Engine::open(state.path(), cloud.clone())
            .expect("open engine")
            .with_offline_cache(
                cache.clone(),
                "profile-account-1".into(),
                "https://example.invalid/".into(),
            )
            .expect("bind cache identity");

        engine.list("space", "/").expect("cache root listing");
        engine.list("space", "/sync").expect("cache sync listing");
        let old_entry = cloud.remote_entry("/sync/item.txt").unwrap();
        let mut old_snapshot = engine
            .fetch_snapshot("space", "/sync/item.txt")
            .expect("cache old content");
        let mut old_bytes = Vec::new();
        old_snapshot.read_to_end(&mut old_bytes).unwrap();
        assert_eq!(old_bytes, b"old revision");
        drop(old_snapshot);
        let pin = engine
            .pin_offline_tree("space", "/sync", |_| {})
            .expect("pin the old snapshot");
        assert_eq!(pin.state, raiun_cache::PinState::Ready);

        // A successful overwrite refreshes the tree but never labels the old
        // pin as current. The previous immutable blob remains retained.
        let replacement = tempfile::NamedTempFile::new_in(state.path()).unwrap();
        fs::write(replacement.path(), b"replacement revision").unwrap();
        let replacement_path = replacement.into_temp_path();
        engine
            .put(
                "space",
                "/sync/item.txt",
                replacement_path.as_ref(),
                WriteCondition::Match(old_entry.etag.clone()),
            )
            .expect("verified overwrite");
        assert_eq!(
            cache.refresh_pin(&pin.id).unwrap().state,
            raiun_cache::PinState::Stale
        );

        // Rename, directory creation, and delete all update the complete
        // parent snapshot before it can be used as an offline listing.
        engine
            .rename(
                "space",
                "/sync/item.txt",
                "/sync/renamed.txt",
                &cloud.remote_entry("/sync/item.txt").unwrap().etag,
            )
            .expect("verified rename");
        engine
            .mkdir("space", "/sync/new-folder")
            .expect("verified mkdir");
        engine
            .delete(
                "space",
                "/sync/renamed.txt",
                &cloud.remote_entry("/sync/renamed.txt").unwrap().etag,
            )
            .expect("verified delete");

        *cloud.fail_all.lock().expect("offline mode lock") = Some(ErrorKind::Offline);
        let offline = engine
            .list("space", "/sync")
            .expect("fresh verified parent snapshot is available offline");
        assert_eq!(offline.len(), 1);
        assert_eq!(offline[0].path, "/sync/new-folder");
        let old_version = ContentVersion {
            resource_id: old_entry.id,
            etag: old_entry.etag,
            protection: ContentProtection::Plaintext,
        };
        let mut retained = cache
            .open_content(
                &cache
                    .find_plaintext_scope("https://example.invalid/", "profile-account-1", "space")
                    .unwrap()
                    .unwrap(),
                &old_version,
            )
            .expect("old immutable content is retained");
        let mut retained_bytes = Vec::new();
        retained.read_to_end(&mut retained_bytes).unwrap();
        assert_eq!(retained_bytes, b"old revision");
        assert_eq!(
            engine
                .fetch_snapshot("space", "/sync/renamed.txt")
                .err()
                .expect("deleted path must not resolve from stale metadata")
                .kind,
            ErrorKind::Offline
        );

        // If both a mutation and its fresh listing fail, the old listing
        // remains invalidated instead of being restored from cache.
        *cloud.fail_all.lock().expect("offline mode lock") = None;
        *cloud.fail_upload.lock().expect("upload flag") = true;
        *cloud.fail_listing.lock().unwrap() = true;
        let another = tempfile::NamedTempFile::new_in(state.path()).unwrap();
        fs::write(another.path(), b"uncertain").unwrap();
        let another_path = another.into_temp_path();
        assert!(
            engine
                .put(
                    "space",
                    "/sync/uncertain.txt",
                    another_path.as_ref(),
                    WriteCondition::Absent
                )
                .is_err()
        );
        *cloud.fail_all.lock().expect("offline mode lock") = Some(ErrorKind::Offline);
        assert_eq!(
            engine.list("space", "/sync").unwrap_err().kind,
            ErrorKind::Offline
        );
        assert_eq!(
            cache.refresh_pin(&pin.id).unwrap().state,
            raiun_cache::PinState::Stale
        );
    }

    #[test]
    fn automatic_refresh_moves_stable_pin_and_updates_only_changed_versions() {
        let state = tempfile::tempdir().expect("state dir");
        #[cfg(unix)]
        fs::set_permissions(
            state.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("private state directory");
        let cloud = Arc::new(FakeCloud::new());
        cloud.insert_dir("/sync/nested");
        cloud.insert_file("/sync/nested/unchanged.txt", b"unchanged");
        cloud.insert_file("/sync/revised.txt", b"old");
        cloud.insert_file("/always.txt", b"policy-old");
        let cache = Cache::open(state.path(), 64 * 1024 * 1024).expect("open cache");
        let engine = Engine::open(state.path(), cloud.clone())
            .expect("open engine")
            .with_offline_cache(
                cache.clone(),
                "profile-account-1".into(),
                "https://example.invalid/".into(),
            )
            .expect("bind cache identity");
        let pin = engine
            .pin_offline_tree("space", "/sync", |_| {})
            .expect("initial folder snapshot");
        engine
            .set_availability_policy("space", "/always.txt", AvailabilityPolicy::AlwaysOffline)
            .expect("initial file policy");
        let scope = cache
            .find_plaintext_scope("https://example.invalid/", "profile-account-1", "space")
            .unwrap()
            .unwrap();
        let pin_root_id = pin.root_resource_id.clone();
        let downloads_before = *cloud.downloads.lock().unwrap();

        // Rename the pinned folder without changing resource identities,
        // revise one pinned file and the standalone policy file, and add a
        // child. The refresh finds the old folder by ID and stages a new
        // complete snapshot before replacing the stable pin record.
        cloud.move_prefix("/sync", "/renamed");
        cloud.insert_file("/renamed/new.txt", b"new child");
        cloud.replace_file("/renamed/revised.txt", b"new revision");
        cloud.replace_file("/always.txt", b"policy-new");

        let report = engine
            .refresh_offline_availability_cancellable("space", || false)
            .expect("refresh complete snapshot");
        assert_eq!(report.files_downloaded, 1);
        assert_eq!(*cloud.downloads.lock().unwrap() - downloads_before, 3);
        let refreshed_pin = cache.refresh_pin(&pin.id).unwrap();
        assert_eq!(refreshed_pin.state, PinState::Ready);
        assert_eq!(refreshed_pin.root_resource_id, pin_root_id);
        assert_eq!(refreshed_pin.root_path, "/renamed");
        assert_eq!(refreshed_pin.required_content_count, 3);
        assert_eq!(cache.pins(&scope).unwrap().len(), 1);
        let policy_entry = engine.stat("space", "/always.txt").unwrap();
        assert_eq!(
            cache.policy_target_state(&scope, &policy_entry.id).unwrap(),
            Some(TargetState::Ready)
        );
        let mut policy_bytes = Vec::new();
        cache
            .open_content(
                &scope,
                &ContentVersion {
                    resource_id: policy_entry.id,
                    etag: policy_entry.etag,
                    protection: ContentProtection::Plaintext,
                },
            )
            .unwrap()
            .read_to_end(&mut policy_bytes)
            .unwrap();
        assert_eq!(policy_bytes, b"policy-new");

        *cloud.fail_all.lock().unwrap() = Some(ErrorKind::Offline);
        assert_eq!(
            engine
                .refresh_offline_availability_cancellable("space", || false)
                .unwrap_err()
                .kind,
            ErrorKind::Offline
        );
        assert_eq!(cache.refresh_pin(&pin.id).unwrap().state, PinState::Ready);
        *cloud.fail_all.lock().unwrap() = None;

        // A second pass with identical versions verifies/reuses all immutable
        // content instead of redownloading it.
        let before_second = *cloud.downloads.lock().unwrap();
        engine
            .refresh_offline_availability_cancellable("space", || false)
            .expect("unchanged refresh");
        assert_eq!(*cloud.downloads.lock().unwrap(), before_second);

        let current_policy_entry = engine.stat("space", "/always.txt").unwrap();
        let protected_old = ContentVersion {
            resource_id: current_policy_entry.id.clone(),
            etag: current_policy_entry.etag.clone(),
            protection: ContentProtection::Plaintext,
        };
        cloud.replace_file("/always.txt", b"policy-third");
        *cloud.fail_download_after_write.lock().unwrap() = true;
        assert!(
            engine
                .refresh_offline_availability_cancellable("space", || false)
                .is_err()
        );
        *cloud.fail_download_after_write.lock().unwrap() = false;
        let (policies, _) = cache.refresh_targets(&scope).unwrap();
        let policy = policies
            .iter()
            .find(|target| target.resource_id == current_policy_entry.id)
            .unwrap();
        assert_eq!(policy.etag, protected_old.etag);
        assert_eq!(policy.state, TargetState::Stale);
        cache
            .open_content(&scope, &protected_old)
            .expect("prior verified policy bytes remain protected after failed refresh");
    }

    #[test]
    fn automatic_refresh_never_adopts_replacement_at_old_path() {
        let state = tempfile::tempdir().expect("state dir");
        #[cfg(unix)]
        fs::set_permissions(
            state.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("private state directory");
        let cloud = Arc::new(FakeCloud::new());
        cloud.insert_dir("/folder");
        cloud.insert_file("/folder/old.txt", b"retained bytes");
        let cache = Cache::open(state.path(), 64 * 1024 * 1024).expect("open cache");
        let engine = Engine::open(state.path(), cloud.clone())
            .expect("open engine")
            .with_offline_cache(
                cache.clone(),
                "profile-account-1".into(),
                "https://example.invalid/".into(),
            )
            .expect("bind cache identity");
        let pin = engine.pin_offline_tree("space", "/folder", |_| {}).unwrap();
        engine
            .set_availability_policy(
                "space",
                "/folder/old.txt",
                AvailabilityPolicy::AlwaysOffline,
            )
            .unwrap();
        let old_id = pin.root_resource_id.clone();
        let old_file_id = cloud.remote_entry("/folder/old.txt").unwrap().id;
        // Remove the original stable identity and place a different object at
        // the same path. A complete traversal proves the old target absent;
        // retained data stays on disk but is never relabeled as current.
        cloud.move_prefix("/folder", "/gone");
        {
            let mut entries = cloud.entries.lock().unwrap();
            entries.remove("/gone");
            entries.remove("/gone/old.txt");
        }
        cloud.insert_dir("/folder");
        cloud.insert_file("/folder/replacement.txt", b"different identity");
        cloud
            .entries
            .lock()
            .unwrap()
            .get_mut("/folder")
            .unwrap()
            .0
            .id = "replacement-folder-id".into();
        let refreshed = engine
            .refresh_offline_availability_cancellable("space", || false)
            .expect("refresh deleted target");
        assert_eq!(refreshed.unavailable, 2);
        let pin = cache.refresh_pin(&pin.id).unwrap();
        assert_eq!(pin.root_resource_id, old_id);
        assert_eq!(pin.state, PinState::Unavailable);
        assert_eq!(pin.root_path, "/folder");
        assert_eq!(
            cache
                .policy_target_state(
                    &cache
                        .find_plaintext_scope(
                            "https://example.invalid/",
                            "profile-account-1",
                            "space",
                        )
                        .unwrap()
                        .unwrap(),
                    &old_file_id,
                )
                .unwrap(),
            Some(TargetState::Unavailable)
        );
        assert!(engine.fetch_snapshot("space", "/folder/old.txt").is_err());
    }

    #[test]
    fn historical_pin_recovery_does_not_restore_an_invalidated_current_listing() {
        let state = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        fs::set_permissions(
            state.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let cloud = Arc::new(FakeCloud::new());
        cloud.insert_file("/sync/pinned.txt", b"retained version");
        let cache = Cache::open(state.path(), 64 * 1024 * 1024).unwrap();
        let engine = Engine::open(state.path(), cloud.clone())
            .unwrap()
            .with_offline_cache(
                cache.clone(),
                "recovery-account".into(),
                "https://example.invalid/".into(),
            )
            .unwrap();
        let pin = engine.pin_offline_tree("space", "/sync", |_| {}).unwrap();
        let scope = cache
            .find_plaintext_scope("https://example.invalid", "recovery-account", "space")
            .unwrap()
            .unwrap();
        cache
            .invalidate_paths(&scope, &["/sync/pinned.txt"])
            .unwrap();
        *cloud.fail_all.lock().unwrap() = Some(ErrorKind::Offline);
        assert!(engine.list("space", "/sync").is_err());
        let recovery = engine
            .offline_pin_recovery_manifest("space", &pin.id)
            .unwrap();
        assert_eq!(recovery.state, PinState::Stale);
        assert_eq!(recovery.entries.len(), 1);
        assert_eq!(recovery.entries[0].entry.path, "/sync/pinned.txt");
        assert!(!recovery.entries[0].entry.writable);
        let expected = &recovery.entries[0];
        let mut reader = engine
            .open_offline_pin_recovery_content("space", &pin.id, expected)
            .unwrap();
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"retained version");
        let mut forged = expected.clone();
        forged.entry.path = "/sync/replacement.txt".into();
        assert!(
            engine
                .open_offline_pin_recovery_content("space", &pin.id, &forged)
                .is_err()
        );
        assert!(
            engine.list("space", "/sync").is_err(),
            "reading recovery metadata must not publish a current listing"
        );
    }

    #[test]
    fn account_rebind_cannot_reuse_another_accounts_offline_cache() {
        let state = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        fs::set_permissions(
            state.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let cloud = Arc::new(FakeCloud::new());
        cloud.insert_file("/sync/pinned.txt", b"account one retained bytes");
        let cache = Cache::open(state.path(), 64 * 1024 * 1024).unwrap();
        let first = Engine::open(state.path(), cloud)
            .unwrap()
            .with_offline_cache(
                cache,
                "first-account".into(),
                "https://example.invalid/".into(),
            )
            .unwrap();
        let pin = first.pin_offline_tree("space", "/sync", |_| {}).unwrap();
        assert_eq!(first.offline_pins("space").unwrap().len(), 1);
        assert!(
            first
                .offline_pin_recovery_manifest("space", &pin.id)
                .is_ok()
        );
        assert_eq!(
            first
                .with_account_scope("first-account".into(), "https://elsewhere.invalid".into())
                .err()
                .unwrap()
                .kind,
            ErrorKind::Conflict
        );
        let same = first
            .with_account_scope("first-account".into(), "https://example.invalid".into())
            .unwrap();
        assert_eq!(
            same.offline_pins("space").unwrap().len(),
            1,
            "canonical equivalent origins preserve the same account cache"
        );
        let rebound = first
            .with_account_scope("second-account".into(), "https://example.invalid/".into())
            .unwrap();
        assert!(
            rebound.offline_pins("space").is_err(),
            "another account must not inherit old cache metadata"
        );
        assert!(
            rebound
                .offline_pin_recovery_manifest("space", &pin.id)
                .is_err()
        );
        // Rebinding does not erase the original account's retained pin.
        assert_eq!(
            first.offline_pin_status("space", &pin.id).unwrap().state,
            PinState::Ready
        );
    }

    #[test]
    fn recursive_pin_and_file_policy_preserve_exact_offline_versions_across_restart() {
        let state = tempfile::tempdir().expect("state dir");
        #[cfg(unix)]
        fs::set_permissions(
            state.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("private state directory");
        let cloud = Arc::new(FakeCloud::new());
        cloud.insert_file("/sync/pinned.txt", b"pinned version");
        cloud.insert_file("/policy.txt", b"always available");
        cloud.insert_file("/cloud-only.txt", b"never use offline bytes");
        let cache = Cache::open(state.path(), 64 * 1024 * 1024).expect("open cache");
        let status_cache = cache.clone();
        let engine = Engine::open(state.path(), cloud.clone())
            .expect("open engine")
            .with_offline_cache(
                cache,
                "profile-account-1".into(),
                "https://example.invalid/".into(),
            )
            .expect("bind cache identity");

        let mut progress = Vec::new();
        let pin = engine
            .pin_offline_tree("space", "/sync", |status| progress.push(status))
            .expect("pin folder recursively");
        assert_eq!(pin.state, raiun_cache::PinState::Ready);
        assert_eq!(pin.item_count, 1);
        assert_eq!(pin.required_content_count, 1);
        assert!(progress.len() >= 2);

        engine
            .set_availability_policy("space", "/policy.txt", AvailabilityPolicy::AlwaysOffline)
            .expect("cache exact file version before policy");
        engine
            .set_availability_policy("space", "/cloud-only.txt", AvailabilityPolicy::CloudOnly)
            .expect("set cloud-only policy");
        drop(engine);

        let cache = Cache::open(state.path(), 64 * 1024 * 1024).expect("reopen cache");
        let scope = cache
            .find_plaintext_scope("https://example.invalid/", "profile-account-1", "space")
            .expect("read scope")
            .expect("persisted scope");
        let persisted_pins = cache.pins(&scope).expect("persistent pin progress");
        assert_eq!(persisted_pins.len(), 1);
        assert_eq!(persisted_pins[0].state, raiun_cache::PinState::Ready);
        assert_eq!(status_cache.evict_recent(0).unwrap().protected_bytes, 30);

        *cloud.fail_all.lock().expect("offline mode lock") = Some(ErrorKind::Offline);
        let engine = Engine::open(state.path(), cloud.clone())
            .expect("reopen engine")
            .with_offline_cache(
                cache,
                "profile-account-1".into(),
                "https://example.invalid/".into(),
            )
            .expect("rebind cache identity");
        let files = engine
            .list("space", "/sync")
            .expect("offline pinned listing");
        assert!(files.iter().any(|entry| entry.path == "/sync/pinned.txt"));
        let mut pinned = engine
            .fetch_snapshot("space", "/sync/pinned.txt")
            .expect("offline pinned read");
        let mut pinned_bytes = Vec::new();
        pinned.read_to_end(&mut pinned_bytes).unwrap();
        assert_eq!(pinned_bytes, b"pinned version");
        let mut always = engine
            .fetch_snapshot("space", "/policy.txt")
            .expect("offline AlwaysOffline read");
        let mut always_bytes = Vec::new();
        always.read_to_end(&mut always_bytes).unwrap();
        assert_eq!(always_bytes, b"always available");
        let error = engine
            .fetch_snapshot("space", "/cloud-only.txt")
            .err()
            .expect("CloudOnly item has no offline content");
        assert_eq!(error.kind, ErrorKind::Offline);
    }

    #[test]
    fn reserved_recovery_directories_are_not_uploaded_as_pair_content() {
        let (_state, _parent, cloud, engine, pair) = setup();
        let recovery = pair.local_path.join(".raiun-preserve-test");
        fs::create_dir(&recovery).expect("recovery directory");
        fs::write(recovery.join("previous-version"), b"preserved local data")
            .expect("recovery copy");
        let report = engine.sync_pair(&pair).expect("sync skips recovery data");
        assert_eq!(report.uploaded, 0);
        assert!(
            cloud
                .bytes("/sync/.raiun-preserve-test/previous-version")
                .is_none()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rejects_non_utf8_local_roots_instead_of_staging_lossy_paths() {
        use std::os::unix::ffi::OsStringExt;

        let state = tempfile::tempdir().expect("state dir");
        let parent = tempfile::tempdir().expect("local parent");
        let local = parent
            .path()
            .join(std::ffi::OsString::from_vec(b"pair-\xff".to_vec()));
        fs::create_dir(&local).expect("non-UTF-8 pair root");
        let engine = Engine::open(state.path(), Arc::new(FakeCloud::new())).expect("engine");
        let pair = FolderPair {
            id: "non-utf8".into(),
            local_path: local,
            space_id: "space".into(),
            vault: None,
            remote_path: "/sync".into(),
            mode: SyncMode::TwoWay,
            excluded_paths: Vec::new(),
            content_filter: raiun_core::MediaFilter::All,
            exclusions: Vec::new(),
        };
        assert_eq!(
            engine.sync_pair(&pair).unwrap_err().kind,
            ErrorKind::Unsupported
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn folder_download_stages_on_destination_filesystem_across_mounts() {
        use std::os::unix::fs::MetadataExt;

        let Ok(local_parent) = tempfile::tempdir_in("/dev/shm") else {
            return;
        };
        let state = tempfile::tempdir().expect("state dir");
        if fs::metadata(local_parent.path()).unwrap().dev()
            == fs::metadata(state.path()).unwrap().dev()
        {
            return;
        }
        let local = local_parent.path().join("pair");
        fs::create_dir_all(&local).expect("pair root");
        let cloud = Arc::new(FakeCloud::new());
        cloud.insert_file("/sync/from-cloud.txt", b"remote bytes");
        let engine = Engine::open(state.path(), cloud).expect("open engine");
        let pair = FolderPair {
            id: "pair".into(),
            local_path: local.clone(),
            space_id: "space".into(),
            vault: None,
            remote_path: "/sync".into(),
            mode: SyncMode::DownloadOnly,
            excluded_paths: Vec::new(),
            content_filter: raiun_core::MediaFilter::All,
            exclusions: Vec::new(),
        };

        let report = engine.sync_pair(&pair).expect("cross-filesystem sync");
        assert_eq!(report.downloaded, 1);
        assert_eq!(
            fs::read(local.join("from-cloud.txt")).unwrap(),
            b"remote bytes"
        );
    }

    #[test]
    fn uploads_and_downloads_changes_and_persists_baseline_across_restart() {
        let (state, _parent, cloud, engine, pair) = setup();
        fs::write(pair.local_path.join("local.txt"), b"first").expect("write local");
        let report = engine.sync_pair(&pair).expect("initial upload");
        assert_eq!(report.uploaded, 1);
        assert_eq!(
            cloud.bytes("/sync/local.txt").as_deref(),
            Some(&b"first"[..])
        );

        cloud.insert_file("/sync/remote.txt", b"from cloud");
        fs::write(pair.local_path.join("local.txt"), b"local edit").expect("edit local");
        let report = engine.sync_pair(&pair).expect("incremental sync");
        assert_eq!(report.uploaded, 1);
        assert_eq!(report.downloaded, 1);
        assert_eq!(
            fs::read(pair.local_path.join("remote.txt")).expect("downloaded"),
            b"from cloud"
        );

        drop(engine);
        let reopened = Engine::open(state.path(), cloud).expect("reopen engine");
        let report = reopened.sync_pair(&pair).expect("restart sync");
        assert_eq!(report.unchanged, 2);
        assert_eq!(reopened.transfers(10).expect("history").len(), 3);
    }

    #[test]
    fn remote_only_update_replaces_unchanged_local_file_without_leaving_backup() {
        let (_state, _parent, cloud, engine, pair) = setup();
        fs::write(pair.local_path.join("shared.txt"), b"baseline").expect("write local");
        engine.sync_pair(&pair).expect("initial sync");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = pair.local_path.join("shared.txt");
            let mut permissions = fs::metadata(&path).unwrap().permissions();
            permissions.set_mode(0o751);
            fs::set_permissions(path, permissions).unwrap();
        }
        cloud.insert_file("/sync/shared.txt", b"remote update");

        let report = engine.sync_pair(&pair).expect("remote-only update");
        assert_eq!(report.downloaded, 1);
        assert_eq!(
            fs::read(pair.local_path.join("shared.txt")).unwrap(),
            b"remote update"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(pair.local_path.join("shared.txt"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o751
            );
        }
        assert_eq!(fs::read_dir(&pair.local_path).unwrap().count(), 1);
    }

    #[test]
    fn preserves_both_sides_when_a_baselined_file_changes_on_both_sides() {
        let (_state, _parent, cloud, engine, pair) = setup();
        fs::write(pair.local_path.join("shared.txt"), b"baseline").expect("write local");
        engine.sync_pair(&pair).expect("initial upload");
        fs::write(pair.local_path.join("shared.txt"), b"local edit").expect("edit local");
        cloud.insert_file("/sync/shared.txt", b"remote edit");
        let report = engine.sync_pair(&pair).expect("conflict sync");
        assert_eq!(report.conflicts, 1);
        assert_eq!(
            fs::read(pair.local_path.join("shared.txt")).expect("local preserved"),
            b"local edit"
        );
        assert_eq!(
            cloud.bytes("/sync/shared.txt").as_deref(),
            Some(&b"remote edit"[..])
        );
    }

    #[test]
    fn conflict_page_is_bounded_and_resolution_keeps_local_with_remote_recovery() {
        let (_state, _parent, cloud, engine, pair) = setup();
        fs::write(pair.local_path.join("first.txt"), b"base-one").expect("local one");
        fs::write(pair.local_path.join("second.txt"), b"base-two").expect("local two");
        engine.sync_pair(&pair).expect("initial upload");
        fs::write(pair.local_path.join("first.txt"), b"local-one").expect("local edit one");
        fs::write(pair.local_path.join("second.txt"), b"local-two").expect("local edit two");
        cloud.insert_file("/sync/first.txt", b"remote-one");
        cloud.insert_file("/sync/second.txt", b"remote-two");

        let page = engine
            .conflicts(&pair, None, 1)
            .expect("first conflict page");
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].path, "first.txt");
        assert_eq!(
            page.items[0].local_hash,
            hash_file(&pair.local_path.join("first.txt")).unwrap()
        );
        assert_eq!(page.next_after.as_deref(), Some("first.txt"));
        let next = engine
            .conflicts(&pair, page.next_after.as_deref(), 1)
            .expect("second conflict page");
        assert_eq!(next.items.len(), 1);
        assert_eq!(next.items[0].path, "second.txt");
        assert_eq!(next.next_after, None);

        let conflict = &page.items[0];
        let resolution = engine
            .resolve_conflict(
                &pair,
                &conflict.path,
                ConflictChoice::KeepLocal,
                &conflict.local_hash,
                &conflict.remote_etag,
            )
            .expect("keep local");
        assert_eq!(resolution.choice, ConflictChoice::KeepLocal);
        assert_eq!(
            fs::read(pair.local_path.join("first.txt")).unwrap(),
            b"local-one"
        );
        assert_eq!(
            cloud.bytes("/sync/first.txt").as_deref(),
            Some(&b"local-one"[..])
        );
        assert_eq!(fs::read(&resolution.recovery_path).unwrap(), b"remote-one");
        assert!(
            resolution
                .recovery_path
                .to_string_lossy()
                .contains(".raiun-preserve-")
        );
        assert_eq!(engine.sync_pair(&pair).unwrap().unchanged, 1);
    }

    #[test]
    fn conflict_resolution_keeps_remote_with_local_recovery_and_advances_baseline() {
        let (_state, _parent, cloud, engine, pair) = setup();
        fs::write(pair.local_path.join("shared.txt"), b"base").expect("local base");
        engine.sync_pair(&pair).expect("initial upload");
        fs::write(pair.local_path.join("shared.txt"), b"local edit").expect("local edit");
        cloud.insert_file("/sync/shared.txt", b"remote edit");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = pair.local_path.join("shared.txt");
            let mut permissions = fs::metadata(&path).unwrap().permissions();
            permissions.set_mode(0o751);
            fs::set_permissions(path, permissions).unwrap();
        }
        let conflict = engine.conflicts(&pair, None, 10).unwrap().items.remove(0);

        let resolution = engine
            .resolve_conflict(
                &pair,
                &conflict.path,
                ConflictChoice::KeepRemote,
                &conflict.local_hash,
                &conflict.remote_etag,
            )
            .expect("keep remote");
        assert_eq!(resolution.choice, ConflictChoice::KeepRemote);
        assert_eq!(
            fs::read(pair.local_path.join("shared.txt")).unwrap(),
            b"remote edit"
        );
        assert_eq!(fs::read(&resolution.recovery_path).unwrap(), b"local edit");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(pair.local_path.join("shared.txt"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o751
            );
        }
        let report = engine.sync_pair(&pair).expect("baseline is current");
        assert_eq!(report.unchanged, 1);
        assert_eq!(report.uploaded, 0);
        assert_eq!(report.downloaded, 0);
    }

    #[test]
    fn stale_conflict_fingerprints_and_disallowed_modes_do_not_overwrite() {
        let (_state, _parent, cloud, engine, pair) = setup();
        fs::write(pair.local_path.join("shared.txt"), b"base").expect("local base");
        engine.sync_pair(&pair).expect("initial upload");
        fs::write(pair.local_path.join("shared.txt"), b"local edit").expect("local edit");
        cloud.insert_file("/sync/shared.txt", b"remote edit");
        let conflict = engine.conflicts(&pair, None, 10).unwrap().items.remove(0);
        fs::write(pair.local_path.join("shared.txt"), b"later local edit").expect("new edit");
        assert_eq!(
            engine
                .resolve_conflict(
                    &pair,
                    &conflict.path,
                    ConflictChoice::KeepLocal,
                    &conflict.local_hash,
                    &conflict.remote_etag,
                )
                .unwrap_err()
                .kind,
            ErrorKind::Conflict
        );
        assert_eq!(
            cloud.bytes("/sync/shared.txt").as_deref(),
            Some(&b"remote edit"[..])
        );

        let current = engine.conflicts(&pair, None, 10).unwrap().items.remove(0);
        cloud.insert_file("/sync/shared.txt", b"newer remote edit");
        assert_eq!(
            engine
                .resolve_conflict(
                    &pair,
                    &current.path,
                    ConflictChoice::KeepRemote,
                    &current.local_hash,
                    &current.remote_etag,
                )
                .unwrap_err()
                .kind,
            ErrorKind::Conflict
        );
        assert_eq!(
            fs::read(pair.local_path.join("shared.txt")).unwrap(),
            b"later local edit"
        );
        assert_eq!(
            cloud.bytes("/sync/shared.txt").as_deref(),
            Some(&b"newer remote edit"[..])
        );

        let mut upload_only = pair.clone();
        upload_only.mode = SyncMode::UploadOnly;
        engine
            .publish_pair_policy(&upload_only)
            .expect("publish upload-only conflict policy");
        let current = engine
            .conflicts(&upload_only, None, 10)
            .unwrap()
            .items
            .remove(0);
        assert_eq!(
            engine
                .resolve_conflict(
                    &upload_only,
                    &current.path,
                    ConflictChoice::KeepRemote,
                    &current.local_hash,
                    &current.remote_etag,
                )
                .unwrap_err()
                .kind,
            ErrorKind::Unsupported
        );
        assert_eq!(
            fs::read(pair.local_path.join("shared.txt")).unwrap(),
            b"later local edit"
        );

        let mut download_only = pair.clone();
        download_only.mode = SyncMode::DownloadOnly;
        engine
            .publish_pair_policy(&download_only)
            .expect("publish download-only conflict policy");
        let current = engine
            .conflicts(&download_only, None, 10)
            .unwrap()
            .items
            .remove(0);
        assert_eq!(
            engine
                .resolve_conflict(
                    &download_only,
                    &current.path,
                    ConflictChoice::KeepLocal,
                    &current.local_hash,
                    &current.remote_etag,
                )
                .unwrap_err()
                .kind,
            ErrorKind::Unsupported
        );
        assert_eq!(
            fs::read(pair.local_path.join("shared.txt")).unwrap(),
            b"later local edit"
        );
        assert_eq!(
            cloud.bytes("/sync/shared.txt").as_deref(),
            Some(&b"newer remote edit"[..])
        );
    }

    #[test]
    fn conflict_listing_skips_content_download_for_one_sided_and_encrypted_files() {
        let (_state, _parent, cloud, engine, pair) = setup();
        fs::write(pair.local_path.join("one-sided.txt"), b"base-one").expect("one-sided");
        fs::write(pair.local_path.join("secret.txt"), b"base-secret").expect("secret");
        engine.sync_pair(&pair).expect("initial upload");
        fs::write(pair.local_path.join("one-sided.txt"), b"local-one").expect("local edit");
        fs::write(pair.local_path.join("secret.txt"), b"local-secret").expect("secret edit");
        cloud.insert_file("/sync/secret.txt", b"remote-secret");
        cloud
            .entries
            .lock()
            .expect("entries mutex")
            .get_mut("/sync/secret.txt")
            .expect("secret remote")
            .0
            .encrypted = true;
        *cloud.downloads.lock().expect("download count") = 0;

        let page = engine.conflicts(&pair, None, 100).expect("list conflicts");
        assert!(page.items.is_empty());
        assert_eq!(*cloud.downloads.lock().expect("download count"), 0);
    }

    #[test]
    fn total_scan_budget_is_cumulative_and_rejects_an_overflowing_addition() {
        let mut total = 0;
        charge_scan_budget(&mut total, 2, 3).expect("first batch");
        charge_scan_budget(&mut total, 1, 3).expect("exact limit");
        let error = charge_scan_budget(&mut total, 1, 3).unwrap_err();
        assert_eq!(error.kind, ErrorKind::InvalidResponse);
        assert!(error.message.contains("3-entry total limit"));
        assert_eq!(total, 3);

        let mut total = usize::MAX;
        assert_eq!(
            charge_scan_budget(&mut total, 1, usize::MAX)
                .unwrap_err()
                .kind,
            ErrorKind::InvalidResponse
        );
        assert_eq!(total, usize::MAX);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn hash_cache_whitelist_is_narrow_and_audit_is_periodic() {
        for trusted in [0xEF53, 0x9123_683E, 0x5846_5342, 0x0102_1994] {
            assert!(trusted_hash_cache_filesystem(trusted));
        }
        for unknown in [0, 0x794C_7630, 0x6573_5546, 0x0102_1995] {
            assert!(!trusted_hash_cache_filesystem(unknown));
        }
        assert!(!should_force_hash_audit(119));
        assert!(should_force_hash_audit(120));
        assert!(!should_force_hash_audit(121));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn zero_nanosecond_ctime_disables_cache_even_when_filesystem_is_allowed() {
        let coarse = LocalFingerprint {
            device: 1,
            inode: 2,
            size: 3,
            mtime_seconds: 4,
            mtime_nanoseconds: 0,
            ctime_seconds: 5,
            ctime_nanoseconds: 0,
        };
        assert!(!may_reuse_local_hash(true, false, Some(coarse)));

        let precise = LocalFingerprint {
            ctime_nanoseconds: 1,
            ..coarse
        };
        assert!(may_reuse_local_hash(true, false, Some(precise)));
        assert!(!may_reuse_local_hash(true, true, Some(precise)));
    }

    #[test]
    fn failed_listing_and_missing_local_root_never_delete_remote_content() {
        let (_state, local_parent, cloud, engine, pair) = setup();
        fs::write(pair.local_path.join("kept.txt"), b"keep").expect("write local");
        engine.sync_pair(&pair).expect("initial sync");
        *cloud.fail_listing.lock().expect("listing flag") = true;
        assert_eq!(
            engine.sync_pair(&pair).unwrap_err().kind,
            ErrorKind::Offline
        );
        *cloud.fail_listing.lock().expect("listing flag") = false;
        fs::remove_dir_all(&pair.local_path).expect("remove unavailable pair root");
        assert!(engine.sync_pair(&pair).is_err());
        assert_eq!(cloud.bytes("/sync/kept.txt").as_deref(), Some(&b"keep"[..]));
        assert!(local_parent.path().exists());
    }

    #[test]
    fn failed_upload_retains_dirty_local_file_and_old_baseline() {
        let (_state, _parent, cloud, engine, pair) = setup();
        fs::write(pair.local_path.join("dirty.txt"), b"baseline").expect("write local");
        engine.sync_pair(&pair).expect("initial sync");
        fs::write(pair.local_path.join("dirty.txt"), b"dirty queued content").expect("edit local");
        *cloud.fail_upload.lock().expect("upload flag") = true;
        assert_eq!(
            engine.sync_pair(&pair).unwrap_err().kind,
            ErrorKind::Offline
        );
        assert_eq!(
            fs::read(pair.local_path.join("dirty.txt")).expect("local remains"),
            b"dirty queued content"
        );
        assert_eq!(
            cloud.bytes("/sync/dirty.txt").as_deref(),
            Some(&b"baseline"[..])
        );
        let transfer = engine.transfers(1).expect("history").remove(0);
        assert_eq!(transfer.state, "failed");
        assert_eq!(transfer.origin, "folder_pair");
        *cloud.fail_upload.lock().expect("upload flag") = false;
        assert_eq!(
            engine
                .sync_pair(&pair)
                .expect("retry by reconciliation")
                .uploaded,
            1
        );
        assert_eq!(
            cloud.bytes("/sync/dirty.txt").as_deref(),
            Some(&b"dirty queued content"[..])
        );
    }

    #[test]
    fn refuses_to_scan_engine_state_as_a_folder_pair() {
        let state = tempfile::tempdir().expect("state dir");
        let local = state.path().join("pair");
        fs::create_dir_all(&local).expect("pair dir");
        let cloud = Arc::new(FakeCloud::new());
        let engine = Engine::open(state.path(), cloud).expect("open engine");
        let pair = FolderPair {
            id: "overlap".into(),
            local_path: local,
            space_id: "space".into(),
            vault: None,
            remote_path: "/sync".into(),
            mode: SyncMode::TwoWay,
            excluded_paths: Vec::new(),
            content_filter: raiun_core::MediaFilter::All,
            exclusions: Vec::new(),
        };
        assert_eq!(
            engine.sync_pair(&pair).unwrap_err().kind,
            ErrorKind::Unsupported
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinks_inside_a_pair_instead_of_following_them() {
        use std::os::unix::fs::symlink;

        let (_state, _parent, cloud, engine, pair) = setup();
        let outside = pair
            .local_path
            .parent()
            .expect("pair parent")
            .join("outside.txt");
        fs::write(&outside, b"outside data").expect("outside file");
        symlink(&outside, pair.local_path.join("link.txt")).expect("symlink");
        assert_eq!(
            engine.sync_pair(&pair).unwrap_err().kind,
            ErrorKind::Unsupported
        );
        assert!(cloud.bytes("/sync/link.txt").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_pair_root_replaced_by_symlink_without_uploading_target_files() {
        use std::os::unix::fs::symlink;

        let (_state, _parent, cloud, engine, pair) = setup();
        let outside = pair
            .local_path
            .parent()
            .expect("pair parent")
            .join("replacement-target");
        fs::create_dir_all(&outside).expect("outside directory");
        fs::write(outside.join("hijack.txt"), b"must not upload").expect("outside content");
        fs::remove_dir(&pair.local_path).expect("remove configured root");
        symlink(&outside, &pair.local_path).expect("replace root with symlink");

        let error = engine.sync_pair(&pair).unwrap_err();
        assert_eq!(error.kind, ErrorKind::Unsupported);
        assert!(cloud.bytes("/sync/hijack.txt").is_none());
    }
}
