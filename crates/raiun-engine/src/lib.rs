//! Persistent, conservative folder-pair reconciliation.
//!
//! Inventories and transfer history live in SQLite. Directory walks and cloud
//! listings are staged incrementally; a failed scan never advances a baseline.
//! The first implementation serializes mutations through one engine mutex.

use raiun_core::backend::{
    CloudBackend, CloudError, CloudSpace, ErrorKind, RemoteEntry, WriteCondition,
};
use raiun_core::{FolderPair, SyncMode};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex, MutexGuard,
    atomic::{AtomicBool, Ordering},
};
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::{Builder as TempBuilder, NamedTempFile};

#[derive(Clone)]
pub struct Engine {
    inner: Arc<Inner>,
}

struct Inner {
    state_dir: PathBuf,
    cache_dir: PathBuf,
    backend: Arc<dyn CloudBackend>,
    db: Mutex<Connection>,
    execution: Mutex<()>,
    sync_paused: AtomicBool,
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

/// A verified download whose temporary file is removed when the snapshot is
/// dropped. Use this for short-lived provider reads that should not accumulate
/// in the persistent engine cache.
pub struct FetchSnapshot {
    // The backend may atomically replace this pathname after receiving it as
    // the download destination. Keep the NamedTempFile only as the path owner;
    // `file` is reopened after the backend returns so reads use the published
    // contents rather than the now-unlinked original inode.
    _temp: NamedTempFile,
    file: File,
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
    pub fn open(state_dir: &Path, backend: Arc<dyn CloudBackend>) -> Result<Self, CloudError> {
        fs::create_dir_all(state_dir).map_err(io_error)?;
        let state_dir = fs::canonicalize(state_dir).map_err(io_error)?;
        let cache_dir = state_dir.join("cache");
        fs::create_dir_all(&cache_dir).map_err(io_error)?;
        let db_path = state_dir.join("engine.sqlite3");
        let db = Connection::open(db_path).map_err(db_error)?;
        db.busy_timeout(std::time::Duration::from_secs(10))
            .map_err(db_error)?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA foreign_keys=ON;
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
             PRAGMA user_version=1;",
        )
        .map_err(db_error)?;
        // An operation that was still running at process death has an unknown
        // remote outcome. Keep it visible as failed; a later reconciliation
        // must inspect the destination before attempting another mutation.
        db.execute("UPDATE transfers SET status='failed',message='engine stopped while operation was running',finished_unix=?1 WHERE status='running'", [now_unix()]).map_err(db_error)?;
        Ok(Self {
            inner: Arc::new(Inner {
                state_dir,
                cache_dir,
                backend,
                db: Mutex::new(db),
                execution: Mutex::new(()),
                sync_paused: AtomicBool::new(false),
            }),
        })
    }

    /// Pause or resume folder-pair reconciliation. An in-flight sync stops at
    /// its next local-entry, remote-entry, or reconciliation boundary.
    pub fn set_sync_paused(&self, paused: bool) {
        self.inner.sync_paused.store(paused, Ordering::Release);
    }

    pub fn spaces(&self) -> Result<Vec<CloudSpace>, CloudError> {
        self.inner.backend.spaces()
    }

    pub fn list(&self, space: &str, path: &str) -> Result<Vec<RemoteEntry>, CloudError> {
        let mut entries = Vec::new();
        self.inner.backend.list(space, path, &mut |entry| {
            if entries.len() >= MAX_LIST_ENTRIES {
                return Err(CloudError::new(
                    ErrorKind::InvalidResponse,
                    "cloud listing exceeds the 100,000-entry limit",
                ));
            }
            entries.push(entry);
            Ok(())
        })?;
        Ok(entries)
    }

    pub fn stat(&self, space: &str, path: &str) -> Result<RemoteEntry, CloudError> {
        self.inner.backend.stat(space, path)
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
        let result = (|| {
            let before = self.inner.backend.stat(space, path)?;
            if before.directory {
                return Err(CloudError::new(
                    ErrorKind::Unsupported,
                    "cannot fetch a directory as a file",
                ));
            }
            let snapshot = NamedTempFile::new_in(self.cache_dir()).map_err(io_error)?;
            let entry =
                self.inner
                    .backend
                    .download(space, path, Some(&before.etag), snapshot.path())?;
            // CloudBackend implementations may publish downloads with an
            // atomic rename over the destination. Reopen the path after the
            // call: the original NamedTempFile handle can now point at an
            // unlinked, empty inode even though the destination has content.
            let mut file = File::open(snapshot.path()).map_err(io_error)?;
            let size = file.metadata().map_err(io_error)?.len();
            if entry.etag != before.etag || size != entry.size || size != before.size {
                return Err(CloudError::new(
                    ErrorKind::InvalidResponse,
                    "download revision or size failed verification",
                ));
            }
            file.sync_all().map_err(io_error)?;
            file.seek(SeekFrom::Start(0)).map_err(io_error)?;
            Ok((
                FetchSnapshot {
                    _temp: snapshot,
                    file,
                },
                size,
            ))
        })();
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
        let id = self.begin_transfer(None, space, path, "mkdir")?;
        match self.inner.backend.mkdir(space, path) {
            Ok(entry) => match self.inner.backend.stat(space, path) {
                Ok(verified) if verified.directory && verified.etag == entry.etag => {
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
        let _guard = self.execution()?;
        let id = self.begin_transfer(None, space, path, "delete")?;
        match self.inner.backend.delete(space, path, expected_etag) {
            Ok(()) => match self.inner.backend.stat(space, path) {
                Err(error) if error.kind == ErrorKind::NotFound => {
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
        let id = self.begin_transfer(None, space, from, "rename")?;
        match self.inner.backend.rename(space, from, to, expected_etag) {
            Ok(entry) => match self.inner.backend.stat(space, to) {
                Ok(verified) if verified.etag == entry.etag => {
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
        validate_pair_runtime(pair)?;
        self.validate_pair_root(pair)?;
        self.clear_stage(&pair.id)?;
        let mut scanned_entries = 0;
        self.scan_local(pair, &mut scanned_entries, true, None)?;
        self.scan_remote_for_conflicts(pair, &mut scanned_entries)?;

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
                    if remote.encrypted {
                        continue;
                    }
                    let remote_hash =
                        if self.conflict_needs_content_compare(pair, &rel, &local.hash, &remote)? {
                            Some(hash_for_remote(self, &pair.space_id, &remote.path)?)
                        } else {
                            None
                        };
                    if self.is_conflict_state(
                        pair,
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
        validate_pair_runtime(pair)?;
        self.validate_pair_root(pair)?;
        validate_conflict_path(rel)?;
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
        let remote = self.inner.backend.stat(&pair.space_id, &remote_path)?;
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
        if !self.is_conflict_state(pair, rel, &local_hash, &remote, Some(&remote_hash))? {
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
                let uploaded = self.upload_inner(
                    Some(&pair.id),
                    &pair.space_id,
                    &remote.path,
                    snapshot.path(),
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
                    &self.inner.backend,
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
        validate_pair_runtime(pair)?;
        self.validate_pair_root(pair)?;
        self.clear_stage(&pair.id)?;
        let mut scanned_entries = 0;
        self.scan_local(pair, &mut scanned_entries, false, None)?;
        self.scan_remote(pair, &mut scanned_entries)?;
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
                let baseline = self.baseline(&pair.id, &rel)?;
                match (local, remote) {
                    (Some(l), Some(r)) if l.directory && r.directory => {
                        report.unchanged += 1;
                    }
                    (Some(l), Some(r)) if !l.directory && !r.directory => {
                        self.reconcile_file(pair, &rel, l, r, baseline, &mut report)?;
                    }
                    (Some(l), None) if l.directory => {
                        if baseline.is_some() {
                            report.needs_attention += 1;
                        } else if pair.mode != SyncMode::DownloadOnly {
                            self.upload_directory(pair, &rel, &mut report)?;
                        }
                    }
                    (Some(l), None) if !l.directory => {
                        if baseline.is_some() {
                            report.needs_attention += 1;
                        } else if pair.mode != SyncMode::DownloadOnly {
                            self.upload_file(pair, &rel, &l.path, None, &mut report)?;
                        }
                    }
                    (None, Some(r)) if r.directory => {
                        if baseline.is_some() {
                            report.needs_attention += 1;
                        } else if pair.mode != SyncMode::UploadOnly {
                            self.create_local_dir(pair, &rel)?;
                        }
                    }
                    (None, Some(r)) if !r.directory => {
                        if baseline.is_some() {
                            report.needs_attention += 1;
                        } else if pair.mode != SyncMode::UploadOnly {
                            self.download_file(pair, &rel, &r, &mut report)?;
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
                let meta = fs::symlink_metadata(&path).map_err(io_error)?;
                if meta.file_type().is_symlink() {
                    return Err(CloudError::new(
                        ErrorKind::Unsupported,
                        format!("symlink is unsupported in folder pair: {}", path.display()),
                    ));
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
                let local_path = path.to_str().ok_or_else(|| {
                    CloudError::new(
                        ErrorKind::Unsupported,
                        "local path contains non-UTF-8 path bytes",
                    )
                })?;
                let directory = meta.is_dir();
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
            self.inner
                .backend
                .list(&pair.space_id, &dir, &mut |entry| {
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
                    if let Err(error) =
                        charge_scan_budget(scanned_entries, 1, MAX_TOTAL_SCAN_ENTRIES)
                    {
                        failure = Some(error.clone());
                        return Err(error);
                    }
                    if skip_encrypted && entry.encrypted {
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
        match self.inner.backend.mkdir(&pair.space_id, &remote) {
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
        fs::create_dir_all(parent).map_err(io_error)?;
        ensure_safe_pair_path(&pair.local_path, &destination, true)?;
        let staged = NamedTempFile::new_in(parent).map_err(io_error)?;
        let id = self.begin_transfer(Some(&pair.id), &pair.space_id, &remote.path, "download")?;
        let result = self
            .inner
            .backend
            .download(
                &pair.space_id,
                &remote.path,
                Some(&remote.etag),
                staged.path(),
            )
            .and_then(|entry| {
                if entry.etag != remote.etag {
                    return Err(CloudError::new(
                        ErrorKind::Conflict,
                        "remote revision changed during download",
                    ));
                }
                staged.as_file().sync_all().map_err(io_error)?;
                let size = fs::metadata(staged.path()).map_err(io_error)?.len();
                if size != entry.size {
                    return Err(CloudError::new(
                        ErrorKind::InvalidResponse,
                        "download size does not match the server response",
                    ));
                }
                Ok((entry, size, hash_file(staged.path())?))
            });
        match result {
            Ok((entry, size, hash)) => {
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
        let before_hash = hash_file(source)?;
        let bytes = fs::metadata(source).map_err(io_error)?.len();
        let id = self.begin_transfer(pair_id, space, path, "upload")?;
        let result = self
            .inner
            .backend
            .upload(space, path, source, condition)
            .and_then(|uploaded| {
                let remote_temp = self.unique_temp("verify")?;
                let checked = self
                    .inner
                    .backend
                    .download(space, path, Some(&uploaded.etag), &remote_temp)
                    .and_then(|verified| {
                        let actual_hash = hash_file(&remote_temp)?;
                        let actual_size = fs::metadata(&remote_temp).map_err(io_error)?.len();
                        if verified.etag != uploaded.etag
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
                self.finish_transfer(id, "completed", bytes, None)?;
                Ok(entry)
            }
            Err(error) => {
                self.finish_transfer(id, "failed", 0, Some(&error.message))?;
                Err(error)
            }
        }
    }

    fn fetch_inner(&self, space: &str, path: &str) -> Result<(PathBuf, u64), CloudError> {
        let before = self.inner.backend.stat(space, path)?;
        if before.directory {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "cannot fetch a directory as a file",
            ));
        }
        let dest = self.cache_dir().join(cache_key(space, path));
        let tmp = self.unique_temp("fetch")?;
        let entry = match self
            .inner
            .backend
            .download(space, path, Some(&before.etag), &tmp)
        {
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

    fn validate_pair_root(&self, pair: &FolderPair) -> Result<(), CloudError> {
        let local_root = ensure_pair_root_is_real_directory(&pair.local_path)?;
        if local_root.starts_with(&self.inner.state_dir)
            || self.inner.state_dir.starts_with(&local_root)
        {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "folder pair overlaps engine state or cache storage",
            ));
        }
        Ok(())
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
    fn db(&self) -> Result<MutexGuard<'_, Connection>, CloudError> {
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

fn ensure_pair_root_is_real_directory(path: &Path) -> Result<PathBuf, CloudError> {
    let before = fs::symlink_metadata(path).map_err(io_error)?;
    if before.file_type().is_symlink() {
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
    if after.file_type().is_symlink() || !same_file(&before, &after) {
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
    File::open(&recovery_file)
        .and_then(|file| file.sync_all())
        .map_err(io_error)?;
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
    let downloaded =
        engine
            .inner
            .backend
            .download(space, remote_path, Some(&expected.etag), staged.path());
    let result = downloaded.and_then(|entry| {
        if entry.etag != expected.etag || entry.size != expected.size {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "remote file changed while its recovery copy was created",
            ));
        }
        let file = File::open(staged.path()).map_err(io_error)?;
        let size = file.metadata().map_err(io_error)?.len();
        file.sync_all().map_err(io_error)?;
        if size != entry.size || hash_file(staged.path())? != expected_hash {
            return Err(CloudError::new(
                ErrorKind::InvalidResponse,
                "remote recovery copy failed content or size verification",
            ));
        }
        Ok((size, entry))
    });
    let (size, _entry) = match result {
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
    if let Err(error) = File::open(&recovery_file)
        .and_then(|file| file.sync_all())
        .map_err(io_error)
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
    let entry = backend.download(space, path, Some(&expected.etag), staged.path())?;
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
    let file = File::open(staged.path()).map_err(io_error)?;
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
    let backup_dir = TempBuilder::new()
        .prefix(".raiun-preserve-")
        .tempdir_in(parent)
        .map_err(io_error)?;
    let backup = backup_dir.path().join("previous-version");

    preserve_unix_permissions(&staged, destination)?;
    File::open(staged.path())
        .and_then(|file| file.sync_all())
        .map_err(io_error)?;

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
    let entry = engine.inner.backend.stat(space, path)?;
    let downloaded = engine
        .inner
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
fn cache_key(space: &str, path: &str) -> String {
    hex(&Sha256::digest(format!("{space}\0{path}").as_bytes()))
}
fn hash_file(path: &Path) -> Result<String, CloudError> {
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
            Ok(metadata) if metadata.file_type().is_symlink() => {
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
fn db_error(error: rusqlite::Error) -> CloudError {
    CloudError::new(ErrorKind::Io, format!("engine database error: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::mpsc::{self, Receiver, SyncSender};

    #[derive(Default)]
    struct FakeCloud {
        entries: Mutex<BTreeMap<String, (RemoteEntry, Vec<u8>)>>,
        next_etag: Mutex<u64>,
        downloads: Mutex<usize>,
        fail_listing: Mutex<bool>,
        fail_upload: Mutex<bool>,
        list_repeat: Mutex<usize>,
        list_gate: Mutex<Option<(SyncSender<()>, Receiver<()>)>>,
    }

    impl FakeCloud {
        fn new() -> Self {
            let cloud = Self::default();
            cloud.insert_dir("/sync");
            cloud
        }

        fn insert_dir(&self, path: &str) {
            self.insert(path, true, Vec::new());
        }

        fn insert_file(&self, path: &str, data: &[u8]) {
            self.insert(path, false, data.to_vec());
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
        fn spaces(&self) -> Result<Vec<CloudSpace>, CloudError> {
            Ok(vec![CloudSpace {
                id: "space".into(),
                name: "Fixture".into(),
                dav_url: "https://example.invalid/dav".into(),
                personal: false,
                writable: true,
                encrypted: false,
            }])
        }

        fn list(
            &self,
            _space: &str,
            path: &str,
            visit: &mut dyn FnMut(RemoteEntry) -> Result<(), CloudError>,
        ) -> Result<(), CloudError> {
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
            self.remote_entry(path)
        }

        fn download(
            &self,
            _space: &str,
            path: &str,
            expected_etag: Option<&str>,
            destination: &Path,
        ) -> Result<RemoteEntry, CloudError> {
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
            self.remote_entry(path)
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
            remote_path: "/sync".into(),
            mode: SyncMode::TwoWay,
        };
        (state, local_parent, cloud, engine, pair)
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
            remote_path: "/sync".into(),
            mode: SyncMode::TwoWay,
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
            remote_path: "/sync".into(),
            mode: SyncMode::TwoWay,
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
            remote_path: "/sync".into(),
            mode: SyncMode::DownloadOnly,
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
            remote_path: "/sync".into(),
            mode: SyncMode::TwoWay,
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
