//! Windows cache construction retains private directory and SQLite VFS owners.
use super::{Cache, CacheError, DbOwner, Inner, MAX_CONTENT_BYTES, MAX_CONTENT_RECORDS, schema};
use raiun_control_windows::{PinnedDirectory, PrivateDirectory};
use std::ffi::OsStr;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};

impl Cache {
    pub(super) fn open_windows(state: &Path, quota_bytes: u64) -> Result<Self, CacheError> {
        let state = PinnedDirectory::open(state).map_err(|_| CacheError::UnsafeDirectory)?;
        let root = PrivateDirectory::create_or_open_under(&state, OsStr::new("cache-v1"))
            .map_err(|_| CacheError::UnsafeDirectory)?;
        // Never ignore a WAL from an incompatible previous storage owner. Its
        // uncheckpointed pages may be the only durable copy of pending edits.
        for name in ["cache.sqlite3-wal", "cache.sqlite3-shm"] {
            match root.open_regular_file(OsStr::new(name)) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                _ => return Err(CacheError::UnsafeDirectory),
            }
        }
        let pinned_root =
            PinnedDirectory::open(root.path()).map_err(|_| CacheError::UnsafeDirectory)?;
        let content = PrivateDirectory::create_or_open_under(&pinned_root, OsStr::new("content"))
            .map_err(|_| CacheError::UnsafeDirectory)?;
        // SQLite owns one root pin; generation locks retain another validated
        // pin to the same directory. Neither can be replaced while in use.
        let lock_root = PrivateDirectory::create_or_open_under(&state, OsStr::new("cache-v1"))
            .map_err(|_| CacheError::UnsafeDirectory)?;
        let root_path = root.path().to_owned();
        let content_path = content.path().to_owned();
        let database =
            raiun_sqlite_windows::RegisteredRollbackDb::open(root).map_err(super::db_error)?;
        schema::initialize(
            database.borrow_cache_connection(),
            schema::JournalMode::PinnedRollback,
        )?;
        let quota_bytes =
            super::load_or_seed_quota(database.borrow_cache_connection(), quota_bytes)?;
        let cache = Self {
            inner: Arc::new(Inner {
                root: root_path,
                content_dir: content_path,
                db: Mutex::new(DbOwner::Windows(database)),
                quota_bytes: std::sync::atomic::AtomicU64::new(quota_bytes),
                windows_root: lock_root,
                windows_content: super::windows_blob::WindowsBlobStore {
                    directory: Arc::new(content),
                    // Recent-content quota is separate from protected data.
                    // This hard safety bound also charges unknown crash stages.
                    max_bytes: MAX_CONTENT_BYTES,
                    max_objects: MAX_CONTENT_RECORDS,
                },
            }),
        };
        cache.remove_unindexed_content()?;
        Ok(cache)
    }
}
