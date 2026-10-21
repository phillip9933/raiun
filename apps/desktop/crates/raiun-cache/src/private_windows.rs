//! Windows cache storage integration and private-directory policy tests.

use super::{CacheError, DB_FILE};
use raiun_control_windows::{PinnedDirectory, PrivateDirectory};
use rusqlite::{Connection, TransactionBehavior};
use std::ffi::OsStr;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

const CACHE_DIRECTORY: &str = "cache-v1";
const CONTENT_DIRECTORY: &str = "content";
const SQLITE_MEMBERS: [&str; 4] = [
    DB_FILE,
    "cache.sqlite3-wal",
    "cache.sqlite3-shm",
    "cache.sqlite3-journal",
];

struct WindowsCacheDirectories {
    root: PrivateDirectory,
    content: PrivateDirectory,
}

impl WindowsCacheDirectories {
    fn create_under(state_directory: &Path) -> Result<Self, CacheError> {
        let state = PinnedDirectory::open(state_directory).map_err(map_private_error)?;
        let root = PrivateDirectory::create_or_open_under(&state, OsStr::new(CACHE_DIRECTORY))
            .map_err(map_private_error)?;
        let root_directory = PinnedDirectory::open(root.path()).map_err(map_private_error)?;
        let content =
            PrivateDirectory::create_or_open_under(&root_directory, OsStr::new(CONTENT_DIRECTORY))
                .map_err(map_private_error)?;
        Ok(Self { root, content })
    }

    fn database_path(&self) -> PathBuf {
        self.root.path().join(DB_FILE)
    }

    fn create_database_file(&self) -> Result<(), CacheError> {
        match self.root.open_regular_file(OsStr::new(DB_FILE)) {
            Ok((_file, _identity)) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let (file, _identity) = self
                    .root
                    .create_new_file(OsStr::new(DB_FILE))
                    .map_err(map_private_error)?;
                file.sync_all().map_err(map_io_error)
            }
            Err(error) => Err(map_private_error(error)),
        }
    }

    /// Validate each currently present SQLite member using the handle-pinned
    /// no-follow, single-link, exact-owner/DACL policy. Missing sidecars are
    /// normal before first use or after SQLite checkpoints them away.
    fn validate_sqlite_members(&self) -> Result<(), CacheError> {
        self.root.verify_path().map_err(map_private_error)?;
        self.content.verify_path().map_err(map_private_error)?;
        let mut database_present = false;
        for name in SQLITE_MEMBERS {
            match self.root.open_regular_file(OsStr::new(name)) {
                Ok((_file, _identity)) => {
                    if name == DB_FILE {
                        database_present = true;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound && name != DB_FILE => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    return Err(CacheError::UnsafeDirectory);
                }
                Err(error) => return Err(map_private_error(error)),
            }
        }
        if !database_present {
            return Err(CacheError::UnsafeDirectory);
        }
        Ok(())
    }
}

fn map_private_error(error: io::Error) -> CacheError {
    if error.kind() == io::ErrorKind::PermissionDenied
        || error.kind() == io::ErrorKind::InvalidInput
    {
        CacheError::UnsafeDirectory
    } else {
        CacheError::Io(error.to_string())
    }
}

fn map_io_error(error: io::Error) -> CacheError {
    CacheError::Io(error.to_string())
}

fn integrated_cache(state_directory: &Path) -> super::Cache {
    let mut cache = super::Cache::open(state_directory, 1024 * 1024).unwrap();
    // Preserve the tighter limits used by this integration suite while going
    // through the same public constructor as production callers.
    let inner = std::sync::Arc::get_mut(&mut cache.inner)
        .expect("newly opened test cache should not have shared owners");
    let store = &mut inner.windows_content;
    store.max_bytes = 1024 * 1024;
    store.max_objects = 128;
    cache
}

#[test]
fn public_cache_open_roundtrips_a_normal_cache() {
    let state = tempfile::tempdir().expect("create synthetic state directory");
    {
        let cache = super::Cache::open(state.path(), 1024).unwrap();
        assert_eq!(cache.quota_bytes(), 1024);
    }

    let reopened = super::Cache::open(state.path(), 1024).unwrap();
    assert_eq!(reopened.quota_bytes(), 1024);
    assert!(reopened.root().join(DB_FILE).is_file());
}

#[test]
fn public_cache_open_rejects_a_preexisting_unsafe_cache_directory_without_repair() {
    let state = tempfile::tempdir().expect("create synthetic state directory");
    let cache_root = state.path().join(CACHE_DIRECTORY);
    std::fs::create_dir(&cache_root).expect("create an untrusted cache directory");

    assert!(matches!(
        super::Cache::open(state.path(), 1024),
        Err(CacheError::UnsafeDirectory)
    ));
    assert!(cache_root.is_dir());
    assert!(
        !cache_root.join(CONTENT_DIRECTORY).exists(),
        "opening must not repair an unsafe preexisting cache directory"
    );
}

#[test]
fn public_cache_open_preserves_and_rejects_legacy_wal_sidecars() {
    for name in ["cache.sqlite3-wal", "cache.sqlite3-shm"] {
        let state = tempfile::tempdir().unwrap();
        let cache = super::Cache::open(state.path(), 1024).unwrap();
        let sidecar = cache.root().join(name);
        drop(cache);
        let recovery = b"synthetic uncheckpointed recovery pages";
        std::fs::write(&sidecar, recovery).unwrap();
        assert!(matches!(
            super::Cache::open(state.path(), 1024),
            Err(CacheError::UnsafeDirectory)
        ));
        assert_eq!(std::fs::read(sidecar).unwrap(), recovery);
    }
}

#[test]
fn public_cache_open_rejects_a_hardlinked_database_without_repair() {
    let state = tempfile::tempdir().expect("create synthetic state directory");
    let cache = super::Cache::open(state.path(), 1024).unwrap();
    let database = cache.root().join(DB_FILE);
    drop(cache);
    let alias = state.path().join("database-alias");
    let original = std::fs::read(&database).unwrap();
    std::fs::hard_link(&database, &alias).expect("create synthetic hard link");

    // The pinned SQLite VFS reports the refused file as a database I/O error.
    // The contract is refusal without opening or repairing either alias.
    assert!(super::Cache::open(state.path(), 1024).is_err());
    assert_eq!(std::fs::read(&database).unwrap(), original);
    assert_eq!(std::fs::read(&alias).unwrap(), original);
    assert!(database.is_file());
    assert!(alias.is_file());
}

fn integrated_scope(account: &str, root: &str) -> super::CacheScope {
    super::CacheScope::new(
        "https://synthetic.invalid/",
        account,
        "space-a",
        root,
        super::ScopeProtection::PlaintextAllowed,
    )
    .unwrap()
}

fn integrated_ciphertext_scope(account: &str, root: &str) -> super::CacheScope {
    super::CacheScope::new(
        "https://synthetic.invalid/",
        account,
        "space-a",
        root,
        super::ScopeProtection::CiphertextOnly,
    )
    .unwrap()
}

struct SeededCiphertextSubtree {
    root_id: String,
    child_id: String,
    root_row: super::CiphertextWriteInfo,
    child_row: super::CiphertextWriteInfo,
    members: Vec<super::CiphertextSubtreeRetarget>,
    old_root_version: super::ContentVersion,
    old_child_version: super::ContentVersion,
}

fn seed_ciphertext_subtree(
    cache: &super::Cache,
    scope: &super::CacheScope,
) -> SeededCiphertextSubtree {
    let root = cache
        .begin_ciphertext_operation_with_state_and_parent(
            scope,
            None,
            "opaque-root",
            Some(""),
            0,
            super::CiphertextWriteOperation::CreateDirectory,
            super::CiphertextWriteState::NeverAttempted,
        )
        .unwrap();
    let root_id = root.id().to_owned();
    let old_root_version = root.content_version();
    let root_body = b"root-v1";
    let root_row = cache
        .publish_ciphertext_write(scope, &root, &mut &root_body[..], root_body.len() as u64)
        .unwrap();
    let child = cache
        .begin_ciphertext_operation_with_state_parent_ref(
            scope,
            None,
            "opaque-root/file",
            Some("opaque-root"),
            Some((&root_id, root_row.revision)),
            8,
            super::CiphertextWriteOperation::CreateFile,
            super::CiphertextWriteState::NeverAttempted,
        )
        .unwrap();
    let child_id = child.id().to_owned();
    let old_child_version = child.content_version();
    let child_body = b"child-v1";
    let child_row = cache
        .publish_ciphertext_write(scope, &child, &mut &child_body[..], child_body.len() as u64)
        .unwrap();

    let members = vec![
        super::CiphertextSubtreeRetarget {
            id: root_id.clone(),
            expected_revision: root_row.revision,
            expected_target: "opaque-root".into(),
            new_target: "opaque-root-new".into(),
            new_parent_path: "".into(),
            new_parent_operation: None,
            plaintext_len: 0,
            operation: super::CiphertextWriteOperation::CreateDirectory,
        },
        super::CiphertextSubtreeRetarget {
            id: child_id.clone(),
            expected_revision: child_row.revision,
            expected_target: "opaque-root/file".into(),
            new_target: "opaque-root-new/file".into(),
            new_parent_path: "opaque-root-new".into(),
            new_parent_operation: Some((root_id.clone(), root_row.revision + 1)),
            plaintext_len: 8,
            operation: super::CiphertextWriteOperation::CreateFile,
        },
    ];
    SeededCiphertextSubtree {
        root_id,
        child_id,
        root_row,
        child_row,
        members,
        old_root_version,
        old_child_version,
    }
}

fn integrated_version() -> super::ContentVersion {
    super::ContentVersion {
        resource_id: "file-a".into(),
        etag: "version-a".into(),
        protection: super::ContentProtection::Plaintext,
    }
}

fn absent_write_request(expected_len: u64) -> super::ConditionalWriteRequest {
    super::ConditionalWriteRequest {
        parent_resource_id: "root-a".into(),
        name: "newfile".into(),
        logical_path: "/newfile".into(),
        resource_id: None,
        base: raiun_core::backend::WriteCondition::Absent,
        expected_len,
        protection: super::ContentProtection::Plaintext,
    }
}

fn publish_integrated(
    cache: &super::Cache,
    scope: &super::CacheScope,
    version: &super::ContentVersion,
    bytes: &[u8],
) -> super::ContentRecord {
    publish_integrated_with_retention(cache, scope, version, bytes, super::Retention::Recent)
}

fn publish_integrated_with_retention(
    cache: &super::Cache,
    scope: &super::CacheScope,
    version: &super::ContentVersion,
    bytes: &[u8],
    retention: super::Retention,
) -> super::ContentRecord {
    let mut source = bytes;
    cache
        .publish_content_internal(
            scope,
            version,
            &mut source,
            bytes.len() as u64,
            retention,
            false,
        )
        .unwrap()
}

fn compact_integrated_ciphertext_create(
    cache: &super::Cache,
    scope: &super::CacheScope,
    target: &str,
    body: &[u8],
) -> (String, u64, super::ContentVersion) {
    let parent = "encrypted-parent";
    let build = cache
        .begin_ciphertext_operation_with_state_and_parent(
            scope,
            None,
            target,
            Some(parent),
            body.len() as u64,
            super::CiphertextWriteOperation::CreateFile,
            super::CiphertextWriteState::NeverAttempted,
        )
        .unwrap();
    let row = cache
        .publish_ciphertext_write(scope, &build, &mut &body[..], body.len() as u64)
        .unwrap();
    let old_version = super::ContentVersion {
        resource_id: format!("vault-write-{}", row.id),
        etag: format!("revision-{}", row.revision),
        protection: super::ContentProtection::Ciphertext,
    };
    cache
        .cancel_never_attempted_ciphertext_file_create(
            scope,
            &row.id,
            row.revision,
            target,
            body.len() as u64,
        )
        .unwrap();
    let ack = cache
        .begin_ciphertext_cancel_ack_compaction(scope, &row.id, row.revision, target)
        .unwrap();
    let compact = b"compact acknowledgement";
    cache
        .publish_ciphertext_write(scope, &ack, &mut &compact[..], compact.len() as u64)
        .unwrap();
    (row.id, row.revision, old_version)
}

fn begin_integrated_plaintext_file_pin(
    cache: &super::Cache,
    scope: &super::CacheScope,
    expected_len: u64,
) -> (super::PinInfo, super::ContentVersion) {
    let root_id = scope.root_resource_id().to_owned();
    let entry = super::RemoteEntry {
        id: "pin-file".into(),
        path: "/pin-file".into(),
        etag: "pin-file-v1".into(),
        size: expected_len,
        directory: false,
        modified_unix: 1,
        writable: true,
        encrypted: false,
    };
    cache
        .publish_listing(
            scope,
            &root_id,
            &[super::CachedEntry {
                parent_resource_id: root_id.clone(),
                entry: entry.clone(),
            }],
            1,
        )
        .unwrap();
    let pin = cache
        .begin_pin_at(
            scope,
            &root_id,
            "/",
            &[super::PinManifestEntry {
                parent_resource_id: root_id.clone(),
                entry: entry.clone(),
            }],
        )
        .unwrap();
    let version = super::ContentVersion {
        resource_id: entry.id,
        etag: entry.etag,
        protection: super::ContentProtection::Plaintext,
    };
    (pin, version)
}

#[test]
fn sqlite_wal_members_validate_with_private_directory_policy() {
    let state = tempfile::tempdir().expect("create synthetic state directory");
    let directories = WindowsCacheDirectories::create_under(state.path()).unwrap();
    directories.create_database_file().unwrap();
    directories.validate_sqlite_members().unwrap();

    let connection = Connection::open(directories.database_path()).unwrap();
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
        .unwrap();
    assert_eq!(journal_mode.to_ascii_lowercase(), "wal");
    connection
        .execute_batch(
            "CREATE TABLE sample(value TEXT NOT NULL);
             BEGIN IMMEDIATE;
             INSERT INTO sample(value) VALUES ('synthetic');
             COMMIT;",
        )
        .unwrap();

    for sidecar in ["cache.sqlite3-wal", "cache.sqlite3-shm"] {
        assert!(directories.root.path().join(sidecar).is_file(), "{sidecar}");
    }
    directories.validate_sqlite_members().unwrap();
}

#[test]
fn sqlite_rollback_journal_validates_with_private_directory_policy() {
    let state = tempfile::tempdir().expect("create synthetic state directory");
    let directories = WindowsCacheDirectories::create_under(state.path()).unwrap();
    directories.create_database_file().unwrap();
    let mut connection = Connection::open(directories.database_path()).unwrap();
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))
        .unwrap();
    assert_eq!(journal_mode.to_ascii_lowercase(), "delete");
    connection
        .execute("CREATE TABLE sample(value TEXT NOT NULL)", [])
        .unwrap();

    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    transaction
        .execute("INSERT INTO sample(value) VALUES ('synthetic')", [])
        .unwrap();
    assert!(
        directories
            .root
            .path()
            .join("cache.sqlite3-journal")
            .is_file(),
        "SQLite should create the rollback journal while the write is pending"
    );
    directories.validate_sqlite_members().unwrap();
    transaction.commit().unwrap();
}

#[test]
fn sqlite_member_hardlink_is_rejected_without_repair() {
    let state = tempfile::tempdir().expect("create synthetic state directory");
    let directories = WindowsCacheDirectories::create_under(state.path()).unwrap();
    directories.create_database_file().unwrap();
    let database = directories.database_path();
    let alias = directories.root.path().join("database-alias");
    std::fs::hard_link(&database, &alias).expect("create synthetic hard link");

    assert!(matches!(
        directories.validate_sqlite_members(),
        Err(CacheError::UnsafeDirectory)
    ));
    assert!(
        database.is_file(),
        "rejected validation must not delete the database"
    );
    assert!(
        alias.is_file(),
        "rejected validation must not repair the alias"
    );
    std::fs::remove_file(alias).unwrap();
}

#[test]
fn rollback_adapter_opens_cache_root_and_preserves_committed_metadata() {
    let state = tempfile::tempdir().unwrap();
    let directories = WindowsCacheDirectories::create_under(state.path()).unwrap();
    let mut database = raiun_sqlite_windows::RegisteredRollbackDb::open(directories.root).unwrap();
    database.with_cache_connection(|connection| {
        let mode: String = connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
        assert_eq!(mode, "delete");
        connection.execute_batch("CREATE TABLE integration_probe(value TEXT NOT NULL); INSERT INTO integration_probe VALUES ('retained');")
    }).unwrap();
    assert!(database.close().is_ok());
    let directories = WindowsCacheDirectories::create_under(state.path()).unwrap();
    let mut reopened = raiun_sqlite_windows::RegisteredRollbackDb::open(directories.root).unwrap();
    reopened
        .with_cache_connection(|connection| {
            let value: String =
                connection
                    .query_row("SELECT value FROM integration_probe", [], |row| row.get(0))?;
            assert_eq!(value, "retained");
            Ok(())
        })
        .unwrap();
    assert!(reopened.close().is_ok());
    let reopened_cache = super::Cache::open(state.path(), 1024).unwrap();
    assert!(reopened_cache.root().join(DB_FILE).is_file());
}

#[test]
fn rollback_owner_serializes_transactions_and_reopens_after_threaded_use() {
    use std::sync::{Arc, Mutex};

    let state = tempfile::tempdir().unwrap();
    let directories = WindowsCacheDirectories::create_under(state.path()).unwrap();
    let mut database = raiun_sqlite_windows::RegisteredRollbackDb::open(directories.root).unwrap();
    database
        .with_cache_connection(|connection| {
            connection.execute_batch("CREATE TABLE integration_probe(value INTEGER PRIMARY KEY)")
        })
        .unwrap();
    let owner = Arc::new(Mutex::new(super::db_owner::DbOwner::Windows(database)));
    let workers = (0..4)
        .map(|value| {
            let owner = Arc::clone(&owner);
            std::thread::spawn(move || -> rusqlite::Result<()> {
                let mut guard = owner.lock().unwrap();
                let rolled_back = guard.transaction()?;
                rolled_back.execute("INSERT INTO integration_probe VALUES (?1)", [value + 100])?;
                drop(rolled_back);
                let committed = guard.transaction_with_behavior(TransactionBehavior::Immediate)?;
                committed.execute("INSERT INTO integration_probe VALUES (?1)", [value])?;
                committed.commit()
            })
        })
        .collect::<Vec<_>>();
    for worker in workers {
        worker.join().unwrap().unwrap();
    }
    let database = Arc::try_unwrap(owner).ok().unwrap().into_inner().unwrap();
    let super::db_owner::DbOwner::Windows(database) = database;
    assert!(database.close().is_ok());

    let directories = WindowsCacheDirectories::create_under(state.path()).unwrap();
    let mut reopened = raiun_sqlite_windows::RegisteredRollbackDb::open(directories.root).unwrap();
    reopened
        .with_cache_connection(|connection| {
            let values = connection
                .prepare("SELECT value FROM integration_probe ORDER BY value")?
                .query_map([], |row| row.get::<_, i64>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            assert_eq!(values, vec![0, 1, 2, 3]);
            Ok(())
        })
        .unwrap();
    assert!(reopened.close().is_ok());
    let reopened_cache = super::Cache::open(state.path(), 1024).unwrap();
    assert!(reopened_cache.root().join(DB_FILE).is_file());
}

#[test]
fn rollback_owner_initializes_real_cache_schema_and_preserves_scoped_metadata() {
    use super::db_owner::DbOwner;
    use super::schema::{self, JournalMode};

    let state = tempfile::tempdir().unwrap();
    let directories = WindowsCacheDirectories::create_under(state.path()).unwrap();
    let database = raiun_sqlite_windows::RegisteredRollbackDb::open(directories.root).unwrap();
    let mut owner = DbOwner::Windows(database);
    schema::initialize(&owner, JournalMode::PinnedRollback).unwrap();
    let transaction = owner
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    transaction.execute("INSERT INTO scopes VALUES ('scope-a','https://synthetic.invalid/','account-a','space-a','root-a',1)", []).unwrap();
    transaction
        .execute("INSERT INTO ciphertext_epochs VALUES ('scope-a',7)", [])
        .unwrap();
    assert!(
        transaction
            .execute(
                "INSERT INTO ciphertext_epochs VALUES ('unknown-scope',1)",
                []
            )
            .is_err()
    );
    transaction.commit().unwrap();
    let DbOwner::Windows(database) = owner;
    assert!(database.close().is_ok());

    let directories = WindowsCacheDirectories::create_under(state.path()).unwrap();
    let database = raiun_sqlite_windows::RegisteredRollbackDb::open(directories.root).unwrap();
    let owner = DbOwner::Windows(database);
    schema::initialize(&owner, JournalMode::PinnedRollback).unwrap();
    let identity: (String, String, String, i64) = owner.query_row(
        "SELECT account_id,space_id,root_resource_id,epoch FROM scopes JOIN ciphertext_epochs USING(scope_key) WHERE scope_key='scope-a'",
        [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
    ).unwrap();
    assert_eq!(
        identity,
        ("account-a".into(), "space-a".into(), "root-a".into(), 7)
    );
    let mode: String = owner
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap();
    assert_eq!(mode, "delete");
    owner.pragma_update(None, "user_version", 999).unwrap();
    assert!(matches!(
        schema::initialize(&owner, JournalMode::PinnedRollback),
        Err(CacheError::Corrupt)
    ));
    let version: i64 = owner
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, 999, "unknown schemas must not be rewritten");
    let DbOwner::Windows(database) = owner;
    assert!(database.close().is_ok());
    assert!(matches!(
        super::Cache::open(state.path(), 1024),
        Err(CacheError::Corrupt)
    ));
}

#[test]
fn central_publication_opens_verified_bytes_and_survives_reopen() {
    let state = tempfile::tempdir().unwrap();
    let cache = integrated_cache(state.path());
    let scope = integrated_scope("account-a", "root-a");
    let version = integrated_version();
    let record = publish_integrated(&cache, &scope, &version, b"integrated bytes");
    assert_eq!(cache.content_record(&scope, &version).unwrap(), record);
    let mut reader = cache.open_content(&scope, &version).unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"integrated bytes");
    drop(reader);
    drop(cache);

    let reopened = integrated_cache(state.path());
    assert_eq!(reopened.content_record(&scope, &version).unwrap(), record);
    let mut reader = reopened.open_content(&scope, &version).unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"integrated bytes");
}

#[test]
fn central_content_keys_separate_accounts_and_roots() {
    let state = tempfile::tempdir().unwrap();
    let cache = integrated_cache(state.path());
    let version = integrated_version();
    let scopes = [
        integrated_scope("account-a", "root-a"),
        integrated_scope("account-b", "root-a"),
        integrated_scope("account-a", "root-b"),
    ];
    let mut paths = Vec::new();
    for scope in &scopes {
        publish_integrated(&cache, scope, &version, b"same bytes");
        let key = super::content_key(scope, &version);
        let path: String = cache
            .lock_db()
            .unwrap()
            .query_row(
                "SELECT relative_path FROM contents WHERE content_key=?1 AND scope_key=?2",
                rusqlite::params![key, scope.key],
                |row| row.get(0),
            )
            .unwrap();
        paths.push(path);
        let mut reader = cache.open_content(scope, &version).unwrap();
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"same bytes");
    }
    paths.sort();
    paths.dedup();
    assert_eq!(paths.len(), 3, "account and root are part of blob identity");
}

#[test]
fn central_reader_blocks_observed_blob_deletion_until_closed() {
    let state = tempfile::tempdir().unwrap();
    let cache = integrated_cache(state.path());
    let scope = integrated_scope("account-a", "root-a");
    let version = integrated_version();
    publish_integrated(&cache, &scope, &version, b"held reader");
    let key = super::content_key(&scope, &version);
    let blob_name = format!("{key}.blob");
    let store = &cache.inner.windows_content;
    let reader = cache.open_content(&scope, &version).unwrap();
    let observation = store
        .directory
        .open_owned_immutable_file(OsStr::new(&blob_name))
        .unwrap();
    let identity = observation.identity();
    drop(observation);

    assert!(
        store
            .directory
            .open_delete_candidate(OsStr::new(&blob_name), identity)
            .is_err()
    );
    drop(reader);
    store
        .directory
        .open_delete_candidate(OsStr::new(&blob_name), identity)
        .unwrap()
        .delete()
        .unwrap();
    assert!(!store.directory.path().join(blob_name).exists());
}

#[test]
fn policy_change_after_central_blob_publish_keeps_unindexed_blob() {
    let state = tempfile::tempdir().unwrap();
    let cache = integrated_cache(state.path());
    let scope = integrated_scope("account-a", "root-a");
    let version = integrated_version();
    let result = cache.publish_content_internal_with_hook(
        &scope,
        &version,
        &mut &b"preserve for recovery"[..],
        21,
        super::ContentPublishOptions {
            retention: super::Retention::Recent,
                recent_budget: false,
            require_listed: false,
            expected_ciphertext_epoch: None,
            pin_build: None,
            ciphertext_write: None,
        },
        || {
            cache
                .lock_db()
                .unwrap()
                .execute(
                    "INSERT INTO policies(scope_key,resource_id,policy,target_path,target_etag,target_state) VALUES(?1,?2,?3,'/','version-a',0)",
                    rusqlite::params![scope.key, version.resource_id, super::AvailabilityPolicy::CloudOnly as i64],
                )
                .unwrap();
        },
    );
    assert!(matches!(result, Err(CacheError::PolicyConflict)));
    assert!(matches!(
        cache.content_record(&scope, &version),
        Err(CacheError::NotFound)
    ));
    let key = super::content_key(&scope, &version);
    let blob_name = format!("{key}.blob");
    let mut recovery = cache
        .inner
        .windows_content
        .open_verified(&blob_name, 21, &sha256_hex(b"preserve for recovery"))
        .unwrap();
    let mut bytes = Vec::new();
    recovery.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"preserve for recovery");
}

#[test]
fn central_publication_lease_spans_blob_hook_and_metadata_commit() {
    let state = tempfile::tempdir().unwrap();
    let cache = integrated_cache(state.path());
    let scope = integrated_scope("account-a", "root-a");
    let version = integrated_version();
    let store = &cache.inner.windows_content;
    let other_store = super::windows_blob::WindowsBlobStore {
        directory: std::sync::Arc::clone(&store.directory),
        max_bytes: store.max_bytes,
        max_objects: store.max_objects,
    };
    let record = cache
        .publish_content_internal_with_hook(
            &scope,
            &version,
            &mut &b"lease held"[..],
            10,
            super::ContentPublishOptions {
                retention: super::Retention::Recent,
                recent_budget: false,
                require_listed: false,
                expected_ciphertext_epoch: None,
                pin_build: None,
                ciphertext_write: None,
            },
            || {
                assert!(matches!(
                    other_store.publication_lease(),
                    Err(CacheError::Conflict)
                ));
            },
        )
        .unwrap();
    assert_eq!(cache.content_record(&scope, &version).unwrap(), record);
    assert!(other_store.publication_lease().is_ok());
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

#[test]
fn integrated_startup_inventory_preserves_indexed_content_and_accounts_for_it() {
    let state = tempfile::tempdir().unwrap();
    let cache = integrated_cache(state.path());
    let scope = integrated_scope("account-a", "root-a");
    let version = integrated_version();
    let record = publish_integrated(&cache, &scope, &version, b"keep");
    cache.remove_unindexed_content().unwrap();
    assert_eq!(cache.usage().unwrap().used_bytes, record.byte_len);
    let mut bytes = Vec::new();
    cache
        .open_content(&scope, &version)
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(bytes, b"keep");
}

#[test]
fn integrated_inventory_rejects_hardlinked_unknown_blob_without_deleting_it() {
    let state = tempfile::tempdir().unwrap();
    let cache = integrated_cache(state.path());
    let unknown_name = format!("{}.blob", "a".repeat(64));
    let unknown = cache.inner.content_dir.join(unknown_name);
    let alias = state.path().join("unknown-blob-alias");
    std::fs::write(&unknown, b"unindexed recovery body").unwrap();
    std::fs::hard_link(&unknown, &alias).unwrap();

    assert!(matches!(
        cache.remove_unindexed_content(),
        Err(CacheError::Io(_))
    ));
    assert_eq!(std::fs::read(&unknown).unwrap(), b"unindexed recovery body");
    assert_eq!(std::fs::read(&alias).unwrap(), b"unindexed recovery body");
}

#[test]
fn integrated_inventory_rejects_unknown_name_without_deleting_it() {
    let state = tempfile::tempdir().unwrap();
    let cache = integrated_cache(state.path());
    let unknown = cache.inner.content_dir.join("unexpected-recovery-name");
    std::fs::write(&unknown, b"preserve unknown").unwrap();

    assert!(matches!(
        cache.remove_unindexed_content(),
        Err(CacheError::InvalidEntry)
    ));
    assert_eq!(std::fs::read(&unknown).unwrap(), b"preserve unknown");
}

#[test]
fn integrated_unindexed_published_body_survives_reopen_and_blocks_quota_bypass() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let state = tempfile::tempdir().unwrap();
    let cache = integrated_cache(state.path());
    let scope = integrated_scope("account-a", "root-a");
    let version = integrated_version();
    let body = vec![b'x'; 1024 * 1024];
    let result = catch_unwind(AssertUnwindSafe(|| {
        cache.publish_content_internal_with_hook(
            &scope,
            &version,
            &mut &body[..],
            body.len() as u64,
            super::ContentPublishOptions {
                retention: super::Retention::Recent,
                recent_budget: false,
                require_listed: false,
                expected_ciphertext_epoch: None,
                pin_build: None,
                ciphertext_write: None,
            },
            || panic!("synthetic interruption after blob publish"),
        )
    }));
    assert!(result.is_err());
    let path = cache
        .inner
        .content_dir
        .join(format!("{}.blob", super::content_key(&scope, &version)));
    assert!(path.is_file());
    let before_reopen = cache.usage().unwrap();
    assert_eq!(before_reopen.used_bytes, body.len() as u64);
    assert_eq!(before_reopen.protected_bytes, body.len() as u64);
    assert!(!before_reopen.over_quota);
    drop(cache);

    let reopened = integrated_cache(state.path());
    assert!(matches!(
        reopened.content_record(&scope, &version),
        Err(CacheError::NotFound)
    ));
    assert_eq!(std::fs::read(&path).unwrap(), body);
    let usage = reopened.usage().unwrap();
    assert_eq!(usage.used_bytes, body.len() as u64);
    assert_eq!(usage.protected_bytes, body.len() as u64);
    assert!(!usage.over_quota);

    let report = reopened.evict_recent(0).unwrap();
    assert_eq!(report.removed_bytes, 0);
    assert_eq!(report.used_bytes, body.len() as u64);
    assert_eq!(report.protected_bytes, body.len() as u64);
    assert!(report.over_quota);
    assert!(path.is_file());

    let next = super::ContentVersion {
        resource_id: "another-file".into(),
        etag: "version-b".into(),
        protection: super::ContentProtection::Plaintext,
    };
    assert!(matches!(
        reopened.publish_content_internal(
            &scope,
            &next,
            &mut &b"x"[..],
            1,
            super::Retention::Recent,
            false,
        ),
        Err(CacheError::InsufficientSpace)
    ));
    assert!(path.is_file());

    // Exercise configured-quota admission independently of the store's hard
    // capacity ceiling. The interrupted immutable body remains charged.
    let mut reopened = reopened;
    std::sync::Arc::get_mut(&mut reopened.inner)
        .unwrap()
        .windows_content
        .max_bytes = 2 * 1024 * 1024;
    reopened
        .publish_listing(
            &scope,
            "root-a",
            &[super::CachedEntry {
                parent_resource_id: "root-a".into(),
                entry: raiun_core::backend::RemoteEntry {
                    id: next.resource_id.clone(),
                    path: "/another-file".into(),
                    etag: next.etag.clone(),
                    directory: false,
                    encrypted: false,
                    size: 1,
                    modified_unix: 0,
                    writable: true,
                },
            }],
            1,
        )
        .unwrap();
    let mut source = std::io::Cursor::new(b"x");
    assert!(matches!(
        reopened.publish_recent_content_with_budget(&scope, &next, &mut source, 1,),
        Err(CacheError::InsufficientSpace)
    ));
    assert_eq!(source.position(), 0);
    assert!(matches!(
        reopened.content_record(&scope, &next),
        Err(CacheError::NotFound)
    ));
    assert_eq!(std::fs::read(&path).unwrap(), body);
    let after = reopened.usage().unwrap();
    assert_eq!(after.used_bytes, usage.used_bytes);
    assert_eq!(after.protected_bytes, usage.protected_bytes);
}

#[test]
fn integrated_eviction_counts_unknown_bytes_before_evicting_indexed_recent_content() {
    let state = tempfile::tempdir().unwrap();
    let cache = integrated_cache(state.path());
    let scope = integrated_scope("account-a", "root-a");
    let version = integrated_version();
    let indexed = publish_integrated(&cache, &scope, &version, b"12345678");
    let unknown = cache
        .inner
        .content_dir
        .join(format!("{}.blob", "b".repeat(64)));
    std::fs::write(&unknown, b"xyz").unwrap();

    let report = cache.evict_recent(10).unwrap();
    assert_eq!(report.removed_bytes, indexed.byte_len);
    assert_eq!(report.used_bytes, 3);
    assert_eq!(report.protected_bytes, 3);
    assert!(!report.over_quota);
    assert!(unknown.is_file());
    assert_eq!(std::fs::read(&unknown).unwrap(), b"xyz");
    assert!(matches!(
        cache.content_record(&scope, &version),
        Err(CacheError::NotFound)
    ));
}

#[test]
fn integrated_eviction_removes_recent_blob_and_metadata() {
    let state = tempfile::tempdir().unwrap();
    let cache = integrated_cache(state.path());
    let scope = integrated_scope("account-a", "root-a");
    let version = integrated_version();
    let record = publish_integrated(&cache, &scope, &version, b"evict me");
    let name = format!("{}.blob", super::content_key(&scope, &version));
    let path = cache.inner.content_dir.join(&name);
    assert!(path.is_file());

    let report = cache.evict_recent(0).unwrap();
    assert_eq!(report.removed_bytes, record.byte_len);
    assert_eq!(report.used_bytes, 0);
    assert_eq!(cache.usage().unwrap().used_bytes, 0);
    assert!(!path.exists());
    assert!(matches!(
        cache.content_record(&scope, &version),
        Err(CacheError::NotFound)
    ));
}

#[test]
fn integrated_cloud_only_removes_recent_blob_and_metadata() {
    let state = tempfile::tempdir().unwrap();
    let cache = integrated_cache(state.path());
    let scope = integrated_scope("account-a", "root-a");
    let version = integrated_version();
    let record = publish_integrated(&cache, &scope, &version, b"cloud only");
    let path = cache
        .inner
        .content_dir
        .join(format!("{}.blob", super::content_key(&scope, &version)));
    assert!(path.is_file());

    cache
        .set_policy_at(
            &scope,
            &version.resource_id,
            "/file-a",
            &version.etag,
            super::AvailabilityPolicy::CloudOnly,
        )
        .unwrap();
    assert_eq!(
        cache.policy(&scope, &version.resource_id).unwrap(),
        super::AvailabilityPolicy::CloudOnly
    );
    assert_eq!(cache.usage().unwrap().used_bytes, 0);
    assert!(!path.exists());
    assert!(matches!(
        cache.content_record(&scope, &version),
        Err(CacheError::NotFound)
    ));
    assert_eq!(record.byte_len, b"cloud only".len() as u64);
    assert!(matches!(
        cache.open_content(&scope, &version),
        Err(CacheError::NotFound)
    ));
}

#[test]
fn integrated_cloud_only_reader_conflict_rolls_back_until_reader_closes() {
    let state = tempfile::tempdir().unwrap();
    let cache = integrated_cache(state.path());
    let scope = integrated_scope("account-a", "root-a");
    let version = integrated_version();
    let record = publish_integrated(&cache, &scope, &version, b"reader keeps this");
    let path = cache
        .inner
        .content_dir
        .join(format!("{}.blob", super::content_key(&scope, &version)));
    let mut reader = cache.open_content(&scope, &version).unwrap();

    assert!(matches!(
        cache.set_policy_at(
            &scope,
            &version.resource_id,
            "/file-a",
            &version.etag,
            super::AvailabilityPolicy::CloudOnly,
        ),
        Err(CacheError::Conflict)
    ));
    assert_eq!(
        cache.policy(&scope, &version.resource_id).unwrap(),
        super::AvailabilityPolicy::Recent
    );
    assert_eq!(cache.content_record(&scope, &version).unwrap(), record);
    assert_eq!(cache.usage().unwrap().used_bytes, record.byte_len);
    assert!(path.is_file());
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"reader keeps this");
    drop(reader);

    cache
        .set_policy_at(
            &scope,
            &version.resource_id,
            "/file-a",
            &version.etag,
            super::AvailabilityPolicy::CloudOnly,
        )
        .unwrap();
    assert_eq!(
        cache.policy(&scope, &version.resource_id).unwrap(),
        super::AvailabilityPolicy::CloudOnly
    );
    assert_eq!(cache.usage().unwrap().used_bytes, 0);
    assert!(!path.exists());
    assert!(matches!(
        cache.content_record(&scope, &version),
        Err(CacheError::NotFound)
    ));
}

#[test]
fn integrated_cloud_only_reader_conflict_preserves_all_recent_versions() {
    let state = tempfile::tempdir().unwrap();
    let cache = integrated_cache(state.path());
    let scope = integrated_scope("account-a", "root-a");
    let first = integrated_version();
    let second = super::ContentVersion {
        resource_id: first.resource_id.clone(),
        etag: "etag-v2".into(),
        protection: first.protection,
    };
    let first_record = publish_integrated(&cache, &scope, &first, b"first version");
    let second_record = publish_integrated(&cache, &scope, &second, b"second version");
    let mut reader = cache.open_content(&scope, &second).unwrap();

    assert!(matches!(
        cache.set_policy_at(
            &scope,
            &first.resource_id,
            "/file-a",
            &second.etag,
            super::AvailabilityPolicy::CloudOnly,
        ),
        Err(CacheError::Conflict)
    ));
    assert_eq!(
        cache.policy(&scope, &first.resource_id).unwrap(),
        super::AvailabilityPolicy::Recent
    );
    assert_eq!(cache.content_record(&scope, &first).unwrap(), first_record);
    assert_eq!(
        cache.content_record(&scope, &second).unwrap(),
        second_record
    );
    assert_eq!(
        cache.usage().unwrap().used_bytes,
        first_record.byte_len + second_record.byte_len
    );

    let mut first_reader = cache.open_content(&scope, &first).unwrap();
    let mut first_bytes = Vec::new();
    first_reader.read_to_end(&mut first_bytes).unwrap();
    assert_eq!(first_bytes, b"first version");
    let mut second_bytes = Vec::new();
    reader.read_to_end(&mut second_bytes).unwrap();
    assert_eq!(second_bytes, b"second version");
}

#[test]
fn integrated_eviction_keeps_row_and_bytes_while_reader_is_open_then_evicts() {
    let state = tempfile::tempdir().unwrap();
    let cache = integrated_cache(state.path());
    let scope = integrated_scope("account-a", "root-a");
    let version = integrated_version();
    let record = publish_integrated(&cache, &scope, &version, b"read then evict");
    let name = format!("{}.blob", super::content_key(&scope, &version));
    let path = cache.inner.content_dir.join(&name);
    let mut reader = cache.open_content(&scope, &version).unwrap();

    let blocked = cache.evict_recent(0).unwrap();
    assert_eq!(blocked.removed_bytes, 0);
    assert_eq!(blocked.used_bytes, record.byte_len);
    assert!(blocked.over_quota);
    assert_eq!(cache.content_record(&scope, &version).unwrap(), record);
    assert!(path.is_file());
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"read then evict");
    drop(reader);

    let completed = cache.evict_recent(0).unwrap();
    assert_eq!(completed.removed_bytes, record.byte_len);
    assert_eq!(completed.used_bytes, 0);
    assert!(!path.exists());
    assert!(matches!(
        cache.content_record(&scope, &version),
        Err(CacheError::NotFound)
    ));
}

#[test]
fn integrated_eviction_preserves_dirty_and_recovery_retention() {
    let state = tempfile::tempdir().unwrap();
    let cache = integrated_cache(state.path());
    let scope = integrated_scope("account-a", "root-a");
    let dirty = super::ContentVersion {
        resource_id: "dirty-file".into(),
        etag: "dirty-version".into(),
        protection: super::ContentProtection::Plaintext,
    };
    let recovery = super::ContentVersion {
        resource_id: "recovery-file".into(),
        etag: "recovery-version".into(),
        protection: super::ContentProtection::Plaintext,
    };
    let dirty_record = publish_integrated_with_retention(
        &cache,
        &scope,
        &dirty,
        b"dirty bytes",
        super::Retention::Dirty,
    );
    let recovery_record = publish_integrated_with_retention(
        &cache,
        &scope,
        &recovery,
        b"recovery bytes",
        super::Retention::Recovery,
    );
    let dirty_path = cache
        .inner
        .content_dir
        .join(format!("{}.blob", super::content_key(&scope, &dirty)));
    let recovery_path = cache
        .inner
        .content_dir
        .join(format!("{}.blob", super::content_key(&scope, &recovery)));

    let report = cache.evict_recent(0).unwrap();
    assert_eq!(report.removed_bytes, 0);
    assert_eq!(
        report.used_bytes,
        dirty_record.byte_len + recovery_record.byte_len
    );
    assert_eq!(
        report.protected_bytes,
        dirty_record.byte_len + recovery_record.byte_len
    );
    assert!(dirty_path.is_file());
    assert!(recovery_path.is_file());
    assert_eq!(
        cache.content_record(&scope, &dirty).unwrap().retention,
        super::Retention::Dirty
    );
    assert_eq!(
        cache.content_record(&scope, &recovery).unwrap().retention,
        super::Retention::Recovery
    );
}

#[test]
fn integrated_cloud_only_evicts_clean_recent_and_preserves_journal_dirty_bytes() {
    let state = tempfile::tempdir().unwrap();
    let cache = integrated_cache(state.path());
    let scope = integrated_scope("account-a", "root-a");
    let clean = super::ContentVersion {
        resource_id: "clean-file".into(),
        etag: "clean-version".into(),
        protection: super::ContentProtection::Plaintext,
    };
    let dirty_base = super::ContentVersion {
        resource_id: "dirty-file".into(),
        etag: "base-version".into(),
        protection: super::ContentProtection::Plaintext,
    };
    let entries = [
        super::CachedEntry {
            parent_resource_id: "root-a".into(),
            entry: raiun_core::backend::RemoteEntry {
                id: clean.resource_id.clone(),
                path: "/clean.txt".into(),
                directory: false,
                size: 5,
                etag: clean.etag.clone(),
                modified_unix: 1,
                writable: true,
                encrypted: false,
            },
        },
        super::CachedEntry {
            parent_resource_id: "root-a".into(),
            entry: raiun_core::backend::RemoteEntry {
                id: dirty_base.resource_id.clone(),
                path: "/dirty.txt".into(),
                directory: false,
                size: 10,
                etag: dirty_base.etag.clone(),
                modified_unix: 1,
                writable: true,
                encrypted: false,
            },
        },
    ];
    cache
        .publish_listing(&scope, "root-a", &entries, 1)
        .unwrap();
    let clean_record = publish_integrated(&cache, &scope, &clean, b"clean");
    let clean_path = cache
        .inner
        .content_dir
        .join(format!("{}.blob", super::content_key(&scope, &clean)));
    assert!(clean_path.is_file());
    assert_eq!(clean_record.retention, super::Retention::Recent);
    assert_eq!(clean_record.byte_len, b"clean".len() as u64);

    // A CloudOnly policy is a local-cache operation. This cache-layer test has
    // no cloud client and makes no claim that bytes already read elsewhere can
    // be recalled or securely erased.
    cache
        .set_policy_at(
            &scope,
            &clean.resource_id,
            "/clean.txt",
            &clean.etag,
            super::AvailabilityPolicy::CloudOnly,
        )
        .unwrap();
    assert_eq!(
        cache.policy(&scope, &clean.resource_id).unwrap(),
        super::AvailabilityPolicy::CloudOnly
    );
    assert!(!clean_path.exists());
    assert!(matches!(
        cache.open_content(&scope, &clean),
        Err(CacheError::NotFound)
    ));

    let dirty_base_record = publish_integrated(&cache, &scope, &dirty_base, b"base bytes");
    let dirty = cache
        .queue_conditional_write(
            &scope,
            super::ConditionalWriteRequest {
                parent_resource_id: "root-a".into(),
                name: "dirty.txt".into(),
                logical_path: "/dirty.txt".into(),
                resource_id: Some(dirty_base.resource_id.clone()),
                base: raiun_core::backend::WriteCondition::Match(dirty_base.etag.clone()),
                expected_len: 17,
                protection: super::ContentProtection::Plaintext,
            },
            &mut &b"exact dirty bytes"[..],
        )
        .unwrap();
    let dirty_key = super::content_key(&scope, &dirty.content);
    let dirty_path = cache.inner.content_dir.join(format!("{dirty_key}.blob"));

    // Exercise the reference-protection invariant independently of the
    // retention label: a journal-referenced body must remain protected even
    // if an inconsistent/legacy row labels it Recent.
    cache
        .lock_db()
        .unwrap()
        .execute(
            "UPDATE contents SET retention=0 WHERE content_key=?1",
            [&dirty_key],
        )
        .unwrap();
    let recent_dirty_record = cache.content_record(&scope, &dirty.content).unwrap();
    assert_eq!(recent_dirty_record.retention, super::Retention::Recent);

    assert!(matches!(
        cache.set_policy_at(
            &scope,
            &dirty_base.resource_id,
            "/dirty.txt",
            &dirty_base.etag,
            super::AvailabilityPolicy::CloudOnly,
        ),
        Err(CacheError::PolicyConflict)
    ));
    assert_eq!(
        cache.policy(&scope, &dirty_base.resource_id).unwrap(),
        super::AvailabilityPolicy::Recent
    );
    assert_eq!(cache.pending_writes(&scope).unwrap(), vec![dirty.clone()]);
    assert_eq!(
        cache.content_record(&scope, &dirty.content).unwrap(),
        recent_dirty_record
    );
    assert!(dirty_path.is_file());
    let mut dirty_bytes = Vec::new();
    cache
        .open_content(&scope, &dirty.content)
        .unwrap()
        .read_to_end(&mut dirty_bytes)
        .unwrap();
    assert_eq!(dirty_bytes, b"exact dirty bytes");
    assert_eq!(
        cache.content_record(&scope, &dirty_base).unwrap(),
        dirty_base_record
    );

    // Recent-cache eviction also treats the journal reference as a hard
    // retention edge; it cannot delete the dirty body or its write record.
    let report = cache.evict_recent(0).unwrap();
    assert_eq!(report.removed_bytes, dirty_base_record.byte_len);
    assert_eq!(report.used_bytes, recent_dirty_record.byte_len);
    assert!(report.over_quota);
    assert!(dirty_path.is_file());
    assert_eq!(cache.pending_writes(&scope).unwrap(), vec![dirty]);
    let mut retained_bytes = Vec::new();
    cache
        .open_content(&scope, &recent_dirty_record.version)
        .expect("pending journal body stays addressable")
        .read_to_end(&mut retained_bytes)
        .unwrap();
    assert_eq!(retained_bytes, b"exact dirty bytes");
}

#[test]
fn integrated_absent_journal_write_survives_reopen_and_is_scope_isolated() {
    let state = tempfile::tempdir().unwrap();
    let cache = integrated_cache(state.path());
    let scope = integrated_scope("account-a", "root-a");
    cache.publish_listing(&scope, "root-a", &[], 1).unwrap();
    let write = cache
        .queue_conditional_write(&scope, absent_write_request(13), &mut &b"journal bytes"[..])
        .unwrap();
    assert_eq!(write.base, raiun_core::backend::WriteCondition::Absent);
    assert_eq!(
        cache.pending_write_for_path(&scope, "/newfile").unwrap(),
        Some(write.clone())
    );
    let mut reader = cache.open_content(&scope, &write.content).unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"journal bytes");
    drop(reader);

    let other_account = integrated_scope("account-b", "root-a");
    let other_root = integrated_scope("account-a", "root-b");
    cache
        .publish_listing(&other_account, "root-a", &[], 1)
        .unwrap();
    cache
        .publish_listing(&other_root, "root-b", &[], 1)
        .unwrap();
    for other in [&other_account, &other_root] {
        assert_eq!(
            cache.pending_write_for_path(other, "/newfile").unwrap(),
            None
        );
        assert!(matches!(
            cache.open_content(other, &write.content),
            Err(CacheError::NotFound)
        ));
    }
    drop(cache);

    let reopened = integrated_cache(state.path());
    let persisted = reopened
        .pending_write_for_path(&scope, "/newfile")
        .unwrap()
        .unwrap();
    assert_eq!(persisted, write);
    let mut reader = reopened.open_content(&scope, &persisted.content).unwrap();
    bytes.clear();
    reader.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"journal bytes");
    assert_eq!(
        reopened
            .pending_write_for_path(&other_account, "/newfile")
            .unwrap(),
        None
    );
}

#[test]
fn integrated_journal_replacement_keeps_base_and_retains_superseded_bytes() {
    let state = tempfile::tempdir().unwrap();
    let cache = integrated_cache(state.path());
    let scope = integrated_scope("account-a", "root-a");
    cache.publish_listing(&scope, "root-a", &[], 1).unwrap();
    let first = cache
        .queue_conditional_write(&scope, absent_write_request(9), &mut &b"old bytes"[..])
        .unwrap();
    let old_key = super::content_key(&scope, &first.content);
    let old_path = cache.inner.content_dir.join(format!("{old_key}.blob"));

    let replaced = cache
        .replace_pending_conditional_write(&scope, absent_write_request(9), &mut &b"new bytes"[..])
        .unwrap();
    assert_eq!(replaced.id, first.id);
    assert_eq!(replaced.base, first.base);
    assert_eq!(replaced.base, raiun_core::backend::WriteCondition::Absent);
    assert_ne!(replaced.content, first.content);
    assert_eq!(
        cache.pending_write_for_path(&scope, "/newfile").unwrap(),
        Some(replaced.clone())
    );

    let old_record = cache.content_record(&scope, &first.content).unwrap();
    assert_eq!(old_record.retention, super::Retention::Recovery);
    assert!(old_path.is_file());
    let new_record = cache.content_record(&scope, &replaced.content).unwrap();
    assert_eq!(new_record.retention, super::Retention::Dirty);
    assert_eq!(
        cache.usage().unwrap().used_bytes,
        old_record.byte_len + new_record.byte_len
    );
    for (version, expected) in [
        (&first.content, b"old bytes".as_slice()),
        (&replaced.content, b"new bytes".as_slice()),
    ] {
        let mut reader = cache.open_content(&scope, version).unwrap();
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, expected);
    }
}

struct InterruptedJournalSource {
    prefix: std::io::Cursor<&'static [u8]>,
}

impl Read for InterruptedJournalSource {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.prefix.position() < self.prefix.get_ref().len() as u64 {
            self.prefix.read(buffer)
        } else {
            Err(io::Error::other("synthetic interrupted journal source"))
        }
    }
}

#[test]
fn integrated_failed_journal_replacement_preserves_old_body_and_stage() {
    let state = tempfile::tempdir().unwrap();
    let cache = integrated_cache(state.path());
    let scope = integrated_scope("account-a", "root-a");
    cache.publish_listing(&scope, "root-a", &[], 1).unwrap();
    let first = cache
        .queue_conditional_write(&scope, absent_write_request(9), &mut &b"old bytes"[..])
        .unwrap();
    let mut source = InterruptedJournalSource {
        prefix: std::io::Cursor::new(b"part"),
    };

    assert!(matches!(
        cache.replace_pending_conditional_write(&scope, absent_write_request(12), &mut source,),
        Err(CacheError::Io(_))
    ));
    assert_eq!(
        cache.pending_write_for_path(&scope, "/newfile").unwrap(),
        Some(first.clone())
    );
    let mut reader = cache.open_content(&scope, &first.content).unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"old bytes");
    let usage = cache.usage().unwrap();
    assert_eq!(
        usage.used_bytes, 13,
        "the 4-byte failed stage remains accounted"
    );
    assert_eq!(usage.protected_bytes, 13);
    let stages = std::fs::read_dir(&cache.inner.content_dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(".stage-"))
        .collect::<Vec<_>>();
    assert_eq!(stages.len(), 1);
    let stage_path = stages[0].path();
    assert_eq!(std::fs::read(&stage_path).unwrap(), b"part");
    drop(reader);
    drop(cache);

    let reopened = integrated_cache(state.path());
    let report = reopened.evict_recent(0).unwrap();
    assert_eq!(report.removed_bytes, 0);
    assert_eq!(report.used_bytes, 13);
    assert_eq!(report.protected_bytes, 13);
    assert!(report.over_quota);
    assert_eq!(std::fs::read(&stage_path).unwrap(), b"part");
    let mut retained = reopened.open_content(&scope, &first.content).unwrap();
    bytes.clear();
    retained.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"old bytes");
}

#[test]
fn integrated_pin_generation_lock_is_scope_exact_and_survives_reopen() {
    let state = tempfile::tempdir().unwrap();
    let cache = integrated_cache(state.path());
    let scope = integrated_ciphertext_scope("account-a", "root-a");
    let lease = cache.lock_pin_generation(&scope).unwrap();
    let second_root = WindowsCacheDirectories::create_under(state.path()).unwrap();
    assert!(matches!(
        super::windows_lock::try_generation_lock(&second_root.root, &scope),
        Err(CacheError::Conflict)
    ));
    assert!(matches!(
        cache.lock_pin_generation(&scope),
        Err(CacheError::Conflict)
    ));

    let other_account = integrated_ciphertext_scope("account-b", "root-a");
    let other_root = integrated_ciphertext_scope("account-a", "root-b");
    let account_lease = cache.lock_pin_generation(&other_account).unwrap();
    let root_lease = cache.lock_pin_generation(&other_root).unwrap();
    drop(account_lease);
    drop(root_lease);

    let lock_name = format!("ciphertext-pin-generation-{}.lock", scope.key);
    let identity_before = cache
        .inner
        .windows_root
        .open_regular_file(OsStr::new(&lock_name))
        .unwrap()
        .1;
    drop(lease);
    drop(cache);

    let reopened = integrated_cache(state.path());
    let reopened_lease = reopened.lock_pin_generation(&scope).unwrap();
    let identity_after = reopened
        .inner
        .windows_root
        .open_regular_file(OsStr::new(&lock_name))
        .unwrap()
        .1;
    assert_eq!(identity_after, identity_before);
    drop(reopened_lease);
}

#[test]
fn integrated_ciphertext_pin_publishes_and_opens_verified_store_content() {
    let state = tempfile::tempdir().unwrap();
    let cache = integrated_cache(state.path());
    let scope = integrated_ciphertext_scope("account-a", "root-a");
    let epoch = cache.ciphertext_epoch(&scope).unwrap();
    let build = cache.begin_ciphertext_pin(&scope, epoch, None).unwrap();
    let root = super::ContentVersion {
        resource_id: "sealed-root-listing".into(),
        etag: "sealed-root-v1".into(),
        protection: super::ContentProtection::Ciphertext,
    };
    let file = super::ContentVersion {
        resource_id: "sealed-file-id".into(),
        etag: "sealed-file-v1".into(),
        protection: super::ContentProtection::Ciphertext,
    };
    let root_bytes = b"root ciphertext";
    let file_bytes = b"file ciphertext";
    cache
        .publish_ciphertext_for_pin_if_epoch(
            &scope,
            &root,
            &mut &root_bytes[..],
            root_bytes.len() as u64,
            &build,
            super::CiphertextPinItemKind::RootListing,
        )
        .unwrap();
    cache
        .publish_ciphertext_for_pin_if_epoch(
            &scope,
            &file,
            &mut &file_bytes[..],
            file_bytes.len() as u64,
            &build,
            super::CiphertextPinItemKind::FileContent,
        )
        .unwrap();
    let ready = cache.finish_ciphertext_pin(&scope, &build).unwrap();
    assert_eq!(ready.state, super::CiphertextPinState::Ready);
    assert_eq!(ready.item_count, 2);
    assert!(matches!(
        cache.set_policy_at(
            &scope,
            &file.resource_id,
            "/sealed-file-id",
            &file.etag,
            super::AvailabilityPolicy::CloudOnly,
        ),
        Err(CacheError::PolicyConflict)
    ));
    assert_eq!(
        cache.policy(&scope, &file.resource_id).unwrap(),
        super::AvailabilityPolicy::Recent
    );
    let mut reader = cache
        .open_ciphertext_pin_content(&scope, build.id(), &file)
        .unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, file_bytes);
}

#[test]
fn integrated_ciphertext_invalidation_removes_only_unprotected_recent_content() {
    let state = tempfile::tempdir().unwrap();
    let cache = integrated_cache(state.path());
    let scope = integrated_ciphertext_scope("account-a", "root-a");
    let other_account = integrated_ciphertext_scope("account-b", "root-a");
    let other_root = integrated_ciphertext_scope("account-a", "root-b");
    let version = |resource_id: &str, etag: &str| super::ContentVersion {
        resource_id: resource_id.into(),
        etag: etag.into(),
        protection: super::ContentProtection::Ciphertext,
    };
    let recent = version("recent-file", "recent-v1");
    let dirty = version("dirty-file", "dirty-v1");
    let recovery = version("recovery-file", "recovery-v1");
    let other_account_file = version("other-account-file", "account-v1");
    let other_root_file = version("other-root-file", "root-v1");
    let recent_record = publish_integrated(&cache, &scope, &recent, b"recent ciphertext");
    let dirty_record = publish_integrated_with_retention(
        &cache,
        &scope,
        &dirty,
        b"dirty ciphertext",
        super::Retention::Dirty,
    );
    let recovery_record = publish_integrated_with_retention(
        &cache,
        &scope,
        &recovery,
        b"recovery ciphertext",
        super::Retention::Recovery,
    );
    let other_account_record = publish_integrated(
        &cache,
        &other_account,
        &other_account_file,
        b"other account",
    );
    let other_root_record =
        publish_integrated(&cache, &other_root, &other_root_file, b"other root");

    let epoch = cache.ciphertext_epoch(&scope).unwrap();
    let build = cache.begin_ciphertext_pin(&scope, epoch, None).unwrap();
    let pin_id = build.id().to_owned();
    let pinned_root = version("pinned-root-listing", "root-v1");
    let pinned_file = version("pinned-file", "pinned-v1");
    let root_bytes = b"pinned root listing";
    let pinned_bytes = b"pinned ciphertext";
    cache
        .publish_ciphertext_for_pin_if_epoch(
            &scope,
            &pinned_root,
            &mut &root_bytes[..],
            root_bytes.len() as u64,
            &build,
            super::CiphertextPinItemKind::RootListing,
        )
        .unwrap();
    cache
        .publish_ciphertext_for_pin_if_epoch(
            &scope,
            &pinned_file,
            &mut &pinned_bytes[..],
            pinned_bytes.len() as u64,
            &build,
            super::CiphertextPinItemKind::FileContent,
        )
        .unwrap();
    let ready = cache.finish_ciphertext_pin(&scope, &build).unwrap();
    assert_eq!(ready.state, super::CiphertextPinState::Ready);
    let pinned_root_record = cache.content_record(&scope, &pinned_root).unwrap();
    let pinned_file_record = cache.content_record(&scope, &pinned_file).unwrap();
    let used_before = cache.usage().unwrap().used_bytes;
    assert_eq!(cache.ciphertext_epoch(&other_account).unwrap(), 0);
    assert_eq!(cache.ciphertext_epoch(&other_root).unwrap(), 0);

    assert_eq!(cache.invalidate_ciphertext_scope(&scope).unwrap(), 1);
    assert_eq!(cache.ciphertext_epoch(&scope).unwrap(), 1);
    assert!(matches!(
        cache.content_record(&scope, &recent),
        Err(CacheError::NotFound)
    ));
    assert_eq!(
        cache.usage().unwrap().used_bytes + recent_record.byte_len,
        used_before
    );
    for (version, record, expected, retention) in [
        (
            &dirty,
            &dirty_record,
            b"dirty ciphertext".as_slice(),
            super::Retention::Dirty,
        ),
        (
            &recovery,
            &recovery_record,
            b"recovery ciphertext".as_slice(),
            super::Retention::Recovery,
        ),
        (
            &pinned_root,
            &pinned_root_record,
            root_bytes.as_slice(),
            super::Retention::Recent,
        ),
        (
            &pinned_file,
            &pinned_file_record,
            pinned_bytes.as_slice(),
            super::Retention::Recent,
        ),
    ] {
        assert_eq!(cache.content_record(&scope, version).unwrap(), *record);
        assert_eq!(record.retention, retention);
        let mut reader = cache.open_content(&scope, version).unwrap();
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, expected);
    }
    assert_eq!(
        cache.ciphertext_pin_info(&scope, &pin_id).unwrap().state,
        super::CiphertextPinState::Stale
    );
    assert_eq!(
        cache
            .content_record(&other_account, &other_account_file)
            .unwrap(),
        other_account_record
    );
    assert_eq!(
        cache.content_record(&other_root, &other_root_file).unwrap(),
        other_root_record
    );
    assert_eq!(cache.ciphertext_epoch(&other_account).unwrap(), 0);
    assert_eq!(cache.ciphertext_epoch(&other_root).unwrap(), 0);
}

#[test]
fn integrated_ciphertext_invalidation_reader_conflict_rolls_back_until_closed() {
    let state = tempfile::tempdir().unwrap();
    let cache = integrated_cache(state.path());
    let scope = integrated_ciphertext_scope("account-a", "root-a");
    let recent = super::ContentVersion {
        resource_id: "recent-file".into(),
        etag: "recent-v1".into(),
        protection: super::ContentProtection::Ciphertext,
    };
    let record = publish_integrated(&cache, &scope, &recent, b"reader protects recent");
    let epoch = cache.ciphertext_epoch(&scope).unwrap();
    let build = cache.begin_ciphertext_pin(&scope, epoch, None).unwrap();
    let pin_id = build.id().to_owned();
    let pinned_root = super::ContentVersion {
        resource_id: "pin-root-listing".into(),
        etag: "root-v1".into(),
        protection: super::ContentProtection::Ciphertext,
    };
    let root_bytes = b"root snapshot";
    cache
        .publish_ciphertext_for_pin_if_epoch(
            &scope,
            &pinned_root,
            &mut &root_bytes[..],
            root_bytes.len() as u64,
            &build,
            super::CiphertextPinItemKind::RootListing,
        )
        .unwrap();
    cache.finish_ciphertext_pin(&scope, &build).unwrap();
    let mut reader = cache.open_content(&scope, &recent).unwrap();

    assert!(matches!(
        cache.invalidate_ciphertext_scope(&scope),
        Err(CacheError::Conflict)
    ));
    assert_eq!(cache.ciphertext_epoch(&scope).unwrap(), epoch);
    assert_eq!(cache.content_record(&scope, &recent).unwrap(), record);
    assert_eq!(
        cache.usage().unwrap().used_bytes,
        record.byte_len + root_bytes.len() as u64
    );
    assert_eq!(
        cache.ciphertext_pin_info(&scope, &pin_id).unwrap().state,
        super::CiphertextPinState::Ready
    );
    let mut recent_bytes = Vec::new();
    reader.read_to_end(&mut recent_bytes).unwrap();
    assert_eq!(recent_bytes, b"reader protects recent");
    drop(reader);

    assert_eq!(
        cache.invalidate_ciphertext_scope(&scope).unwrap(),
        epoch + 1
    );
    assert_eq!(cache.ciphertext_epoch(&scope).unwrap(), epoch + 1);
    assert!(matches!(
        cache.content_record(&scope, &recent),
        Err(CacheError::NotFound)
    ));
    assert_eq!(
        cache.ciphertext_pin_info(&scope, &pin_id).unwrap().state,
        super::CiphertextPinState::Stale
    );
    let mut pinned_reader = cache.open_content(&scope, &pinned_root).unwrap();
    let mut pinned_bytes = Vec::new();
    pinned_reader.read_to_end(&mut pinned_bytes).unwrap();
    assert_eq!(pinned_bytes, root_bytes);
}

#[test]
fn integrated_ciphertext_content_cleanup_refuses_referenced_pending_revision() {
    let state = tempfile::tempdir().unwrap();
    let cache = integrated_cache(state.path());
    let scope = integrated_ciphertext_scope("account-a", "root-a");
    let target = "encrypted-parent/encrypted-file";
    let body = b"pending ciphertext revision";
    let build = cache
        .begin_ciphertext_operation_with_state_and_parent(
            &scope,
            None,
            target,
            Some("encrypted-parent"),
            body.len() as u64,
            super::CiphertextWriteOperation::CreateFile,
            super::CiphertextWriteState::NeverAttempted,
        )
        .unwrap();
    let row = cache
        .publish_ciphertext_write(&scope, &build, &mut &body[..], body.len() as u64)
        .unwrap();
    let version = super::ContentVersion {
        resource_id: format!("vault-write-{}", row.id),
        etag: format!("revision-{}", row.revision),
        protection: super::ContentProtection::Ciphertext,
    };

    assert!(matches!(
        cache.remove_unreferenced_ciphertext_write_content(&scope, &row.id, row.revision),
        Err(CacheError::Conflict)
    ));
    assert_eq!(
        cache.ciphertext_write_info(&scope, &row.id).unwrap().state,
        super::CiphertextWriteState::NeverAttempted
    );
    let record = cache.content_record(&scope, &version).unwrap();
    let mut reader = cache
        .open_ciphertext_write(&scope, &row.id, row.revision)
        .unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, body);
    assert_eq!(record.byte_len, body.len() as u64);
}

#[test]
fn integrated_ciphertext_content_cleanup_waits_for_open_reader() {
    let state = tempfile::tempdir().unwrap();
    let cache = integrated_cache(state.path());
    let scope = integrated_ciphertext_scope("account-a", "root-a");
    let (id, revision, old_version) = compact_integrated_ciphertext_create(
        &cache,
        &scope,
        "encrypted-parent/encrypted-file",
        b"retired ciphertext body",
    );
    let record = cache.content_record(&scope, &old_version).unwrap();
    let path = cache
        .inner
        .content_dir
        .join(format!("{}.blob", super::content_key(&scope, &old_version)));
    let mut reader = cache.open_content(&scope, &old_version).unwrap();

    assert!(matches!(
        cache.remove_unreferenced_ciphertext_write_content(&scope, &id, revision),
        Err(CacheError::Conflict)
    ));
    assert_eq!(cache.content_record(&scope, &old_version).unwrap(), record);
    assert!(path.is_file());
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"retired ciphertext body");
    drop(reader);

    cache
        .remove_unreferenced_ciphertext_write_content(&scope, &id, revision)
        .unwrap();
    assert!(matches!(
        cache.content_record(&scope, &old_version),
        Err(CacheError::NotFound)
    ));
    assert!(!path.exists());
    let receipt = cache.ciphertext_write_info(&scope, &id).unwrap();
    assert_eq!(receipt.revision, revision + 1);
    assert_eq!(
        receipt.state,
        super::CiphertextWriteState::AcknowledgedReceipt
    );
}

#[test]
fn integrated_ciphertext_content_cleanup_retries_after_metadata_was_removed() {
    let state = tempfile::tempdir().unwrap();
    let cache = integrated_cache(state.path());
    let scope = integrated_ciphertext_scope("account-a", "root-a");
    let (id, revision, old_version) = compact_integrated_ciphertext_create(
        &cache,
        &scope,
        "encrypted-parent/retry-file",
        b"orphaned after interrupted cleanup",
    );
    let key = super::content_key(&scope, &old_version);
    let path = cache.inner.content_dir.join(format!("{key}.blob"));
    assert!(path.is_file());
    let removed = cache
        .lock_db()
        .unwrap()
        .execute(
            "DELETE FROM contents WHERE scope_key=?1 AND content_key=?2",
            rusqlite::params![scope.key, key],
        )
        .unwrap();
    assert_eq!(removed, 1);
    assert!(path.is_file(), "simulate a crash after metadata commit");

    cache
        .remove_unreferenced_ciphertext_write_content(&scope, &id, revision)
        .unwrap();
    assert!(!path.exists());
    cache
        .remove_unreferenced_ciphertext_write_content(&scope, &id, revision)
        .unwrap();
    assert!(!path.exists());
    assert!(matches!(
        cache.content_record(&scope, &old_version),
        Err(CacheError::NotFound)
    ));
}

#[test]
fn integrated_ciphertext_content_cleanup_preserves_dirty_and_recovery_records() {
    let state = tempfile::tempdir().unwrap();
    let cache = integrated_cache(state.path());
    let scope = integrated_ciphertext_scope("account-a", "root-a");
    let dirty_id = "d".repeat(32);
    let recovery_id = "e".repeat(32);
    let dirty = super::ContentVersion {
        resource_id: format!("vault-write-{dirty_id}"),
        etag: "revision-1".into(),
        protection: super::ContentProtection::Ciphertext,
    };
    let recovery = super::ContentVersion {
        resource_id: format!("vault-write-{recovery_id}"),
        etag: "revision-1".into(),
        protection: super::ContentProtection::Ciphertext,
    };
    let dirty_record = publish_integrated_with_retention(
        &cache,
        &scope,
        &dirty,
        b"dirty recovery body",
        super::Retention::Dirty,
    );
    let recovery_record = publish_integrated_with_retention(
        &cache,
        &scope,
        &recovery,
        b"recovery body",
        super::Retention::Recovery,
    );
    for (id, version, record, expected) in [
        (
            dirty_id.as_str(),
            &dirty,
            &dirty_record,
            b"dirty recovery body".as_slice(),
        ),
        (
            recovery_id.as_str(),
            &recovery,
            &recovery_record,
            b"recovery body".as_slice(),
        ),
    ] {
        let path = cache
            .inner
            .content_dir
            .join(format!("{}.blob", super::content_key(&scope, version)));
        assert!(matches!(
            cache.remove_unreferenced_ciphertext_write_content(&scope, id, 1),
            Err(CacheError::Conflict)
        ));
        assert_eq!(cache.content_record(&scope, version).unwrap(), *record);
        assert!(path.is_file());
        let mut reader = cache.open_content(&scope, version).unwrap();
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, expected);
    }
}

#[test]
fn integrated_folder_pin_becomes_ready_after_verified_body_is_published() {
    let state = tempfile::tempdir().unwrap();
    let cache = integrated_cache(state.path());
    let scope = integrated_scope("account-a", "root-a");
    let body = b"verified body";
    let (pin, version) = begin_integrated_plaintext_file_pin(&cache, &scope, body.len() as u64);
    assert_eq!(pin.state, super::PinState::Building);

    publish_integrated(&cache, &scope, &version, body);
    let ready = cache.refresh_pin(&pin.id).unwrap();
    assert_eq!(ready.state, super::PinState::Ready);
    assert_eq!(ready.required_content_count, 1);
    assert_eq!(ready.ready_content_count, 1);
    let mut reader = cache.open_content(&scope, &version).unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, body);
}

#[test]
fn integrated_folder_pin_missing_body_remains_not_ready() {
    let state = tempfile::tempdir().unwrap();
    let cache = integrated_cache(state.path());
    let scope = integrated_scope("account-a", "root-a");
    let body = b"body later missing";
    let (pin, version) = begin_integrated_plaintext_file_pin(&cache, &scope, body.len() as u64);
    publish_integrated(&cache, &scope, &version, body);
    let path = cache
        .inner
        .content_dir
        .join(format!("{}.blob", super::content_key(&scope, &version)));
    std::fs::remove_file(&path).unwrap();

    let refreshed = cache.refresh_pin(&pin.id).unwrap();
    assert_eq!(refreshed.state, super::PinState::Building);
    assert_eq!(refreshed.ready_content_count, 0);
    assert!(cache.content_record(&scope, &version).is_ok());
    assert!(!path.exists());
}

#[test]
fn integrated_folder_pin_modified_body_remains_not_ready() {
    let state = tempfile::tempdir().unwrap();
    let cache = integrated_cache(state.path());
    let scope = integrated_scope("account-a", "root-a");
    let body = b"verified body";
    let (pin, version) = begin_integrated_plaintext_file_pin(&cache, &scope, body.len() as u64);
    publish_integrated(&cache, &scope, &version, body);
    let path = cache
        .inner
        .content_dir
        .join(format!("{}.blob", super::content_key(&scope, &version)));
    std::fs::write(&path, b"tampered body").unwrap();

    let refreshed = cache.refresh_pin(&pin.id).unwrap();
    assert_eq!(refreshed.state, super::PinState::Building);
    assert_eq!(refreshed.ready_content_count, 0);
    assert!(cache.content_record(&scope, &version).is_ok());
}

#[test]
fn integrated_folder_pin_hardlink_policy_error_propagates() {
    let state = tempfile::tempdir().unwrap();
    let cache = integrated_cache(state.path());
    let scope = integrated_scope("account-a", "root-a");
    let body = b"hardlinked body";
    let (pin, version) = begin_integrated_plaintext_file_pin(&cache, &scope, body.len() as u64);
    publish_integrated(&cache, &scope, &version, body);
    let path = cache
        .inner
        .content_dir
        .join(format!("{}.blob", super::content_key(&scope, &version)));
    let alias = state.path().join("content-alias");
    std::fs::hard_link(&path, &alias).unwrap();

    assert!(matches!(cache.refresh_pin(&pin.id), Err(CacheError::Io(_))));
    assert!(path.is_file());
    assert!(alias.is_file());
    std::fs::remove_file(alias).unwrap();
}

#[test]
fn integrated_ciphertext_subtree_retarget_commits_root_and_child_together() {
    use std::io::Cursor;

    let state = tempfile::tempdir().unwrap();
    let cache = integrated_cache(state.path());
    let scope = integrated_ciphertext_scope("account-a", "root-a");
    let seeded = seed_ciphertext_subtree(&cache, &scope);
    let builds = cache
        .begin_ciphertext_never_attempted_subtree_retarget(
            &scope,
            &seeded.root_id,
            seeded.root_row.revision,
            &seeded.members,
        )
        .unwrap();
    let mut bodies = [
        Cursor::new(b"root-v2".to_vec()),
        Cursor::new(b"child-v2".to_vec()),
    ];
    let mut contents = builds
        .iter()
        .zip(bodies.iter_mut())
        .map(|(build, source)| super::CiphertextSubtreeRetargetContent {
            build,
            source,
            expected_len: if build.operation == super::CiphertextWriteOperation::CreateDirectory {
                7
            } else {
                8
            },
        })
        .collect::<Vec<_>>();

    let published = cache
        .publish_ciphertext_subtree_retarget(&scope, &builds, &mut contents, &seeded.root_id)
        .unwrap();
    assert_eq!(published.len(), 2);
    for (id, old_row, expected_target) in [
        (seeded.root_id.as_str(), &seeded.root_row, "opaque-root-new"),
        (
            seeded.child_id.as_str(),
            &seeded.child_row,
            "opaque-root-new/file",
        ),
    ] {
        let current = cache.ciphertext_write_info(&scope, id).unwrap();
        assert_eq!(current.revision, old_row.revision + 1);
        assert_ne!(current.target_key, old_row.target_key);
        assert_eq!(
            current.target_key,
            super::ciphertext_target_key(expected_target).unwrap()
        );
    }
    for (id, revision, expected) in [
        (
            seeded.root_id.as_str(),
            seeded.root_row.revision + 1,
            b"root-v2".as_slice(),
        ),
        (
            seeded.child_id.as_str(),
            seeded.child_row.revision + 1,
            b"child-v2".as_slice(),
        ),
    ] {
        let mut reader = cache.open_ciphertext_write(&scope, id, revision).unwrap();
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, expected);
    }
}

#[test]
fn integrated_lost_subtree_commit_ack_preserves_old_and_new_recovery_blobs() {
    use std::io::Cursor;

    let state = tempfile::tempdir().unwrap();
    let cache = integrated_cache(state.path());
    let scope = integrated_ciphertext_scope("account-a", "root-a");
    let seeded = seed_ciphertext_subtree(&cache, &scope);
    let builds = cache
        .begin_ciphertext_never_attempted_subtree_retarget(
            &scope,
            &seeded.root_id,
            seeded.root_row.revision,
            &seeded.members,
        )
        .unwrap();
    let mut bodies = [
        Cursor::new(b"root-v2".to_vec()),
        Cursor::new(b"child-v2".to_vec()),
    ];
    let mut contents = builds
        .iter()
        .zip(bodies.iter_mut())
        .map(|(build, source)| super::CiphertextSubtreeRetargetContent {
            build,
            source,
            expected_len: if build.operation == super::CiphertextWriteOperation::CreateDirectory {
                7
            } else {
                8
            },
        })
        .collect::<Vec<_>>();

    assert!(matches!(
        cache.publish_ciphertext_subtree_retarget_with_ack(
            &scope,
            &builds,
            &mut contents,
            &seeded.root_id,
            || Err(CacheError::Database(
                "synthetic lost acknowledgement".into()
            )),
        ),
        Err(CacheError::Database(_))
    ));
    drop(contents);
    drop(cache);

    let reopened = integrated_cache(state.path());
    for (version, expected) in [
        (&seeded.old_root_version, b"root-v1".as_slice()),
        (&seeded.old_child_version, b"child-v1".as_slice()),
    ] {
        let mut reader = reopened.open_content(&scope, version).unwrap();
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, expected);
    }
    for (id, old_row, expected) in [
        (
            seeded.root_id.as_str(),
            &seeded.root_row,
            b"root-v2".as_slice(),
        ),
        (
            seeded.child_id.as_str(),
            &seeded.child_row,
            b"child-v2".as_slice(),
        ),
    ] {
        let current = reopened.ciphertext_write_info(&scope, id).unwrap();
        assert_eq!(current.revision, old_row.revision + 1);
        let mut reader = reopened
            .open_ciphertext_write(&scope, id, current.revision)
            .unwrap();
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, expected);
    }
}
