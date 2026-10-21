//! Durable policy-intent revision tests.

use super::*;
use std::io::{Cursor, Read};

const POLICY_INTENT_CAPACITY: i64 = MAX_CONTENT_RECORDS as i64;

fn test_scope(account: &str, root: &str) -> CacheScope {
    CacheScope::new(
        "https://policy-intent.example.test/",
        account,
        "synthetic-space",
        root,
        ScopeProtection::PlaintextAllowed,
    )
    .unwrap()
}

fn test_cache() -> (tempfile::TempDir, Cache) {
    let state = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    set_private_dir(state.path()).unwrap();
    let cache = Cache::open(state.path(), 1024 * 1024).unwrap();
    (state, cache)
}

fn revision(cache: &Cache, scope: &CacheScope, resource_id: &str) -> Option<i64> {
    cache
        .lock_db()
        .unwrap()
        .query_row(
            "SELECT revision FROM policy_intent_revisions WHERE scope_key=?1 AND resource_id=?2",
            rusqlite::params![scope.key, resource_id],
            |row| row.get(0),
        )
        .optional()
        .unwrap()
}

fn entry(id: &str, path: &str, etag: &str, size: u64) -> RemoteEntry {
    RemoteEntry {
        id: id.into(),
        path: path.into(),
        etag: etag.into(),
        directory: false,
        encrypted: false,
        size,
        modified_unix: 1,
        writable: true,
    }
}

fn listed(entry: &RemoteEntry, parent: &str) -> CachedEntry {
    CachedEntry {
        parent_resource_id: parent.into(),
        entry: entry.clone(),
    }
}

fn read_content(cache: &Cache, scope: &CacheScope, version: &ContentVersion) -> Vec<u8> {
    let mut bytes = Vec::new();
    cache
        .open_content(scope, version)
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    bytes
}

fn ledger_count(cache: &Cache) -> i64 {
    cache
        .lock_db()
        .unwrap()
        .query_row("SELECT COUNT(*) FROM policy_intent_revisions", [], |row| {
            row.get(0)
        })
        .unwrap()
}

type JournalRow = (
    i64,
    String,
    String,
    String,
    Option<String>,
    i64,
    String,
    String,
    i64,
);

fn journal_rows(db: &rusqlite::Connection, scope: &CacheScope) -> Vec<JournalRow> {
    let mut statement = db
        .prepare("SELECT id,parent_id,name,path,resource_id,base_kind,base_etag,content_key,state FROM writes WHERE scope_key=?1 ORDER BY id")
        .unwrap();
    statement
        .query_map([&scope.key], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                row.get(8)?,
            ))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

#[test]
fn policy_revision_increases_across_aba_and_repeated_identical_intents() {
    let (_state, cache) = test_cache();
    let scope = test_scope("account-a", "root-a");

    cache
        .set_policy_at(
            &scope,
            "file-a",
            "/file-a",
            "etag-a",
            AvailabilityPolicy::Recent,
        )
        .unwrap();
    assert_eq!(revision(&cache, &scope, "file-a"), Some(1));
    cache
        .set_policy_at(
            &scope,
            "file-a",
            "/file-a",
            "etag-a",
            AvailabilityPolicy::CloudOnly,
        )
        .unwrap();
    assert_eq!(revision(&cache, &scope, "file-a"), Some(2));
    cache
        .set_policy_at(
            &scope,
            "file-a",
            "/file-a",
            "etag-a",
            AvailabilityPolicy::Recent,
        )
        .unwrap();
    assert_eq!(revision(&cache, &scope, "file-a"), Some(3));

    cache
        .set_policy_at(
            &scope,
            "file-a",
            "/file-a",
            "etag-a",
            AvailabilityPolicy::Recent,
        )
        .unwrap();
    assert_eq!(revision(&cache, &scope, "file-a"), Some(4));
}

#[test]
fn deleting_and_recreating_policy_retains_the_monotonic_tombstone() {
    let (_state, cache) = test_cache();
    let scope = test_scope("account-a", "root-a");
    cache
        .set_policy_at(
            &scope,
            "file-a",
            "/file-a",
            "etag-a",
            AvailabilityPolicy::Recent,
        )
        .unwrap();
    assert_eq!(revision(&cache, &scope, "file-a"), Some(1));

    {
        let db = cache.lock_db().unwrap();
        db.execute(
            "DELETE FROM policies WHERE scope_key=?1 AND resource_id=?2",
            rusqlite::params![scope.key, "file-a"],
        )
        .unwrap();
        let policy_exists: bool = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM policies WHERE scope_key=?1 AND resource_id=?2)",
                rusqlite::params![scope.key, "file-a"],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!policy_exists);
    }
    assert_eq!(revision(&cache, &scope, "file-a"), Some(2));

    cache
        .set_policy_at(
            &scope,
            "file-a",
            "/file-a",
            "etag-a",
            AvailabilityPolicy::Recent,
        )
        .unwrap();
    assert_eq!(revision(&cache, &scope, "file-a"), Some(3));
}

#[test]
fn policy_intent_revisions_are_isolated_by_registered_scope() {
    let (_state, cache) = test_cache();
    let first = test_scope("account-a", "root-a");
    let second = test_scope("account-b", "root-b");
    cache
        .set_policy_at(
            &first,
            "shared-id",
            "/one",
            "v1",
            AvailabilityPolicy::Recent,
        )
        .unwrap();
    cache
        .set_policy_at(
            &second,
            "shared-id",
            "/two",
            "v1",
            AvailabilityPolicy::Recent,
        )
        .unwrap();
    assert_eq!(revision(&cache, &first, "shared-id"), Some(1));
    assert_eq!(revision(&cache, &second, "shared-id"), Some(1));

    cache
        .set_policy_at(
            &first,
            "shared-id",
            "/one",
            "v1",
            AvailabilityPolicy::CloudOnly,
        )
        .unwrap();
    assert_eq!(revision(&cache, &first, "shared-id"), Some(2));
    assert_eq!(revision(&cache, &second, "shared-id"), Some(1));
}

#[test]
fn rejected_cloud_only_with_dirty_journal_does_not_advance_intent_or_drop_bytes() {
    let (_state, cache) = test_cache();
    let scope = test_scope("account-a", "root-a");
    let file = entry("file-a", "/draft.txt", "base-v1", 4);
    cache
        .publish_listing(&scope, "root-a", &[listed(&file, "root-a")], 1)
        .unwrap();
    cache
        .set_listed_file_policy(&scope, &file, AvailabilityPolicy::Recent)
        .unwrap();
    let base = ContentVersion {
        resource_id: file.id.clone(),
        etag: file.etag.clone(),
        protection: ContentProtection::Plaintext,
    };
    cache
        .publish_content(
            &scope,
            &base,
            &mut Cursor::new(b"base"),
            4,
            Retention::Recent,
        )
        .unwrap();
    let queued = cache
        .queue_conditional_write(
            &scope,
            ConditionalWriteRequest {
                parent_resource_id: "root-a".into(),
                name: "draft.txt".into(),
                logical_path: file.path.clone(),
                resource_id: Some(file.id.clone()),
                base: WriteCondition::Match(file.etag.clone()),
                expected_len: 13,
                protection: ContentProtection::Plaintext,
            },
            &mut Cursor::new(b"unsynced edit"),
        )
        .unwrap();
    let before = revision(&cache, &scope, &file.id);
    assert_eq!(before, Some(1));
    let pending_before = cache.pending_writes(&scope).unwrap();
    let dirty_before = read_content(&cache, &scope, &queued.content);

    assert!(matches!(
        cache.set_listed_file_policy(&scope, &file, AvailabilityPolicy::CloudOnly),
        Err(CacheError::PolicyConflict)
    ));
    assert_eq!(revision(&cache, &scope, &file.id), before);
    assert_eq!(
        cache.policy(&scope, &file.id).unwrap(),
        AvailabilityPolicy::Recent
    );
    assert_eq!(cache.pending_writes(&scope).unwrap(), pending_before);
    assert_eq!(read_content(&cache, &scope, &queued.content), dirty_before);
}

#[test]
fn intent_revision_overflow_rolls_back_cloud_only_policy_and_content_removal() {
    let (_state, cache) = test_cache();
    let scope = test_scope("account-a", "root-a");
    let file = entry("file-a", "/file-a", "etag-a", 4);
    cache
        .publish_listing(&scope, "root-a", &[listed(&file, "root-a")], 1)
        .unwrap();
    cache
        .set_listed_file_policy(&scope, &file, AvailabilityPolicy::Recent)
        .unwrap();
    let version = ContentVersion {
        resource_id: file.id.clone(),
        etag: file.etag.clone(),
        protection: ContentProtection::Plaintext,
    };
    cache
        .publish_content(
            &scope,
            &version,
            &mut Cursor::new(b"keep"),
            4,
            Retention::Recent,
        )
        .unwrap();
    cache
        .lock_db()
        .unwrap()
        .execute(
            "UPDATE policy_intent_revisions SET revision=?3 WHERE scope_key=?1 AND resource_id=?2",
            rusqlite::params![scope.key, file.id, i64::MAX],
        )
        .unwrap();

    assert!(
        cache
            .set_listed_file_policy(&scope, &file, AvailabilityPolicy::CloudOnly)
            .is_err()
    );
    assert_eq!(revision(&cache, &scope, &file.id), Some(i64::MAX));
    assert_eq!(
        cache.policy(&scope, &file.id).unwrap(),
        AvailabilityPolicy::Recent
    );
    assert_eq!(read_content(&cache, &scope, &version), b"keep");
}

#[test]
fn version_five_migration_seeds_revision_and_preserves_dirty_journal_content() {
    let (state, cache) = test_cache();
    let scope = test_scope("account-a", "root-a");
    let file = entry("file-a", "/draft.txt", "base-v1", 4);
    cache
        .publish_listing(&scope, "root-a", &[listed(&file, "root-a")], 1)
        .unwrap();
    cache
        .set_listed_file_policy(&scope, &file, AvailabilityPolicy::Recent)
        .unwrap();
    let base = ContentVersion {
        resource_id: file.id.clone(),
        etag: file.etag.clone(),
        protection: ContentProtection::Plaintext,
    };
    cache
        .publish_content(
            &scope,
            &base,
            &mut Cursor::new(b"base"),
            4,
            Retention::Recent,
        )
        .unwrap();
    let queued = cache
        .queue_conditional_write(
            &scope,
            ConditionalWriteRequest {
                parent_resource_id: "root-a".into(),
                name: "draft.txt".into(),
                logical_path: file.path.clone(),
                resource_id: Some(file.id.clone()),
                base: WriteCondition::Match(file.etag.clone()),
                expected_len: 13,
                protection: ContentProtection::Plaintext,
            },
            &mut Cursor::new(b"unsynced edit"),
        )
        .unwrap();
    let dirty_before = read_content(&cache, &scope, &queued.content);
    let pending_before = cache.pending_writes(&scope).unwrap();

    {
        let db = cache.lock_db().unwrap();
        db.execute_batch(
            "DROP TRIGGER IF EXISTS policy_intent_insert;
             DROP TRIGGER IF EXISTS policy_intent_update;
             DROP TRIGGER IF EXISTS policy_intent_delete;
             DROP TRIGGER IF EXISTS policy_intent_capacity;
             DROP TRIGGER IF EXISTS policy_binding_immutable;
             DROP TABLE policy_intent_revisions;
             PRAGMA user_version=5;",
        )
        .unwrap();
    }
    drop(cache);

    let migrated = Cache::open(state.path(), 1024 * 1024).unwrap();
    assert_eq!(
        migrated.policy(&scope, &file.id).unwrap(),
        AvailabilityPolicy::Recent
    );
    assert_eq!(revision(&migrated, &scope, &file.id), Some(1));
    assert_eq!(migrated.pending_writes(&scope).unwrap(), pending_before);
    assert_eq!(
        read_content(&migrated, &scope, &queued.content),
        dirty_before
    );
}

#[test]
fn full_intent_ledger_allows_existing_identity_but_refuses_a_new_one() {
    let (_state, cache) = test_cache();
    let scope = test_scope("account-a", "root-a");
    cache
        .set_policy_at(
            &scope,
            "existing-file",
            "/existing-file",
            "etag-1",
            AvailabilityPolicy::Recent,
        )
        .unwrap();

    let capacity_trigger: String = cache
        .lock_db()
        .unwrap()
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type='trigger' AND name='policy_intent_capacity'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    {
        let mut db = cache.lock_db().unwrap();
        let transaction = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        transaction
            .execute_batch("DROP TRIGGER policy_intent_capacity;")
            .unwrap();
        transaction
            .execute(
                "WITH RECURSIVE seq(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM seq WHERE n<?1)
                 INSERT INTO policy_intent_revisions(scope_key,resource_id,revision)
                 SELECT 'capacity-fixture',printf('tombstone-%07d',n),1 FROM seq",
                rusqlite::params![POLICY_INTENT_CAPACITY - 1],
            )
            .unwrap();
        transaction.execute_batch(&capacity_trigger).unwrap();
        transaction.commit().unwrap();
    }
    assert_eq!(ledger_count(&cache), POLICY_INTENT_CAPACITY);

    cache
        .set_policy_at(
            &scope,
            "existing-file",
            "/existing-file",
            "etag-1",
            AvailabilityPolicy::Recent,
        )
        .unwrap();
    assert_eq!(revision(&cache, &scope, "existing-file"), Some(2));
    cache
        .lock_db()
        .unwrap()
        .execute(
            "DELETE FROM policies WHERE scope_key=?1 AND resource_id=?2",
            rusqlite::params![scope.key, "existing-file"],
        )
        .unwrap();
    assert_eq!(revision(&cache, &scope, "existing-file"), Some(3));
    cache
        .set_policy_at(
            &scope,
            "existing-file",
            "/existing-file",
            "etag-1",
            AvailabilityPolicy::Recent,
        )
        .unwrap();
    assert_eq!(revision(&cache, &scope, "existing-file"), Some(4));
    assert_eq!(ledger_count(&cache), POLICY_INTENT_CAPACITY);

    assert!(
        cache
            .set_policy_at(
                &scope,
                "new-file",
                "/new-file",
                "etag-new",
                AvailabilityPolicy::Recent,
            )
            .is_err()
    );
    let policy_exists: bool = cache
        .lock_db()
        .unwrap()
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM policies WHERE scope_key=?1 AND resource_id=?2)",
            rusqlite::params![scope.key, "new-file"],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!policy_exists);
    assert_eq!(revision(&cache, &scope, "new-file"), None);
    assert_eq!(ledger_count(&cache), POLICY_INTENT_CAPACITY);
}

#[test]
fn over_capacity_v5_migration_rolls_back_without_changing_dirty_recovery() {
    let (state, cache) = test_cache();
    let scope = test_scope("account-a", "root-a");
    let file = entry("file-a", "/draft.txt", "base-v1", 4);
    cache
        .publish_listing(&scope, "root-a", &[listed(&file, "root-a")], 1)
        .unwrap();
    cache
        .set_listed_file_policy(&scope, &file, AvailabilityPolicy::Recent)
        .unwrap();
    let base = ContentVersion {
        resource_id: file.id.clone(),
        etag: file.etag.clone(),
        protection: ContentProtection::Plaintext,
    };
    cache
        .publish_content(
            &scope,
            &base,
            &mut Cursor::new(b"base"),
            4,
            Retention::Recent,
        )
        .unwrap();
    let queued = cache
        .queue_conditional_write(
            &scope,
            ConditionalWriteRequest {
                parent_resource_id: "root-a".into(),
                name: "draft.txt".into(),
                logical_path: file.path.clone(),
                resource_id: Some(file.id.clone()),
                base: WriteCondition::Match(file.etag.clone()),
                expected_len: 13,
                protection: ContentProtection::Plaintext,
            },
            &mut Cursor::new(b"unsynced edit"),
        )
        .unwrap();
    let dirty_before = read_content(&cache, &scope, &queued.content);
    let blob_path = cache
        .inner
        .content_dir
        .join(format!("{}.blob", content_key(&scope, &queued.content)));
    let blob_before = std::fs::read(&blob_path).unwrap();
    let root = cache.root().to_path_buf();

    {
        let mut db = cache.lock_db().unwrap();
        let transaction = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        transaction
            .execute_batch(
                "DROP TRIGGER policy_intent_insert;
                 DROP TRIGGER policy_intent_update;
                 DROP TRIGGER policy_intent_delete;
                 DROP TRIGGER policy_intent_capacity;
                 DROP TRIGGER policy_binding_immutable;
                 DROP TABLE policy_intent_revisions;",
            )
            .unwrap();
        transaction
            .execute(
                "WITH RECURSIVE seq(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM seq WHERE n<?1)
                 INSERT INTO policies(scope_key,resource_id,policy,target_path,target_etag,target_state)
                 SELECT 'legacy-capacity-fixture',printf('legacy-%07d',n),0,'/','',0 FROM seq",
                rusqlite::params![POLICY_INTENT_CAPACITY],
            )
            .unwrap();
        transaction.execute_batch("PRAGMA user_version=5;").unwrap();
        transaction.commit().unwrap();
    }
    let before_rows = {
        let db = cache.lock_db().unwrap();
        journal_rows(&db, &scope)
    };
    assert_eq!(before_rows.len(), 1);
    drop(cache);

    assert!(matches!(
        Cache::open(state.path(), 1024 * 1024),
        Err(CacheError::LimitExceeded)
    ));

    let raw = rusqlite::Connection::open_with_flags(
        root.join(DB_FILE),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let version: i64 = raw
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, 5);
    let policy_count: i64 = raw
        .query_row("SELECT COUNT(*) FROM policies", [], |row| row.get(0))
        .unwrap();
    assert_eq!(policy_count, POLICY_INTENT_CAPACITY + 1);
    let original_policy: i64 = raw
        .query_row(
            "SELECT policy FROM policies WHERE scope_key=?1 AND resource_id=?2",
            rusqlite::params![scope.key, file.id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(original_policy, AvailabilityPolicy::Recent as i64);
    let ledger_exists: bool = raw
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='policy_intent_revisions')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!ledger_exists);
    assert_eq!(journal_rows(&raw, &scope), before_rows);
    assert_eq!(std::fs::read(&blob_path).unwrap(), blob_before);
    assert_eq!(blob_before, dirty_before);
}

#[test]
fn listing_refresh_updates_policy_target_without_advancing_user_intent() {
    let (_state, cache) = test_cache();
    let scope = test_scope("account-a", "root-a");
    let original = entry("stable-file", "/old-name.txt", "etag-1", 4);
    cache
        .publish_listing(&scope, "root-a", &[listed(&original, "root-a")], 1)
        .unwrap();
    cache
        .publish_content(
            &scope,
            &ContentVersion {
                resource_id: original.id.clone(),
                etag: original.etag.clone(),
                protection: ContentProtection::Plaintext,
            },
            &mut Cursor::new(b"base"),
            4,
            Retention::Recent,
        )
        .unwrap();
    cache
        .set_policy_at(
            &scope,
            &original.id,
            &original.path,
            &original.etag,
            AvailabilityPolicy::AlwaysOffline,
        )
        .unwrap();
    assert_eq!(revision(&cache, &scope, "stable-file"), Some(1));

    let renamed = entry("stable-file", "/new-name.txt", "etag-2", 4);
    cache
        .publish_listing(&scope, "root-a", &[listed(&renamed, "root-a")], 2)
        .unwrap();
    let (targets, _) = cache.refresh_targets(&scope).unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].resource_id, "stable-file");
    assert_eq!(targets[0].path, "/new-name.txt");
    assert_eq!(targets[0].etag, "etag-1");
    assert_eq!(targets[0].state, TargetState::Stale);
    assert_eq!(revision(&cache, &scope, "stable-file"), Some(1));
}

#[test]
fn current_version_missing_ledger_row_fails_closed_without_reseeding() {
    let (state, cache) = test_cache();
    let scope = test_scope("account-a", "root-a");
    cache
        .set_policy_at(
            &scope,
            "file-a",
            "/file-a",
            "etag-a",
            AvailabilityPolicy::Recent,
        )
        .unwrap();
    let root = cache.root().to_path_buf();
    cache
        .lock_db()
        .unwrap()
        .execute(
            "DELETE FROM policy_intent_revisions WHERE scope_key=?1 AND resource_id=?2",
            rusqlite::params![scope.key, "file-a"],
        )
        .unwrap();
    assert_eq!(revision(&cache, &scope, "file-a"), None);
    drop(cache);

    assert!(matches!(
        Cache::open(state.path(), 1024 * 1024),
        Err(CacheError::Corrupt)
    ));

    let raw = rusqlite::Connection::open(root.join(DB_FILE)).unwrap();
    let version: i64 = raw
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, CACHE_VERSION as i64);
    let policy_count: i64 = raw
        .query_row(
            "SELECT COUNT(*) FROM policies WHERE scope_key=?1 AND resource_id=?2",
            rusqlite::params![scope.key, "file-a"],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(policy_count, 1);
    let revision_count: i64 = raw
        .query_row(
            "SELECT COUNT(*) FROM policy_intent_revisions WHERE scope_key=?1 AND resource_id=?2",
            rusqlite::params![scope.key, "file-a"],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(revision_count, 0);
}

#[test]
fn pending_offline_intents_are_bounded_scoped_and_survive_reopen() {
    let (state, cache) = test_cache();
    let scope = test_scope("account-a", "root-a");
    let other = test_scope("account-b", "root-a");
    register_scope(&cache.lock_db().unwrap(), &scope).unwrap();
    register_scope(&cache.lock_db().unwrap(), &other).unwrap();
    {
        let db = cache.lock_db().unwrap();
        for (key, count) in [(&scope.key, 10), (&other.key, 1)] {
            for i in 0..count {
                let id = format!("file-{i:02}");
                db.execute("INSERT INTO policies(scope_key,resource_id,policy,target_path,target_etag,target_state) VALUES(?1,?2,1,'/file','v1',1)", params![key,id]).unwrap();
            }
        }
    }
    drop(cache);
    let cache = Cache::open(state.path(), 1024 * 1024).unwrap();
    let exact = cache
        .pending_plaintext_offline_intent(&scope, "file-00")
        .unwrap()
        .unwrap();
    assert_eq!(exact.path, "/file");
    assert_eq!(exact.etag, "v1");
    assert!(exact.revision > 0);
    assert!(
        cache
            .pending_plaintext_offline_intent(&scope, "unknown")
            .unwrap()
            .is_none()
    );
    let first = cache
        .pending_plaintext_offline_intents(&scope, None)
        .unwrap();
    assert_eq!(first.len(), 8);
    assert_eq!(first[0].resource_id, "file-00");
    let second = cache
        .pending_plaintext_offline_intents(&scope, Some(&first[7].resource_id))
        .unwrap();
    assert_eq!(second.len(), 2);
    assert_eq!(second[0].resource_id, "file-08");
    assert_eq!(
        cache
            .pending_plaintext_offline_intents(&other, None)
            .unwrap()
            .len(),
        1
    );
    assert!(
        cache
            .pending_plaintext_offline_intents(&scope, Some(""))
            .is_err()
    );
    cache
        .lock_db()
        .unwrap()
        .execute(
            "DELETE FROM policy_intent_revisions WHERE scope_key=?1 AND resource_id='file-00'",
            params![scope.key],
        )
        .unwrap();
    assert!(matches!(
        cache.pending_plaintext_offline_intents(&scope, None),
        Err(CacheError::Corrupt)
    ));
}
