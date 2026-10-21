use super::*;
use rusqlite::params;
use std::cell::Cell;
use std::io::{Cursor, Read};

fn listed_folder_file(cache: &Cache, scope: &CacheScope, retention: Retention) -> ContentVersion {
    let folder = entry("folder", "folder", "/folder", "folder-v1", 0, true);
    cache
        .publish_listing(scope, "root-a", &[folder], 1)
        .unwrap();
    let mut file = entry("file", "file", "/folder/file.txt", "file-v1", 8, false);
    file.parent_resource_id = "folder".into();
    cache.publish_listing(scope, "folder", &[file], 2).unwrap();
    let version = ContentVersion {
        resource_id: "file".into(),
        etag: "file-v1".into(),
        protection: ContentProtection::Plaintext,
    };
    cache
        .publish_content(scope, &version, &mut Cursor::new(b"contents"), 8, retention)
        .unwrap();
    version
}

fn insert_folder_intent(cache: &Cache, scope: &CacheScope) {
    let db = cache.lock_db().unwrap();
    db.execute(
        "INSERT INTO folder_cloud_only_intents(scope_key,root_id) VALUES(?1,?2)",
        params![scope.key, "folder"],
    )
    .unwrap();
}

#[test]
fn open_recent_rechecks_folder_policy_after_blob_verification() {
    let (_temp, cache) = cache();
    let scope = scope(ScopeProtection::PlaintextAllowed);
    let version = listed_folder_file(&cache, &scope, Retention::Recent);
    let callback_count = Cell::new(0);
    let inserted = Cell::new(false);

    let result = cache.open_content_cancellable(&scope, &version, || {
        let count = callback_count.get() + 1;
        callback_count.set(count);
        // Call one is the initial cancellation check. Call two is the first
        // hash-loop check, after the original policy admission and file open.
        if count == 2 {
            insert_folder_intent(&cache, &scope);
            inserted.set(true);
        }
        false
    });

    assert!(
        inserted.get(),
        "the policy mutation must interleave during verification"
    );
    assert!(callback_count.get() >= 2);
    assert!(matches!(result, Err(CacheError::PolicyConflict)));
    assert_eq!(
        cache.policy(&scope, "file").unwrap(),
        AvailabilityPolicy::CloudOnly
    );
}

#[test]
fn open_dirty_content_remains_available_when_folder_intent_arrives_during_verification() {
    let (_temp, cache) = cache();
    let scope = scope(ScopeProtection::PlaintextAllowed);
    let version = listed_folder_file(&cache, &scope, Retention::Dirty);
    let callback_count = Cell::new(0);
    let inserted = Cell::new(false);

    let mut reader = cache
        .open_content_cancellable(&scope, &version, || {
            let count = callback_count.get() + 1;
            callback_count.set(count);
            if count == 2 {
                insert_folder_intent(&cache, &scope);
                inserted.set(true);
            }
            false
        })
        .expect("folder CloudOnly must not revoke Dirty content");
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();

    assert!(
        inserted.get(),
        "the policy mutation must interleave during verification"
    );
    assert_eq!(bytes, b"contents");
    assert_eq!(
        cache.content_record(&scope, &version).unwrap().retention,
        Retention::Dirty
    );
}
