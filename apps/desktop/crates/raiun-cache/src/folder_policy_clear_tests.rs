use super::*;
use rusqlite::params;
use std::io::{Cursor, Read};

fn clear_row(
    parent: &str,
    id: &str,
    path: &str,
    etag: &str,
    size: u64,
    directory: bool,
) -> CachedEntry {
    CachedEntry {
        parent_resource_id: parent.to_owned(),
        entry: RemoteEntry {
            id: id.to_owned(),
            path: path.to_owned(),
            etag: etag.to_owned(),
            size,
            directory,
            modified_unix: 1,
            writable: true,
            encrypted: false,
        },
    }
}

fn inject_intent(cache: &Cache, scope: &CacheScope, root_id: &str) {
    let db = cache.lock_db().unwrap();
    db.execute(
        "INSERT INTO folder_cloud_only_intents(scope_key,root_id) VALUES(?1,?2)",
        params![scope.key, root_id],
    )
    .unwrap();
}

fn intent_exists(cache: &Cache, scope: &CacheScope, root_id: &str) -> bool {
    let db = cache.lock_db().unwrap();
    db.query_row(
        "SELECT EXISTS(SELECT 1 FROM folder_cloud_only_intents WHERE scope_key=?1 AND root_id=?2)",
        params![scope.key, root_id],
        |row| row.get(0),
    )
    .unwrap()
}

#[test]
fn clear_folder_intent_removes_only_exact_root_and_preserves_nested_intent() {
    let (_temp, cache) = cache();
    let scope = scope(ScopeProtection::PlaintextAllowed);
    cache.publish_listing(&scope, "root-a", &[], 1).unwrap();
    inject_intent(&cache, &scope, "outer-folder");
    inject_intent(&cache, &scope, "nested-folder");

    assert!(
        cache
            .clear_folder_cloud_only(&scope, "outer-folder")
            .unwrap()
    );
    assert!(!intent_exists(&cache, &scope, "outer-folder"));
    assert!(intent_exists(&cache, &scope, "nested-folder"));
    assert!(
        !cache
            .clear_folder_cloud_only(&scope, "outer-folder")
            .unwrap()
    );
}

#[test]
fn clear_folder_intent_is_scope_exact_and_does_not_remove_other_account_row() {
    let (_temp, cache) = cache();
    let scope_a = scope(ScopeProtection::PlaintextAllowed);
    let scope_b = CacheScope::new(
        "https://cloud.example.test/",
        "account-b",
        "space-a",
        "root-a",
        ScopeProtection::PlaintextAllowed,
    )
    .unwrap();
    cache.publish_listing(&scope_a, "root-a", &[], 1).unwrap();
    cache.publish_listing(&scope_b, "root-a", &[], 1).unwrap();
    inject_intent(&cache, &scope_b, "same-folder-id");

    assert!(
        !cache
            .clear_folder_cloud_only(&scope_a, "same-folder-id")
            .unwrap()
    );
    assert!(intent_exists(&cache, &scope_b, "same-folder-id"));
    assert!(!intent_exists(&cache, &scope_a, "same-folder-id"));
}

#[test]
fn orphaned_folder_intent_remains_clearable_without_live_ancestry() {
    let (_temp, cache) = cache();
    let scope = scope(ScopeProtection::PlaintextAllowed);
    let folder = clear_row(
        "root-a",
        "removed-folder",
        "/old-name",
        "folder-v1",
        0,
        true,
    );
    cache
        .publish_listing(&scope, "root-a", std::slice::from_ref(&folder), 1)
        .unwrap();
    inject_intent(&cache, &scope, "removed-folder");
    // A later complete parent listing removes the folder from the current
    // ancestry. Clearing is still keyed by the exact scope and stable root ID.
    cache.publish_listing(&scope, "root-a", &[], 2).unwrap();
    assert!(cache.listing(&scope, "root-a").unwrap().entries.is_empty());

    assert!(
        cache
            .clear_folder_cloud_only(&scope, "removed-folder")
            .unwrap()
    );
    assert!(!intent_exists(&cache, &scope, "removed-folder"));
}

#[test]
fn clearing_folder_intent_leaves_dirty_content_pins_and_explicit_file_policy_unchanged() {
    let (_temp, cache) = cache();
    let scope = scope(ScopeProtection::PlaintextAllowed);
    let folder = clear_row("root-a", "folder-root", "/folder", "folder-v1", 0, true);
    cache
        .publish_listing(&scope, "root-a", std::slice::from_ref(&folder), 1)
        .unwrap();
    let file = clear_row(
        "folder-root",
        "protected-file",
        "/folder/protected.bin",
        "file-v1",
        4,
        false,
    );
    cache
        .publish_listing(&scope, "folder-root", std::slice::from_ref(&file), 2)
        .unwrap();
    let dirty = ContentVersion {
        resource_id: "protected-file".to_owned(),
        etag: "file-v1".to_owned(),
        protection: ContentProtection::Plaintext,
    };
    cache
        .publish_content(
            &scope,
            &dirty,
            &mut Cursor::new(b"keep".to_vec()),
            4,
            Retention::Dirty,
        )
        .unwrap();
    // Establish a genuine saved pin through the cache API, and an explicit
    // resource policy through the policy API before adding folder intent.
    let pin = cache
        .begin_pin_manifest_at_cancellable(
            &scope,
            "folder-root",
            "/folder",
            &[PinManifestEntry {
                parent_resource_id: "folder-root".to_owned(),
                entry: file.entry.clone(),
            }],
            || false,
        )
        .unwrap();
    assert_eq!(cache.refresh_pin(&pin.id).unwrap().state, PinState::Ready);
    cache
        .set_policy_at(
            &scope,
            "protected-file",
            "/folder/protected.bin",
            "file-v1",
            AvailabilityPolicy::AlwaysOffline,
        )
        .unwrap();
    inject_intent(&cache, &scope, "folder-root");

    let explicit_policy_before: i64 = {
        let db = cache.lock_db().unwrap();
        db.query_row(
            "SELECT policy FROM policies WHERE scope_key=?1 AND resource_id='protected-file'",
            params![scope.key],
            |row| row.get(0),
        )
        .unwrap()
    };
    let content_before = cache.content_record(&scope, &dirty).unwrap();
    let pin_before: (i64, i64) = {
        let db = cache.lock_db().unwrap();
        db.query_row(
            "SELECT state,(SELECT COUNT(*) FROM pin_items WHERE pin_id=pins.pin_id) FROM pins WHERE pin_id=?1",
            params![pin.id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
    };
    assert_eq!(
        explicit_policy_before,
        AvailabilityPolicy::AlwaysOffline as i64
    );
    assert_eq!(content_before.retention, Retention::Dirty);
    assert_eq!(
        cache.policy(&scope, "protected-file"),
        Err(CacheError::PolicyConflict)
    );

    assert!(
        cache
            .clear_folder_cloud_only(&scope, "folder-root")
            .unwrap()
    );

    assert_eq!(
        cache.policy(&scope, "protected-file").unwrap(),
        AvailabilityPolicy::AlwaysOffline
    );
    let explicit_policy_after: i64 = {
        let db = cache.lock_db().unwrap();
        db.query_row(
            "SELECT policy FROM policies WHERE scope_key=?1 AND resource_id='protected-file'",
            params![scope.key],
            |row| row.get(0),
        )
        .unwrap()
    };
    assert_eq!(explicit_policy_after, explicit_policy_before);
    assert_eq!(
        cache.content_record(&scope, &dirty).unwrap(),
        content_before
    );
    let mut reader = cache.open_content(&scope, &dirty).unwrap();
    let mut dirty_bytes = Vec::new();
    reader.read_to_end(&mut dirty_bytes).unwrap();
    assert_eq!(dirty_bytes, b"keep");
    let pin_after: (i64, i64) = {
        let db = cache.lock_db().unwrap();
        db.query_row(
            "SELECT state,(SELECT COUNT(*) FROM pin_items WHERE pin_id=pins.pin_id) FROM pins WHERE pin_id=?1",
            params![pin.id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
    };
    assert_eq!(pin_after, pin_before);
    assert!(!intent_exists(&cache, &scope, "folder-root"));
}
