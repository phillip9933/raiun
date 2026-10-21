use super::*;
use rusqlite::params;
use std::io::{Cursor, Read};

fn policy_row(
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

fn policy_version(id: &str, etag: &str) -> ContentVersion {
    ContentVersion {
        resource_id: id.to_owned(),
        etag: etag.to_owned(),
        protection: ContentProtection::Plaintext,
    }
}

fn publish_dirty(cache: &Cache, scope: &CacheScope, version: &ContentVersion, body: &[u8]) {
    cache
        .publish_content(
            scope,
            version,
            &mut Cursor::new(body.to_vec()),
            body.len() as u64,
            Retention::Dirty,
        )
        .unwrap();
}

fn read_body(cache: &Cache, scope: &CacheScope, version: &ContentVersion) -> Vec<u8> {
    let mut reader = cache.open_content(scope, version).unwrap();
    let mut body = Vec::new();
    reader.read_to_end(&mut body).unwrap();
    body
}

fn inject_folder_intent(cache: &Cache, scope: &CacheScope, root_id: &str) {
    let db = cache.lock_db().unwrap();
    db.execute(
        "INSERT INTO folder_cloud_only_intents(scope_key,root_id) VALUES(?1,?2)",
        params![scope.key, root_id],
    )
    .unwrap();
}

struct PolicyConflictFixture {
    _temp: tempfile::TempDir,
    cache: Cache,
    scope: CacheScope,
    safe_pin: PinInfo,
    protected: ContentVersion,
    protected_body: Vec<u8>,
    safe: ContentVersion,
    safe_body: Vec<u8>,
    safe_folder: CachedEntry,
    nested_folder: CachedEntry,
    safe_file: CachedEntry,
    nested_file: CachedEntry,
}

fn policy_conflict_fixture() -> PolicyConflictFixture {
    let (_temp, cache) = cache();
    let scope = scope(ScopeProtection::PlaintextAllowed);
    let safe_folder = policy_row("root-a", "safe-folder", "/safe", "safe-dir-v1", 0, true);
    let nested_folder = policy_row(
        "root-a",
        "nested-folder",
        "/nested",
        "nested-dir-v1",
        0,
        true,
    );
    cache
        .publish_listing(
            &scope,
            "root-a",
            &[safe_folder.clone(), nested_folder.clone()],
            1,
        )
        .unwrap();

    let safe_body = b"s".to_vec();
    let protected_body = b"p".to_vec();
    let safe_file = policy_row(
        "safe-folder",
        "safe-file",
        "/safe/file.txt",
        "safe-file-v1",
        safe_body.len() as u64,
        false,
    );
    let nested_file = policy_row(
        "nested-folder",
        "protected-file",
        "/nested/file.txt",
        "protected-v1",
        protected_body.len() as u64,
        false,
    );
    cache
        .publish_listing(&scope, "safe-folder", std::slice::from_ref(&safe_file), 2)
        .unwrap();
    cache
        .publish_listing(
            &scope,
            "nested-folder",
            std::slice::from_ref(&nested_file),
            3,
        )
        .unwrap();

    let safe = policy_version("safe-file", "safe-file-v1");
    let protected = policy_version("protected-file", "protected-v1");
    publish_dirty(&cache, &scope, &safe, &safe_body);
    publish_dirty(&cache, &scope, &protected, &protected_body);
    cache
        .set_policy_at(
            &scope,
            "protected-file",
            "/nested/file.txt",
            "protected-v1",
            AvailabilityPolicy::Recent,
        )
        .unwrap();

    let safe_manifest = [PinManifestEntry {
        parent_resource_id: "safe-folder".into(),
        entry: safe_file.clone().entry,
    }];
    let safe_pin = cache
        .begin_pin_manifest_at_cancellable(&scope, "safe-folder", "/safe", &safe_manifest, || false)
        .unwrap();
    let safe_pin = cache
        .refresh_pin_cancellable(&safe_pin.id, || false)
        .unwrap();
    assert_eq!(safe_pin.state, PinState::Ready);

    inject_folder_intent(&cache, &scope, "nested-folder");
    PolicyConflictFixture {
        _temp,
        cache,
        scope,
        safe_pin,
        protected,
        protected_body,
        safe,
        safe_body,
        safe_folder,
        nested_folder,
        safe_file,
        nested_file,
    }
}

#[test]
fn nested_folder_intent_refuses_always_offline_without_changing_policy_or_dirty_content() {
    let fixture = policy_conflict_fixture();
    let cache = &fixture.cache;
    let scope = &fixture.scope;
    assert_eq!(
        cache.policy(scope, &fixture.protected.resource_id).unwrap(),
        AvailabilityPolicy::CloudOnly
    );

    assert_eq!(
        cache.set_policy_at(
            scope,
            &fixture.protected.resource_id,
            "/nested/file.txt",
            &fixture.protected.etag,
            AvailabilityPolicy::AlwaysOffline,
        ),
        Err(CacheError::PolicyConflict)
    );
    // The nested intent is exact to this scope; an identically named resource
    // in another account can still receive its own file policy.
    let other_scope = CacheScope::new(
        "https://cloud.example.test/",
        "account-b",
        "space-a",
        "root-a",
        ScopeProtection::PlaintextAllowed,
    )
    .unwrap();
    let other_file = policy_row(
        "root-a",
        "protected-file",
        "/protected.txt",
        "protected-v1",
        fixture.protected_body.len() as u64,
        false,
    );
    cache
        .publish_listing(&other_scope, "root-a", &[other_file], 1)
        .unwrap();
    publish_dirty(
        cache,
        &other_scope,
        &fixture.protected,
        &fixture.protected_body,
    );
    cache
        .set_policy_at(
            &other_scope,
            &fixture.protected.resource_id,
            "/protected.txt",
            &fixture.protected.etag,
            AvailabilityPolicy::AlwaysOffline,
        )
        .unwrap();
    assert_eq!(
        cache
            .policy(&other_scope, &fixture.protected.resource_id)
            .unwrap(),
        AvailabilityPolicy::AlwaysOffline
    );

    // A failed transition must leave the original explicit Recent row in
    // place and keep its Dirty bytes fully readable.
    let stored_policy: i64 = cache
        .lock_db()
        .unwrap()
        .query_row(
            "SELECT policy FROM policies WHERE scope_key=?1 AND resource_id=?2",
            params![scope.key, fixture.protected.resource_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored_policy, AvailabilityPolicy::Recent as i64);
    assert_eq!(
        cache
            .content_record(scope, &fixture.protected)
            .unwrap()
            .retention,
        Retention::Dirty
    );
    assert_eq!(
        read_body(cache, scope, &fixture.protected),
        fixture.protected_body
    );
    assert_eq!(read_body(cache, scope, &fixture.safe), fixture.safe_body);
    assert_eq!(
        cache
            .pin_info_for_scope(scope, &fixture.safe_pin.id)
            .unwrap(),
        fixture.safe_pin
    );
}

#[test]
fn root_pin_admission_checks_nested_intent_and_preserves_existing_pin_and_dirty_bytes() {
    let fixture = policy_conflict_fixture();
    let cache = &fixture.cache;
    let scope = &fixture.scope;
    let pins_before = cache.pins(scope).unwrap();
    assert_eq!(pins_before, vec![fixture.safe_pin.clone()]);

    let root_manifest = [
        PinManifestEntry {
            parent_resource_id: "root-a".into(),
            entry: fixture.safe_folder.entry.clone(),
        },
        PinManifestEntry {
            parent_resource_id: "root-a".into(),
            entry: fixture.nested_folder.entry.clone(),
        },
        PinManifestEntry {
            parent_resource_id: "safe-folder".into(),
            entry: fixture.safe_file.entry.clone(),
        },
        PinManifestEntry {
            parent_resource_id: "nested-folder".into(),
            entry: fixture.nested_file.entry.clone(),
        },
    ];
    assert_eq!(
        cache.begin_pin_manifest_at_cancellable(scope, "root-a", "/", &root_manifest, || false),
        Err(CacheError::PolicyConflict)
    );
    assert_eq!(cache.pins(scope).unwrap(), pins_before);
    assert_eq!(
        read_body(cache, scope, &fixture.protected),
        fixture.protected_body
    );
    assert_eq!(read_body(cache, scope, &fixture.safe), fixture.safe_body);
    assert_eq!(
        cache
            .content_record(scope, &fixture.protected)
            .unwrap()
            .retention,
        Retention::Dirty
    );
    assert_eq!(
        cache
            .content_record(scope, &fixture.safe)
            .unwrap()
            .retention,
        Retention::Dirty
    );
    let stored_policy: i64 = cache
        .lock_db()
        .unwrap()
        .query_row(
            "SELECT policy FROM policies WHERE scope_key=?1 AND resource_id=?2",
            params![scope.key, fixture.protected.resource_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored_policy, AvailabilityPolicy::Recent as i64);
}
