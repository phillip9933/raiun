use super::*;
use std::io::{Cursor, Read};

#[test]
fn fresh_directory_metadata_can_advance_without_rebinding_the_cached_folder() {
    let fixture = admission_fixture(Retention::Recent);
    let mut selected = fixture.folder.clone();
    selected.entry.etag = "fresh-directory-etag".into();
    selected.entry.modified_unix += 1;
    let mut observed = observations(&fixture);
    observed[0].entries = vec![selected.clone()];
    fixture
        .cache
        .set_folder_cloud_only(&fixture.scope, &selected, &observed)
        .unwrap();
    assert_eq!(
        fixture
            .cache
            .listing(&fixture.scope, "root-a")
            .unwrap()
            .entries,
        vec![selected]
    );
    assert_eq!(
        fixture.cache.policy(&fixture.scope, "child-id").unwrap(),
        AvailabilityPolicy::CloudOnly
    );
}

#[test]
fn persisted_empty_ciphertext_pin_root_blocks_admission_without_items() {
    let fixture = admission_fixture(Retention::Recent);
    let before = fixture.cache.listing(&fixture.scope, "folder-id").unwrap();
    // Normal ciphertext APIs require a ciphertext-only scope. A persisted
    // inconsistent root must nevertheless fail closed before any items exist.
    fixture.cache.lock_db().unwrap().execute(
        "INSERT INTO ciphertext_pin_roots(pin_id,scope_key,root_resource_id,created_at) VALUES('empty-cipher-pin',?1,'folder-id',1)",
        [&fixture.scope.key],
    ).unwrap();
    assert_eq!(
        fixture.cache.set_folder_cloud_only(
            &fixture.scope,
            &fixture.folder,
            &observations(&fixture)
        ),
        Err(CacheError::PolicyConflict)
    );
    assert_eq!(
        fixture.cache.listing(&fixture.scope, "folder-id").unwrap(),
        before
    );
    assert_eq!(
        fixture.cache.policy(&fixture.scope, "child-id").unwrap(),
        AvailabilityPolicy::Recent
    );
    assert_eq!(
        read_admission_body(
            &fixture.cache,
            &fixture.scope,
            &admission_version("child-id", "child-v1")
        ),
        fixture.body
    );
    let count: i64 = fixture
        .cache
        .lock_db()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM ciphertext_pin_roots WHERE pin_id='empty-cipher-pin'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
}

fn admission_row(
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

fn admission_version(id: &str, etag: &str) -> ContentVersion {
    ContentVersion {
        resource_id: id.to_owned(),
        etag: etag.to_owned(),
        protection: ContentProtection::Plaintext,
    }
}

fn read_admission_body(cache: &Cache, scope: &CacheScope, version: &ContentVersion) -> Vec<u8> {
    let mut reader = cache.open_content(scope, version).unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    bytes
}

struct AdmissionFixture {
    _temp: tempfile::TempDir,
    cache: Cache,
    scope: CacheScope,
    folder: CachedEntry,
    child: CachedEntry,
    body: Vec<u8>,
}

fn admission_fixture(retention: Retention) -> AdmissionFixture {
    let (_temp, cache) = cache();
    let scope = scope(ScopeProtection::PlaintextAllowed);
    let folder = admission_row("root-a", "folder-id", "/folder", "folder-v1", 0, true);
    cache
        .publish_listing(&scope, "root-a", std::slice::from_ref(&folder), 10)
        .unwrap();
    let body = b"retained child".to_vec();
    let child = admission_row(
        "folder-id",
        "child-id",
        "/folder/child.txt",
        "child-v1",
        body.len() as u64,
        false,
    );
    cache
        .publish_listing(&scope, "folder-id", std::slice::from_ref(&child), 11)
        .unwrap();
    let version = admission_version("child-id", "child-v1");
    cache
        .publish_content(
            &scope,
            &version,
            &mut Cursor::new(body.clone()),
            body.len() as u64,
            retention,
        )
        .unwrap();
    AdmissionFixture {
        _temp,
        cache,
        scope,
        folder,
        child,
        body,
    }
}

fn observations(fixture: &AdmissionFixture) -> Vec<FolderPolicyListing> {
    let root = fixture.cache.listing(&fixture.scope, "root-a").unwrap();
    let folder = fixture
        .cache
        .listing(&fixture.scope, &fixture.folder.entry.id)
        .unwrap();
    vec![
        FolderPolicyListing {
            parent_resource_id: "root-a".into(),
            expected_generation: Some(root.generation),
            entries: root.entries,
        },
        FolderPolicyListing {
            parent_resource_id: fixture.folder.entry.id.clone(),
            expected_generation: Some(folder.generation),
            entries: folder.entries,
        },
    ]
}

fn pin_folder_child(fixture: &AdmissionFixture) -> PinInfo {
    let pin = fixture
        .cache
        .begin_pin_manifest_at_cancellable(
            &fixture.scope,
            &fixture.folder.entry.id,
            "/folder",
            &[PinManifestEntry {
                parent_resource_id: fixture.folder.entry.id.clone(),
                entry: fixture.child.entry.clone(),
            }],
            || false,
        )
        .unwrap();
    fixture.cache.refresh_pin(&pin.id).unwrap()
}

#[test]
fn clean_nested_folder_admission_commits_listing_intent_and_recent_eviction_across_reopen() {
    let fixture = admission_fixture(Retention::Recent);
    let version = admission_version("child-id", "child-v1");
    assert_eq!(
        fixture.cache.policy(&fixture.scope, "child-id").unwrap(),
        AvailabilityPolicy::Recent
    );
    assert_eq!(
        fixture
            .cache
            .content_record(&fixture.scope, &version)
            .unwrap()
            .retention,
        Retention::Recent
    );

    fixture
        .cache
        .set_folder_cloud_only(&fixture.scope, &fixture.folder, &observations(&fixture))
        .unwrap();

    assert_eq!(
        fixture.cache.policy(&fixture.scope, "child-id").unwrap(),
        AvailabilityPolicy::CloudOnly
    );
    assert_eq!(
        fixture.cache.content_record(&fixture.scope, &version),
        Err(CacheError::NotFound)
    );
    let root_after = fixture.cache.listing(&fixture.scope, "root-a").unwrap();
    let folder_after = fixture.cache.listing(&fixture.scope, "folder-id").unwrap();
    assert_eq!(root_after.generation, 2);
    assert_eq!(folder_after.generation, 2);
    assert_eq!(root_after.entries, vec![fixture.folder.clone()]);
    assert_eq!(folder_after.entries, vec![fixture.child.clone()]);

    drop(fixture.cache);
    let reopened = Cache::open(fixture._temp.path(), 1024).unwrap();
    assert_eq!(
        reopened.policy(&fixture.scope, "child-id").unwrap(),
        AvailabilityPolicy::CloudOnly
    );
    assert_eq!(
        reopened.content_record(&fixture.scope, &version),
        Err(CacheError::NotFound)
    );
    assert_eq!(
        reopened.listing(&fixture.scope, "root-a").unwrap(),
        root_after
    );
}

#[test]
fn dirty_and_recovery_descendants_refuse_without_changing_listing_or_content() {
    for retention in [Retention::Dirty, Retention::Recovery] {
        let fixture = admission_fixture(retention);
        let before_root = fixture.cache.listing(&fixture.scope, "root-a").unwrap();
        let before_folder = fixture.cache.listing(&fixture.scope, "folder-id").unwrap();
        let version = admission_version("child-id", "child-v1");
        let before_record = fixture
            .cache
            .content_record(&fixture.scope, &version)
            .unwrap();
        let before_policy = fixture.cache.policy(&fixture.scope, "child-id").unwrap();
        assert_eq!(before_record.retention, retention);

        assert_eq!(
            fixture.cache.set_folder_cloud_only(
                &fixture.scope,
                &fixture.folder,
                &observations(&fixture)
            ),
            Err(CacheError::PolicyConflict)
        );
        assert_eq!(
            fixture.cache.listing(&fixture.scope, "root-a").unwrap(),
            before_root
        );
        assert_eq!(
            fixture.cache.listing(&fixture.scope, "folder-id").unwrap(),
            before_folder
        );
        assert_eq!(
            fixture
                .cache
                .content_record(&fixture.scope, &version)
                .unwrap(),
            before_record
        );
        assert_eq!(
            fixture.cache.policy(&fixture.scope, "child-id").unwrap(),
            before_policy
        );
        assert_eq!(
            read_admission_body(&fixture.cache, &fixture.scope, &version),
            fixture.body
        );
    }
}

#[test]
fn always_offline_descendant_and_ready_pin_refuse_without_mutating_pin_or_metadata() {
    let fixture = admission_fixture(Retention::Recent);
    let version = admission_version("child-id", "child-v1");
    fixture
        .cache
        .set_policy_at(
            &fixture.scope,
            "child-id",
            "/folder/child.txt",
            "child-v1",
            AvailabilityPolicy::AlwaysOffline,
        )
        .unwrap();
    let before_policy = fixture.cache.policy(&fixture.scope, "child-id").unwrap();
    let before_root = fixture.cache.listing(&fixture.scope, "root-a").unwrap();
    let before_folder = fixture.cache.listing(&fixture.scope, "folder-id").unwrap();
    assert_eq!(
        fixture.cache.set_folder_cloud_only(
            &fixture.scope,
            &fixture.folder,
            &observations(&fixture)
        ),
        Err(CacheError::PolicyConflict)
    );
    assert_eq!(
        fixture.cache.policy(&fixture.scope, "child-id").unwrap(),
        before_policy
    );
    assert_eq!(
        fixture.cache.listing(&fixture.scope, "root-a").unwrap(),
        before_root
    );
    assert_eq!(
        fixture.cache.listing(&fixture.scope, "folder-id").unwrap(),
        before_folder
    );
    assert_eq!(
        fixture
            .cache
            .content_record(&fixture.scope, &version)
            .unwrap()
            .retention,
        Retention::Recent
    );
    assert_eq!(
        read_admission_body(&fixture.cache, &fixture.scope, &version),
        fixture.body
    );

    let fixture = admission_fixture(Retention::Recent);
    let pin = pin_folder_child(&fixture);
    assert_eq!(pin.state, PinState::Ready);
    let before_root = fixture.cache.listing(&fixture.scope, "root-a").unwrap();
    let before_folder = fixture.cache.listing(&fixture.scope, "folder-id").unwrap();
    let before_pin = fixture.cache.pin_info(&pin.id).unwrap();
    assert_eq!(
        fixture.cache.set_folder_cloud_only(
            &fixture.scope,
            &fixture.folder,
            &observations(&fixture)
        ),
        Err(CacheError::PolicyConflict)
    );
    assert_eq!(fixture.cache.pin_info(&pin.id).unwrap(), before_pin);
    assert_eq!(
        fixture.cache.listing(&fixture.scope, "root-a").unwrap(),
        before_root
    );
    assert_eq!(
        fixture.cache.listing(&fixture.scope, "folder-id").unwrap(),
        before_folder
    );
    assert_eq!(
        fixture.cache.policy(&fixture.scope, "child-id").unwrap(),
        AvailabilityPolicy::Recent
    );
    assert_eq!(
        read_admission_body(&fixture.cache, &fixture.scope, &version),
        fixture.body
    );
}

#[test]
fn generation_mismatch_and_moved_out_member_refuse_atomically() {
    let fixture = admission_fixture(Retention::Recent);
    let before_root = fixture.cache.listing(&fixture.scope, "root-a").unwrap();
    let before_folder = fixture.cache.listing(&fixture.scope, "folder-id").unwrap();
    let mut stale = observations(&fixture);
    stale[0].expected_generation = Some(before_root.generation + 10);
    assert_eq!(
        fixture
            .cache
            .set_folder_cloud_only(&fixture.scope, &fixture.folder, &stale),
        Err(CacheError::Conflict)
    );
    assert_eq!(
        fixture.cache.listing(&fixture.scope, "root-a").unwrap(),
        before_root
    );
    assert_eq!(
        fixture.cache.listing(&fixture.scope, "folder-id").unwrap(),
        before_folder
    );

    let mut moved_out = observations(&fixture);
    // The child existed in the admitted folder before the remote observations,
    // but the fresh complete folder listing no longer contains it. A sibling
    // or root listing cannot make the cache delete this old identity.
    moved_out[1].entries.clear();
    assert!(matches!(
        fixture
            .cache
            .set_folder_cloud_only(&fixture.scope, &fixture.folder, &moved_out),
        Err(CacheError::Conflict | CacheError::PolicyConflict)
    ));
    assert_eq!(
        fixture.cache.listing(&fixture.scope, "root-a").unwrap(),
        before_root
    );
    assert_eq!(
        fixture.cache.listing(&fixture.scope, "folder-id").unwrap(),
        before_folder
    );
    let version = admission_version("child-id", "child-v1");
    assert_eq!(
        read_admission_body(&fixture.cache, &fixture.scope, &version),
        fixture.body
    );
    assert_eq!(
        fixture.cache.policy(&fixture.scope, "child-id").unwrap(),
        AvailabilityPolicy::Recent
    );
}

#[test]
fn admission_covers_new_descendant_directories_before_recent_content_can_be_published() {
    let (_temp, cache) = cache();
    let scope = scope(ScopeProtection::PlaintextAllowed);
    let folder = admission_row("root-a", "folder-id", "/folder", "folder-v1", 0, true);
    cache
        .publish_listing(&scope, "root-a", std::slice::from_ref(&folder), 1)
        .unwrap();
    cache.publish_listing(&scope, "folder-id", &[], 2).unwrap();

    let root_listing = cache.listing(&scope, "root-a").unwrap();
    let folder_listing = cache.listing(&scope, "folder-id").unwrap();
    let nested = admission_row(
        "folder-id",
        "nested-id",
        "/folder/nested",
        "nested-v1",
        0,
        true,
    );
    let nested_file_listing = Vec::new();
    let observations = [
        FolderPolicyListing {
            parent_resource_id: "root-a".into(),
            expected_generation: Some(root_listing.generation),
            entries: root_listing.entries,
        },
        FolderPolicyListing {
            parent_resource_id: "folder-id".into(),
            expected_generation: Some(folder_listing.generation),
            entries: vec![nested.clone()],
        },
        FolderPolicyListing {
            parent_resource_id: "nested-id".into(),
            expected_generation: None,
            entries: nested_file_listing,
        },
    ];
    cache
        .set_folder_cloud_only(&scope, &folder, &observations)
        .unwrap();

    let new_file = admission_row(
        "nested-id",
        "new-file",
        "/folder/nested/new.txt",
        "new-v1",
        3,
        false,
    );
    cache
        .publish_listing(&scope, "nested-id", std::slice::from_ref(&new_file), 3)
        .unwrap();
    let version = admission_version("new-file", "new-v1");
    assert_eq!(
        cache.publish_recent_content_with_budget(&scope, &version, &mut Cursor::new(b"new"), 3,),
        Err(CacheError::PolicyConflict)
    );
    assert_eq!(
        cache.content_record(&scope, &version),
        Err(CacheError::NotFound)
    );
    assert_eq!(
        cache.policy(&scope, "new-file").unwrap(),
        AvailabilityPolicy::CloudOnly
    );
}

#[test]
fn root_cloud_only_admission_uses_exact_scope_root_identity_and_slash_path() {
    let (_temp, cache) = cache();
    let scope = scope(ScopeProtection::PlaintextAllowed);
    let root = admission_row("root-a", "root-a", "/", "root-v1", 0, true);
    let recent = admission_row(
        "root-a",
        "root-child",
        "/root-child.txt",
        "child-v1",
        4,
        false,
    );
    cache
        .publish_listing(&scope, "root-a", std::slice::from_ref(&recent), 1)
        .unwrap();
    let body = b"root";
    let version = admission_version("root-child", "child-v1");
    cache
        .publish_content(
            &scope,
            &version,
            &mut Cursor::new(body),
            body.len() as u64,
            Retention::Recent,
        )
        .unwrap();
    let listing = cache.listing(&scope, "root-a").unwrap();
    let observations = [FolderPolicyListing {
        parent_resource_id: "root-a".into(),
        expected_generation: Some(listing.generation),
        entries: listing.entries,
    }];

    cache
        .set_folder_cloud_only(&scope, &root, &observations)
        .unwrap();
    assert_eq!(
        cache.policy(&scope, "root-child").unwrap(),
        AvailabilityPolicy::CloudOnly
    );
    assert_eq!(
        cache.content_record(&scope, &version),
        Err(CacheError::NotFound)
    );
}

#[test]
fn orphan_recent_content_blocks_admission_without_eviction_or_listing_publication() {
    let (_temp, cache) = cache();
    let scope = scope(ScopeProtection::PlaintextAllowed);
    let folder = admission_row("root-a", "folder-id", "/folder", "folder-v1", 0, true);
    let orphan = admission_row("root-a", "orphan-id", "/orphan.txt", "orphan-v1", 6, false);
    cache
        .publish_listing(&scope, "root-a", &[folder.clone(), orphan.clone()], 1)
        .unwrap();
    cache.publish_listing(&scope, "folder-id", &[], 2).unwrap();
    let version = admission_version("orphan-id", "orphan-v1");
    let body = b"orphan";
    cache
        .publish_content(
            &scope,
            &version,
            &mut Cursor::new(body),
            body.len() as u64,
            Retention::Recent,
        )
        .unwrap();
    // A later complete parent listing removes the resource while its verified
    // Recent bytes remain cached. Admission must refuse rather than evict a
    // retained identity whose ancestry is no longer provable.
    cache
        .publish_listing(&scope, "root-a", std::slice::from_ref(&folder), 3)
        .unwrap();
    let before_root = cache.listing(&scope, "root-a").unwrap();
    let before_folder = cache.listing(&scope, "folder-id").unwrap();
    let observations = [
        FolderPolicyListing {
            parent_resource_id: "root-a".into(),
            expected_generation: Some(before_root.generation),
            entries: before_root.entries.clone(),
        },
        FolderPolicyListing {
            parent_resource_id: "folder-id".into(),
            expected_generation: Some(before_folder.generation),
            entries: before_folder.entries.clone(),
        },
    ];

    assert!(matches!(
        cache.set_folder_cloud_only(&scope, &folder, &observations),
        Err(CacheError::PolicyConflict | CacheError::Conflict)
    ));
    assert_eq!(cache.listing(&scope, "root-a").unwrap(), before_root);
    assert_eq!(cache.listing(&scope, "folder-id").unwrap(), before_folder);
    assert_eq!(
        cache.content_record(&scope, &version).unwrap().retention,
        Retention::Recent
    );
    assert_eq!(read_admission_body(&cache, &scope, &version), body);
    assert_eq!(
        cache.policy(&scope, "folder-id").unwrap(),
        AvailabilityPolicy::Recent
    );
}

#[test]
fn pending_create_write_blocks_folder_admission_and_keeps_journal_bytes() {
    let (_temp, cache) = cache();
    let scope = scope(ScopeProtection::PlaintextAllowed);
    let folder = admission_row("root-a", "folder-id", "/folder", "folder-v1", 0, true);
    cache
        .publish_listing(&scope, "root-a", std::slice::from_ref(&folder), 1)
        .unwrap();
    cache.publish_listing(&scope, "folder-id", &[], 2).unwrap();
    let write = cache
        .queue_conditional_write(
            &scope,
            ConditionalWriteRequest {
                parent_resource_id: "folder-id".into(),
                name: "new.txt".into(),
                logical_path: "/folder/new.txt".into(),
                resource_id: None,
                base: WriteCondition::Absent,
                expected_len: 5,
                protection: ContentProtection::Plaintext,
            },
            &mut Cursor::new(b"draft"),
        )
        .unwrap();
    let before_pending = cache.pending_writes(&scope).unwrap();
    let before_content = cache.content_record(&scope, &write.content).unwrap();
    let root_listing = cache.listing(&scope, "root-a").unwrap();
    let folder_listing = cache.listing(&scope, "folder-id").unwrap();
    let observations = [
        FolderPolicyListing {
            parent_resource_id: "root-a".into(),
            expected_generation: Some(root_listing.generation),
            entries: root_listing.entries,
        },
        FolderPolicyListing {
            parent_resource_id: "folder-id".into(),
            expected_generation: Some(folder_listing.generation),
            entries: folder_listing.entries,
        },
    ];

    assert!(matches!(
        cache.set_folder_cloud_only(&scope, &folder, &observations),
        Err(CacheError::PolicyConflict | CacheError::Conflict)
    ));
    assert_eq!(cache.pending_writes(&scope).unwrap(), before_pending);
    assert_eq!(
        cache.content_record(&scope, &write.content).unwrap(),
        before_content
    );
    assert_eq!(
        read_admission_body(&cache, &scope, &write.content),
        b"draft"
    );
    assert_eq!(
        cache.listing(&scope, "root-a").unwrap().generation,
        root_listing.generation
    );
    assert_eq!(
        cache.listing(&scope, "folder-id").unwrap().generation,
        folder_listing.generation
    );
    assert_eq!(
        cache.policy(&scope, "folder-id").unwrap(),
        AvailabilityPolicy::Recent
    );
}
