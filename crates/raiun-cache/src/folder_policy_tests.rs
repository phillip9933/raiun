use super::*;
use rusqlite::params;
use std::io::{Cursor, Read};

fn folder_row(parent: &str, id: &str, path: &str, directory: bool) -> CachedEntry {
    CachedEntry {
        parent_resource_id: parent.to_owned(),
        entry: RemoteEntry {
            id: id.to_owned(),
            path: path.to_owned(),
            etag: "v1".to_owned(),
            size: if directory { 0 } else { 1 },
            directory,
            modified_unix: 1,
            writable: true,
            encrypted: false,
        },
    }
}

fn add_folder_intent(cache: &Cache, scope: &CacheScope, root_id: &str) {
    let db = cache.lock_db().unwrap();
    db.execute(
        "INSERT INTO folder_cloud_only_intents(scope_key,root_id) VALUES(?1,?2)",
        params![scope.key, root_id],
    )
    .unwrap();
}

fn content_version(id: &str, etag: &str) -> ContentVersion {
    ContentVersion {
        resource_id: id.to_owned(),
        etag: etag.to_owned(),
        protection: ContentProtection::Plaintext,
    }
}

fn read_cached(cache: &Cache, scope: &CacheScope, version: &ContentVersion) -> Vec<u8> {
    let mut reader = cache.open_content(scope, version).unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    bytes
}

#[test]
fn inherited_folder_cloud_only_blocks_recent_but_keeps_dirty_and_recovery_readable() {
    let (_temp, cache) = cache();
    let scope = scope(ScopeProtection::PlaintextAllowed);
    cache
        .publish_listing(
            &scope,
            "root-a",
            &[folder_row("root-a", "folder-id", "/folder", true)],
            1,
        )
        .unwrap();
    let children = [
        folder_row("folder-id", "recent-file", "/folder/recent.txt", false),
        folder_row("folder-id", "dirty-file", "/folder/dirty.txt", false),
        folder_row("folder-id", "recovery-file", "/folder/recovery.txt", false),
        folder_row("folder-id", "new-file", "/folder/new.txt", false),
    ];
    cache
        .publish_listing(&scope, "folder-id", &children, 2)
        .unwrap();

    let recent = content_version("recent-file", "v1");
    let dirty = content_version("dirty-file", "v1");
    let recovery = content_version("recovery-file", "v1");
    for (version, body, retention) in [
        (&recent, b"r".as_slice(), Retention::Recent),
        (&dirty, b"d".as_slice(), Retention::Dirty),
        (&recovery, b"x".as_slice(), Retention::Recovery),
    ] {
        cache
            .publish_content(
                &scope,
                version,
                &mut Cursor::new(body),
                body.len() as u64,
                retention,
            )
            .unwrap();
    }

    add_folder_intent(&cache, &scope, "folder-id");
    assert_eq!(
        cache.policy(&scope, "recent-file").unwrap(),
        AvailabilityPolicy::CloudOnly
    );
    assert!(matches!(
        cache.open_content(&scope, &recent),
        Err(CacheError::PolicyConflict)
    ));
    assert!(matches!(
        cache.publish_recent_content_with_budget(
            &scope,
            &content_version("new-file", "v1"),
            &mut Cursor::new(b"n"),
            1,
        ),
        Err(CacheError::PolicyConflict)
    ));
    assert_eq!(
        cache.content_record(&scope, &content_version("new-file", "v1")),
        Err(CacheError::NotFound)
    );
    assert_eq!(read_cached(&cache, &scope, &dirty), b"d");
    assert_eq!(read_cached(&cache, &scope, &recovery), b"x");
}

#[test]
fn folder_intent_follows_stable_id_after_rename_but_not_replacement_or_other_scope() {
    let (_temp, cache) = cache();
    let scope_a = scope(ScopeProtection::PlaintextAllowed);
    cache
        .publish_listing(
            &scope_a,
            "root-a",
            &[folder_row("root-a", "folder-id", "/folder", true)],
            1,
        )
        .unwrap();
    cache
        .publish_listing(
            &scope_a,
            "folder-id",
            &[folder_row(
                "folder-id",
                "child-id",
                "/folder/child.txt",
                false,
            )],
            2,
        )
        .unwrap();
    add_folder_intent(&cache, &scope_a, "folder-id");

    cache
        .publish_listing(
            &scope_a,
            "root-a",
            &[folder_row("root-a", "folder-id", "/renamed", true)],
            3,
        )
        .unwrap();
    cache
        .publish_listing(
            &scope_a,
            "folder-id",
            &[folder_row(
                "folder-id",
                "child-id",
                "/renamed/child.txt",
                false,
            )],
            4,
        )
        .unwrap();
    assert_eq!(
        cache.policy(&scope_a, "child-id").unwrap(),
        AvailabilityPolicy::CloudOnly
    );

    cache
        .publish_listing(
            &scope_a,
            "root-a",
            &[folder_row("root-a", "replacement-id", "/renamed", true)],
            5,
        )
        .unwrap();
    cache
        .publish_listing(
            &scope_a,
            "replacement-id",
            &[folder_row(
                "replacement-id",
                "replacement-child",
                "/renamed/child.txt",
                false,
            )],
            6,
        )
        .unwrap();
    assert_eq!(
        cache.policy(&scope_a, "replacement-child").unwrap(),
        AvailabilityPolicy::Recent
    );

    let scope_b = CacheScope::new(
        "https://cloud.example.test/",
        "account-b",
        "space-a",
        "root-a",
        ScopeProtection::PlaintextAllowed,
    )
    .unwrap();
    cache
        .publish_listing(
            &scope_b,
            "root-a",
            &[folder_row("root-a", "folder-id", "/renamed", true)],
            1,
        )
        .unwrap();
    cache
        .publish_listing(
            &scope_b,
            "folder-id",
            &[folder_row(
                "folder-id",
                "child-id",
                "/renamed/child.txt",
                false,
            )],
            2,
        )
        .unwrap();
    assert_eq!(
        cache.policy(&scope_b, "child-id").unwrap(),
        AvailabilityPolicy::Recent
    );
}

#[test]
fn ancestry_resolver_rejects_ambiguous_missing_and_cyclic_identity_chains() {
    let (_temp, cache) = cache();
    let scope = scope(ScopeProtection::PlaintextAllowed);
    cache
        .publish_listing(
            &scope,
            "root-a",
            &[
                folder_row("root-a", "folder-a", "/a", true),
                folder_row("root-a", "folder-b", "/b", true),
            ],
            1,
        )
        .unwrap();
    cache
        .publish_listing(
            &scope,
            "folder-a",
            &[folder_row("folder-a", "shared-id", "/a/shared", false)],
            2,
        )
        .unwrap();
    cache
        .publish_listing(
            &scope,
            "folder-b",
            &[folder_row("folder-b", "shared-id", "/b/shared", false)],
            3,
        )
        .unwrap();
    add_folder_intent(&cache, &scope, "folder-a");
    assert_eq!(
        cache.policy(&scope, "shared-id"),
        Err(CacheError::PolicyConflict)
    );

    let (_missing_temp, missing_cache) = super::cache();
    let missing_scope = super::scope(ScopeProtection::PlaintextAllowed);
    missing_cache
        .publish_listing(&missing_scope, "root-a", &[], 1)
        .unwrap();
    missing_cache
        .publish_listing(
            &missing_scope,
            "orphan-folder",
            &[folder_row(
                "orphan-folder",
                "orphan-child",
                "/orphan/child.txt",
                false,
            )],
            2,
        )
        .unwrap();
    add_folder_intent(&missing_cache, &missing_scope, "orphan-folder");
    assert_eq!(
        missing_cache.policy(&missing_scope, "orphan-child"),
        Err(CacheError::PolicyConflict)
    );

    let (_cycle_temp, cycle_cache) = super::cache();
    let cycle_scope = super::scope(ScopeProtection::PlaintextAllowed);
    cycle_cache
        .publish_listing(
            &cycle_scope,
            "cycle-b",
            &[folder_row("cycle-b", "cycle-a", "/a/b", true)],
            1,
        )
        .unwrap();
    cycle_cache
        .publish_listing(
            &cycle_scope,
            "cycle-a",
            &[folder_row("cycle-a", "cycle-b", "/a", true)],
            2,
        )
        .unwrap();
    add_folder_intent(&cycle_cache, &cycle_scope, "cycle-a");
    assert_eq!(
        cycle_cache.policy(&cycle_scope, "cycle-a"),
        Err(CacheError::PolicyConflict)
    );
}

#[test]
fn ancestry_resolver_accepts_sixty_four_edges_and_rejects_sixty_five() {
    let (_temp, cache) = cache();
    let scope = scope(ScopeProtection::PlaintextAllowed);
    let ids = (0..=64)
        .map(|index| format!("folder-{index:02}"))
        .collect::<Vec<_>>();
    cache
        .publish_listing(
            &scope,
            "root-a",
            &[folder_row("root-a", &ids[0], "/d00", true)],
            1,
        )
        .unwrap();
    for index in 0..64 {
        let path = (0..=(index + 1))
            .map(|part| format!("d{part:02}"))
            .collect::<Vec<_>>()
            .join("/");
        cache
            .publish_listing(
                &scope,
                &ids[index],
                &[folder_row(
                    &ids[index],
                    &ids[index + 1],
                    &format!("/{path}"),
                    true,
                )],
                index as i64 + 2,
            )
            .unwrap();
    }
    add_folder_intent(&cache, &scope, &ids[0]);
    assert_eq!(
        cache.policy(&scope, &ids[64]),
        Err(CacheError::LimitExceeded)
    );

    let within_bound = (0..64)
        .map(|index| format!("within-{index:02}"))
        .collect::<Vec<_>>();
    cache
        .publish_listing(
            &scope,
            "root-a",
            &[
                folder_row("root-a", &ids[0], "/d00", true),
                folder_row("root-a", &within_bound[0], "/w00", true),
            ],
            100,
        )
        .unwrap();
    for index in 0..63 {
        let path = (0..=(index + 1))
            .map(|part| format!("w{part:02}"))
            .collect::<Vec<_>>()
            .join("/");
        cache
            .publish_listing(
                &scope,
                &within_bound[index],
                &[folder_row(
                    &within_bound[index],
                    &within_bound[index + 1],
                    &format!("/{path}"),
                    true,
                )],
                index as i64 + 101,
            )
            .unwrap();
    }
    add_folder_intent(&cache, &scope, &within_bound[0]);
    assert_eq!(
        cache.policy(&scope, &within_bound[63]).unwrap(),
        AvailabilityPolicy::CloudOnly
    );
}

#[test]
fn recent_publication_race_rejects_and_cleans_only_its_unreferenced_blob() {
    for reuse_dirty_version in [false, true] {
        let (_temp, cache) = cache();
        let scope = scope(ScopeProtection::PlaintextAllowed);
        cache
            .publish_listing(
                &scope,
                "root-a",
                &[folder_row("root-a", "folder-id", "/folder", true)],
                1,
            )
            .unwrap();

        let dirty = content_version("file-id", "dirty-v1");
        let mut initial_row = folder_row("folder-id", "file-id", "/folder/file.txt", false);
        initial_row.entry.etag = "dirty-v1".to_owned();
        cache
            .publish_listing(&scope, "folder-id", &[initial_row], 2)
            .unwrap();
        cache
            .publish_content(&scope, &dirty, &mut Cursor::new(b"d"), 1, Retention::Dirty)
            .unwrap();
        let dirty_blob = cache
            .inner
            .content_dir
            .join(format!("{}.blob", content_key(&scope, &dirty)));
        let dirty_before = std::fs::read(&dirty_blob).unwrap();

        let candidate = if reuse_dirty_version {
            dirty.clone()
        } else {
            let mut row = folder_row("folder-id", "file-id", "/folder/file.txt", false);
            row.entry.etag = "recent-v2".to_owned();
            cache
                .publish_listing(&scope, "folder-id", &[row], 3)
                .unwrap();
            content_version("file-id", "recent-v2")
        };
        let candidate_body: &'static [u8] = if reuse_dirty_version { b"d" } else { b"n" };
        let candidate_blob = cache
            .inner
            .content_dir
            .join(format!("{}.blob", content_key(&scope, &candidate)));

        let result = cache.publish_content_internal_with_hook(
            &scope,
            &candidate,
            &mut Cursor::new(candidate_body),
            candidate_body.len() as u64,
            ContentPublishOptions {
                retention: Retention::Recent,
                recent_budget: false,
                require_listed: true,
                expected_ciphertext_epoch: None,
                pin_build: None,
                ciphertext_write: None,
            },
            || {
                let db = cache.lock_db().unwrap();
                db.execute(
                    "INSERT INTO folder_cloud_only_intents(scope_key,root_id) VALUES(?1,?2)",
                    params![scope.key, "folder-id"],
                )
                .unwrap();
                // Simulate an ancestor replacement after the blob is staged.
                // The late policy check must fail closed without deleting an
                // older Dirty version that is already referenced.
                db.execute(
                    "UPDATE listing_entries SET resource_id='replacement-folder' \
                     WHERE scope_key=?1 AND parent_id='root-a' AND resource_id='folder-id'",
                    [scope.key.as_str()],
                )
                .unwrap();
            },
        );

        assert!(matches!(result, Err(CacheError::PolicyConflict)));
        assert_eq!(read_cached(&cache, &scope, &dirty), dirty_before);
        assert_eq!(std::fs::read(&dirty_blob).unwrap(), dirty_before);
        assert_eq!(
            cache.content_record(&scope, &dirty).unwrap().retention,
            Retention::Dirty
        );
        if reuse_dirty_version {
            // The candidate shares the existing immutable Dirty version.
            assert!(candidate_blob.exists());
            assert_eq!(std::fs::read(&candidate_blob).unwrap(), dirty_before);
        } else {
            // A newly staged Recent version is unreferenced after rejection.
            assert!(!candidate_blob.exists());
            assert_eq!(
                cache.content_record(&scope, &candidate),
                Err(CacheError::NotFound)
            );
        }
    }
}

#[test]
fn schema_seven_upgrade_preserves_dirty_bytes_without_inventing_folder_intent() {
    let (state, cache) = cache();
    let owner = scope(ScopeProtection::PlaintextAllowed);
    cache
        .publish_listing(
            &owner,
            "root-a",
            &[folder_row("root-a", "old-file", "/old.txt", false)],
            1,
        )
        .unwrap();
    let version = content_version("old-file", "v1");
    cache
        .publish_content(
            &owner,
            &version,
            &mut Cursor::new(b"d"),
            1,
            Retention::Dirty,
        )
        .unwrap();
    let database_path = cache.root().join(DB_FILE);
    drop(cache);
    let db = rusqlite::Connection::open(database_path).unwrap();
    db.execute_batch("DROP TABLE folder_cloud_only_intents; PRAGMA user_version=7;")
        .unwrap();
    drop(db);
    let cache = Cache::open(state.path(), 1024).unwrap();
    assert_eq!(read_cached(&cache, &owner, &version), b"d");
    assert_eq!(
        cache.content_record(&owner, &version).unwrap().retention,
        Retention::Dirty
    );
    assert_eq!(
        cache.policy(&owner, "old-file").unwrap(),
        AvailabilityPolicy::Recent
    );
    let db = cache.lock_db().unwrap();
    let version: i64 = db
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, 8);
    let intents: i64 = db
        .query_row("SELECT COUNT(*) FROM folder_cloud_only_intents", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(intents, 0);
}
