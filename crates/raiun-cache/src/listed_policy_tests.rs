use super::*;
use std::io::{Cursor, Read};

fn test_scope(protection: ScopeProtection) -> CacheScope {
    CacheScope::new(
        "https://cache-policy.example.test/",
        "synthetic-account",
        "synthetic-space",
        "synthetic-root",
        protection,
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

fn remote_entry(
    id: &str,
    path: &str,
    etag: &str,
    size: u64,
    directory: bool,
    encrypted: bool,
) -> RemoteEntry {
    RemoteEntry {
        id: id.into(),
        path: path.into(),
        directory,
        size,
        etag: etag.into(),
        modified_unix: 1,
        writable: true,
        encrypted,
    }
}

fn listed(entry: &RemoteEntry, parent: &str) -> CachedEntry {
    CachedEntry {
        parent_resource_id: parent.into(),
        entry: entry.clone(),
    }
}

fn publish_recent(cache: &Cache, scope: &CacheScope, entry: &RemoteEntry, bytes: &[u8]) {
    cache
        .publish_listing(
            scope,
            "synthetic-root",
            &[listed(entry, "synthetic-root")],
            10,
        )
        .unwrap();
    cache
        .publish_content(
            scope,
            &ContentVersion {
                resource_id: entry.id.clone(),
                etag: entry.etag.clone(),
                protection: ContentProtection::Plaintext,
            },
            &mut Cursor::new(bytes),
            bytes.len() as u64,
            Retention::Recent,
        )
        .unwrap();
}

fn cached_bytes(
    cache: &Cache,
    scope: &CacheScope,
    entry: &RemoteEntry,
) -> Result<Vec<u8>, CacheError> {
    let mut bytes = Vec::new();
    cache
        .open_content(
            scope,
            &ContentVersion {
                resource_id: entry.id.clone(),
                etag: entry.etag.clone(),
                protection: ContentProtection::Plaintext,
            },
        )?
        .read_to_end(&mut bytes)
        .unwrap();
    Ok(bytes)
}

#[test]
fn listed_policy_cannot_admit_offline_without_a_verified_download_workflow() {
    let (_state, cache) = test_cache();
    let scope = test_scope(ScopeProtection::PlaintextAllowed);
    let entry = remote_entry("uncached", "/uncached.txt", "v1", 5, false, false);
    cache
        .publish_listing(
            &scope,
            "synthetic-root",
            &[listed(&entry, "synthetic-root")],
            10,
        )
        .unwrap();
    assert!(matches!(
        cache.set_listed_file_policy(&scope, &entry, AvailabilityPolicy::AlwaysOffline),
        Err(CacheError::PolicyConflict)
    ));
    assert_eq!(
        cache.policy(&scope, &entry.id).unwrap(),
        AvailabilityPolicy::Recent
    );
    assert!(matches!(
        cached_bytes(&cache, &scope, &entry),
        Err(CacheError::NotFound)
    ));
}

#[test]
fn listed_cloud_only_evicts_exact_recent_content_and_recent_can_be_restored() {
    let (_state, cache) = test_cache();
    let scope = test_scope(ScopeProtection::PlaintextAllowed);
    let entry = remote_entry("file-1", "/notes.txt", "v1", 5, false, false);
    publish_recent(&cache, &scope, &entry, b"hello");

    cache
        .set_listed_file_policy(&scope, &entry, AvailabilityPolicy::CloudOnly)
        .unwrap();

    assert_eq!(
        cache.policy(&scope, &entry.id).unwrap(),
        AvailabilityPolicy::CloudOnly
    );
    assert!(matches!(
        cached_bytes(&cache, &scope, &entry),
        Err(CacheError::NotFound)
    ));
    assert!(matches!(
        cache.content_record(
            &scope,
            &ContentVersion {
                resource_id: entry.id.clone(),
                etag: entry.etag.clone(),
                protection: ContentProtection::Plaintext,
            }
        ),
        Err(CacheError::NotFound)
    ));

    cache
        .set_listed_file_policy(&scope, &entry, AvailabilityPolicy::Recent)
        .unwrap();
    assert_eq!(
        cache.policy(&scope, &entry.id).unwrap(),
        AvailabilityPolicy::Recent
    );
    cache
        .publish_content(
            &scope,
            &ContentVersion {
                resource_id: entry.id.clone(),
                etag: entry.etag.clone(),
                protection: ContentProtection::Plaintext,
            },
            &mut Cursor::new(b"fresh"),
            5,
            Retention::Recent,
        )
        .unwrap();
    assert_eq!(cached_bytes(&cache, &scope, &entry).unwrap(), b"fresh");
}

#[test]
fn listed_policy_rejects_stale_identity_version_path_or_size_without_mutation() {
    let (_state, cache) = test_cache();
    let scope = test_scope(ScopeProtection::PlaintextAllowed);
    let entry = remote_entry("file-2", "/report.txt", "etag-2", 6, false, false);
    publish_recent(&cache, &scope, &entry, b"report");

    let mut stale = Vec::new();
    let mut changed = entry.clone();
    changed.id = "different-id".into();
    stale.push(changed);
    let mut changed = entry.clone();
    changed.etag = "etag-old".into();
    stale.push(changed);
    let mut changed = entry.clone();
    changed.path = "/renamed.txt".into();
    stale.push(changed);
    let mut changed = entry.clone();
    changed.size += 1;
    stale.push(changed);

    for candidate in stale {
        assert!(matches!(
            cache.set_listed_file_policy(&scope, &candidate, AvailabilityPolicy::CloudOnly),
            Err(CacheError::PolicyConflict)
        ));
        assert_eq!(
            cache.policy(&scope, &entry.id).unwrap(),
            AvailabilityPolicy::Recent
        );
        assert_eq!(cached_bytes(&cache, &scope, &entry).unwrap(), b"report");
    }
}

#[test]
fn listed_policy_rejects_encrypted_directories_and_weak_or_malformed_etags() {
    let (_state, cache) = test_cache();
    let scope = test_scope(ScopeProtection::PlaintextAllowed);
    let directory = remote_entry("dir-1", "/folder", "dir-v1", 0, true, false);
    let encrypted = remote_entry("enc-1", "/secret.bin", "enc-v1", 4, false, true);
    let weak = remote_entry("weak-1", "/weak.txt", "W/weak", 4, false, false);
    let padded_weak = remote_entry("weak-2", "/padded.txt", " W/weak", 4, false, false);
    let control_etag = remote_entry("bad-1", "/bad.txt", "etag\nvalue", 4, false, false);

    for candidate in [&directory, &encrypted, &weak, &padded_weak, &control_etag] {
        assert!(matches!(
            cache.set_listed_file_policy(&scope, candidate, AvailabilityPolicy::CloudOnly),
            Err(CacheError::PolicyConflict)
        ));
    }

    let ciphertext_scope = test_scope(ScopeProtection::CiphertextOnly);
    let ordinary = remote_entry("ordinary", "/ordinary.txt", "v1", 1, false, false);
    assert!(matches!(
        cache.set_listed_file_policy(&ciphertext_scope, &ordinary, AvailabilityPolicy::CloudOnly),
        Err(CacheError::PolicyConflict)
    ));
}

#[test]
fn listed_policy_requires_registered_scope_and_unambiguous_listing_identity() {
    let (_state, cache) = test_cache();
    let scope = test_scope(ScopeProtection::PlaintextAllowed);
    let entry = remote_entry("file-3", "/unique.txt", "v1", 3, false, false);
    publish_recent(&cache, &scope, &entry, b"one");

    let unregistered_scope = CacheScope::new(
        "https://cache-policy.example.test/",
        "other-account",
        "synthetic-space",
        "synthetic-root",
        ScopeProtection::PlaintextAllowed,
    )
    .unwrap();
    assert!(matches!(
        cache.set_listed_file_policy(&unregistered_scope, &entry, AvailabilityPolicy::CloudOnly),
        Err(CacheError::NotFound)
    ));

    let duplicate = remote_entry("file-3", "/alternate.txt", "v1", 3, false, false);
    cache
        .publish_listing(
            &scope,
            "another-parent",
            &[listed(&duplicate, "another-parent")],
            11,
        )
        .unwrap();
    assert!(matches!(
        cache.set_listed_file_policy(&scope, &entry, AvailabilityPolicy::CloudOnly),
        Err(CacheError::PolicyConflict)
    ));
    assert_eq!(
        cache.policy(&scope, &entry.id).unwrap(),
        AvailabilityPolicy::Recent
    );
    assert_eq!(cached_bytes(&cache, &scope, &entry).unwrap(), b"one");
}

#[test]
fn listed_policy_refuses_stale_entry_after_complete_listing_replaces_its_version() {
    let (_state, cache) = test_cache();
    let scope = test_scope(ScopeProtection::PlaintextAllowed);
    let old_entry = remote_entry("file-5", "/versioned.txt", "v1", 3, false, false);
    publish_recent(&cache, &scope, &old_entry, b"old");

    let new_entry = remote_entry("file-5", "/versioned.txt", "v2", 3, false, false);
    cache
        .publish_listing(
            &scope,
            "synthetic-root",
            &[listed(&new_entry, "synthetic-root")],
            11,
        )
        .unwrap();

    assert!(matches!(
        cache.set_listed_file_policy(&scope, &old_entry, AvailabilityPolicy::CloudOnly),
        Err(CacheError::PolicyConflict)
    ));
    assert_eq!(
        cache.policy(&scope, &old_entry.id).unwrap(),
        AvailabilityPolicy::Recent
    );
    assert_eq!(cached_bytes(&cache, &scope, &old_entry).unwrap(), b"old");
    assert_eq!(
        cache.listing(&scope, "synthetic-root").unwrap().entries[0].entry,
        new_entry
    );
}

#[test]
fn listed_policy_refuses_a_path_reused_by_another_listed_resource() {
    let (_state, cache) = test_cache();
    let scope = test_scope(ScopeProtection::PlaintextAllowed);
    let entry = remote_entry("file-6", "/reused.txt", "v1", 4, false, false);
    publish_recent(&cache, &scope, &entry, b"keep");

    let path_reuse = remote_entry("other-file", "/reused.txt", "v1", 4, false, false);
    cache
        .publish_listing(
            &scope,
            "another-parent",
            &[listed(&path_reuse, "another-parent")],
            11,
        )
        .unwrap();

    assert!(matches!(
        cache.set_listed_file_policy(&scope, &entry, AvailabilityPolicy::CloudOnly),
        Err(CacheError::PolicyConflict)
    ));
    assert_eq!(
        cache.policy(&scope, &entry.id).unwrap(),
        AvailabilityPolicy::Recent
    );
    assert_eq!(cached_bytes(&cache, &scope, &entry).unwrap(), b"keep");
}

#[test]
fn listed_cloud_only_refuses_pinned_content_without_changing_pin_or_bytes() {
    let (_state, cache) = test_cache();
    let scope = test_scope(ScopeProtection::PlaintextAllowed);
    let entry = remote_entry("file-7", "/pinned.txt", "v1", 4, false, false);
    publish_recent(&cache, &scope, &entry, b"keep");
    let pin = cache
        .begin_pin(
            &scope,
            "synthetic-root",
            &[PinManifestEntry {
                parent_resource_id: "synthetic-root".into(),
                entry: entry.clone(),
            }],
        )
        .unwrap();
    assert_eq!(pin.state, PinState::Ready);

    assert!(matches!(
        cache.set_listed_file_policy(&scope, &entry, AvailabilityPolicy::CloudOnly),
        Err(CacheError::PolicyConflict)
    ));
    assert_eq!(
        cache.policy(&scope, &entry.id).unwrap(),
        AvailabilityPolicy::Recent
    );
    assert_eq!(cache.pin_info(&pin.id).unwrap(), pin);
    assert_eq!(cached_bytes(&cache, &scope, &entry).unwrap(), b"keep");
}

#[test]
fn listed_cloud_only_refuses_journaled_dirty_content_and_preserves_its_bytes() {
    let (_state, cache) = test_cache();
    let scope = test_scope(ScopeProtection::PlaintextAllowed);
    let entry = remote_entry("file-4", "/draft.txt", "base-v1", 4, false, false);
    publish_recent(&cache, &scope, &entry, b"base");
    let queued = cache
        .queue_conditional_write(
            &scope,
            ConditionalWriteRequest {
                parent_resource_id: "synthetic-root".into(),
                name: "draft.txt".into(),
                logical_path: entry.path.clone(),
                resource_id: Some(entry.id.clone()),
                base: WriteCondition::Match(entry.etag.clone()),
                expected_len: 13,
                protection: ContentProtection::Plaintext,
            },
            &mut Cursor::new(b"unsynced edit"),
        )
        .unwrap();

    assert!(matches!(
        cache.set_listed_file_policy(&scope, &entry, AvailabilityPolicy::CloudOnly),
        Err(CacheError::PolicyConflict)
    ));
    assert_eq!(
        cache.policy(&scope, &entry.id).unwrap(),
        AvailabilityPolicy::Recent
    );
    assert_eq!(cache.pending_writes(&scope).unwrap(), vec![queued.clone()]);
    assert_eq!(cached_bytes(&cache, &scope, &entry).unwrap(), b"base");
    let dirty = cache
        .open_content(&scope, &queued.content)
        .expect("the journaled edit remains readable");
    let mut bytes = Vec::new();
    dirty.take(64).read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"unsynced edit");
}

#[test]
fn listed_offline_policy_refuses_a_download_evicted_before_policy_commit() {
    let (_state, cache) = test_cache();
    let scope = test_scope(ScopeProtection::PlaintextAllowed);
    let entry = remote_entry("offline-race", "/offline.txt", "v1", 5, false, false);
    publish_recent(&cache, &scope, &entry, b"hello");
    cache.evict_recent(0).unwrap();
    assert!(matches!(
        cache.set_policy_at(
            &scope,
            &entry.id,
            &entry.path,
            &entry.etag,
            AvailabilityPolicy::AlwaysOffline
        ),
        Err(CacheError::PolicyConflict)
    ));
    assert_eq!(
        cache.policy(&scope, &entry.id).unwrap(),
        AvailabilityPolicy::Recent
    );
    assert!(matches!(
        cached_bytes(&cache, &scope, &entry),
        Err(CacheError::NotFound)
    ));
    cache
        .publish_content(
            &scope,
            &ContentVersion {
                resource_id: entry.id.clone(),
                etag: entry.etag.clone(),
                protection: ContentProtection::Plaintext,
            },
            &mut Cursor::new(b"hello"),
            5,
            Retention::Recent,
        )
        .unwrap();
    cache
        .set_policy_at(
            &scope,
            &entry.id,
            &entry.path,
            &entry.etag,
            AvailabilityPolicy::AlwaysOffline,
        )
        .unwrap();
    cache.evict_recent(0).unwrap();
    assert_eq!(
        cache.policy(&scope, &entry.id).unwrap(),
        AvailabilityPolicy::AlwaysOffline
    );
    assert_eq!(cached_bytes(&cache, &scope, &entry).unwrap(), b"hello");
}

#[test]
fn listed_offline_policy_refuses_cached_bytes_with_a_different_listed_size() {
    let (_state, cache) = test_cache();
    let scope = test_scope(ScopeProtection::PlaintextAllowed);
    let mut entry = remote_entry("offline-size", "/sized.txt", "v1", 5, false, false);
    publish_recent(&cache, &scope, &entry, b"hello");
    entry.size = 7;
    cache
        .publish_listing(
            &scope,
            "synthetic-root",
            &[listed(&entry, "synthetic-root")],
            11,
        )
        .unwrap();
    assert!(matches!(
        cache.set_policy_at(
            &scope,
            &entry.id,
            &entry.path,
            &entry.etag,
            AvailabilityPolicy::AlwaysOffline
        ),
        Err(CacheError::PolicyConflict)
    ));
    assert_eq!(
        cache.policy(&scope, &entry.id).unwrap(),
        AvailabilityPolicy::Recent
    );
    assert_eq!(cached_bytes(&cache, &scope, &entry).unwrap(), b"hello");
}

// Shared across native Windows and Unix cache backends.
fn invalidation_entry(
    id: &str,
    _name: &str,
    path: &str,
    etag: &str,
    size: u64,
    directory: bool,
) -> CachedEntry {
    listed(
        &remote_entry(id, path, etag, size, directory, false),
        "synthetic-root",
    )
}

#[test]
fn path_invalidation_stales_only_affected_policy_and_keeps_listing_gate() {
    let (_temp, cache) = test_cache();
    let scope = test_scope(ScopeProtection::PlaintextAllowed);
    let affected = invalidation_entry("affected", "affected.txt", "/affected.txt", "a1", 3, false);
    let sibling = invalidation_entry("sibling", "sibling.txt", "/sibling.txt", "s1", 3, false);
    cache
        .publish_listing(
            &scope,
            "synthetic-root",
            &[affected.clone(), sibling.clone()],
            1,
        )
        .unwrap();

    for (item, bytes) in [(&affected, &b"old"[..]), (&sibling, &b"sib"[..])] {
        let version = ContentVersion {
            resource_id: item.entry.id.clone(),
            etag: item.entry.etag.clone(),
            protection: ContentProtection::Plaintext,
        };
        cache
            .publish_content(
                &scope,
                &version,
                &mut Cursor::new(bytes),
                3,
                Retention::Recent,
            )
            .unwrap();
        cache
            .set_policy_at(
                &scope,
                &item.entry.id,
                &item.entry.path,
                &item.entry.etag,
                AvailabilityPolicy::AlwaysOffline,
            )
            .unwrap();
    }

    cache.invalidate_paths(&scope, &["/affected.txt"]).unwrap();
    assert_eq!(
        cache.policy_target_state(&scope, "affected").unwrap(),
        Some(TargetState::Stale)
    );
    assert_eq!(
        cache.policy_target_state(&scope, "sibling").unwrap(),
        Some(TargetState::Ready)
    );
    // The sibling's Ready policy does not substitute for the invalidated
    // complete root listing, and invalidation never deletes its bytes.
    assert_eq!(
        cache.listing(&scope, "synthetic-root"),
        Err(CacheError::IncompleteListing)
    );
    assert_eq!(cache.entry_for_path(&scope, "/sibling.txt").unwrap(), None);
    let sibling_version = ContentVersion {
        resource_id: "sibling".into(),
        etag: "s1".into(),
        protection: ContentProtection::Plaintext,
    };
    let mut retained = cache.open_content(&scope, &sibling_version).unwrap();
    let mut bytes = Vec::new();
    retained.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"sib");

    cache
        .publish_listing(&scope, "synthetic-root", &[affected, sibling], 2)
        .unwrap();
    assert_eq!(
        cache.policy_target_state(&scope, "affected").unwrap(),
        Some(TargetState::Stale)
    );
    assert_eq!(
        cache.policy_target_state(&scope, "sibling").unwrap(),
        Some(TargetState::Ready)
    );
}

#[test]
fn subtree_invalidation_stales_descendant_policy_by_path_or_listed_identity() {
    let (_temp, cache) = test_cache();
    let scope = test_scope(ScopeProtection::PlaintextAllowed);
    let directory = invalidation_entry("tree-id", "tree", "/tree", "d1", 0, true);
    let sibling = invalidation_entry("outside", "outside.txt", "/outside.txt", "o1", 3, false);
    cache
        .publish_listing(
            &scope,
            "synthetic-root",
            &[directory.clone(), sibling.clone()],
            1,
        )
        .unwrap();
    let nested = CachedEntry {
        parent_resource_id: "tree-id".into(),
        entry: RemoteEntry {
            id: "nested-id".into(),
            path: "/tree/nested.txt".into(),
            etag: "n1".into(),
            size: 3,
            directory: false,
            modified_unix: 1,
            writable: true,
            encrypted: false,
        },
    };
    cache
        .publish_listing(&scope, "tree-id", std::slice::from_ref(&nested), 2)
        .unwrap();
    for item in [&nested, &sibling] {
        let version = ContentVersion {
            resource_id: item.entry.id.clone(),
            etag: item.entry.etag.clone(),
            protection: ContentProtection::Plaintext,
        };
        cache
            .publish_content(
                &scope,
                &version,
                &mut Cursor::new(b"abc"),
                3,
                Retention::Recent,
            )
            .unwrap();
        cache
            .set_policy_at(
                &scope,
                &item.entry.id,
                &item.entry.path,
                &item.entry.etag,
                AvailabilityPolicy::AlwaysOffline,
            )
            .unwrap();
    }

    // Model a persisted policy path that lagged an alias update; invalidation
    // must still find the policy through its exact resource ID in the
    // affected complete listing, without matching a path prefix alone.
    cache
        .lock_db()
        .unwrap()
        .execute(
            "UPDATE policies SET target_path='/legacy/nested.txt' WHERE scope_key=?1 AND resource_id='nested-id'",
            [&scope.key],
        )
        .unwrap();

    cache.invalidate_paths(&scope, &["/tree"]).unwrap();
    assert_eq!(
        cache.policy_target_state(&scope, "nested-id").unwrap(),
        Some(TargetState::Stale)
    );
    assert_eq!(
        cache.policy_target_state(&scope, "outside").unwrap(),
        Some(TargetState::Ready)
    );
    assert_eq!(
        cache.listing(&scope, "tree-id"),
        Err(CacheError::IncompleteListing)
    );
    assert_eq!(
        cache.listing(&scope, "synthetic-root"),
        Err(CacheError::IncompleteListing)
    );
}

#[test]
fn root_invalidation_stales_all_ready_policies_but_preserves_other_states() {
    let (_temp, cache) = test_cache();
    let scope = test_scope(ScopeProtection::PlaintextAllowed);
    let ready = invalidation_entry("ready", "ready.txt", "/ready.txt", "r1", 3, false);
    let stale = invalidation_entry("stale", "stale.txt", "/stale.txt", "s1", 3, false);
    let unavailable = invalidation_entry(
        "unavailable",
        "unavailable.txt",
        "/unavailable.txt",
        "u1",
        3,
        false,
    );
    let entries = [ready.clone(), stale.clone(), unavailable.clone()];
    cache
        .publish_listing(&scope, "synthetic-root", &entries, 1)
        .unwrap();
    for item in &entries {
        let version = ContentVersion {
            resource_id: item.entry.id.clone(),
            etag: item.entry.etag.clone(),
            protection: ContentProtection::Plaintext,
        };
        cache
            .publish_content(
                &scope,
                &version,
                &mut Cursor::new(b"abc"),
                3,
                Retention::Recent,
            )
            .unwrap();
        cache
            .set_policy_at(
                &scope,
                &item.entry.id,
                &item.entry.path,
                &item.entry.etag,
                AvailabilityPolicy::AlwaysOffline,
            )
            .unwrap();
    }
    cache
        .set_policy_refresh_state(&scope, "stale", "/stale.txt", "s1", TargetState::Stale)
        .unwrap();
    cache
        .set_policy_refresh_state(
            &scope,
            "unavailable",
            "/unavailable.txt",
            "u1",
            TargetState::Unavailable,
        )
        .unwrap();

    cache.invalidate_paths(&scope, &["/"]).unwrap();
    for (id, expected) in [
        ("ready", TargetState::Stale),
        ("stale", TargetState::Stale),
        ("unavailable", TargetState::Unavailable),
    ] {
        assert_eq!(
            cache.policy_target_state(&scope, id).unwrap(),
            Some(expected)
        );
    }
    assert_eq!(
        cache.listing(&scope, "synthetic-root"),
        Err(CacheError::IncompleteListing)
    );
}

#[test]
fn content_publish_rechecks_complete_listing_and_preserves_dirty_bytes() {
    for invalidate in [false, true] {
        let (_temp, cache) = test_cache();
        let scope = test_scope(ScopeProtection::PlaintextAllowed);
        let dirty_entry = remote_entry("dirty", "/dirty.txt", "d1", 4, false, false);
        let incoming_entry = remote_entry("incoming", "/incoming.txt", "v1", 3, false, false);
        cache
            .publish_listing(
                &scope,
                "synthetic-root",
                &[
                    listed(&dirty_entry, "synthetic-root"),
                    listed(&incoming_entry, "synthetic-root"),
                ],
                10,
            )
            .unwrap();

        let dirty_version = ContentVersion {
            resource_id: dirty_entry.id.clone(),
            etag: dirty_entry.etag.clone(),
            protection: ContentProtection::Plaintext,
        };
        cache
            .publish_content(
                &scope,
                &dirty_version,
                &mut Cursor::new(b"keep"),
                4,
                Retention::Dirty,
            )
            .unwrap();

        let incoming_version = ContentVersion {
            resource_id: incoming_entry.id.clone(),
            etag: incoming_entry.etag.clone(),
            protection: ContentProtection::Plaintext,
        };
        let result = cache.publish_content_internal_with_hook(
            &scope,
            &incoming_version,
            &mut Cursor::new(b"new"),
            3,
            ContentPublishOptions {
                retention: Retention::Recent,
                recent_budget: false,
                require_listed: true,
                expected_ciphertext_epoch: None,
                pin_build: None,
                ciphertext_write: None,
            },
            || {
                if invalidate {
                    cache.invalidate_paths(&scope, &["/incoming.txt"]).unwrap();
                } else {
                    let changed_entry =
                        remote_entry("incoming", "/incoming.txt", "v2", 3, false, false);
                    cache
                        .publish_listing(
                            &scope,
                            "synthetic-root",
                            &[
                                listed(&dirty_entry, "synthetic-root"),
                                listed(&changed_entry, "synthetic-root"),
                            ],
                            11,
                        )
                        .unwrap();
                }
            },
        );

        assert!(matches!(result, Err(CacheError::Conflict)));
        assert!(matches!(
            cache.content_record(&scope, &incoming_version),
            Err(CacheError::NotFound)
        ));
        assert_eq!(
            cache
                .content_record(&scope, &dirty_version)
                .unwrap()
                .retention,
            Retention::Dirty
        );
        assert_eq!(cached_bytes(&cache, &scope, &dirty_entry).unwrap(), b"keep");
    }
}
