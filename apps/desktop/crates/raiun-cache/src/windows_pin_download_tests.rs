use super::*;
use std::io::{Cursor, Read};

fn scope() -> CacheScope {
    CacheScope::new(
        "https://cloud.example.test/",
        "pin-download-account",
        "pin-download-space",
        "pin-download-root",
        ScopeProtection::PlaintextAllowed,
    )
    .unwrap()
}

fn other_scope() -> CacheScope {
    CacheScope::new(
        "https://cloud.example.test/",
        "pin-download-account",
        "pin-download-space",
        "other-pin-download-root",
        ScopeProtection::PlaintextAllowed,
    )
    .unwrap()
}

fn entry(id: &str, path: &str, etag: &str, size: u64) -> RemoteEntry {
    RemoteEntry {
        id: id.into(),
        path: path.into(),
        etag: etag.into(),
        size,
        directory: false,
        modified_unix: 1,
        writable: true,
        encrypted: false,
    }
}

fn cache(quota: u64) -> (tempfile::TempDir, Cache) {
    let state = tempfile::tempdir().unwrap();
    let cache = Cache::open(state.path(), quota).unwrap();
    (state, cache)
}

fn publish_listing(cache: &Cache, scope: &CacheScope, entries: &[RemoteEntry], generation: i64) {
    let listed = entries
        .iter()
        .map(|entry| CachedEntry {
            parent_resource_id: scope.root_resource_id.clone(),
            entry: entry.clone(),
        })
        .collect::<Vec<_>>();
    cache
        .publish_listing(scope, &scope.root_resource_id, &listed, generation)
        .unwrap();
}

fn begin_pin(cache: &Cache, scope: &CacheScope, entry: &RemoteEntry) -> PinInfo {
    let pin = cache
        .begin_pin(
            scope,
            &scope.root_resource_id,
            &[PinManifestEntry {
                parent_resource_id: scope.root_resource_id.clone(),
                entry: entry.clone(),
            }],
        )
        .unwrap();
    assert_eq!(pin.state, PinState::Building);
    pin
}

fn version(entry: &RemoteEntry) -> ContentVersion {
    ContentVersion {
        resource_id: entry.id.clone(),
        etag: entry.etag.clone(),
        protection: ContentProtection::Plaintext,
    }
}

fn read_content(cache: &Cache, scope: &CacheScope, entry: &RemoteEntry) -> Vec<u8> {
    let mut reader = cache.open_content(scope, &version(entry)).unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    bytes
}

fn blob_files(cache: &Cache) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(cache.inner.windows_content.directory.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "blob")
        })
        .collect()
}

#[test]
fn pin_download_is_recent_and_eviction_waits_until_pin_is_removed() {
    let (_state, cache) = cache(128);
    let scope = scope();
    let dirty_scope = other_scope();
    let pinned = entry("pinned-file", "/pinned.txt", "pin-etag", 4);
    let dirty = entry("dirty-file", "/dirty.txt", "dirty-etag", 5);
    publish_listing(&cache, &scope, std::slice::from_ref(&pinned), 1);
    publish_listing(&cache, &dirty_scope, std::slice::from_ref(&dirty), 1);
    let pin = begin_pin(&cache, &scope, &pinned);

    let mut stage = cache
        .begin_plaintext_pin_download(&scope, &pinned, &pin.id)
        .unwrap();
    stage.append(0, b"body").unwrap();
    stage.finish().unwrap().commit().unwrap();

    let record = cache.content_record(&scope, &version(&pinned)).unwrap();
    assert_eq!(record.retention, Retention::Recent);
    assert_eq!(
        cache.policy(&scope, &pinned.id).unwrap(),
        AvailabilityPolicy::Recent
    );
    assert_eq!(
        cache.pin_info_for_scope(&scope, &pin.id).unwrap().state,
        PinState::Ready
    );

    cache
        .publish_content(
            &dirty_scope,
            &version(&dirty),
            &mut Cursor::new(b"dirty"),
            dirty.size,
            Retention::Dirty,
        )
        .unwrap();
    let while_pinned = cache.evict_recent(0).unwrap();
    assert_eq!(while_pinned.removed_bytes, 0);
    assert_eq!(read_content(&cache, &scope, &pinned), b"body");

    cache.cancel_pin_for_scope(&scope, &pin.id).unwrap();
    let after_unpin = cache.evict_recent(0).unwrap();
    assert_eq!(after_unpin.removed_bytes, pinned.size);
    assert!(matches!(
        cache.content_record(&scope, &version(&pinned)),
        Err(CacheError::NotFound)
    ));
    assert_eq!(read_content(&cache, &dirty_scope, &dirty), b"dirty");
    assert_eq!(
        cache
            .content_record(&dirty_scope, &version(&dirty))
            .unwrap()
            .retention,
        Retention::Dirty
    );
}

#[test]
fn pin_download_admission_requires_exact_scope_member_and_non_cloud_only_policy() {
    let (_state, cache) = cache(128);
    let scope = scope();
    let other_scope = other_scope();
    let remote = entry("member", "/member.txt", "etag-one", 4);
    publish_listing(&cache, &scope, std::slice::from_ref(&remote), 1);
    publish_listing(&cache, &other_scope, std::slice::from_ref(&remote), 1);
    let pin = begin_pin(&cache, &scope, &remote);

    let wrong_version = entry("member", "/member.txt", "etag-two", 4);
    assert!(matches!(
        cache.begin_plaintext_pin_download(&scope, &wrong_version, &pin.id),
        Err(CacheError::PolicyConflict)
    ));
    assert!(matches!(
        cache.begin_plaintext_pin_download(&other_scope, &remote, &pin.id),
        Err(CacheError::PolicyConflict)
    ));
    assert!(blob_files(&cache).is_empty());

    // Public CloudOnly changes correctly refuse a retained pin. Establish the
    // independent file choice first, then try acquiring a new folder member.
    cache.cancel_pin_for_scope(&scope, &pin.id).unwrap();
    cache
        .set_policy_at(
            &scope,
            &remote.id,
            &remote.path,
            &remote.etag,
            AvailabilityPolicy::CloudOnly,
        )
        .unwrap();
    let pin = begin_pin(&cache, &scope, &remote);
    assert!(matches!(
        cache.begin_plaintext_pin_download(&scope, &remote, &pin.id),
        Err(CacheError::PolicyConflict)
    ));
    assert!(blob_files(&cache).is_empty());
    assert_eq!(
        cache.policy(&scope, &remote.id).unwrap(),
        AvailabilityPolicy::CloudOnly
    );
}

#[test]
fn pin_removed_or_member_staled_before_commit_preserves_published_bytes() {
    for stale_member in [false, true] {
        let (_state, cache) = cache(128);
        let scope = scope();
        let remote = entry("member", "/member.txt", "etag-one", 4);
        publish_listing(&cache, &scope, std::slice::from_ref(&remote), 1);
        let pin = begin_pin(&cache, &scope, &remote);
        let mut stage = cache
            .begin_plaintext_pin_download(&scope, &remote, &pin.id)
            .unwrap();
        stage.append(0, b"body").unwrap();
        let verified = stage.finish().unwrap();

        if stale_member {
            cache
                .invalidate_paths(&scope, &[remote.path.as_str()])
                .unwrap();
            assert_eq!(cache.pin_info(&pin.id).unwrap().state, PinState::Stale);
        } else {
            cache.cancel_pin_for_scope(&scope, &pin.id).unwrap();
        }

        assert!(matches!(verified.commit(), Err(CacheError::PolicyConflict)));
        assert!(matches!(
            cache.content_record(&scope, &version(&remote)),
            Err(CacheError::NotFound)
        ));
        let blobs = blob_files(&cache);
        assert_eq!(blobs.len(), 1);
        assert_eq!(std::fs::read(&blobs[0]).unwrap(), b"body");
    }
}

#[test]
fn cached_pin_promotion_keeps_recent_policy_and_refuses_removed_pin() {
    let (_state, cache) = cache(128);
    let scope = scope();
    let remote = entry("cached-member", "/cached.txt", "etag-cached", 6);
    publish_listing(&cache, &scope, std::slice::from_ref(&remote), 1);
    let pin = begin_pin(&cache, &scope, &remote);
    let before = cache
        .publish_content(
            &scope,
            &version(&remote),
            &mut Cursor::new(b"cached"),
            remote.size,
            Retention::Recent,
        )
        .unwrap();
    let bytes_before = cache.usage().unwrap().used_bytes;

    let verified = cache
        .begin_cached_plaintext_pin_verification(&scope, &remote, &pin.id)
        .unwrap()
        .finish()
        .unwrap();
    let committed = verified.commit().unwrap();
    assert_eq!(committed.sha256, before.sha256);
    assert_eq!(committed.byte_len, before.byte_len);
    assert_eq!(committed.retention, Retention::Recent);
    assert_eq!(cache.usage().unwrap().used_bytes, bytes_before);
    assert_eq!(
        cache.policy(&scope, &remote.id).unwrap(),
        AvailabilityPolicy::Recent
    );
    assert_eq!(
        cache.pin_info_for_scope(&scope, &pin.id).unwrap().state,
        PinState::Ready
    );

    let verification = cache
        .begin_cached_plaintext_pin_verification(&scope, &remote, &pin.id)
        .unwrap();
    let verified = verification.finish().unwrap();
    cache.cancel_pin_for_scope(&scope, &pin.id).unwrap();
    assert!(matches!(verified.commit(), Err(CacheError::PolicyConflict)));
    let retained = cache.content_record(&scope, &version(&remote)).unwrap();
    assert_eq!(retained.sha256, before.sha256);
    assert_eq!(retained.byte_len, before.byte_len);
    assert_eq!(retained.retention, Retention::Recent);
    assert_eq!(read_content(&cache, &scope, &remote), b"cached");
    assert_eq!(
        cache.policy(&scope, &remote.id).unwrap(),
        AvailabilityPolicy::Recent
    );
}
