use super::*;
use std::io::{Cursor, Read};

fn scope() -> CacheScope {
    CacheScope::new(
        "https://cloud.example.test/",
        "cached-promotion-account",
        "cached-promotion-space",
        "cached-promotion-root",
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

fn publish_listing(cache: &Cache, scope: &CacheScope, entry: &RemoteEntry, generation: i64) {
    cache
        .publish_listing(
            scope,
            "cached-promotion-root",
            &[CachedEntry {
                parent_resource_id: "cached-promotion-root".into(),
                entry: entry.clone(),
            }],
            generation,
        )
        .unwrap();
}

fn version(entry: &RemoteEntry) -> ContentVersion {
    ContentVersion {
        resource_id: entry.id.clone(),
        etag: entry.etag.clone(),
        protection: ContentProtection::Plaintext,
    }
}

fn blobs(cache: &Cache) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(cache.inner.windows_content.directory.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "blob")
        })
        .collect()
}

fn stages(cache: &Cache) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(cache.inner.windows_content.directory.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with(".stage-v1-"))
        })
        .collect()
}

fn publish_content(
    cache: &Cache,
    scope: &CacheScope,
    entry: &RemoteEntry,
    bytes: &[u8],
    retention: Retention,
) -> ContentRecord {
    cache
        .publish_content(
            scope,
            &version(entry),
            &mut Cursor::new(bytes),
            entry.size,
            retention,
        )
        .unwrap()
}

fn read_content(cache: &Cache, scope: &CacheScope, entry: &RemoteEntry) -> Vec<u8> {
    let mut reader = cache.open_content(scope, &version(entry)).unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    bytes
}

#[test]
fn indexed_recent_version_is_promoted_without_a_new_stage_or_blob() {
    let (_state, cache) = cache(1024);
    let scope = scope();
    let remote = entry("recent-file", "/recent.txt", "etag-a", 6);
    publish_listing(&cache, &scope, &remote, 1);
    let before = publish_content(&cache, &scope, &remote, b"recent", Retention::Recent);
    let before_blobs = blobs(&cache);
    assert_eq!(before_blobs.len(), 1);
    assert!(stages(&cache).is_empty());

    let verification = cache
        .begin_cached_plaintext_offline_verification(&scope, &remote)
        .unwrap();
    assert_eq!(blobs(&cache), before_blobs);
    assert!(stages(&cache).is_empty());
    assert_eq!(
        cache.policy_target_state(&scope, &remote.id).unwrap(),
        Some(TargetState::Stale)
    );

    let verified = verification.finish().unwrap();
    assert_eq!(blobs(&cache), before_blobs);
    assert!(stages(&cache).is_empty());
    assert_eq!(verified.commit().unwrap(), before);
    assert_eq!(blobs(&cache), before_blobs);
    assert_eq!(
        cache.policy_target_state(&scope, &remote.id).unwrap(),
        Some(TargetState::Ready)
    );
    assert_eq!(read_content(&cache, &scope, &remote), b"recent");
}

#[test]
fn protected_cached_versions_promote_without_quota_or_retention_downgrade() {
    for retention in [Retention::Dirty, Retention::Recovery] {
        let (_state, cache) = cache(1);
        let scope = scope();
        let remote = entry("dirty-file", "/dirty.txt", "etag-dirty", 5);
        publish_listing(&cache, &scope, &remote, 1);
        let before = publish_content(&cache, &scope, &remote, b"dirty", retention);
        let before_blobs = blobs(&cache);
        assert_eq!(before_blobs.len(), 1);

        let verified = cache
            .begin_cached_plaintext_offline_verification(&scope, &remote)
            .unwrap()
            .finish()
            .unwrap();
        assert_eq!(verified.commit().unwrap(), before);
        assert_eq!(blobs(&cache), before_blobs);
        assert!(stages(&cache).is_empty());
        assert_eq!(
            cache
                .content_record(&scope, &version(&remote))
                .unwrap()
                .retention,
            retention
        );
        assert_eq!(read_content(&cache, &scope, &remote), b"dirty");
    }
}

#[test]
fn recent_policy_superseding_cached_verification_refuses_ready_commit() {
    let (_state, cache) = cache(1024);
    let scope = scope();
    let remote = entry("superseded-file", "/superseded.txt", "etag-a", 4);
    publish_listing(&cache, &scope, &remote, 1);
    let before = publish_content(&cache, &scope, &remote, b"body", Retention::Recent);
    let verification = cache
        .begin_cached_plaintext_offline_verification(&scope, &remote)
        .unwrap();
    cache
        .set_policy_at(
            &scope,
            &remote.id,
            &remote.path,
            &remote.etag,
            AvailabilityPolicy::Recent,
        )
        .unwrap();

    let verified = verification.finish().unwrap();
    assert!(matches!(verified.commit(), Err(CacheError::PolicyConflict)));
    assert_eq!(
        cache.content_record(&scope, &version(&remote)).unwrap(),
        before
    );
    assert_eq!(cache.policy_target_state(&scope, &remote.id).unwrap(), None);
    assert_eq!(read_content(&cache, &scope, &remote), b"body");
}

#[test]
fn changed_metadata_refuses_cached_promotion_without_changing_the_index() {
    let (_state, cache) = cache(1024);
    let scope = scope();
    let original = entry("metadata-file", "/old.txt", "etag-a", 4);
    publish_listing(&cache, &scope, &original, 1);
    let before = publish_content(&cache, &scope, &original, b"body", Retention::Recent);
    let verification = cache
        .begin_cached_plaintext_offline_verification(&scope, &original)
        .unwrap();

    let changed = entry("metadata-file", "/new.txt", "etag-b", 4);
    publish_listing(&cache, &scope, &changed, 2);
    let verified = verification.finish().unwrap();
    assert!(matches!(verified.commit(), Err(CacheError::PolicyConflict)));
    assert_eq!(
        cache.content_record(&scope, &version(&original)).unwrap(),
        before
    );
    assert_eq!(read_content(&cache, &scope, &original), b"body");
    assert_eq!(
        cache.policy_target_state(&scope, &original.id).unwrap(),
        Some(TargetState::Stale)
    );
}

#[test]
fn corrupted_cached_blob_fails_readback_without_ready_claim() {
    let (_state, cache) = cache(1024);
    let scope = scope();
    let remote = entry("corrupt-file", "/corrupt.txt", "etag-a", 4);
    publish_listing(&cache, &scope, &remote, 1);
    let before = publish_content(&cache, &scope, &remote, b"good", Retention::Recent);
    let path = blobs(&cache).pop().unwrap();
    std::fs::write(&path, b"evil").unwrap();

    let verification = cache
        .begin_cached_plaintext_offline_verification(&scope, &remote)
        .unwrap();
    assert!(matches!(verification.finish(), Err(CacheError::Corrupt)));
    assert_eq!(
        cache.content_record(&scope, &version(&remote)).unwrap(),
        before
    );
    assert_eq!(
        cache.policy_target_state(&scope, &remote.id).unwrap(),
        Some(TargetState::Stale)
    );
    assert_eq!(std::fs::read(path).unwrap(), b"evil");
}
