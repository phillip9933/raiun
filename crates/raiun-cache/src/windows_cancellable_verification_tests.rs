use super::*;
use std::io::{Cursor, Read};

fn scope() -> CacheScope {
    CacheScope::new(
        "https://cloud.example.test/",
        "cancellable-download-account",
        "cancellable-download-space",
        "cancellable-download-root",
        ScopeProtection::PlaintextAllowed,
    )
    .unwrap()
}

fn entry(id: &str, path: &str, etag: &str, bytes: &[u8]) -> RemoteEntry {
    RemoteEntry {
        id: id.into(),
        path: path.into(),
        etag: etag.into(),
        size: bytes.len() as u64,
        directory: false,
        modified_unix: 1,
        writable: true,
        encrypted: false,
    }
}

fn version(entry: &RemoteEntry) -> ContentVersion {
    ContentVersion {
        resource_id: entry.id.clone(),
        etag: entry.etag.clone(),
        protection: ContentProtection::Plaintext,
    }
}

fn cache(quota: u64) -> (tempfile::TempDir, Cache) {
    let state = tempfile::tempdir().unwrap();
    let cache = Cache::open(state.path(), quota).unwrap();
    (state, cache)
}

fn publish_listing(cache: &Cache, scope: &CacheScope, entries: &[RemoteEntry]) {
    cache
        .publish_listing(
            scope,
            "cancellable-download-root",
            &entries
                .iter()
                .map(|entry| CachedEntry {
                    parent_resource_id: "cancellable-download-root".into(),
                    entry: entry.clone(),
                })
                .collect::<Vec<_>>(),
            1,
        )
        .unwrap();
}

fn publish_content(
    cache: &Cache,
    scope: &CacheScope,
    entry: &RemoteEntry,
    bytes: &[u8],
    retention: Retention,
) {
    cache
        .publish_content(
            scope,
            &version(entry),
            &mut Cursor::new(bytes),
            entry.size,
            retention,
        )
        .unwrap();
}

fn read_content(cache: &Cache, scope: &CacheScope, entry: &RemoteEntry) -> Vec<u8> {
    let mut reader = cache.open_content(scope, &version(entry)).unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    bytes
}

fn stage_paths(cache: &Cache) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(cache.inner.windows_content.directory.path())
        .unwrap()
        .map(|item| item.unwrap().path())
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with(".stage-v1-"))
        })
        .collect()
}

fn blob_paths(cache: &Cache) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(cache.inner.windows_content.directory.path())
        .unwrap()
        .map(|item| item.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "blob")
        })
        .collect()
}

fn large_body() -> Vec<u8> {
    (0_usize..(128 * 1024 + 37))
        .map(|index| (index.wrapping_mul(31) % 251) as u8)
        .collect()
}

fn cancel_on_fourth_check() -> (
    impl FnMut() -> bool,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
) {
    let checks = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = checks.clone();
    let callback = move || observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1 >= 4;
    (callback, checks)
}

#[test]
fn cached_precancel_preserves_dirty_and_recovery_bytes_with_stale_intents() {
    let (_state, cache) = cache(1024 * 1024);
    let scope = scope();
    let dirty_bytes = large_body();
    let recovery_bytes = large_body();
    let dirty = entry("dirty-cached", "/dirty.bin", "etag-dirty", &dirty_bytes);
    let recovery = entry(
        "recovery-cached",
        "/recovery.bin",
        "etag-recovery",
        &recovery_bytes,
    );
    publish_listing(&cache, &scope, &[dirty.clone(), recovery.clone()]);
    publish_content(&cache, &scope, &dirty, &dirty_bytes, Retention::Dirty);
    publish_content(
        &cache,
        &scope,
        &recovery,
        &recovery_bytes,
        Retention::Recovery,
    );

    for (remote, expected_retention, expected_bytes) in [
        (&dirty, Retention::Dirty, &dirty_bytes),
        (&recovery, Retention::Recovery, &recovery_bytes),
    ] {
        let verification = cache
            .begin_cached_plaintext_offline_verification(&scope, remote)
            .unwrap();
        assert!(matches!(
            verification.finish_cancellable(|| true),
            Err(CacheError::Cancelled)
        ));
        let record = cache.content_record(&scope, &version(remote)).unwrap();
        assert_eq!(record.retention, expected_retention);
        assert_eq!(read_content(&cache, &scope, remote), *expected_bytes);
        assert_eq!(
            cache.policy_target_state(&scope, &remote.id).unwrap(),
            Some(TargetState::Stale)
        );
    }
}

#[test]
fn cached_midread_cancel_preserves_indexed_bytes_and_stale_intent() {
    let (_state, cache) = cache(1024 * 1024);
    let scope = scope();
    let bytes = large_body();
    let remote = entry("cached-midread", "/cached.bin", "etag-cached", &bytes);
    publish_listing(&cache, &scope, std::slice::from_ref(&remote));
    publish_content(&cache, &scope, &remote, &bytes, Retention::Dirty);

    let verification = cache
        .begin_cached_plaintext_offline_verification(&scope, &remote)
        .unwrap();
    let (cancelled, checks) = cancel_on_fourth_check();
    assert!(matches!(
        verification.finish_cancellable(cancelled),
        Err(CacheError::Cancelled)
    ));
    assert!(checks.load(std::sync::atomic::Ordering::SeqCst) >= 4);
    assert_eq!(read_content(&cache, &scope, &remote), bytes);
    assert_eq!(
        cache
            .content_record(&scope, &version(&remote))
            .unwrap()
            .retention,
        Retention::Dirty
    );
    assert_eq!(
        cache.policy_target_state(&scope, &remote.id).unwrap(),
        Some(TargetState::Stale)
    );
}

#[test]
fn staged_precancel_keeps_its_reservation_charged_without_index_or_ready_state() {
    let (_state, cache) = cache(1024 * 1024);
    let scope = scope();
    let bytes = large_body();
    let remote = entry("stage-precancel", "/stage.bin", "etag-stage", &bytes);
    publish_listing(&cache, &scope, std::slice::from_ref(&remote));
    let mut stage = cache
        .begin_plaintext_offline_download(&scope, &remote)
        .unwrap();
    stage.append(0, &bytes).unwrap();
    let usage_before = cache.usage().unwrap().used_bytes;
    assert_eq!(stage_paths(&cache).len(), 1);

    assert!(matches!(
        stage.finish_cancellable(|| true),
        Err(CacheError::Cancelled)
    ));
    assert_eq!(stage_paths(&cache).len(), 1);
    assert!(blob_paths(&cache).is_empty());
    assert!(matches!(
        cache.content_record(&scope, &version(&remote)),
        Err(CacheError::NotFound)
    ));
    assert_eq!(cache.usage().unwrap().used_bytes, usage_before);
    assert_eq!(
        cache.policy_target_state(&scope, &remote.id).unwrap(),
        Some(TargetState::Stale)
    );
}

#[test]
fn staged_midread_cancel_preserves_published_unindexed_blob_and_quota_charge() {
    let (_state, cache) = cache(1024 * 1024);
    let scope = scope();
    let bytes = large_body();
    let remote = entry(
        "stage-midread",
        "/stage-midread.bin",
        "etag-stage-midread",
        &bytes,
    );
    publish_listing(&cache, &scope, std::slice::from_ref(&remote));
    let mut stage = cache
        .begin_plaintext_offline_download(&scope, &remote)
        .unwrap();
    stage.append(0, &bytes).unwrap();
    let (cancelled, checks) = cancel_on_fourth_check();

    assert!(matches!(
        stage.finish_cancellable(cancelled),
        Err(CacheError::Cancelled)
    ));
    assert!(checks.load(std::sync::atomic::Ordering::SeqCst) >= 4);
    assert!(stage_paths(&cache).is_empty());
    let blobs = blob_paths(&cache);
    assert_eq!(blobs.len(), 1);
    assert_eq!(std::fs::read(&blobs[0]).unwrap(), bytes);
    assert!(matches!(
        cache.content_record(&scope, &version(&remote)),
        Err(CacheError::NotFound)
    ));
    assert!(cache.usage().unwrap().used_bytes >= bytes.len() as u64);
    assert_eq!(
        cache.policy_target_state(&scope, &remote.id).unwrap(),
        Some(TargetState::Stale)
    );
}

#[test]
fn uncancelled_staged_verification_commits_matching_bytes_ready() {
    let (_state, cache) = cache(1024 * 1024);
    let scope = scope();
    let bytes = large_body();
    let remote = entry(
        "stage-success",
        "/stage-success.bin",
        "etag-success",
        &bytes,
    );
    publish_listing(&cache, &scope, std::slice::from_ref(&remote));
    let mut stage = cache
        .begin_plaintext_offline_download(&scope, &remote)
        .unwrap();
    stage.append(0, &bytes).unwrap();
    let verified = stage.finish_cancellable(|| false).unwrap();
    let record = verified.commit().unwrap();

    assert_eq!(record.byte_len, bytes.len() as u64);
    assert_eq!(read_content(&cache, &scope, &remote), bytes);
    assert_eq!(
        cache.policy_target_state(&scope, &remote.id).unwrap(),
        Some(TargetState::Ready)
    );
    assert!(stage_paths(&cache).is_empty());
    assert_eq!(blob_paths(&cache).len(), 1);
}
