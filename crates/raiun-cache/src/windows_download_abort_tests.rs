use super::*;
use std::io::{Cursor, Read};

fn scope() -> CacheScope {
    CacheScope::new(
        "https://cloud.example.test/",
        "download-abort-account",
        "download-abort-space",
        "download-abort-root",
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
    cache
        .publish_listing(
            scope,
            "download-abort-root",
            &entries
                .iter()
                .map(|entry| CachedEntry {
                    parent_resource_id: "download-abort-root".into(),
                    entry: entry.clone(),
                })
                .collect::<Vec<_>>(),
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

fn stage_files(cache: &Cache) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(cache.inner.windows_content.directory.path())
        .unwrap()
        .map(|item| item.unwrap().path())
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with(".stage-v1-"))
        })
        .collect()
}

fn blob_files(cache: &Cache) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(cache.inner.windows_content.directory.path())
        .unwrap()
        .map(|item| item.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "blob")
        })
        .collect()
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

#[test]
fn abort_before_first_chunk_releases_reservation_and_quota_without_ready_content() {
    let (_state, cache) = cache(8);
    let scope = scope();
    let first = entry("abort-first", "/first.bin", "etag-first", 8);
    let second = entry("abort-second", "/second.bin", "etag-second", 8);
    publish_listing(&cache, &scope, &[first.clone(), second.clone()], 1);

    let stage = cache
        .begin_plaintext_offline_download(&scope, &first)
        .unwrap();
    assert_eq!(stage_files(&cache).len(), 1);
    assert_eq!(std::fs::metadata(&stage_files(&cache)[0]).unwrap().len(), 0);
    stage.abort().unwrap();

    assert!(stage_files(&cache).is_empty());
    assert!(blob_files(&cache).is_empty());
    assert!(matches!(
        cache.content_record(&scope, &version(&first)),
        Err(CacheError::NotFound)
    ));
    assert_eq!(
        cache.policy_target_state(&scope, &first.id).unwrap(),
        Some(TargetState::Stale)
    );

    // The explicit abort releases its promised bytes for a later reservation.
    let second_stage = cache
        .begin_plaintext_offline_download(&scope, &second)
        .unwrap();
    assert_eq!(stage_files(&cache).len(), 1);
    second_stage.abort().unwrap();
    assert!(stage_files(&cache).is_empty());
}

#[test]
fn explicit_abort_keeps_the_intent_stale_and_never_claims_ready() {
    let (_state, cache) = cache(16);
    let scope = scope();
    let remote = entry("aborted-intent", "/aborted.bin", "etag-a", 8);
    publish_listing(&cache, &scope, std::slice::from_ref(&remote), 1);

    let mut stage = cache
        .begin_plaintext_offline_download(&scope, &remote)
        .unwrap();
    stage.append(0, b"partial").unwrap();
    stage.abort().unwrap();

    assert_eq!(
        cache.policy_target_state(&scope, &remote.id).unwrap(),
        Some(TargetState::Stale)
    );
    assert!(matches!(
        cache.content_record(&scope, &version(&remote)),
        Err(CacheError::NotFound)
    ));
    assert!(stage_files(&cache).is_empty());
    assert!(blob_files(&cache).is_empty());
}

#[test]
fn mid_body_abort_removes_only_its_stage_and_preserves_dirty_and_recovery_blobs() {
    let (_state, cache) = cache(64);
    let scope = scope();
    let dirty = entry("dirty", "/dirty.txt", "dirty-etag", 5);
    let recovery = entry("recovery", "/recovery.txt", "recovery-etag", 8);
    let incoming = entry("incoming", "/incoming.txt", "incoming-etag", 12);
    publish_listing(
        &cache,
        &scope,
        &[dirty.clone(), recovery.clone(), incoming.clone()],
        1,
    );
    publish_content(&cache, &scope, &dirty, b"dirty", Retention::Dirty);
    publish_content(&cache, &scope, &recovery, b"recovery", Retention::Recovery);
    let protected_blobs = blob_files(&cache);
    assert_eq!(protected_blobs.len(), 2);

    let mut stage = cache
        .begin_plaintext_offline_download(&scope, &incoming)
        .unwrap();
    stage.append(0, b"partial").unwrap();
    assert_eq!(stage_files(&cache).len(), 1);
    stage.abort().unwrap();

    assert!(stage_files(&cache).is_empty());
    assert_eq!(blob_files(&cache), protected_blobs);
    assert_eq!(read_content(&cache, &scope, &dirty), b"dirty");
    assert_eq!(read_content(&cache, &scope, &recovery), b"recovery");
    assert_eq!(
        cache
            .content_record(&scope, &version(&dirty))
            .unwrap()
            .retention,
        Retention::Dirty
    );
    assert_eq!(
        cache
            .content_record(&scope, &version(&recovery))
            .unwrap()
            .retention,
        Retention::Recovery
    );
    assert!(matches!(
        cache.content_record(&scope, &version(&incoming)),
        Err(CacheError::NotFound)
    ));
}

#[test]
fn aborting_one_of_two_concurrent_stages_preserves_the_other_stage_and_body() {
    let (_state, cache) = cache(32);
    let scope = scope();
    let first = entry("concurrent-first", "/first.bin", "etag-first", 10);
    let second = entry("concurrent-second", "/second.bin", "etag-second", 10);
    publish_listing(&cache, &scope, &[first.clone(), second.clone()], 1);

    let mut first_stage = cache
        .begin_plaintext_offline_download(&scope, &first)
        .unwrap();
    let mut second_stage = cache
        .begin_plaintext_offline_download(&scope, &second)
        .unwrap();
    first_stage.append(0, b"first-body").unwrap();
    second_stage.append(0, b"keep-this").unwrap();
    first_stage.abort().unwrap();

    let remaining = stage_files(&cache);
    assert_eq!(remaining.len(), 1);
    assert_eq!(std::fs::read(&remaining[0]).unwrap(), b"keep-this");
    assert!(blob_files(&cache).is_empty());
    assert_eq!(
        cache.policy_target_state(&scope, &second.id).unwrap(),
        Some(TargetState::Stale)
    );
    second_stage.abort().unwrap();
    assert!(stage_files(&cache).is_empty());
}

#[test]
fn dropping_without_explicit_abort_preserves_uncertain_stage_bytes() {
    let (_state, cache) = cache(32);
    let scope = scope();
    let remote = entry("uncertain", "/uncertain.bin", "etag-a", 12);
    publish_listing(&cache, &scope, std::slice::from_ref(&remote), 1);

    let mut stage = cache
        .begin_plaintext_offline_download(&scope, &remote)
        .unwrap();
    stage.append(0, b"partial-body").unwrap();
    drop(stage);

    let retained = stage_files(&cache);
    assert_eq!(retained.len(), 1);
    assert_eq!(std::fs::read(&retained[0]).unwrap(), b"partial-body");
    assert!(blob_files(&cache).is_empty());
    assert!(matches!(
        cache.content_record(&scope, &version(&remote)),
        Err(CacheError::NotFound)
    ));
    assert_eq!(
        cache.policy_target_state(&scope, &remote.id).unwrap(),
        Some(TargetState::Stale)
    );
}

#[test]
fn failed_commit_after_finish_preserves_the_verified_blob() {
    let (_state, cache) = cache(32);
    let scope = scope();
    let original = entry("changed", "/original.txt", "etag-a", 4);
    publish_listing(&cache, &scope, std::slice::from_ref(&original), 1);

    let mut stage = cache
        .begin_plaintext_offline_download(&scope, &original)
        .unwrap();
    stage.append(0, b"body").unwrap();
    let verified = stage.finish().unwrap();
    assert!(stage_files(&cache).is_empty());
    let published = blob_files(&cache);
    assert_eq!(published.len(), 1);
    assert_eq!(std::fs::read(&published[0]).unwrap(), b"body");

    let changed = entry("changed", "/renamed.txt", "etag-b", 4);
    publish_listing(&cache, &scope, std::slice::from_ref(&changed), 2);
    assert!(matches!(verified.commit(), Err(CacheError::PolicyConflict)));

    assert_eq!(blob_files(&cache), published);
    assert_eq!(std::fs::read(&published[0]).unwrap(), b"body");
    assert!(matches!(
        cache.content_record(&scope, &version(&original)),
        Err(CacheError::NotFound)
    ));
    assert_eq!(
        cache.policy_target_state(&scope, &original.id).unwrap(),
        Some(TargetState::Stale)
    );
}
