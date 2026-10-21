use super::*;
use std::io::{Cursor, Read};

fn scope() -> CacheScope {
    CacheScope::new(
        "https://cloud.example.test/",
        "stage-test-account",
        "stage-test-space",
        "stage-test-root",
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

fn listed(entry: &RemoteEntry) -> CachedEntry {
    CachedEntry {
        parent_resource_id: "stage-test-root".into(),
        entry: entry.clone(),
    }
}

fn cache(quota: u64) -> (tempfile::TempDir, Cache) {
    let state = tempfile::tempdir().unwrap();
    let cache = Cache::open(state.path(), quota).unwrap();
    (state, cache)
}

fn publish_listing(cache: &Cache, scope: &CacheScope, entries: &[RemoteEntry], generation: i64) {
    let entries = entries.iter().map(listed).collect::<Vec<_>>();
    cache
        .publish_listing(scope, "stage-test-root", &entries, generation)
        .unwrap();
}

fn stage_files(cache: &Cache) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(cache.inner.windows_content.directory.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with(".stage-v1-"))
        })
        .collect()
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

fn version(entry: &RemoteEntry) -> ContentVersion {
    ContentVersion {
        resource_id: entry.id.clone(),
        etag: entry.etag.clone(),
        protection: ContentProtection::Plaintext,
    }
}

#[test]
fn verified_download_stays_unindexed_until_commit_then_becomes_ready() {
    let (_state, cache) = cache(1024);
    let scope = scope();
    let remote = entry("file-a", "/file-a.txt", "etag-a", 5);
    publish_listing(&cache, &scope, std::slice::from_ref(&remote), 1);

    let mut stage = cache
        .begin_plaintext_offline_download(&scope, &remote)
        .unwrap();
    assert_eq!(
        cache.policy_target_state(&scope, &remote.id).unwrap(),
        Some(TargetState::Stale)
    );
    stage.append(0, b"hello").unwrap();
    let verified = stage.finish().unwrap();

    assert!(matches!(
        cache.content_record(&scope, &version(&remote)),
        Err(CacheError::NotFound)
    ));
    assert_eq!(blob_files(&cache).len(), 1);
    assert_eq!(stage_files(&cache).len(), 0);

    let record = verified.commit().unwrap();
    assert_eq!(record.byte_len, 5);
    assert_eq!(record.retention, Retention::Recent);
    assert_eq!(
        cache.policy_target_state(&scope, &remote.id).unwrap(),
        Some(TargetState::Ready)
    );
    let mut reader = cache.open_content(&scope, &version(&remote)).unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"hello");
}

#[test]
fn download_commit_refuses_cloud_only_supersession() {
    let (_state, cache) = cache(1024);
    let scope = scope();
    let remote = entry("file-cloud-only", "/file-cloud-only.txt", "etag-a", 4);
    publish_listing(&cache, &scope, std::slice::from_ref(&remote), 1);
    let mut stage = cache
        .begin_plaintext_offline_download(&scope, &remote)
        .unwrap();
    stage.append(0, b"data").unwrap();
    cache
        .set_policy_at(
            &scope,
            &remote.id,
            &remote.path,
            &remote.etag,
            AvailabilityPolicy::CloudOnly,
        )
        .unwrap();
    let verified = stage.finish().unwrap();

    assert!(matches!(verified.commit(), Err(CacheError::PolicyConflict)));
    assert!(matches!(
        cache.content_record(&scope, &version(&remote)),
        Err(CacheError::NotFound)
    ));
    assert_eq!(blob_files(&cache).len(), 1, "verified orphan is preserved");
}

#[test]
fn download_commit_refuses_policy_aba_even_when_content_is_already_indexed() {
    let (_state, cache) = cache(1024);
    let scope = scope();
    let remote = entry("file-aba", "/file-aba.txt", "etag-a", 4);
    publish_listing(&cache, &scope, std::slice::from_ref(&remote), 1);
    let mut stage = cache
        .begin_plaintext_offline_download(&scope, &remote)
        .unwrap();
    stage.append(0, b"same").unwrap();

    // CloudOnly -> Recent -> AlwaysOffline returns to the same visible policy,
    // but each explicit user intent must still supersede the in-flight stage.
    cache
        .set_policy_at(
            &scope,
            &remote.id,
            &remote.path,
            &remote.etag,
            AvailabilityPolicy::CloudOnly,
        )
        .unwrap();
    let existing = version(&remote);
    cache
        .publish_content(
            &scope,
            &existing,
            &mut Cursor::new(b"same"),
            4,
            Retention::Dirty,
        )
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
    cache
        .set_policy_at(
            &scope,
            &remote.id,
            &remote.path,
            &remote.etag,
            AvailabilityPolicy::AlwaysOffline,
        )
        .unwrap();
    let before = cache.content_record(&scope, &existing).unwrap();
    let verified = stage.finish().unwrap();

    assert!(matches!(verified.commit(), Err(CacheError::PolicyConflict)));
    assert_eq!(cache.content_record(&scope, &existing).unwrap(), before);
    assert_eq!(
        cache.policy_target_state(&scope, &remote.id).unwrap(),
        Some(TargetState::Ready)
    );
}

#[test]
fn download_commit_refuses_changed_metadata_and_preserves_published_bytes() {
    let (_state, cache) = cache(1024);
    let scope = scope();
    let original = entry("file-change", "/file-change.txt", "etag-a", 4);
    publish_listing(&cache, &scope, std::slice::from_ref(&original), 1);
    let mut stage = cache
        .begin_plaintext_offline_download(&scope, &original)
        .unwrap();
    stage.append(0, b"data").unwrap();
    let verified = stage.finish().unwrap();

    let changed = entry("file-change", "/renamed.txt", "etag-b", 4);
    publish_listing(&cache, &scope, std::slice::from_ref(&changed), 2);

    assert!(matches!(verified.commit(), Err(CacheError::PolicyConflict)));
    assert!(matches!(
        cache.content_record(&scope, &version(&original)),
        Err(CacheError::NotFound)
    ));
    let published = blob_files(&cache);
    assert_eq!(published.len(), 1);
    assert_eq!(std::fs::read(&published[0]).unwrap(), b"data");
}

#[test]
fn bad_offsets_short_and_long_stages_fail_without_losing_partial_bytes() {
    let (_state, cache) = cache(1024);
    let scope = scope();
    let remote = entry("file-bounds", "/file-bounds.txt", "etag-a", 4);
    publish_listing(&cache, &scope, std::slice::from_ref(&remote), 1);

    let mut wrong_offset = cache
        .begin_plaintext_offline_download(&scope, &remote)
        .unwrap();
    assert!(matches!(
        wrong_offset.append(1, b"x"),
        Err(CacheError::Conflict)
    ));
    wrong_offset.append(0, b"ab").unwrap();
    assert!(matches!(
        wrong_offset.append(1, b"x"),
        Err(CacheError::Conflict)
    ));
    assert!(matches!(wrong_offset.finish(), Err(CacheError::Corrupt)));

    let mut too_long = cache
        .begin_plaintext_offline_download(&scope, &remote)
        .unwrap();
    too_long.append(0, b"abc").unwrap();
    assert!(matches!(
        too_long.append(3, b"de"),
        Err(CacheError::LimitExceeded)
    ));
    drop(too_long);

    assert_eq!(
        cache.policy_target_state(&scope, &remote.id).unwrap(),
        Some(TargetState::Stale)
    );
    assert!(matches!(
        cache.content_record(&scope, &version(&remote)),
        Err(CacheError::NotFound)
    ));
    let mut retained = stage_files(&cache)
        .into_iter()
        .map(|path| std::fs::read(path).unwrap())
        .collect::<Vec<_>>();
    retained.sort();
    assert_eq!(retained, vec![b"ab".to_vec(), b"abc".to_vec()]);
}

#[test]
fn quota_refusal_admits_no_download_body_and_preserves_dirty_content() {
    let (_state, cache) = cache(5);
    let scope = scope();
    let dirty = entry("dirty-file", "/dirty.txt", "dirty-etag", 5);
    let incoming = entry("incoming-file", "/incoming.txt", "incoming-etag", 1);
    publish_listing(&cache, &scope, &[dirty.clone(), incoming.clone()], 1);
    let dirty_version = version(&dirty);
    cache
        .publish_content(
            &scope,
            &dirty_version,
            &mut Cursor::new(b"dirty"),
            5,
            Retention::Dirty,
        )
        .unwrap();

    assert!(matches!(
        cache.begin_plaintext_offline_download(&scope, &incoming),
        Err(CacheError::InsufficientSpace)
    ));
    assert!(stage_files(&cache).is_empty());
    assert_eq!(
        cache.policy_target_state(&scope, &incoming.id).unwrap(),
        None
    );
    let mut reader = cache.open_content(&scope, &dirty_version).unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"dirty");
    assert_eq!(
        cache
            .content_record(&scope, &dirty_version)
            .unwrap()
            .retention,
        Retention::Dirty
    );
}

#[test]
fn independent_cache_charges_live_reservation_and_database_remains_available() {
    let (state, first) = cache(10);
    let scope = scope();
    let reserved = entry("reserved-file", "/reserved.txt", "etag-a", 8);
    let rejected = entry("rejected-file", "/rejected.txt", "etag-b", 3);
    publish_listing(&first, &scope, &[reserved.clone(), rejected.clone()], 1);

    let mut stage = first
        .begin_plaintext_offline_download(&scope, &reserved)
        .unwrap();
    let first_stages = stage_files(&first);
    assert_eq!(std::fs::metadata(&first_stages[0]).unwrap().len(), 0);

    // A separate handle can open the same database while the stage writer is
    // still live. Inventory must charge all eight promised bytes before any
    // chunk arrives, without requiring the writer or a process-wide DB lock.
    let second = Cache::open(state.path(), 10).unwrap();
    assert!(matches!(
        second.begin_plaintext_offline_download(&scope, &rejected),
        Err(CacheError::InsufficientSpace)
    ));
    assert_eq!(stage_files(&second).len(), 1);
    stage.append(0, b"x").unwrap();
    drop(stage);
    let second_stages = stage_files(&second);
    assert_eq!(std::fs::read(&second_stages[0]).unwrap(), b"x");
    assert_eq!(
        second.policy_target_state(&scope, &rejected.id).unwrap(),
        None
    );
}

#[test]
fn encrypted_directory_ciphertext_scope_and_oversized_inputs_fail_before_reserving() {
    let (_state, cache) = cache(MAX_STAGED_PLAINTEXT_BYTES + 1);
    let scope = scope();
    let regular = entry("regular-file", "/regular.txt", "etag-a", 1);
    let mut encrypted = entry("encrypted-file", "/encrypted", "etag-b", 1);
    encrypted.encrypted = true;
    let mut directory = entry("directory", "/folder", "etag-c", 0);
    directory.directory = true;
    let oversized = entry(
        "oversized-file",
        "/oversized.bin",
        "etag-d",
        MAX_STAGED_PLAINTEXT_BYTES + 1,
    );
    publish_listing(
        &cache,
        &scope,
        &[regular.clone(), encrypted.clone(), directory.clone()],
        1,
    );

    assert!(matches!(
        cache.begin_plaintext_offline_download(&scope, &encrypted),
        Err(CacheError::ProtectionMismatch)
    ));
    assert!(matches!(
        cache.begin_plaintext_offline_download(&scope, &directory),
        Err(CacheError::ProtectionMismatch)
    ));
    assert!(matches!(
        // The hard metadata limit rejects before catalog lookup or allocation.
        cache.begin_plaintext_offline_download(&scope, &oversized),
        Err(CacheError::InvalidEntry)
    ));

    let ciphertext_scope = CacheScope::new(
        "https://cloud.example.test/",
        "stage-test-account",
        "stage-test-space",
        "stage-test-root",
        ScopeProtection::CiphertextOnly,
    )
    .unwrap();
    assert!(matches!(
        cache.begin_plaintext_offline_download(&ciphertext_scope, &regular),
        Err(CacheError::ProtectionMismatch)
    ));

    assert!(stage_files(&cache).is_empty());
    for rejected in [&encrypted, &directory, &oversized] {
        assert_eq!(
            cache.policy_target_state(&scope, &rejected.id).unwrap(),
            None
        );
    }
}
