use super::*;

fn state() -> tempfile::TempDir {
    let state = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    set_private_dir(state.path()).unwrap();
    state
}

#[test]
fn configured_quota_is_durable_and_shared_by_independently_opened_handles() {
    let state = state();
    let first = Cache::open(state.path(), 512 * 1024 * 1024).unwrap();
    let second = Cache::open(state.path(), 768 * 1024 * 1024).unwrap();
    assert_eq!(second.quota_bytes(), 512 * 1024 * 1024);

    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let updater = first.clone();
    let update_barrier = std::sync::Arc::clone(&barrier);
    let update = std::thread::spawn(move || {
        update_barrier.wait();
        updater
            .set_quota_bytes(384 * 1024 * 1024)
            .expect("save valid cache quota");
    });
    let observer = second.clone();
    let observe_barrier = std::sync::Arc::clone(&barrier);
    let read = std::thread::spawn(move || {
        observe_barrier.wait();
        for _ in 0..10_000 {
            if observer.quota_bytes() == 384 * 1024 * 1024 {
                return;
            }
            std::thread::yield_now();
        }
        panic!("independent handle did not observe the persisted setting");
    });
    update.join().unwrap();
    read.join().unwrap();

    assert_eq!(first.quota_bytes(), 384 * 1024 * 1024);
    assert_eq!(second.quota_bytes(), 384 * 1024 * 1024);
    assert_eq!(second.usage().unwrap().quota_bytes, 384 * 1024 * 1024);

    drop(first);
    drop(second);
    let reopened = Cache::open(state.path(), 1024 * 1024 * 1024).unwrap();
    assert_eq!(reopened.quota_bytes(), 384 * 1024 * 1024);
}

#[test]
fn quota_validation_does_not_change_the_persisted_setting() {
    let state = state();
    let cache = Cache::open(state.path(), 512 * 1024 * 1024).unwrap();
    for invalid in [
        0,
        MIN_CACHE_QUOTA_BYTES - 1,
        MAX_CONTENT_BYTES + 1,
        u64::MAX,
    ] {
        assert_eq!(
            cache.set_quota_bytes(invalid),
            Err(CacheError::LimitExceeded)
        );
        assert_eq!(cache.quota_bytes(), 512 * 1024 * 1024);
    }
}

#[test]
fn saving_limit_is_separate_from_safe_recent_eviction_and_preserves_dirty_bytes() {
    use std::io::Cursor;

    let state = state();
    let cache = Cache::open(state.path(), 4).unwrap();
    let scope = CacheScope::new(
        "https://quota.example.test/",
        "synthetic-account",
        "synthetic-space",
        "synthetic-root",
        ScopeProtection::PlaintextAllowed,
    )
    .unwrap();
    let recent = RemoteEntry {
        id: "recent-item".into(),
        path: "/recent.txt".into(),
        directory: false,
        size: 4,
        etag: "recent-v1".into(),
        modified_unix: 1,
        writable: true,
        encrypted: false,
    };
    let dirty = RemoteEntry {
        id: "dirty-item".into(),
        path: "/dirty.txt".into(),
        directory: false,
        size: 4,
        etag: "dirty-v1".into(),
        modified_unix: 1,
        writable: true,
        encrypted: false,
    };
    cache
        .publish_listing(
            &scope,
            "synthetic-root",
            &[
                CachedEntry {
                    parent_resource_id: "synthetic-root".into(),
                    entry: recent.clone(),
                },
                CachedEntry {
                    parent_resource_id: "synthetic-root".into(),
                    entry: dirty.clone(),
                },
            ],
            1,
        )
        .unwrap();
    let version = |entry: &RemoteEntry| ContentVersion {
        resource_id: entry.id.clone(),
        etag: entry.etag.clone(),
        protection: ContentProtection::Plaintext,
    };
    cache
        .publish_content(
            &scope,
            &version(&recent),
            &mut Cursor::new(b"read"),
            4,
            Retention::Recent,
        )
        .unwrap();
    cache
        .publish_content(
            &scope,
            &version(&dirty),
            &mut Cursor::new(b"edit"),
            4,
            Retention::Dirty,
        )
        .unwrap();

    cache.set_quota_bytes(MIN_CACHE_QUOTA_BYTES).unwrap();
    assert!(cache.content_record(&scope, &version(&recent)).is_ok());
    assert!(cache.content_record(&scope, &version(&dirty)).is_ok());

    let report = cache.evict_recent(0).unwrap();
    assert!(report.removed_bytes >= 4);
    assert!(matches!(
        cache.content_record(&scope, &version(&recent)),
        Err(CacheError::NotFound)
    ));
    assert_eq!(
        cache
            .content_record(&scope, &version(&dirty))
            .unwrap()
            .retention,
        Retention::Dirty
    );
}

#[test]
fn missing_quota_setting_fails_closed_for_admission_and_configured_eviction() {
    use std::io::Cursor;

    let state = state();
    let cache = Cache::open(state.path(), 1024).unwrap();
    let scope = CacheScope::new(
        "https://quota-read-error.example.test/",
        "synthetic-account",
        "synthetic-space",
        "synthetic-root",
        ScopeProtection::PlaintextAllowed,
    )
    .unwrap();
    let entry = |id: &str| RemoteEntry {
        id: id.into(),
        path: format!("/{id}.txt"),
        directory: false,
        size: 4,
        etag: "v1".into(),
        modified_unix: 1,
        writable: true,
        encrypted: false,
    };
    let recent = entry("recent");
    let incoming = entry("incoming");
    let cached = |entry: &RemoteEntry| CachedEntry {
        parent_resource_id: "synthetic-root".into(),
        entry: entry.clone(),
    };
    cache
        .publish_listing(
            &scope,
            "synthetic-root",
            &[cached(&recent), cached(&incoming)],
            1,
        )
        .unwrap();
    let version = |entry: &RemoteEntry| ContentVersion {
        resource_id: entry.id.clone(),
        etag: entry.etag.clone(),
        protection: ContentProtection::Plaintext,
    };
    cache
        .publish_recent_content_with_budget(&scope, &version(&recent), &mut Cursor::new(b"keep"), 4)
        .unwrap();

    // Simulate a stale, lower display fallback followed by an unavailable
    // durable setting. Operations must trust neither and must not evict.
    cache.inner.quota_bytes.store(0, Ordering::Release);
    cache
        .lock_db()
        .unwrap()
        .execute("DELETE FROM cache_settings WHERE setting='quota_bytes'", [])
        .unwrap();
    assert_eq!(cache.quota_bytes(), 0);
    assert!(matches!(
        cache.try_quota_bytes(),
        Err(CacheError::Database(_))
    ));
    assert!(matches!(
        cache.evict_to_quota(),
        Err(CacheError::Database(_))
    ));
    assert!(cache.content_record(&scope, &version(&recent)).is_ok());
    assert!(matches!(
        cache.publish_recent_content_with_budget(
            &scope,
            &version(&incoming),
            &mut Cursor::new(b"new!"),
            4,
        ),
        Err(CacheError::Database(_))
    ));
    assert!(matches!(
        cache.content_record(&scope, &version(&incoming)),
        Err(CacheError::NotFound)
    ));
}
