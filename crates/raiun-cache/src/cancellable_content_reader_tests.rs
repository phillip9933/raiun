use super::*;
use std::io::{Cursor, Read, Write};

#[cfg(windows)]
const FIRST_CHUNK_CANCELLATION_CHECK: usize = 4;
#[cfg(not(windows))]
const FIRST_CHUNK_CANCELLATION_CHECK: usize = 3;

fn scope() -> CacheScope {
    CacheScope::new(
        "https://cloud.example.test/",
        "cancellable-reader-account",
        "cancellable-reader-space",
        "cancellable-reader-root",
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

fn cache() -> (tempfile::TempDir, Cache) {
    let state = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    set_private_dir(state.path()).unwrap();
    let cache = Cache::open(state.path(), 1024 * 1024).unwrap();
    (state, cache)
}

fn publish_listing(cache: &Cache, scope: &CacheScope, entries: &[RemoteEntry]) {
    cache
        .publish_listing(
            scope,
            "cancellable-reader-root",
            &entries
                .iter()
                .map(|entry| CachedEntry {
                    parent_resource_id: "cancellable-reader-root".into(),
                    entry: entry.clone(),
                })
                .collect::<Vec<_>>(),
            1,
        )
        .unwrap();
}

fn publish_content(cache: &Cache, scope: &CacheScope, entry: &RemoteEntry, retention: Retention) {
    let bytes = body();
    cache
        .publish_content(
            scope,
            &version(entry),
            &mut Cursor::new(&bytes),
            entry.size,
            retention,
        )
        .unwrap();
}

fn body() -> Vec<u8> {
    (0_usize..(128 * 1024 + 37))
        .map(|index| (index.wrapping_mul(31) % 251) as u8)
        .collect()
}

fn read_content(cache: &Cache, scope: &CacheScope, entry: &RemoteEntry) -> Vec<u8> {
    let mut reader = cache.open_content(scope, &version(entry)).unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    bytes
}

fn blob_path(cache: &Cache, scope: &CacheScope, entry: &RemoteEntry) -> std::path::PathBuf {
    cache
        .inner
        .content_dir
        .join(format!("{}.blob", content_key(scope, &version(entry))))
}

#[cfg(windows)]
fn staged_reservations(cache: &Cache) -> usize {
    std::fs::read_dir(&cache.inner.content_dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|item| item.file_name().to_string_lossy().starts_with(".stage-v1-"))
        .count()
}

#[test]
fn precancelled_open_preserves_dirty_and_recovery_content() {
    let (_state, cache) = cache();
    let scope = scope();
    let dirty = entry("dirty-reader", "/dirty.bin", "dirty-etag", &body());
    let recovery = entry("recovery-reader", "/recovery.bin", "recovery-etag", &body());
    publish_listing(&cache, &scope, &[dirty.clone(), recovery.clone()]);
    publish_content(&cache, &scope, &dirty, Retention::Dirty);
    publish_content(&cache, &scope, &recovery, Retention::Recovery);

    for (remote, retention) in [(&dirty, Retention::Dirty), (&recovery, Retention::Recovery)] {
        assert!(matches!(
            cache.open_content_cancellable(&scope, &version(remote), || true),
            Err(CacheError::Cancelled)
        ));
        let record = cache.content_record(&scope, &version(remote)).unwrap();
        assert_eq!(record.retention, retention);
        assert_eq!(read_content(&cache, &scope, remote), body());
    }
}

#[test]
fn midread_cancel_after_first_64k_preserves_index_and_dirty_bytes() {
    let (_state, cache) = cache();
    let scope = scope();
    let bytes = body();
    let remote = entry("midread-reader", "/midread.bin", "midread-etag", &bytes);
    publish_listing(&cache, &scope, std::slice::from_ref(&remote));
    cache
        .publish_content(
            &scope,
            &version(&remote),
            &mut Cursor::new(&bytes),
            remote.size,
            Retention::Dirty,
        )
        .unwrap();
    let checks = std::sync::atomic::AtomicUsize::new(0);

    assert!(matches!(
        cache.open_content_cancellable(&scope, &version(&remote), || {
            checks.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1
                >= FIRST_CHUNK_CANCELLATION_CHECK
        }),
        Err(CacheError::Cancelled)
    ));
    assert!(checks.load(std::sync::atomic::Ordering::SeqCst) >= FIRST_CHUNK_CANCELLATION_CHECK);
    assert_eq!(
        cache
            .content_record(&scope, &version(&remote))
            .unwrap()
            .retention,
        Retention::Dirty
    );
    assert_eq!(read_content(&cache, &scope, &remote), bytes);
}

#[test]
fn corrupt_tail_is_rejected_before_any_reader_is_returned() {
    let (_state, cache) = cache();
    let scope = scope();
    let bytes = body();
    let remote = entry("corrupt-reader", "/corrupt.bin", "corrupt-etag", &bytes);
    publish_listing(&cache, &scope, std::slice::from_ref(&remote));
    cache
        .publish_content(
            &scope,
            &version(&remote),
            &mut Cursor::new(&bytes),
            remote.size,
            Retention::Recovery,
        )
        .unwrap();
    // Keep the original length: verification must detect a changed tail
    // digest before exposing even a reader for an unmodified prefix.
    use std::io::Seek as _;
    let mut tampered = std::fs::OpenOptions::new()
        .write(true)
        .open(blob_path(&cache, &scope, &remote))
        .unwrap();
    tampered.seek(std::io::SeekFrom::End(-1)).unwrap();
    tampered
        .write_all(&[bytes[bytes.len() - 1] ^ 0x80])
        .unwrap();
    drop(tampered);

    let result = cache.open_content_cancellable(&scope, &version(&remote), || false);
    assert!(matches!(result, Err(CacheError::Corrupt)));
    assert_eq!(
        cache
            .content_record(&scope, &version(&remote))
            .unwrap()
            .retention,
        Retention::Recovery
    );
}

#[cfg(windows)]
#[test]
fn oversized_metadata_is_rejected_before_creating_intent_or_reservation() {
    let state = tempfile::tempdir().unwrap();
    let cache = Cache::open(state.path(), 1024 * 1024).unwrap();
    let scope = scope();
    let remote = RemoteEntry {
        id: "too-large-for-quota".into(),
        path: "/too-large.bin".into(),
        etag: "large-etag".into(),
        size: (17 * 1024 * 1024) as u64,
        directory: false,
        modified_unix: 1,
        writable: true,
        encrypted: false,
    };
    publish_listing(&cache, &scope, std::slice::from_ref(&remote));

    assert!(matches!(
        cache.begin_plaintext_offline_download(&scope, &remote),
        Err(CacheError::InsufficientSpace)
    ));
    assert_eq!(cache.usage().unwrap().used_bytes, 0);
    assert_eq!(cache.policy_target_state(&scope, &remote.id).unwrap(), None);
    assert!(matches!(
        cache.content_record(&scope, &version(&remote)),
        Err(CacheError::NotFound)
    ));
    assert_eq!(staged_reservations(&cache), 0);
}
