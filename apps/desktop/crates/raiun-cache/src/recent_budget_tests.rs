use super::*;
use std::io::{self, Cursor, Read};
use std::sync::{Arc, Barrier};

fn test_scope(protection: ScopeProtection) -> CacheScope {
    CacheScope::new(
        "https://recent-budget.example.test/",
        "synthetic-account",
        "synthetic-space",
        "synthetic-root",
        protection,
    )
    .unwrap()
}

fn test_cache_with_quota(quota: u64) -> (tempfile::TempDir, Cache) {
    let state = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    set_private_dir(state.path()).unwrap();
    let cache = Cache::open(state.path(), quota).unwrap();
    (state, cache)
}

fn entry(id: &str, path: &str, etag: &str, bytes: &[u8]) -> RemoteEntry {
    RemoteEntry {
        id: id.into(),
        path: path.into(),
        directory: false,
        size: bytes.len() as u64,
        etag: etag.into(),
        modified_unix: 1,
        writable: true,
        encrypted: false,
    }
}

fn listed(entry: &RemoteEntry) -> CachedEntry {
    CachedEntry {
        parent_resource_id: "synthetic-root".into(),
        entry: entry.clone(),
    }
}

fn publish_listing(cache: &Cache, scope: &CacheScope, entries: &[RemoteEntry]) {
    let listed = entries.iter().map(listed).collect::<Vec<_>>();
    cache
        .publish_listing(scope, "synthetic-root", &listed, 10)
        .unwrap();
}

fn version(entry: &RemoteEntry, protection: ContentProtection) -> ContentVersion {
    ContentVersion {
        resource_id: entry.id.clone(),
        etag: entry.etag.clone(),
        protection,
    }
}

fn read_content(cache: &Cache, scope: &CacheScope, item: &RemoteEntry) -> Vec<u8> {
    let mut reader = cache
        .open_content(scope, &version(item, ContentProtection::Plaintext))
        .unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    bytes
}

#[derive(Default)]
struct CountedReader {
    bytes: Cursor<Vec<u8>>,
    consumed: Arc<std::sync::atomic::AtomicUsize>,
}

impl CountedReader {
    fn new(bytes: &[u8]) -> (Self, Arc<std::sync::atomic::AtomicUsize>) {
        let consumed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        (
            Self {
                bytes: Cursor::new(bytes.to_vec()),
                consumed: Arc::clone(&consumed),
            },
            consumed,
        )
    }
}

impl Read for CountedReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let read = self.bytes.read(output)?;
        self.consumed
            .fetch_add(read, std::sync::atomic::Ordering::SeqCst);
        Ok(read)
    }
}

#[test]
fn budget_refusal_happens_before_reading_source() {
    let (_state, cache) = test_cache_with_quota(4);
    let scope = test_scope(ScopeProtection::PlaintextAllowed);
    let existing = entry("existing", "/existing.txt", "v1", b"full");
    let incoming = entry("incoming", "/incoming.txt", "v1", b"new!");
    publish_listing(&cache, &scope, &[existing.clone(), incoming.clone()]);
    cache
        .publish_recent_content_with_budget(
            &scope,
            &version(&existing, ContentProtection::Plaintext),
            &mut Cursor::new(b"full"),
            4,
        )
        .unwrap();

    let (mut source, consumed) = CountedReader::new(b"new!");
    assert!(matches!(
        cache.publish_recent_content_with_budget(
            &scope,
            &version(&incoming, ContentProtection::Plaintext),
            &mut source,
            4,
        ),
        Err(CacheError::InsufficientSpace)
    ));
    assert_eq!(consumed.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(matches!(
        cache.content_record(&scope, &version(&incoming, ContentProtection::Plaintext)),
        Err(CacheError::NotFound)
    ));
    assert_eq!(read_content(&cache, &scope, &existing), b"full");
}

#[test]
fn concurrent_cache_handles_cannot_admit_more_than_the_shared_quota() {
    let (state, first) = test_cache_with_quota(5);
    let second = Cache::open(state.path(), 5).unwrap();
    let scope = test_scope(ScopeProtection::PlaintextAllowed);
    let left = entry("left", "/left.txt", "v1", b"four");
    let right = entry("right", "/right.txt", "v1", b"also");
    publish_listing(&first, &scope, &[left.clone(), right.clone()]);

    let barrier = Arc::new(Barrier::new(3));
    let left_barrier = Arc::clone(&barrier);
    let left_scope = scope.clone();
    let left_thread = std::thread::spawn(move || {
        left_barrier.wait();
        first.publish_recent_content_with_budget(
            &left_scope,
            &version(&left, ContentProtection::Plaintext),
            &mut Cursor::new(b"four"),
            4,
        )
    });
    let right_barrier = Arc::clone(&barrier);
    let right_scope = scope.clone();
    let right_thread = std::thread::spawn(move || {
        right_barrier.wait();
        second.publish_recent_content_with_budget(
            &right_scope,
            &version(&right, ContentProtection::Plaintext),
            &mut Cursor::new(b"also"),
            4,
        )
    });
    barrier.wait();

    let results = [left_thread.join().unwrap(), right_thread.join().unwrap()];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| {
                matches!(
                    result,
                    Err(CacheError::InsufficientSpace | CacheError::Conflict)
                )
            })
            .count(),
        1,
        "the loser must be refused by either quota admission or lock contention"
    );
    // Query through the original path while both independent handles have
    // completed, proving the shared on-disk budget result.
    let reopened = Cache::open(state.path(), 5).unwrap();
    assert_eq!(reopened.usage().unwrap().used_bytes, 4);
}

#[test]
fn budget_refusal_preserves_dirty_and_recovery_records() {
    let (_state, cache) = test_cache_with_quota(1);
    let scope = test_scope(ScopeProtection::PlaintextAllowed);
    let dirty = entry("dirty", "/dirty.txt", "d1", b"edit");
    let recovery = entry("recovery", "/recovery.txt", "r1", b"save");
    let incoming = entry("incoming", "/incoming.txt", "v1", b"new");
    publish_listing(
        &cache,
        &scope,
        &[dirty.clone(), recovery.clone(), incoming.clone()],
    );
    cache
        .publish_content(
            &scope,
            &version(&dirty, ContentProtection::Plaintext),
            &mut Cursor::new(b"edit"),
            4,
            Retention::Dirty,
        )
        .unwrap();
    cache
        .publish_content(
            &scope,
            &version(&recovery, ContentProtection::Plaintext),
            &mut Cursor::new(b"save"),
            4,
            Retention::Recovery,
        )
        .unwrap();

    assert!(matches!(
        cache.publish_recent_content_with_budget(
            &scope,
            &version(&incoming, ContentProtection::Plaintext),
            &mut Cursor::new(b"new"),
            3,
        ),
        Err(CacheError::InsufficientSpace)
    ));
    assert_eq!(
        cache
            .content_record(&scope, &version(&dirty, ContentProtection::Plaintext))
            .unwrap()
            .retention,
        Retention::Dirty
    );
    assert_eq!(
        cache
            .content_record(&scope, &version(&recovery, ContentProtection::Plaintext))
            .unwrap()
            .retention,
        Retention::Recovery
    );
    assert_eq!(read_content(&cache, &scope, &dirty), b"edit");
    assert_eq!(read_content(&cache, &scope, &recovery), b"save");
}

#[test]
fn indexed_version_is_reused_without_additional_quota_even_when_over_budget() {
    let (_state, cache) = test_cache_with_quota(4);
    let scope = test_scope(ScopeProtection::PlaintextAllowed);
    let item = entry("cached", "/cached.txt", "v1", b"keep");
    let extra_dirty = entry("dirty", "/dirty.txt", "d1", b"more");
    publish_listing(&cache, &scope, &[item.clone(), extra_dirty.clone()]);
    cache
        .publish_recent_content_with_budget(
            &scope,
            &version(&item, ContentProtection::Plaintext),
            &mut Cursor::new(b"keep"),
            4,
        )
        .unwrap();
    cache
        .publish_content(
            &scope,
            &version(&extra_dirty, ContentProtection::Plaintext),
            &mut Cursor::new(b"more"),
            4,
            Retention::Dirty,
        )
        .unwrap();
    assert!(cache.usage().unwrap().over_quota);

    let record = cache
        .publish_recent_content_with_budget(
            &scope,
            &version(&item, ContentProtection::Plaintext),
            &mut Cursor::new(b"keep"),
            4,
        )
        .unwrap();
    assert_eq!(record.retention, Retention::Recent);
    assert_eq!(read_content(&cache, &scope, &item), b"keep");
    assert_eq!(read_content(&cache, &scope, &extra_dirty), b"more");
}

#[test]
fn budgeted_recent_publish_refuses_ciphertext_scopes_without_reading_source() {
    let (_state, cache) = test_cache_with_quota(32);
    let scope = test_scope(ScopeProtection::CiphertextOnly);
    let item = entry("cipher", "/opaque", "v1", b"opaque");
    let (mut source, consumed) = CountedReader::new(b"opaque");
    assert!(matches!(
        cache.publish_recent_content_with_budget(
            &scope,
            &version(&item, ContentProtection::Ciphertext),
            &mut source,
            6,
        ),
        Err(CacheError::ProtectionMismatch)
    ));
    assert_eq!(consumed.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[test]
fn bounded_eviction_removes_at_most_two_recent_candidates_and_keeps_dirty() {
    let (_state, cache) = test_cache_with_quota(64);
    let scope = test_scope(ScopeProtection::PlaintextAllowed);
    let recent = (0..4)
        .map(|index| {
            let bytes = [b'a' + index as u8; 2];
            (
                entry(
                    &format!("recent-{index}"),
                    &format!("/{index}.txt"),
                    "v1",
                    &bytes,
                ),
                bytes,
            )
        })
        .collect::<Vec<_>>();
    let dirty = entry("dirty", "/dirty.txt", "d1", b"keep");
    let mut all = recent
        .iter()
        .map(|(entry, _)| entry.clone())
        .collect::<Vec<_>>();
    all.push(dirty.clone());
    publish_listing(&cache, &scope, &all);

    for (item, bytes) in &recent {
        cache
            .publish_content(
                &scope,
                &version(item, ContentProtection::Plaintext),
                &mut Cursor::new(bytes),
                2,
                Retention::Recent,
            )
            .unwrap();
    }
    cache
        .publish_content(
            &scope,
            &version(&dirty, ContentProtection::Plaintext),
            &mut Cursor::new(b"keep"),
            4,
            Retention::Dirty,
        )
        .unwrap();

    let report = cache.evict_recent_bounded(0, 2).unwrap();
    assert_eq!(report.removed_bytes, 4);
    let remaining = recent
        .iter()
        .filter(|(item, _)| {
            cache
                .content_record(&scope, &version(item, ContentProtection::Plaintext))
                .is_ok()
        })
        .count();
    assert_eq!(remaining, 2);
    assert_eq!(
        cache
            .content_record(&scope, &version(&dirty, ContentProtection::Plaintext))
            .unwrap()
            .retention,
        Retention::Dirty
    );
    assert_eq!(read_content(&cache, &scope, &dirty), b"keep");
    assert!(matches!(
        cache.evict_recent_bounded(0, 0),
        Err(CacheError::LimitExceeded)
    ));
    assert!(matches!(
        cache.evict_recent_bounded(0, 65),
        Err(CacheError::LimitExceeded)
    ));
}
