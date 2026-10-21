use super::*;
use std::io::{Cursor, Read};
use std::sync::atomic::{AtomicUsize, Ordering};

fn cache() -> (tempfile::TempDir, Cache) {
    let state = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    set_private_dir(state.path()).unwrap();
    let cache = Cache::open(state.path(), 16 * 1024 * 1024).unwrap();
    (state, cache)
}

fn scope() -> CacheScope {
    CacheScope::new(
        "https://pin-snapshot.example.test/",
        "snapshot-account",
        "snapshot-space",
        "snapshot-root",
        ScopeProtection::PlaintextAllowed,
    )
    .unwrap()
}

fn entry(id: &str, path: &str, etag: &str, size: usize) -> RemoteEntry {
    RemoteEntry {
        id: id.to_owned(),
        path: path.to_owned(),
        etag: etag.to_owned(),
        size: size as u64,
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

fn publish_listing(cache: &Cache, scope: &CacheScope, item: &RemoteEntry, fetched: i64) {
    cache
        .publish_listing(
            scope,
            scope.root_resource_id(),
            &[CachedEntry {
                parent_resource_id: scope.root_resource_id().to_owned(),
                entry: item.clone(),
            }],
            fetched,
        )
        .unwrap();
}

fn begin_pin(cache: &Cache, scope: &CacheScope, item: &RemoteEntry) -> PinInfo {
    cache
        .begin_pin(
            scope,
            scope.root_resource_id(),
            &[PinManifestEntry {
                parent_resource_id: scope.root_resource_id().to_owned(),
                entry: item.clone(),
            }],
        )
        .unwrap()
}

fn publish_body(
    cache: &Cache,
    scope: &CacheScope,
    item: &RemoteEntry,
    bytes: &[u8],
    retention: Retention,
) {
    assert_eq!(bytes.len() as u64, item.size);
    cache
        .publish_content(
            scope,
            &version(item),
            &mut Cursor::new(bytes),
            item.size,
            retention,
        )
        .unwrap();
}

fn read_body(cache: &Cache, scope: &CacheScope, item: &RemoteEntry) -> Vec<u8> {
    let mut reader = cache.open_content(scope, &version(item)).unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    bytes
}

type RawItem = (String, String, String, String, String, i64, i64, i64);

#[derive(Debug, PartialEq, Eq)]
struct RawPin {
    id: String,
    scope: String,
    root: String,
    path: String,
    state: i64,
    items: Vec<RawItem>,
}

fn raw_pin(cache: &Cache, pin_id: &str) -> RawPin {
    let db = cache.lock_db().unwrap();
    let (scope, root, path, state) = db
        .query_row(
            "SELECT scope_key,root_id,root_path,state FROM pins WHERE pin_id=?1",
            [pin_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .unwrap();
    let mut statement = db
        .prepare(
            "SELECT resource_id,parent_id,name,path,etag,size,directory,encrypted FROM pin_items WHERE pin_id=?1 ORDER BY resource_id",
        )
        .unwrap();
    let items = statement
        .query_map([pin_id], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
            ))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    RawPin {
        id: pin_id.to_owned(),
        scope,
        root,
        path,
        state,
        items,
    }
}

fn patterned_body(length: usize) -> Vec<u8> {
    (0..length).map(|index| (index % 251) as u8).collect()
}

#[test]
fn refresh_conflicts_with_pin_metadata_changed_during_unlocked_hash() {
    let (_state, cache) = cache();
    let scope = scope();
    let body = patterned_body(1024 * 1024);
    let item = entry("file-a", "/file-a.bin", "etag-a", body.len());
    publish_listing(&cache, &scope, &item, 1);
    let pin = begin_pin(&cache, &scope, &item);
    publish_body(&cache, &scope, &item, &body, Retention::Recent);
    let before = raw_pin(&cache, &pin.id);
    assert_eq!(before.state, 0);

    let probes = AtomicUsize::new(0);
    let mut changed_during_hash = false;
    let result = cache.refresh_pin_cancellable(&pin.id, || {
        // Callback 4 is reached after the first 64 KiB hash slice on both
        // portable and Windows readers. It must run with the DB mutex free.
        if probes.fetch_add(1, Ordering::SeqCst) == 4 {
            let db = cache
                .inner
                .db
                .try_lock()
                .expect("hash probe ran while holding the cache DB mutex");
            assert_eq!(
                db.execute(
                    "UPDATE pin_items SET name=?3,path=?4 WHERE pin_id=?1 AND resource_id=?2",
                    rusqlite::params![pin.id, item.id, "renamed.bin", "/renamed.bin"],
                )
                .unwrap(),
                1
            );
            changed_during_hash = true;
        }
        false
    });

    assert!(
        changed_during_hash,
        "the probe must run during content hashing"
    );
    assert!(matches!(result, Err(CacheError::Conflict)));
    let after = raw_pin(&cache, &pin.id);
    assert_eq!(after.state, before.state, "conflict must not publish Ready");
    assert_ne!(
        after.items, before.items,
        "the simulated writer's metadata remains"
    );
    assert_eq!(after.items[0].3, "/renamed.bin");
    assert_eq!(read_body(&cache, &scope, &item), body);
}

#[test]
fn same_etag_with_new_manifest_size_does_not_make_cached_body_ready() {
    let (_state, cache) = cache();
    let scope = scope();
    let old_body = b"the old complete body";
    let old_item = entry("file-a", "/file-a.bin", "same-etag", old_body.len());
    publish_listing(&cache, &scope, &old_item, 1);
    publish_body(&cache, &scope, &old_item, old_body, Retention::Recent);

    let current_item = entry("file-a", "/file-a.bin", "same-etag", old_body.len() + 1);
    publish_listing(&cache, &scope, &current_item, 2);
    let pin = begin_pin(&cache, &scope, &current_item);

    let refreshed = cache.refresh_pin(&pin.id).unwrap();
    assert_eq!(refreshed.state, PinState::Building);
    assert_eq!(refreshed.ready_content_count, 0);
    let old_record = cache.content_record(&scope, &version(&old_item)).unwrap();
    assert_eq!(old_record.byte_len, old_body.len() as u64);
    assert_eq!(read_body(&cache, &scope, &old_item), old_body);
}

#[test]
fn cancelling_staged_hash_preserves_both_pin_manifests_and_bytes() {
    let (_state, cache) = cache();
    let scope = scope();
    let old_body = b"old dirty bytes";
    let old_item = entry("old-file", "/old.bin", "old-etag", old_body.len());
    publish_listing(&cache, &scope, &old_item, 1);
    let active = begin_pin(&cache, &scope, &old_item);
    publish_body(&cache, &scope, &old_item, old_body, Retention::Dirty);

    let staged_body = patterned_body(1024 * 1024);
    let staged_item = entry("new-file", "/new.bin", "new-etag", staged_body.len());
    publish_listing(&cache, &scope, &staged_item, 2);
    let staged = begin_pin(&cache, &scope, &staged_item);
    publish_body(
        &cache,
        &scope,
        &staged_item,
        &staged_body,
        Retention::Recent,
    );
    let active_before = raw_pin(&cache, &active.id);
    let staged_before = raw_pin(&cache, &staged.id);
    let probes = AtomicUsize::new(0);

    let result = cache.replace_pin_snapshot_cancellable(&scope, &active.id, &staged.id, || {
        probes.fetch_add(1, Ordering::SeqCst) >= 4
    });

    assert!(matches!(result, Err(CacheError::Cancelled)));
    assert_eq!(raw_pin(&cache, &active.id), active_before);
    assert_eq!(raw_pin(&cache, &staged.id), staged_before);
    assert_eq!(read_body(&cache, &scope, &old_item), old_body);
    assert_eq!(read_body(&cache, &scope, &staged_item), staged_body);
}

#[test]
fn successful_replacement_keeps_dirty_bytes_and_pins_new_bytes_against_eviction() {
    let (_state, cache) = cache();
    let scope = scope();
    let old_body = b"dirty source snapshot";
    let old_item = entry("old-file", "/old.bin", "old-etag", old_body.len());
    publish_listing(&cache, &scope, &old_item, 1);
    let active = begin_pin(&cache, &scope, &old_item);
    publish_body(&cache, &scope, &old_item, old_body, Retention::Dirty);

    let new_body = b"new pinned content";
    let new_item = entry("new-file", "/new.bin", "new-etag", new_body.len());
    publish_listing(&cache, &scope, &new_item, 2);
    let staging = begin_pin(&cache, &scope, &new_item);
    publish_body(&cache, &scope, &new_item, new_body, Retention::Recent);

    let replaced = cache
        .replace_pin_snapshot_cancellable(&scope, &active.id, &staging.id, || false)
        .unwrap();
    assert_eq!(replaced.id, active.id);
    assert_eq!(replaced.state, PinState::Ready);
    assert!(matches!(
        cache.pin_info_for_scope(&scope, &staging.id),
        Err(CacheError::PinNotFound)
    ));
    assert_eq!(
        cache.pin_info_for_scope(&scope, &active.id).unwrap().state,
        PinState::Ready
    );

    let evicted = cache.evict_recent(0).unwrap();
    assert_eq!(evicted.removed_bytes, 0);
    assert_eq!(read_body(&cache, &scope, &old_item), old_body);
    assert_eq!(read_body(&cache, &scope, &new_item), new_body);
    assert_eq!(
        cache
            .content_record(&scope, &version(&old_item))
            .unwrap()
            .retention,
        Retention::Dirty
    );
}

#[test]
fn stale_refresh_expectation_refuses_pre_replacement_active_mutation() {
    let (_state, cache) = cache();
    let scope = scope();
    let dirty_body = b"active dirty bytes";
    let active_item = entry(
        "active-file",
        "/active.bin",
        "active-etag",
        dirty_body.len(),
    );
    publish_listing(&cache, &scope, &active_item, 1);
    let active = begin_pin(&cache, &scope, &active_item);
    publish_body(&cache, &scope, &active_item, dirty_body, Retention::Dirty);
    assert_eq!(
        cache.refresh_pin(&active.id).unwrap().state,
        PinState::Ready
    );

    let replacement_body = b"replacement snapshot";
    let replacement_item = entry(
        "replacement-file",
        "/replacement.bin",
        "replacement-etag",
        replacement_body.len(),
    );
    publish_listing(&cache, &scope, &replacement_item, 2);
    let staging = begin_pin(&cache, &scope, &replacement_item);
    publish_body(
        &cache,
        &scope,
        &replacement_item,
        replacement_body,
        Retention::Recent,
    );
    assert_eq!(
        cache.refresh_pin(&staging.id).unwrap().state,
        PinState::Ready
    );

    let expected = cache
        .pin_refresh_expectation(&scope, &active.id, scope.root_resource_id(), "/")
        .unwrap();
    // Simulate a concurrent metadata writer after the UI captured its opaque
    // expectation, but before the replacement operation starts.
    let db = cache.lock_db().unwrap();
    assert_eq!(
        db.execute(
            "UPDATE pins SET root_path=?2 WHERE pin_id=?1",
            rusqlite::params![active.id, "/moved-root/"],
        )
        .unwrap(),
        1
    );
    drop(db);
    let active_after_writer = raw_pin(&cache, &active.id);
    let staged_before = raw_pin(&cache, &staging.id);

    let result =
        cache.replace_pin_snapshot_if_current_cancellable(&scope, &expected, &staging.id, || false);
    assert!(matches!(result, Err(CacheError::Conflict)));
    assert_eq!(raw_pin(&cache, &active.id), active_after_writer);
    assert_eq!(raw_pin(&cache, &staging.id), staged_before);
    assert_eq!(read_body(&cache, &scope, &active_item), dirty_body);
    assert_eq!(
        read_body(&cache, &scope, &replacement_item),
        replacement_body
    );
    assert_eq!(
        cache
            .content_record(&scope, &version(&active_item))
            .unwrap()
            .retention,
        Retention::Dirty
    );
}

#[test]
fn current_refresh_expectation_swaps_snapshot_and_keeps_dirty_content() {
    let (_state, cache) = cache();
    let scope = scope();
    let dirty_body = b"keep dirty active bytes";
    let active_item = entry(
        "active-file",
        "/active.bin",
        "active-etag",
        dirty_body.len(),
    );
    publish_listing(&cache, &scope, &active_item, 1);
    let active = begin_pin(&cache, &scope, &active_item);
    publish_body(&cache, &scope, &active_item, dirty_body, Retention::Dirty);
    assert_eq!(
        cache.refresh_pin(&active.id).unwrap().state,
        PinState::Ready
    );

    let expected = cache
        .pin_refresh_expectation(&scope, &active.id, scope.root_resource_id(), "/")
        .unwrap();

    let new_body = b"verified replacement bytes";
    let new_item = entry("new-file", "/new.bin", "new-etag", new_body.len());
    publish_listing(&cache, &scope, &new_item, 2);
    let staging = begin_pin(&cache, &scope, &new_item);
    publish_body(&cache, &scope, &new_item, new_body, Retention::Recent);
    assert_eq!(
        cache.refresh_pin(&staging.id).unwrap().state,
        PinState::Ready
    );

    let result = cache
        .replace_pin_snapshot_if_current_cancellable(&scope, &expected, &staging.id, || false)
        .unwrap();
    assert_eq!(result.id, active.id);
    assert_eq!(result.state, PinState::Ready);
    assert!(matches!(
        cache.pin_info_for_scope(&scope, &staging.id),
        Err(CacheError::PinNotFound)
    ));
    assert_eq!(read_body(&cache, &scope, &active_item), dirty_body);
    assert_eq!(read_body(&cache, &scope, &new_item), new_body);
    assert_eq!(
        cache
            .content_record(&scope, &version(&active_item))
            .unwrap()
            .retention,
        Retention::Dirty
    );
}

#[test]
fn refresh_expectation_scope_root_and_state_admission_are_fenced() {
    let (_state, cache) = cache();
    let scope = scope();
    let body = b"state admission bytes";
    let first = entry("file-a", "/file-a.bin", "etag-a", body.len());
    publish_listing(&cache, &scope, &first, 1);
    let building = begin_pin(&cache, &scope, &first);
    assert!(matches!(
        cache.pin_refresh_expectation(&scope, &building.id, scope.root_resource_id(), "/",),
        Err(CacheError::Conflict)
    ));
    let other = CacheScope::new(
        "https://pin-snapshot.example.test/",
        "other-account",
        "snapshot-space",
        scope.root_resource_id(),
        ScopeProtection::PlaintextAllowed,
    )
    .unwrap();
    publish_listing(&cache, &other, &first, 1);
    assert!(matches!(
        cache.pin_refresh_expectation(&other, &building.id, scope.root_resource_id(), "/"),
        Err(CacheError::PinNotFound)
    ));
    assert!(matches!(
        cache.pin_refresh_expectation(&scope, &building.id, "different-root", "/"),
        Err(CacheError::Conflict)
    ));

    publish_body(&cache, &scope, &first, body, Retention::Dirty);
    assert_eq!(
        cache.refresh_pin(&building.id).unwrap().state,
        PinState::Ready
    );
    let second = entry("file-a", "/file-a.bin", "etag-b", body.len());
    publish_listing(&cache, &scope, &second, 2);
    assert_eq!(raw_pin(&cache, &building.id).state, 2);
    let stale_before = raw_pin(&cache, &building.id);
    publish_body(&cache, &scope, &second, body, Retention::Recent);
    let staging = begin_pin(&cache, &scope, &second);
    publish_body(&cache, &scope, &second, body, Retention::Recent);
    assert_eq!(
        cache.refresh_pin(&staging.id).unwrap().state,
        PinState::Ready
    );
    // Stale is an admitted active state; its captured token must still be
    // honored exactly, while a Building record is never capturable.
    let expected = cache
        .pin_refresh_expectation(&scope, &building.id, scope.root_resource_id(), "/")
        .unwrap();
    assert_eq!(raw_pin(&cache, &building.id), stale_before);
    let refreshed = cache
        .replace_pin_snapshot_if_current_cancellable(&scope, &expected, &staging.id, || false)
        .unwrap();
    assert_eq!(refreshed.id, building.id);
    assert_eq!(refreshed.state, PinState::Ready);
    assert_eq!(read_body(&cache, &scope, &first), body);
}
