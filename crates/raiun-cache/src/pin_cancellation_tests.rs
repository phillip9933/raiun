use super::*;
use std::io::Cursor;

#[test]
fn cancelled_pin_refresh_preserves_manifest_status_and_verified_content() {
    let state = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    set_private_dir(state.path()).unwrap();
    let cache = Cache::open(state.path(), 2 * 1024 * 1024).unwrap();
    let scope = CacheScope::new(
        "https://pin-cancel.example.test/",
        "account",
        "space",
        "root",
        ScopeProtection::PlaintextAllowed,
    )
    .unwrap();
    let bytes = vec![42_u8; 1024 * 1024];
    let entry = RemoteEntry {
        id: "file".into(),
        path: "/file".into(),
        etag: "v1".into(),
        size: bytes.len() as u64,
        directory: false,
        encrypted: false,
        writable: true,
        modified_unix: 1,
    };
    cache
        .publish_listing(
            &scope,
            "root",
            &[CachedEntry {
                parent_resource_id: "root".into(),
                entry: entry.clone(),
            }],
            1,
        )
        .unwrap();
    let version = ContentVersion {
        resource_id: entry.id.clone(),
        etag: entry.etag.clone(),
        protection: ContentProtection::Plaintext,
    };
    cache
        .publish_content(
            &scope,
            &version,
            &mut Cursor::new(&bytes),
            bytes.len() as u64,
            Retention::Recent,
        )
        .unwrap();
    let pin = cache
        .begin_pin(
            &scope,
            "root",
            &[PinManifestEntry {
                parent_resource_id: "root".into(),
                entry,
            }],
        )
        .unwrap();
    assert_eq!(pin.state, PinState::Ready);
    let mut probes = 0;
    assert!(matches!(
        cache.refresh_pin_cancellable(&pin.id, || {
            probes += 1;
            probes >= 8
        }),
        Err(CacheError::Cancelled)
    ));
    assert!(probes >= 8);
    assert_eq!(cache.pin_info_for_scope(&scope, &pin.id).unwrap(), pin);
    assert_eq!(
        cache.content_record(&scope, &version).unwrap().byte_len,
        bytes.len() as u64
    );
    assert_eq!(cache.evict_recent(0).unwrap().removed_bytes, 0);
}

#[test]
fn cancelled_pin_refresh_before_lookup_does_not_modify_cache() {
    let state = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    set_private_dir(state.path()).unwrap();
    let cache = Cache::open(state.path(), 1024).unwrap();
    assert!(matches!(
        cache.refresh_pin_cancellable("missing-pin", || true),
        Err(CacheError::Cancelled)
    ));
    assert!(matches!(
        cache.refresh_pin("missing-pin"),
        Err(CacheError::PinNotFound)
    ));
}

#[test]
fn manifest_admission_rolls_back_cancellation_and_defers_content_verification() {
    let state = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    set_private_dir(state.path()).unwrap();
    let cache = Cache::open(state.path(), 1024).unwrap();
    let scope = CacheScope::new(
        "https://pin-admission.example.test/",
        "account",
        "space",
        "root",
        ScopeProtection::PlaintextAllowed,
    )
    .unwrap();
    let entry = RemoteEntry {
        id: "file".into(),
        path: "/file".into(),
        etag: "v1".into(),
        size: 0,
        directory: false,
        encrypted: false,
        writable: true,
        modified_unix: 1,
    };
    cache
        .publish_listing(
            &scope,
            "root",
            &[CachedEntry {
                parent_resource_id: "root".into(),
                entry: entry.clone(),
            }],
            1,
        )
        .unwrap();
    cache
        .publish_content(
            &scope,
            &ContentVersion {
                resource_id: entry.id.clone(),
                etag: entry.etag.clone(),
                protection: ContentProtection::Plaintext,
            },
            &mut Cursor::new([]),
            0,
            Retention::Recent,
        )
        .unwrap();
    let manifest = [PinManifestEntry {
        parent_resource_id: "root".into(),
        entry,
    }];
    // Cancel immediately before the transaction commits, after inserting its row.
    let mut probes = 0;
    assert!(matches!(
        cache.begin_pin_manifest_at_cancellable(&scope, "root", "/", &manifest, || {
            probes += 1;
            probes == 4
        }),
        Err(CacheError::Cancelled)
    ));
    assert_eq!(probes, 4);
    assert!(cache.pins(&scope).unwrap().is_empty());
    let db = cache.lock_db().unwrap();
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM pin_items", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    drop(db);
    let pin = cache
        .begin_pin_manifest_at_cancellable(&scope, "root", "/", &manifest, || false)
        .unwrap();
    assert_eq!(pin.state, PinState::Building);
    assert_eq!(pin.item_count, 1);
    assert_eq!(pin.required_content_count, 1);
    assert_eq!(pin.ready_content_count, 0);
    // Verified readiness is deliberately a separate, cancellable operation.
    let ready = cache.refresh_pin_cancellable(&pin.id, || false).unwrap();
    assert_eq!(ready.state, PinState::Ready);
    assert_eq!(ready.ready_content_count, 1);
    cache.cancel_pin_for_scope(&scope, &pin.id).unwrap();
    assert_eq!(
        cache
            .begin_pin_at(&scope, "root", "/", &manifest)
            .unwrap()
            .state,
        PinState::Ready
    );
}
