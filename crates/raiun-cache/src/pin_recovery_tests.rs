use super::*;
use std::io::Cursor;

fn cache() -> (tempfile::TempDir, Cache) {
    let state = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    set_private_dir(state.path()).unwrap();
    let cache = Cache::open(state.path(), 16 * 1024 * 1024).unwrap();
    (state, cache)
}

fn scope_for(account: &str, protection: ScopeProtection) -> CacheScope {
    CacheScope::new(
        "https://pin-recovery.example.test/",
        account,
        "recovery-space",
        "recovery-root",
        protection,
    )
    .unwrap()
}

fn directory(id: &str, path: &str) -> RemoteEntry {
    RemoteEntry {
        id: id.into(),
        path: path.into(),
        etag: format!("{id}-etag"),
        size: 0,
        directory: true,
        modified_unix: 1,
        writable: true,
        encrypted: false,
    }
}

fn file(id: &str, path: &str, body: &[u8]) -> RemoteEntry {
    RemoteEntry {
        id: id.into(),
        path: path.into(),
        etag: format!("{id}-etag"),
        size: body.len() as u64,
        directory: false,
        modified_unix: 1,
        writable: true,
        encrypted: false,
    }
}

fn fixture_manifest(body: &[u8]) -> Vec<PinManifestEntry> {
    let dir = directory("directory-id", "/folder");
    let item = file("file-id", "/folder/file.txt", body);
    vec![
        PinManifestEntry {
            parent_resource_id: "recovery-root".into(),
            entry: dir,
        },
        PinManifestEntry {
            parent_resource_id: "directory-id".into(),
            entry: item,
        },
    ]
}

fn publish_complete_listings(cache: &Cache, scope: &CacheScope, body: &[u8]) {
    let manifest = fixture_manifest(body);
    cache
        .publish_listing(
            scope,
            scope.root_resource_id(),
            &[CachedEntry {
                parent_resource_id: scope.root_resource_id().into(),
                entry: manifest[0].entry.clone(),
            }],
            1,
        )
        .unwrap();
    cache
        .publish_listing(
            scope,
            "directory-id",
            &[CachedEntry {
                parent_resource_id: "directory-id".into(),
                entry: manifest[1].entry.clone(),
            }],
            1,
        )
        .unwrap();
}

fn create_ready_pin(cache: &Cache, scope: &CacheScope, body: &[u8]) -> PinInfo {
    publish_complete_listings(cache, scope, body);
    let manifest = fixture_manifest(body);
    let pin = cache
        .begin_pin_manifest_at_cancellable(scope, scope.root_resource_id(), "/", &manifest, || {
            false
        })
        .unwrap();
    let item = &manifest[1].entry;
    cache
        .publish_content(
            scope,
            &ContentVersion {
                resource_id: item.id.clone(),
                etag: item.etag.clone(),
                protection: ContentProtection::Plaintext,
            },
            &mut Cursor::new(body),
            body.len() as u64,
            Retention::Dirty,
        )
        .unwrap();
    cache.refresh_pin(&pin.id).unwrap()
}

#[test]
fn retained_stale_pin_survives_restart_without_republishing_or_mutating_state() {
    let (state, cache) = cache();
    let scope = scope_for("recovery-account", ScopeProtection::PlaintextAllowed);
    let body = b"retained recovery bytes";
    let pin = create_ready_pin(&cache, &scope, body);
    assert_eq!(pin.state, PinState::Ready);
    let pending_bytes = b"journal bytes remain pending";
    let write = cache
        .queue_conditional_write(
            &scope,
            ConditionalWriteRequest {
                parent_resource_id: "directory-id".into(),
                name: "file.txt".into(),
                logical_path: "/folder/file.txt".into(),
                resource_id: Some("file-id".into()),
                base: WriteCondition::Match("file-id-etag".into()),
                expected_len: pending_bytes.len() as u64,
                protection: ContentProtection::Plaintext,
            },
            &mut Cursor::new(pending_bytes),
        )
        .unwrap();
    let journal_before = cache.pending_writes(&scope).unwrap();
    assert_eq!(journal_before, vec![write]);
    assert_eq!(
        cache
            .invalidate_paths(&scope, &["/folder/file.txt"])
            .unwrap(),
        1
    );
    assert_eq!(
        cache.listing(&scope, "directory-id"),
        Err(CacheError::IncompleteListing)
    );
    let before: (i64, i64, i64, i64) = {
        let db = cache.lock_db().unwrap();
        db.query_row(
            "SELECT (SELECT state FROM pins WHERE pin_id=?1), (SELECT COUNT(*) FROM pin_items WHERE pin_id=?1), (SELECT COUNT(*) FROM contents WHERE scope_key=?2), (SELECT COUNT(*) FROM writes)",
            params![pin.id, scope.key],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap()
    };
    assert_eq!(before.0, 2, "the pin remains durably Stale");

    drop(cache);
    let reopened = Cache::open(state.path(), 16 * 1024 * 1024).unwrap();
    let retained = reopened
        .retained_pin_manifest(&scope, &pin.id)
        .expect("read exact stale pin metadata for recovery");
    assert_eq!(retained.state, PinState::Stale);
    assert_eq!(retained.root_resource_id, "recovery-root");
    assert_eq!(retained.root_path, "/");
    assert_eq!(retained.entries.len(), 2);
    assert!(retained.entries.iter().all(|item| !item.entry.writable));
    assert!(
        retained
            .entries
            .iter()
            .all(|item| item.entry.modified_unix == 0)
    );
    assert!(
        retained
            .entries
            .iter()
            .any(|item| item.entry.path == "/folder/file.txt")
    );
    assert_eq!(reopened.pending_writes(&scope).unwrap(), journal_before);
    assert_eq!(
        reopened.listing(&scope, "directory-id"),
        Err(CacheError::IncompleteListing)
    );
    let after: (i64, i64, i64, i64) = {
        let db = reopened.lock_db().unwrap();
        db.query_row(
            "SELECT (SELECT state FROM pins WHERE pin_id=?1), (SELECT COUNT(*) FROM pin_items WHERE pin_id=?1), (SELECT COUNT(*) FROM contents WHERE scope_key=?2), (SELECT COUNT(*) FROM writes)",
            params![pin.id, scope.key],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap()
    };
    assert_eq!(after, before, "recovery metadata reads are read-only");
}

#[test]
fn retained_pin_manifest_requires_exact_plaintext_scope_and_known_pin() {
    let (_state, cache) = cache();
    let scope = scope_for("recovery-account", ScopeProtection::PlaintextAllowed);
    let pin = create_ready_pin(&cache, &scope, b"metadata");
    let other = scope_for("different-account", ScopeProtection::PlaintextAllowed);
    cache
        .publish_listing(&other, other.root_resource_id(), &[], 1)
        .unwrap();
    assert_eq!(
        cache.retained_pin_manifest(&other, &pin.id),
        Err(CacheError::PinNotFound)
    );
    assert_eq!(
        cache.retained_pin_manifest(&scope, &"a".repeat(64)),
        Err(CacheError::PinNotFound)
    );
    let ciphertext_scope = scope_for("recovery-account", ScopeProtection::CiphertextOnly);
    assert_eq!(
        cache.retained_pin_manifest(&ciphertext_scope, &pin.id),
        Err(CacheError::ProtectionMismatch)
    );
}

#[test]
fn retained_pin_rejects_tampered_parent_path_edges() {
    let (_state, cache) = cache();
    let scope = scope_for("recovery-account", ScopeProtection::PlaintextAllowed);
    let pin = create_ready_pin(&cache, &scope, b"metadata");
    cache
        .lock_db()
        .unwrap()
        .execute(
            "UPDATE pin_items SET path='/elsewhere/file.txt' WHERE pin_id=?1 AND resource_id='file-id'",
            [&pin.id],
        )
        .unwrap();
    assert_eq!(
        cache.retained_pin_manifest(&scope, &pin.id),
        Err(CacheError::IncompleteManifest)
    );
}

#[test]
fn retained_pin_rejects_duplicate_paths_and_excludes_unavailable_pins() {
    let (_state, cache) = cache();
    let scope = scope_for("recovery-account", ScopeProtection::PlaintextAllowed);
    let pin = create_ready_pin(&cache, &scope, b"metadata");
    cache
        .lock_db()
        .unwrap()
        .execute(
            "INSERT INTO pin_items(pin_id,resource_id,parent_id,name,path,etag,size,directory,encrypted) VALUES(?1,'duplicate-file-id','directory-id','file.txt','/folder/file.txt','duplicate-etag',8,0,0)",
            [&pin.id],
        )
        .unwrap();
    assert_eq!(
        cache.retained_pin_manifest(&scope, &pin.id),
        Err(CacheError::InvalidEntry)
    );

    let other_scope = scope_for("other-account", ScopeProtection::PlaintextAllowed);
    let unavailable = create_ready_pin(&cache, &other_scope, b"unavailable");
    cache
        .lock_db()
        .unwrap()
        .execute("UPDATE pins SET state=3 WHERE pin_id=?1", [&unavailable.id])
        .unwrap();
    assert_eq!(
        cache.retained_pin_manifest(&other_scope, &unavailable.id),
        Err(CacheError::NotFound)
    );
}

#[test]
fn retained_pin_rejects_entry_sizes_above_content_limit() {
    let (_state, cache) = cache();
    let scope = scope_for("recovery-account", ScopeProtection::PlaintextAllowed);
    let pin = create_ready_pin(&cache, &scope, b"metadata");
    cache
        .lock_db()
        .unwrap()
        .execute(
            "UPDATE pin_items SET size=?2 WHERE pin_id=?1 AND resource_id='file-id'",
            params![pin.id, (MAX_CONTENT_BYTES + 1) as i64],
        )
        .unwrap();
    assert_eq!(
        cache.retained_pin_manifest(&scope, &pin.id),
        Err(CacheError::InvalidEntry)
    );
}

#[test]
fn retained_pin_catalog_is_exact_scoped_bounded_and_excludes_unavailable() {
    let (_state, cache) = cache();
    let scope = scope_for("recovery-account", ScopeProtection::PlaintextAllowed);
    let ready = create_ready_pin(&cache, &scope, b"catalog bytes");
    let stale = create_ready_pin(&cache, &scope, b"catalog bytes");
    cache
        .lock_db()
        .unwrap()
        .execute("UPDATE pins SET state=2 WHERE pin_id=?1", [&stale.id])
        .unwrap();
    let unavailable = create_ready_pin(&cache, &scope, b"catalog bytes");
    cache
        .lock_db()
        .unwrap()
        .execute("UPDATE pins SET state=3 WHERE pin_id=?1", [&unavailable.id])
        .unwrap();

    let catalog = cache.retained_pin_catalog(&scope).unwrap();
    assert!(catalog.contains(&RetainedPinSummary {
        pin_id: ready.id.clone(),
        root_resource_id: "recovery-root".into(),
        root_path: "/".into(),
        state: PinState::Ready,
    }));
    assert!(catalog.contains(&RetainedPinSummary {
        pin_id: stale.id.clone(),
        root_resource_id: "recovery-root".into(),
        root_path: "/".into(),
        state: PinState::Stale,
    }));
    assert!(!catalog.iter().any(|item| item.pin_id == unavailable.id));
    assert!(
        catalog
            .windows(2)
            .all(|pair| pair[0].pin_id < pair[1].pin_id)
    );

    let other = scope_for("different-account", ScopeProtection::PlaintextAllowed);
    cache
        .publish_listing(&other, other.root_resource_id(), &[], 1)
        .unwrap();
    assert!(cache.retained_pin_catalog(&other).unwrap().is_empty());
    let ciphertext_scope = scope_for("recovery-account", ScopeProtection::CiphertextOnly);
    assert_eq!(
        cache.retained_pin_catalog(&ciphertext_scope),
        Err(CacheError::ProtectionMismatch)
    );
}

#[test]
fn retained_pin_catalog_fails_closed_on_corrupt_identity_state_and_bounds() {
    let (_state, cache) = cache();
    let scope = scope_for("recovery-account", ScopeProtection::PlaintextAllowed);
    let pin = create_ready_pin(&cache, &scope, b"metadata");

    cache
        .lock_db()
        .unwrap()
        .execute("UPDATE pins SET state=9 WHERE pin_id=?1", [&pin.id])
        .unwrap();
    assert_eq!(cache.retained_pin_catalog(&scope), Err(CacheError::Corrupt));
    cache
        .lock_db()
        .unwrap()
        .execute(
            "UPDATE pins SET state=1,root_id='' WHERE pin_id=?1",
            [&pin.id],
        )
        .unwrap();
    assert_eq!(
        cache.retained_pin_catalog(&scope),
        Err(CacheError::InvalidEntry)
    );
    cache
        .lock_db()
        .unwrap()
        .execute(
            "UPDATE pins SET root_id='other-root' WHERE pin_id=?1",
            [&pin.id],
        )
        .unwrap();
    assert_eq!(
        cache.retained_pin_catalog(&scope),
        Err(CacheError::IncompleteManifest)
    );
    cache
        .lock_db()
        .unwrap()
        .execute(
            "UPDATE pins SET root_id='recovery-root',root_path=printf('%.*c',?2,'x') WHERE pin_id=?1",
            params![pin.id, MAX_LISTING_BYTES as i64 + 1],
        )
        .unwrap();
    assert_eq!(
        cache.retained_pin_catalog(&scope),
        Err(CacheError::LimitExceeded)
    );
}

#[test]
fn retained_pin_catalog_rejects_too_many_rows_without_truncating() {
    let (_state, cache) = cache();
    let scope = scope_for("recovery-account", ScopeProtection::PlaintextAllowed);
    cache
        .publish_listing(&scope, scope.root_resource_id(), &[], 1)
        .unwrap();
    let mut db = cache.lock_db().unwrap();
    let tx = db.transaction().unwrap();
    for index in 0..=MAX_PIN_RECORDS {
        tx.execute(
            "INSERT INTO pins(pin_id,scope_key,root_id,root_path,state,created_at) VALUES(?1,?2,?3,'/',1,1)",
            params![format!("synthetic-pin-{index:05}"), scope.key, scope.root_resource_id],
        )
        .unwrap();
    }
    tx.commit().unwrap();
    drop(db);
    assert_eq!(
        cache.retained_pin_catalog(&scope),
        Err(CacheError::LimitExceeded)
    );
}
