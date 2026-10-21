use super::*;
use std::cell::Cell;
use std::io::{Cursor, Read};

fn cache() -> (tempfile::TempDir, Cache) {
    let state = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    set_private_dir(state.path()).unwrap();
    let cache = Cache::open(state.path(), 16 * 1024 * 1024).unwrap();
    (state, cache)
}

fn scope(account: &str) -> CacheScope {
    CacheScope::new(
        "https://folder-role.example.test/",
        account,
        "space-a",
        "scope-root",
        ScopeProtection::PlaintextAllowed,
    )
    .unwrap()
}

fn entry(id: &str, path: &str, etag: &str, body: &[u8]) -> RemoteEntry {
    RemoteEntry {
        id: id.to_owned(),
        path: path.to_owned(),
        etag: etag.to_owned(),
        size: body.len() as u64,
        directory: false,
        modified_unix: 1,
        writable: true,
        encrypted: false,
    }
}

fn manifest(scope: &CacheScope, item: &RemoteEntry) -> Vec<PinManifestEntry> {
    vec![PinManifestEntry {
        parent_resource_id: scope.root_resource_id().to_owned(),
        entry: item.clone(),
    }]
}

fn publish_listing(cache: &Cache, scope: &CacheScope, item: &RemoteEntry) {
    cache
        .publish_listing(
            scope,
            scope.root_resource_id(),
            &[CachedEntry {
                parent_resource_id: scope.root_resource_id().to_owned(),
                entry: item.clone(),
            }],
            1,
        )
        .unwrap();
}

fn publish_body(
    cache: &Cache,
    scope: &CacheScope,
    item: &RemoteEntry,
    body: &[u8],
    retention: Retention,
) {
    cache
        .publish_content(
            scope,
            &ContentVersion {
                resource_id: item.id.clone(),
                etag: item.etag.clone(),
                protection: ContentProtection::Plaintext,
            },
            &mut Cursor::new(body.to_vec()),
            item.size,
            retention,
        )
        .unwrap();
}

fn read_body(cache: &Cache, scope: &CacheScope, item: &RemoteEntry) -> Vec<u8> {
    let mut reader = cache
        .open_content(
            scope,
            &ContentVersion {
                resource_id: item.id.clone(),
                etag: item.etag.clone(),
                protection: ContentProtection::Plaintext,
            },
        )
        .unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    bytes
}

fn initial_pin(cache: &Cache, scope: &CacheScope, item: &RemoteEntry) -> PinInfo {
    cache
        .begin_initial_pin_manifest_at_cancellable(
            scope,
            scope.root_resource_id(),
            "/",
            &manifest(scope, item),
            || false,
        )
        .unwrap()
}

fn ready_initial(cache: &Cache, scope: &CacheScope, item: &RemoteEntry, body: &[u8]) -> PinInfo {
    publish_body(cache, scope, item, body, Retention::Dirty);
    let pin = initial_pin(cache, scope, item);
    assert_eq!(pin.state, PinState::Building);
    cache.refresh_pin_cancellable(&pin.id, || false).unwrap()
}

struct RefreshFixture {
    _state: tempfile::TempDir,
    cache: Cache,
    scope: CacheScope,
    active: PinInfo,
    staged: PinInfo,
    active_item: RemoteEntry,
    staged_item: RemoteEntry,
}

fn ready_refresh_fixture() -> RefreshFixture {
    let (state, cache) = cache();
    let scope = scope("role-account");
    let active_item = entry(
        "active-file",
        "/folder/active",
        "active-v1",
        b"active dirty",
    );
    publish_listing(&cache, &scope, &active_item);
    let active = ready_initial(&cache, &scope, &active_item, b"active dirty");
    let staged_item = entry("staged-file", "/folder/staged", "staged-v1", b"stage dirty");
    publish_listing(&cache, &scope, &staged_item);
    publish_body(
        &cache,
        &scope,
        &staged_item,
        b"stage dirty",
        Retention::Dirty,
    );
    let staged = cache
        .begin_folder_refresh_manifest_at_cancellable(
            &scope,
            &active.id,
            scope.root_resource_id(),
            "/",
            &manifest(&scope, &staged_item),
            || false,
        )
        .unwrap();
    assert_eq!(
        cache
            .refresh_pin_cancellable(&staged.id, || false)
            .unwrap()
            .state,
        PinState::Ready
    );
    RefreshFixture {
        _state: state,
        cache,
        scope,
        active,
        staged,
        active_item,
        staged_item,
    }
}

fn replace_fixture(
    fixture: &RefreshFixture,
    cancelled: impl FnMut() -> bool,
) -> Result<PinInfo, CacheError> {
    let expected = fixture
        .cache
        .pin_refresh_expectation(
            &fixture.scope,
            &fixture.active.id,
            fixture.scope.root_resource_id(),
            "/",
        )
        .unwrap();
    fixture.cache.replace_pin_snapshot_if_current_cancellable(
        &fixture.scope,
        &expected,
        &fixture.staged.id,
        cancelled,
    )
}

#[test]
fn interrupted_initial_roles_reopen_exactly_and_generic_legacy_stays_unknown() {
    let (state, cache) = cache();
    let owner = scope("role-account");
    let wrong_scope = scope("other-role-account");
    let body = b"dirty bytes retained";
    let item = entry("initial-file", "/folder/file", "v1", body);
    publish_listing(&cache, &owner, &item);
    let initial = cache
        .begin_initial_pin_manifest_at_cancellable(
            &owner,
            owner.root_resource_id(),
            "/",
            &manifest(&owner, &item),
            || false,
        )
        .unwrap();
    publish_body(&cache, &owner, &item, body, Retention::Dirty);
    let generic = cache
        .begin_pin_manifest_at_cancellable(
            &owner,
            owner.root_resource_id(),
            "/legacy",
            &manifest(&owner, &item),
            || false,
        )
        .unwrap();
    publish_listing(&cache, &wrong_scope, &item);

    let expected = Some(FolderPinRoles {
        active_pin_id: None,
        staging_pin_id: Some(initial.id.clone()),
        staging_is_initial: true,
    });
    assert_eq!(
        cache
            .folder_pin_roles(&owner, owner.root_resource_id(), "/")
            .unwrap(),
        expected
    );
    assert_eq!(
        cache
            .folder_pin_roles(&owner, "folder-root", "/elsewhere")
            .unwrap(),
        None
    );
    assert_eq!(
        cache
            .folder_pin_roles(&wrong_scope, owner.root_resource_id(), "/")
            .unwrap(),
        None
    );
    assert_eq!(
        cache
            .folder_pin_roles(&owner, owner.root_resource_id(), "/legacy")
            .unwrap(),
        None,
        "generic/legacy pins must not be adopted as folder roles"
    );
    assert_eq!(read_body(&cache, &owner, &item), body);
    drop(cache);

    let reopened = Cache::open(state.path(), 16 * 1024 * 1024).unwrap();
    assert_eq!(
        reopened
            .folder_pin_roles(&owner, owner.root_resource_id(), "/")
            .unwrap(),
        expected
    );
    assert_eq!(
        reopened
            .folder_pin_roles(&owner, owner.root_resource_id(), "/legacy")
            .unwrap(),
        None
    );
    assert_ne!(initial.id, generic.id);
}

#[test]
fn initial_promotion_refresh_stage_and_atomic_swap_survive_reopen() {
    let (state, cache) = cache();
    let owner = scope("role-account");
    let first = entry("first-file", "/folder/first", "v1", b"first bytes");
    publish_listing(&cache, &owner, &first);
    let active = ready_initial(&cache, &owner, &first, b"first bytes");
    assert_eq!(active.state, PinState::Ready);
    assert_eq!(
        cache
            .folder_pin_roles(&owner, owner.root_resource_id(), "/")
            .unwrap(),
        Some(FolderPinRoles {
            active_pin_id: Some(active.id.clone()),
            staging_pin_id: None,
            staging_is_initial: false,
        })
    );

    let second = entry("second-file", "/folder/second", "v2", b"second bytes");
    publish_listing(&cache, &owner, &second);
    publish_body(&cache, &owner, &second, b"second bytes", Retention::Dirty);
    let staged = cache
        .begin_folder_refresh_manifest_at_cancellable(
            &owner,
            &active.id,
            owner.root_resource_id(),
            "/",
            &manifest(&owner, &second),
            || false,
        )
        .unwrap();
    assert_eq!(
        cache
            .refresh_pin_cancellable(&staged.id, || false)
            .unwrap()
            .state,
        PinState::Ready
    );
    let roles = Some(FolderPinRoles {
        active_pin_id: Some(active.id.clone()),
        staging_pin_id: Some(staged.id.clone()),
        staging_is_initial: false,
    });
    assert_eq!(
        cache
            .folder_pin_roles(&owner, owner.root_resource_id(), "/")
            .unwrap(),
        roles,
        "readiness inspection must not promote a refresh stage"
    );

    let expected = cache
        .pin_refresh_expectation(&owner, &active.id, owner.root_resource_id(), "/")
        .unwrap();
    let replaced = cache
        .replace_pin_snapshot_if_current_cancellable(&owner, &expected, &staged.id, || false)
        .unwrap();
    assert_eq!(replaced.id, active.id);
    assert_eq!(
        cache
            .folder_pin_roles(&owner, owner.root_resource_id(), "/")
            .unwrap(),
        Some(FolderPinRoles {
            active_pin_id: Some(active.id.clone()),
            staging_pin_id: None,
            staging_is_initial: false,
        })
    );
    drop(cache);

    // Model a caller/auth failure after the durable replacement commit. A new
    // process can recover the active ID, but still needs fresh backend auth.
    let reopened = Cache::open(state.path(), 16 * 1024 * 1024).unwrap();
    assert_eq!(
        reopened
            .folder_pin_roles(&owner, owner.root_resource_id(), "/")
            .unwrap(),
        Some(FolderPinRoles {
            active_pin_id: Some(active.id.clone()),
            staging_pin_id: None,
            staging_is_initial: false,
        })
    );
    assert_eq!(reopened.pins(&owner).unwrap().len(), 1);
}

#[test]
fn cancelled_stage_admission_preserves_roles_and_dirty_content_then_stage_delete_keeps_active() {
    let (_state, cache) = cache();
    let owner = scope("role-account");
    let first = entry("first-file", "/folder/first", "v1", b"dirty original");
    publish_listing(&cache, &owner, &first);
    let active = ready_initial(&cache, &owner, &first, b"dirty original");
    let before = cache
        .folder_pin_roles(&owner, owner.root_resource_id(), "/")
        .unwrap();
    let second = entry("second-file", "/folder/second", "v2", b"new bytes");
    publish_listing(&cache, &owner, &second);
    let cancelled = cache.begin_folder_refresh_manifest_at_cancellable(
        &owner,
        &active.id,
        owner.root_resource_id(),
        "/",
        &manifest(&owner, &second),
        || true,
    );
    assert_eq!(cancelled, Err(CacheError::Cancelled));
    assert_eq!(
        cache
            .folder_pin_roles(&owner, owner.root_resource_id(), "/")
            .unwrap(),
        before
    );
    assert_eq!(read_body(&cache, &owner, &first), b"dirty original");

    publish_body(&cache, &owner, &second, b"new bytes", Retention::Dirty);
    let staged = cache
        .begin_folder_refresh_manifest_at_cancellable(
            &owner,
            &active.id,
            owner.root_resource_id(),
            "/",
            &manifest(&owner, &second),
            || false,
        )
        .unwrap();
    cache.cancel_pin_for_scope(&owner, &staged.id).unwrap();
    assert_eq!(
        cache
            .folder_pin_roles(&owner, owner.root_resource_id(), "/")
            .unwrap(),
        before,
        "deleting a stage must leave the active role intact"
    );
    assert_eq!(read_body(&cache, &owner, &first), b"dirty original");
}

#[test]
fn cross_scope_pin_reference_in_role_journal_is_corrupt() {
    let (_state, cache) = cache();
    let owner = scope("role-account");
    let other = scope("other-role-account");
    let own_item = entry("own-file", "/folder/own", "own-v1", b"own");
    publish_listing(&cache, &owner, &own_item);
    let own = cache
        .begin_initial_pin_manifest_at_cancellable(
            &owner,
            owner.root_resource_id(),
            "/",
            &manifest(&owner, &own_item),
            || false,
        )
        .unwrap();
    let foreign_item = entry("foreign-file", "/folder/foreign", "foreign-v1", b"foreign");
    publish_listing(&cache, &other, &foreign_item);
    let foreign = cache
        .begin_pin_manifest_at_cancellable(
            &other,
            owner.root_resource_id(),
            "/",
            &manifest(&other, &foreign_item),
            || false,
        )
        .unwrap();

    {
        let db = cache.lock_db().unwrap();
        db.execute(
            "UPDATE folder_pin_roles SET staging_pin_id=?4 WHERE scope_key=?1 AND root_id=?2 AND root_path=?3",
            params![owner.key, owner.root_resource_id(), "/", foreign.id],
        )
        .unwrap();
    }
    assert_eq!(
        cache.folder_pin_roles(&owner, owner.root_resource_id(), "/"),
        Err(CacheError::Corrupt)
    );
    // Keep the local role's pin referenced by the fixture to make the mutation
    // explicit; its own row remains intact in the pins table.
    assert_eq!(own.state, PinState::Building);
}

#[test]
fn deleting_active_keeps_refresh_stage_recovery_only() {
    let (_state, cache) = cache();
    let owner = scope("role-account");
    let first = entry("first-file", "/folder/first", "v1", b"first bytes");
    publish_listing(&cache, &owner, &first);
    let active = ready_initial(&cache, &owner, &first, b"first bytes");
    let second = entry("second-file", "/folder/second", "v2", b"second bytes");
    publish_listing(&cache, &owner, &second);
    publish_body(&cache, &owner, &second, b"second bytes", Retention::Dirty);
    let staged = cache
        .begin_folder_refresh_manifest_at_cancellable(
            &owner,
            &active.id,
            owner.root_resource_id(),
            "/",
            &manifest(&owner, &second),
            || false,
        )
        .unwrap();

    cache.cancel_pin_for_scope(&owner, &active.id).unwrap();
    let recovery_only = Some(FolderPinRoles {
        active_pin_id: None,
        staging_pin_id: Some(staged.id.clone()),
        staging_is_initial: false,
    });
    assert_eq!(
        cache
            .folder_pin_roles(&owner, owner.root_resource_id(), "/")
            .unwrap(),
        recovery_only
    );
    assert_eq!(
        cache
            .refresh_pin_cancellable(&staged.id, || false)
            .unwrap()
            .state,
        PinState::Ready
    );
    assert_eq!(
        cache
            .folder_pin_roles(&owner, owner.root_resource_id(), "/")
            .unwrap(),
        recovery_only,
        "refresh-stage readiness cannot recreate a deleted active role"
    );
}

#[test]
fn schema_v6_upgrade_keeps_generic_pin_and_dirty_bytes_without_role_inference() {
    let (state, cache) = cache();
    let owner = scope("migration-account");
    let body = b"v6 dirty retained content";
    let item = entry("v6-file", "/folder/v6-file", "v6-etag", body);
    publish_listing(&cache, &owner, &item);
    publish_body(&cache, &owner, &item, body, Retention::Dirty);
    let pin = cache
        .begin_pin_manifest_at_cancellable(
            &owner,
            owner.root_resource_id(),
            "/",
            &manifest(&owner, &item),
            || false,
        )
        .unwrap();
    let content_version = ContentVersion {
        resource_id: item.id.clone(),
        etag: item.etag.clone(),
        protection: ContentProtection::Plaintext,
    };
    let before_record = cache.content_record(&owner, &content_version).unwrap();
    drop(cache);

    let db = rusqlite::Connection::open(state.path().join("cache.sqlite3")).unwrap();
    db.execute_batch(
        "DROP TRIGGER IF EXISTS folder_pin_role_delete;
         DROP TABLE IF EXISTS folder_pin_roles;
         DROP TABLE IF EXISTS folder_cloud_only_intents;
         PRAGMA user_version=6;",
    )
    .unwrap();
    drop(db);

    let upgraded = Cache::open(state.path(), 16 * 1024 * 1024).unwrap();
    let schema_version: i64 = upgraded
        .lock_db()
        .unwrap()
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(schema_version, CACHE_VERSION as i64);
    assert_eq!(
        upgraded
            .folder_pin_roles(&owner, owner.root_resource_id(), "/")
            .unwrap(),
        None,
        "v6 generic pins must not be inferred as folder roles"
    );
    assert_eq!(upgraded.pins(&owner).unwrap().len(), 1);
    assert_eq!(
        upgraded.content_record(&owner, &content_version).unwrap(),
        before_record
    );
    assert_eq!(before_record.retention, Retention::Dirty);
    assert_eq!(read_body(&upgraded, &owner, &item), body);
    assert_eq!(pin.state, PinState::Building);
}

#[test]
fn cancellation_at_replacement_commit_preserves_both_pins_roles_and_dirty_bytes() {
    let measured = ready_refresh_fixture();
    let count = Cell::new(0_usize);
    let completed = replace_fixture(&measured, || {
        count.set(count.get() + 1);
        false
    })
    .unwrap();
    assert_eq!(completed.id, measured.active.id);
    let final_probe = count.get();
    assert!(final_probe > 0);
    drop(measured);

    let fixture = ready_refresh_fixture();
    let before_roles = fixture
        .cache
        .folder_pin_roles(&fixture.scope, fixture.scope.root_resource_id(), "/")
        .unwrap();
    let before_pins = fixture.cache.pins(&fixture.scope).unwrap();
    let probes = Cell::new(0_usize);
    let result = replace_fixture(&fixture, || {
        let next = probes.get() + 1;
        probes.set(next);
        next == final_probe
    });
    assert_eq!(
        probes.get(),
        final_probe,
        "cancellation should fire at the final probe"
    );
    assert_eq!(result, Err(CacheError::Cancelled));
    assert_eq!(
        fixture
            .cache
            .folder_pin_roles(&fixture.scope, fixture.scope.root_resource_id(), "/")
            .unwrap(),
        before_roles
    );
    assert_eq!(fixture.cache.pins(&fixture.scope).unwrap(), before_pins);
    for item in [&fixture.active_item, &fixture.staged_item] {
        let version = ContentVersion {
            resource_id: item.id.clone(),
            etag: item.etag.clone(),
            protection: ContentProtection::Plaintext,
        };
        assert_eq!(
            fixture
                .cache
                .content_record(&fixture.scope, &version)
                .unwrap()
                .retention,
            Retention::Dirty
        );
    }
    assert_eq!(
        read_body(&fixture.cache, &fixture.scope, &fixture.active_item),
        b"active dirty"
    );
    assert_eq!(
        read_body(&fixture.cache, &fixture.scope, &fixture.staged_item),
        b"stage dirty"
    );

    let retried = replace_fixture(&fixture, || false).unwrap();
    assert_eq!(retried.id, fixture.active.id);
    assert_eq!(
        fixture
            .cache
            .folder_pin_roles(&fixture.scope, fixture.scope.root_resource_id(), "/")
            .unwrap(),
        Some(FolderPinRoles {
            active_pin_id: Some(fixture.active.id.clone()),
            staging_pin_id: None,
            staging_is_initial: false,
        })
    );
}

#[test]
fn v6_upgrade_does_not_reseed_a_missing_policy_intent_fence() {
    let (state, cache) = cache();
    let owner = scope("role-account");
    cache
        .set_policy_at(&owner, "file", "/file", "v1", AvailabilityPolicy::Recent)
        .unwrap();
    {
        let db = cache.lock_db().unwrap();
        db.execute("DELETE FROM policy_intent_revisions", [])
            .unwrap();
        db.pragma_update(None, "user_version", 6).unwrap();
    }
    drop(cache);
    assert!(matches!(
        Cache::open(state.path(), 16 * 1024 * 1024),
        Err(CacheError::Corrupt)
    ));
}

#[test]
fn intent_observation_is_read_only_and_preserves_unknown_saved_pins() {
    let (_state, cache) = cache();
    let owner = scope("role-account");
    let empty = cache
        .folder_pin_intent(&owner, owner.root_resource_id(), "/")
        .unwrap();
    assert_eq!(
        empty,
        FolderPinIntent {
            roles: None,
            has_unknown_pins: false
        }
    );
    assert_eq!(
        cache
            .lock_db()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM scopes", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    let item = entry("file", "/file", "v1", b"dirty bytes");
    publish_listing(&cache, &owner, &item);
    publish_body(&cache, &owner, &item, b"dirty bytes", Retention::Dirty);
    let initial = initial_pin(&cache, &owner, &item);
    let known = cache
        .folder_pin_intent(&owner, owner.root_resource_id(), "/")
        .unwrap();
    assert_eq!(
        known.roles.unwrap().staging_pin_id.as_deref(),
        Some(initial.id.as_str())
    );
    assert!(!known.has_unknown_pins);
    assert_eq!(
        cache
            .lock_db()
            .unwrap()
            .query_row(
                "SELECT state FROM pins WHERE pin_id=?1",
                [&initial.id],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        0,
        "intent discovery must not promote cached readiness"
    );
    let generic = cache
        .begin_pin_manifest_at_cancellable(
            &owner,
            owner.root_resource_id(),
            "/",
            &manifest(&owner, &item),
            || false,
        )
        .unwrap();
    let unknown = cache
        .folder_pin_intent(&owner, owner.root_resource_id(), "/")
        .unwrap();
    assert!(unknown.has_unknown_pins);
    assert_eq!(
        unknown.roles.unwrap().staging_pin_id.as_deref(),
        Some(initial.id.as_str())
    );
    assert_ne!(initial.id, generic.id);
    assert_eq!(read_body(&cache, &owner, &item), b"dirty bytes");
}
