#[cfg(windows)]
#[path = "offline_download_tests.rs"]
mod offline_download_tests;

use super::*;
use raiun_cache::{AvailabilityPolicy, Cache, CacheScope, ScopeProtection};
use std::sync::atomic::{AtomicUsize, Ordering};

const SPACE: &str = "space-synthetic";
const ROOT: &str = "root-synthetic";
const PATH: &str = "/docs/report.txt";
const RESOURCE: &str = "resource-report";
const ETAG: &str = "\"version-7\"";
const SIZE: u64 = 11;

#[derive(Default)]
struct MemoryCatalog {
    bindings: Mutex<Vec<ProviderIdentityBinding>>,
    upserts: AtomicUsize,
}

impl ProviderIdentityCatalog for MemoryCatalog {
    fn load(
        &self,
        _scope: &ProviderIdentityCatalogScope,
    ) -> Result<Vec<ProviderIdentityBinding>, BackendError> {
        Ok(self.bindings.lock().unwrap().clone())
    }

    fn upsert(
        &self,
        _scope: &ProviderIdentityCatalogScope,
        _binding: &ProviderIdentityBinding,
    ) -> Result<(), BackendError> {
        self.upserts.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn remove(
        &self,
        _scope: &ProviderIdentityCatalogScope,
        _identity: OpaqueIdentity,
    ) -> Result<(), BackendError> {
        Ok(())
    }
}

struct Fixture {
    _temp: tempfile::TempDir,
    backend: OpenCloudPlaceholderBackend,
    catalog: Arc<MemoryCatalog>,
    identity: OpaqueIdentity,
}

fn fixture(with_catalog: bool) -> Fixture {
    fixture_with_quota(with_catalog, 1024 * 1024)
}

fn fixture_with_quota(with_catalog: bool, quota: u64) -> Fixture {
    let origin = "https://cache-binding.example".to_owned();
    let account = "account-cache-binding".to_owned();
    let client = Arc::new(OpenCloudClient::new(&origin, "synthetic-token".into()).unwrap());
    let provider_scope = ProviderScope::new(
        client.as_ref(),
        "profile-cache-binding".into(),
        account.clone(),
        client.server_origin().unwrap(),
    )
    .unwrap();
    let local_root_identity = crate::ConfiguredRootIdentity {
        volume_serial: 0x2211,
        file_index: 0x334455,
    };
    let catalog_scope =
        ProviderIdentityCatalogScope::new(&provider_scope, local_root_identity, SPACE, ROOT)
            .unwrap();
    let identity = binding_identity(&catalog_scope, "file", &[SPACE, ROOT, PATH, RESOURCE]);
    let binding = ProviderIdentityBinding::File {
        identity: *identity.as_bytes(),
        space_id: SPACE.into(),
        root_resource_id: ROOT.into(),
        path: PATH.into(),
        remote_id: RESOURCE.into(),
        etag: ETAG.into(),
        size: SIZE,
    };
    let catalog = Arc::new(MemoryCatalog::default());
    if with_catalog {
        *catalog.bindings.lock().unwrap() = vec![binding];
    }
    let temp = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let cache = Cache::open(temp.path(), quota).unwrap();
    let backend = if with_catalog {
        OpenCloudPlaceholderBackend::new_with_identity_catalog_and_cache(
            client,
            provider_scope,
            local_root_identity,
            catalog.clone(),
            cache.clone(),
        )
        .unwrap()
    } else {
        OpenCloudPlaceholderBackend::new_with_cache(client, provider_scope, cache.clone()).unwrap()
    };
    if with_catalog {
        // Load a preexisting protected identity catalog as a process-restart
        // would. This must not invoke the catalog's upsert path.
        backend.load_catalog_for_root(SPACE, ROOT).unwrap();
        let cache_scope = CacheScope::new(
            &origin,
            &account,
            SPACE,
            ROOT,
            ScopeProtection::PlaintextAllowed,
        )
        .unwrap();
        cache
            .set_policy_at(
                &cache_scope,
                RESOURCE,
                PATH,
                ETAG,
                AvailabilityPolicy::CloudOnly,
            )
            .unwrap();
    }
    Fixture {
        _temp: temp,
        backend,
        catalog,
        identity,
    }
}

fn expected<'a>(
    space_id: &'a str,
    root_resource_id: &'a str,
    path: &'a str,
    resource_id: &'a str,
    etag: &'a str,
    size: u64,
) -> FileCacheBindingExpectation<'a> {
    FileCacheBindingExpectation {
        space_id,
        root_resource_id,
        path,
        resource_id,
        etag,
        size,
    }
}

fn exact_expected() -> FileCacheBindingExpectation<'static> {
    expected(SPACE, ROOT, PATH, RESOURCE, ETAG, SIZE)
}

#[test]
fn exact_catalog_binding_returns_last_observed_cache_metadata_without_network_or_identity_creation()
{
    let fixture = fixture(true);
    let before_files = fixture.backend.state.lock().unwrap().files.len();
    let status = fixture
        .backend
        .file_cache_status_for_binding(&exact_expected(), &CancellationToken::new())
        .unwrap();
    assert_eq!(status.policy, AvailabilityPolicy::CloudOnly);
    assert!(!status.recorded_complete_version);
    assert_eq!(status.recorded_bytes, 0);
    let state = fixture.backend.state.lock().unwrap();
    assert_eq!(state.files.len(), before_files);
    assert_eq!(before_files, 1);
    assert!(state.files.contains_key(&fixture.identity));
    assert_eq!(fixture.catalog.upserts.load(Ordering::Relaxed), 0);
}

#[test]
fn every_mismatched_binding_component_is_not_found() {
    let fixture = fixture(true);
    let cases = [
        expected("another-space", ROOT, PATH, RESOURCE, ETAG, SIZE),
        expected(SPACE, "another-root", PATH, RESOURCE, ETAG, SIZE),
        expected(SPACE, ROOT, "/docs/other.txt", RESOURCE, ETAG, SIZE),
        expected(SPACE, ROOT, PATH, "another-resource", ETAG, SIZE),
        expected(SPACE, ROOT, PATH, RESOURCE, "\"version-8\"", SIZE),
        expected(SPACE, ROOT, PATH, RESOURCE, ETAG, SIZE + 1),
    ];
    for mismatch in cases {
        assert_eq!(
            fixture
                .backend
                .file_cache_status_for_binding(&mismatch, &CancellationToken::new()),
            Err(BackendError::NotFound),
            "mismatched scope or listed-file metadata must not resolve"
        );
    }
    assert_eq!(fixture.backend.state.lock().unwrap().files.len(), 1);
}

#[test]
fn unavailable_or_uninitialized_catalog_fails_closed() {
    let fixture = fixture(false);
    assert_eq!(
        fixture
            .backend
            .file_cache_status_for_binding(&exact_expected(), &CancellationToken::new()),
        Err(BackendError::Unavailable)
    );
}

#[test]
fn cancellation_and_revocation_return_no_cache_status() {
    let fixture = fixture(true);
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    assert_eq!(
        fixture
            .backend
            .file_cache_status_for_binding(&exact_expected(), &cancelled),
        Err(BackendError::Cancelled)
    );

    fixture.backend.revoked.store(true, Ordering::Release);
    assert_eq!(
        fixture
            .backend
            .file_cache_status_for_binding(&exact_expected(), &CancellationToken::new()),
        Err(BackendError::Unavailable)
    );
}

#[test]
fn same_path_under_another_root_does_not_resolve_the_catalog_file() {
    let fixture = fixture(true);
    let same_path_other_root = expected(SPACE, "different-root", PATH, RESOURCE, ETAG, SIZE);
    assert_eq!(
        fixture
            .backend
            .file_cache_status_for_binding(&same_path_other_root, &CancellationToken::new()),
        Err(BackendError::NotFound)
    );
    assert_eq!(fixture.backend.state.lock().unwrap().files.len(), 1);
}

fn policy_listing(fixture: &Fixture) -> CacheScope {
    let scope = CacheScope::new(
        fixture.backend.scope.server_origin(),
        fixture.backend.scope.account_id(),
        SPACE,
        ROOT,
        ScopeProtection::PlaintextAllowed,
    )
    .unwrap();
    fixture
        .backend
        .cache
        .as_ref()
        .unwrap()
        .publish_listing(
            &scope,
            ROOT,
            &[raiun_cache::CachedEntry {
                parent_resource_id: ROOT.into(),
                entry: raiun_core::backend::RemoteEntry {
                    id: RESOURCE.into(),
                    path: PATH.into(),
                    etag: ETAG.into(),
                    size: SIZE,
                    directory: false,
                    modified_unix: 0,
                    writable: true,
                    encrypted: false,
                },
            }],
            1,
        )
        .unwrap();
    scope
}

#[test]
fn exact_binding_policy_evicts_only_clean_local_content_and_keeps_catalog_identity() {
    let fixture = fixture(true);
    let scope = policy_listing(&fixture);
    let cache = fixture.backend.cache.as_ref().unwrap();
    fixture
        .backend
        .set_file_cache_policy_for_binding(
            &exact_expected(),
            AvailabilityPolicy::Recent,
            &CancellationToken::new(),
        )
        .unwrap();
    let version = raiun_cache::ContentVersion {
        resource_id: RESOURCE.into(),
        etag: ETAG.into(),
        protection: raiun_cache::ContentProtection::Plaintext,
    };
    cache
        .publish_content(
            &scope,
            &version,
            &mut &b"hello world"[..],
            SIZE,
            raiun_cache::Retention::Recent,
        )
        .unwrap();
    assert!(
        fixture
            .backend
            .file_cache_status_for_binding(&exact_expected(), &CancellationToken::new())
            .unwrap()
            .recorded_complete_version
    );
    fixture
        .backend
        .set_file_cache_policy_for_binding(
            &exact_expected(),
            AvailabilityPolicy::CloudOnly,
            &CancellationToken::new(),
        )
        .unwrap();
    assert_eq!(
        cache.content_record(&scope, &version),
        Err(raiun_cache::CacheError::NotFound)
    );
    let status = fixture
        .backend
        .file_cache_status_for_binding(&exact_expected(), &CancellationToken::new())
        .unwrap();
    assert_eq!(status.policy, AvailabilityPolicy::CloudOnly);
    assert!(!status.recorded_complete_version);
    assert_eq!(fixture.catalog.upserts.load(Ordering::Relaxed), 0);
    assert_eq!(fixture.backend.state.lock().unwrap().files.len(), 1);
}

#[test]
fn binding_policy_rejects_stale_tuple_and_never_promises_always_offline() {
    let fixture = fixture(true);
    let scope = policy_listing(&fixture);
    for mismatch in [
        expected("other", ROOT, PATH, RESOURCE, ETAG, SIZE),
        expected(SPACE, "other", PATH, RESOURCE, ETAG, SIZE),
        expected(SPACE, ROOT, "/other", RESOURCE, ETAG, SIZE),
        expected(SPACE, ROOT, PATH, "other", ETAG, SIZE),
        expected(SPACE, ROOT, PATH, RESOURCE, "other", SIZE),
        expected(SPACE, ROOT, PATH, RESOURCE, ETAG, SIZE + 1),
    ] {
        assert!(
            fixture
                .backend
                .set_file_cache_policy_for_binding(
                    &mismatch,
                    AvailabilityPolicy::Recent,
                    &CancellationToken::new()
                )
                .is_err()
        );
    }
    assert!(
        fixture
            .backend
            .set_file_cache_policy_for_binding(
                &exact_expected(),
                AvailabilityPolicy::AlwaysOffline,
                &CancellationToken::new()
            )
            .is_err()
    );
    assert_eq!(
        fixture
            .backend
            .cache
            .as_ref()
            .unwrap()
            .policy(&scope, RESOURCE)
            .unwrap(),
        AvailabilityPolicy::CloudOnly
    );
}

#[test]
fn binding_policy_preserves_dirty_journal_and_bounds_callback_drain_wait() {
    let fixture = fixture(true);
    let scope = policy_listing(&fixture);
    let cache = fixture.backend.cache.as_ref().unwrap();
    fixture
        .backend
        .set_file_cache_policy_for_binding(
            &exact_expected(),
            AvailabilityPolicy::Recent,
            &CancellationToken::new(),
        )
        .unwrap();
    let write = cache
        .queue_conditional_write(
            &scope,
            raiun_cache::ConditionalWriteRequest {
                parent_resource_id: ROOT.into(),
                name: "report.txt".into(),
                logical_path: PATH.into(),
                resource_id: Some(RESOURCE.into()),
                base: raiun_core::backend::WriteCondition::Match(ETAG.into()),
                expected_len: SIZE,
                protection: raiun_cache::ContentProtection::Plaintext,
            },
            &mut &b"local edits"[..],
        )
        .unwrap();
    assert!(
        fixture
            .backend
            .set_file_cache_policy_for_binding(
                &exact_expected(),
                AvailabilityPolicy::CloudOnly,
                &CancellationToken::new()
            )
            .is_err()
    );
    assert_eq!(cache.pending_writes(&scope).unwrap(), vec![write]);
    assert_eq!(
        cache.policy(&scope, RESOURCE).unwrap(),
        AvailabilityPolicy::Recent
    );
    let _callback = fixture.backend.lease_gate.read().unwrap();
    let token = CancellationToken::with_timeout(std::time::Duration::from_millis(2));
    assert_eq!(
        fixture.backend.set_file_cache_policy_for_binding(
            &exact_expected(),
            AvailabilityPolicy::CloudOnly,
            &token
        ),
        Err(BackendError::Unavailable)
    );
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    assert_eq!(
        fixture.backend.set_file_cache_policy_for_binding(
            &exact_expected(),
            AvailabilityPolicy::CloudOnly,
            &cancelled
        ),
        Err(BackendError::Cancelled)
    );
}

#[test]
fn complete_callback_response_above_quota_skips_cache_without_failing_verified_read() {
    let fixture = fixture_with_quota(true, SIZE - 1);
    let _scope = policy_listing(&fixture);
    fixture
        .backend
        .set_file_cache_policy_for_binding(
            &exact_expected(),
            AvailabilityPolicy::Recent,
            &CancellationToken::new(),
        )
        .unwrap();
    let binding = fixture
        .backend
        .state
        .lock()
        .unwrap()
        .files
        .get(&fixture.identity)
        .unwrap()
        .clone();
    fixture
        .backend
        .publish_complete_cached_content(&binding, 0, b"hello world", &CancellationToken::new())
        .unwrap();
    let status = fixture
        .backend
        .file_cache_status_for_binding(&exact_expected(), &CancellationToken::new())
        .unwrap();
    assert_eq!(status.policy, AvailabilityPolicy::Recent);
    assert!(!status.recorded_complete_version);
    assert_eq!(
        fixture
            .backend
            .cache
            .as_ref()
            .unwrap()
            .usage()
            .unwrap()
            .used_bytes,
        0
    );
    assert_eq!(fixture.catalog.upserts.load(Ordering::Relaxed), 0);
}

#[test]
fn complete_callback_budget_reclaims_recent_but_preserves_dirty_when_cache_is_full() {
    for retention in [
        raiun_cache::Retention::Recent,
        raiun_cache::Retention::Dirty,
    ] {
        let fixture = fixture_with_quota(true, SIZE);
        let scope = policy_listing(&fixture);
        fixture
            .backend
            .set_file_cache_policy_for_binding(
                &exact_expected(),
                AvailabilityPolicy::Recent,
                &CancellationToken::new(),
            )
            .unwrap();
        let cache = fixture.backend.cache.as_ref().unwrap();
        let entry = |id: &str, path: &str, etag: &str| raiun_cache::CachedEntry {
            parent_resource_id: ROOT.into(),
            entry: raiun_core::backend::RemoteEntry {
                id: id.into(),
                path: path.into(),
                etag: etag.into(),
                directory: false,
                encrypted: false,
                size: SIZE,
                modified_unix: 0,
                writable: true,
            },
        };
        cache
            .publish_listing(
                &scope,
                ROOT,
                &[
                    entry(RESOURCE, PATH, ETAG),
                    entry("older", "/docs/old.txt", "\"old-v1\""),
                ],
                2,
            )
            .unwrap();
        let old = raiun_cache::ContentVersion {
            resource_id: "older".into(),
            etag: "\"old-v1\"".into(),
            protection: raiun_cache::ContentProtection::Plaintext,
        };
        cache
            .publish_content(&scope, &old, &mut &b"old version"[..], SIZE, retention)
            .unwrap();
        let binding = fixture
            .backend
            .state
            .lock()
            .unwrap()
            .files
            .get(&fixture.identity)
            .unwrap()
            .clone();
        fixture
            .backend
            .publish_complete_cached_content(&binding, 0, b"hello world", &CancellationToken::new())
            .unwrap();
        let status = fixture
            .backend
            .file_cache_status_for_binding(&exact_expected(), &CancellationToken::new())
            .unwrap();
        assert_eq!(
            status.recorded_complete_version,
            retention == raiun_cache::Retention::Recent
        );
        match retention {
            raiun_cache::Retention::Recent => assert_eq!(
                cache.content_record(&scope, &old),
                Err(raiun_cache::CacheError::NotFound)
            ),
            raiun_cache::Retention::Dirty => {
                assert_eq!(
                    cache.content_record(&scope, &old).unwrap().retention,
                    retention
                );
                let mut bytes = Vec::new();
                std::io::Read::read_to_end(
                    &mut cache.open_content(&scope, &old).unwrap(),
                    &mut bytes,
                )
                .unwrap();
                assert_eq!(bytes, b"old version");
            }
            _ => unreachable!(),
        }
        assert!(cache.usage().unwrap().used_bytes <= SIZE);
        assert_eq!(fixture.catalog.upserts.load(Ordering::Relaxed), 0);
        assert_eq!(fixture.backend.state.lock().unwrap().files.len(), 1);
    }
}

#[test]
fn listed_file_page_returns_exact_authenticated_rows_without_catalog_writes() {
    let fixture = fixture(true);
    let before = fixture.backend.state.lock().unwrap().files.clone();
    let page = fixture
        .backend
        .listed_file_page(None, &CancellationToken::new())
        .unwrap();
    assert_eq!(page.rows.len(), 1);
    assert_eq!(
        page.rows[0],
        super::ListedFileRow {
            space_id: SPACE.into(),
            root_resource_id: ROOT.into(),
            path: PATH.into(),
            resource_id: RESOURCE.into(),
            etag: ETAG.into(),
            size: SIZE,
        }
    );
    assert_eq!(page.next_cursor, None);
    assert_eq!(page.unavailable_rows, 0);
    assert!(page.read_only);
    assert!(page.last_observed);
    assert!(!page.atomic_snapshot);
    assert!(fixture.backend.state.lock().unwrap().files == before);
    assert_eq!(fixture.catalog.upserts.load(Ordering::Relaxed), 0);
}

#[test]
fn listed_file_page_rejects_malformed_unknown_cancelled_and_revoked_requests() {
    let fixture = fixture(true);
    for cursor in [
        Some("A".repeat(32)),
        Some("f".repeat(31)),
        Some("g".repeat(32)),
    ] {
        assert_eq!(
            fixture
                .backend
                .listed_file_page(cursor.as_deref(), &CancellationToken::new()),
            Err(BackendError::NotFound)
        );
    }
    let mut unknown = [0xff; 16];
    while fixture.identity.as_bytes() == &unknown {
        unknown[15] = unknown[15].wrapping_sub(1);
    }
    let cursor = unknown
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(
        fixture
            .backend
            .listed_file_page(Some(&cursor), &CancellationToken::new()),
        Err(BackendError::NotFound)
    );
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    assert_eq!(
        fixture.backend.listed_file_page(None, &cancelled),
        Err(BackendError::Cancelled)
    );

    let revoked = self::fixture(true);
    revoked.backend.revoked.store(true, Ordering::Release);
    assert_eq!(
        revoked
            .backend
            .listed_file_page(None, &CancellationToken::new()),
        Err(BackendError::Unavailable)
    );
}

#[test]
fn listed_file_page_marks_ambiguous_duplicate_bindings_unavailable() {
    let fixture = fixture(true);
    let binding = fixture
        .backend
        .state
        .lock()
        .unwrap()
        .files
        .get(&fixture.identity)
        .unwrap()
        .clone();
    let mut duplicate_bytes = [0xa5; 16];
    while OpaqueIdentity(duplicate_bytes) == fixture.identity {
        duplicate_bytes[15] = duplicate_bytes[15].wrapping_add(1);
    }
    fixture
        .backend
        .state
        .lock()
        .unwrap()
        .files
        .insert(OpaqueIdentity(duplicate_bytes), binding);

    let page = fixture
        .backend
        .listed_file_page(None, &CancellationToken::new())
        .unwrap();
    assert!(page.rows.is_empty());
    assert_eq!(page.unavailable_rows, 2);
    assert_eq!(page.next_cursor, None);
    assert_eq!(fixture.catalog.upserts.load(Ordering::Relaxed), 0);
}

#[test]
fn listed_file_page_stops_before_serialized_budget_and_resumes_without_skipping_candidates() {
    let fixture = fixture(true);
    {
        let mut state = fixture.backend.state.lock().unwrap();
        state.files.clear();
        for index in 1u8..=9 {
            state.files.insert(
                OpaqueIdentity([index; 16]),
                FileBinding {
                    space_id: SPACE.into(),
                    root_resource_id: format!("root-{}", "r".repeat(5_000)),
                    path: format!("/{}", "p".repeat(5_000)),
                    remote_id: format!("resource-{}-{index}", "q".repeat(5_000)),
                    etag: format!("etag-{}", "e".repeat(5_000)),
                    size: SIZE,
                },
            );
        }
    }

    let mut cursor: Option<String> = None;
    let mut observed = Vec::new();
    let mut page_count = 0;
    loop {
        let page = fixture
            .backend
            .listed_file_page(cursor.as_deref(), &CancellationToken::new())
            .unwrap();
        let encoded = serde_json::to_vec(&page).unwrap();
        assert!(encoded.len() <= 128 * 1024);
        assert!(page.rows.len() <= 8);
        observed.extend(page.rows.iter().map(|row| row.resource_id.clone()));
        cursor = page.next_cursor;
        page_count += 1;
        if cursor.is_none() {
            break;
        }
        assert!(page_count < 9, "cursor did not advance through candidates");
    }
    assert!(
        page_count >= 2,
        "large rows should exercise the byte budget"
    );
    assert_eq!(observed.len(), 9);
    observed.sort();
    observed.dedup();
    assert_eq!(
        observed.len(),
        9,
        "pagination must not skip or repeat a candidate"
    );
    assert_eq!(fixture.catalog.upserts.load(Ordering::Relaxed), 0);
}

#[test]
fn pending_offline_status_matches_only_current_path_and_version_after_cache_reopen() {
    let mut fixture = fixture(true);
    let scope = policy_listing(&fixture);
    let cache = fixture.backend.cache.as_ref().unwrap();
    cache
        .set_policy_at(&scope, RESOURCE, PATH, ETAG, AvailabilityPolicy::Recent)
        .unwrap();
    let version = raiun_cache::ContentVersion {
        resource_id: RESOURCE.into(),
        etag: ETAG.into(),
        protection: raiun_cache::ContentProtection::Plaintext,
    };
    cache
        .publish_content(
            &scope,
            &version,
            &mut &b"hello world"[..],
            SIZE,
            raiun_cache::Retention::Recent,
        )
        .unwrap();
    cache
        .set_policy_at(
            &scope,
            RESOURCE,
            PATH,
            ETAG,
            AvailabilityPolicy::AlwaysOffline,
        )
        .unwrap();
    assert!(
        !fixture
            .backend
            .file_cache_status_for_binding(&exact_expected(), &CancellationToken::new())
            .unwrap()
            .pending_offline_intent
    );
    cache
        .set_policy_refresh_state(
            &scope,
            RESOURCE,
            PATH,
            ETAG,
            raiun_cache::TargetState::Stale,
        )
        .unwrap();
    fixture.backend.cache = Some(Cache::open(fixture._temp.path(), 1024 * 1024).unwrap());
    let status = fixture
        .backend
        .file_cache_status_for_binding(&exact_expected(), &CancellationToken::new())
        .unwrap();
    assert!(status.pending_offline_intent);
    assert!(status.recorded_complete_version); // Metadata intent is independent of recorded bytes.
    let cache = fixture.backend.cache.as_ref().unwrap();
    for (path, etag) in [("/moved.txt", ETAG), (PATH, "different-version")] {
        cache
            .set_policy_refresh_state(
                &scope,
                RESOURCE,
                path,
                etag,
                raiun_cache::TargetState::Stale,
            )
            .unwrap();
        assert!(
            !fixture
                .backend
                .file_cache_status_for_binding(&exact_expected(), &CancellationToken::new())
                .unwrap()
                .pending_offline_intent
        );
    }
    cache
        .set_policy_refresh_state(
            &scope,
            RESOURCE,
            PATH,
            ETAG,
            raiun_cache::TargetState::Unavailable,
        )
        .unwrap();
    assert!(
        fixture
            .backend
            .file_cache_status_for_binding(&exact_expected(), &CancellationToken::new())
            .unwrap()
            .pending_offline_intent
    );
    assert_eq!(fixture.catalog.upserts.load(Ordering::Relaxed), 0);
    assert!(cache.content_record(&scope, &version).is_ok());
}

#[test]
fn device_quota_updates_persist_and_revoked_backends_cannot_change_them() {
    let f = fixture(true);
    let old = f.backend.device_cache_usage().unwrap().quota_bytes;
    assert!(f.backend.set_device_cache_quota(0).is_err());
    assert_eq!(f.backend.device_cache_usage().unwrap().quota_bytes, old);
    f.backend
        .set_device_cache_quota(5 * 1024 * 1024 * 1024)
        .unwrap();
    assert_eq!(
        f.backend.device_cache_usage().unwrap().quota_bytes,
        5 * 1024 * 1024 * 1024
    );
    f.backend.revoke();
    assert!(
        f.backend
            .set_device_cache_quota(1024 * 1024 * 1024)
            .is_err()
    );
    assert_eq!(
        f.backend
            .cache
            .as_ref()
            .unwrap()
            .usage()
            .unwrap()
            .quota_bytes,
        5 * 1024 * 1024 * 1024
    );
}
