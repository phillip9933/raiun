use super::*;
use raiun_cache::{ContentProtection, ContentVersion, Retention};
use std::io::Read;

fn version() -> ContentVersion {
    ContentVersion {
        resource_id: RESOURCE.into(),
        etag: ETAG.into(),
        protection: ContentProtection::Plaintext,
    }
}

fn cache(fixture: &Fixture) -> &Cache {
    fixture.backend.cache.as_ref().unwrap()
}

fn publish_cached_body(fixture: &Fixture, scope: &CacheScope) {
    cache(fixture)
        .publish_content(
            scope,
            &version(),
            &mut &b"hello world"[..],
            SIZE,
            Retention::Recent,
        )
        .unwrap();
}

fn cached_body(fixture: &Fixture, scope: &CacheScope) -> Vec<u8> {
    let mut reader = cache(fixture).open_content(scope, &version()).unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    bytes
}

/// The verification hook runs after full local verification and before the
/// final lease/intent commit. These try-locks prove it holds no backend state,
/// callback lease, token-generation, or cache database lock.
fn assert_verification_released_guards(fixture: &Fixture) {
    let lease = fixture
        .backend
        .lease_gate
        .try_write()
        .expect("offline body verification must not hold the backend lease");
    drop(lease);

    let token = fixture
        .backend
        .client
        .try_lock_token_generation(fixture.backend.token_generation)
        .unwrap()
        .expect("offline body verification must not hold the token lock");
    drop(token);

    let state = fixture
        .backend
        .state
        .try_lock()
        .expect("offline body verification must not hold backend state");
    drop(state);

    cache(fixture)
        .usage()
        .expect("offline body verification must not hold the cache database");
}

#[test]
fn cached_success_commits_ready_without_any_network_request_or_new_body() {
    let fixture = fixture(true);
    let scope = policy_listing(&fixture);
    let cache = cache(&fixture);
    cache
        .set_policy_at(&scope, RESOURCE, PATH, ETAG, AvailabilityPolicy::Recent)
        .unwrap();
    publish_cached_body(&fixture, &scope);
    let before = cache.content_record(&scope, &version()).unwrap();

    let record = fixture
        .backend
        .download_file_offline_with_test_hook(&exact_expected(), &CancellationToken::new(), || {
            assert_verification_released_guards(&fixture)
        })
        .unwrap();

    assert_eq!(record, before);
    assert_eq!(cached_body(&fixture, &scope), b"hello world");
    assert_eq!(
        cache.policy(&scope, RESOURCE).unwrap(),
        AvailabilityPolicy::AlwaysOffline
    );
    assert_eq!(
        cache.policy_target_state(&scope, RESOURCE).unwrap(),
        Some(raiun_cache::TargetState::Ready)
    );
    assert_eq!(fixture.catalog.upserts.load(Ordering::Relaxed), 0);
}

#[test]
fn token_generation_change_after_verification_prevents_ready_commit() {
    let fixture = fixture(true);
    let scope = policy_listing(&fixture);
    let cache = cache(&fixture);
    cache
        .set_policy_at(&scope, RESOURCE, PATH, ETAG, AvailabilityPolicy::Recent)
        .unwrap();
    publish_cached_body(&fixture, &scope);

    let result = fixture.backend.download_file_offline_with_test_hook(
        &exact_expected(),
        &CancellationToken::new(),
        || {
            assert_verification_released_guards(&fixture);
            fixture
                .backend
                .client
                .set_bearer_token("rotated-synthetic-token".into())
                .unwrap();
        },
    );

    assert!(matches!(
        result,
        Err(OfflineDownloadError::Backend(BackendError::Unavailable))
    ));
    assert_eq!(cached_body(&fixture, &scope), b"hello world");
    assert_eq!(
        cache.policy(&scope, RESOURCE).unwrap(),
        AvailabilityPolicy::AlwaysOffline
    );
    assert_eq!(
        cache.policy_target_state(&scope, RESOURCE).unwrap(),
        Some(raiun_cache::TargetState::Stale)
    );
}

#[test]
fn backend_revocation_after_verification_prevents_ready_commit_and_keeps_cached_bytes() {
    let fixture = fixture(true);
    let scope = policy_listing(&fixture);
    let cache = cache(&fixture);
    cache
        .set_policy_at(&scope, RESOURCE, PATH, ETAG, AvailabilityPolicy::Recent)
        .unwrap();
    publish_cached_body(&fixture, &scope);

    let result = fixture.backend.download_file_offline_with_test_hook(
        &exact_expected(),
        &CancellationToken::new(),
        || {
            assert_verification_released_guards(&fixture);
            fixture.backend.revoke();
        },
    );

    assert!(matches!(
        result,
        Err(OfflineDownloadError::Backend(BackendError::Unavailable))
    ));
    assert!(fixture.backend.is_revoked());
    assert_eq!(cached_body(&fixture, &scope), b"hello world");
    assert_eq!(
        cache.policy(&scope, RESOURCE).unwrap(),
        AvailabilityPolicy::AlwaysOffline
    );
    assert_eq!(
        cache.policy_target_state(&scope, RESOURCE).unwrap(),
        Some(raiun_cache::TargetState::Stale)
    );
}

#[test]
fn changed_live_file_root_binding_after_verification_prevents_ready_commit() {
    let fixture = fixture(true);
    let scope = policy_listing(&fixture);
    let cache = cache(&fixture);
    cache
        .set_policy_at(&scope, RESOURCE, PATH, ETAG, AvailabilityPolicy::Recent)
        .unwrap();
    publish_cached_body(&fixture, &scope);

    let result = fixture.backend.download_file_offline_with_test_hook(
        &exact_expected(),
        &CancellationToken::new(),
        || {
            assert_verification_released_guards(&fixture);
            let mut state = fixture.backend.state.try_lock().unwrap();
            state
                .files
                .get_mut(&fixture.identity)
                .expect("registered synthetic file remains present")
                .root_resource_id = "replaced-root".into();
        },
    );

    assert!(matches!(
        result,
        Err(OfflineDownloadError::Backend(BackendError::NotFound))
    ));
    assert_eq!(cached_body(&fixture, &scope), b"hello world");
    assert_eq!(
        cache.policy(&scope, RESOURCE).unwrap(),
        AvailabilityPolicy::AlwaysOffline
    );
    assert_eq!(
        cache.policy_target_state(&scope, RESOURCE).unwrap(),
        Some(raiun_cache::TargetState::Stale)
    );
}

#[test]
fn newer_recent_policy_intent_after_verification_prevents_ready_commit() {
    let fixture = fixture(true);
    let scope = policy_listing(&fixture);
    let cache = cache(&fixture);
    cache
        .set_policy_at(&scope, RESOURCE, PATH, ETAG, AvailabilityPolicy::Recent)
        .unwrap();
    publish_cached_body(&fixture, &scope);

    let result = fixture.backend.download_file_offline_with_test_hook(
        &exact_expected(),
        &CancellationToken::new(),
        || {
            assert_verification_released_guards(&fixture);
            fixture
                .backend
                .set_file_cache_policy_for_binding(
                    &exact_expected(),
                    AvailabilityPolicy::Recent,
                    &CancellationToken::new(),
                )
                .unwrap();
        },
    );

    assert!(matches!(
        result,
        Err(OfflineDownloadError::Backend(BackendError::Unavailable))
    ));
    assert_eq!(cached_body(&fixture, &scope), b"hello world");
    assert_eq!(
        cache.policy(&scope, RESOURCE).unwrap(),
        AvailabilityPolicy::Recent
    );
    assert_eq!(cache.policy_target_state(&scope, RESOURCE).unwrap(), None);
}

#[test]
fn cancellation_after_verification_prevents_ready_commit_and_keeps_cached_bytes() {
    let fixture = fixture(true);
    let scope = policy_listing(&fixture);
    let cache = cache(&fixture);
    cache
        .set_policy_at(&scope, RESOURCE, PATH, ETAG, AvailabilityPolicy::Recent)
        .unwrap();
    publish_cached_body(&fixture, &scope);
    let cancellation = CancellationToken::new();

    let result = fixture.backend.download_file_offline_with_test_hook(
        &exact_expected(),
        &cancellation,
        || {
            assert_verification_released_guards(&fixture);
            cancellation.cancel();
        },
    );

    assert!(matches!(
        result,
        Err(OfflineDownloadError::Backend(BackendError::Cancelled))
    ));
    assert_eq!(cached_body(&fixture, &scope), b"hello world");
    assert_eq!(
        cache.policy(&scope, RESOURCE).unwrap(),
        AvailabilityPolicy::AlwaysOffline
    );
    assert_eq!(
        cache.policy_target_state(&scope, RESOURCE).unwrap(),
        Some(raiun_cache::TargetState::Stale)
    );
}

#[test]
fn cancellation_after_final_commit_admission_allows_durable_ready_completion() {
    let fixture = fixture(true);
    let scope = policy_listing(&fixture);
    let cache = cache(&fixture);
    cache
        .set_policy_at(&scope, RESOURCE, PATH, ETAG, AvailabilityPolicy::Recent)
        .unwrap();
    publish_cached_body(&fixture, &scope);
    let cancellation = CancellationToken::new();

    let record = fixture
        .backend
        .download_file_offline_with_commit_hook(&exact_expected(), &cancellation, || {
            cancellation.cancel()
        })
        .expect("completion admitted before the later cancellation should win");

    assert!(cancellation.is_cancelled());
    assert_eq!(record, cache.content_record(&scope, &version()).unwrap());
    assert_eq!(cached_body(&fixture, &scope), b"hello world");
    assert_eq!(
        cache.policy(&scope, RESOURCE).unwrap(),
        AvailabilityPolicy::AlwaysOffline
    );
    assert_eq!(
        cache.policy_target_state(&scope, RESOURCE).unwrap(),
        Some(raiun_cache::TargetState::Ready)
    );
    assert_eq!(fixture.catalog.upserts.load(Ordering::Relaxed), 0);
}

#[test]
fn revoked_backend_before_admission_creates_no_offline_intent() {
    let fixture = fixture(true);
    let scope = policy_listing(&fixture);
    let cache = cache(&fixture);
    assert_eq!(
        cache.policy(&scope, RESOURCE).unwrap(),
        AvailabilityPolicy::CloudOnly
    );
    assert_eq!(cache.policy_target_state(&scope, RESOURCE).unwrap(), None);
    assert_eq!(cache.usage().unwrap().used_bytes, 0);

    fixture.backend.revoke();
    let result = fixture.backend.download_file_offline_with_test_hook(
        &exact_expected(),
        &CancellationToken::new(),
        || panic!("revoked backend must reject before verification"),
    );

    assert!(matches!(
        result,
        Err(OfflineDownloadError::Backend(BackendError::Unavailable))
    ));
    assert_eq!(
        cache.policy(&scope, RESOURCE).unwrap(),
        AvailabilityPolicy::CloudOnly
    );
    assert_eq!(cache.policy_target_state(&scope, RESOURCE).unwrap(), None);
    assert_eq!(cache.usage().unwrap().used_bytes, 0);
    assert_eq!(fixture.catalog.upserts.load(Ordering::Relaxed), 0);
}

fn cached_folder_pin(fixture: &Fixture) -> (CacheScope, raiun_cache::PinInfo) {
    let scope = policy_listing(fixture);
    let cache = cache(fixture);
    let file = cache.listing(&scope, ROOT).unwrap().entries[0]
        .entry
        .clone();
    cache
        .publish_listing(
            &scope,
            ROOT,
            &[raiun_cache::CachedEntry {
                parent_resource_id: ROOT.into(),
                entry: raiun_core::backend::RemoteEntry {
                    id: "docs".into(),
                    path: "/docs".into(),
                    etag: "directory-v1".into(),
                    size: 0,
                    directory: true,
                    modified_unix: 0,
                    writable: true,
                    encrypted: false,
                },
            }],
            2,
        )
        .unwrap();
    cache
        .publish_listing(
            &scope,
            "docs",
            &[raiun_cache::CachedEntry {
                parent_resource_id: "docs".into(),
                entry: file.clone(),
            }],
            2,
        )
        .unwrap();
    cache
        .set_policy_at(&scope, RESOURCE, PATH, ETAG, AvailabilityPolicy::Recent)
        .unwrap();
    publish_cached_body(fixture, &scope);
    let pin = cache
        .begin_pin_manifest_at_cancellable(
            &scope,
            "docs",
            "/docs",
            &[raiun_cache::PinManifestEntry {
                parent_resource_id: "docs".into(),
                entry: file,
            }],
            || false,
        )
        .unwrap();
    (scope, pin)
}

#[test]
fn cached_folder_member_keeps_recent_policy_and_requires_live_pin() {
    let fixture = fixture(true);
    let (scope, pin) = cached_folder_pin(&fixture);
    let cache = cache(&fixture);
    let before = cache.content_record(&scope, &version()).unwrap();
    let record = fixture
        .backend
        .download_pinned_file_offline_for_binding(
            &exact_expected(),
            &pin.id,
            &CancellationToken::new(),
        )
        .unwrap();
    assert_eq!(record, before);
    assert_eq!(
        cache.policy(&scope, RESOURCE).unwrap(),
        AvailabilityPolicy::Recent
    );
    assert_eq!(cache.policy_target_state(&scope, RESOURCE).unwrap(), None);
    assert_eq!(
        cache.refresh_pin(&pin.id).unwrap().state,
        raiun_cache::PinState::Ready
    );
    assert_eq!(cache.evict_recent(0).unwrap().removed_bytes, 0);
    cache.cancel_pin_for_scope(&scope, &pin.id).unwrap();
    assert!(matches!(
        fixture.backend.download_pinned_file_offline_for_binding(
            &exact_expected(),
            &pin.id,
            &CancellationToken::new(),
        ),
        Err(OfflineDownloadError::Backend(BackendError::Unavailable))
    ));
    assert_eq!(cached_body(&fixture, &scope), b"hello world");
    assert_eq!(cache.evict_recent(0).unwrap().removed_bytes, SIZE);
}

#[test]
fn folder_pin_removed_after_unlocked_verification_refuses_commit_preserving_bytes() {
    let fixture = fixture(true);
    let (scope, pin) = cached_folder_pin(&fixture);
    let result = fixture.backend.download_pinned_file_with_test_hook(
        &exact_expected(),
        &pin.id,
        &CancellationToken::new(),
        || {
            assert_verification_released_guards(&fixture);
            cache(&fixture)
                .cancel_pin_for_scope(&scope, &pin.id)
                .unwrap();
        },
    );
    assert!(matches!(
        result,
        Err(OfflineDownloadError::Backend(BackendError::Unavailable))
    ));
    assert_eq!(
        cache(&fixture).policy(&scope, RESOURCE).unwrap(),
        AvailabilityPolicy::Recent
    );
    assert_eq!(cached_body(&fixture, &scope), b"hello world");
    assert_eq!(fixture.catalog.upserts.load(Ordering::Relaxed), 0);
}
