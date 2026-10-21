// Engine-level regressions for recursive folder CloudOnly admission.

use super::*;
use raiun_cache::CachedListing;
use std::io::Read;

struct FolderPolicyFixture {
    _state: tempfile::TempDir,
    cloud: Arc<FakeCloud>,
    cache: Cache,
    engine: Engine,
    scope: CacheScope,
    sync: RemoteEntry,
}

fn fixture() -> FolderPolicyFixture {
    let state = tempfile::Builder::new()
        .prefix("raiun-folder-policy-")
        .tempdir()
        .expect("private state directory");
    #[cfg(unix)]
    fs::set_permissions(
        state.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .expect("set private state permissions");

    let cloud = Arc::new(FakeCloud::new());
    cloud.insert_dir("/sync/nested");
    cloud.insert_file("/sync/nested/old.txt", b"cached recent bytes");
    cloud.insert_file("/always.txt", b"always offline bytes");
    let cache = Cache::open(state.path(), 64 * 1024 * 1024).expect("open cache");
    let engine = Engine::open(state.path(), cloud.clone())
        .expect("open engine")
        .with_offline_cache(
            cache.clone(),
            "profile-account-1".into(),
            "https://example.invalid/".into(),
        )
        .expect("bind cache identity");

    // Seed the selected directory in its cached parent listing before applying
    // policy, matching the UI's path-to-entry flow.
    engine.list("space", "/").expect("cache root listing");
    let root = cloud.remote_entry("/").expect("root exists");
    let sync = cloud
        .remote_entry("/sync")
        .expect("selected directory exists");
    engine
        .list("space", "/sync")
        .expect("cache selected listing");
    engine
        .list("space", "/sync/nested")
        .expect("cache nested listing");
    let scope = cache
        .find_plaintext_scope("https://example.invalid/", "profile-account-1", "space")
        .expect("find registered scope")
        .expect("scope registered");
    // Confirm the seeded root listing actually contains this exact directory.
    assert!(
        cache
            .listing(&scope, &root.id)
            .unwrap()
            .entries
            .iter()
            .any(|row| row.entry == sync)
    );

    FolderPolicyFixture {
        _state: state,
        cloud,
        cache,
        engine,
        scope,
        sync,
    }
}

fn read_cached(f: &FolderPolicyFixture, entry: &RemoteEntry) -> Vec<u8> {
    read_version(
        f,
        &ContentVersion {
            resource_id: entry.id.clone(),
            etag: entry.etag.clone(),
            protection: ContentProtection::Plaintext,
        },
    )
}

fn read_version(f: &FolderPolicyFixture, version: &ContentVersion) -> Vec<u8> {
    let mut reader = f
        .cache
        .open_content(&f.scope, version)
        .expect("open cached version");
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).expect("read cached bytes");
    bytes
}

fn listings(f: &FolderPolicyFixture) -> Vec<(String, CachedListing)> {
    let root = f.cloud.remote_entry("/").unwrap();
    let nested = f.cloud.remote_entry("/sync/nested").unwrap();
    [root.id, f.sync.id.clone(), nested.id]
        .into_iter()
        .map(|id| (id.clone(), f.cache.listing(&f.scope, &id).unwrap()))
        .collect()
}

#[test]
fn cloud_only_recursively_evicts_recent_and_inherits_to_new_remote_descendants() {
    let f = fixture();
    let old = f.cloud.remote_entry("/sync/nested/old.txt").unwrap();
    f.engine
        .fetch_snapshot("space", &old.path)
        .expect("cache existing file as Recent");
    assert_eq!(read_cached(&f, &old), b"cached recent bytes");
    assert_eq!(f.cache.pins(&f.scope).unwrap().len(), 0);

    // These descendants arrive remotely after the cached /sync listing. The
    // collector must include their complete subtree in the policy admission.
    f.cloud.insert_dir("/sync/new-branch");
    f.cloud.insert_dir("/sync/new-branch/deep");
    f.cloud
        .insert_file("/sync/new-branch/deep/new.txt", b"remote only");
    let remote_before = f.cloud.entries.lock().unwrap().clone();
    let deletes_before = *f.cloud.delete_calls.lock().unwrap();

    f.engine
        .set_availability_policy("space", "/sync", AvailabilityPolicy::CloudOnly)
        .expect("admit recursive CloudOnly policy");

    assert_eq!(
        f.cache.policy(&f.scope, &old.id).unwrap(),
        AvailabilityPolicy::CloudOnly
    );
    assert!(matches!(
        f.cache.content_record(
            &f.scope,
            &ContentVersion {
                resource_id: old.id.clone(),
                etag: old.etag.clone(),
                protection: ContentProtection::Plaintext,
            }
        ),
        Err(raiun_cache::CacheError::NotFound)
    ));
    let new = f
        .cloud
        .remote_entry("/sync/new-branch/deep/new.txt")
        .unwrap();
    assert_eq!(
        f.cache.policy(&f.scope, &new.id).unwrap(),
        AvailabilityPolicy::CloudOnly,
        "newly discovered descendants inherit the folder intent"
    );
    assert_eq!(*f.cloud.delete_calls.lock().unwrap(), deletes_before);
    assert_eq!(*f.cloud.downloads.lock().unwrap(), 1);
    assert_eq!(*f.cloud.entries.lock().unwrap(), remote_before);
}

#[test]
fn recent_clears_only_folder_intent_and_preserves_file_policy_and_dirty_bytes() {
    let f = fixture();
    let old = f.cloud.remote_entry("/sync/nested/old.txt").unwrap();
    f.engine
        .fetch_snapshot("space", &old.path)
        .expect("cache child content");
    f.engine
        .set_availability_policy("space", "/always.txt", AvailabilityPolicy::AlwaysOffline)
        .expect("set sibling file policy");
    let always = f.cloud.remote_entry("/always.txt").unwrap();
    let mut edited = f.engine.fetch_snapshot("space", &always.path).unwrap();
    let mut always_bytes = Vec::new();
    edited.read_to_end(&mut always_bytes).unwrap();
    assert_eq!(always_bytes, b"always offline bytes");

    f.engine
        .set_availability_policy("space", "/sync", AvailabilityPolicy::CloudOnly)
        .expect("set folder intent");
    let downloads_before_clear = *f.cloud.downloads.lock().unwrap();
    f.engine
        .set_availability_policy("space", "/sync", AvailabilityPolicy::Recent)
        .expect("clear only selected folder intent");

    assert_eq!(
        f.cache.policy(&f.scope, &old.id).unwrap(),
        AvailabilityPolicy::Recent
    );
    assert_eq!(
        f.cache.policy(&f.scope, &always.id).unwrap(),
        AvailabilityPolicy::AlwaysOffline
    );
    assert_eq!(*f.cloud.downloads.lock().unwrap(), downloads_before_clear);
    assert!(matches!(
        f.cache.content_record(
            &f.scope,
            &ContentVersion {
                resource_id: old.id.clone(),
                etag: old.etag.clone(),
                protection: ContentProtection::Plaintext,
            }
        ),
        Err(raiun_cache::CacheError::NotFound)
    ));
    assert_eq!(*f.cloud.downloads.lock().unwrap(), downloads_before_clear);
    // Clearing policy only permits a future ordinary fetch; it does not
    // restore bytes removed when CloudOnly was admitted.
    f.engine
        .fetch_snapshot("space", &old.path)
        .expect("Recent content may be fetched again after clearing intent");
    assert_eq!(
        *f.cloud.downloads.lock().unwrap(),
        downloads_before_clear + 1
    );
    assert_eq!(read_cached(&f, &old), b"cached recent bytes");
    assert_eq!(read_cached(&f, &always), b"always offline bytes");

    // A dirty edit is independent of a folder's inherited setting. Clearing
    // the folder rule must leave that dirty state and its bytes intact.
    let request = ConditionalWriteRequest {
        parent_resource_id: f.cloud.remote_entry("/").unwrap().id,
        name: "always.txt".into(),
        logical_path: "/always.txt".into(),
        resource_id: Some(always.id.clone()),
        base: WriteCondition::Match(always.etag.clone()),
        expected_len: b"dirty edit".len() as u64,
        protection: ContentProtection::Plaintext,
    };
    f.cache
        .queue_conditional_write(&f.scope, request, &mut &b"dirty edit"[..])
        .expect("queue dirty sibling edit");
    let pending_before = f.cache.pending_writes(&f.scope).unwrap();
    let dirty_version = pending_before[0].content.clone();
    assert_eq!(read_version(&f, &dirty_version), b"dirty edit");

    f.engine
        .set_availability_policy("space", "/sync", AvailabilityPolicy::CloudOnly)
        .expect("CloudOnly folder admission with unrelated dirty file");
    f.engine
        .set_availability_policy("space", "/sync", AvailabilityPolicy::Recent)
        .expect("clear folder intent again");
    assert_eq!(f.cache.pending_writes(&f.scope).unwrap(), pending_before);
    assert_eq!(read_version(&f, &dirty_version), b"dirty edit");
    assert_eq!(read_cached(&f, &always), b"always offline bytes");
    assert_eq!(
        f.cache.policy(&f.scope, &always.id).unwrap(),
        AvailabilityPolicy::AlwaysOffline
    );
}

#[test]
fn dirty_descendant_refusal_does_not_publish_collected_listings_or_evict_content() {
    let f = fixture();
    let child = f.cloud.remote_entry("/sync/nested/old.txt").unwrap();
    f.engine
        .fetch_snapshot("space", &child.path)
        .expect("cache child content");
    let nested = f.cloud.remote_entry("/sync/nested").unwrap();
    let request = ConditionalWriteRequest {
        parent_resource_id: nested.id.clone(),
        name: "old.txt".into(),
        logical_path: child.path.clone(),
        resource_id: Some(child.id.clone()),
        base: WriteCondition::Match(child.etag.clone()),
        expected_len: b"dirty edit".len() as u64,
        protection: ContentProtection::Plaintext,
    };
    f.cache
        .queue_conditional_write(&f.scope, request, &mut &b"dirty edit"[..])
        .expect("queue dirty descendant edit");
    let before_listings = listings(&f);
    let before_pending = f.cache.pending_writes(&f.scope).unwrap();
    let before_pins = f.cache.pins(&f.scope).unwrap();
    let before_cloud = f.cloud.entries.lock().unwrap().clone();
    let before_downloads = *f.cloud.downloads.lock().unwrap();
    let before_deletes = *f.cloud.delete_calls.lock().unwrap();
    let before_content = read_cached(&f, &child);

    let error = f
        .engine
        .set_availability_policy("space", "/sync", AvailabilityPolicy::CloudOnly)
        .expect_err("dirty descendant must refuse CloudOnly");
    assert!(matches!(
        error.kind,
        ErrorKind::Conflict | ErrorKind::InvalidResponse
    ));

    assert_eq!(
        listings(&f),
        before_listings,
        "collector must not publish listings"
    );
    assert_eq!(f.cache.pending_writes(&f.scope).unwrap(), before_pending);
    assert_eq!(f.cache.pins(&f.scope).unwrap(), before_pins);
    assert_eq!(read_cached(&f, &child), before_content);
    assert_eq!(*f.cloud.downloads.lock().unwrap(), before_downloads);
    assert_eq!(*f.cloud.delete_calls.lock().unwrap(), before_deletes);
    assert_eq!(*f.cloud.entries.lock().unwrap(), before_cloud);
    assert_eq!(
        f.cache.policy(&f.scope, &child.id).unwrap(),
        AvailabilityPolicy::Recent,
        "failed admission leaves the prior policy visible"
    );
}

#[test]
fn ready_pin_refusal_preserves_pin_generation_and_cached_bytes() {
    let f = fixture();
    let pin = f
        .engine
        .pin_offline_tree("space", "/sync", |_| {})
        .expect("create ready selected-folder pin");
    assert_eq!(pin.state, PinState::Ready);
    let child = f.cloud.remote_entry("/sync/nested/old.txt").unwrap();
    let before_listings = listings(&f);
    let before_pins = f.cache.pins(&f.scope).unwrap();
    assert_eq!(before_pins.len(), 1);
    assert_eq!(before_pins[0].state, PinState::Ready);
    let before_downloads = *f.cloud.downloads.lock().unwrap();
    let before_deletes = *f.cloud.delete_calls.lock().unwrap();
    let before_cloud = f.cloud.entries.lock().unwrap().clone();
    let before_content = read_cached(&f, &child);

    let error = f
        .engine
        .set_availability_policy("space", "/sync", AvailabilityPolicy::CloudOnly)
        .expect_err("a ready recursive pin protects its subtree");
    assert!(matches!(
        error.kind,
        ErrorKind::Conflict | ErrorKind::InvalidResponse
    ));

    assert_eq!(listings(&f), before_listings);
    assert_eq!(f.cache.pins(&f.scope).unwrap(), before_pins);
    assert_eq!(read_cached(&f, &child), before_content);
    assert_eq!(*f.cloud.downloads.lock().unwrap(), before_downloads);
    assert_eq!(*f.cloud.delete_calls.lock().unwrap(), before_deletes);
    assert_eq!(*f.cloud.entries.lock().unwrap(), before_cloud);
    assert_eq!(f.cache.refresh_pin(&pin.id).unwrap().state, PinState::Ready);
}

#[test]
fn collection_failure_leaves_cached_metadata_unchanged() {
    let f = fixture();
    let child = f.cloud.remote_entry("/sync/nested/old.txt").unwrap();
    f.engine.fetch_snapshot("space", &child.path).unwrap();
    let before_listings = listings(&f);
    let before_cloud = f.cloud.entries.lock().unwrap().clone();
    let before_content = read_cached(&f, &child);
    *f.cloud.fail_listing.lock().unwrap() = true;

    let error = f
        .engine
        .set_availability_policy("space", "/sync", AvailabilityPolicy::CloudOnly)
        .expect_err("failed live listing must abort before publication");
    assert_eq!(error.kind, ErrorKind::Offline);
    assert_eq!(listings(&f), before_listings);
    assert_eq!(read_cached(&f, &child), before_content);
    assert_eq!(*f.cloud.entries.lock().unwrap(), before_cloud);
    assert_eq!(f.cache.pins(&f.scope).unwrap().len(), 0);
}

#[test]
fn encrypted_sibling_still_consumes_the_traversal_entry_budget_before_filtering() {
    let f = fixture();
    f.cloud.insert_dir("/encrypted-parent");
    f.cloud.insert_file("/encrypted-parent/secret", b"opaque");
    f.engine.list("space", "/").expect("cache parent listing");
    f.engine
        .list("space", "/encrypted-parent")
        .expect("cache child listing baseline");
    let parent = f.cloud.remote_entry("/encrypted-parent").unwrap();
    {
        let mut entries = f.cloud.entries.lock().unwrap();
        let (secret, _) = entries.get_mut("/encrypted-parent/secret").unwrap();
        secret.encrypted = true;
    }
    let cached_before = f.cache.listing(&f.scope, &parent.id).unwrap();
    let mut total_entries = MAX_LIST_ENTRIES;
    let mut metadata_bytes = 0;

    let error = f
        .engine
        .collect_folder_policy_listing(
            "space",
            &f.scope,
            &parent,
            false,
            &mut total_entries,
            &mut metadata_bytes,
        )
        .expect_err("encrypted sibling must count toward aggregate traversal work");

    assert_eq!(error.kind, ErrorKind::Unsupported);
    assert_eq!(total_entries, MAX_LIST_ENTRIES + 1);
    assert_eq!(
        f.cache.listing(&f.scope, &parent.id).unwrap(),
        cached_before,
        "failed collection must not publish a cache generation"
    );
}
