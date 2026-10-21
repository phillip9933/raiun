use super::*;
use std::io::Cursor;

fn pinned_entry(id: &str, etag: &str, body_len: u64) -> CachedEntry {
    CachedEntry {
        parent_resource_id: "root-a".into(),
        entry: RemoteEntry {
            id: id.into(),
            path: "/pinned.txt".into(),
            etag: etag.into(),
            size: body_len,
            directory: false,
            modified_unix: 1,
            writable: true,
            encrypted: false,
        },
    }
}

fn ready_pin(cache: &Cache, scope: &CacheScope, item: &CachedEntry, body: &[u8]) -> PinInfo {
    cache
        .publish_listing(scope, "root-a", std::slice::from_ref(item), 10)
        .unwrap();
    let pin = cache
        .begin_pin(
            scope,
            "root-a",
            &[PinManifestEntry {
                parent_resource_id: "root-a".into(),
                entry: item.entry.clone(),
            }],
        )
        .unwrap();
    cache
        .publish_content(
            scope,
            &ContentVersion {
                resource_id: item.entry.id.clone(),
                etag: item.entry.etag.clone(),
                protection: ContentProtection::Plaintext,
            },
            &mut Cursor::new(body),
            body.len() as u64,
            Retention::Recent,
        )
        .unwrap();
    cache.refresh_pin(&pin.id).unwrap()
}

#[test]
fn listing_publication_transaction_rollback_preserves_generation_entries_and_pin() {
    let (_temp, cache) = cache();
    let scope = scope(ScopeProtection::PlaintextAllowed);
    let old = pinned_entry("file-pin", "etag-1", 4);
    let pin = ready_pin(&cache, &scope, &old, b"base");
    assert_eq!(pin.state, PinState::Ready);
    let prior = cache.listing(&scope, "root-a").unwrap();
    assert_eq!(prior.generation, 1);

    let replacement = pinned_entry("file-pin", "etag-2", 5);
    {
        let db = cache.lock_db().unwrap();
        let tx = db.unchecked_transaction().unwrap();
        let staged = super::super::listing_publication::publish_listing_in_transaction(
            &tx,
            &scope,
            "root-a",
            std::slice::from_ref(&replacement),
            20,
        )
        .unwrap();
        assert_eq!(staged.generation, 2);
        // Simulate a later policy/protection refusal by dropping the caller's
        // transaction instead of committing the staged metadata.
    }

    let after_rollback = cache.listing(&scope, "root-a").unwrap();
    assert_eq!(after_rollback, prior);
    assert_eq!(cache.pin_info(&pin.id).unwrap().state, PinState::Ready);

    let db = cache.lock_db().unwrap();
    let tx = db.unchecked_transaction().unwrap();
    let committed = super::super::listing_publication::publish_listing_in_transaction(
        &tx,
        &scope,
        "root-a",
        std::slice::from_ref(&replacement),
        21,
    )
    .unwrap();
    assert_eq!(committed.generation, 2);
    tx.commit().unwrap();
    drop(db);

    let after_commit = cache.listing(&scope, "root-a").unwrap();
    assert_eq!(after_commit.generation, 2);
    assert_eq!(after_commit.fetched_at_unix, 21);
    assert_eq!(after_commit.entries, vec![replacement]);
    assert_eq!(cache.pin_info(&pin.id).unwrap().state, PinState::Stale);
}
