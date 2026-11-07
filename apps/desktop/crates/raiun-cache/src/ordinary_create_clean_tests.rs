use super::*;
use std::io::Cursor;
fn fixture() -> (tempfile::TempDir, Cache, CacheScope) {
    let dir = tempfile::tempdir().unwrap();
    set_private_dir(dir.path()).unwrap();
    let cache = Cache::open(dir.path(), 1024 * 1024).unwrap();
    let scope = CacheScope::new(
        "https://cloud.example.test/",
        "account",
        "space",
        "root",
        ScopeProtection::PlaintextAllowed,
    )
    .unwrap();
    (dir, cache, scope)
}
fn request(id: u32, path: &str) -> OrdinaryCreateRequest {
    OrdinaryCreateRequest {
        max_pending_bytes: 1024 * 1024,
        handoff_id: format!("{id:032x}"),
        parent_resource_id: "root".into(),
        name: path.rsplit('/').next().unwrap().into(),
        logical_path: path.into(),
        expected_len: 4,
        expected_sha256: format!("{:x}", Sha256::digest(b"body")),
    }
}
fn make_ready(cache: &Cache, scope: &CacheScope, id: u32) -> OrdinaryCreateReceipt {
    let r = cache
        .stage_ordinary_create(
            scope,
            request(id, &format!("/file{id}")),
            &mut Cursor::new(b"body"),
        )
        .unwrap();
    cache.admit_ordinary_create(scope, &r).unwrap()
}
fn complete(cache: &Cache, scope: &CacheScope, r: &OrdinaryCreateReceipt) -> OrdinaryCreateReceipt {
    let claim = cache.claim_ordinary_create(scope, r).unwrap().unwrap();
    let remote = RemoteEntry {
        id: format!("real-{}", r.write.id),
        path: r.write.logical_path.clone(),
        etag: "\"verified\"".into(),
        size: 4,
        directory: false,
        modified_unix: 1,
        writable: true,
        encrypted: false,
    };
    cache
        .complete_ordinary_create(scope, &claim, &remote, &r.sha256)
        .unwrap()
}
fn clean(cache: &Cache, scope: &CacheScope, id: u32) -> OrdinaryCreateReceipt {
    let r = make_ready(cache, scope, id);
    cache
        .acknowledge_ordinary_create_handoff(scope, &r)
        .unwrap();
    complete(cache, scope, &r)
}
fn read(cache: &Cache, scope: &CacheScope, r: &OrdinaryCreateReceipt) -> Vec<u8> {
    let mut out = Vec::new();
    cache
        .open_content(scope, &r.write.content)
        .unwrap()
        .read_to_end(&mut out)
        .unwrap();
    out
}
fn gc(cache: &Cache, scope: &CacheScope) -> EvictionReport {
    cache
        .evict_acknowledged_ordinary_create_bodies(scope, 0, 64)
        .unwrap()
}
#[test]
fn ack_and_remote_completion_commute_even_during_claim() {
    let (_dir, cache, s) = fixture();
    let a = make_ready(&cache, &s, 1);
    let a = cache.acknowledge_ordinary_create_handoff(&s, &a).unwrap();
    assert!(a.local_handoff_acknowledged);
    assert_eq!(gc(&cache, &s).removed_bytes, 0);
    complete(&cache, &s, &a);
    let b = make_ready(&cache, &s, 2);
    let b = complete(&cache, &s, &b);
    assert!(!b.local_handoff_acknowledged);
    let report = gc(&cache, &s);
    assert_eq!(report.removed_bytes, 4);
    assert_eq!(read(&cache, &s, &b), b"body");
    cache.acknowledge_ordinary_create_handoff(&s, &b).unwrap();
    let c = make_ready(&cache, &s, 3);
    let claim = cache.claim_ordinary_create(&s, &c).unwrap().unwrap();
    cache.acknowledge_ordinary_create_handoff(&s, &c).unwrap();
    let entry = RemoteEntry {
        id: "real-c".into(),
        path: c.write.logical_path.clone(),
        etag: "\"ok\"".into(),
        size: 4,
        directory: false,
        modified_unix: 1,
        writable: true,
        encrypted: false,
    };
    assert!(
        cache
            .complete_ordinary_create(&s, &claim, &entry, &c.sha256)
            .unwrap()
            .local_handoff_acknowledged
    );
    assert_eq!(gc(&cache, &s).removed_bytes, 8);
}
#[test]
fn evicted_receipt_history_reopens_and_retry_never_republishes() {
    let (dir, cache, s) = fixture();
    let r = clean(&cache, &s, 1);
    assert_eq!(gc(&cache, &s).removed_bytes, 4);
    let evicted = cache
        .ordinary_create_for_write(&s, r.write.id)
        .unwrap()
        .unwrap();
    assert!(evicted.body_evicted && evicted.local_handoff_acknowledged);
    assert_eq!(
        cache.open_content(&s, &r.write.content).unwrap_err(),
        CacheError::NotFound
    );
    assert_eq!(cache.pending_writes(&s).unwrap(), vec![r.write.clone()]);
    drop(cache);
    let cache = Cache::open(dir.path(), 1024 * 1024).unwrap();
    assert_eq!(
        cache
            .ordinary_create_for_handoff(&s, &r.handoff_id)
            .unwrap(),
        Some(evicted.clone())
    );
    assert_eq!(
        cache.acknowledge_ordinary_create_handoff(&s, &r).unwrap(),
        evicted
    );
    let retry = cache
        .stage_ordinary_create(&s, request(1, "/file1"), &mut Cursor::new(b"body"))
        .unwrap();
    assert!(retry.body_evicted);
    assert!(
        cache
            .stage_ordinary_create(&s, request(1, "/file1"), &mut Cursor::new(b"evil"))
            .is_err()
    );
    let db = cache.lock_db().unwrap();
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM contents", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM writes", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
}
#[test]
fn ack_refuses_staged_forged_scope_body_and_missing_copy() {
    let (_dir, cache, s) = fixture();
    let r = cache
        .stage_ordinary_create(&s, request(1, "/file1"), &mut Cursor::new(b"body"))
        .unwrap();
    assert!(cache.acknowledge_ordinary_create_handoff(&s, &r).is_err());
    let r = cache.admit_ordinary_create(&s, &r).unwrap();
    let mut forged = r.clone();
    forged.sha256 = "0".repeat(64);
    assert!(
        cache
            .acknowledge_ordinary_create_handoff(&s, &forged)
            .is_err()
    );
    let other = CacheScope::new(
        "https://cloud.example.test/",
        "different",
        "space",
        "root",
        ScopeProtection::PlaintextAllowed,
    )
    .unwrap();
    assert!(
        cache
            .acknowledge_ordinary_create_handoff(&other, &r)
            .is_err()
    );
    fs::remove_file(
        cache
            .inner
            .content_dir
            .join(format!("{}.blob", content_key(&s, &r.write.content))),
    )
    .unwrap();
    assert!(cache.acknowledge_ordinary_create_handoff(&s, &r).is_err());
    assert!(
        !cache
            .ordinary_create_for_write(&s, r.write.id)
            .unwrap()
            .unwrap()
            .local_handoff_acknowledged
    );
}
#[test]
fn unresolved_states_and_legacy_history_never_become_clean() {
    let (_dir, cache, s) = fixture();
    let staged = cache
        .stage_ordinary_create(&s, request(1, "/file1"), &mut Cursor::new(b"body"))
        .unwrap();
    let ready = make_ready(&cache, &s, 2);
    cache
        .acknowledge_ordinary_create_handoff(&s, &ready)
        .unwrap();
    let claimed = make_ready(&cache, &s, 3);
    cache
        .acknowledge_ordinary_create_handoff(&s, &claimed)
        .unwrap();
    let _claim = cache.claim_ordinary_create(&s, &claimed).unwrap().unwrap();
    let uncertain = make_ready(&cache, &s, 4);
    cache
        .acknowledge_ordinary_create_handoff(&s, &uncertain)
        .unwrap();
    let claim = cache
        .claim_ordinary_create(&s, &uncertain)
        .unwrap()
        .unwrap();
    cache.mark_ordinary_create_uncertain(&s, claim).unwrap();
    let conflict = make_ready(&cache, &s, 5);
    cache
        .acknowledge_ordinary_create_handoff(&s, &conflict)
        .unwrap();
    cache.block_ordinary_create(&s, &conflict).unwrap();
    cache.publish_listing(&s, "root", &[], 1).unwrap();
    let legacy = cache
        .queue_conditional_write(
            &s,
            ConditionalWriteRequest {
                parent_resource_id: "root".into(),
                name: "legacy".into(),
                logical_path: "/legacy".into(),
                resource_id: None,
                base: WriteCondition::Absent,
                expected_len: 4,
                protection: ContentProtection::Plaintext,
            },
            &mut Cursor::new(b"body"),
        )
        .unwrap();
    cache.mark_write_verified(&s, legacy.id).unwrap();
    assert_eq!(gc(&cache, &s).removed_bytes, 0);
    for r in [staged, ready, claimed, uncertain, conflict] {
        assert_eq!(read(&cache, &s, &r), b"body");
    }
    assert_eq!(
        cache.content_record(&s, &legacy.content).unwrap().retention,
        Retention::Dirty
    );
}
#[test]
fn policy_pin_scope_hold_covers_new_child_without_pin_item_and_recovery() {
    let (_dir, cache, s) = fixture();
    let r = clean(&cache, &s, 1);
    let db = cache.lock_db().unwrap();
    db.execute("INSERT INTO pins(pin_id,scope_key,root_id,root_path,state,created_at) VALUES('folder',?1,'folder-root','/ancestor',2,0)",params![s.key]).unwrap();
    drop(db);
    assert_eq!(gc(&cache, &s).removed_bytes, 0);
    assert_eq!(read(&cache, &s, &r), b"body");
    let db = cache.lock_db().unwrap();
    db.execute("DELETE FROM pins", []).unwrap();
    db.execute("INSERT INTO policies(scope_key,resource_id,policy,target_path,target_etag) VALUES(?1,?2,1,?3,?4)",params![s.key,r.remote.as_ref().unwrap().resource_id,r.write.logical_path,r.remote.as_ref().unwrap().etag]).unwrap();
    drop(db);
    assert_eq!(gc(&cache, &s).removed_bytes, 0);
    let db = cache.lock_db().unwrap();
    db.execute("DELETE FROM policies", []).unwrap();
    db.execute("UPDATE contents SET retention=2", []).unwrap();
    drop(db);
    assert_eq!(gc(&cache, &s).removed_bytes, 0);
}
#[test]
fn policy_admitted_between_retirement_and_unlink_keeps_body_and_charge() {
    let (_dir, cache, s) = fixture();
    let r = clean(&cache, &s, 1);
    let report=cache.evict_clean_creates_with_hook(&s,0,64,|point|{if point==CleanupPoint::Retired{let db=cache.lock_db()?;db.execute("INSERT INTO pins(pin_id,scope_key,root_id,root_path,state,created_at) VALUES('later',?1,'root','/',0,0)",params![s.key]).map_err(db_error)?;}Ok(())}).unwrap();
    assert_eq!(report.removed_bytes, 0);
    assert_eq!(cache.usage().unwrap().protected_bytes, 4);
    assert_eq!(read(&cache, &s, &r), b"body");
    let db = cache.lock_db().unwrap();
    assert_eq!(disposition(&db, &s, r.write.id).unwrap(), 1);
}
#[test]
fn crash_after_retirement_retries_exact_body_and_keeps_byte_charge() {
    let (dir, cache, s) = fixture();
    let r = clean(&cache, &s, 1);
    assert!(
        cache
            .evict_clean_creates_with_hook(&s, 0, 64, |point| if point == CleanupPoint::Retired {
                Err(CacheError::Io("synthetic retirement interruption".into()))
            } else {
                Ok(())
            })
            .is_err()
    );
    assert_eq!(cache.usage().unwrap().protected_bytes, 4);
    assert_eq!(read(&cache, &s, &r), b"body");
    drop(cache);
    let cache = Cache::open(dir.path(), 1024 * 1024).unwrap();
    assert!(
        cache
            .ordinary_create_for_write(&s, r.write.id)
            .unwrap()
            .unwrap()
            .body_evicted
    );
    let retained = clean(&cache, &s, 2);
    let recovered = cache
        .evict_acknowledged_ordinary_create_bodies(&s, 1024 * 1024, 64)
        .unwrap();
    assert_eq!(recovered.removed_bytes, 4);
    assert_eq!(recovered.used_bytes, 4);
    assert_eq!(read(&cache, &s, &retained), b"body");
    assert_eq!(cache.usage().unwrap().protected_bytes, retained.byte_len);
}
#[test]
fn crash_after_unlink_is_expected_clean_miss_until_finalization() {
    let (dir, cache, s) = fixture();
    let r = clean(&cache, &s, 1);
    assert!(
        cache
            .evict_clean_creates_with_hook(&s, 0, 64, |point| if point == CleanupPoint::Unlinked {
                Err(CacheError::Io("synthetic unlink interruption".into()))
            } else {
                Ok(())
            })
            .is_err()
    );
    assert_eq!(cache.usage().unwrap().protected_bytes, 4);
    drop(cache);
    let cache = Cache::open(dir.path(), 1024 * 1024).unwrap();
    assert!(
        cache
            .ordinary_create_for_write(&s, r.write.id)
            .unwrap()
            .unwrap()
            .body_evicted
    );
    assert_eq!(gc(&cache, &s).removed_bytes, 0);
    assert_eq!(cache.usage().unwrap().protected_bytes, 0);
    assert_eq!(cache.pending_writes(&s).unwrap(), vec![r.write]);
}
#[test]
fn exact_unindexed_tombstone_residual_only_unknown_and_mismatch_preserved() {
    let (_dir, cache, s) = fixture();
    let r = clean(&cache, &s, 1);
    gc(&cache, &s);
    let path = cache
        .inner
        .content_dir
        .join(format!("{}.blob", content_key(&s, &r.write.content)));
    fs::write(&path, b"body").unwrap();
    set_private_file(&File::open(&path).unwrap()).unwrap();
    assert_eq!(gc(&cache, &s).removed_bytes, 4);
    assert!(!path.exists());
    fs::write(&path, b"evil").unwrap();
    set_private_file(&File::open(&path).unwrap()).unwrap();
    assert!(
        cache
            .evict_acknowledged_ordinary_create_bodies(&s, 0, 64)
            .is_err()
    );
    assert_eq!(fs::read(&path).unwrap(), b"evil");
    fs::remove_file(&path).unwrap();
    let unknown = cache
        .inner
        .content_dir
        .join(format!("{}.blob", "f".repeat(64)));
    fs::write(&unknown, b"unknown").unwrap();
    set_private_file(&File::open(&unknown).unwrap()).unwrap();
    let report = gc(&cache, &s);
    assert_eq!(report.removed_bytes, 0);
    assert_eq!(report.used_bytes, 7);
    assert!(unknown.exists());
}
#[test]
fn unexpected_missing_or_forged_disposition_stays_corrupt() {
    let (_dir, cache, s) = fixture();
    let r = make_ready(&cache, &s, 1);
    let db = cache.lock_db().unwrap();
    db.execute("DELETE FROM contents", []).unwrap();
    drop(db);
    assert_eq!(
        cache.ordinary_create_for_write(&s, r.write.id),
        Err(CacheError::Corrupt)
    );
    let db = cache.lock_db().unwrap();
    db.execute(
        "UPDATE ordinary_create_handoffs SET body_state=2,local_handoff_ack=1",
        [],
    )
    .unwrap();
    drop(db);
    assert_eq!(
        cache.ordinary_create_for_write(&s, r.write.id),
        Err(CacheError::Corrupt)
    );
}
fn downgrade_fixture(cache: &Cache) {
    let db = cache.lock_db().unwrap();
    db.execute_batch("DROP INDEX ordinary_create_body_cleanup; ALTER TABLE ordinary_create_handoffs DROP COLUMN body_len; ALTER TABLE ordinary_create_handoffs DROP COLUMN body_sha256; ALTER TABLE ordinary_create_handoffs DROP COLUMN local_handoff_ack; ALTER TABLE ordinary_create_handoffs DROP COLUMN body_state; PRAGMA user_version=9;").unwrap();
}
#[test]
fn schema_nine_migration_snapshots_bytes_but_never_infers_local_ack() {
    let (dir, cache, s) = fixture();
    let r = make_ready(&cache, &s, 1);
    let r = complete(&cache, &s, &r);
    downgrade_fixture(&cache);
    drop(cache);
    let cache = Cache::open(dir.path(), 1024 * 1024).unwrap();
    let got = cache
        .ordinary_create_for_write(&s, r.write.id)
        .unwrap()
        .unwrap();
    assert_eq!(got, r);
    assert!(!got.local_handoff_acknowledged && !got.body_evicted);
    assert_eq!(gc(&cache, &s).removed_bytes, 0);
    assert_eq!(read(&cache, &s, &r), b"body");
}
#[test]
fn schema_nine_corrupt_body_metadata_rolls_back_instead_of_inventing_tombstone() {
    let (dir, cache, s) = fixture();
    make_ready(&cache, &s, 1);
    downgrade_fixture(&cache);
    let db = cache.lock_db().unwrap();
    db.execute("DELETE FROM contents", []).unwrap();
    drop(db);
    drop(cache);
    assert!(Cache::open(dir.path(), 1024 * 1024).is_err());
    let db = Connection::open(dir.path().join("cache-v1").join(DB_FILE)).unwrap();
    assert_eq!(
        db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        9
    );
}
#[test]
fn bounded_scope_cleanup_does_not_touch_other_scope_or_live_reader() {
    let (_dir, cache, s) = fixture();
    let a = clean(&cache, &s, 1);
    let b = clean(&cache, &s, 2);
    let other = CacheScope::new(
        "https://cloud.example.test/",
        "account",
        "other-space",
        "root",
        ScopeProtection::PlaintextAllowed,
    )
    .unwrap();
    let c = clean(&cache, &other, 3);
    let mut reader = cache.open_content(&s, &a.write.content).unwrap();
    // Opening A refreshes its wall-clock access time. Pin the intended LRU
    // order after that touch so crossing a second cannot make B the victim.
    {
        let db = cache.lock_db().unwrap();
        assert_eq!(
            db.execute(
                "UPDATE contents SET last_accessed=CASE content_key WHEN ?1 THEN 1 WHEN ?2 THEN 2 END WHERE content_key IN (?1,?2)",
                params![content_key(&s, &a.write.content), content_key(&s, &b.write.content)],
            )
            .unwrap(),
            2
        );
    }
    assert_eq!(
        cache
            .evict_acknowledged_ordinary_create_bodies(&s, 0, 1)
            .unwrap()
            .removed_bytes,
        4
    );
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"body");
    assert_eq!(read(&cache, &s, &b), b"body");
    assert_eq!(read(&cache, &other, &c), b"body");
    assert!(
        cache
            .evict_acknowledged_ordinary_create_bodies(&s, 0, 0)
            .is_err()
    );
}
