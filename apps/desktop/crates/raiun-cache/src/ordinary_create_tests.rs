use super::*;
use std::io::Cursor;
fn scope() -> CacheScope {
    CacheScope::new(
        "https://cloud.example.test/",
        "account",
        "space",
        "root",
        ScopeProtection::PlaintextAllowed,
    )
    .unwrap()
}
fn request(id: u32, path: &str, body: &[u8]) -> OrdinaryCreateRequest {
    OrdinaryCreateRequest {
        max_pending_bytes: 1024 * 1024,
        handoff_id: format!("{id:032x}"),
        parent_resource_id: "root".into(),
        name: path.rsplit('/').next().unwrap().into(),
        logical_path: path.into(),
        expected_len: body.len() as u64,
        expected_sha256: format!("{:x}", Sha256::digest(body)),
    }
}
fn fixture() -> (tempfile::TempDir, Cache, CacheScope) {
    let dir = tempfile::tempdir().unwrap();
    set_private_dir(dir.path()).unwrap();
    let cache = Cache::open(dir.path(), 1024 * 1024).unwrap();
    (dir, cache, scope())
}
fn stage(cache: &Cache, scope: &CacheScope, id: u32, path: &str) -> OrdinaryCreateReceipt {
    cache
        .stage_ordinary_create(scope, request(id, path, b"body"), &mut Cursor::new(b"body"))
        .unwrap()
}
fn ready(cache: &Cache, scope: &CacheScope, id: u32, path: &str) -> OrdinaryCreateReceipt {
    cache
        .admit_ordinary_create(scope, &stage(cache, scope, id, path))
        .unwrap()
}
fn remote(path: &str) -> RemoteEntry {
    RemoteEntry {
        id: "real-remote".into(),
        path: path.into(),
        etag: "\"strong\"".into(),
        size: 4,
        directory: false,
        modified_unix: 1,
        writable: true,
        encrypted: false,
    }
}
fn body(cache: &Cache, scope: &CacheScope, receipt: &OrdinaryCreateReceipt) -> Vec<u8> {
    let mut bytes = Vec::new();
    cache
        .open_content(scope, &receipt.write.content)
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    bytes
}
#[test]
fn durable_stage_needs_no_listing_and_never_dispatches() {
    let (dir, cache, s) = fixture();
    let r = stage(&cache, &s, 1, "/new");
    assert_eq!(r.state, OrdinaryCreateState::Staged);
    assert!(cache.ready_ordinary_creates(&s, 2).unwrap().is_empty());
    assert_eq!(body(&cache, &s, &r), b"body");
    drop(cache);
    let cache = Cache::open(dir.path(), 1024 * 1024).unwrap();
    assert_eq!(
        cache
            .ordinary_create_for_handoff(&s, &r.handoff_id)
            .unwrap(),
        Some(r.clone())
    );
    assert_eq!(body(&cache, &s, &r), b"body");
}
#[test]
fn retry_is_idempotent_but_rehashes_source_and_never_resets_claim() {
    let (_dir, cache, s) = fixture();
    let r = ready(&cache, &s, 1, "/new");
    let _claim = cache.claim_ordinary_create(&s, &r).unwrap().unwrap();
    assert_eq!(
        stage(&cache, &s, 1, "/new").state,
        OrdinaryCreateState::Claimed
    );
    assert!(
        cache
            .stage_ordinary_create(&s, request(1, "/new", b"body"), &mut Cursor::new(b"evil"))
            .is_err()
    );
    assert!(
        cache
            .stage_ordinary_create(&s, request(1, "/other", b"body"), &mut Cursor::new(b"body"))
            .is_err()
    );
    let db = cache.lock_db().unwrap();
    for table in ["writes", "contents", "ordinary_create_handoffs"] {
        assert_eq!(
            db.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
}
#[test]
fn bad_body_not_published_and_vault_refused() {
    let (_dir, cache, s) = fixture();
    for bytes in [b"evil".as_slice(), b"bod", b"bodyx"] {
        assert!(
            cache
                .stage_ordinary_create(&s, request(1, "/new", b"body"), &mut Cursor::new(bytes))
                .is_err()
        );
    }
    assert!(
        cache
            .ordinary_create_for_handoff(&s, &format!("{:032x}", 1))
            .unwrap()
            .is_none()
    );
    stage(&cache, &s, 1, "/new");
    let vault = CacheScope::new(
        "https://cloud.example.test/",
        "account",
        "space",
        "vault",
        ScopeProtection::CiphertextOnly,
    )
    .unwrap();
    assert_eq!(
        cache.stage_ordinary_create(
            &vault,
            request(2, "/new", b"body"),
            &mut Cursor::new(b"body")
        ),
        Err(CacheError::ProtectionMismatch)
    );
}
#[test]
fn pending_byte_ceiling_is_storage_enforced_without_eviction() {
    let (_dir, cache, s) = fixture();
    let mut req = request(1, "/new", b"body");
    req.max_pending_bytes = 3;
    assert_eq!(
        cache.stage_ordinary_create(&s, req.clone(), &mut Cursor::new(b"body")),
        Err(CacheError::LimitExceeded)
    );
    let old = stage(&cache, &s, 2, "/other");
    req.max_pending_bytes = 4;
    assert_eq!(
        cache.stage_ordinary_create(&s, req, &mut Cursor::new(b"body")),
        Err(CacheError::LimitExceeded)
    );
    assert_eq!(body(&cache, &s, &old), b"body");
    let db = cache.lock_db().unwrap();
    db.execute(
        "UPDATE cache_settings SET value=7 WHERE setting='quota_bytes'",
        [],
    )
    .unwrap();
    drop(db);
    let mut req = request(3, "/third", b"xx");
    req.max_pending_bytes = 7;
    assert_eq!(
        cache.stage_ordinary_create(&s, req, &mut Cursor::new(b"xx")),
        Err(CacheError::LimitExceeded)
    );
}
#[test]
fn one_claim_and_reopen_does_not_invalidate_live_owner() {
    let (dir, cache, s) = fixture();
    let r = ready(&cache, &s, 1, "/new");
    let other = Cache::open(dir.path(), 1024 * 1024).unwrap();
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let b = barrier.clone();
    let ss = s.clone();
    let rr = r.clone();
    let worker = std::thread::spawn(move || {
        b.wait();
        other.claim_ordinary_create(&ss, &rr)
    });
    barrier.wait();
    let a = cache.claim_ordinary_create(&s, &r);
    let b = worker.join().unwrap();
    assert_eq!(
        usize::from(a.as_ref().is_ok_and(|v| v.is_some()))
            + usize::from(b.as_ref().is_ok_and(|v| v.is_some())),
        1
    );
    let reopened = Cache::open(dir.path(), 1024 * 1024).unwrap();
    assert_eq!(
        reopened
            .ordinary_create_for_write(&s, r.write.id)
            .unwrap()
            .unwrap()
            .state,
        OrdinaryCreateState::Claimed
    );
    assert_eq!(
        reopened.recover_interrupted_ordinary_creates(&s).unwrap(),
        1
    );
    assert_eq!(
        reopened.recover_interrupted_ordinary_creates(&s).unwrap(),
        0
    );
    assert!(reopened.claim_ordinary_create(&s, &r).unwrap().is_none());
}
#[test]
fn forged_scope_receipt_and_nonce_cannot_transition() {
    let (_dir, cache, s) = fixture();
    let r = stage(&cache, &s, 1, "/new");
    let mut forged = r.clone();
    forged.sha256 = "0".repeat(64);
    assert_eq!(
        cache.admit_ordinary_create(&s, &forged),
        Err(CacheError::Conflict)
    );
    let r = cache.admit_ordinary_create(&s, &r).unwrap();
    let claim = cache.claim_ordinary_create(&s, &r).unwrap().unwrap();
    let other = CacheScope::new(
        "https://cloud.example.test/",
        "other",
        "space",
        "root",
        ScopeProtection::PlaintextAllowed,
    )
    .unwrap();
    assert!(
        cache
            .complete_ordinary_create(&other, &claim, &remote("/new"), &claim.receipt.sha256)
            .is_err()
    );
    let wrong = OrdinaryCreateClaim {
        receipt: claim.receipt.clone(),
        nonce: "0".repeat(32),
    };
    assert!(cache.mark_ordinary_create_uncertain(&s, wrong).is_err());
    assert_eq!(
        cache
            .mark_ordinary_create_uncertain(&s, claim)
            .unwrap()
            .state,
        OrdinaryCreateState::Uncertain
    );
}
#[test]
fn omission_weak_etag_and_mismatch_stay_claimed_until_explicit_uncertain() {
    let (_dir, cache, s) = fixture();
    let r = ready(&cache, &s, 1, "/new");
    let claim = cache.claim_ordinary_create(&s, &r).unwrap().unwrap();
    for etag in ["", "W/\"weak\"", "\"\"", "unquoted", "\"bad\n\""] {
        let mut entry = remote("/new");
        entry.etag = etag.into();
        assert!(
            cache
                .complete_ordinary_create(&s, &claim, &entry, &claim.receipt.sha256)
                .is_err()
        );
    }
    let mut entry = remote("/new");
    entry.encrypted = true;
    assert!(
        cache
            .complete_ordinary_create(&s, &claim, &entry, &claim.receipt.sha256)
            .is_err()
    );
    assert!(
        cache
            .complete_ordinary_create(&s, &claim, &remote("/other"), &claim.receipt.sha256)
            .is_err()
    );
    assert!(
        cache
            .complete_ordinary_create(&s, &claim, &remote("/new"), &"0".repeat(64))
            .is_err()
    );
    let r = cache.mark_ordinary_create_uncertain(&s, claim).unwrap();
    assert_eq!(r.state, OrdinaryCreateState::Uncertain);
    assert_eq!(body(&cache, &s, &r), b"body");
    assert!(cache.ready_ordinary_creates(&s, 2).unwrap().is_empty());
}
#[test]
fn verified_cas_is_one_use_and_retains_body_and_receipt() {
    let (_dir, cache, s) = fixture();
    let r = ready(&cache, &s, 1, "/new");
    let claim = cache.claim_ordinary_create(&s, &r).unwrap().unwrap();
    let r = cache
        .complete_ordinary_create(&s, &claim, &remote("/new"), &claim.receipt.sha256)
        .unwrap();
    assert_eq!(r.write.state, WriteState::Verified);
    assert_eq!(r.remote.as_ref().unwrap().resource_id, "real-remote");
    assert_eq!(body(&cache, &s, &r), b"body");
    assert!(
        cache
            .complete_ordinary_create(&s, &claim, &remote("/new"), &claim.receipt.sha256)
            .is_err()
    );
    assert_eq!(stage(&cache, &s, 1, "/new"), r);
    assert!(!cache.ordinary_create_path_blocked(&s, "/new").unwrap());
    assert_eq!(
        cache
            .content_record(&s, &r.write.content)
            .unwrap()
            .retention,
        Retention::Dirty
    );
}
#[test]
fn generic_mutators_cannot_bypass_ledger() {
    let (_dir, cache, s) = fixture();
    let r = stage(&cache, &s, 1, "/new");
    assert_eq!(
        cache.mark_write_verified(&s, r.write.id),
        Err(CacheError::Conflict)
    );
    assert_eq!(
        cache.mark_write_conflict(&s, r.write.id),
        Err(CacheError::Conflict)
    );
    let req = ConditionalWriteRequest {
        parent_resource_id: "root".into(),
        name: "new".into(),
        logical_path: "/new".into(),
        resource_id: None,
        base: WriteCondition::Absent,
        expected_len: 4,
        protection: ContentProtection::Plaintext,
    };
    assert!(
        cache
            .replace_pending_conditional_write(&s, req, &mut Cursor::new(b"evil"))
            .is_err()
    );
    assert_eq!(body(&cache, &s, &r), b"body");
    assert_eq!(
        cache.block_ordinary_create(&s, &r).unwrap().state,
        OrdinaryCreateState::Conflict
    );
    assert!(cache.admit_ordinary_create(&s, &r).is_err());
}
#[test]
fn literal_component_overlap_and_bounded_pages() {
    let (_dir, cache, s) = fixture();
    stage(&cache, &s, 1, "/a%_/file");
    stage(&cache, &s, 2, "/second");
    stage(&cache, &s, 3, "/third");
    for path in ["/", "/a%_", "/a%_/file", "/a%_/file/child"] {
        assert!(cache.ordinary_create_path_blocked(&s, path).unwrap());
    }
    for path in ["/aXX", "/a%_suffix", "/a%_/file_suffix"] {
        assert!(!cache.ordinary_create_path_blocked(&s, path).unwrap());
    }
    let page = cache.ordinary_creates(&s, None, 2).unwrap();
    assert_eq!(page.counts.staged, 3);
    assert_eq!(page.items.len(), 2);
    let last = cache.ordinary_creates(&s, page.next_after, 2).unwrap();
    assert_eq!(last.items.len(), 1);
    assert!(last.next_after.is_none());
    assert!(cache.ordinary_creates(&s, None, 0).is_err());
    assert!(cache.ready_ordinary_creates(&s, 65).is_err());
}
#[test]
fn v8_migration_preserves_legacy_ineligibility() {
    let (dir, cache, s) = fixture();
    cache.publish_listing(&s, "root", &[], 1).unwrap();
    let old = cache
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
    {
        let db = cache.lock_db().unwrap();
        db.execute_batch("DROP TABLE ordinary_create_handoffs; PRAGMA user_version=8;")
            .unwrap();
    }
    drop(cache);
    let cache = Cache::open(dir.path(), 1024 * 1024).unwrap();
    let page = cache.ordinary_creates(&s, None, 10).unwrap();
    assert_eq!(page.counts.legacy_unclassified, 1);
    assert!(page.items.is_empty());
    assert!(cache.ready_ordinary_creates(&s, 2).unwrap().is_empty());
    assert!(
        cache
            .ordinary_create_path_blocked(&s, "/legacy/child")
            .unwrap()
    );
    assert!(
        cache
            .ordinary_create_for_write(&s, old.id)
            .unwrap()
            .is_none()
    );
    let db = cache.lock_db().unwrap();
    assert_eq!(
        db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        9
    );
}
#[test]
fn corrupt_binding_refuses_receipt() {
    let (_dir, cache, s) = fixture();
    let r = stage(&cache, &s, 1, "/new");
    let db = cache.lock_db().unwrap();
    db.execute(
        "UPDATE ordinary_create_handoffs SET content_key='wrong' WHERE write_id=?1",
        [r.write.id],
    )
    .unwrap();
    drop(db);
    assert_eq!(
        cache.ordinary_create_for_write(&s, r.write.id),
        Err(CacheError::Corrupt)
    );
}

#[test]
fn legacy_body_counts_toward_new_backlog_ceiling() {
    let (_dir, cache, s) = fixture();
    cache.publish_listing(&s, "root", &[], 1).unwrap();
    cache
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
    let mut req = request(2, "/new", b"x");
    req.max_pending_bytes = 4;
    assert_eq!(
        cache.stage_ordinary_create(&s, req, &mut Cursor::new(b"x")),
        Err(CacheError::LimitExceeded)
    );
    assert_eq!(
        cache
            .ordinary_creates(&s, None, 10)
            .unwrap()
            .counts
            .legacy_unclassified,
        1
    );
}

#[test]
fn metadata_record_ceiling_is_checked_before_body_io() {
    let (_dir, cache, s) = fixture();
    let staged = stage(&cache, &s, 1, "/kept");
    let db = cache.lock_db().unwrap();
    db.execute("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<99999) INSERT INTO writes(scope_key,parent_id,name,path,resource_id,base_kind,base_etag,content_key,state,created_at) SELECT ?1,'root',printf('old%d',x),printf('/old%d',x),NULL,0,'',?2,2,0 FROM n",params![s.key,content_key(&s,&staged.write.content)]).unwrap();
    drop(db);
    struct NoRead;
    impl Read for NoRead {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            panic!("record bound must be checked before reading");
        }
    }
    assert_eq!(
        cache.stage_ordinary_create(&s, request(2, "/new", b"body"), &mut NoRead),
        Err(CacheError::LimitExceeded)
    );
    assert_eq!(body(&cache, &s, &staged), b"body");
}

#[test]
fn bounded_ready_batch_and_counts_preserve_every_terminal_state() {
    let (_dir, cache, s) = fixture();
    let staged = stage(&cache, &s, 1, "/staged");
    let ready_receipt = ready(&cache, &s, 2, "/ready");
    let claimed = ready(&cache, &s, 3, "/claimed");
    let claim = cache.claim_ordinary_create(&s, &claimed).unwrap().unwrap();
    let uncertain = ready(&cache, &s, 4, "/uncertain");
    let u = cache
        .claim_ordinary_create(&s, &uncertain)
        .unwrap()
        .unwrap();
    cache.mark_ordinary_create_uncertain(&s, u).unwrap();
    let blocked = stage(&cache, &s, 5, "/blocked");
    cache.block_ordinary_create(&s, &blocked).unwrap();
    let verified = ready(&cache, &s, 6, "/verified");
    let v = cache.claim_ordinary_create(&s, &verified).unwrap().unwrap();
    cache
        .complete_ordinary_create(&s, &v, &remote("/verified"), &v.receipt.sha256)
        .unwrap();
    assert_eq!(
        cache.ready_ordinary_creates(&s, 1).unwrap(),
        vec![ready_receipt]
    );
    let page = cache.ordinary_creates(&s, None, 256).unwrap();
    assert_eq!(
        page.counts,
        OrdinaryCreateCounts {
            staged: 1,
            ready: 1,
            claimed: 1,
            uncertain: 1,
            conflict: 1,
            verified: 1,
            legacy_unclassified: 0
        }
    );
    assert!(
        cache
            .ordinary_create_path_blocked(&s, &staged.write.logical_path)
            .unwrap()
    );
    assert!(
        cache
            .ordinary_create_path_blocked(&s, &uncertain.write.logical_path)
            .unwrap()
    );
    drop(claim);
}

#[test]
fn legacy_queue_cannot_alias_handoff_path_after_parent_identity_changes() {
    let (_dir, cache, s) = fixture();
    let mut req = request(1, "/folder/file", b"body");
    req.parent_resource_id = "parent-a".into();
    let staged = cache
        .stage_ordinary_create(&s, req, &mut Cursor::new(b"body"))
        .unwrap();
    cache.publish_listing(&s, "parent-b", &[], 1).unwrap();
    let absent = ConditionalWriteRequest {
        parent_resource_id: "parent-b".into(),
        name: "file".into(),
        logical_path: "/folder/file".into(),
        resource_id: None,
        base: WriteCondition::Absent,
        expected_len: 4,
        protection: ContentProtection::Plaintext,
    };
    assert_eq!(
        cache.queue_conditional_write(&s, absent, &mut Cursor::new(b"evil")),
        Err(CacheError::LimitExceeded)
    );
    let listed = remote("/folder/file");
    cache
        .publish_listing(
            &s,
            "parent-b",
            &[CachedEntry {
                parent_resource_id: "parent-b".into(),
                entry: listed.clone(),
            }],
            2,
        )
        .unwrap();
    let matched = ConditionalWriteRequest {
        parent_resource_id: "parent-b".into(),
        name: "file".into(),
        logical_path: listed.path.clone(),
        resource_id: Some(listed.id),
        base: WriteCondition::Match(listed.etag),
        expected_len: 4,
        protection: ContentProtection::Plaintext,
    };
    assert_eq!(
        cache.queue_conditional_write(&s, matched, &mut Cursor::new(b"evil")),
        Err(CacheError::LimitExceeded)
    );
    assert_eq!(
        cache
            .ordinary_create_for_write(&s, staged.write.id)
            .unwrap(),
        Some(staged.clone())
    );
    assert_eq!(body(&cache, &s, &staged), b"body");
    assert_eq!(cache.pending_writes(&s).unwrap(), vec![staged.write]);
}
