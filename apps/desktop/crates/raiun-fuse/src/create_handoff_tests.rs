// Included in the existing test module so the real FUSE helpers and fake backend
// exercise CREATE -> local commit -> release without mounting a host filesystem.
#[derive(Default)]
struct CreateBarrier {
    state: Mutex<(usize, bool)>,
    changed: Condvar,
    active: AtomicUsize,
    peak: AtomicUsize,
}
struct CreateBarrierActive<'a>(&'a CreateBarrier);
impl Drop for CreateBarrierActive<'_> {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}
impl CreateBarrier {
    fn enter(
        &self,
        cancellation: &raiun_core::backend::OperationCancellation,
    ) -> CreateBarrierActive<'_> {
        let count = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(count, Ordering::SeqCst);
        let mut state = self.state.lock().unwrap();
        state.0 += 1;
        self.changed.notify_all();
        while !state.1 && !cancellation.is_cancelled() {
            state = self
                .changed
                .wait_timeout(state, Duration::from_millis(20))
                .unwrap()
                .0;
        }
        CreateBarrierActive(self)
    }
    fn wait_entered(&self, count: usize) {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut state = self.state.lock().unwrap();
        while state.0 < count {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "upload body did not enter");
            state = self.changed.wait_timeout(state, remaining).unwrap().0;
        }
    }
    fn release(&self) {
        self.state.lock().unwrap().1 = true;
        self.changed.notify_all();
    }
}

fn enable_create_handoff(
    fs: &mut RaiunFilesystem,
    budget: u64,
    dispatch: bool,
) -> CreateUploadOwner {
    let cache_dir = fs.spool_dir.parent().unwrap().join("handoff-cache");
    fs::create_dir_all(&cache_dir).unwrap();
    fs::set_permissions(&cache_dir, fs::Permissions::from_mode(0o700)).unwrap();
    fs.engine = fs
        .engine
        .with_offline_cache(
            raiun_cache::Cache::open(&cache_dir, 64 * 1024 * 1024).unwrap(),
            "fuse-test-account".into(),
            "https://example.invalid".into(),
        )
        .unwrap();
    fs.engine.list("personal", "/").unwrap();
    let owner = fs
        .engine
        .start_create_upload_owner(CreateUploadHooks {
            is_current: Arc::new(|| true),
            dispatch_allowed: Arc::new(move |_| dispatch),
        })
        .unwrap();
    let admission = owner.handle();
    fs.create_handoff = Some(CreateHandoffCapability {
        handle: owner.handle(),
        current: Arc::new(move || admission.is_accepting()),
        max_pending_bytes: budget,
    });
    owner
}

fn new_create_bytes(fs: &RaiunFilesystem, name: &str, body: &[u8]) -> (Node, Arc<Mutex<OpenFile>>) {
    new_create_bytes_in_parent(fs, PERSONAL, name, body)
}

fn new_create_bytes_in_parent(
    fs: &RaiunFilesystem,
    parent: u64,
    name: &str,
    body: &[u8],
) -> (Node, Arc<Mutex<OpenFile>>) {
    let (node, fh, _) = fs
        .create_ordinary_file(parent, OsStr::new(name), libc::O_WRONLY | libc::O_EXCL)
        .unwrap();
    let handle = fs.file_handle(fh).unwrap();
    assert!(
        fs.ordinary_open_flags(node.ino, fh)
            .contains(FopenFlags::FOPEN_DIRECT_IO)
    );
    {
        let mut open = handle.lock().unwrap();
        let OpenFile::Write(write) = &mut *open else {
            panic!("new write handle")
        };
        write.file.write_all(body).unwrap();
        write.dirty = true;
    }
    (node, handle)
}

#[test]
fn create_handoff_sequential_release_allows_two_bodies_and_pending_reads() {
    let temp = tempfile::tempdir().unwrap();
    let barrier = Arc::new(CreateBarrier::default());
    let backend = Arc::new(FakeBackend {
        create_barrier: Some(barrier.clone()),
        ..FakeBackend::default()
    });
    let mut fs = filesystem(&temp, backend.clone());
    let mut owner = enable_create_handoff(&mut fs, 1024 * 1024, true);
    let (a, a_handle) = new_create_bytes(&fs, "create-a.txt", b"first immutable body");
    fs.commit(&a_handle).unwrap();
    fs.finish_ordinary_handle(&a_handle).unwrap();
    assert!(!fs.spool_paths("personal", "/create-a.txt").0.exists());
    barrier.wait_entered(1);
    let (_, b_handle) = new_create_bytes(&fs, "create-b.txt", b"second immutable body");
    fs.commit(&b_handle).unwrap();
    fs.finish_ordinary_handle(&b_handle).unwrap();
    barrier.wait_entered(2);
    assert_eq!(barrier.peak.load(Ordering::SeqCst), 2);
    // Neither remote PUT has completed, yet actual FUSE browse/read helpers see
    // both immutable local files even after their mutable spools were removed.
    let children = fs.children(PERSONAL).unwrap();
    assert!(
        children
            .iter()
            .any(|n| n.name == "create-b.txt" && matches!(n.kind, NodeKind::PendingCreate { .. }))
    );
    let fh = fs.open_node(a.ino, libc::O_RDONLY).unwrap();
    assert!(
        fs.ordinary_open_flags(a.ino, fh)
            .contains(FopenFlags::FOPEN_DIRECT_IO)
    );
    let read = fs.file_handle(fh).unwrap();
    let mut read = read.lock().unwrap();
    let OpenFile::Read(ReadHandle::Snapshot(snapshot)) = &mut *read else {
        panic!("immutable snapshot")
    };
    let mut body = Vec::new();
    snapshot.read_to_end(&mut body).unwrap();
    assert_eq!(body, b"first immutable body");
    assert!(fs.open_node(a.ino, libc::O_WRONLY).is_err());
    assert!(
        fs.delete_child(PERSONAL, OsStr::new("create-a.txt"), false)
            .is_err()
    );
    {
        let open = a_handle.lock().unwrap();
        let OpenFile::Write(write) = &*open else {
            panic!("writer")
        };
        assert!(create_handoff::ensure_mutable(write).is_err());
    }
    let scope = fs.engine.ordinary_write_scope("personal").unwrap();
    assert!(fs.engine.has_pending_create_overlap(&scope, "/").unwrap());
    barrier.release();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let page = fs.engine.ordinary_create_page(&scope, None, 32).unwrap();
        if page
            .items
            .iter()
            .all(|receipt| receipt.state == raiun_cache::OrdinaryCreateState::Verified)
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "create did not verify: {:?}",
            page.items
        );
        thread::sleep(Duration::from_millis(10));
    }
    assert!(matches!(
        fs.getattr_node(a.ino).unwrap().kind,
        NodeKind::Remote { .. }
    ));
    owner.stop_and_join().unwrap();
    assert_eq!(barrier.active.load(Ordering::SeqCst), 0);
}

#[test]
fn create_handoff_failed_admission_freezes_same_handle_and_preserves_v3_recovery() {
    let temp = tempfile::tempdir().unwrap();
    let mut fs = filesystem(&temp, Arc::new(FakeBackend::default()));
    let mut owner = enable_create_handoff(&mut fs, 1, false);
    let (_, handle) = new_create_bytes(&fs, "too-large.txt", b"preserved body exceeds budget");
    assert!(fs.commit(&handle).is_err());
    let (id, marker) = {
        let open = handle.lock().unwrap();
        let OpenFile::Write(write) = &*open else {
            panic!("writer")
        };
        assert!(create_handoff::ensure_mutable(write).is_err());
        assert!(write.dirty);
        assert!(!write.cleanup_on_release);
        assert_eq!(
            fs::read(&write.spool).unwrap(),
            b"preserved body exceeds budget"
        );
        let bytes = fs::read(&write.manifest).unwrap();
        let marker: OrdinaryWriteManifest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(marker.version, 3);
        (marker.handoff.unwrap().id, write.manifest.clone())
    };
    assert!(fs.commit(&handle).is_err());
    let marker: OrdinaryWriteManifest = serde_json::from_slice(&fs::read(marker).unwrap()).unwrap();
    assert_eq!(marker.handoff.unwrap().id, id);
    assert!(
        fs.prepare_write(999, "personal", "/too-large.txt", None, false)
            .is_err()
    );
    let page = recovery::list_recoveries(&fs.spool_dir, None, 64).unwrap();
    assert_eq!(page.items.len(), 1);
    owner.stop_and_join().unwrap();
}

#[test]
fn create_handoff_lost_receipt_marker_relooks_same_id_without_second_write() {
    let temp = tempfile::tempdir().unwrap();
    let mut fs = filesystem(&temp, Arc::new(FakeBackend::default()));
    let mut owner = enable_create_handoff(&mut fs, 1024 * 1024, false);
    let (_, handle) = new_create_bytes(&fs, "receipt.txt", b"durable receipt body");
    let (scope, id, first_id) = {
        let mut open = handle.lock().unwrap();
        let OpenFile::Write(write) = &mut *open else {
            panic!("writer")
        };
        write.file.flush().unwrap();
        write.file.sync_all().unwrap();
        create_handoff::prepare(write).unwrap();
        let create = write.create.as_ref().unwrap();
        let intent = create.intent.as_ref().unwrap();
        let receipt = fs
            .engine
            .queue_new_plaintext_create_scoped(
                raiun_engine::CreateHandoffRequest {
                    parent: &create.parent,
                    source: &write.file,
                    expected_len: intent.len,
                    expected_sha256: &intent.sha256,
                    handoff_id: &intent.id,
                    max_pending_bytes: 1024 * 1024,
                },
                &|| true,
            )
            .unwrap();
        // Crash boundary: Cache Ready exists, durable V3 still has intent only.
        assert!(intent.receipt.is_none());
        (
            write.scope.clone(),
            intent.id.clone(),
            receipt.storage_receipt().write.id,
        )
    };
    fs.commit(&handle).unwrap();
    let receipt = fs
        .engine
        .create_receipt_for_handoff(&scope, "/receipt.txt", &id)
        .unwrap()
        .unwrap();
    assert_eq!(receipt.storage_receipt().write.id, first_id);
    assert_eq!(
        fs.engine
            .ordinary_create_page(&scope, None, 32)
            .unwrap()
            .items
            .len(),
        1
    );
    fs.finish_ordinary_handle(&handle).unwrap();
    owner.stop_and_join().unwrap();
}

#[test]
fn create_handoff_mount_owner_stop_cancels_joins_without_unmount_and_closes_admission() {
    let temp = tempfile::tempdir().unwrap();
    let barrier = Arc::new(CreateBarrier::default());
    let backend = Arc::new(FakeBackend {
        create_barrier: Some(barrier.clone()),
        ..FakeBackend::default()
    });
    let mut fs = filesystem(&temp, backend);
    let owner = enable_create_handoff(&mut fs, 1024 * 1024, true);
    let (_, handle) = new_create_bytes(&fs, "cancel.txt", b"retained on cancellation");
    fs.commit(&handle).unwrap();
    barrier.wait_entered(1);
    let mut mount = MountHandle {
        session: None,
        create_upload_owner: Some(owner),
        root: temp.path().to_owned(),
        source: "fixture-no-mount".into(),
    };
    mount.stop_create_uploads().unwrap();
    mount.stop_create_uploads().unwrap();
    assert_eq!(barrier.active.load(Ordering::SeqCst), 0);
    assert!(!fs.create_handoff.as_ref().unwrap().handle.is_accepting());
    let scope = fs.engine.ordinary_write_scope("personal").unwrap();
    let pending = fs
        .engine
        .pending_create(&scope, "/cancel.txt")
        .unwrap()
        .unwrap();
    assert_eq!(
        pending.receipt.state,
        raiun_cache::OrdinaryCreateState::Uncertain
    );
    assert!(fs.commit(&handle).is_err());
}

#[test]
fn create_handoff_foreign_receipt_marker_never_authorizes_spool_cleanup() {
    let temp = tempfile::tempdir().unwrap();
    let mut fs = filesystem(&temp, Arc::new(FakeBackend::default()));
    let mut owner = enable_create_handoff(&mut fs, 1024 * 1024, false);
    let (_, handle) = new_create_bytes(&fs, "foreign-marker.txt", b"must remain recoverable");
    fs.commit(&handle).unwrap();
    let (spool, marker) = fs.spool_paths("personal", "/foreign-marker.txt");
    let mut json: serde_json::Value = serde_json::from_slice(&fs::read(&marker).unwrap()).unwrap();
    json["handoff"]["receipt"]["write_id"] = serde_json::json!(999999);
    fs::write(&marker, serde_json::to_vec(&json).unwrap()).unwrap();
    assert!(fs.finish_ordinary_handle(&handle).is_err());
    assert_eq!(fs::read(spool).unwrap(), b"must remain recoverable");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&fs::read(marker).unwrap()).unwrap(),
        json
    );
    owner.stop_and_join().unwrap();
}

#[test]
fn create_handoff_optin_does_not_promote_existing_v2_absent_recovery() {
    let temp = tempfile::tempdir().unwrap();
    let mut fs = filesystem(&temp, Arc::new(FakeBackend::default()));
    let mut owner = enable_create_handoff(&mut fs, 1024 * 1024, false);
    let mut old = fs
        .prepare_write(999, "personal", "/legacy-v2.txt", None, true)
        .unwrap();
    old.file
        .write_all(b"legacy recovery retains its original meaning")
        .unwrap();
    old.file.sync_all().unwrap();
    assert!(
        fs.create_ordinary_file(
            PERSONAL,
            OsStr::new("legacy-v2.txt"),
            libc::O_WRONLY | libc::O_EXCL
        )
        .is_err()
    );
    let scope = fs.engine.ordinary_write_scope("personal").unwrap();
    assert!(
        fs.engine
            .ordinary_create_page(&scope, None, 32)
            .unwrap()
            .items
            .is_empty()
    );
    assert_eq!(
        fs::read(&old.spool).unwrap(),
        b"legacy recovery retains its original meaning"
    );
    let marker: OrdinaryWriteManifest =
        serde_json::from_slice(&fs::read(&old.manifest).unwrap()).unwrap();
    assert_eq!(marker.version, 2);
    assert!(marker.handoff.is_none());
    owner.stop_and_join().unwrap();
}

#[test]
fn create_handoff_source_path_replacement_preserves_original_fd_and_never_readies() {
    let temp = tempfile::tempdir().unwrap();
    let barrier = Arc::new(CreateBarrier::default());
    let backend = Arc::new(FakeBackend {
        create_barrier: Some(barrier.clone()),
        ..FakeBackend::default()
    });
    let mut fs = filesystem(&temp, backend);
    let mut owner = enable_create_handoff(&mut fs, 1024 * 1024, true);
    let (_, handle) = new_create_bytes(&fs, "replace-source.txt", b"original pinned body");
    let scope = fs.engine.ordinary_write_scope("personal").unwrap();
    owner.handle().wake_scope(&scope).unwrap();
    let original_path = {
        let mut open = handle.lock().unwrap();
        let OpenFile::Write(write) = &mut *open else {
            panic!("writer")
        };
        write.file.sync_all().unwrap();
        create_handoff::prepare(write).unwrap();
        let preserved = temp.path().join("preserved-original-spool");
        fs::rename(&write.spool, &preserved).unwrap();
        fs::write(&write.spool, b"replacement pathname").unwrap();
        preserved
    };
    assert!(fs.commit(&handle).is_err());
    assert!(
        fs.engine
            .ordinary_create_page(&scope, None, 32)
            .unwrap()
            .items
            .is_empty()
    );
    assert_eq!(barrier.state.lock().unwrap().0, 0);
    let mut open = handle.lock().unwrap();
    let OpenFile::Write(write) = &mut *open else {
        panic!("writer")
    };
    write.file.seek(SeekFrom::Start(0)).unwrap();
    let mut pinned = Vec::new();
    write.file.read_to_end(&mut pinned).unwrap();
    assert_eq!(pinned, b"original pinned body");
    assert_eq!(fs::read(original_path).unwrap(), pinned);
    drop(open);
    owner.stop_and_join().unwrap();
}

#[test]
fn create_handoff_same_inode_body_change_cannot_replace_durable_expected_hash() {
    let temp = tempfile::tempdir().unwrap();
    let barrier = Arc::new(CreateBarrier::default());
    let backend = Arc::new(FakeBackend {
        create_barrier: Some(barrier.clone()),
        ..FakeBackend::default()
    });
    let mut fs = filesystem(&temp, backend);
    let mut owner = enable_create_handoff(&mut fs, 1024 * 1024, true);
    let (_, handle) = new_create_bytes(&fs, "changed-body.txt", b"original bytes");
    let scope = fs.engine.ordinary_write_scope("personal").unwrap();
    owner.handle().wake_scope(&scope).unwrap();
    let original_intent = {
        let mut open = handle.lock().unwrap();
        let OpenFile::Write(write) = &mut *open else {
            panic!("writer")
        };
        write.file.sync_all().unwrap();
        create_handoff::prepare(write).unwrap();
        let intent = write
            .create
            .as_ref()
            .unwrap()
            .intent
            .as_ref()
            .unwrap()
            .clone();
        // Simulate an external writer bypassing the immutable FUSE handle.
        fs::write(&write.spool, b"tampered bytes").unwrap();
        intent
    };
    assert!(fs.commit(&handle).is_err());
    assert!(
        fs.engine
            .ordinary_create_page(&scope, None, 32)
            .unwrap()
            .items
            .is_empty()
    );
    assert_eq!(barrier.state.lock().unwrap().0, 0);
    let open = handle.lock().unwrap();
    let OpenFile::Write(write) = &*open else {
        panic!("writer")
    };
    assert_eq!(
        write.create.as_ref().unwrap().intent.as_ref().unwrap(),
        &original_intent
    );
    assert!(write.spool.exists() && write.manifest.exists());
    assert!(create_handoff::ensure_mutable(write).is_err());
    drop(open);
    owner.stop_and_join().unwrap();
}

#[test]
#[ignore = "requires explicitly authorized isolated Linux VM and RAIUN_FUSE_CREATE_HANDOFF_VM_TEST=1; never run on host"]
fn live_fuse_create_handoff_sequential_fsync_close_two_held_uploads_in_vm() {
    assert_eq!(
        std::env::var("RAIUN_FUSE_CREATE_HANDOFF_VM_TEST").as_deref(),
        Ok("1"),
        "explicit isolated VM test opt-in is required before mounting"
    );
    assert!(
        Path::new("/dev/fuse").exists(),
        "VM FUSE device is required"
    );
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("task-only-mount");
    let provider_state = temp.path().join("provider-state");
    let cache_dir = temp.path().join("private-cache");
    fs::create_dir(&root).unwrap();
    fs::create_dir(&cache_dir).unwrap();
    fs::set_permissions(&cache_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let barrier = Arc::new(CreateBarrier::default());
    let backend = Arc::new(FakeBackend {
        create_barrier: Some(barrier.clone()),
        ..FakeBackend::default()
    });
    let cache = raiun_cache::Cache::open(&cache_dir, 64 * 1024 * 1024).unwrap();
    let engine = Engine::open(&temp.path().join("engine"), backend)
        .unwrap()
        .with_offline_cache(
            cache,
            "fuse-vm-synthetic-account".into(),
            "https://example.invalid".into(),
        )
        .unwrap();
    let mut mount = mount_with_vault_registry_and_create_handoff(
        engine.clone(),
        &root,
        &provider_state,
        "fuse-vm-task",
        VaultMountRegistry::new(),
        Some(CreateHandoffOptions {
            hooks: CreateUploadHooks {
                is_current: Arc::new(|| true),
                dispatch_allowed: Arc::new(|_| true),
            },
            max_pending_bytes: 1024 * 1024,
        }),
    )
    .unwrap();
    let personal = root.join("Personal");
    for (name, bytes, expected_entered) in [
        ("native-a.txt", b"kernel A durable handoff".as_slice(), 1),
        ("native-b.txt", b"kernel B durable handoff".as_slice(), 2),
    ] {
        let path = personal.join(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap(); // local custody must ACK while PUT remains held
        assert!(file.write_all(b"refused edit after handoff").is_err());
        drop(file); // actual kernel FLUSH/RELEASE must retire only receipt-owned spool
        barrier.wait_entered(expected_entered);
        let stem = format!("{:016x}", stable_hash(&format!("personal\0/{name}")));
        let spool = provider_state.join("provider-spool");
        let deadline = Instant::now() + Duration::from_secs(10);
        while spool.join(format!("{stem}.data")).exists()
            || spool.join(format!("{stem}.meta")).exists()
        {
            assert!(
                Instant::now() < deadline,
                "kernel RELEASE did not retire exact spool"
            );
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }
    assert_eq!(barrier.peak.load(Ordering::SeqCst), 2);
    let names = fs::read_dir(&personal)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    assert!(names.contains(&std::ffi::OsString::from("native-a.txt")));
    assert!(names.contains(&std::ffi::OsString::from("native-b.txt")));
    assert_eq!(
        fs::read(personal.join("native-a.txt")).unwrap(),
        b"kernel A durable handoff"
    );
    assert_eq!(
        fs::read(personal.join("native-b.txt")).unwrap(),
        b"kernel B durable handoff"
    );
    let scope = engine.ordinary_write_scope("personal").unwrap();
    let page = engine.ordinary_create_page(&scope, None, 32).unwrap();
    assert_eq!(page.items.len(), 2);
    assert!(
        page.items
            .iter()
            .all(|receipt| receipt.local_handoff_acknowledged
                && receipt.state == raiun_cache::OrdinaryCreateState::Claimed)
    );
    barrier.release();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let page = engine.ordinary_create_page(&scope, None, 32).unwrap();
        if page
            .items
            .iter()
            .all(|receipt| receipt.state == raiun_cache::OrdinaryCreateState::Verified)
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "native synthetic creates did not verify"
        );
        thread::sleep(Duration::from_millis(10));
    }
    mount.unmount().unwrap();
    assert_eq!(barrier.active.load(Ordering::SeqCst), 0);
}

#[test]
fn create_handoff_durable_marker_precedes_cache_ack_and_ack_failure_retains_writer() {
    let temp = tempfile::tempdir().unwrap();
    let mut fs = filesystem(&temp, Arc::new(FakeBackend::default()));
    let mut owner = enable_create_handoff(&mut fs, 1024 * 1024, false);
    let (_, handle) = new_create_bytes(&fs, "ack-boundary.txt", b"retain on ACK refusal");
    let (_, marker) = fs.spool_paths("personal", "/ack-boundary.txt");
    let admission = owner.handle();
    // Epoch remains current throughout staging/Ready. It changes exactly after
    // the receipt projection becomes durable, before the Engine Cache-ACK call.
    fs.create_handoff.as_mut().unwrap().current = Arc::new(move || {
        admission.is_accepting()
            && fs::read(&marker)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<OrdinaryWriteManifest>(&bytes).ok())
                .is_some_and(|marker| marker.handoff.is_none_or(|intent| intent.receipt.is_none()))
    });
    assert!(fs.commit(&handle).is_err());
    let open = handle.lock().unwrap();
    let OpenFile::Write(write) = &*open else {
        panic!("writer")
    };
    let marker: OrdinaryWriteManifest =
        serde_json::from_slice(&fs::read(&write.manifest).unwrap()).unwrap();
    assert!(marker.handoff.as_ref().unwrap().receipt.is_some());
    let intent = write.create.as_ref().unwrap().intent.as_ref().unwrap();
    let receipt = fs
        .engine
        .create_receipt_for_handoff(&write.scope, &write.path, &intent.id)
        .unwrap()
        .unwrap();
    assert!(!receipt.storage_receipt().local_handoff_acknowledged);
    assert!(write.dirty && !write.cleanup_on_release);
    assert!(create_handoff::ensure_mutable(write).is_err());
    assert_eq!(fs::read(&write.spool).unwrap(), b"retain on ACK refusal");
    drop(open);
    owner.stop_and_join().unwrap();
}

#[test]
fn create_handoff_persisted_receipt_cannot_be_downgraded_to_intent_only() {
    let temp = tempfile::tempdir().unwrap();
    let mut fs = filesystem(&temp, Arc::new(FakeBackend::default()));
    let mut owner = enable_create_handoff(&mut fs, 1024 * 1024, false);
    let (_, handle) = new_create_bytes(
        &fs,
        "no-downgrade.txt",
        b"persisted receipt retains ownership",
    );
    fs.commit(&handle).unwrap();
    let mut open = handle.lock().unwrap();
    let OpenFile::Write(write) = &mut *open else {
        panic!("writer")
    };
    let before = fs::read(&write.manifest).unwrap();
    let receipt = write
        .create
        .as_mut()
        .unwrap()
        .intent
        .as_mut()
        .unwrap()
        .receipt
        .take()
        .unwrap();
    assert!(create_handoff::persist(write).is_err());
    assert_eq!(fs::read(&write.manifest).unwrap(), before);
    write
        .create
        .as_mut()
        .unwrap()
        .intent
        .as_mut()
        .unwrap()
        .receipt = Some(receipt);
    drop(open);
    fs.finish_ordinary_handle(&handle).unwrap();
    owner.stop_and_join().unwrap();
}

#[test]
fn create_handoff_cleanup_preserves_same_inode_bytes_changed_after_ack() {
    let temp = tempfile::tempdir().unwrap();
    let mut fs = filesystem(&temp, Arc::new(FakeBackend::default()));
    let mut owner = enable_create_handoff(&mut fs, 1024 * 1024, false);
    let (_, handle) = new_create_bytes(&fs, "changed-after-ack.txt", b"original bytes");
    fs.commit(&handle).unwrap();
    let (spool, marker) = fs.spool_paths("personal", "/changed-after-ack.txt");
    fs::write(&spool, b"tampered bytes").unwrap();
    assert!(fs.finish_ordinary_handle(&handle).is_err());
    assert_eq!(fs::read(&spool).unwrap(), b"tampered bytes");
    assert!(marker.exists());
    owner.stop_and_join().unwrap();
}

#[test]
fn create_handoff_preledger_frozen_child_blocks_ordinary_ancestor_rmdir() {
    let temp = tempfile::tempdir().unwrap();
    let backend = Arc::new(FakeBackend::default());
    backend.add_space_entry("personal", "/ordinary-parent", b"", true, "parent-v1");
    let mut fs = filesystem(&temp, backend.clone());
    let mut owner = enable_create_handoff(&mut fs, 1, false);
    let parent = fs
        .children(PERSONAL)
        .unwrap()
        .into_iter()
        .find(|node| node.name == "ordinary-parent")
        .unwrap();
    let (_, handle) = new_create_bytes_in_parent(
        &fs,
        parent.ino,
        "failed-child.txt",
        b"preserve before Cache admission",
    );
    assert!(fs.commit(&handle).is_err());
    assert!(fs.finish_ordinary_handle(&handle).is_err()); // release writer reservation, retain recovery
    let scope = fs.engine.ordinary_write_scope("personal").unwrap();
    assert!(
        fs.engine
            .ordinary_create_page(&scope, None, 32)
            .unwrap()
            .items
            .is_empty()
    );
    assert!(
        fs.children(parent.ino).unwrap().is_empty(),
        "remote emptiness alone misses the local-only frozen child"
    );
    assert!(
        fs.delete_child(PERSONAL, OsStr::new("ordinary-parent"), true)
            .is_err()
    );
    assert!(
        backend
            .files
            .lock()
            .unwrap()
            .contains_key(&("personal".into(), "/ordinary-parent".into()))
    );
    let (spool, marker) = fs.spool_paths("personal", "/ordinary-parent/failed-child.txt");
    assert_eq!(fs::read(spool).unwrap(), b"preserve before Cache admission");
    assert!(marker.exists());
    owner.stop_and_join().unwrap();
}

struct EvictedCreateReadFixture {
    temp: tempfile::TempDir,
    fs: RaiunFilesystem,
    backend: Arc<FakeBackend>,
    owner: CreateUploadOwner,
    barrier: Arc<CreateBarrier>,
    ino: u64,
    scope: CacheScope,
    view: PendingCreateView,
}
impl EvictedCreateReadFixture {
    fn pending(dispatch: bool) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let barrier = Arc::new(CreateBarrier::default());
        let backend = Arc::new(FakeBackend {
            create_barrier: Some(barrier.clone()),
            ..FakeBackend::default()
        });
        let mut fs = filesystem(&temp, backend.clone());
        let owner = enable_create_handoff(&mut fs, 1024 * 1024, dispatch);
        let (node, handle) =
            new_create_bytes(&fs, "evicted-read.txt", b"original verified create bytes");
        fs.commit(&handle).unwrap();
        fs.finish_ordinary_handle(&handle).unwrap();
        if dispatch {
            barrier.wait_entered(1);
        }
        let NodeKind::PendingCreate { scope, view, .. } = fs.node(node.ino).unwrap().kind else {
            panic!("pending inode")
        };
        Self {
            temp,
            fs,
            backend,
            owner,
            barrier,
            ino: node.ino,
            scope,
            view: *view,
        }
    }
    fn cache(&self) -> raiun_cache::Cache {
        raiun_cache::Cache::open(&self.temp.path().join("handoff-cache"), 64 * 1024 * 1024).unwrap()
    }
    fn verify_and_evict(&mut self) {
        self.barrier.release();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            // Poll through the existing Engine/Cache connection. Cache::open
            // initializes schema and is not a read-only polling operation.
            let receipt = self
                .fs
                .engine
                .ordinary_create_page(&self.scope, None, 1)
                .unwrap()
                .items
                .into_iter()
                .next()
                .unwrap();
            if receipt.state == raiun_cache::OrdinaryCreateState::Verified {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "create did not verify: {:?}; transfers: {:?}",
                receipt,
                self.fs.engine.transfers(10).unwrap()
            );
            thread::sleep(Duration::from_millis(10));
        }
        self.owner.stop_and_join().unwrap();
        self.cache()
            .evict_acknowledged_ordinary_create_bodies(&self.scope, 0, 64)
            .unwrap();
        let receipt = self
            .cache()
            .ordinary_create_for_handoff(&self.scope, &self.view.receipt.handoff_id)
            .unwrap()
            .unwrap();
        assert!(receipt.body_evicted && receipt.local_handoff_acknowledged);
        assert_eq!(receipt.state, raiun_cache::OrdinaryCreateState::Verified);
        // Do not refresh the retained FUSE inode through GETATTR or listing.
        assert!(matches!(
            self.fs.node(self.ino).unwrap().kind,
            NodeKind::PendingCreate { .. }
        ));
    }
    fn download_count(&self) -> usize {
        self.fs
            .engine
            .transfers(500)
            .unwrap()
            .iter()
            .filter(|t| t.direction == "download")
            .count()
    }
}

#[test]
fn create_handoff_evicted_verified_body_opens_retained_pending_inode_without_getattr() {
    let mut fixture = EvictedCreateReadFixture::pending(true);
    fixture.verify_and_evict();
    let fh = fixture.fs.open_node(fixture.ino, libc::O_RDONLY).unwrap();
    let handle = fixture.fs.file_handle(fh).unwrap();
    let mut open = handle.lock().unwrap();
    let OpenFile::Read(ReadHandle::Snapshot(snapshot)) = &mut *open else {
        panic!("read snapshot")
    };
    let mut body = Vec::new();
    snapshot.read_to_end(&mut body).unwrap();
    assert_eq!(body, b"original verified create bytes");
    assert!(matches!(
        fixture.fs.node(fixture.ino).unwrap().kind,
        NodeKind::Remote { .. }
    ));
}

#[test]
fn create_handoff_eviction_after_pending_metadata_refresh_uses_exact_verified_snapshot() {
    let mut fixture = EvictedCreateReadFixture::pending(true);
    let refreshed = fixture.fs.refresh_remote_node(fixture.ino).unwrap();
    let NodeKind::PendingCreate { scope, view, .. } = refreshed.kind else {
        panic!("still active")
    };
    fixture.verify_and_evict(); // deterministic race boundary before body open
    let mut snapshot = fixture.fs.open_pending_create_read(&scope, &view).unwrap();
    let mut body = Vec::new();
    snapshot.read_to_end(&mut body).unwrap();
    assert_eq!(body, b"original verified create bytes");
}

#[test]
fn create_handoff_evicted_body_refuses_changed_root_id_revision_or_encryption() {
    for change in ["root", "id", "etag", "encrypted"] {
        let mut fixture = EvictedCreateReadFixture::pending(true);
        fixture.verify_and_evict();
        if change == "root" {
            fixture
                .backend
                .replace_root_id("personal", "different-root");
        } else {
            let mut files = fixture.backend.files.lock().unwrap();
            let entry = &mut files
                .get_mut(&("personal".into(), "/evicted-read.txt".into()))
                .unwrap()
                .0;
            match change {
                "id" => entry.id = "different-id".into(),
                "etag" => entry.etag = "\"different-revision\"".into(),
                "encrypted" => entry.encrypted = true,
                _ => unreachable!(),
            }
        }
        let before = fixture.download_count();
        assert!(
            fixture.fs.open_node(fixture.ino, libc::O_RDONLY).is_err(),
            "{change}"
        );
        assert_eq!(
            fixture.download_count(),
            before,
            "{change} must refuse before body download"
        );
    }
}

#[test]
fn create_handoff_active_and_uncertain_missing_bodies_never_fall_back_to_remote() {
    for uncertain in [false, true] {
        let mut fixture = EvictedCreateReadFixture::pending(uncertain);
        fixture.owner.stop_and_join().unwrap();
        let expected = if uncertain {
            raiun_cache::OrdinaryCreateState::Uncertain
        } else {
            raiun_cache::OrdinaryCreateState::Ready
        };
        let content = fixture.temp.path().join("handoff-cache/cache-v1/content");
        let blobs = fs::read_dir(content)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "blob"))
            .collect::<Vec<_>>();
        assert_eq!(blobs.len(), 1);
        fs::remove_file(&blobs[0]).unwrap(); // owned synthetic corruption fixture
        let before = fixture.download_count();
        assert!(fixture.fs.open_node(fixture.ino, libc::O_RDONLY).is_err());
        assert_eq!(fixture.download_count(), before);
        let receipt = fixture
            .cache()
            .ordinary_create_for_handoff(&fixture.scope, &fixture.view.receipt.handoff_id)
            .unwrap()
            .unwrap();
        assert_eq!(receipt.state, expected);
        assert!(!receipt.body_evicted);
    }
}

#[test]
fn create_handoff_evicted_snapshot_checks_full_original_digest_not_only_remote_metadata() {
    let mut fixture = EvictedCreateReadFixture::pending(true);
    fixture.verify_and_evict();
    {
        let mut files = fixture.backend.files.lock().unwrap();
        let (_, bytes) = files
            .get_mut(&("personal".into(), "/evicted-read.txt".into()))
            .unwrap();
        bytes[0] ^= 1; // same real ID/strong revision/length, wrong remote content
    }
    assert!(fixture.fs.open_node(fixture.ino, libc::O_RDONLY).is_err());
    assert!(matches!(
        fixture.fs.node(fixture.ino).unwrap().kind,
        NodeKind::PendingCreate { .. }
    ));
    assert!(
        fixture.fs.open_node(fixture.ino, libc::O_RDONLY).is_err(),
        "a failed digest must not promote the next open around the receipt check"
    );
}

#[test]
fn create_handoff_offline_restart_registers_known_invalidated_scope_and_preserves_reads() {
    for uncertain in [false, true] {
        let mut fixture = EvictedCreateReadFixture::pending(uncertain);
        fixture.owner.stop_and_join().unwrap();
        let EvictedCreateReadFixture {
            temp: _temp,
            fs,
            backend,
            owner,
            barrier,
            scope,
            ino,
            ..
        } = fixture;
        drop(owner); // release old sole ownership before new scope recovery
        backend.set_network_error(Some(ErrorKind::Offline));
        assert!(
            fs.engine.list("personal", "/").is_err(),
            "invalidated listing cannot stand for a complete offline directory"
        );
        let sends = barrier.state.lock().unwrap().0;
        let mut owner = fs
            .engine
            .start_create_upload_owner(CreateUploadHooks {
                is_current: Arc::new(|| true),
                dispatch_allowed: Arc::new(|_| false),
            })
            .unwrap();
        fs.register_create_upload_scopes(&owner.handle()).unwrap();
        assert_eq!(barrier.state.lock().unwrap().0, sends);
        assert!(
            fs.children(PERSONAL)
                .unwrap()
                .iter()
                .any(|node| matches!(node.kind, NodeKind::PendingCreate { .. }))
        );
        let fh = fs.open_node(ino, libc::O_RDONLY).unwrap();
        let handle = fs.file_handle(fh).unwrap();
        let mut open = handle.lock().unwrap();
        let OpenFile::Read(ReadHandle::Snapshot(snapshot)) = &mut *open else {
            panic!("offline immutable snapshot")
        };
        let mut body = Vec::new();
        snapshot.read_to_end(&mut body).unwrap();
        assert_eq!(body, b"original verified create bytes");
        let page = fs.engine.ordinary_create_page(&scope, None, 1).unwrap();
        assert_eq!(
            page.items[0].state,
            if uncertain {
                raiun_cache::OrdinaryCreateState::Uncertain
            } else {
                raiun_cache::OrdinaryCreateState::Ready
            }
        );
        drop(open);
        owner.stop_and_join().unwrap();
    }
}

fn unregistered_create_scope_fixture() -> (
    tempfile::TempDir,
    RaiunFilesystem,
    Arc<FakeBackend>,
    CreateUploadOwner,
) {
    let temp = tempfile::tempdir().unwrap();
    let backend = Arc::new(FakeBackend::default());
    let mut fs = filesystem(&temp, backend.clone());
    let cache = temp.path().join("unregistered-cache");
    fs::create_dir(&cache).unwrap();
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o700)).unwrap();
    fs.engine = fs
        .engine
        .with_offline_cache(
            raiun_cache::Cache::open(&cache, 64 * 1024 * 1024).unwrap(),
            "fuse-test-account".into(),
            "https://example.invalid".into(),
        )
        .unwrap();
    let owner = fs
        .engine
        .start_create_upload_owner(CreateUploadHooks {
            is_current: Arc::new(|| true),
            dispatch_allowed: Arc::new(|_| false),
        })
        .unwrap();
    (temp, fs, backend, owner)
}

#[test]
fn create_handoff_scope_registration_initializes_only_genuinely_unregistered_online_scope() {
    let (_temp, fs, backend, mut owner) = unregistered_create_scope_fixture();
    let scope = fs
        .engine
        .ordinary_create_scope("personal")
        .unwrap()
        .unwrap();
    assert_eq!(
        fs.engine
            .ordinary_create_page(&scope, None, 1)
            .unwrap_err()
            .kind,
        ErrorKind::NotFound
    );
    let before = backend.list_calls.load(Ordering::SeqCst);
    fs.register_create_upload_scopes(&owner.handle()).unwrap();
    assert_eq!(backend.list_calls.load(Ordering::SeqCst), before + 1);
    assert!(
        fs.engine
            .ordinary_create_page(&scope, None, 1)
            .unwrap()
            .items
            .is_empty()
    );
    fs.register_create_upload_scopes(&owner.handle()).unwrap();
    assert_eq!(
        backend.list_calls.load(Ordering::SeqCst),
        before + 1,
        "known scope does not require another complete listing"
    );
    owner.stop_and_join().unwrap();
}

#[test]
fn create_handoff_scope_registration_refuses_offline_unknown_or_changed_root() {
    {
        let (_temp, fs, backend, mut owner) = unregistered_create_scope_fixture();
        backend.set_network_error(Some(ErrorKind::Offline));
        assert!(fs.register_create_upload_scopes(&owner.handle()).is_err());
        assert_eq!(backend.list_calls.load(Ordering::SeqCst), 0);
        owner.stop_and_join().unwrap();
    }
    {
        let (_temp, fs, backend, mut owner) = unregistered_create_scope_fixture();
        *backend.root_on_next_list.lock().unwrap() =
            Some("root-changed-during-initialization".into());
        assert!(fs.register_create_upload_scopes(&owner.handle()).is_err());
        owner.stop_and_join().unwrap();
    }
}
