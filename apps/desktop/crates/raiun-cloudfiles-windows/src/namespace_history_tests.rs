use super::*;

// Fail immediately if the reader tries to create/publish or read snapshot bodies.
struct ReadOnlyProtector(Arc<dyn EditRecordProtector>);
impl EditRecordProtector for ReadOnlyProtector {
    fn seal(&self, _: &[u8], _: &[u8]) -> Result<Vec<u8>, crate::JournalError> {
        panic!("history reader must not seal or publish metadata")
    }
    fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, crate::JournalError> {
        self.0.open(aad, sealed)
    }
    fn protect_directory(&self, _: &std::path::Path) -> Result<(), crate::JournalError> {
        panic!("history reader must not repair directory protection")
    }
}
struct ReadOnly(Arc<dyn Directory>);
impl Directory for ReadOnly {
    fn verify(&self) -> Result<(), StoreError> {
        self.0.verify()
    }
    fn entries(&self, limit: usize) -> Result<Vec<String>, StoreError> {
        self.0.entries(limit)
    }
    fn child(&self, name: &str, create: bool) -> Result<Arc<dyn Directory>, StoreError> {
        assert!(!create, "history reader must not create directories");
        Ok(Arc::new(Self(self.0.child(name, false)?)))
    }
    fn create(&self, _: &str) -> Result<(Box<dyn StageWrite>, Identity), StoreError> {
        panic!("history reader must not create files")
    }
    fn open(&self, name: &str) -> Result<Box<dyn PinnedRead>, StoreError> {
        assert!(
            !name.contains("body"),
            "history reader must not read payloads"
        );
        self.0.open(name)
    }
    fn publish(&self, _: &str, _: &str, _: Identity) -> Result<(), StoreError> {
        panic!("history reader must not publish")
    }
}
fn group(base: &SnapshotStore) -> (crate::ProviderScope, crate::ConfiguredRootIdentity) {
    let client = raiun_opencloud::OpenCloudClient::new_with_proxy(
        &base.scope.server_origin,
        "synthetic-token".into(),
        &raiun_opencloud::ProxyConfig::Direct,
    )
    .unwrap();
    (
        crate::ProviderScope::new(
            &client,
            base.scope.profile_id.clone(),
            base.scope.account_subject.clone(),
            base.scope.server_origin.clone(),
        )
        .unwrap(),
        crate::ConfiguredRootIdentity {
            volume_serial: base.scope.root_volume_serial,
            file_index: base.scope.root_file_index,
        },
    )
}
fn summary(
    base: &SnapshotStore,
    policy: StorePolicy,
) -> Result<NamespaceHistorySummary, StoreError> {
    let (provider, physical) = group(base);
    history_summary_existing(
        Some(Arc::new(ReadOnly(Arc::clone(&base.root)))),
        Arc::new(ReadOnlyProtector(Arc::clone(&base.protector))),
        policy,
        &provider,
        physical,
    )
}
fn related(base: &SnapshotStore, change: impl FnOnce(&mut EditJournalScope)) -> Arc<SnapshotStore> {
    let mut scope = base.scope.clone();
    change(&mut scope);
    SnapshotStore::from_directory(
        Arc::clone(&base.root),
        scope,
        Arc::clone(&base.protector),
        base.policy,
    )
    .unwrap()
}
fn publish(base: &Arc<SnapshotStore>, generation: u64, done: bool) {
    let store = FileRenameStore::new(Arc::clone(base)).unwrap();
    let mut candidate = intent(base, "before.bin", "after.bin", generation);
    if let NamespaceOperation::MoveWithinScope {
        source,
        destination,
    } = &mut candidate.operation
    {
        source.local.local_file.file_index += generation * 100;
        destination.local_file = source.local.local_file;
    }
    let publication = fresh(store.publish_intent(candidate).unwrap());
    if done {
        let mut lease = publication.acquire_dispatch().unwrap();
        complete(&mut lease);
    }
}

#[test]
fn absent_empty_and_lock_only_are_read_only_and_invalid_target_is_not_empty() {
    let (_temp, base, _) = fixture();
    let (provider, physical) = group(&base);
    assert_eq!(
        history_summary_existing(
            None,
            Arc::clone(&base.protector),
            policy(),
            &provider,
            physical
        )
        .unwrap(),
        NamespaceHistorySummary::default()
    );
    assert!(
        history_summary_existing(
            None,
            Arc::clone(&base.protector),
            policy(),
            &provider,
            crate::ConfiguredRootIdentity {
                file_index: 0,
                ..physical
            }
        )
        .is_err()
    );
    assert!(base.root.entries(10).unwrap().is_empty());
    assert!(matches!(
        summary(&base, policy()),
        Err(StoreError::IncompleteEvidence)
    ));
    assert!(base.root.entries(10).unwrap().is_empty());
    drop(base.acquire_lock().unwrap());
    assert_eq!(
        summary(&base, policy()).unwrap(),
        NamespaceHistorySummary::default()
    );
    assert_eq!(base.root.entries(10).unwrap(), vec![V2_QUOTA_LOCK]);
}

#[test]
fn pending_complete_and_mixed_actual_scopes_are_grouped_without_body_reads() {
    let (_temp, base, _) = fixture();
    publish(&base, 1, false);
    assert_eq!(
        summary(&base, policy()).unwrap(),
        NamespaceHistorySummary {
            records: 1,
            unresolved: 1,
            other_namespace_evidence: false,
            ..NamespaceHistorySummary::default()
        }
    );
    let second = related(&base, |scope| {
        scope.space_id = "space-two".into();
        scope.root_resource_id = "root-two".into();
    });
    publish(&second, 2, true);
    assert_eq!(
        summary(&second, policy()).unwrap(),
        NamespaceHistorySummary {
            records: 2,
            unresolved: 1,
            other_namespace_evidence: false,
            ..NamespaceHistorySummary::default()
        }
    );
    let foreign = related(&base, |scope| scope.account_subject = "foreign".into());
    publish(&foreign, 3, true);
    assert_eq!(
        summary(&foreign, policy()).unwrap(),
        NamespaceHistorySummary {
            records: 1,
            unresolved: 0,
            other_namespace_evidence: false,
            ..NamespaceHistorySummary::default()
        }
    );
    for change in [0, 1, 2, 3] {
        let other = related(&base, |scope| match change {
            0 => scope.profile_id = "other".into(),
            1 => scope.server_origin = "https://other.invalid".into(),
            2 => scope.root_volume_serial += 1,
            _ => scope.root_file_index += 1,
        });
        assert_eq!(
            summary(&other, policy()).unwrap(),
            NamespaceHistorySummary::default()
        );
    }
}

#[test]
fn corrupt_prefix_shared_budget_and_missing_or_nonzero_lock_are_unknown() {
    let (temp, base, _) = fixture();
    publish(&base, 1, false);
    let mut bounded = policy();
    bounded.max_metadata_bytes_per_scan = 1;
    assert!(summary(&base, bounded).is_err());
    let mut bounded = policy();
    bounded.max_entries = 3;
    assert!(summary(&base, bounded).is_err());
    let directory = temp.path().join(ROOT).join(scope_key(&base.scope).unwrap());
    let entry = std::fs::read_dir(&directory)
        .unwrap()
        .find_map(|entry| {
            let p = entry.unwrap().path();
            p.to_string_lossy().ends_with(".intent").then_some(p)
        })
        .unwrap();
    let original = std::fs::read(&entry).unwrap();
    std::fs::write(&entry, b"bad authenticated metadata").unwrap();
    assert!(summary(&base, policy()).is_err());
    std::fs::write(&entry, original).unwrap();
    std::fs::write(temp.path().join(V2_QUOTA_LOCK), b"x").unwrap();
    assert!(summary(&base, policy()).is_err());
    std::fs::remove_file(temp.path().join(V2_QUOTA_LOCK)).unwrap();
    assert!(summary(&base, policy()).is_err());
    assert!(!temp.path().join(V2_QUOTA_LOCK).exists());
}

#[test]
fn budget_is_shared_between_catalogs_and_selected_event_prefixes() {
    let (_temp, base, _) = fixture();
    publish(&base, 1, true);
    let one = summary(&base, policy()).unwrap();
    assert_eq!(one.unresolved, 0);
    // One catalog and complete prefix fit; aggregate enumeration across a
    // second real scope cannot reset the same bounded entry allowance.
    let mut bounded = policy();
    bounded.max_entries = 15;
    assert!(summary(&base, bounded).is_ok());
    let second = related(&base, |scope| scope.space_id = "another-space".into());
    publish(&second, 2, true);
    assert!(matches!(
        summary(&base, bounded),
        Err(StoreError::ScanLimit)
    ));
}

#[test]
fn file_format_presence_requires_configuration_and_catalogs_are_authenticated() {
    {
        let name = namespace_file_store::ROOT;
        let (_temp, base, _) = fixture();
        drop(base.acquire_lock().unwrap());
        let other = base.root.child(name, true).unwrap();
        let read = summary(&base, policy()).unwrap();
        assert!(read.file_evidence);
        assert!(history_unresolved(&read, false).is_err());
        assert_eq!(history_unresolved(&read, true), Ok(false));
        other.child(&"a".repeat(64), true).unwrap();
        let (mut stage, _) = other.create(&format!("{}.scope", "a".repeat(64))).unwrap();
        stage.write_all(b"corrupt catalog").unwrap();
        stage.sync().unwrap();
        drop(stage);
        assert!(summary(&base, policy()).is_err());
    }
}

#[test]
fn snapshot_catalogs_authenticate_without_reading_payloads_or_counting_them_as_renames() {
    let (_temp, base, _) = fixture();
    let reservation = base
        .try_begin_capture(SnapshotBinding {
            record_id: String::new(),
            scope: base.scope.clone(),
            generation: 1,
            local_file: LocalFileIdentity {
                volume_serial: base.scope.root_volume_serial,
                file_index: 99,
            },
            relative_path: "snapshot.bin".into(),
            remote: None,
            content_len: 3,
        })
        .unwrap();
    reservation
        .capture(&mut std::io::Cursor::new(b"abc"), &mut || false)
        .unwrap()
        .verify_and_commit(&mut || false)
        .unwrap();
    assert_eq!(
        summary(&base, policy()).unwrap(),
        NamespaceHistorySummary::default()
    );
    publish(&base, 1, false);
    assert_eq!(summary(&base, policy()).unwrap().unresolved, 1);
    // Even a foreign or snapshot-only catalog is authenticated globally.
    let catalog = format!("{}.scope", scope_key(&base.scope).unwrap());
    let mut stored = base.root.open(&catalog).unwrap();
    let mut bytes = Vec::new();
    stored.read_to_end(&mut bytes).unwrap();
    drop(stored);
    bytes[0] ^= 1;
    // Exact synthetic backing file mutation, never performed by the reader.
    // The fixture root is a real temporary directory and has no user state.
    let path = _temp.path().join(catalog);
    std::fs::write(path, bytes).unwrap();
    assert!(summary(&base, policy()).is_err());
}

fn publish_directory(base: &Arc<SnapshotStore>, generation: u64, done: bool) -> String {
    let store = namespace_store::synthetic_history_store(Arc::clone(base));
    let destination = LocalNamespaceEntry {
        parent: parent(base),
        name: format!("directory-{generation}"),
        local_file: LocalFileIdentity {
            volume_serial: base.scope.root_volume_serial,
            file_index: 10000 + generation,
        },
        object_kind: NamespaceObjectKind::Directory,
    };
    let publication = store
        .publish_intent(NamespaceIntent {
            schema_version: 1,
            record_id: "0".repeat(32),
            record_generation: generation,
            operation: NamespaceOperation::CreateDirectory {
                destination: destination.clone(),
            },
        })
        .unwrap();
    let id = publication.record.intent.record_id.clone();
    if done {
        let mut lease = store.acquire_dispatch(&publication.record.key).unwrap();
        lease
            .append_event(NamespaceEventKind::RemoteSubmitted)
            .unwrap();
        lease
            .append_event(NamespaceEventKind::RemoteVerified {
                report: NamespaceDestinationReport {
                    destination: destination.clone(),
                    remote: RemoteEditBaseline {
                        resource_id: format!("created-directory-{generation}"),
                        etag: "\"mkdir-etag\"".into(),
                        byte_len: 0,
                    },
                    content: None,
                },
            })
            .unwrap();
        lease
            .append_event(NamespaceEventKind::LocalCompleted { destination })
            .unwrap();
        assert!(lease.progress().recorded_complete);
    }
    id
}
fn directory_path(temp: &tempfile::TempDir, base: &SnapshotStore) -> std::path::PathBuf {
    temp.path()
        .join(namespace_store::ROOT)
        .join(scope_key(&base.scope).unwrap())
}
#[test]
fn completed_directory_and_rename_share_actual_health_policy_read_only() {
    let (_temp, base, _) = fixture();
    publish(&base, 1, true);
    publish_directory(&base, 2, true);
    let read = summary(&base, policy()).unwrap();
    assert_eq!((read.records, read.unresolved), (1, 0));
    assert_eq!((read.directory_records, read.directory_unresolved), (1, 0));
    assert!(read.directory_evidence);
    assert_eq!(history_unresolved(&read, true), Ok(false));
    assert!(history_unresolved(&read, false).is_err());
    publish_directory(&base, 3, false);
    let read = summary(&base, policy()).unwrap();
    assert_eq!((read.directory_records, read.directory_unresolved), (2, 1));
    assert_eq!(history_unresolved(&read, true), Ok(true));
}
#[test]
fn empty_directory_root_and_catalog_need_explicit_namespace_context() {
    let (temp, base, _) = fixture();
    drop(base.acquire_lock().unwrap());
    base.root.child(namespace_store::ROOT, true).unwrap();
    let empty = summary(&base, policy()).unwrap();
    assert!(empty.directory_evidence);
    assert_eq!(empty.directory_records, 0);
    assert!(history_unresolved(&empty, false).is_err());
    assert_eq!(history_unresolved(&empty, true), Ok(false));
    let id = publish_directory(&base, 1, false);
    std::fs::remove_file(directory_path(&temp, &base).join(format!("{id}.intent"))).unwrap();
    let catalog_only = summary(&base, policy()).unwrap();
    assert!(catalog_only.directory_evidence);
    assert_eq!(catalog_only.directory_records, 0);
    assert!(history_unresolved(&catalog_only, false).is_err());
    assert_eq!(history_unresolved(&catalog_only, true), Ok(false));
}
#[test]
fn directory_missing_prefix_or_catalog_and_foreign_selected_record_are_unknown() {
    for case in 0..4 {
        let (temp, base, _) = fixture();
        publish(&base, 1, true);
        let id = publish_directory(&base, 2, true);
        match case {
            0 => std::fs::remove_file(
                directory_path(&temp, &base).join(format!("{id}.event.{:020}", 2)),
            )
            .unwrap(),
            1 => std::fs::write(
                temp.path()
                    .join(namespace_store::ROOT)
                    .join(format!("{}.scope", scope_key(&base.scope).unwrap())),
                b"corrupt catalog",
            )
            .unwrap(),
            2 => std::fs::remove_file(
                temp.path()
                    .join(namespace_store::ROOT)
                    .join(format!("{}.scope", scope_key(&base.scope).unwrap())),
            )
            .unwrap(),
            _ => {
                let foreign = related(&base, |s| s.root_file_index += 1);
                let other = publish_directory(&foreign, 3, false);
                let foreign_bytes =
                    std::fs::read(directory_path(&temp, &foreign).join(format!("{other}.intent")))
                        .unwrap();
                std::fs::write(
                    directory_path(&temp, &base).join(format!("{id}.intent")),
                    foreign_bytes,
                )
                .unwrap();
            }
        }
        assert!(summary(&base, policy()).is_err(), "case={case}");
    }
}
#[test]
fn foreign_directory_catalogs_are_authenticated_and_names_validated_not_selected() {
    let (temp, base, _) = fixture();
    let foreign = related(&base, |s| s.account_subject = "foreign-account".into());
    publish_directory(&foreign, 1, true);
    let read = summary(&base, policy()).unwrap();
    assert!(read.directory_evidence);
    assert_eq!((read.directory_records, read.directory_unresolved), (0, 0));
    assert!(history_unresolved(&read, false).is_err());
    assert_eq!(history_unresolved(&read, true), Ok(false));
    std::fs::write(
        directory_path(&temp, &foreign).join("unknown-partial"),
        b"retained",
    )
    .unwrap();
    assert!(summary(&base, policy()).is_err());
}
fn entry_floor(base: &SnapshotStore) -> usize {
    let mut low = 4;
    let mut high = policy().max_entries;
    while low < high {
        let mid = low + (high - low) / 2;
        let mut limit = policy();
        limit.max_entries = mid;
        match summary(base, limit) {
            Ok(_) => high = mid,
            Err(StoreError::ScanLimit) => low = mid + 1,
            Err(other) => panic!("unexpected bounded reader error: {other:?}"),
        }
    }
    low
}
#[test]
fn mixed_formats_use_one_allowance_and_directory_remaining_record_limit() {
    let (_temp, base, _) = fixture();
    publish(&base, 1, true);
    let rename_floor = entry_floor(&base);
    let (_other_temp, directory_only, _) = fixture();
    publish_directory(&directory_only, 1, true);
    let directory_floor = entry_floor(&directory_only);
    publish_directory(&base, 2, true);
    let mut limit = policy();
    limit.max_entries = rename_floor.max(directory_floor);
    assert!(matches!(summary(&base, limit), Err(StoreError::ScanLimit)));
    assert_eq!(
        history_unresolved(&summary(&base, policy()).unwrap(), true),
        Ok(false)
    );
    publish_directory(&base, 3, false);
    let dir = base
        .root
        .child(namespace_store::ROOT, false)
        .unwrap()
        .child(&scope_key(&base.scope).unwrap(), false)
        .unwrap();
    let (provider, physical) = group(&base);
    assert!(matches!(
        namespace_store::history_counts_existing(
            &ReadOnly(dir.clone()),
            &ReadOnlyProtector(Arc::clone(&base.protector)),
            &base.scope,
            &provider,
            physical,
            &mut Budget::new(policy()),
            1
        ),
        Err(StoreError::ScanLimit)
    ));
    assert_eq!(
        namespace_store::history_counts_existing(
            &ReadOnly(dir),
            &ReadOnlyProtector(Arc::clone(&base.protector)),
            &base.scope,
            &provider,
            physical,
            &mut Budget::new(policy()),
            2
        )
        .unwrap(),
        (2, 1)
    );
    // Simulate the caller's already consumed metadata allowance, then feed
    // both actual decoders the SAME remaining Budget. Each alone fits.
    let rename_dir = base
        .root
        .child(ROOT, false)
        .unwrap()
        .child(&scope_key(&base.scope).unwrap(), false)
        .unwrap();
    let decoder = FileRenameStore {
        base: SnapshotStore::from_directory(
            Arc::new(ReadOnly(Arc::clone(&base.root))),
            base.scope.clone(),
            Arc::new(ReadOnlyProtector(Arc::clone(&base.protector))),
            policy(),
        )
        .unwrap(),
    };
    let mut rename_budget = Budget::new(policy());
    let names = record_names(&*rename_dir, &mut rename_budget).unwrap();
    decoder
        .load_records(
            &ReadOnly(rename_dir.clone()),
            &base.scope,
            &names,
            &mut rename_budget,
            2,
        )
        .unwrap();
    let rename_bytes = policy().max_metadata_bytes_per_scan - rename_budget.bytes;
    let mut directory_budget = Budget::new(policy());
    let directory = base
        .root
        .child(namespace_store::ROOT, false)
        .unwrap()
        .child(&scope_key(&base.scope).unwrap(), false)
        .unwrap();
    namespace_store::history_counts_existing(
        &ReadOnly(directory.clone()),
        &ReadOnlyProtector(Arc::clone(&base.protector)),
        &base.scope,
        &provider,
        physical,
        &mut directory_budget,
        2,
    )
    .unwrap();
    let directory_bytes = policy().max_metadata_bytes_per_scan - directory_budget.bytes;
    let mut shared_budget = Budget::new(policy());
    shared_budget.bytes = rename_bytes.max(directory_bytes);
    let names = record_names(&*rename_dir, &mut shared_budget).unwrap();
    decoder
        .load_records(
            &ReadOnly(rename_dir),
            &base.scope,
            &names,
            &mut shared_budget,
            2,
        )
        .unwrap();
    assert!(matches!(
        namespace_store::history_counts_existing(
            &ReadOnly(directory),
            &ReadOnlyProtector(Arc::clone(&base.protector)),
            &base.scope,
            &provider,
            physical,
            &mut shared_budget,
            2
        ),
        Err(StoreError::ScanLimit)
    ));
    let root = base.root.child(namespace_store::ROOT, false).unwrap();
    let scopes = namespace_store::validated_catalog_scopes(
        &ReadOnly(root.clone()),
        &*base.protector,
        &mut Budget::new(policy()),
    )
    .unwrap();
    let keys = namespace_store::validated_catalog_scope_keys(
        &ReadOnly(root),
        &*base.protector,
        &mut Budget::new(policy()),
    )
    .unwrap();
    assert_eq!(scopes, vec![base.scope.clone()]);
    assert_eq!(keys, vec![scope_key(&base.scope).unwrap()]);
}

fn publish_file(base: &Arc<SnapshotStore>, generation: u64) -> namespace_file_store::FileCreateKey {
    let name = format!("created-{generation}.bin");
    let destination = LocalNamespaceEntry {
        parent: parent(base),
        name: name.clone(),
        local_file: LocalFileIdentity {
            volume_serial: base.scope.root_volume_serial,
            file_index: 20000 + generation,
        },
        object_kind: NamespaceObjectKind::File,
    };
    let path = format!("Documents/{name}");
    let reservation = base
        .try_begin_capture(SnapshotBinding {
            record_id: String::new(),
            scope: base.scope.clone(),
            generation,
            local_file: destination.local_file,
            relative_path: path.clone(),
            remote: None,
            content_len: 3,
        })
        .unwrap();
    let committed = reservation
        .capture(&mut std::io::Cursor::new(b"abc"), &mut || false)
        .unwrap()
        .verify_and_commit(&mut || false)
        .unwrap();
    let digest = hex(committed.manifest().content_sha256());
    let files = namespace_file_store::FileCreateStore::new(Arc::clone(base)).unwrap();
    files
        .publish_fresh(
            NamespaceIntent {
                schema_version: 1,
                record_id: "0".repeat(32),
                record_generation: generation,
                operation: NamespaceOperation::CreateFile {
                    destination,
                    content: crate::namespace_intent::NamespaceFileContent {
                        byte_len: 3,
                        sha256: digest,
                    },
                },
            },
            committed,
            namespace_file_store::CapturedCreatePath::new(
                vec!["Personal".into(), "Documents".into(), name],
                path,
            )
            .unwrap(),
            &mut || false,
        )
        .unwrap()
        .record()
        .key()
        .clone()
}
fn file_path(temp: &tempfile::TempDir, base: &SnapshotStore) -> std::path::PathBuf {
    temp.path()
        .join(namespace_file_store::ROOT)
        .join(scope_key(&base.scope).unwrap())
}
#[test]
fn file_pending_submitted_and_attention_remain_unresolved_without_body_access() {
    let (_temp, base, _) = fixture();
    publish(&base, 1, true);
    publish_directory(&base, 2, true);
    let key = publish_file(&base, 3);
    let files = namespace_file_store::FileCreateStore::new(Arc::clone(&base)).unwrap();
    let mut lease = files.acquire_dispatch(&key).unwrap();
    for step in 0..3 {
        if step > 0 {
            if step == 1 {
                lease.mark_submitted().unwrap();
            } else {
                lease
                    .record_attention(crate::namespace_intent::NamespaceAttention::Uncertain)
                    .unwrap();
            }
        }
        let read = summary(&base, policy()).unwrap();
        assert_eq!(
            (
                read.records,
                read.directory_records,
                read.file_records,
                read.file_unresolved
            ),
            (1, 1, 1, 1)
        );
        assert!(read.file_evidence);
        assert_eq!(history_unresolved(&read, true), Ok(true));
        assert!(history_unresolved(&read, false).is_err());
    }
}
#[test]
fn empty_file_catalog_stays_configuration_bound_and_missing_body_is_never_clean() {
    let (temp, base, _) = fixture();
    let key = publish_file(&base, 1);
    let files = namespace_file_store::FileCreateStore::new(Arc::clone(&base)).unwrap();
    let record = files.discover().unwrap().pop().unwrap();
    std::fs::remove_file(
        temp.path()
            .join(scope_key(&base.scope).unwrap())
            .join(format!("{}.body", record.snapshot_id())),
    )
    .unwrap();
    assert!(files.discover().is_err());
    assert!(files.open_joined(&key, &mut || false).is_err());
    let read = summary(&base, policy()).unwrap();
    assert_eq!((read.file_records, read.file_unresolved), (1, 1));
    assert_eq!(history_unresolved(&read, true), Ok(true));
    std::fs::remove_file(file_path(&temp, &base).join(format!("{}.intent", key.record_id())))
        .unwrap();
    let read = summary(&base, policy()).unwrap();
    assert_eq!(read.file_records, 0);
    assert_eq!(history_unresolved(&read, true), Ok(false));
    assert!(history_unresolved(&read, false).is_err());
}
#[test]
fn create_join_corruption_missing_reference_or_stage_never_becomes_clean() {
    for case in 0..5 {
        let (temp, base, _) = fixture();
        let key = publish_file(&base, 1);
        let dir = file_path(&temp, &base);
        match case {
            0 => std::fs::write(
                dir.join(format!("{}.intent", key.record_id())),
                b"corrupt join",
            )
            .unwrap(),
            1 => std::fs::write(
                temp.path()
                    .join(namespace_file_store::ROOT)
                    .join(format!("{}.scope", scope_key(&base.scope).unwrap())),
                b"corrupt catalog",
            )
            .unwrap(),
            2 => std::fs::write(
                dir.join(format!("{}.event.{:020}", key.record_id(), 2)),
                b"missing first event",
            )
            .unwrap(),
            3 => std::fs::write(dir.join("unknown.stage"), b"incomplete").unwrap(),
            _ => {
                let files = namespace_file_store::FileCreateStore::new(Arc::clone(&base)).unwrap();
                let row = files.discover().unwrap().pop().unwrap();
                std::fs::remove_file(
                    temp.path()
                        .join(scope_key(&base.scope).unwrap())
                        .join(format!("{}.manifest", row.snapshot_id())),
                )
                .unwrap();
            }
        }
        assert!(summary(&base, policy()).is_err(), "case={case}");
    }
}
#[test]
fn legitimate_foreign_create_scope_is_not_adopted_but_selected_transplant_fails() {
    let (temp, base, _) = fixture();
    let foreign = related(&base, |s| s.root_file_index += 1);
    let foreign_key = publish_file(&foreign, 1);
    let read = summary(&base, policy()).unwrap();
    assert!(read.file_evidence);
    assert_eq!((read.file_records, read.file_unresolved), (0, 0));
    assert_eq!(history_unresolved(&read, true), Ok(false));
    assert!(history_unresolved(&read, false).is_err());
    let key = publish_file(&base, 2);
    let bytes = std::fs::read(
        file_path(&temp, &foreign).join(format!("{}.intent", foreign_key.record_id())),
    )
    .unwrap();
    std::fs::write(
        file_path(&temp, &base).join(format!("{}.intent", key.record_id())),
        bytes,
    )
    .unwrap();
    assert!(summary(&base, policy()).is_err());
}
#[test]
fn all_three_formats_share_entry_metadata_and_remaining_record_allowance() {
    let (_temp, base, _) = fixture();
    publish(&base, 1, true);
    let rename_floor = entry_floor(&base);
    let (_dtemp, directory, _) = fixture();
    publish_directory(&directory, 1, true);
    let directory_floor = entry_floor(&directory);
    let (_ftemp, file, _) = fixture();
    publish_file(&file, 1);
    let file_floor = entry_floor(&file);
    publish_directory(&base, 2, true);
    publish_file(&base, 3);
    let mut limit = policy();
    limit.max_entries = rename_floor.max(directory_floor).max(file_floor);
    assert!(matches!(summary(&base, limit), Err(StoreError::ScanLimit)));
    publish_file(&base, 4);
    let (provider, physical) = group(&base);
    let read = |budget: &mut Budget, remaining| {
        namespace_file_store::history_counts_existing(
            Arc::new(ReadOnly(Arc::clone(&base.root))),
            Arc::new(ReadOnlyProtector(Arc::clone(&base.protector))),
            policy(),
            &provider,
            physical,
            budget,
            remaining,
        )
    };
    assert!(matches!(
        read(&mut Budget::new(policy()), 1),
        Err(StoreError::ScanLimit)
    ));
    assert_eq!(read(&mut Budget::new(policy()), 2).unwrap(), (2, 2));
    let mut tight = Budget::new(policy());
    tight.bytes = 1;
    assert!(matches!(read(&mut tight, 2), Err(StoreError::ScanLimit)));
    // Keep a valid StorePolicy while simulating the caller's partially spent
    // metadata allowance. The SAME budget passes through all three decoders.
    let _quota = base.acquire_lock().unwrap();
    let rename_directory = base
        .root
        .child(ROOT, false)
        .unwrap()
        .child(&scope_key(&base.scope).unwrap(), false)
        .unwrap();
    let directory_directory = base
        .root
        .child(namespace_store::ROOT, false)
        .unwrap()
        .child(&scope_key(&base.scope).unwrap(), false)
        .unwrap();
    let rename_decoder = FileRenameStore {
        base: SnapshotStore::from_directory(
            Arc::new(ReadOnly(Arc::clone(&base.root))),
            base.scope.clone(),
            Arc::new(ReadOnlyProtector(Arc::clone(&base.protector))),
            policy(),
        )
        .unwrap(),
    };
    let rename_read = |budget: &mut Budget| {
        let names = record_names(&*rename_directory, budget)?;
        rename_decoder
            .load_records(
                &ReadOnly(rename_directory.clone()),
                &base.scope,
                &names,
                budget,
                1,
            )
            .map(|_| ())
    };
    let directory_read = |budget: &mut Budget| {
        namespace_store::history_counts_existing(
            &ReadOnly(directory_directory.clone()),
            &ReadOnlyProtector(Arc::clone(&base.protector)),
            &base.scope,
            &provider,
            physical,
            budget,
            1,
        )
    };
    let mut rb = Budget::new(policy());
    rename_read(&mut rb).unwrap();
    let mut db = Budget::new(policy());
    directory_read(&mut db).unwrap();
    let mut fb = Budget::new(policy());
    read(&mut fb, 2).unwrap();
    let used = |b: &Budget| policy().max_metadata_bytes_per_scan - b.bytes;
    let mut shared = Budget::new(policy());
    shared.bytes = used(&rb) + used(&db) + used(&fb) - 1;
    rename_read(&mut shared).unwrap();
    directory_read(&mut shared).unwrap();
    assert!(matches!(read(&mut shared, 2), Err(StoreError::ScanLimit)));
    drop(_quota);
    let aggregate = summary(&base, policy()).unwrap();
    assert_eq!(
        (
            aggregate.records,
            aggregate.directory_records,
            aggregate.file_records
        ),
        (1, 1, 2)
    );
    assert_eq!(history_unresolved(&aggregate, true), Ok(true));
}
