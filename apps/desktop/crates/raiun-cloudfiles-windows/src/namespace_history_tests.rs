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
fn other_namespace_formats_force_unknown_flag_and_their_catalogs_are_authenticated() {
    {
        let name = namespace_file_store::ROOT;
        let (_temp, base, _) = fixture();
        drop(base.acquire_lock().unwrap());
        let other = base.root.child(name, true).unwrap();
        assert!(summary(&base, policy()).unwrap().other_namespace_evidence);
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
