use super::*;

// Fail immediately if the reader tries to create/publish or read snapshot bodies.
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
        Arc::clone(&base.protector),
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
    assert_eq!(
        summary(&base, policy()).unwrap(),
        NamespaceHistorySummary::default()
    );
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
            other_namespace_evidence: false
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
            other_namespace_evidence: false
        }
    );
    let foreign = related(&base, |scope| scope.account_subject = "foreign".into());
    publish(&foreign, 3, true);
    assert_eq!(
        summary(&foreign, policy()).unwrap(),
        NamespaceHistorySummary {
            records: 1,
            unresolved: 0,
            other_namespace_evidence: false
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
    for name in [namespace_store::ROOT, namespace_file_store::ROOT] {
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
