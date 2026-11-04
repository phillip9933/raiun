use super::super::SnapshotStore;
use super::*;
use crate::namespace_intent::{
    CapturedAuthorization, LocalNamespaceEntry, NamespaceDestinationReport, NamespaceParent,
    StorageClassification,
};
use crate::{LocalFileIdentity, RemoteEditBaseline};
use std::sync::Arc;

fn policy() -> StorePolicy {
    StorePolicy {
        max_content_bytes: 8 * 1024 * 1024,
        max_state_bytes: 32 * 1024 * 1024,
        max_entries: 2048,
        max_metadata_bytes_per_scan: 4 * 1024 * 1024,
    }
}

fn fixture() -> (tempfile::TempDir, Arc<SnapshotStore>, Arc<FileRenameStore>) {
    let (temp, base) = super::super::synthetic_test_store(policy());
    let store = FileRenameStore::new(Arc::clone(&base)).unwrap();
    (temp, base, store)
}

fn intent(base: &SnapshotStore, from: &str, to: &str, generation: u64) -> NamespaceIntent {
    NamespaceIntent {
        schema_version: 1,
        record_id: "0".repeat(32),
        record_generation: generation,
        operation: NamespaceOperation::MoveWithinScope {
            source: ExistingNamespaceEntry {
                local: LocalNamespaceEntry {
                    parent: parent(base),
                    name: from.into(),
                    local_file: LocalFileIdentity {
                        volume_serial: base.scope.root_volume_serial,
                        file_index: 40,
                    },
                    object_kind: NamespaceObjectKind::File,
                },
                remote: RemoteEditBaseline {
                    resource_id: "opaque-file-id".into(),
                    etag: "\"source-etag\"".into(),
                    byte_len: 19,
                },
            },
            destination: LocalNamespaceEntry {
                parent: parent(base),
                name: to.into(),
                local_file: LocalFileIdentity {
                    volume_serial: base.scope.root_volume_serial,
                    file_index: 40,
                },
                object_kind: NamespaceObjectKind::File,
            },
        },
    }
}

fn parent(base: &SnapshotStore) -> NamespaceParent {
    NamespaceParent {
        scope: base.scope.clone(),
        authorization: CapturedAuthorization {
            agent_generation: 3,
            token_generation: 5,
        },
        classification: StorageClassification::Ordinary,
        local_file: LocalFileIdentity {
            volume_serial: base.scope.root_volume_serial,
            file_index: 20,
        },
        local_components: vec!["Personal".into(), "Documents".into()],
        remote: RemoteEditBaseline {
            resource_id: "opaque-parent-id".into(),
            etag: "\"parent-etag\"".into(),
            byte_len: 0,
        },
    }
}

fn complete(lease: &mut FileRenameLease) {
    let NamespaceOperation::MoveWithinScope {
        source,
        destination,
    } = lease.intent().operation.clone()
    else {
        unreachable!();
    };
    let mut remote = source.remote.clone();
    remote.etag = "\"renamed-etag\"".into();
    lease
        .append_event(NamespaceEventKind::RemoteSubmitted)
        .unwrap();
    lease
        .append_event(NamespaceEventKind::RemoteVerified {
            report: NamespaceDestinationReport {
                destination: destination.clone(),
                remote,
                content: None,
            },
        })
        .unwrap();
    lease
        .append_event(NamespaceEventKind::LocalCompleted { destination })
        .unwrap();
    lease
        .append_event(NamespaceEventKind::SourceRemovalVerified { source })
        .unwrap();
}

fn fresh(result: FileRenamePublishResult) -> FreshFileRenamePublication {
    match result {
        FileRenamePublishResult::Fresh(value) => value,
        FileRenamePublishResult::Retained => panic!("expected a newly owned publication"),
    }
}

#[test]
fn fresh_publication_dispatches_once_and_roundtrips_authenticated_events() {
    let (_temp, base, store) = fixture();
    let original = intent(&base, "before.txt", "after.txt", 8);
    let publication = fresh(store.publish_intent(original.clone()).unwrap());
    let mut lease = publication.acquire_dispatch().unwrap();
    assert!(crate::namespace_file_rename::FileRenameJournal::owns_fresh_publication(&lease));
    complete(&mut lease);
    assert!(lease.progress().recorded_complete);
    drop(lease);

    let history = store.discover_account_root().unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].intent.operation, original.operation);
    assert!(history[0].progress.recorded_complete);
    assert!(matches!(
        store.publish_intent(original).unwrap(),
        FileRenamePublishResult::Retained
    ));
}

#[test]
fn pristine_duplicate_and_unresolved_same_file_never_mint_a_second_receipt() {
    let (_temp, base, store) = fixture();
    let first = intent(&base, "before.txt", "after.txt", 8);
    let publication = fresh(store.publish_intent(first.clone()).unwrap());
    drop(publication);
    assert!(matches!(
        store.publish_intent(first).unwrap(),
        FileRenamePublishResult::Retained
    ));
    assert_eq!(
        store.discover_account_root().unwrap()[0].progress.sequence,
        0
    );

    let later = intent(&base, "after.txt", "third.txt", 9);
    assert!(matches!(
        store.publish_intent(later).unwrap(),
        FileRenamePublishResult::Retained
    ));
}

#[test]
fn completed_same_file_history_allows_a_later_distinct_rename() {
    let (_temp, _base, store) = fixture();
    let first = intent(&store.base, "before.txt", "after.txt", 8);
    complete(
        &mut fresh(store.publish_intent(first).unwrap())
            .acquire_dispatch()
            .unwrap(),
    );
    let later = intent(&store.base, "after.txt", "third.txt", 9);
    assert!(matches!(
        store.publish_intent(later).unwrap(),
        FileRenamePublishResult::Fresh(_)
    ));
}

#[test]
fn append_error_permanently_revokes_fresh_custody_and_poisoned_lease() {
    let (_temp, base, store) = fixture();
    let publication = fresh(
        store
            .publish_intent(intent(&base, "before.txt", "after.txt", 8))
            .unwrap(),
    );
    let mut lease = publication.acquire_dispatch().unwrap();
    assert_eq!(
        lease.append_event(NamespaceEventKind::RemoteVerified {
            report: NamespaceDestinationReport {
                destination: match &lease.intent().operation {
                    NamespaceOperation::MoveWithinScope { destination, .. } => destination.clone(),
                    _ => unreachable!(),
                },
                remote: RemoteEditBaseline {
                    resource_id: "opaque-file-id".into(),
                    etag: "\"renamed-etag\"".into(),
                    byte_len: 19,
                },
                content: None,
            },
        }),
        Err(StoreError::Invalid)
    );
    assert!(!crate::namespace_file_rename::FileRenameJournal::owns_fresh_publication(&lease));
    assert_eq!(
        lease.append_event(NamespaceEventKind::RemoteSubmitted),
        Err(StoreError::PublicationUncertain)
    );
    drop(lease);
    assert!(matches!(
        store
            .publish_intent(intent(&base, "before.txt", "after.txt", 8))
            .unwrap(),
        FileRenamePublishResult::Retained
    ));
}

#[test]
fn local_completion_before_submission_permanently_poisons_the_lease() {
    let (_temp, base, store) = fixture();
    let publication = fresh(
        store
            .publish_intent(intent(&base, "before.txt", "after.txt", 8))
            .unwrap(),
    );
    let mut lease = publication.acquire_dispatch().unwrap();
    let destination = match &lease.intent().operation {
        NamespaceOperation::MoveWithinScope { destination, .. } => destination.clone(),
        _ => unreachable!(),
    };
    assert_eq!(
        lease.append_event(NamespaceEventKind::LocalCompleted { destination }),
        Err(StoreError::Invalid)
    );
    assert!(!crate::namespace_file_rename::FileRenameJournal::owns_fresh_publication(&lease));
    assert_eq!(
        lease.append_event(NamespaceEventKind::RemoteSubmitted),
        Err(StoreError::PublicationUncertain)
    );
}

#[test]
fn orphan_stage_is_retained_and_fails_closed() {
    let (temp, base, store) = fixture();
    drop(fresh(
        store
            .publish_intent(intent(&base, "before.txt", "after.txt", 8))
            .unwrap(),
    ));
    let root_path = temp.path().join(ROOT);
    std::fs::write(root_path.join("orphan.stage"), b"stage").unwrap();
    assert!(store.discover_scopes().is_err());
    assert!(root_path.join("orphan.stage").exists());
}

#[test]
fn tampered_scope_catalog_is_retained_and_fails_closed() {
    let (temp, base, store) = fixture();
    drop(fresh(
        store
            .publish_intent(intent(&base, "before.txt", "after.txt", 8))
            .unwrap(),
    ));
    let root_path = temp.path().join(ROOT);
    let scope_name = std::fs::read_dir(&root_path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .find(|name| name.ends_with(".scope"))
        .unwrap();
    let scope_path = root_path.join(scope_name);
    std::fs::write(&scope_path, b"tampered catalog").unwrap();
    assert!(store.discover_scopes().is_err());
    assert_eq!(std::fs::read(scope_path).unwrap(), b"tampered catalog");
}

#[test]
fn reservation_limits_refuse_publication_before_creating_rename_state() {
    let (_temp, base, _store) = fixture();
    let mut constrained = policy();
    constrained.max_content_bytes = 0;
    constrained.max_state_bytes = 1024;
    let limited_base = SnapshotStore::from_directory(
        Arc::clone(&base.root),
        base.scope.clone(),
        Arc::clone(&base.protector),
        constrained,
    )
    .unwrap();
    let limited_store = FileRenameStore::new(Arc::clone(&limited_base)).unwrap();
    assert!(matches!(
        limited_store.publish_intent(intent(&limited_base, "before.txt", "after.txt", 8)),
        Err(StoreError::Quota)
    ));
    assert!(
        !base
            .root
            .entries(base.policy.max_entries)
            .unwrap()
            .iter()
            .any(|name| name == ROOT)
    );

    let mut constrained_entries = policy();
    constrained_entries.max_entries = 4;
    let entry_limited_base = SnapshotStore::from_directory(
        Arc::clone(&base.root),
        base.scope.clone(),
        Arc::clone(&base.protector),
        constrained_entries,
    )
    .unwrap();
    let entry_limited = FileRenameStore::new(Arc::clone(&entry_limited_base)).unwrap();
    assert!(matches!(
        entry_limited.publish_intent(intent(&entry_limited_base, "before.txt", "after.txt", 9)),
        Err(StoreError::ScanLimit)
    ));
    assert!(
        !base
            .root
            .entries(base.policy.max_entries)
            .unwrap()
            .iter()
            .any(|name| name == ROOT)
    );
}

#[test]
fn persistent_record_lock_excludes_a_second_dispatch_handle() {
    let (_temp, base, store) = fixture();
    let publication = fresh(
        store
            .publish_intent(intent(&base, "before.txt", "after.txt", 8))
            .unwrap(),
    );
    let lease = publication.acquire_dispatch().unwrap();
    let lock_name = format!("{}.dispatch.lock", lease.intent().record_id);
    let mut contender = lease.directory.open(&lock_name).unwrap();
    assert_eq!(contender.lock_exclusive().unwrap_err(), StoreError::Busy);
    contender.verify().unwrap();
    drop(contender);
    drop(lease);
}

#[test]
fn existing_rename_root_without_quota_is_not_repaired_by_publish() {
    let (temp, base, store) = fixture();
    drop(fresh(
        store
            .publish_intent(intent(&base, "before.txt", "after.txt", 8))
            .unwrap(),
    ));
    let quota_path = temp.path().join(V2_QUOTA_LOCK);
    std::fs::remove_file(&quota_path).unwrap();
    assert!(matches!(
        store.publish_intent(intent(&base, "different.txt", "renamed.txt", 9)),
        Err(StoreError::IncompleteEvidence)
    ));
    assert!(!quota_path.exists());
    assert!(store.discover_account_root().is_err());
}

#[test]
fn fresh_receipt_without_quota_cannot_recreate_it_for_dispatch() {
    let (temp, base, store) = fixture();
    let publication = fresh(
        store
            .publish_intent(intent(&base, "before.txt", "after.txt", 8))
            .unwrap(),
    );
    let quota_path = temp.path().join(V2_QUOTA_LOCK);
    std::fs::remove_file(&quota_path).unwrap();
    assert!(matches!(
        publication.acquire_dispatch(),
        Err(StoreError::IncompleteEvidence)
    ));
    assert!(!quota_path.exists());
}

#[test]
fn unrelated_existing_v2_root_without_quota_is_not_repaired() {
    let (temp, base, store) = fixture();
    drop(base.root.child(namespace_store::ROOT, true).unwrap());
    let quota_path = temp.path().join(V2_QUOTA_LOCK);
    assert!(matches!(
        store.publish_intent(intent(&base, "before.txt", "after.txt", 8)),
        Err(StoreError::IncompleteEvidence)
    ));
    assert!(!quota_path.exists());
}

#[test]
fn account_root_filters_other_account_and_inventory_charges_rename_metadata() {
    let (_temp, base, store) = fixture();
    let publication = fresh(
        store
            .publish_intent(intent(&base, "before.txt", "after.txt", 8))
            .unwrap(),
    );
    drop(publication);
    let inventory = store.base.inventory().unwrap();
    assert!(inventory.entries >= 4);
    assert!(inventory.bytes > 0);
    assert_eq!(store.discover_account_root().unwrap().len(), 1);

    let mut other_scope = base.scope.clone();
    other_scope.account_subject = "other-account".into();
    let other_base = SnapshotStore::from_directory(
        Arc::clone(&base.root),
        other_scope,
        Arc::clone(&base.protector),
        base.policy,
    )
    .unwrap();
    let other_store = FileRenameStore::new(other_base).unwrap();
    assert!(other_store.discover_account_root().unwrap().is_empty());
}

#[test]
fn damaged_event_chain_is_not_returned_as_authenticated_history() {
    let (temp, base, store) = fixture();
    let publication = fresh(
        store
            .publish_intent(intent(&base, "before.txt", "after.txt", 8))
            .unwrap(),
    );
    let mut lease = publication.acquire_dispatch().unwrap();
    lease
        .append_event(NamespaceEventKind::RemoteSubmitted)
        .unwrap();
    let id = lease.intent().record_id.clone();
    drop(lease);
    let scope = scope_key(&base.scope).unwrap();
    let event_path = temp
        .path()
        .join(ROOT)
        .join(scope)
        .join(format!("{id}.event.{:020}", 1));
    let mut bytes = std::fs::read(&event_path).unwrap();
    bytes[0] ^= 1;
    std::fs::write(event_path, bytes).unwrap();
    assert!(store.discover_account_root().is_err());
}

fn seed_file_scope(base: &SnapshotStore, scope: &EditJournalScope) {
    let exists = base
        .root
        .entries(base.policy.max_entries)
        .unwrap()
        .iter()
        .any(|name| name == namespace_file_store::ROOT);
    let root = base
        .root
        .child(namespace_file_store::ROOT, !exists)
        .unwrap();
    let key = scope_key(scope).unwrap();
    let aad = [
        b"raiun/namespace-file-join/v1\0".as_slice(),
        b"scope\0",
        key.as_bytes(),
    ]
    .concat();
    let sealed = base.seal_metadata(&aad, scope).unwrap();
    persist_metadata(&*root, &format!("{key}.scope"), &sealed).unwrap();
    root.child(&key, true).unwrap();
}

#[test]
fn mixed_file_and_rename_scope_union_bounds_existing_and_requested_keys() {
    let (_temp, base, store) = fixture();
    drop(base.acquire_lock().unwrap());
    for index in 0..256 {
        let mut scope = base.scope.clone();
        scope.space_id = format!("mixed-{index}");
        seed_file_scope(&base, &scope);
    }
    // File-only catalogs are validated although this typed reader returns no
    // rename scopes. Its requested (distinct) key is rejected before writes.
    assert!(store.discover_scopes().unwrap().is_empty());
    let mut budget = Budget::new(base.policy);
    let names = base.root.entries(budget.remaining_entries()).unwrap();
    budget.entries(names.len()).unwrap();
    assert_eq!(
        store
            .validate_global_catalogs(&names, &mut budget, true)
            .err(),
        Some(StoreError::ScanLimit)
    );
    assert_eq!(base.ensure_scope().err(), Some(StoreError::ScanLimit));
    assert!(
        !base
            .root
            .entries(base.policy.max_entries)
            .unwrap()
            .contains(&ROOT.to_owned())
    );
    // A valid rename catalog contributes the 257th distinct key. Every
    // affected shared scan fails even though neither typed store exceeds256.
    let root = base.root.child(ROOT, true).unwrap();
    let sealed = base
        .seal_metadata(&scope_aad(&base.key), &base.scope)
        .unwrap();
    persist_metadata(&*root, &format!("{}.scope", base.key), &sealed).unwrap();
    root.child(&base.key, true).unwrap();
    assert_eq!(store.discover_scopes().err(), Some(StoreError::ScanLimit));
    assert_eq!(base.discover_metadata().err(), Some(StoreError::ScanLimit));
    assert_eq!(base.inventory().err(), Some(StoreError::ScanLimit));
}

#[test]
fn shared_scope_key_is_charged_once_but_file_catalog_is_never_skipped() {
    let (temp, base, store) = fixture();
    drop(base.acquire_lock().unwrap());
    base.ensure_scope().unwrap();
    seed_file_scope(&base, &base.scope);
    let root = base.root.child(ROOT, true).unwrap();
    let sealed = base
        .seal_metadata(&scope_aad(&base.key), &base.scope)
        .unwrap();
    persist_metadata(&*root, &format!("{}.scope", base.key), &sealed).unwrap();
    root.child(&base.key, true).unwrap();
    assert_eq!(store.discover_scopes().unwrap(), vec![base.scope.clone()]);
    let mut budget = Budget::new(base.policy);
    let names = base.root.entries(budget.remaining_entries()).unwrap();
    budget.entries(names.len()).unwrap();
    assert_eq!(
        base.validate_root_catalogs_with_scope_union(&names, &mut budget)
            .unwrap()
            .keys
            .len(),
        1
    );
    std::fs::write(
        temp.path()
            .join(namespace_file_store::ROOT)
            .join(format!("{}.scope", base.key)),
        b"tampered catalog",
    )
    .unwrap();
    assert_eq!(
        store.discover_scopes().err(),
        Some(StoreError::CorruptEvidence)
    );
    assert!(base.inventory().is_err());
}
