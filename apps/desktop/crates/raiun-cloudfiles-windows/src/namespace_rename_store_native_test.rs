//! Explicit fresh private-state proof only. No Cloud Files, MOVE or network.
use super::*;
use crate::namespace_file_rename::FileRenameJournal;
use crate::namespace_intent::{
    CapturedAuthorization, LocalNamespaceEntry, NamespaceDestinationReport, NamespaceParent,
    StorageClassification,
};
use crate::{DpapiEditRecordProtector, LocalFileIdentity, RemoteEditBaseline};
use raiun_control_windows::{PinnedDirectory, PinnedFileIdentity, PrivateDirectory};
use std::{ffi::OsStr, path::PathBuf};

const PAYLOAD: &[u8] = b"synthetic rename journal proof\n";

fn make_intent(
    scope: &EditJournalScope,
    parent: PinnedFileIdentity,
    file: PinnedFileIdentity,
    number: u64,
) -> NamespaceIntent {
    let parent = NamespaceParent {
        scope: scope.clone(),
        authorization: CapturedAuthorization {
            agent_generation: 1,
            token_generation: 1,
        },
        classification: StorageClassification::Ordinary,
        local_file: LocalFileIdentity {
            volume_serial: parent.volume_serial,
            file_index: parent.file_index,
        },
        local_components: vec!["Personal".into()],
        remote: RemoteEditBaseline {
            resource_id: "synthetic-parent".into(),
            etag: "\"parent-v1\"".into(),
            byte_len: 0,
        },
    };
    let entry = LocalNamespaceEntry {
        parent,
        name: format!("before-{number}.txt"),
        local_file: LocalFileIdentity {
            volume_serial: file.volume_serial,
            file_index: file.file_index,
        },
        object_kind: NamespaceObjectKind::File,
    };
    let mut destination = entry.clone();
    destination.name = format!("after-{number}.txt");
    NamespaceIntent {
        schema_version: 1,
        record_id: "0".repeat(32),
        record_generation: number,
        operation: NamespaceOperation::MoveWithinScope {
            source: ExistingNamespaceEntry {
                local: entry,
                remote: RemoteEditBaseline {
                    resource_id: format!("synthetic-file-{number}"),
                    etag: "\"before-v1\"".into(),
                    byte_len: PAYLOAD.len() as u64,
                },
            },
            destination,
        },
    }
}

fn fresh(result: FileRenamePublishResult) -> FreshFileRenamePublication {
    match result {
        FileRenamePublishResult::Fresh(value) => value,
        FileRenamePublishResult::Retained => panic!("fresh publication required"),
    }
}

#[test]
#[ignore = "explicit fresh protected DPAPI journal proof; no mounted namespace operation"]
#[cfg(all(debug_assertions, feature = "synthetic-agent-integration"))]
fn fresh_private_dpapi_rename_journal() {
    assert_eq!(
        std::env::var("RAIUN_RUN_RENAME_STORE_PROOF").as_deref(),
        Ok("fresh-owned-state")
    );
    let root = PathBuf::from(
        std::env::var_os("RAIUN_RENAME_STORE_PROOF_ROOT").expect("explicit fresh proof root"),
    );
    assert!(root.is_absolute());
    std::fs::create_dir(&root).expect("never reuse a retained proof root");
    std::fs::write(root.join("OWNER.txt"), b"raiun-rename-store-r26-v1\n").unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let fixture = PinnedDirectory::open(&root).unwrap();
        let logical = fixture
            .create_child_directory(OsStr::new("scope-root"))
            .unwrap();
        let personal = logical
            .create_child_directory(OsStr::new("Personal"))
            .unwrap();
        let mut files = Vec::new();
        for number in 1..=2 {
            let (mut file, identity) = personal
                .create_new_file(OsStr::new(&format!("before-{number}.txt")))
                .unwrap();
            file.write_all(PAYLOAD).unwrap();
            file.sync_all().unwrap();
            drop(file);
            files.push(identity);
        }
        assert_ne!(files[0], files[1]);
        let state = Arc::new(
            PrivateDirectory::create_or_open_under(&fixture, OsStr::new("state")).unwrap(),
        );
        let sessions = Arc::new(
            PrivateDirectory::create_or_open_under(
                &PinnedDirectory::open(state.path()).unwrap(),
                OsStr::new("sessions"),
            )
            .unwrap(),
        );
        let protector: Arc<dyn EditRecordProtector> = Arc::new(
            DpapiEditRecordProtector::from_existing_private_directory(Arc::clone(&sessions))
                .unwrap(),
        );
        let policy = StorePolicy {
            max_content_bytes: 32 * 1024 * 1024,
            max_state_bytes: 64 * 1024 * 1024,
            max_entries: 2000,
            max_metadata_bytes_per_scan: 8 * 1024 * 1024,
        };
        let scope = EditJournalScope {
            profile_id: "default".into(),
            server_origin: "https://synthetic.invalid".into(),
            account_subject: "synthetic-rename-account".into(),
            space_id: "synthetic-personal".into(),
            root_resource_id: "synthetic-root".into(),
            root_volume_serial: logical.identity().volume_serial,
            root_file_index: logical.identity().file_index,
        };
        let base = SnapshotStore::create_or_open(
            Arc::clone(&state),
            scope.clone(),
            Arc::clone(&protector),
            policy,
        )
        .unwrap();
        let store = FileRenameStore::new(Arc::clone(&base)).unwrap();
        let first = make_intent(&scope, personal.identity(), files[0], 1);
        let mut lease = fresh(store.publish_intent(first.clone()).unwrap())
            .acquire_dispatch()
            .unwrap();
        assert!(lease.owns_fresh_publication());
        let lock_name = format!("{}.dispatch.lock", lease.intent().record_id);
        let mut contender = lease.directory.open(&lock_name).unwrap();
        assert_eq!(contender.lock_exclusive(), Err(StoreError::Busy));
        contender.verify().unwrap();
        drop(contender);
        let NamespaceOperation::MoveWithinScope {
            source,
            destination,
        } = lease.intent().operation.clone()
        else {
            unreachable!()
        };
        let mut remote = source.remote.clone();
        remote.etag = "\"after-v1\"".into();
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
        assert_eq!(lease.progress().sequence, 4);
        assert!(lease.progress().recorded_complete);
        drop(lease);
        assert!(matches!(
            store.publish_intent(first).unwrap(),
            FileRenamePublishResult::Retained
        ));

        let second = make_intent(&scope, personal.identity(), files[1], 2);
        let mut lease = fresh(store.publish_intent(second.clone()).unwrap())
            .acquire_dispatch()
            .unwrap();
        let NamespaceOperation::MoveWithinScope { destination, .. } =
            lease.intent().operation.clone()
        else {
            unreachable!()
        };
        assert_eq!(
            lease.append_event(NamespaceEventKind::LocalCompleted { destination }),
            Err(StoreError::Invalid)
        );
        assert!(!lease.owns_fresh_publication());
        assert_eq!(
            lease.append_event(NamespaceEventKind::RemoteSubmitted),
            Err(StoreError::PublicationUncertain)
        );
        assert_eq!(lease.progress().sequence, 0);
        drop(lease);
        assert!(matches!(
            store.publish_intent(second).unwrap(),
            FileRenamePublishResult::Retained
        ));

        let reopened = SnapshotStore::open_existing(
            Arc::clone(&state),
            scope.clone(),
            Arc::clone(&protector),
            policy,
        )
        .unwrap();
        let reopened_store = FileRenameStore::new(Arc::clone(&reopened)).unwrap();
        let history = reopened_store.discover_account_root().unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(
            history
                .iter()
                .filter(|h| h.progress.recorded_complete && h.progress.sequence == 4)
                .count(),
            1
        );
        assert_eq!(
            history
                .iter()
                .filter(|h| h.progress.sequence == 0 && !h.progress.recorded_complete)
                .count(),
            1
        );
        let mut other_scope = scope.clone();
        other_scope.account_subject = "other-synthetic-account".into();
        let other = SnapshotStore::open_existing(
            Arc::clone(&state),
            other_scope,
            Arc::clone(&protector),
            policy,
        )
        .unwrap();
        assert!(
            FileRenameStore::new(other)
                .unwrap()
                .discover_account_root()
                .unwrap()
                .is_empty()
        );
        let mkdir = namespace_store::DirectoryIntentStore::create_or_open(
            Arc::clone(&state),
            scope.clone(),
            Arc::clone(&protector),
            policy,
        )
        .unwrap();
        assert!(mkdir.discover_account_root().unwrap().is_empty());
        let ordinary_directory = personal
            .create_child_directory(OsStr::new("synthetic-directory"))
            .unwrap();
        let mut rename_shape = make_intent(&scope, personal.identity(), files[0], 3);
        assert!(matches!(
            mkdir.publish_intent(rename_shape.clone()),
            Err(StoreError::Invalid)
        ));
        let NamespaceOperation::MoveWithinScope { source, .. } = &rename_shape.operation else {
            unreachable!()
        };
        rename_shape.operation = NamespaceOperation::CreateDirectory {
            destination: LocalNamespaceEntry {
                parent: source.local.parent.clone(),
                name: "synthetic-directory".into(),
                object_kind: NamespaceObjectKind::Directory,
                local_file: LocalFileIdentity {
                    volume_serial: ordinary_directory.identity().volume_serial,
                    file_index: ordinary_directory.identity().file_index,
                },
            },
        };
        assert!(mkdir.publish_intent(rename_shape).unwrap().created);
        let mkdir_records = mkdir.discover_account_root().unwrap();
        assert_eq!(mkdir_records.len(), 1);
        assert!(matches!(
            mkdir_records[0].intent.operation,
            NamespaceOperation::CreateDirectory { .. }
        ));
        assert_eq!(reopened_store.discover_account_root().unwrap().len(), 2);

        let quota = reopened.acquire_lock().unwrap();
        let inventory = reopened.inventory().unwrap();
        assert_eq!(
            reopened.root.external_recovery_usage(policy).unwrap(),
            (0, 0)
        );
        let root_names = reopened.root.entries(policy.max_entries).unwrap();
        assert_eq!(root_names.len(), 3);
        assert!(
            root_names.contains(&ROOT.to_owned()) && root_names.contains(&V2_QUOTA_LOCK.to_owned())
        );
        let rename = reopened.root.child(ROOT, false).unwrap();
        let scope_key = scope_key(&scope).unwrap();
        let rename_names = rename.entries(policy.max_entries).unwrap();
        assert_eq!(rename_names.len(), 2);
        let directory = rename.child(&scope_key, false).unwrap();
        let leaves = directory.entries(policy.max_entries).unwrap();
        assert_eq!(leaves.len(), 8);
        let mut physical_bytes = rename
            .open(&format!("{scope_key}.scope"))
            .unwrap()
            .len()
            .unwrap();
        for name in &leaves {
            let file = directory.open(name).unwrap();
            physical_bytes += file.len().unwrap();
            file.verify().unwrap();
        }
        let mkdir_root = reopened.root.child(namespace_store::ROOT, false).unwrap();
        let mkdir_names = mkdir_root.entries(policy.max_entries).unwrap();
        assert_eq!(mkdir_names.len(), 2);
        let mkdir_scope = mkdir_root.child(&scope_key, false).unwrap();
        let mkdir_leaves = mkdir_scope.entries(policy.max_entries).unwrap();
        assert_eq!(mkdir_leaves.len(), 1);
        physical_bytes += mkdir_root
            .open(&format!("{scope_key}.scope"))
            .unwrap()
            .len()
            .unwrap();
        for name in &mkdir_leaves {
            let file = mkdir_scope.open(name).unwrap();
            physical_bytes += file.len().unwrap();
            file.verify().unwrap();
        }
        assert_eq!(inventory.bytes, physical_bytes);
        assert_eq!(
            inventory.entries,
            root_names.len()
                + rename_names.len()
                + leaves.len()
                + mkdir_names.len()
                + mkdir_leaves.len()
        );
        quota.verify().unwrap();
        drop(quota);
        for (index, identity) in files.iter().enumerate() {
            let (mut file, actual) = personal
                .open_immutable_regular_file(OsStr::new(&format!("before-{}.txt", index + 1)))
                .unwrap();
            assert_eq!(actual, *identity);
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, PAYLOAD);
        }
        fixture.verify_path().unwrap();
        ordinary_directory.verify_path().unwrap();
        state.verify_path().unwrap();
        sessions.verify_path().unwrap();
        serde_json::json!({
            "fixture":"fresh-private-rename-journal-r26","passed":true,
            "authenticated_histories":2,"completed_report_sequence":4,"poisoned_pending_sequence":0,
            "duplicate_or_recovered_history_mints_no_fresh_custody":true,
            "invalid_pre_submit_completion_refused":true,"append_error_permanently_poisoned":true,
            "same_user_dpapi_reopen_authenticated":true,"other_account_root_isolated":true,
            "mkdir_reader_ignores_rename_records_and_authenticates_catalog":true,
            "mkdir_publish_rejects_rename_operation":true,"coexisting_mkdir_records":1,
            "exclusive_dispatch_lock_contender_busy":true,
            "inventory_bytes":inventory.bytes,"inventory_entries":inventory.entries,
            "exact_physical_metadata_accounting":true,"private_pins_valid":true,
            "known_fixture_roots_and_files_retained":true,
            "actual_native_rename_performed":false,"actual_MOVE_requests":0,
            "network_used":false,"CloudFiles_or_provider_used":false,"default_state_opened":false,
            "stored_reports_grant_no_native_or_remote_authority":true
        })
    }));
    let value = match &result {
        Ok(value) => value.clone(),
        Err(_) => {
            serde_json::json!({"fixture":"fresh-private-rename-journal-r26","passed":false,"error":"assertion failed; preserve all state and logs","forced_cleanup":false})
        }
    };
    std::fs::write(
        root.join("RESULT.json"),
        serde_json::to_vec_pretty(&value).unwrap(),
    )
    .unwrap();
    assert!(
        result.is_ok(),
        "fresh protected journal proof failed; retain evidence"
    );
}
