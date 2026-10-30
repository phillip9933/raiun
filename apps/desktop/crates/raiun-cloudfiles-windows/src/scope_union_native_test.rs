//! Fresh private catalog-boundary proof; no Cloud Files, network or dispatch.
use super::*;
use crate::DpapiEditRecordProtector;
use raiun_control_windows::{PinnedDirectory, PrivateDirectory};
use std::{ffi::OsStr, path::PathBuf};

fn seed(base: &SnapshotStore, format: usize, scope: &EditJournalScope) {
    let key = scope_key(scope).unwrap();
    let (root, aad) = match format {
        0 => (Arc::clone(&base.root), scope_aad(&key)),
        1 => (
            base.root.child(namespace_store::ROOT, true).unwrap(),
            [
                b"raiun/namespace-store/v1\0".as_slice(),
                b"scope\0",
                key.as_bytes(),
            ]
            .concat(),
        ),
        2 => (
            base.root.child(namespace_file_store::ROOT, true).unwrap(),
            [
                b"raiun/namespace-file-join/v1\0".as_slice(),
                b"scope\0",
                key.as_bytes(),
            ]
            .concat(),
        ),
        3 => (
            base.root.child(namespace_rename_store::ROOT, true).unwrap(),
            [
                b"raiun/namespace-rename-store/v1\0".as_slice(),
                b"scope\0",
                key.as_bytes(),
            ]
            .concat(),
        ),
        _ => unreachable!(),
    };
    let sealed = base.seal_metadata(&aad, scope).unwrap();
    persist_metadata(&*root, &format!("{key}.scope"), &sealed).unwrap();
    root.child(&key, true).unwrap();
}

fn scope_at(scope: &EditJournalScope, index: usize) -> EditJournalScope {
    let mut next = scope.clone();
    next.space_id = format!("synthetic-scope-{index}");
    next.root_resource_id = format!("synthetic-root-{index}");
    next
}

fn catalog_scan(base: &SnapshotStore) -> Result<RootCatalogScopes, StoreError> {
    let mut budget = Budget::new(base.policy);
    let names = base.root.entries(budget.remaining_entries())?;
    budget.entries(names.len())?;
    base.validate_root_catalogs_with_scope_union(&names, &mut budget)
}

#[test]
#[ignore = "explicit fresh private DPAPI mixed-format scope boundary proof"]
fn fresh_private_dpapi_shared_scope_union() {
    assert_eq!(
        std::env::var("RAIUN_RUN_SCOPE_UNION_PROOF").as_deref(),
        Ok("fresh-owned-state")
    );
    let root = PathBuf::from(
        std::env::var_os("RAIUN_SCOPE_UNION_PROOF_ROOT").expect("explicit fresh root"),
    );
    assert!(root.is_absolute());
    std::fs::create_dir(&root).expect("never reuse retained evidence");
    std::fs::write(root.join("OWNER.txt"), b"raiun-scope-union-r27-v1\n").unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let fixture = PinnedDirectory::open(&root).unwrap();
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
            max_entries: 20_000,
            max_metadata_bytes_per_scan: 16 * 1024 * 1024,
        };
        let scope = EditJournalScope {
            profile_id: "default".into(),
            server_origin: "https://synthetic.invalid".into(),
            account_subject: "scope-union-r27".into(),
            space_id: "synthetic-scope-0".into(),
            root_resource_id: "synthetic-root-0".into(),
            root_volume_serial: fixture.identity().volume_serial,
            root_file_index: fixture.identity().file_index,
        };
        let base = SnapshotStore::create_or_open(
            Arc::clone(&state),
            scope.clone(),
            Arc::clone(&protector),
            policy,
        )
        .unwrap();
        drop(base.acquire_lock().unwrap());
        // The original omission: 256 distinct file-join catalogs, no snapshot,
        // mkdir or rename catalog. A requested 257th key must fail pre-write.
        for index in 0..256 {
            seed(&base, 2, &scope_at(&scope, index));
        }
        assert_eq!(catalog_scan(&base).unwrap().keys.len(), 256);
        let other = SnapshotStore::create_or_open(
            Arc::clone(&state),
            scope_at(&scope, 256),
            Arc::clone(&protector),
            policy,
        )
        .unwrap();
        assert_eq!(
            other.validate_requested_catalog_scope(),
            Err(StoreError::ScanLimit)
        );
        assert_eq!(other.ensure_scope().err(), Some(StoreError::ScanLimit));
        assert!(
            !base
                .root
                .entries(policy.max_entries)
                .unwrap()
                .contains(&format!("{}.scope", other.key))
        );
        let rename = namespace_rename_store::FileRenameStore::new(Arc::clone(&base)).unwrap();
        let mkdir = namespace_store::DirectoryIntentStore::create_or_open(
            Arc::clone(&state),
            scope.clone(),
            Arc::clone(&protector),
            policy,
        )
        .unwrap();
        let reader = namespace_store::NamespaceHistoryReader::open_existing(
            Arc::clone(&state),
            Arc::clone(&protector),
            policy,
        )
        .unwrap();
        let files = namespace_file_store::FileCreateStore::new(Arc::clone(&base)).unwrap();
        assert!(reader.discover_scopes().unwrap().is_empty());
        assert!(mkdir.discover_account_root().unwrap().is_empty());
        assert!(rename.discover_scopes().unwrap().is_empty());
        assert!(base.discover_metadata().unwrap().is_empty());
        assert!(files.discover().unwrap().is_empty());
        // Three additional format catalogs carry the SAME key. Authenticate
        // every format, count once, and preserve each reader's typed result.
        for format in [0, 1, 3] {
            seed(&base, format, &scope);
        }
        assert_eq!(catalog_scan(&base).unwrap().keys.len(), 256);
        assert_eq!(reader.discover_scopes().unwrap(), vec![scope.clone()]);
        assert_eq!(rename.discover_scopes().unwrap(), vec![scope.clone()]);
        assert!(mkdir.discover_account_root().unwrap().is_empty());
        assert!(base.discover_metadata().unwrap().is_empty());
        assert!(files.discover().unwrap().is_empty());
        assert!(base.inventory().is_ok());
        // An existing 257th distinct key is split across formats; every scan
        // and accounting path must reject it even though each format is <=256.
        seed(&base, 3, &scope_at(&scope, 256));
        assert_eq!(catalog_scan(&base).err(), Some(StoreError::ScanLimit));
        assert_eq!(reader.discover_scopes().err(), Some(StoreError::ScanLimit));
        assert_eq!(
            mkdir.discover_account_root().err(),
            Some(StoreError::ScanLimit)
        );
        assert_eq!(rename.discover_scopes().err(), Some(StoreError::ScanLimit));
        assert_eq!(base.discover_metadata().err(), Some(StoreError::ScanLimit));
        assert_eq!(files.discover().err(), Some(StoreError::ScanLimit));
        assert_eq!(base.inventory().err(), Some(StoreError::ScanLimit));
        // A separate fresh state retains a corrupt duplicate-key catalog.
        // It must authenticate despite another format already owning key0.
        let corrupt_state = Arc::new(
            PrivateDirectory::create_or_open_under(&fixture, OsStr::new("corrupt-state")).unwrap(),
        );
        let corrupt = SnapshotStore::create_or_open(
            Arc::clone(&corrupt_state),
            scope.clone(),
            Arc::clone(&protector),
            policy,
        )
        .unwrap();
        drop(corrupt.acquire_lock().unwrap());
        seed(&corrupt, 0, &scope);
        let file_root = corrupt
            .root
            .child(namespace_file_store::ROOT, true)
            .unwrap();
        let aad = [
            b"raiun/namespace-file-join/v1\0".as_slice(),
            b"scope\0",
            corrupt.key.as_bytes(),
        ]
        .concat();
        let sealed = corrupt.seal_metadata(&aad, &scope_at(&scope, 999)).unwrap();
        persist_metadata(&*file_root, &format!("{}.scope", corrupt.key), &sealed).unwrap();
        file_root.child(&corrupt.key, true).unwrap();
        assert_eq!(
            catalog_scan(&corrupt).err(),
            Some(StoreError::CorruptEvidence)
        );
        let corrupt_reader = namespace_store::NamespaceHistoryReader::open_existing(
            Arc::clone(&corrupt_state),
            Arc::clone(&protector),
            policy,
        )
        .unwrap();
        assert_eq!(
            corrupt_reader.discover_scopes().err(),
            Some(StoreError::CorruptEvidence)
        );
        corrupt_state.verify_path().unwrap();
        state.verify_path().unwrap();
        sessions.verify_path().unwrap();
        fixture.verify_path().unwrap();
        serde_json::json!({"fixture":"fresh-private-scope-union-r27","passed":true,"file_only_distinct_scopes":256,"duplicate_catalog_formats":4,"requested_257_refused_before_snapshot_creation":true,"existing_mixed_257_refused_all_readers_and_inventory":true,"same_key_counted_once":true,"all_formats_authenticated":true,"typed_readers_preserved":true,"corrupt_file_catalog_refused":true,"network_used":false,"provider_used":false,"default_state_opened":false,"retained_all_fixture_state":true})
    }));
    match result {
        Ok(report) => std::fs::write(
            root.join("RESULT.json"),
            serde_json::to_vec_pretty(&report).unwrap(),
        )
        .unwrap(),
        Err(error) => {
            std::fs::write(
                root.join("FAILED.txt"),
                b"scope-union proof failed; preserve all state\n",
            )
            .unwrap();
            std::panic::resume_unwind(error);
        }
    }
}
