use super::*;
use raiun_core::backend::CloudBackend;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone)]
struct ContentCountingProtector {
    inner: Arc<crate::DpapiEditRecordProtector>,
    opened_content_records: Arc<AtomicUsize>,
}

impl ContentCountingProtector {
    fn from_existing_state(state: Arc<raiun_control_windows::PrivateDirectory>) -> Self {
        let inner = crate::DpapiEditRecordProtector::from_existing_private_directory(state)
            .expect("DPAPI protector from exact owned state directory");
        Self {
            inner: Arc::new(inner),
            opened_content_records: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn reset_content_open_count(&self) {
        self.opened_content_records.store(0, Ordering::Relaxed);
    }

    fn content_open_count(&self) -> usize {
        self.opened_content_records.load(Ordering::Relaxed)
    }
}

impl EditRecordProtector for ContentCountingProtector {
    fn seal(
        &self,
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, crate::JournalError> {
        self.inner.seal(associated_data, plaintext)
    }

    fn open(&self, associated_data: &[u8], sealed: &[u8]) -> Result<Vec<u8>, crate::JournalError> {
        let plaintext = self.inner.open(associated_data, sealed)?;
        // Count legacy body-inclusive records and authenticated V2 body
        // chunks. Catalog and manifest metadata use separate formats/domains.
        if plaintext.starts_with(b"RAIUNED1")
            || associated_data.starts_with(b"raiun/local-streamed-snapshot/chunk/v2\0")
        {
            self.opened_content_records.fetch_add(1, Ordering::Relaxed);
        }
        Ok(plaintext)
    }

    fn protect_directory(&self, path: &std::path::Path) -> Result<(), crate::JournalError> {
        self.inner.protect_directory(path)
    }
}

fn owned_case(name: &str) -> std::path::PathBuf {
    const OWNER: &[u8] = b"raiun-r52-content-health-owned-v1\n";
    assert_eq!(
        std::env::var("RAIUN_R52_NATIVE").as_deref(),
        Ok("1"),
        "R52 requires a fresh retained synthetic fixture guard"
    );
    let root = std::path::PathBuf::from(
        std::env::var_os("RAIUN_R52_FIXTURE_DIR").expect("R52 fixture directory is required"),
    );
    assert!(root.is_absolute(), "R52 fixture path must be absolute");
    assert_eq!(fs::read(root.join("OWNER")).unwrap(), OWNER);
    let case = root.join(name);
    fs::create_dir(&case).expect("R52 case directories are never reused");
    case
}

fn provider_scope() -> ProviderScope {
    let client = raiun_opencloud::OpenCloudClient::new(
        "https://r52.invalid",
        "fixture-token-not-a-credential".into(),
    )
    .unwrap();
    ProviderScope::new(
        &client,
        "default".into(),
        "r52-account".into(),
        client.server_origin().unwrap(),
    )
    .unwrap()
}

fn edit_scope(provider: &ProviderScope, root: ConfiguredRootIdentity) -> EditJournalScope {
    EditJournalScope {
        profile_id: provider.profile_id().to_owned(),
        server_origin: provider.server_origin().to_owned(),
        account_subject: provider.account_id().to_owned(),
        space_id: "r52-personal".into(),
        root_resource_id: "r52-root".into(),
        root_volume_serial: root.volume_serial,
        root_file_index: root.file_index,
    }
}

fn policy() -> crate::streamed_store::StorePolicy {
    crate::streamed_store::StorePolicy {
        max_content_bytes: 1024 * 1024,
        max_state_bytes: 16 * 1024 * 1024,
        max_entries: 512,
        max_metadata_bytes_per_scan: 1024 * 1024,
    }
}

fn private_state(case: &std::path::Path) -> Arc<raiun_control_windows::PrivateDirectory> {
    let parent =
        raiun_control_windows::PinnedDirectory::open(case).expect("pin owned fixture case");
    Arc::new(
        raiun_control_windows::PrivateDirectory::create_or_open_under(
            &parent,
            std::ffi::OsStr::new("state"),
        )
        .expect("create private state only below owned fixture"),
    )
}

fn catalog_at(
    state: &raiun_control_windows::PrivateDirectory,
    protector: Arc<dyn EditRecordProtector>,
) -> ScopeCatalog {
    ScopeCatalog {
        state_directory: state.path().to_path_buf(),
        protector,
        lock: Arc::new(Mutex::new(())),
        admission: None,
    }
}

fn content_presence(
    catalog: &ScopeCatalog,
    provider: &ProviderScope,
    root: ConfiguredRootIdentity,
) -> Result<bool, crate::JournalError> {
    catalog.content_presence_bounded(
        provider,
        root,
        &mut crate::streamed_store::DiscoveryBudget::new(policy()),
    )
}

fn synthetic_root() -> ConfiguredRootIdentity {
    ConfiguredRootIdentity {
        volume_serial: 17,
        file_index: 29,
    }
}

#[test]
#[ignore = "requires a fresh retained R52 DPAPI fixture root"]
fn r52_legacy_empty_and_retained_content_are_classified_without_body_decryption() {
    let case = owned_case("legacy-content");
    let state = private_state(&case);
    let provider = provider_scope();
    let root = synthetic_root();
    let selected = edit_scope(&provider, root);
    let protector = ContentCountingProtector::from_existing_state(Arc::clone(&state));
    let catalog = catalog_at(&state, Arc::new(protector.clone()));
    assert!(!content_presence(&catalog, &provider, root).unwrap());

    // Scope registration authenticates the catalog before the writer creates
    // the corresponding journal directory; a direct open would be an orphan.
    catalog.register_scope(&selected).unwrap();
    let journal = catalog.open_journal(&selected).unwrap();
    journal
        .append_edit(
            1,
            crate::LocalFileIdentity {
                volume_serial: root.volume_serial,
                file_index: 41,
            },
            "notes.txt",
            None,
            b"synthetic retained body",
        )
        .unwrap();
    protector.reset_content_open_count();
    assert!(content_presence(&catalog, &provider, root).unwrap());
    assert_eq!(
        protector.content_open_count(),
        0,
        "the health scan must not DPAPI-open a content-inclusive legacy record"
    );
    let recovered = journal.recover_all().unwrap();
    assert_eq!(recovered.records.len(), 1);
    assert!(
        protector.content_open_count() > 0,
        "the counting protector must detect an intentional body-inclusive recovery open"
    );
    drop(recovered);
}

#[test]
#[ignore = "requires a fresh retained R52 DPAPI fixture root"]
fn r52_legacy_stage_is_nonclean_and_unrecognized_entry_fails_closed() {
    let provider = provider_scope();
    let root = synthetic_root();
    let selected = edit_scope(&provider, root);

    let stage_case = owned_case("legacy-stage");
    let stage_state = private_state(&stage_case);
    let stage_protector = ContentCountingProtector::from_existing_state(Arc::clone(&stage_state));
    let stage_catalog = catalog_at(&stage_state, Arc::new(stage_protector));
    stage_catalog.register_scope(&selected).unwrap();
    let _stage_journal = stage_catalog.open_journal(&selected).unwrap();
    let stage_path = EditJournal::storage_root(stage_state.path())
        .join(EditJournal::scope_directory_key(&selected).unwrap());
    fs::write(
        stage_path.join(".stage-0123456789abcdef"),
        b"retained synthetic stage",
    )
    .unwrap();
    assert!(content_presence(&stage_catalog, &provider, root).unwrap());

    let unknown_case = owned_case("legacy-unknown");
    let unknown_state = private_state(&unknown_case);
    let unknown_protector =
        ContentCountingProtector::from_existing_state(Arc::clone(&unknown_state));
    let unknown_catalog = catalog_at(&unknown_state, Arc::new(unknown_protector));
    unknown_catalog.register_scope(&selected).unwrap();
    let _unknown_journal = unknown_catalog.open_journal(&selected).unwrap();
    let unknown_path = EditJournal::storage_root(unknown_state.path())
        .join(EditJournal::scope_directory_key(&selected).unwrap());
    let unknown_entry = unknown_path.join("unexpected-entry");
    fs::write(&unknown_entry, b"unknown evidence").unwrap();
    assert!(content_presence(&unknown_catalog, &provider, root).is_err());
    assert_eq!(fs::read(unknown_entry).unwrap(), b"unknown evidence");

    let orphan_case = owned_case("legacy-orphan");
    let orphan_state = private_state(&orphan_case);
    let orphan_protector = ContentCountingProtector::from_existing_state(Arc::clone(&orphan_state));
    let orphan_catalog = catalog_at(&orphan_state, Arc::new(orphan_protector));
    let _orphan_journal = orphan_catalog.open_journal(&selected).unwrap();
    let absent_catalog = orphan_state.path().join(CATALOG_DIRECTORY);
    assert!(!absent_catalog.exists());
    assert!(content_presence(&orphan_catalog, &provider, root).is_err());
    assert!(
        !absent_catalog.exists(),
        "the reader must not repair an orphan"
    );
}

#[cfg(windows)]
#[test]
#[ignore = "requires a fresh retained R52 DPAPI fixture root"]
fn r52_prepared_health_excludes_own_namespace_and_detects_v2_with_no_streamed_context() {
    use crate::namespace_intent::{
        CapturedAuthorization, ExistingNamespaceEntry, LocalNamespaceEntry, NamespaceIntent,
        NamespaceObjectKind, NamespaceOperation, NamespaceParent, StorageClassification,
    };
    use crate::streamed_snapshot::SnapshotBinding;
    use crate::streamed_store::SnapshotStore;
    use raiun_control_windows::{PinnedDirectory, PrivateDirectory};
    use std::io::{Cursor, Write};

    let fixture = owned_case("prepared-health");
    let fixture_parent = PinnedDirectory::open(&fixture).unwrap();
    let logical_root = fixture_parent
        .create_child_directory(std::ffi::OsStr::new("logical-root"))
        .unwrap();
    let personal = logical_root
        .create_child_directory(std::ffi::OsStr::new("Personal"))
        .unwrap();
    let (_, source_identity) = personal
        .create_new_file(std::ffi::OsStr::new("before.bin"))
        .unwrap();
    let parent_identity = personal.identity();
    let root = ConfiguredRootIdentity {
        volume_serial: logical_root.identity().volume_serial,
        file_index: logical_root.identity().file_index,
    };
    let state = Arc::new(
        PrivateDirectory::create_or_open_under(&fixture_parent, std::ffi::OsStr::new("state"))
            .unwrap(),
    );
    let provider_scope = provider_scope();
    let scope = edit_scope(&provider_scope, root);
    let authorization = CapturedAuthorization {
        agent_generation: 4,
        token_generation: provider_scope.token_generation(),
    };
    let protector = ContentCountingProtector::from_existing_state(Arc::clone(&state));
    let protector_arc: Arc<dyn EditRecordProtector> = Arc::new(protector.clone());
    let store_policy = policy();
    let provider = DurableEditRecoveryProvider::new(
        state.path().to_path_buf(),
        provider_scope.clone(),
        root,
        protector.clone(),
    )
    .with_modern_namespace_file_rename(store_policy)
    .unwrap();
    let prepared = provider.prepare(&provider_scope, root).unwrap();
    assert!(!prepared.has_unresolved_content().unwrap());

    let namespace = prepared
        .file_rename_store(&scope, authorization)
        .unwrap()
        .unwrap();
    let parent = NamespaceParent {
        scope: scope.clone(),
        authorization,
        classification: StorageClassification::Ordinary,
        local_file: crate::LocalFileIdentity {
            volume_serial: parent_identity.volume_serial,
            file_index: parent_identity.file_index,
        },
        local_components: vec!["Personal".into()],
        remote: crate::RemoteEditBaseline {
            resource_id: "r52-parent".into(),
            etag: "\"parent-r52\"".into(),
            byte_len: 0,
        },
    };
    let source = LocalNamespaceEntry {
        parent: parent.clone(),
        name: "before.bin".into(),
        local_file: crate::LocalFileIdentity {
            volume_serial: source_identity.volume_serial,
            file_index: source_identity.file_index,
        },
        object_kind: NamespaceObjectKind::File,
    };
    let publication = namespace.publish_intent(NamespaceIntent {
        schema_version: 1,
        record_id: "a".repeat(32),
        record_generation: 1,
        operation: NamespaceOperation::MoveWithinScope {
            source: ExistingNamespaceEntry {
                local: source.clone(),
                remote: crate::RemoteEditBaseline {
                    resource_id: "r52-file".into(),
                    etag: "\"file-r52\"".into(),
                    byte_len: 4,
                },
            },
            destination: LocalNamespaceEntry {
                name: "after.bin".into(),
                ..source
            },
        },
    });
    assert!(publication.is_ok(), "R52 stage=namespace_publication");
    assert!(matches!(
        publication.unwrap(),
        crate::streamed_store::namespace_rename_store::FileRenamePublishResult::Fresh(_)
    ));
    assert!(prepared.has_unresolved().unwrap());
    protector.reset_content_open_count();
    assert!(!prepared.has_unresolved_content().unwrap());
    assert_eq!(
        protector.content_open_count(),
        0,
        "namespace intent metadata is not content recovery"
    );

    let snapshot = SnapshotStore::create_or_open(
        Arc::clone(&state),
        scope.clone(),
        Arc::clone(&protector_arc),
        store_policy,
    )
    .unwrap();
    let reservation = snapshot
        .try_begin_capture(SnapshotBinding {
            record_id: String::new(),
            scope: scope.clone(),
            generation: 1,
            local_file: crate::LocalFileIdentity {
                volume_serial: root.volume_serial,
                file_index: root.file_index + 3,
            },
            relative_path: "Personal/notes.txt".into(),
            remote: None,
            content_len: 4,
        })
        .unwrap();
    reservation
        .capture(&mut Cursor::new(b"data"), &mut || false)
        .unwrap()
        .verify_and_commit(&mut || false)
        .unwrap();
    assert!(
        protector.content_open_count() > 0,
        "capture verification must prove the counter detects V2 chunk decryption"
    );
    protector.reset_content_open_count();
    assert!(prepared.has_unresolved_content().unwrap());
    assert_eq!(
        protector.content_open_count(),
        0,
        "v2 health must classify committed content from metadata without opening its body"
    );

    let incomplete_case = owned_case("incomplete-capture");
    let incomplete_parent = PinnedDirectory::open(&incomplete_case).unwrap();
    let incomplete_state = Arc::new(
        PrivateDirectory::create_or_open_under(&incomplete_parent, std::ffi::OsStr::new("state"))
            .unwrap(),
    );
    let incomplete_protector =
        ContentCountingProtector::from_existing_state(Arc::clone(&incomplete_state));
    let incomplete_store = SnapshotStore::create_or_open(
        Arc::clone(&incomplete_state),
        scope.clone(),
        Arc::new(incomplete_protector.clone()),
        store_policy,
    )
    .unwrap();
    let reservation = incomplete_store
        .try_begin_capture(SnapshotBinding {
            record_id: String::new(),
            scope: scope.clone(),
            generation: 1,
            local_file: crate::LocalFileIdentity {
                volume_serial: root.volume_serial,
                file_index: root.file_index + 4,
            },
            relative_path: "Personal/incomplete.txt".into(),
            remote: None,
            content_len: 4,
        })
        .unwrap();
    drop(reservation);
    assert!(
        SnapshotStore::content_history_pending_existing(
            crate::recovery_state::RecoveryStateRoot::modern(incomplete_state),
            Arc::new(incomplete_protector),
            store_policy,
            &provider_scope,
            root,
            |_| Ok(false),
        )
        .is_err(),
        "a retained precommit reservation is unknown content evidence"
    );

    let missing_quota_case = owned_case("missing-quota");
    let missing_parent = PinnedDirectory::open(&missing_quota_case).unwrap();
    let missing_state = Arc::new(
        PrivateDirectory::create_or_open_under(&missing_parent, std::ffi::OsStr::new("state"))
            .unwrap(),
    );
    let missing_protector =
        ContentCountingProtector::from_existing_state(Arc::clone(&missing_state));
    let missing_v2 = PrivateDirectory::create_or_open_under(
        &PinnedDirectory::open(missing_state.path()).unwrap(),
        std::ffi::OsStr::new(crate::streamed_store::V2_STORE_ROOT),
    )
    .unwrap();
    assert!(
        SnapshotStore::content_history_pending_existing(
            crate::recovery_state::RecoveryStateRoot::modern(Arc::clone(&missing_state)),
            Arc::new(missing_protector),
            store_policy,
            &provider_scope,
            root,
            |_| Ok(false),
        )
        .is_err()
    );
    assert!(fs::read_dir(missing_v2.path()).unwrap().next().is_none());

    let corrupt_case = owned_case("corrupt-catalog");
    let corrupt_parent = PinnedDirectory::open(&corrupt_case).unwrap();
    let corrupt_state = Arc::new(
        PrivateDirectory::create_or_open_under(&corrupt_parent, std::ffi::OsStr::new("state"))
            .unwrap(),
    );
    let corrupt_protector =
        ContentCountingProtector::from_existing_state(Arc::clone(&corrupt_state));
    let admission = crate::recovery_admission::RecoveryAdmission::new(
        Arc::clone(&corrupt_state),
        Arc::new(corrupt_protector.clone()),
        store_policy,
    )
    .unwrap();
    drop(admission.try_reserve_unscoped(0, 0).unwrap());
    let corrupt_v2 = PrivateDirectory::open_under(
        &PinnedDirectory::open(corrupt_state.path()).unwrap(),
        std::ffi::OsStr::new(crate::streamed_store::V2_STORE_ROOT),
    )
    .unwrap();
    let (mut file, _) = corrupt_v2
        .create_new_file(std::ffi::OsStr::new("malformed.scope"))
        .unwrap();
    file.write_all(b"retained malformed metadata").unwrap();
    file.sync_all().unwrap();
    drop(file);
    let corrupt_path = corrupt_v2.path().join("malformed.scope");
    let before = fs::read(&corrupt_path).unwrap();
    assert!(
        SnapshotStore::content_history_pending_existing(
            crate::recovery_state::RecoveryStateRoot::modern(corrupt_state),
            Arc::new(corrupt_protector),
            store_policy,
            &provider_scope,
            root,
            |_| Ok(false),
        )
        .is_err()
    );
    assert_eq!(fs::read(corrupt_path).unwrap(), before);
}
