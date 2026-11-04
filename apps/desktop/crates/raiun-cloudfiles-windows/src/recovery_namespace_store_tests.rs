use super::*;
use crate::{
    ConfiguredRootIdentity, DurableEditRecoveryProvider, EditJournalScope, EditRecoveryProvider,
    PreparedEditRecovery, ProviderScope, RemoteEditBaseline,
    namespace_intent::{
        CapturedAuthorization, ExistingNamespaceEntry, LocalNamespaceEntry, NamespaceIntent,
        NamespaceObjectKind, NamespaceOperation, NamespaceParent, StorageClassification,
    },
};
use raiun_control_windows::{PinnedDirectory, PrivateDirectory};
use std::{ffi::OsStr, fs, os::windows::fs::MetadataExt, path::PathBuf, sync::Arc};

const OPT_IN: &str = "RAIUN_R44_NATIVE";
const FIXTURE_ENV: &str = "RAIUN_R44_FIXTURE_DIR";
const OWNER: &[u8] = b"raiun-r44-store-factory-owned-v1\n";
const R44_SELECTOR_FILTER: &str = "recovery_provider::namespace_storage::tests::r44_";
const HEALTH_SPEC: FixtureSpec = FixtureSpec {
    opt_in: "RAIUN_NAMESPACE_HEALTH_NATIVE",
    fixture_env: "RAIUN_NAMESPACE_HEALTH_FIXTURE_DIR",
    owner: b"raiun-namespace-health-owned-v1\n",
    selector_filter: "recovery_provider::namespace_storage::tests::namespace_health_",
};

struct FixtureSpec {
    opt_in: &'static str,
    fixture_env: &'static str,
    owner: &'static [u8],
    selector_filter: &'static str,
}

const R44_SPEC: FixtureSpec = FixtureSpec {
    opt_in: OPT_IN,
    fixture_env: FIXTURE_ENV,
    owner: OWNER,
    selector_filter: R44_SELECTOR_FILTER,
};

struct OwnedCase {
    fixture: PathBuf,
    state_path: PathBuf,
    provider: Option<DurableEditRecoveryProvider>,
    scope: ProviderScope,
    edit_scope: EditJournalScope,
    root: ConfiguredRootIdentity,
    parent_file: crate::LocalFileIdentity,
    source_file: crate::LocalFileIdentity,
    authorization: CapturedAuthorization,
}

fn policy() -> crate::streamed_store::StorePolicy {
    crate::streamed_store::StorePolicy {
        max_content_bytes: 32 * 1024 * 1024,
        max_state_bytes: 64 * 1024 * 1024,
        max_entries: 2000,
        max_metadata_bytes_per_scan: 8 * 1024 * 1024,
    }
}

fn owned_case(label: &str, spec: &FixtureSpec) -> OwnedCase {
    assert_eq!(std::env::var(spec.opt_in).as_deref(), Ok("1"));
    let arguments = std::env::args().collect::<Vec<_>>();
    assert!(
        arguments.iter().any(|arg| arg == spec.selector_filter)
            && arguments.iter().any(|arg| arg == "--ignored")
            && arguments.iter().any(|arg| arg == "--test-threads=1")
    );
    let fixture = PathBuf::from(std::env::var_os(spec.fixture_env).expect("wrapper fixture path"));
    assert!(fixture.is_absolute());
    let metadata = fs::symlink_metadata(&fixture).expect("fixture metadata");
    assert!(metadata.is_dir() && metadata.file_attributes() & 0x400 == 0);
    let owner_metadata = fs::symlink_metadata(fixture.join("OWNER.txt")).expect("owner marker");
    assert!(owner_metadata.is_file() && owner_metadata.file_attributes() & 0x400 == 0);
    assert_eq!(owner_metadata.len(), spec.owner.len() as u64);
    assert_eq!(fs::read(fixture.join("OWNER.txt")).unwrap(), spec.owner);

    let case_path = fixture.join(label);
    assert_eq!(
        fs::symlink_metadata(&case_path).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
    fs::create_dir(&case_path).expect("unique retained case directory");
    let case_pin = PinnedDirectory::open(&case_path).expect("pin owned case");
    let logical = case_pin
        .create_child_directory(OsStr::new("logical-root"))
        .expect("create synthetic logical root");
    let personal = logical
        .create_child_directory(OsStr::new("Personal"))
        .expect("create synthetic Personal directory");
    let (_, source_identity) = personal
        .create_new_file(OsStr::new("before.bin"))
        .expect("create synthetic source identity");
    let logical_identity = logical.identity();
    let parent_identity = personal.identity();
    let state = Arc::new(
        PrivateDirectory::create_or_open_under(&case_pin, OsStr::new("state"))
            .expect("create private state under owned fixture"),
    );
    let state_path = state.path().to_path_buf();
    let protector =
        crate::DpapiEditRecordProtector::from_existing_private_directory(Arc::clone(&state))
            .expect("DPAPI protector from exact fixture state");
    let client = raiun_opencloud::OpenCloudClient::new_with_proxy(
        "https://r44.invalid",
        "fixture-token".into(),
        &raiun_opencloud::ProxyConfig::Direct,
    )
    .expect("synthetic client config");
    let scope = ProviderScope::new(
        &client,
        "r44-profile".into(),
        "r44-account".into(),
        "https://r44.invalid".into(),
    )
    .expect("synthetic provider scope");
    let root = ConfiguredRootIdentity {
        volume_serial: logical_identity.volume_serial,
        file_index: logical_identity.file_index,
    };
    let edit_scope = EditJournalScope {
        profile_id: scope.profile_id().to_owned(),
        server_origin: scope.server_origin().to_owned(),
        account_subject: scope.account_id().to_owned(),
        space_id: "r44-space".into(),
        root_resource_id: "r44-root".into(),
        root_volume_serial: root.volume_serial,
        root_file_index: root.file_index,
    };
    let authorization = CapturedAuthorization {
        agent_generation: 4,
        token_generation: client.token_generation(),
    };
    let provider =
        DurableEditRecoveryProvider::new(state_path.clone(), scope.clone(), root, protector);
    OwnedCase {
        fixture,
        state_path,
        provider: Some(provider),
        scope,
        edit_scope,
        root,
        parent_file: crate::LocalFileIdentity {
            volume_serial: parent_identity.volume_serial,
            file_index: parent_identity.file_index,
        },
        source_file: crate::LocalFileIdentity {
            volume_serial: source_identity.volume_serial,
            file_index: source_identity.file_index,
        },
        authorization,
    }
}

fn synthetic_intent(case: &OwnedCase) -> NamespaceIntent {
    let parent = NamespaceParent {
        scope: case.edit_scope.clone(),
        authorization: case.authorization,
        classification: StorageClassification::Ordinary,
        local_file: case.parent_file,
        local_components: vec!["Personal".into()],
        remote: RemoteEditBaseline {
            resource_id: "synthetic-r44-parent".into(),
            etag: "\"parent-v1\"".into(),
            byte_len: 0,
        },
    };
    let source = LocalNamespaceEntry {
        parent: parent.clone(),
        name: "before.bin".into(),
        local_file: case.source_file,
        object_kind: NamespaceObjectKind::File,
    };
    let mut destination = source.clone();
    destination.name = "after.bin".into();
    NamespaceIntent {
        schema_version: 1,
        record_id: "0".repeat(32),
        record_generation: 1,
        operation: NamespaceOperation::MoveWithinScope {
            source: ExistingNamespaceEntry {
                local: source,
                remote: RemoteEditBaseline {
                    resource_id: "synthetic-r44-file".into(),
                    etag: "\"before-v1\"".into(),
                    byte_len: 4,
                },
            },
            destination,
        },
    }
}

fn prepare(
    case: &OwnedCase,
    provider: &DurableEditRecoveryProvider,
) -> Arc<dyn PreparedEditRecovery> {
    provider
        .prepare(&case.scope, case.root)
        .expect("prepare exact provider scope")
}

struct LegacyPrepared {
    scope: ProviderScope,
    root: ConfiguredRootIdentity,
}

impl PreparedEditRecovery for LegacyPrepared {
    fn provider_scope(&self) -> &ProviderScope {
        &self.scope
    }
    fn root_identity(&self) -> ConfiguredRootIdentity {
        self.root
    }
    fn append_edit(
        &self,
        _binding: &crate::PlaceholderEditBinding,
        _root: ConfiguredRootIdentity,
        _file: crate::LocalFileIdentity,
        _path: &str,
        _content: &[u8],
    ) -> Result<(), BackendError> {
        Err(BackendError::Unavailable)
    }
    fn has_unresolved(&self) -> Result<bool, BackendError> {
        Err(BackendError::Unavailable)
    }
}

#[test]
#[ignore = "R44 explicit wrapper-owned DPAPI storage fixture"]
fn r44_default_and_unconfigured_provider_offer_no_namespace_store() {
    let case = owned_case("r44-default-none", &R44_SPEC);
    let legacy = LegacyPrepared {
        scope: case.scope.clone(),
        root: case.root,
    };
    assert!(
        legacy
            .file_rename_store(&case.edit_scope, case.authorization)
            .unwrap()
            .is_none()
    );
    let prepared = prepare(&case, case.provider.as_ref().unwrap());
    assert!(
        prepared
            .file_rename_store(&case.edit_scope, case.authorization)
            .expect("unsupported is a normal absence")
            .is_none()
    );
    assert!(!case.state_path.join("cloud-files-edit-journal-v2").exists());
}

#[test]
#[ignore = "R44 explicit wrapper-owned DPAPI storage fixture"]
fn r44_namespace_only_keeps_streamed_capture_disabled_and_pending_unknown() {
    let mut case = owned_case("r44-namespace-only", &R44_SPEC);
    let configured = case
        .provider
        .take()
        .unwrap()
        .with_modern_namespace_file_rename(policy())
        .expect("explicit modern namespace opt-in");
    let prepared = prepare(&case, &configured);
    assert!(!prepared.supports_streamed_capture());
    assert!(prepared.begin_streamed_job().is_none());
    assert_eq!(prepared.cached_ordinary_pending_count(), None);
    assert!(
        prepared
            .file_rename_store(&case.edit_scope, case.authorization)
            .expect("scoped storage factory")
            .is_some()
    );
    let mut gui_case = owned_case("r44-gui-namespace-only", &R44_SPEC);
    let gui = gui_case
        .provider
        .take()
        .unwrap()
        .with_gui_namespace_file_rename(policy())
        .expect("explicit compatibility admission for owned state");
    assert_eq!(
        gui.namespace_rename.as_ref().unwrap().state.path(),
        gui_case.state_path
    );
    let gui_prepared = prepare(&gui_case, &gui);
    assert!(!gui_prepared.supports_streamed_capture());
    assert!(gui_prepared.begin_streamed_job().is_none());
    assert_eq!(gui_prepared.cached_ordinary_pending_count(), None);
    assert!(
        gui_prepared
            .file_rename_store(&gui_case.edit_scope, gui_case.authorization)
            .expect("same original admitted compatibility state")
            .is_some()
    );
}

#[test]
#[ignore = "R44 explicit wrapper-owned DPAPI storage fixture"]
fn r44_wrong_provider_scope_root_or_auth_rejects_before_store_creation() {
    let mut case = owned_case("r44-reject-before-write", &R44_SPEC);
    let configured = case
        .provider
        .take()
        .unwrap()
        .with_modern_namespace_file_rename(policy())
        .expect("explicit namespace opt-in");
    let prepared = prepare(&case, &configured);
    // Recovery preflight already reserves the common quota domain. Record
    // that legitimate baseline before testing malformed factory requests.
    let quota_root = case.state_path.join("cloud-files-edit-journal-v2");
    let before = fs::read_dir(&quota_root)
        .unwrap()
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<std::collections::BTreeSet<_>>>()
        .unwrap();
    let mut wrong_profile = case.edit_scope.clone();
    wrong_profile.profile_id.push_str("-other");
    assert!(
        prepared
            .file_rename_store(&wrong_profile, case.authorization)
            .is_err()
    );
    let mut wrong_account = case.edit_scope.clone();
    wrong_account.account_subject.push_str("-other");
    assert!(
        prepared
            .file_rename_store(&wrong_account, case.authorization)
            .is_err()
    );
    let mut wrong_origin = case.edit_scope.clone();
    wrong_origin.server_origin = "https://other.invalid".to_owned();
    assert!(
        prepared
            .file_rename_store(&wrong_origin, case.authorization)
            .is_err()
    );
    let mut wrong_volume = case.edit_scope.clone();
    wrong_volume.root_volume_serial = wrong_volume.root_volume_serial.wrapping_add(1);
    assert!(
        prepared
            .file_rename_store(&wrong_volume, case.authorization)
            .is_err()
    );
    let mut empty_space = case.edit_scope.clone();
    empty_space.space_id.clear();
    assert!(
        prepared
            .file_rename_store(&empty_space, case.authorization)
            .is_err()
    );
    let mut wrong_root = case.edit_scope.clone();
    wrong_root.root_file_index += 1;
    assert!(
        prepared
            .file_rename_store(&wrong_root, case.authorization)
            .is_err()
    );
    assert!(
        prepared
            .file_rename_store(
                &case.edit_scope,
                CapturedAuthorization {
                    agent_generation: 0,
                    ..case.authorization
                },
            )
            .is_err()
    );
    assert!(
        prepared
            .file_rename_store(
                &case.edit_scope,
                CapturedAuthorization {
                    token_generation: case.authorization.token_generation + 1,
                    ..case.authorization
                },
            )
            .is_err()
    );
    let after = fs::read_dir(&quota_root)
        .unwrap()
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<std::collections::BTreeSet<_>>>()
        .unwrap();
    assert_eq!(
        before, after,
        "rejected requests must not alter the preflight quota domain"
    );
    assert!(!quota_root.join("namespace-rename-v1").exists());
}

#[test]
#[ignore = "R44 explicit wrapper-owned DPAPI storage fixture"]
fn r44_streamed_context_is_reused_for_namespace_storage() {
    let mut case = owned_case("r44-streamed-reuse", &R44_SPEC);
    let configured = case
        .provider
        .take()
        .unwrap()
        .with_streamed_recovery(policy())
        .expect("admit streamed context");
    let streamed_state = Arc::clone(&configured.streamed.as_ref().unwrap().state);
    let streamed_admission = Arc::clone(&configured.streamed.as_ref().unwrap().admission);
    let configured = configured
        .with_modern_namespace_file_rename(policy())
        .expect("namespace opt-in reuses exact admitted context");
    let namespace = configured.namespace_rename.as_ref().unwrap();
    assert!(Arc::ptr_eq(&namespace.state, &streamed_state));
    assert!(Arc::ptr_eq(&namespace.admission, &streamed_admission));
    let prepared = prepare(&case, &configured);
    assert!(prepared.supports_streamed_capture());
    assert!(
        prepared
            .file_rename_store(&case.edit_scope, case.authorization)
            .unwrap()
            .is_some()
    );
}

#[test]
#[ignore = "R44 explicit wrapper-owned DPAPI storage fixture"]
fn r44_namespace_opt_in_is_last_and_policy_mismatch_fails_closed() {
    let mut case = owned_case("r44-builder-order", &R44_SPEC);
    let configured = case
        .provider
        .take()
        .unwrap()
        .with_modern_namespace_file_rename(policy())
        .expect("namespace opt-in");
    assert!(
        configured
            .with_modern_namespace_file_rename(policy())
            .is_err()
    );
    let mut case = owned_case("r44-stream-after-namespace", &R44_SPEC);
    let configured = case
        .provider
        .take()
        .unwrap()
        .with_modern_namespace_file_rename(policy())
        .expect("namespace opt-in");
    assert!(configured.with_streamed_recovery(policy()).is_err());

    let mut case = owned_case("r44-streamed-only-reconfigure", &R44_SPEC);
    let streamed = case
        .provider
        .take()
        .unwrap()
        .with_streamed_recovery(policy())
        .expect("streamed-only builder");
    let reconfigured = streamed
        .with_streamed_recovery_policy(
            crate::streamed_store::StorePolicy {
                max_content_bytes: 16 * 1024 * 1024,
                ..policy()
            },
            crate::StreamedRecoveryPolicy::default(),
        )
        .expect("preserve existing streamed-only reconfiguration behavior");
    assert!(
        reconfigured
            .with_modern_namespace_file_rename(crate::streamed_store::StorePolicy {
                max_content_bytes: 16 * 1024 * 1024,
                ..policy()
            })
            .is_ok()
    );
    let mut case = owned_case("r44-policy-mismatch", &R44_SPEC);
    let streamed = case
        .provider
        .take()
        .unwrap()
        .with_streamed_recovery(policy())
        .expect("streamed context");
    assert!(
        streamed
            .with_modern_namespace_file_rename(crate::streamed_store::StorePolicy {
                max_content_bytes: 16 * 1024 * 1024,
                ..policy()
            })
            .is_err()
    );
}

#[test]
#[ignore = "R44 explicit wrapper-owned DPAPI storage fixture"]
fn r44_scoped_store_reopens_from_same_protected_state() {
    let mut case = owned_case("r44-store-reopen", &R44_SPEC);
    let configured = case
        .provider
        .take()
        .unwrap()
        .with_modern_namespace_file_rename(policy())
        .expect("explicit namespace opt-in");
    let first = prepare(&case, &configured)
        .file_rename_store(&case.edit_scope, case.authorization)
        .expect("initial scoped factory")
        .expect("opted-in store");
    let reopened = prepare(&case, &configured)
        .file_rename_store(&case.edit_scope, case.authorization)
        .expect("reopen scoped factory")
        .expect("opted-in store reopened");
    assert!(case.state_path.join("cloud-files-edit-journal-v2").is_dir());
    assert!(!Arc::ptr_eq(&first, &reopened));
    let intent = synthetic_intent(&case);
    assert!(matches!(
        first
            .publish_intent(intent.clone())
            .expect("publish protected intent"),
        crate::streamed_store::namespace_rename_store::FileRenamePublishResult::Fresh(_)
    ));
    assert!(matches!(
        reopened
            .publish_intent(intent)
            .expect("discover existing protected history"),
        crate::streamed_store::namespace_rename_store::FileRenamePublishResult::Retained
    ));
    assert_eq!(reopened.discover_account_root().unwrap().len(), 1);
    assert!(case.fixture.join("OWNER.txt").is_file());
}

#[test]
#[ignore = "explicit fresh namespace-health metadata fixture; no CF registration or network"]
fn namespace_health_empty_and_legacy_baseline_are_read_only() {
    let mut case = owned_case("health-empty", &HEALTH_SPEC);
    let configured = case
        .provider
        .take()
        .unwrap()
        .with_modern_namespace_file_rename(policy())
        .expect("explicit namespace opt-in");
    let prepared = prepare(&case, &configured);
    assert!(!prepared.has_unresolved().unwrap());
    assert_eq!(prepared.cached_ordinary_pending_count(), None);
    assert!(
        !case
            .state_path
            .join("cloud-files-edit-journal-v2")
            .join("namespace-rename-v1")
            .exists()
    );

    let mut baseline = owned_case("health-v1-baseline", &HEALTH_SPEC);
    let baseline_provider = baseline.provider.take().unwrap();
    let baseline_prepared = prepare(&baseline, &baseline_provider);
    assert!(
        !baseline_prepared
            .has_unresolved()
            .expect("legacy-only empty status remains healthy")
    );
    assert!(
        !baseline
            .state_path
            .join("cloud-files-edit-journal-v2")
            .exists()
    );

    let baseline_state = PinnedDirectory::open(&baseline.state_path)
        .expect("pin exact legacy baseline state directory");
    let empty_v2 = PrivateDirectory::create_or_open_under(
        &baseline_state,
        OsStr::new(crate::streamed_store::V2_STORE_ROOT),
    )
    .expect("create owned empty v2 root under legacy state");
    let empty_v2_path = empty_v2.path().to_path_buf();
    let _empty_v2_pin = PinnedDirectory::open(&empty_v2_path).expect("pin empty v2 root");
    assert!(
        fs::read_dir(&empty_v2_path)
            .expect("read synthetic empty v2 root")
            .next()
            .is_none()
    );
    assert_eq!(
        fs::symlink_metadata(empty_v2_path.join(crate::streamed_store::V2_QUOTA_LOCK))
            .expect_err("empty v2 root has no quota lock")
            .kind(),
        std::io::ErrorKind::NotFound
    );
    assert!(matches!(
        baseline_prepared.has_unresolved(),
        Err(crate::BackendError::Unavailable)
    ));
    assert!(
        fs::read_dir(&empty_v2_path)
            .expect("recheck empty v2 root")
            .next()
            .is_none()
    );
    assert_eq!(
        fs::symlink_metadata(empty_v2_path.join(crate::streamed_store::V2_QUOTA_LOCK))
            .expect_err("health reader did not create quota lock")
            .kind(),
        std::io::ErrorKind::NotFound
    );
}

#[test]
#[ignore = "explicit fresh namespace-health metadata fixture; no CF registration or network"]
fn namespace_health_pending_complete_and_unopted_restart() {
    let mut case = owned_case("health-pending-complete", &HEALTH_SPEC);
    let configured = case
        .provider
        .take()
        .unwrap()
        .with_streamed_recovery(policy())
        .expect("explicit shared streamed state admission")
        .with_modern_namespace_file_rename(policy())
        .expect("namespace storage reuses same state and admission");
    let prepared = prepare(&case, &configured);
    let store = prepared
        .file_rename_store(&case.edit_scope, case.authorization)
        .expect("exact account/root factory")
        .expect("namespace storage opted in");
    let fresh = match store
        .publish_intent(synthetic_intent(&case))
        .expect("persist fresh synthetic pending intent")
    {
        crate::streamed_store::namespace_rename_store::FileRenamePublishResult::Fresh(fresh) => {
            fresh
        }
        crate::streamed_store::namespace_rename_store::FileRenamePublishResult::Retained => {
            panic!("fresh fixture must not contain retained history")
        }
    };
    let history = store
        .discover_account_root()
        .expect("authenticate pending history");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].progress.sequence, 0);
    assert_eq!(
        history[0].progress.remote,
        crate::namespace_intent::NamespacePhase::Pending
    );
    assert!(!history[0].progress.recorded_complete);
    assert!(prepared.has_unresolved().unwrap());
    assert!(configured.has_unresolved_edits().unwrap());
    let unsupported = unconfigured_reopen(&case);
    assert!(unsupported.has_unresolved_edits().is_err());
    assert!(unsupported.prepare(&case.scope, case.root).is_err());

    // These are authenticated metadata fixtures, not cloud/native completion
    // proofs. Reader classification must never create dispatch custody.
    let mut lease = fresh.acquire_dispatch().unwrap();
    let NamespaceOperation::MoveWithinScope {
        source,
        destination,
    } = lease.intent().operation.clone()
    else {
        unreachable!();
    };
    let mut remote = source.remote.clone();
    remote.etag = "\"metadata-after-v1\"".into();
    lease
        .append_event(crate::namespace_intent::NamespaceEventKind::RemoteSubmitted)
        .unwrap();
    lease
        .append_event(
            crate::namespace_intent::NamespaceEventKind::RemoteVerified {
                report: crate::namespace_intent::NamespaceDestinationReport {
                    destination: destination.clone(),
                    remote,
                    content: None,
                },
            },
        )
        .unwrap();
    lease
        .append_event(crate::namespace_intent::NamespaceEventKind::LocalCompleted { destination })
        .unwrap();
    lease
        .append_event(crate::namespace_intent::NamespaceEventKind::SourceRemovalVerified { source })
        .unwrap();
    assert!(!prepared.has_unresolved().unwrap());
    assert!(!configured.has_unresolved_edits().unwrap());
    assert_eq!(prepared.cached_ordinary_pending_count(), None);
    assert!(unsupported.prepare(&case.scope, case.root).is_err());
    let resumed = unconfigured_reopen(&case)
        .with_modern_namespace_file_rename(policy())
        .unwrap();
    assert!(!prepare(&case, &resumed).has_unresolved().unwrap());
}

fn unconfigured_reopen(case: &OwnedCase) -> DurableEditRecoveryProvider {
    let parent = PinnedDirectory::open(case.state_path.parent().unwrap()).unwrap();
    let state = Arc::new(
        PrivateDirectory::open_under(&parent, case.state_path.file_name().unwrap()).unwrap(),
    );
    let protector =
        crate::DpapiEditRecordProtector::from_existing_private_directory(state).unwrap();
    DurableEditRecoveryProvider::new(
        case.state_path.clone(),
        case.scope.clone(),
        case.root,
        protector,
    )
}

#[test]
#[ignore = "explicit fresh namespace-health metadata fixture; no CF registration or network"]
fn namespace_health_corrupt_history_stays_unknown_without_repair() {
    let mut case = owned_case("health-corrupt", &HEALTH_SPEC);
    let configured = case
        .provider
        .take()
        .unwrap()
        .with_modern_namespace_file_rename(policy())
        .unwrap();
    let prepared = prepare(&case, &configured);
    let store = prepared
        .file_rename_store(&case.edit_scope, case.authorization)
        .unwrap()
        .unwrap();
    drop(store.publish_intent(synthetic_intent(&case)).unwrap());
    let directory = case
        .state_path
        .join("cloud-files-edit-journal-v2")
        .join("namespace-rename-v1");
    let catalog = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension() == Some(OsStr::new("scope")))
        .unwrap();
    let corrupt = b"owned invalid namespace catalog";
    fs::write(&catalog, corrupt).unwrap();
    assert!(prepared.has_unresolved().is_err());
    assert!(configured.has_unresolved_edits().is_err());
    assert!(
        unconfigured_reopen(&case)
            .prepare(&case.scope, case.root)
            .is_err()
    );
    assert_eq!(fs::read(catalog).unwrap(), corrupt);
}
