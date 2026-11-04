//! Opt-in native storage compatibility only: no account, network or CF mount.
use super::*;
use crate::{
    ConfiguredRootIdentity, DpapiEditRecordProtector, DurableEditRecoveryProvider,
    EditJournalScope, EditRecordProtector, LocalFileIdentity, ProviderScope,
    recovery_admission::RecoveryAdmission,
    streamed_snapshot::SnapshotBinding,
    streamed_store::{SnapshotStore, StoreError, StorePolicy, V2_STORE_ROOT},
};
use sha2::{Digest, Sha256};
use std::{ffi::OsStr, fs, io::Read, process::Command};

const TEST: &str = "recovery_state::tests::gui_legacy_session_state_isolated_child";
const MARKER: &[u8] = b"raiun GUI legacy state fixture v1\n";
const CONTENT_LEN: u64 = 17 * 1024 * 1024 + 7;

fn policy() -> StorePolicy {
    StorePolicy {
        max_content_bytes: 32 * 1024 * 1024,
        max_state_bytes: 256 * 1024 * 1024,
        max_entries: 4096,
        max_metadata_bytes_per_scan: 16 * 1024 * 1024,
    }
}

fn scope() -> EditJournalScope {
    EditJournalScope {
        profile_id: "default".into(),
        server_origin: "https://synthetic.invalid".into(),
        account_subject: "synthetic-subject".into(),
        space_id: "personal".into(),
        root_resource_id: "synthetic-root".into(),
        root_volume_serial: 1,
        root_file_index: 2,
    }
}

#[test]
#[ignore = "explicit fresh-owned Windows GUI bootstrap/DPAPI fixture; no original state or CF provider"]
fn gui_legacy_session_state_isolated_child() {
    if let Ok(mode) = std::env::var("RAIUN_GUI_STATE_COMPAT_CHILD") {
        assert!(matches!(mode.as_str(), "save" | "reopen"));
        run_child(&mode);
        return;
    }
    assert_eq!(
        std::env::var("RAIUN_RUN_GUI_STATE_COMPAT").as_deref(),
        Ok("fresh-owned-state")
    );
    // Retain every fixture on both success and failure. Never select an
    // existing user directory from configuration or command-line arguments.
    let base = tempfile::Builder::new()
        .prefix("raiun-gui-state-compat-")
        .tempdir()
        .unwrap()
        .keep();
    let _pin = PinnedDirectory::open(&base).unwrap();
    let local = base.join("appdata");
    fs::create_dir(&local).unwrap();
    fs::write(base.join("fixture.marker"), MARKER).unwrap();
    for mode in ["save", "reopen"] {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                TEST,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("RAIUN_GUI_STATE_COMPAT_CHILD", mode)
            .env("RAIUN_GUI_STATE_COMPAT_BASE", &base)
            .env("LOCALAPPDATA", &local)
            .output()
            .unwrap();
        fs::write(base.join(format!("{mode}.stdout")), &output.stdout).unwrap();
        fs::write(base.join(format!("{mode}.stderr")), &output.stderr).unwrap();
        assert!(
            output.status.success(),
            "isolated {mode} failed; evidence retained"
        );
    }
    println!("gui_state_compat=save_reopen_dpapi_quota_acl_retention_passed");
}

fn run_child(mode: &str) {
    use std::os::windows::fs::MetadataExt;
    let base = std::env::var_os("RAIUN_GUI_STATE_COMPAT_BASE")
        .map(std::path::PathBuf::from)
        .unwrap();
    assert!(
        base.file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("raiun-gui-state-compat-")
    );
    assert_eq!(
        base.parent().unwrap().canonicalize().unwrap(),
        std::env::temp_dir().canonicalize().unwrap()
    );
    let _base_pin = PinnedDirectory::open(&base).unwrap();
    let marker = fs::symlink_metadata(base.join("fixture.marker")).unwrap();
    assert!(marker.is_file() && marker.file_attributes() & 0x400 == 0);
    assert_eq!(marker.len(), MARKER.len() as u64);
    assert_eq!(fs::read(base.join("fixture.marker")).unwrap(), MARKER);
    let local = base.join("appdata");
    assert_eq!(std::env::var_os("LOCALAPPDATA").unwrap(), local.as_os_str());
    let _local_pin = PinnedDirectory::open(&local).unwrap();
    if mode == "save" {
        assert!(!local.join("Raiun").exists(), "fresh fixture required");
    }
    // Exercise the exact ordinary GUI constructor, not a headless root override.
    let protector = DpapiEditRecordProtector::current_user().unwrap();
    let state_path = protector.local_state_directory().to_path_buf();
    assert_eq!(state_path, local.join("Raiun").join("sessions"));
    let parent = PinnedDirectory::open(state_path.parent().unwrap()).unwrap();
    assert!(PrivateDirectory::open_under(&parent, OsStr::new("sessions")).is_err());
    let state = RecoveryStateRoot::existing_gui(&state_path).unwrap();
    let identity = state.identity();
    let retained = state_path.join("cloud-files-edit-journal-v1");
    let sentinel = retained.join("retained-synthetic.bin");
    if mode == "save" {
        fs::create_dir(&retained).unwrap();
        protector.protect_directory(&retained).unwrap();
        fs::write(&sentinel, vec![0x35; 1024 * 1024]).unwrap();
    }
    let before = Sha256::digest(fs::read(&sentinel).unwrap());
    let protector: Arc<dyn EditRecordProtector> = Arc::new(protector);
    let store = SnapshotStore::create_or_open_admitted(
        Arc::clone(&state),
        scope(),
        Arc::clone(&protector),
        policy(),
    )
    .unwrap();
    let admission =
        RecoveryAdmission::new_admitted(Arc::clone(&state), Arc::clone(&protector), policy())
            .unwrap();
    assert_eq!(admission.state_identity(), identity);
    if mode == "save" {
        let mut tiny = policy();
        tiny.max_state_bytes = 512 * 1024;
        let constrained =
            RecoveryAdmission::new_admitted(Arc::clone(&state), Arc::clone(&protector), tiny)
                .unwrap();
        assert!(matches!(
            constrained.try_reserve_unscoped(0, 0),
            Err(StoreError::Quota)
        ));
        let binding = SnapshotBinding {
            record_id: String::new(),
            scope: scope(),
            generation: 1,
            local_file: LocalFileIdentity {
                volume_serial: 1,
                file_index: 4,
            },
            relative_path: "synthetic.bin".into(),
            remote: None,
            content_len: CONTENT_LEN,
        };
        let lease = admission.try_reserve_unscoped(0, 0).unwrap();
        assert_eq!(
            store.try_begin_capture(binding.clone()).err(),
            Some(StoreError::Busy),
            "competing capture must report busy without admitting a reservation"
        );
        drop(lease);
        let committed = store
            .try_begin_capture(binding)
            .unwrap()
            .capture(&mut std::io::repeat(0x5a).take(CONTENT_LEN), &mut || false)
            .unwrap()
            .verify_and_commit(&mut || false)
            .unwrap();
        let record = committed.manifest().binding().record_id.clone();
        fs::write(base.join("snapshot.json"), serde_json::to_vec(&serde_json::json!({
            "record":record,"state_volume":identity.volume_serial,"state_index":identity.file_index
        })).unwrap()).unwrap();
    }
    let saved: serde_json::Value =
        serde_json::from_slice(&fs::read(base.join("snapshot.json")).unwrap()).unwrap();
    assert_eq!(
        saved["state_volume"].as_u64(),
        Some(u64::from(identity.volume_serial))
    );
    assert_eq!(saved["state_index"].as_u64(), Some(identity.file_index));
    let id = saved["record"].as_str().unwrap();
    let manifest = store.discover_metadata().unwrap();
    assert_eq!(manifest.len(), 1);
    assert_eq!(manifest[0].binding().record_id, id);
    let snapshot = store.open_verified(id, &mut || false).unwrap();
    let mut reader = snapshot.into_reader(Arc::new(|| false)).unwrap();
    let mut buffer = [0u8; 64 * 1024];
    let mut read = 0u64;
    loop {
        let n = reader.read(&mut buffer).unwrap();
        if n == 0 {
            break;
        }
        assert!(buffer[..n].iter().all(|b| *b == 0x5a));
        read += n as u64;
    }
    assert_eq!(read, CONTENT_LEN);
    drop(reader);
    assert_eq!(Sha256::digest(fs::read(&sentinel).unwrap()), before);
    state.verify_path().unwrap();
    assert_eq!(state.identity(), identity);
    assert!(PrivateDirectory::open_under(&parent, OsStr::new("sessions")).is_err());
    let v2_parent = PinnedDirectory::open(&state_path).unwrap();
    PrivateDirectory::open_under(&v2_parent, OsStr::new(V2_STORE_ROOT)).unwrap();
    assert!(
        !state_path.join("recovery-v2").exists(),
        "no second quota/storage domain"
    );
    // Also exercise the provider's explicit compatibility constructor. It
    // grants no upload/native completion and remains unused by GUI production.
    let client = raiun_opencloud::OpenCloudClient::new(
        "https://synthetic.invalid",
        "synthetic-token".into(),
    )
    .unwrap();
    let provider_scope = ProviderScope::new(
        &client,
        "default".into(),
        "synthetic-subject".into(),
        "https://synthetic.invalid".into(),
    )
    .unwrap();
    DurableEditRecoveryProvider::current_user(
        provider_scope,
        ConfiguredRootIdentity {
            volume_serial: 1,
            file_index: 2,
        },
    )
    .unwrap()
    .with_gui_streamed_recovery(policy())
    .unwrap();
    fs::write(
        base.join(format!("{mode}.json")),
        serde_json::to_vec(&serde_json::json!({
            "passed":true,"bytes":CONTENT_LEN,"legacy_sentinel_preserved":true,
            "legacy_root_still_rejected_by_modern_policy":true,"strict_v2_child":true,
            "original_root_identity_retained":true,"separate_process":mode=="reopen",
            "no_network_accounts_mounts":true
        }))
        .unwrap(),
    )
    .unwrap();
}
