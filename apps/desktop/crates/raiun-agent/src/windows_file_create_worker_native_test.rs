//! Root held-stop and one existing-subfolder positive native worker fixture.
//! No dispatch/custody/health admission is supplied by this module.
use super::windows_file_create_public_entry_test::{RetainedFactory, digest, generated, policy};
use super::*;
use cf::EditRecoveryProvider;
use raiun_cloudfiles_windows as cf;
use raiun_control_windows::{PinnedDirectory, PrivateDirectory};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsStr,
    fs,
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    os::windows::fs::MetadataExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
const SELECTOR: &str = "agent_windows::windows_file_create_worker_native_test::owner_workers_complete_then_cancel_held_create";
const NESTED_SELECTOR: &str = "agent_windows::windows_file_create_worker_native_test::owner_workers_existing_personal_subfolder_completes";
const FOLDER: &str = "Courses & CEUs #1";
const PARENT_ID: &str = "managed-parent";
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Case {
    RootHeldStop,
    ExistingSubfolder,
}
impl Case {
    fn selector(self) -> &'static str {
        if self == Self::RootHeldStop {
            SELECTOR
        } else {
            NESTED_SELECTOR
        }
    }
    fn nested(self) -> bool {
        self == Self::ExistingSubfolder
    }
    fn relative(self, name: &str) -> String {
        if self.nested() {
            format!("{FOLDER}/{name}")
        } else {
            name.into()
        }
    }
    fn parent(self, cloud: &Path) -> PathBuf {
        let personal = cloud.join("Personal");
        if self.nested() {
            personal.join(FOLDER)
        } else {
            personal
        }
    }
    fn components(self) -> Vec<&'static str> {
        if self.nested() {
            vec!["Personal", FOLDER, A]
        } else {
            vec!["Personal", A]
        }
    }
    fn url(self, base: &str, name: Option<&str>) -> url::Url {
        let mut value = url::Url::parse(base).unwrap();
        if self.nested() || name.is_some() {
            let mut parts = value.path_segments_mut().unwrap();
            parts.pop_if_empty();
            if self.nested() {
                parts.push(FOLDER);
            }
            if let Some(name) = name {
                parts.push(name);
            }
        }
        value
    }
}
const FLAG: &str = "RAIUN_CREATE_WORKER_NATIVE";
const DIRECTORY: &str = "RAIUN_CREATE_WORKER_FIXTURE_DIR";
const ROLE: &str = "RAIUN_CREATE_WORKER_CHILD_ROLE";
const OWNER: &[u8] = b"raiun-create-worker-native-owned-v1\n";
const SPACE: &str = "personal-drive";
const ROOT_ID: &str = "personal-drive!root";
const DAV: &str = "/dav/spaces/personal-drive/";
const A: &str = "source.bin";
const B: &str = "stop.bin";
const LENGTH: u64 = 17 * 1024 * 1024 + 7;
fn b_body() -> Vec<u8> {
    (0..4096).map(|n| (n % 251) as u8).collect()
}
fn expected(name: &str) -> (u64, [u8; 32]) {
    if name == A {
        (LENGTH, generated(&mut io::sink()))
    } else {
        let b = b_body();
        (b.len() as u64, Sha256::digest(b).into())
    }
}
fn report(root: &Path, name: &str, value: Value) {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join(name))
        .unwrap();
    f.write_all(&serde_json::to_vec_pretty(&value).unwrap())
        .unwrap();
    f.sync_all().unwrap();
}
fn wait(mut predicate: impl FnMut() -> bool, label: &str) {
    let deadline = Instant::now() + Duration::from_secs(25);
    while !predicate() {
        assert!(
            Instant::now() < deadline,
            "factual barrier not reached: {label}"
        );
        thread::sleep(Duration::from_millis(10));
    }
}
fn guard(case: Case) -> PathBuf {
    assert_eq!(std::env::var(FLAG).as_deref(), Ok("fresh-owned-state"));
    let args = std::env::args().collect::<Vec<_>>();
    for value in ["--ignored", "--exact", "--test-threads=1", case.selector()] {
        assert!(args.iter().any(|s| s == value));
    }
    assert!(
        std::env::var_os("RAIUN_HEADLESS_CONFIG").is_none()
            && std::env::var_os("RAIUN_STATE_DIR").is_none()
    );
    let root = PathBuf::from(std::env::var_os(DIRECTORY).unwrap());
    assert!(root.is_absolute());
    assert!(
        matches!(root.components().next(), Some(std::path::Component::Prefix(prefix))
        if matches!(prefix.kind(),std::path::Prefix::Disk(_))),
        "Only normal drive-absolute fixture paths, never UNC/device namespaces"
    );
    assert!(
        root.components().count() >= 3
            && !root
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir)),
        "Fixture must be a child directory, not a drive root or traversal"
    );
    for (path, is_dir) in [(root.clone(), true), (root.join("OWNER.txt"), false)] {
        let m = fs::symlink_metadata(path).unwrap();
        assert_eq!(m.is_dir(), is_dir);
        assert_eq!(m.file_attributes() & 0x400, 0);
        if !is_dir {
            assert!(m.is_file() && m.len() == OWNER.len() as u64);
        }
    }
    assert_eq!(fs::read(root.join("OWNER.txt")).unwrap(), OWNER);
    root
}
fn spawn(root: &Path, role: &str, case: Case) -> Child {
    let mut c = Command::new(std::env::current_exe().unwrap());
    c.env_clear();
    for key in [
        "SystemRoot",
        "WINDIR",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "APPDATA",
        "HOMEDRIVE",
        "HOMEPATH",
        "COMSPEC",
        "PATH",
        "PATHEXT",
        "USERNAME",
        "USERDOMAIN",
        "PROCESSOR_ARCHITECTURE",
        "NUMBER_OF_PROCESSORS",
    ] {
        if let Some(value) = std::env::var_os(key) {
            c.env(key, value);
        }
    }
    let log = |suffix: &str| {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join(format!("{role}.{suffix}.log")))
            .unwrap()
    };
    let child = c
        .args([
            "--ignored",
            "--exact",
            case.selector(),
            "--test-threads=1",
            "--nocapture",
        ])
        .env(FLAG, "fresh-owned-state")
        .env(DIRECTORY, root)
        .env(ROLE, role)
        .env("LOCALAPPDATA", root.join("gui-localappdata"))
        .stdin(Stdio::null())
        .stdout(log("stdout"))
        .stderr(log("stderr"))
        .spawn()
        .unwrap();
    report(
        root,
        &format!("{role}.process.json"),
        json!({"pid":child.id(),"forced_stop":false}),
    );
    child
}
fn terminal(mut child: Child) -> bool {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status.success();
        }
        if Instant::now() >= deadline {
            std::mem::forget(child);
            panic!("owned child timeout HOLD; normal shutdown required, no signals/replay");
        }
        thread::sleep(Duration::from_millis(20));
    }
}
fn io_child(root: &Path, name: &str, case: Case) {
    assert!(terminal(spawn(
        root,
        if name == A { "create-a" } else { "create-b" },
        case
    )));
}
fn filesystem(root: &Path, role: &str, case: Case) {
    assert!(
        !case.nested() || role == "create-a",
        "Nested case has one positive file only"
    );
    let name = if role == "create-a" { A } else { B };
    let personal = root.join("cloud-root/Personal");
    fs::read_dir(root.join("cloud-root"))
        .unwrap()
        .collect::<io::Result<Vec<_>>>()
        .unwrap();
    fs::read_dir(&personal)
        .unwrap()
        .collect::<io::Result<Vec<_>>>()
        .unwrap();
    let parent = case.parent(&root.join("cloud-root"));
    if case.nested() {
        // Enumerate the existing server directory through actual Cloud Files;
        // no mkdir/manual placeholder/producer call supplies this parent.
        fs::read_dir(&parent)
            .unwrap()
            .collect::<io::Result<Vec<_>>>()
            .unwrap();
    }
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(parent.join(name))
        .unwrap();
    if name == A {
        generated(&mut f);
    } else {
        f.write_all(&b_body()).unwrap();
    }
    f.sync_all().unwrap();
}
/// Only the fixed positive-path file is queried; no arbitrary path/authority.
pub(super) fn observe_owner(
    connection: &cf::ConfiguredRootConnection,
    backend: &Arc<cf::OpenCloudPlaceholderBackend>,
    binding: &ActiveProviderBinding,
    case: Case,
) -> Result<Value, String> {
    if backend.is_revoked() {
        return Err("Create worker owner retired".into());
    }
    let (parent, o) = if case.nested() {
        let (parent, file) = connection
            .create_worker_subfolder_fixture_observation()
            .map_err(|_| "Create worker nested metadata unavailable")?;
        (Some(parent), file)
    } else {
        (
            None,
            connection
                .rename_public_entry_fixture_observation(cf::RenamePublicEntryFixturePath::Source)
                .map_err(|_| "Create worker native metadata unavailable")?,
        )
    };
    let e = connection
        .observe_namespace_entry(&case.components())
        .map_err(|_| "Create worker entry metadata unavailable")?;
    if backend.is_revoked() {
        return Err("Create worker owner retired during observation".into());
    }
    if o.local_file != e.local_file || o.local_file.volume_serial != binding.identity.volume_serial
    {
        return Err("Create worker native scope mismatch".into());
    }
    let mut value = json!({"file_index":o.local_file.file_index,"volume_serial":o.local_file.volume_serial,"attributes":o.attributes,"tag":o.reparse_tag,"state":o.placeholder_state,"identity":o.opaque_identity,"bytes":e.byte_len,"cloud_file":e.kind==cf::NamespaceEntryKind::CloudFile});
    if let Some(parent) = parent {
        value["parent"] = json!({"file_index":parent.local_file.file_index,"volume_serial":parent.local_file.volume_serial,"attributes":parent.attributes,"tag":parent.reparse_tag,"state":parent.placeholder_state,"identity":parent.opaque_identity});
    }
    Ok(value)
}
fn inspect(agent: &WindowsAgent, binding: &ActiveProviderBinding) {
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    agent
        .provider
        .commands
        .try_send(ProviderCommand::InspectConnection {
            binding: binding.clone(),
            response: tx,
        })
        .unwrap_or_else(|_| panic!("Original owner inspection queue unavailable"));
    assert!(
        rx.recv_timeout(Duration::from_secs(3))
            .expect("actual owner response while SDK held")
            .unwrap()
    );
}
fn observe(agent: &WindowsAgent, binding: &ActiveProviderBinding, case: Case) -> Value {
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    agent
        .provider
        .commands
        .try_send(ProviderCommand::CreateWorkerObservation {
            binding: binding.clone(),
            selected: case,
            response: tx,
        })
        .unwrap_or_else(|_| panic!("Original owner observation queue unavailable"));
    rx.recv_timeout(Duration::from_secs(3)).unwrap().unwrap()
}
fn owner(root_dir: &Path, case: Case) {
    assert_eq!(
        std::env::var_os("LOCALAPPDATA").unwrap(),
        root_dir.join("gui-localappdata")
    );
    assert!(raiun_control_windows::headless_context().unwrap().is_none());
    let origin = fs::read_to_string(root_dir.join("server.txt")).unwrap();
    assert!(
        origin
            .strip_prefix("http://")
            .and_then(|v| v.parse::<std::net::SocketAddr>().ok())
            .is_some_and(|a| a.ip() == std::net::Ipv4Addr::LOCALHOST && a.port() != 0)
    );
    let cloud = root_dir.join("cloud-root");
    fs::create_dir(&cloud).unwrap();
    let client = Arc::new(
        OpenCloudClient::new_with_proxy(
            &origin,
            "synthetic-access-token".into(),
            &raiun_opencloud::ProxyConfig::Direct,
        )
        .unwrap(),
    );
    let server_origin = client.server_origin().unwrap();
    let account = personal_account_identity(&server_origin, SPACE);
    let scope = cf::ProviderScope::new(
        &client,
        "default".into(),
        account.clone(),
        server_origin.clone(),
    )
    .unwrap();
    let lease = cf::pin_configured_root(&cloud).unwrap();
    let physical = lease.identity();
    drop(lease);
    let wrapper = PinnedDirectory::open(root_dir).unwrap();
    let state = Arc::new(
        PrivateDirectory::create_or_open_under(&wrapper, OsStr::new("private-state")).unwrap(),
    );
    let protector =
        cf::DpapiEditRecordProtector::from_existing_private_directory(state.clone()).unwrap();
    let recovery = Arc::new(
        cf::DurableEditRecoveryProvider::new(
            state.path().to_path_buf(),
            scope.clone(),
            physical,
            protector.clone(),
        )
        .with_streamed_recovery(policy())
        .unwrap()
        .with_modern_namespace_file_rename(policy())
        .unwrap(),
    );
    let catalog = recovery.identity_catalog();
    let backend = Arc::new(
        cf::OpenCloudPlaceholderBackend::new_with_identity_catalog(
            client.clone(),
            scope.clone(),
            physical,
            catalog.clone(),
        )
        .unwrap(),
    );
    backend.register_composite_root_for(SPACE, ROOT_ID).unwrap();
    let prepared = recovery.prepare(&scope, physical).unwrap();
    let factory = Arc::new(RetainedFactory {
        scope: scope.clone(),
        root: physical,
        prepared: prepared.clone(),
    });
    assert!(Arc::ptr_eq(
        &factory.prepare(&scope, physical).unwrap(),
        &prepared
    ));
    let sessions = Arc::new(
        PrivateDirectory::create_or_open_under(&wrapper, OsStr::new("private-sessions")).unwrap(),
    );
    let store = DpapiStore {
        store: raiun_control_windows::DpapiSessionStore::from_existing_private_directory(
            sessions.clone(),
        )
        .unwrap(),
        profile_scope: "default".into(),
    };
    let agent = Arc::new(
        WindowsAgent::new_for_profile_with_services(
            "default",
            store,
            None,
            Arc::new(raiun_vault::session::VaultSessionCoordinator::new()),
        )
        .unwrap(),
    );
    agent.attach_existing_file_save_owner().unwrap();
    let generation = 1;
    agent.generation.store(generation, Ordering::Release);
    agent
        .provider
        .authorized_generation
        .store(generation, Ordering::Release);
    agent
        .provider
        .lifecycle_test_activation
        .store(true, Ordering::Release);
    agent
        .provider
        .initial_save_test_activation
        .store(true, Ordering::Release);
    agent
        .provider
        .create_test_activation
        .store(true, Ordering::Release);
    let session = auth::Session {
        app_token_username: None,
        server: server_origin.clone(),
        client_id: "create-worker-synthetic-client".into(),
        access_token: "synthetic-access-token".into(),
        refresh_token: None,
        expires_at: unix_time_now() + 3600,
        token_endpoint: format!("{server_origin}/token"),
        expected_issuer: None,
        last_refresh_at: None,
        proxy: raiun_opencloud::ProxyConfig::Direct,
    };
    let binding = ActiveProviderBinding {
        generation,
        path: cloud.clone(),
        identity: physical,
        personal_space_id: SPACE.into(),
        personal_root_resource_id: ROOT_ID.into(),
    };
    let configuration = RootConfiguration {
        profile_scope: agent.profile_scope.clone(),
        server: session.server.clone(),
        client_id: session.client_id.clone(),
        issuer: None,
        path: cloud.to_string_lossy().into_owned(),
        volume_serial: physical.volume_serial,
        file_index: physical.file_index,
        registration_ownership: Some(RegistrationOwnership {
            state: "registered".into(),
            account_id: account.clone(),
            personal_drive_id: SPACE.into(),
            personal_root_resource_id: Some(ROOT_ID.into()),
            volume_serial: physical.volume_serial,
            file_index: physical.file_index,
        }),
        valid: true,
    };
    {
        let mut s = agent.state.lock().unwrap();
        s.session = Some(session);
        s.root_configuration = Some(configuration);
        s.online_authenticated = true;
        s.active_generation = generation;
    }
    let mut save_owner = agent
        .provider
        .prepare_existing_file_save_worker(&binding, &agent.state, &agent.session_store, false)
        .unwrap()
        .expect("original existing save owner");
    let custody = raiun_engine::folder_pairs::AccountScope::new(
        "default".into(),
        url::Url::parse(&server_origin).unwrap().to_string(),
        "create-worker-synthetic-client".into(),
        None,
        account,
    )
    .unwrap();
    agent
        .provider
        .connect_with_file_rename(
            cloud.clone(),
            generation,
            physical,
            false,
            SPACE.into(),
            ROOT_ID.into(),
            backend.clone(),
            factory.clone(),
            Some(catalog.clone()),
            serde_json::to_vec(&custody).unwrap(),
            agent.session_store.clone(),
        )
        .unwrap();
    agent.check_existing_file_save_account(&binding).unwrap();
    let original = save_owner.original_active.as_ref().unwrap().clone();
    let actual = agent
        .provider
        .fresh_close_source
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .marker(&binding)
        .unwrap();
    assert!(Arc::ptr_eq(&original, &actual) && actual.load(Ordering::Acquire));
    save_owner.committed = true;
    let edit_scope = cf::EditJournalScope {
        profile_id: scope.profile_id().into(),
        server_origin: scope.server_origin().into(),
        account_subject: scope.account_id().into(),
        space_id: SPACE.into(),
        root_resource_id: ROOT_ID.into(),
        root_volume_serial: physical.volume_serial,
        root_file_index: physical.file_index,
    };
    let exercise = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        wait(
            || {
                agent
                    .provider
                    .mixed_namespace_observation()
                    .is_ok_and(|o| o["attached"] == true && o["held"] == false)
            },
            "actual original observer attached",
        );
        io_child(root_dir, A, case);
        wait(
            || root_dir.join("A-HELD.json").is_file(),
            "worker A SDK response held",
        );
        inspect(&agent, &binding);
        assert!(!root_dir.join("A-RESPONSE.json").exists());
        assert!(!root_dir.join("A-HOLD-FAILED.json").exists());
        // Assertion-only reopening after the actual FileCreate publication/PUT.
        // This reader never enters runtime factory, admission, dispatch or ACK.
        let snapshots = cf::streamed_store::SnapshotStore::open_existing(
            state.clone(),
            edit_scope.clone(),
            Arc::new(protector.clone()),
            policy(),
        )
        .unwrap();
        let files =
            cf::streamed_store::namespace_file_store::FileCreateStore::new(snapshots.clone())
                .unwrap();
        report(
            root_dir,
            "A-RELEASE.json",
            json!({"owner_inspection_terminal":true}),
        );
        wait(
            || {
                files.discover().is_ok_and(|records| {
                    records.len() == 1
                        && records[0].progress().recorded_complete
                        && records[0].progress().local_completed
                })
            },
            "actual worker reply/native completion",
        );
        let records = files.discover().unwrap();
        assert_eq!(records.len(), 1);
        let a = &records[0];
        assert_eq!(
            a.progress().remote,
            cf::namespace_intent::NamespacePhase::Verified
        );
        let cf::namespace_intent::NamespaceOperation::CreateFile {
            destination,
            content,
        } = &a.intent().operation
        else {
            panic!("unexpected operation")
        };
        assert_eq!(destination.name, A);
        assert_eq!(destination.parent.scope, edit_scope);
        assert_eq!(content.byte_len, LENGTH);
        let verified = files.open_joined(a.key(), &mut || false).unwrap();
        assert!(verified.manifest().binding().remote.is_none());
        assert_eq!(
            verified.manifest().binding().local_file,
            destination.local_file
        );
        assert_eq!(
            digest(verified.into_reader(Arc::new(|| false)).unwrap()),
            expected(A)
        );
        let streams = snapshots.discover_records().unwrap();
        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0].manifest.binding().record_id, a.snapshot_id());
        assert_eq!(
            streams[0].state,
            cf::streamed_store::StreamedAttemptState::LocallyAcknowledged {
                attempt_id: 0,
                attempts: 0
            }
        );
        assert!(
            !prepared.has_unresolved().unwrap()
                && !prepared
                    .has_unresolved_content_authenticated_legacy()
                    .unwrap()
        );
        let native = observe(&agent, &binding, case);
        assert_eq!(native["file_index"], destination.local_file.file_index);
        assert_eq!(
            native["volume_serial"],
            destination.local_file.volume_serial
        );
        assert_eq!(native["cloud_file"], true);
        assert_eq!(native["bytes"], LENGTH);
        assert_eq!(native["state"].as_u64().unwrap() & 0x39, 9);
        assert_eq!(native["attributes"].as_u64().unwrap() & 0x400, 0x400);
        assert_eq!(native["tag"].as_u64().unwrap() & !0xf000, 0x9000001a);
        let catalog_scope =
            cf::ProviderIdentityCatalogScope::new(&scope, physical, SPACE, ROOT_ID).unwrap();
        let entries = catalog.load(&catalog_scope).unwrap();
        let exact = entries
            .iter()
            .filter_map(|e| match e {
                cf::ProviderIdentityBinding::File {
                    identity,
                    space_id,
                    root_resource_id,
                    path,
                    remote_id,
                    etag,
                    size,
                } if space_id == SPACE
                    && root_resource_id == ROOT_ID
                    && path == &format!("/{}", case.relative(A))
                    && remote_id == "created-a"
                    && etag == "\"created-a-v1\""
                    && *size == LENGTH =>
                {
                    Some(*identity)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(exact.len(), 1);
        assert_eq!(native["identity"], json!(exact[0]));
        assert_eq!(
            digest(fs::File::open(case.parent(&cloud).join(A)).unwrap()),
            expected(A)
        );
        if case.nested() {
            assert_eq!(
                destination.parent.local_components,
                vec!["Personal".to_owned(), FOLDER.to_owned()]
            );
            assert_eq!(destination.parent.remote.resource_id, PARENT_ID);
            assert_eq!(destination.parent.remote.etag, "\"parent-v1\"");
            assert_eq!(
                streams[0].manifest.binding().relative_path,
                case.relative(A)
            );
            assert_eq!(
                native["parent"]["file_index"],
                destination.parent.local_file.file_index
            );
            assert_eq!(
                native["parent"]["volume_serial"],
                destination.parent.local_file.volume_serial
            );
            assert_eq!(
                native["parent"]["attributes"].as_u64().unwrap() & 0x410,
                0x410
            );
            assert_eq!(
                native["parent"]["tag"].as_u64().unwrap() & !0xf000,
                0x9000001a
            );
            let parents = entries
                .iter()
                .filter_map(|entry| match entry {
                    cf::ProviderIdentityBinding::Directory {
                        identity,
                        space_id,
                        root_resource_id,
                        path,
                        remote_id,
                    } if space_id == SPACE
                        && root_resource_id == ROOT_ID
                        && path == &format!("/{FOLDER}")
                        && remote_id == PARENT_ID =>
                    {
                        Some(*identity)
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            assert_eq!(parents.len(), 1);
            assert_eq!(native["parent"]["identity"], json!(parents[0]));
            report(
                root_dir,
                "CASE.json",
                json!({"passed":true,"existing_managed_parent":true,"original_parent_intent_retained":true,"nested_native_catalog_and_linked_ack":true,"one_put":true,"forced_cleanup":false}),
            );
            return;
        }
        io_child(root_dir, B, case);
        wait(
            || root_dir.join("B-HELD.json").is_file(),
            "worker B SDK response held",
        );
        inspect(&agent, &binding);
        assert!(!root_dir.join("B-RESPONSE.json").exists());
        assert!(!root_dir.join("B-HOLD-FAILED.json").exists());
        // This production method cancels the original job and joins actual SDK data;
        // the server must still be holding its response when disconnect returns.
        agent.provider.disconnect().unwrap();
        assert!(!root_dir.join("B-RESPONSE.json").exists());
        assert!(!root_dir.join("B-HOLD-FAILED.json").exists());
        assert!(!agent.provider.is_connected());
        report(
            root_dir,
            "B-STOPPED.json",
            json!({"normal_disconnect_terminal_while_response_held":true}),
        );
        let records = files.discover().unwrap();
        assert_eq!(records.len(), 2);
        let b=records.iter().find(|r|matches!(&r.intent().operation,cf::namespace_intent::NamespaceOperation::CreateFile{destination,..}if destination.name==B)).unwrap();
        assert!(!b.progress().local_completed && !b.progress().recorded_complete);
        let verified = files.open_joined(b.key(), &mut || false).unwrap();
        assert_eq!(
            digest(verified.into_reader(Arc::new(|| false)).unwrap()),
            expected(B)
        );
        let streams = snapshots.discover_records().unwrap();
        let unfinished = streams
            .iter()
            .find(|r| r.manifest.binding().record_id == b.snapshot_id())
            .unwrap();
        assert!(!matches!(
            unfinished.state,
            cf::streamed_store::StreamedAttemptState::LocallyAcknowledged { .. }
        ));
        assert!(prepared.has_unresolved().unwrap());
        assert_eq!(
            digest(fs::File::open(cloud.join("Personal").join(B)).unwrap()),
            expected(B)
        );
        assert_eq!(
            fs::symlink_metadata(cloud.join("Personal").join(B))
                .unwrap()
                .file_attributes()
                & 0x400,
            0
        );
        assert!(cf::pin_registered_configured_root(&cloud, physical).is_ok());
        assert!(state.verify_path().is_ok() && sessions.verify_path().is_ok());
        report(
            root_dir,
            "CASE.json",
            json!({"passed":true,"owner_terminal_while_held":true,"a_completed":true,"a_linked_zero_attempt_ack":true,"b_normal_disconnect_while_held":true,"b_unfinished_body_retained":true,"sequential_one_per_root":true,"forced_cleanup":false}),
        );
    }));
    let disconnected = agent.provider.disconnect().is_ok();
    let close_joined = agent.stop_fresh_close_worker().is_ok();
    let stopped = agent.stop_and_join().is_ok();
    if case.nested() && exercise.is_ok() && disconnected {
        assert_eq!(
            digest(fs::File::open(case.parent(&cloud).join(A)).unwrap()),
            expected(A)
        );
    }
    let registration = cf::pin_registered_configured_root(&cloud, physical).is_ok();
    let private = state.verify_path().is_ok() && sessions.verify_path().is_ok();
    report(
        root_dir,
        "OWNER-RESULTS.json",
        json!({"passed":exercise.is_ok()&&disconnected&&close_joined&&stopped&&registration&&private,"normal_disconnect":disconnected,"save_owner_joined":close_joined,"agent_joined":stopped,"registration_retained":registration,"original_private_state_retained":private,"native_execution_by_controller_required":true}),
    );
    assert!(
        exercise.is_ok() && disconnected && close_joined && stopped && registration && private,
        "fixture failed; original evidence retained"
    );
}
struct Server {
    origin: String,
    stop: Arc<AtomicBool>,
    puts: [Arc<AtomicUsize>; 2],
    gets: [Arc<AtomicUsize>; 2],
    invalid: Arc<AtomicUsize>,
    worker: Option<thread::JoinHandle<()>>,
    case: Case,
}
fn etag(index: usize) -> &'static str {
    if index == 0 {
        "\"created-a-v1\""
    } else {
        "\"created-b-v1\""
    }
}
fn remote_id(index: usize) -> &'static str {
    if index == 0 { "created-a" } else { "created-b" }
}
fn response(socket: &mut TcpStream, status: &str, body: &str, headers: &[(&str, &str)]) -> bool {
    let extra = headers
        .iter()
        .map(|(k, v)| format!("{k}: {v}\r\n"))
        .collect::<String>();
    write!(socket,"HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: application/xml\r\nConnection: close\r\n{extra}\r\n{body}",body.len()).is_ok()
}
fn xml(path: &str, index: Option<usize>, created: [bool; 2], children: bool) -> String {
    let entry = |path: &str, index: Option<usize>| {
        let (length, id, tag) = index.map_or((0, ROOT_ID, "\"root-v1\""), |i| {
            (if i == 0 { LENGTH } else { 4096 }, remote_id(i), etag(i))
        });
        format!(
            r#"<d:response><d:href>{path}</d:href><d:propstat><d:prop><d:resourcetype>{}</d:resourcetype><d:getcontentlength>{length}</d:getcontentlength><d:getetag>{tag}</d:getetag><oc:fileid>{id}</oc:fileid><oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"#,
            if index.is_none() {
                "<d:collection/>"
            } else {
                ""
            }
        )
    };
    let mut all = entry(path, index);
    if children {
        for (i, name) in [A, B].iter().enumerate() {
            if created[i] {
                all.push_str(&entry(&format!("{DAV}{name}"), Some(i)));
            }
        }
    }
    format!(
        "<d:multistatus xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\">{all}</d:multistatus>"
    )
}
fn nested_xml(
    path: &str,
    parent: bool,
    leaf: bool,
    created: bool,
    children: bool,
    parent_path: &str,
    file_path: &str,
) -> String {
    let entry = |path: &str, directory: bool, id: &str, tag: &str, length: u64| {
        let href = path.replace('&', "&amp;");
        format!(
            r#"<d:response><d:href>{href}</d:href><d:propstat><d:prop><d:resourcetype>{}</d:resourcetype><d:getcontentlength>{length}</d:getcontentlength><d:getetag>{tag}</d:getetag><oc:fileid>{id}</oc:fileid><oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"#,
            if directory { "<d:collection/>" } else { "" }
        )
    };
    let parent_tag = if created {
        "\"parent-v2\""
    } else {
        "\"parent-v1\""
    };
    let mut body = if leaf {
        entry(path, false, remote_id(0), etag(0), LENGTH)
    } else if parent {
        entry(path, true, PARENT_ID, parent_tag, 0)
    } else {
        entry(path, true, ROOT_ID, "\"root-v1\"", 0)
    };
    if children && !leaf {
        if !parent {
            body.push_str(&entry(parent_path, true, PARENT_ID, parent_tag, 0));
        } else if created {
            body.push_str(&entry(file_path, false, remote_id(0), etag(0), LENGTH));
        }
    }
    format!(
        "<d:multistatus xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\">{body}</d:multistatus>"
    )
}
impl Server {
    fn start(root: &Path, case: Case) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let origin = format!("http://{address}");
        let stop = Arc::new(AtomicBool::new(false));
        let puts = std::array::from_fn(|_| Arc::new(AtomicUsize::new(0)));
        let gets = std::array::from_fn(|_| Arc::new(AtomicUsize::new(0)));
        let invalid = Arc::new(AtomicUsize::new(0));
        let (st, ps, gs, bad, root) = (
            stop.clone(),
            puts.clone(),
            gets.clone(),
            invalid.clone(),
            root.to_path_buf(),
        );
        let worker = thread::spawn(move || {
            let base = format!("http://{address}{DAV}");
            let parent_url = case.url(&base, None);
            let file_urls = [case.url(&base, Some(A)), case.url(&base, Some(B))];
            let mut created = [false; 2];
            let deadline = Instant::now() + Duration::from_secs(180);
            while !st.load(Ordering::Acquire) && Instant::now() < deadline {
                let mut socket = match listener.accept() {
                    Ok((s, _)) => s,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(_) => {
                        bad.fetch_add(1, Ordering::AcqRel);
                        break;
                    }
                };
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(15)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(15)))
                    .unwrap();
                let mut header = Vec::new();
                let mut byte = [0];
                while !header.ends_with(b"\r\n\r\n") && header.len() < 32768 {
                    if socket.read_exact(&mut byte).is_err() {
                        break;
                    }
                    header.push(byte[0]);
                }
                if !header.ends_with(b"\r\n\r\n") {
                    bad.fetch_add(1, Ordering::AcqRel);
                    continue;
                }
                let text = String::from_utf8(header).unwrap();
                let mut request = text.lines().next().unwrap().split_whitespace();
                let method = request.next().unwrap();
                let path = request.next().unwrap();
                let headers = text
                    .lines()
                    .skip(1)
                    .filter_map(|line| {
                        line.split_once(':')
                            .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_owned()))
                    })
                    .collect::<std::collections::HashMap<_, _>>();
                if headers.get("authorization").map(String::as_str)
                    != Some("Bearer synthetic-access-token")
                {
                    bad.fetch_add(1, Ordering::AcqRel);
                    let _ = response(&mut socket, "403 Forbidden", "", &[]);
                    continue;
                }
                // Drain bounded DAV XML bodies before responding/closing;
                // unread request data can reset the Windows connection.
                if method != "PUT" {
                    assert!(!headers.contains_key("transfer-encoding"));
                    let length = headers
                        .get("content-length")
                        .map_or(0, |v| v.parse::<usize>().unwrap());
                    assert!(length <= 32768, "bounded metadata request body");
                    let mut body = vec![0u8; length];
                    socket.read_exact(&mut body).unwrap();
                }
                let index = file_urls.iter().position(|url| path == url.path());
                let is_parent = case.nested() && path.trim_end_matches('/') == parent_url.path();
                if method == "PUT" {
                    let Some(i) = index else {
                        bad.fetch_add(1, Ordering::AcqRel);
                        continue;
                    };
                    let name = if i == 0 { A } else { B };
                    assert_eq!(
                        ps[i].fetch_add(1, Ordering::AcqRel),
                        0,
                        "one actual PUT per fixed file; no retries"
                    );
                    let length = headers
                        .get("content-length")
                        .unwrap()
                        .parse::<u64>()
                        .unwrap();
                    assert_eq!(length, expected(name).0);
                    assert_eq!(headers.get("if-none-match").map(String::as_str), Some("*"));
                    assert!(!headers.contains_key("if-match"));
                    let condition = headers.get("if").unwrap();
                    assert!(
                        condition.contains(&format!("<http://{address}{DAV}>"))
                            && condition.contains("([\"root-v1\"])")
                    );
                    if case.nested() {
                        assert_eq!(i, 0, "one nested positive only");
                        assert_eq!(
                            condition,
                            &format!("<{base}> ([\"root-v1\"]) <{parent_url}> ([\"parent-v1\"])")
                        );
                        assert!(!condition.contains("%2520") && !condition.contains("%2523"));
                    }
                    let label = if i == 0 { "A" } else { "B" };
                    let mut out = fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(root.join(format!("{label}-upload.body")))
                        .unwrap();
                    let mut remaining = length;
                    let mut hash = Sha256::new();
                    let mut buffer = [0; 65536];
                    while remaining > 0 {
                        let n = remaining.min(buffer.len() as u64) as usize;
                        socket.read_exact(&mut buffer[..n]).unwrap();
                        out.write_all(&buffer[..n]).unwrap();
                        hash.update(&buffer[..n]);
                        remaining -= n as u64;
                    }
                    out.sync_all().unwrap();
                    drop(out);
                    assert_eq!(<[u8; 32]>::from(hash.finalize()), expected(name).1);
                    created[i] = true;
                    report(
                        &root,
                        &format!("{label}-HELD.json"),
                        json!({"whole_body_received":length,"puts":1}),
                    );
                    let release = root.join(if i == 0 {
                        "A-RELEASE.json"
                    } else {
                        "B-STOPPED.json"
                    });
                    let until = Instant::now() + Duration::from_secs(25);
                    while !release.is_file()
                        && !st.load(Ordering::Acquire)
                        && Instant::now() < until
                    {
                        thread::sleep(Duration::from_millis(5));
                    }
                    // A finite safety deadline is a failure, never simulated cancellation proof.
                    if !release.is_file() {
                        report(
                            &root,
                            &format!("{label}-HOLD-FAILED.json"),
                            json!({"held_barrier_failed":true,"response_not_released_by_owner":true}),
                        );
                        bad.fetch_add(1, Ordering::AcqRel);
                        break;
                    }
                    let wrote = response(&mut socket, "201 Created", "", &[("ETag", etag(i))]);
                    report(
                        &root,
                        &format!("{label}-RESPONSE.json"),
                        json!({"response_attempted_after_release":true,"written":wrote}),
                    );
                    if i == 0 && !wrote {
                        bad.fetch_add(1, Ordering::AcqRel);
                    }
                } else if method == "GET" && path == "/graph/v1.0/me/drives" {
                    let body = format!(
                        r#"{{"value":[{{"id":"{SPACE}","name":"Personal","driveType":"personal","root":{{"id":"{ROOT_ID}","webDavUrl":"http://{address}{DAV}"}}}}]}}"#
                    );
                    if !response(&mut socket, "200 OK", &body, &[]) {
                        bad.fetch_add(1, Ordering::AcqRel);
                    }
                } else if method == "PROPFIND"
                    && path.trim_end_matches('/') == DAV.trim_end_matches('/')
                {
                    let children = headers.get("depth").is_some_and(|v| v != "0");
                    if !response(
                        &mut socket,
                        "207 Multi-Status",
                        &if case.nested() {
                            nested_xml(
                                path,
                                false,
                                false,
                                created[0],
                                children,
                                parent_url.path(),
                                file_urls[0].path(),
                            )
                        } else {
                            xml(path, None, created, children)
                        },
                        &[],
                    ) {
                        bad.fetch_add(1, Ordering::AcqRel);
                    }
                } else if method == "PROPFIND" && is_parent {
                    let children = headers.get("depth").is_some_and(|value| value != "0");
                    if !response(
                        &mut socket,
                        "207 Multi-Status",
                        &nested_xml(
                            path,
                            true,
                            false,
                            created[0],
                            children,
                            parent_url.path(),
                            file_urls[0].path(),
                        ),
                        &[],
                    ) {
                        bad.fetch_add(1, Ordering::AcqRel);
                    }
                } else if let ("PROPFIND", Some(i)) = (method, index) {
                    let wrote = if created[i] {
                        response(
                            &mut socket,
                            "207 Multi-Status",
                            &if case.nested() {
                                nested_xml(
                                    path,
                                    false,
                                    true,
                                    created[0],
                                    false,
                                    parent_url.path(),
                                    file_urls[0].path(),
                                )
                            } else {
                                xml(path, Some(i), created, false)
                            },
                            &[],
                        )
                    } else {
                        response(&mut socket, "404 Not Found", "", &[])
                    };
                    if !wrote {
                        bad.fetch_add(1, Ordering::AcqRel);
                    }
                } else if method == "GET" && index.is_some_and(|i| created[i]) {
                    let i = index.unwrap();
                    assert_eq!(headers.get("if-match").map(String::as_str), Some(etag(i)));
                    assert!(!headers.contains_key("range"));
                    gs[i].fetch_add(1, Ordering::AcqRel);
                    let label = if i == 0 { "A" } else { "B" };
                    let length = expected(if i == 0 { A } else { B }).0;
                    let wrote=write!(socket,"HTTP/1.1 200 OK\r\nContent-Length: {length}\r\nETag: {}\r\nConnection: close\r\n\r\n",etag(i)).is_ok()&&io::copy(&mut fs::File::open(root.join(format!("{label}-upload.body"))).unwrap(),&mut socket).is_ok_and(|n|n==length);
                    if !wrote {
                        bad.fetch_add(1, Ordering::AcqRel);
                    }
                } else {
                    bad.fetch_add(1, Ordering::AcqRel);
                    let _ = response(&mut socket, "405 Method Not Allowed", "", &[]);
                }
            }
        });
        Self {
            origin,
            stop,
            puts,
            gets,
            invalid,
            worker: Some(worker),
            case,
        }
    }
    fn finish(mut self) -> bool {
        self.stop.store(true, Ordering::Release);
        let joined = self.worker.take().unwrap().join().is_ok();
        joined
            && self.invalid.load(Ordering::Acquire) == 0
            && self.puts[0].load(Ordering::Acquire) == 1
            && self.puts[1].load(Ordering::Acquire) == if self.case.nested() { 0 } else { 1 }
            && self.gets[0].load(Ordering::Acquire) == 1
            && self.gets[1].load(Ordering::Acquire) == 0
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
#[test]
#[ignore = "actual native observer/owner/two SDK workers; fresh isolated ordinary Windows user +explicit controller admission required"]
fn owner_workers_complete_then_cancel_held_create() {
    run(Case::RootHeldStop);
}
#[test]
#[ignore = "actual existing managed Personal subfolder/create/native/custody; fresh ordinary Windows user and controller admission required"]
fn owner_workers_existing_personal_subfolder_completes() {
    run(Case::ExistingSubfolder);
}
fn run(case: Case) {
    let root = guard(case);
    if let Some(role) = std::env::var_os(ROLE) {
        match role.to_str().unwrap() {
            "owner" => owner(&root, case),
            "create-a" | "create-b" => filesystem(&root, role.to_str().unwrap(), case),
            _ => panic!("unknown fixed native child role"),
        };
        return;
    }
    assert!(fs::read_dir(&root).unwrap().all(|e| matches!(
        e.unwrap().file_name().to_str(),
        Some("OWNER.txt" | "runner.json" | "stdout.log" | "stderr.log")
    )));
    report(
        &root,
        "STARTED.json",
        json!({"selector":case.selector(),"passed":false,"runtime_admission_by_controller_required":true}),
    );
    fs::create_dir(root.join("gui-localappdata")).unwrap();
    let server = Server::start(&root, case);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join("server.txt"))
        .unwrap();
    f.write_all(server.origin.as_bytes()).unwrap();
    f.sync_all().unwrap();
    drop(f);
    let exercise = terminal(spawn(&root, "owner", case));
    let protocol = server.finish();
    let owner_report: Value =
        serde_json::from_slice(&fs::read(root.join("OWNER-RESULTS.json")).unwrap()).unwrap();
    let passed = exercise && protocol && owner_report["passed"] == true;
    report(
        &root,
        "RESULTS.json",
        json!({"passed":passed,"outer_owner_terminal_zero":exercise,"protocol_valid":protocol,"owner":owner_report,"actual_observer_dispatch_worker_path":true,"sequential_one_active_create_per_root":true,"same_root_bulk_parallel_claim":false,"forced_stop":false,"installer_or_package_acceptance":false}),
    );
    assert!(
        passed,
        "native fixture failed; evidence retained; no replay"
    );
}
