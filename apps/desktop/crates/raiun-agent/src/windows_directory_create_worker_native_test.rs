//! Source-only ignored ordinary-directory owner/worker qualification candidate.
//! Runtime admission and exact-artifact native execution remain controller-owned.
use super::windows_file_create_public_entry_test::{RetainedFactory, policy};
use super::*;
use cf::EditRecoveryProvider;
use raiun_cloudfiles_windows as cf;
use raiun_control_windows::{PinnedDirectory, PrivateDirectory};
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
const SELECTOR: &str = "agent_windows::windows_directory_create_worker_native_test::owner_workers_complete_then_stop_held_directory";
const FLAG: &str = "RAIUN_DIRECTORY_WORKER_NATIVE";
const DIRECTORY: &str = "RAIUN_DIRECTORY_WORKER_FIXTURE_DIR";
const ROLE: &str = "RAIUN_DIRECTORY_WORKER_CHILD_ROLE";
const OWNER: &[u8] = b"raiun-directory-worker-native-owned-v1\n";
const SPACE: &str = "personal-drive";
const ROOT_ID: &str = "personal-drive!root";
const DAV: &str = "/dav/spaces/personal-drive/";
const A: &str = "directory-a";
const B: &str = "directory-b";
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
fn guard() -> PathBuf {
    assert_eq!(std::env::consts::ARCH, "x86_64");
    assert_eq!(std::mem::size_of::<usize>(), 8);
    assert_eq!(std::env::var(FLAG).as_deref(), Ok("fresh-owned-state"));
    let args = std::env::args().collect::<Vec<_>>();
    for value in ["--ignored", "--exact", "--test-threads=1", SELECTOR] {
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
fn spawn(root: &Path, role: &str) -> Child {
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
            SELECTOR,
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
fn filesystem(root: &Path, role: &str) {
    let name = match role {
        "mkdir-a" => A,
        "mkdir-b" => B,
        _ => panic!("unknown mkdir role"),
    };
    let personal = root.join("cloud-root/Personal");
    for path in [root.join("cloud-root"), personal.clone()] {
        fs::read_dir(path)
            .unwrap()
            .collect::<io::Result<Vec<_>>>()
            .unwrap();
    }
    fs::create_dir(personal.join(name)).unwrap();
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
fn owner(root_dir: &Path) {
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
        .directory_phase_test_activation
        .store(true, Ordering::Release);
    let session = auth::Session {
        app_token_username: None,
        server: server_origin.clone(),
        client_id: "directory-worker-synthetic-client".into(),
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
    let custody = raiun_engine::folder_pairs::AccountScope::new(
        "default".into(),
        url::Url::parse(&server_origin).unwrap().to_string(),
        "directory-worker-synthetic-client".into(),
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
    let edit_scope = cf::EditJournalScope {
        profile_id: scope.profile_id().into(),
        server_origin: scope.server_origin().into(),
        account_subject: scope.account_id().into(),
        space_id: SPACE.into(),
        root_resource_id: ROOT_ID.into(),
        root_volume_serial: physical.volume_serial,
        root_file_index: physical.file_index,
    };
    let authorization = cf::namespace_intent::CapturedAuthorization {
        agent_generation: generation,
        token_generation: scope.token_generation(),
    };
    assert!(
        !agent
            .provider
            .create_test_activation
            .load(Ordering::Acquire)
    );
    assert!(
        !agent
            .provider
            .namespace_test_activation
            .load(Ordering::Acquire)
    );
    assert!(
        !agent
            .provider
            .mixed_namespace_test_activation
            .load(Ordering::Acquire)
    );
    report(
        root_dir,
        "CONTEXT.json",
        json!({
            "original_prepared_factory_pointer_equal": Arc::ptr_eq(&factory.prepare(&scope, physical).unwrap(), &prepared),
            "root_volume_serial":physical.volume_serial,"root_file_index":physical.file_index,
            "agent_generation":generation,"token_generation":scope.token_generation(),
            "directory_only_instance_opt_in":true,"loopback_only":true,
            "task_id_and_deadline_observation_exposed":false,
            "source_route_original_metadata_job_seconds":30,
            "sdk_pool_source_worker_count":2
        }),
    );
    let exercise = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        wait(
            || {
                agent
                    .provider
                    .mixed_namespace_observation()
                    .is_ok_and(|o| o["attached"] == true && o["held"] == false)
            },
            "original observer attached",
        );
        assert!(terminal(spawn(root_dir, "mkdir-a")));
        wait(
            || root_dir.join("A-HELD.json").is_file(),
            "original SDK MKCOL A held",
        );
        inspect(&agent, &binding);
        assert!(!root_dir.join("A-RESPONSE.json").exists());
        assert!(!root_dir.join("A-HOLD-FAILED.json").exists());
        let before_a = observe(&agent, A);
        assert_eq!(before_a.attributes & 0x410, 0x10);
        assert_eq!(before_a.reparse_tag, 0);
        assert!(before_a.opaque_identity.is_none());
        // Assertion-only reader from the ORIGINAL prepared context. It never
        // replaces runtime admission/store/policy, dispatches history or replays.
        let directories = prepared
            .directory_intent_store(&edit_scope, authorization)
            .unwrap()
            .unwrap();
        let records = directories.discover().unwrap();
        assert_eq!(records.len(), 1);
        let initial_a = &records[0];
        check_record(
            initial_a,
            A,
            &edit_scope,
            authorization,
            before_a.local_file,
        );
        assert_eq!(
            initial_a.progress.remote,
            cf::namespace_intent::NamespacePhase::Submitted
        );
        assert!(!initial_a.progress.local_completed && !initial_a.progress.recorded_complete);
        let parent = observe_components(&agent, vec!["Personal".into()]);
        let cf::namespace_intent::NamespaceOperation::CreateDirectory { destination } =
            &initial_a.intent.operation
        else {
            panic!("directory intent required")
        };
        assert_eq!(destination.parent.local_file, parent.local_file);
        report(
            root_dir,
            "A-OBSERVED.json",
            json!({"record_id":initial_a.intent.record_id,"generation":initial_a.intent.record_generation,"original_file_index":before_a.local_file.file_index,"original_volume_serial":before_a.local_file.volume_serial,"owner_inspection_terminal_while_sdk_held":true,"submitted_not_completed":true}),
        );
        report(
            root_dir,
            "A-RELEASE.json",
            json!({"after_owner_inspection":true}),
        );
        wait(
            || {
                directories.discover().is_ok_and(|records| {
                    records.len() == 1
                        && records[0].progress.local_completed
                        && records[0].progress.recorded_complete
                })
            },
            "A journal/native LocalCompleted",
        );
        let records = directories.discover().unwrap();
        let a = &records[0];
        assert!(a.intent == initial_a.intent);
        assert_eq!(
            a.progress.remote,
            cf::namespace_intent::NamespacePhase::Verified
        );
        assert!(a.progress.attention.is_none());
        let native_a = observe(&agent, A);
        assert_eq!(native_a.local_file, before_a.local_file);
        assert_eq!(native_a.attributes & 0x410, 0x410);
        assert_eq!(native_a.reparse_tag & !0xf000, 0x9000001a);
        // Directory policy keeps InSync absent: enabling on-demand population
        // does not qualify the directory tree's content as synchronized.
        assert_eq!(native_a.placeholder_state & 1, 1);
        assert_eq!(native_a.placeholder_state & 8, 0);
        let catalog_scope =
            cf::ProviderIdentityCatalogScope::new(&scope, physical, SPACE, ROOT_ID).unwrap();
        let entries = catalog.load(&catalog_scope).unwrap();
        let identities = entries
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
                    && path == &format!("/{A}")
                    && remote_id == "created-directory-a" =>
                {
                    Some(*identity)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(identities.len(), 1);
        assert_eq!(native_a.opaque_identity, Some(identities[0]));
        assert!(!prepared.has_unresolved().unwrap());
        report(
            root_dir,
            "A-COMPLETED.json",
            json!({"original_intent_and_physical_id_retained":true,"verified_remote_id":"created-directory-a","native_cloud_directory":true,"raw_placeholder_state":native_a.placeholder_state,"directory_in_sync":false,"journal_local_completed":true,"one_mkcol":true}),
        );

        assert!(terminal(spawn(root_dir, "mkdir-b")));
        wait(
            || root_dir.join("B-HELD.json").is_file(),
            "original SDK MKCOL B held",
        );
        inspect(&agent, &binding);
        let before_b = observe(&agent, B);
        assert_eq!(before_b.attributes & 0x410, 0x10);
        assert_eq!(before_b.reparse_tag, 0);
        let records = directories.discover().unwrap();
        assert_eq!(records.len(), 2);
        let initial_b = records.iter().find(|r| directory_name(r) == B).unwrap();
        check_record(
            initial_b,
            B,
            &edit_scope,
            authorization,
            before_b.local_file,
        );
        assert_eq!(
            initial_b.progress.remote,
            cf::namespace_intent::NamespacePhase::Submitted
        );
        assert!(!initial_b.progress.local_completed && !initial_b.progress.recorded_complete);
        assert!(!root_dir.join("B-RESPONSE.json").exists());
        let terminal = Arc::new(AtomicBool::new(false));
        let observed_terminal = terminal.clone();
        let release_root = root_dir.to_path_buf();
        let release = thread::spawn(move || {
            // Bounded release allows normal synchronous HTTP completion. This
            // is not proof that cancellation aborted the socket instantly.
            thread::sleep(Duration::from_millis(100));
            let before_release = observed_terminal.load(Ordering::Acquire);
            report(
                &release_root,
                "B-RELEASE.json",
                json!({"bounded_response_release_for_normal_disconnect":true,"terminal_before_release":before_release,"sync_http_may_require_response":true}),
            );
            before_release
        });
        let stopped = agent.provider.disconnect();
        terminal.store(true, Ordering::Release);
        let terminal_while_held = release.join().expect("join bounded response releaser");
        stopped.unwrap();
        assert!(!agent.provider.is_connected());
        let records = directories.discover().unwrap();
        assert_eq!(records.len(), 2);
        let b = records.iter().find(|r| directory_name(r) == B).unwrap();
        assert!(b.intent == initial_b.intent);
        assert_eq!(
            b.progress.remote,
            cf::namespace_intent::NamespacePhase::Submitted
        );
        assert_eq!(
            b.progress.attention,
            Some(cf::namespace_intent::NamespaceAttention::Uncertain)
        );
        assert!(!b.progress.local_completed && !b.progress.recorded_complete);
        // Stop discards late SDK result data; no fabricated journal event is required.
        assert!(prepared.has_unresolved().unwrap());
        let path = cloud.join("Personal").join(B);
        let physical_b = PinnedDirectory::open(&path).unwrap().identity();
        assert_eq!(physical_b.volume_serial, before_b.local_file.volume_serial);
        assert_eq!(physical_b.file_index, before_b.local_file.file_index);
        let metadata = fs::symlink_metadata(&path).unwrap();
        assert_eq!(metadata.file_attributes() & 0x410, 0x10);
        assert_eq!(fs::read_dir(&path).unwrap().count(), 0);
        assert!(cf::pin_registered_configured_root(&cloud, physical).is_ok());
        assert!(state.verify_path().is_ok() && sessions.verify_path().is_ok());
        let entries = catalog.load(&catalog_scope).unwrap();
        assert!(!entries.iter().any(|entry|matches!(entry,cf::ProviderIdentityBinding::Directory{path,..} if path==&format!("/{B}"))));
        report(
            root_dir,
            "B-STOPPED.json",
            json!({"normal_disconnect_joined":true,"terminal_while_response_held":terminal_while_held,"original_intent_record_id":b.intent.record_id,"original_intent_generation":b.intent.record_generation,"remote_phase":"Submitted","remote_outcome":"uncertain","local_completed":false,"recorded_complete":false,"original_file_index":before_b.local_file.file_index,"registration_retained":true,"forced_stop":false}),
        );
    }));
    // On assertion failure release synthetic response barriers before normal
    // cleanup, preserving failed evidence. Never kill, unregister, delete or retry.
    for label in ["A", "B"] {
        if root_dir.join(format!("{label}-HELD.json")).is_file()
            && !root_dir.join(format!("{label}-RELEASE.json")).exists()
        {
            report(
                root_dir,
                &format!("{label}-RELEASE.json"),
                json!({"failure_cleanup_release":true}),
            );
        }
    }
    let disconnected = agent.provider.disconnect().is_ok();
    let stopped = agent.stop_and_join().is_ok();
    let registration = cf::pin_registered_configured_root(&cloud, physical).is_ok();
    let private = state.verify_path().is_ok() && sessions.verify_path().is_ok();
    report(
        root_dir,
        "OWNER-RESULTS.json",
        json!({"passed":exercise.is_ok()&&disconnected&&stopped&&registration&&private,"normal_disconnect":disconnected,"agent_joined":stopped,"registration_retained":registration,"original_private_state_retained":private,"no_unregistration_or_deletion":true}),
    );
    assert!(
        exercise.is_ok() && disconnected && stopped && registration && private,
        "fixture failed; retain exact state/evidence; no replay"
    );
}
fn observe_components(
    agent: &WindowsAgent,
    components: Vec<String>,
) -> cf::NamespaceDirectoryObservation {
    agent
        .provider
        .namespace_directory_observation(components)
        .unwrap()
}
fn observe(agent: &WindowsAgent, name: &str) -> cf::NamespaceDirectoryObservation {
    assert!(matches!(name, A | B));
    observe_components(agent, vec!["Personal".into(), name.into()])
}
fn directory_name(record: &cf::streamed_store::namespace_store::StoredDirectoryIntent) -> &str {
    match &record.intent.operation {
        cf::namespace_intent::NamespaceOperation::CreateDirectory { destination } => {
            &destination.name
        }
        _ => panic!("only directory intents are admitted"),
    }
}
fn check_record(
    record: &cf::streamed_store::namespace_store::StoredDirectoryIntent,
    name: &str,
    scope: &cf::EditJournalScope,
    authorization: cf::namespace_intent::CapturedAuthorization,
    local: cf::LocalFileIdentity,
) {
    assert!(!record.intent.record_id.is_empty() && record.intent.record_generation != 0);
    let cf::namespace_intent::NamespaceOperation::CreateDirectory { destination } =
        &record.intent.operation
    else {
        panic!("only directory intent")
    };
    assert_eq!(destination.name, name);
    assert_eq!(
        destination.object_kind,
        cf::namespace_intent::NamespaceObjectKind::Directory
    );
    assert_eq!(&destination.parent.scope, scope);
    assert_eq!(destination.parent.authorization, authorization);
    assert_eq!(
        destination.parent.classification,
        cf::namespace_intent::StorageClassification::Ordinary
    );
    assert_eq!(
        destination.parent.local_components,
        vec!["Personal".to_owned()]
    );
    assert_eq!(destination.parent.remote.resource_id, ROOT_ID);
    assert_eq!(destination.parent.remote.byte_len, 0);
    assert_eq!(destination.local_file, local);
}
struct Server {
    origin: String,
    stop: Arc<AtomicBool>,
    mkcols: [Arc<AtomicUsize>; 2],
    invalid: Arc<AtomicUsize>,
    worker: Option<thread::JoinHandle<()>>,
}
fn response(socket: &mut TcpStream, status: &str, body: &str) -> bool {
    write!(socket,"HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: application/xml\r\nConnection: close\r\n\r\n{body}",body.len()).is_ok()
}
fn xml(path: &str, index: Option<usize>, created: [bool; 2], children: bool) -> String {
    let entry = |path: &str, index: Option<usize>| {
        let (id, tag) = match index {
            Some(0) => ("created-directory-a", "\"directory-a-v1\""),
            Some(1) => ("created-directory-b", "\"directory-b-v1\""),
            _ => (ROOT_ID, "\"root-v1\""),
        };
        format!(
            r#"<d:response><d:href>{path}</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getcontentlength>0</d:getcontentlength><d:getetag>{tag}</d:getetag><oc:fileid>{id}</oc:fileid><oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"#
        )
    };
    let mut body = entry(path, index);
    if children && index.is_none() {
        for (i, name) in [A, B].iter().enumerate() {
            if created[i] {
                body.push_str(&entry(&format!("{DAV}{name}"), Some(i)));
            }
        }
    }
    format!(
        "<d:multistatus xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\">{body}</d:multistatus>"
    )
}
impl Server {
    fn start(root: &Path) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let origin = format!("http://{address}");
        let stop = Arc::new(AtomicBool::new(false));
        let mkcols = std::array::from_fn(|_| Arc::new(AtomicUsize::new(0)));
        let invalid = Arc::new(AtomicUsize::new(0));
        let (st, counts, bad, root) = (
            stop.clone(),
            mkcols.clone(),
            invalid.clone(),
            root.to_path_buf(),
        );
        let worker = thread::spawn(move || {
            let mut created = [false; 2];
            let deadline = Instant::now() + Duration::from_secs(180);
            while !st.load(Ordering::Acquire) && Instant::now() < deadline {
                let mut socket = match listener.accept() {
                    Ok((socket, _)) => socket,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
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
                let mut first = text.lines().next().unwrap().split_whitespace();
                let method = first.next().unwrap();
                let path = first.next().unwrap();
                let headers = text
                    .lines()
                    .skip(1)
                    .filter_map(|line| {
                        line.split_once(':')
                            .map(|(key, value)| (key.to_ascii_lowercase(), value.trim().to_owned()))
                    })
                    .collect::<std::collections::HashMap<_, _>>();
                if headers.get("authorization").map(String::as_str)
                    != Some("Bearer synthetic-access-token")
                {
                    bad.fetch_add(1, Ordering::AcqRel);
                    let _ = response(&mut socket, "403 Forbidden", "");
                    continue;
                }
                assert!(!headers.contains_key("transfer-encoding"));
                let length = headers
                    .get("content-length")
                    .map_or(0, |value| value.parse::<usize>().unwrap());
                assert!(length <= 32768);
                let mut body = vec![0; length];
                socket.read_exact(&mut body).unwrap();
                let index = [A, B]
                    .iter()
                    .position(|name| path.trim_end_matches('/') == format!("{DAV}{name}"));
                if method == "MKCOL" {
                    let Some(i) = index else {
                        bad.fetch_add(1, Ordering::AcqRel);
                        continue;
                    };
                    assert_eq!(
                        counts[i].fetch_add(1, Ordering::AcqRel),
                        0,
                        "exactly one MKCOL per fixed directory; no retry"
                    );
                    assert_eq!(length, 0);
                    // Ordinary SDK sends bare MKCOL after metadata checks.
                    // Do not invent atomic create or parent-CAS semantics.
                    assert!(!headers.contains_key("if-none-match"));
                    assert!(!headers.contains_key("if-match"));
                    assert!(!headers.contains_key("if"));
                    created[i] = true;
                    let label = if i == 0 { "A" } else { "B" };
                    report(
                        &root,
                        &format!("{label}-HELD.json"),
                        json!({"method":"MKCOL","requests":1,"synthetic_server_created":true,"response_released":false}),
                    );
                    let release = root.join(format!("{label}-RELEASE.json"));
                    let until = Instant::now() + Duration::from_secs(25);
                    while !release.is_file()
                        && !st.load(Ordering::Acquire)
                        && Instant::now() < until
                    {
                        thread::sleep(Duration::from_millis(5));
                    }
                    if !release.is_file() {
                        report(
                            &root,
                            &format!("{label}-HOLD-FAILED.json"),
                            json!({"held_barrier_failed":true}),
                        );
                        bad.fetch_add(1, Ordering::AcqRel);
                        break;
                    }
                    let wrote = response(&mut socket, "201 Created", "");
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
                    if !response(&mut socket, "200 OK", &body) {
                        bad.fetch_add(1, Ordering::AcqRel);
                    }
                } else if method == "PROPFIND"
                    && path.trim_end_matches('/') == DAV.trim_end_matches('/')
                {
                    let children = headers.get("depth").is_some_and(|value| value != "0");
                    if !response(
                        &mut socket,
                        "207 Multi-Status",
                        &xml(path, None, created, children),
                    ) {
                        bad.fetch_add(1, Ordering::AcqRel);
                    }
                } else if let ("PROPFIND", Some(i)) = (method, index) {
                    let wrote = if created[i] {
                        response(
                            &mut socket,
                            "207 Multi-Status",
                            &xml(path, Some(i), created, false),
                        )
                    } else {
                        response(&mut socket, "404 Not Found", "")
                    };
                    if !wrote {
                        bad.fetch_add(1, Ordering::AcqRel);
                    }
                } else {
                    bad.fetch_add(1, Ordering::AcqRel);
                    let _ = response(&mut socket, "405 Method Not Allowed", "");
                }
            }
        });
        Self {
            origin,
            stop,
            mkcols,
            invalid,
            worker: Some(worker),
        }
    }
    fn finish(mut self) -> bool {
        self.stop.store(true, Ordering::Release);
        let joined = self.worker.take().unwrap().join().is_ok();
        joined
            && self.invalid.load(Ordering::Acquire) == 0
            && self
                .mkcols
                .iter()
                .all(|count| count.load(Ordering::Acquire) == 1)
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
#[ignore = "actual directory observer/owner/two SDK workers; source-only candidate; exact artifact + fresh standard-user NTFS/Defender/current-context controller admission required"]
fn owner_workers_complete_then_stop_held_directory() {
    let root = guard();
    if let Some(role) = std::env::var_os(ROLE) {
        match role.to_str().unwrap() {
            "owner" => owner(&root),
            "mkdir-a" | "mkdir-b" => filesystem(&root, role.to_str().unwrap()),
            _ => panic!("unknown fixed native child role"),
        };
        return;
    }
    assert!(fs::read_dir(&root).unwrap().all(|entry| matches!(
        entry.unwrap().file_name().to_str(),
        Some("OWNER.txt" | "runner.json" | "stdout.log" | "stderr.log")
    )));
    report(
        &root,
        "STARTED.json",
        json!({"selector":SELECTOR,"passed":false,"external_exact_artifact_role_ntfs_defender_current_context_admission_required":true,"not_authorized_by_source_preparation":true}),
    );
    fs::create_dir(root.join("gui-localappdata")).unwrap();
    let server = Server::start(&root);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join("server.txt"))
        .unwrap();
    file.write_all(server.origin.as_bytes()).unwrap();
    file.sync_all().unwrap();
    drop(file);
    let exercise = terminal(spawn(&root, "owner"));
    let protocol = server.finish();
    let owner: Value =
        serde_json::from_slice(&fs::read(root.join("OWNER-RESULTS.json")).unwrap()).unwrap();
    let passed = exercise && protocol && owner["passed"] == true;
    report(
        &root,
        "RESULTS.json",
        json!({"passed":passed,"outer_owner_terminal_zero":exercise,"protocol_valid":protocol,"owner":owner,"actual_directory_observer_dispatch_shared_worker_path":true,"one_active_candidate_per_original_root":true,"no_nonempty_tree_or_broad_matrix_qualification":true,"forced_stop":false,"installer_or_package_acceptance":false}),
    );
    assert!(
        passed,
        "native candidate failed; preserve all state/evidence; no retry"
    );
}
