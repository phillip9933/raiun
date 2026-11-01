//! Two ignored actual connected-create cases. No production activation.
use super::*;
use cf::{EditRecoveryProvider, PreparedEditRecovery};
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
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
const SPACE: &str = "personal-drive";
const ROOT_ID: &str = "personal-drive!root";
const NAME: &str = "source.bin";
const FILE_ID: &str = "created-file";
const ETAG: &str = "\"created-v1\"";
const DAV: &str = "/dav/spaces/personal-drive/";
const LENGTH: u64 = 17 * 1024 * 1024 + 7;
const OWNER: &[u8] = b"raiun-connected-create-native-owned-v1\n";
const OPT_IN: &str = "RAIUN_CONNECTED_CREATE_NATIVE";
const FIXTURE: &str = "RAIUN_CONNECTED_CREATE_FIXTURE_DIR";
const ROLE: &str = "RAIUN_CONNECTED_CREATE_CHILD_ROLE";
const PREFIX: &str = "agent_windows::windows_file_create_public_entry_test::";
fn selector(held: bool) -> String {
    format!(
        "{PREFIX}{}",
        if held {
            "connected_create_held_network_foreground_break_retains_unfinished"
        } else {
            "connected_create_personal_17mib_completes_linked_custody"
        }
    )
}
fn wait_fact(mut fact: impl FnMut() -> bool, label: &str) {
    let deadline = Instant::now() + Duration::from_secs(12);
    while !fact() {
        assert!(
            Instant::now() < deadline,
            "bounded factual barrier: {label}"
        );
        thread::sleep(Duration::from_millis(5));
    }
}
fn report(root: &Path, name: &str, value: serde_json::Value) {
    let mut out = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join(name))
        .unwrap();
    out.write_all(&serde_json::to_vec_pretty(&value).unwrap())
        .unwrap();
    out.sync_all().unwrap();
}
fn guarded(held: bool) -> PathBuf {
    assert_eq!(std::env::var(OPT_IN).as_deref(), Ok("fresh-owned-state"));
    let args = std::env::args().collect::<Vec<_>>();
    let exact = selector(held);
    for required in ["--ignored", "--exact", "--test-threads=1", exact.as_str()] {
        assert!(args.iter().any(|a| a == required));
    }
    let root = PathBuf::from(std::env::var_os(FIXTURE).unwrap());
    assert!(root.is_absolute());
    let metadata = fs::symlink_metadata(&root).unwrap();
    assert!(metadata.is_dir() && metadata.file_attributes() & 0x400 == 0);
    let marker = root.join("OWNER.txt");
    let metadata = fs::symlink_metadata(&marker).unwrap();
    assert!(
        metadata.is_file()
            && metadata.file_attributes() & 0x400 == 0
            && metadata.len() == OWNER.len() as u64
    );
    assert_eq!(fs::read(marker).unwrap(), OWNER);
    assert!(
        std::env::var_os("RAIUN_HEADLESS_CONFIG").is_none()
            && std::env::var_os("RAIUN_STATE_DIR").is_none()
    );
    root
}
fn generated(out: &mut impl Write) -> [u8; 32] {
    generated_variant(out, false)
}
fn generated_variant(out: &mut impl Write, modified: bool) -> [u8; 32] {
    let mut position = 0;
    let mut buffer = [0u8; 65536];
    let mut hash = Sha256::new();
    while position < LENGTH {
        let n = (LENGTH - position).min(buffer.len() as u64) as usize;
        for (i, b) in buffer[..n].iter_mut().enumerate() {
            *b = if modified && position + i as u64 == 0 {
                0xff
            } else {
                ((position + i as u64) % 251) as u8
            };
        }
        out.write_all(&buffer[..n]).unwrap();
        hash.update(&buffer[..n]);
        position += n as u64;
    }
    hash.finalize().into()
}
fn digest(mut input: impl Read) -> (u64, [u8; 32]) {
    let mut buffer = [0u8; 65536];
    let mut total = 0;
    let mut hash = Sha256::new();
    loop {
        let n = input.read(&mut buffer).unwrap();
        if n == 0 {
            break;
        }
        total += n as u64;
        hash.update(&buffer[..n]);
    }
    (total, hash.finalize().into())
}
fn child(root: &Path) -> bool {
    let Some(role) = std::env::var_os(ROLE) else {
        return false;
    };
    let personal = root.join("cloud-root/Personal");
    match role.to_str().unwrap() {
        "generate" => {
            fs::read_dir(root.join("cloud-root"))
                .unwrap()
                .collect::<io::Result<Vec<_>>>()
                .unwrap();
            fs::read_dir(&personal)
                .unwrap()
                .collect::<io::Result<Vec<_>>>()
                .unwrap();
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(personal.join(NAME))
                .unwrap();
            generated(&mut f);
            f.sync_all().unwrap();
        }
        "writer" => {
            wait_fact(
                || root.join("PUT-HELD.json").is_file(),
                "real PUT body accepted",
            );
            let started = Instant::now();
            let mut f = fs::OpenOptions::new()
                .write(true)
                .open(personal.join(NAME))
                .unwrap();
            f.write_all(&[0xff]).unwrap();
            f.sync_all().unwrap();
            drop(f);
            report(
                root,
                "FOREGROUND.json",
                serde_json::json!({"completed":true,"elapsed_ms":started.elapsed().as_millis()}),
            );
        }
        _ => panic!("unknown explicit fixture child role"),
    }
    true
}
fn spawn_child(root: &Path, held: bool, role: &str) -> std::process::Child {
    let output = |kind| {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join(format!("{role}.{kind}.log")))
            .unwrap()
    };
    Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            &selector(held),
            "--test-threads=1",
            "--nocapture",
        ])
        .env(ROLE, role)
        .stdin(Stdio::null())
        .stdout(Stdio::from(output("stdout")))
        .stderr(Stdio::from(output("stderr")))
        .spawn()
        .unwrap()
}
fn join_child(child: &mut std::process::Child) {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut overdue = false;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(
                status.success() && !overdue,
                "child failed/overdue; retained without signals"
            );
            return;
        }
        overdue |= Instant::now() >= deadline;
        thread::sleep(Duration::from_millis(10));
    }
}

struct RetainedFactory {
    scope: cf::ProviderScope,
    root: cf::ConfiguredRootIdentity,
    prepared: Arc<dyn PreparedEditRecovery>,
}
impl EditRecoveryProvider for RetainedFactory {
    fn prepare(
        &self,
        scope: &cf::ProviderScope,
        root: cf::ConfiguredRootIdentity,
    ) -> Result<Arc<dyn PreparedEditRecovery>, cf::BackendError> {
        if *scope != self.scope || root != self.root {
            return Err(cf::BackendError::Unavailable);
        }
        Ok(Arc::clone(&self.prepared))
    }
}
fn policy() -> cf::streamed_store::StorePolicy {
    cf::streamed_store::StorePolicy {
        max_content_bytes: 32 * 1024 * 1024,
        max_state_bytes: 512 * 1024 * 1024,
        max_entries: 4096,
        max_metadata_bytes_per_scan: 8 * 1024 * 1024,
    }
}

fn run(held: bool) {
    let fixture = guarded(held);
    if child(&fixture) {
        return;
    }
    assert!(fs::read_dir(&fixture).unwrap().all(|e| matches!(
        e.unwrap().file_name().to_str(),
        Some("OWNER.txt" | "runner.json" | "stdout.log" | "stderr.log")
    )));
    let cloud_root = fixture.join("cloud-root");
    fs::create_dir(&cloud_root).unwrap();
    report(
        &fixture,
        "STARTED.json",
        serde_json::json!({"selector":selector(held),"native_case_completed":false,"length":LENGTH}),
    );
    let server = Loopback::start(&fixture, held);
    let client = Arc::new(
        OpenCloudClient::new_with_proxy(
            &server.origin,
            "synthetic-access-token".into(),
            &raiun_opencloud::ProxyConfig::Direct,
        )
        .unwrap(),
    );
    let origin = client.server_origin().unwrap();
    let account = personal_account_identity(&origin, SPACE);
    let provider_scope =
        cf::ProviderScope::new(&client, "default".into(), account.clone(), origin.clone()).unwrap();
    let lease = cf::pin_configured_root(&cloud_root).unwrap();
    let root = lease.identity();
    let wrapper = PinnedDirectory::open(&fixture).unwrap();
    let state = Arc::new(
        PrivateDirectory::create_or_open_under(&wrapper, OsStr::new("private-state")).unwrap(),
    );
    let protector =
        cf::DpapiEditRecordProtector::from_existing_private_directory(Arc::clone(&state)).unwrap();
    let recovery = Arc::new(
        cf::DurableEditRecoveryProvider::new(
            state.path().to_path_buf(),
            provider_scope.clone(),
            root,
            protector.clone(),
        )
        .with_streamed_recovery(policy())
        .unwrap()
        .with_modern_namespace_file_rename(policy())
        .unwrap(),
    );
    let backend = Arc::new(
        cf::OpenCloudPlaceholderBackend::new_with_identity_catalog(
            Arc::clone(&client),
            provider_scope.clone(),
            root,
            recovery.identity_catalog(),
        )
        .unwrap(),
    );
    let composite = backend.register_composite_root_for(SPACE, ROOT_ID).unwrap();
    let prepared = recovery.prepare(&provider_scope, root).unwrap();
    let factory = Arc::new(RetainedFactory {
        scope: provider_scope.clone(),
        root,
        prepared: Arc::clone(&prepared),
    });
    // The real custody guard requires canonical account metadata and a
    // profile-bound protected store. Keep both inside this fresh wrapper;
    // never consult the current user's saved sessions or repair old history.
    let sessions = Arc::new(
        PrivateDirectory::create_or_open_under(&wrapper, OsStr::new("private-sessions")).unwrap(),
    );
    let session_store = DpapiStore {
        store: raiun_control_windows::DpapiSessionStore::from_existing_private_directory(sessions)
            .unwrap(),
        profile_scope: "default".into(),
    };
    let agent = Arc::new(
        WindowsAgent::new_for_profile_with_services(
            "default",
            session_store,
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
    let session = auth::Session {
        app_token_username: None,
        server: origin.clone(),
        client_id: "create-synthetic-client".into(),
        access_token: "synthetic-access-token".into(),
        refresh_token: None,
        expires_at: unix_time_now() + 3600,
        token_endpoint: format!("{origin}/token"),
        expected_issuer: None,
        last_refresh_at: None,
        proxy: raiun_opencloud::ProxyConfig::Direct,
    };
    let binding = ActiveProviderBinding {
        generation,
        path: cloud_root.clone(),
        identity: root,
        personal_space_id: SPACE.into(),
        personal_root_resource_id: ROOT_ID.into(),
    };
    let configuration = RootConfiguration {
        profile_scope: agent.profile_scope.clone(),
        server: session.server.clone(),
        client_id: session.client_id.clone(),
        issuer: None,
        path: cloud_root.to_string_lossy().into_owned(),
        volume_serial: root.volume_serial,
        file_index: root.file_index,
        registration_ownership: Some(RegistrationOwnership {
            state: "registered".into(),
            account_id: account.clone(),
            personal_drive_id: SPACE.into(),
            personal_root_resource_id: Some(ROOT_ID.into()),
            volume_serial: root.volume_serial,
            file_index: root.file_index,
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
        .expect("actual existing save owner");
    let publisher = agent
        .provider
        .fresh_close_source
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .publisher(generation)
        .unwrap();
    let custody_account = raiun_engine::folder_pairs::AccountScope::new(
        "default".into(),
        url::Url::parse(&origin).unwrap().to_string(),
        "create-synthetic-client".into(),
        None,
        account.clone(),
    )
    .unwrap();
    let custody_account = serde_json::to_vec(&custody_account).unwrap();
    let custody = windows_vault_custody::WindowsVaultCustody::prepare_with_fresh_close_publisher(
        Arc::clone(&agent.session_store),
        &custody_account,
        &cf::prepare_vault_custody_root(&lease, backend.as_ref(), composite).unwrap(),
        Some(publisher),
    )
    .unwrap();
    let runtime = cf::prepare_configured_root_runtime(
        lease,
        Arc::clone(&backend),
        composite,
        factory.clone(),
    )
    .unwrap();
    let runtime = cf::attach_vault_published_history(runtime, custody).unwrap();
    let mut connection = cf::connect_configured_root(runtime).unwrap();
    agent.check_existing_file_save_account(&binding).unwrap();
    let original = save_owner.original_active.as_ref().unwrap();
    let actual = agent
        .provider
        .fresh_close_source
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .marker(&binding)
        .unwrap();
    assert!(Arc::ptr_eq(original, &actual) && actual.load(Ordering::Acquire));
    save_owner.committed = true;
    let personal = cloud_root.join("Personal");

    let mut generator = spawn_child(&fixture, held, "generate");
    join_child(&mut generator);
    wait_fact(
        || connection.rename_public_entry_fixture_callback_counts() == Some((0, 0, 0)),
        "initial callbacks settled",
    );
    let before = connection
        .observe_namespace_entry(&["Personal", NAME])
        .unwrap();
    assert_eq!(before.kind, cf::NamespaceEntryKind::PlainFile);
    assert_eq!(before.byte_len, LENGTH);
    assert_ne!(before.local_file.file_index, 0);
    let expected = generated(&mut io::sink());
    assert_eq!(
        digest(fs::File::open(personal.join(NAME)).unwrap()),
        (LENGTH, expected)
    );
    let authorization = cf::namespace_intent::CapturedAuthorization {
        agent_generation: generation,
        token_generation: client.token_generation(),
    };
    let scope = cf::EditJournalScope {
        profile_id: provider_scope.profile_id().into(),
        server_origin: provider_scope.server_origin().into(),
        account_subject: provider_scope.account_id().into(),
        space_id: SPACE.into(),
        root_resource_id: ROOT_ID.into(),
        root_volume_serial: root.volume_serial,
        root_file_index: root.file_index,
    };
    let mut writer = held.then(|| spawn_child(&fixture, held, "writer"));
    let owner = agent.clone();
    let active = actual.clone();
    let original_client = client.clone();
    let current = Arc::new(move |a: cf::namespace_intent::CapturedAuthorization| {
        a == authorization
            && owner.generation.load(Ordering::Acquire) == generation
            && active.load(Ordering::Acquire)
            && original_client.token_generation() == a.token_generation
    });
    let job = cf::CancellationToken::for_recovery_job(
        cf::StreamedRecoveryPolicy::new(Duration::from_secs(120)).unwrap(),
    );
    let original_deadline = job.deadline();
    let started = Instant::now();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let outcome = connection
            .reconcile_fresh_personal_file_create(
                &backend,
                NAME,
                authorization,
                generation,
                &job,
                current,
            )
            .unwrap();
        if let Some(child) = writer.as_mut() {
            join_child(child);
        }
        assert_eq!(job.deadline(), original_deadline);
        assert_eq!(
            server.puts.load(Ordering::Acquire),
            1,
            "one actual PUT only"
        );
        assert_eq!(
            digest(fs::File::open(fixture.join("remote-upload.body")).unwrap()),
            (LENGTH, expected)
        );
        assert_eq!(server.received.load(Ordering::Acquire), LENGTH as usize);
        let snapshots = cf::streamed_store::SnapshotStore::open_existing(
            state.clone(),
            scope.clone(),
            Arc::new(protector.clone()),
            policy(),
        )
        .unwrap();
        let files =
            cf::streamed_store::namespace_file_store::FileCreateStore::new(snapshots.clone())
                .unwrap();
        let joined = files.discover().unwrap();
        assert_eq!(joined.len(), 1);
        let record = &joined[0];
        assert_eq!(record.intent().record_generation, generation);
        let verified = files.open_joined(record.key(), &mut || false).unwrap();
        assert!(verified.manifest().binding().remote.is_none());
        assert_eq!(verified.manifest().binding().local_file, before.local_file);
        assert_eq!(
            digest(verified.into_reader(Arc::new(|| false)).unwrap()),
            (LENGTH, expected)
        );
        let stream = snapshots.discover_records().unwrap();
        assert_eq!(stream.len(), 1);
        assert_eq!(stream[0].manifest.binding().record_id, record.snapshot_id());
        let after = connection
            .observe_namespace_entry(&["Personal", NAME])
            .unwrap();
        assert_eq!(after.local_file, before.local_file);
        if held {
            assert!(matches!(
                outcome,
                cf::FreshFileCreateOutcome::SubmittedUncertain
                    | cf::FreshFileCreateOutcome::RemoteVerifiedLocalIncomplete
            ));
            assert!(!record.progress().recorded_complete && !record.progress().local_completed);
            assert!(!matches!(
                stream[0].state,
                cf::streamed_store::StreamedAttemptState::LocallyAcknowledged { .. }
            ));
            assert!(prepared.has_unresolved().unwrap());
            assert_eq!(after.kind, cf::NamespaceEntryKind::PlainFile);
            assert_eq!(
                digest(fs::File::open(personal.join(NAME)).unwrap()),
                (LENGTH, generated_variant(&mut io::sink(), true)),
                "entire modified working copy remains exact, not merely its first byte"
            );
            assert!(
                server.foreground_before_release.load(Ordering::Acquire),
                "actual writer completed before response release"
            );
        } else {
            assert_eq!(outcome, cf::FreshFileCreateOutcome::LocallyCompleted);
            assert_eq!(after.kind, cf::NamespaceEntryKind::CloudFile);
            let observation = connection
                .rename_public_entry_fixture_observation(cf::RenamePublicEntryFixturePath::Source)
                .unwrap();
            assert_eq!(observation.local_file, before.local_file);
            assert_eq!(observation.placeholder_state & 0x39, 9);
            assert_eq!(observation.attributes & 0x400, 0x400);
            assert_eq!(observation.reparse_tag & !0xf000, 0x9000001a);
            let catalog_scope =
                cf::ProviderIdentityCatalogScope::new(&provider_scope, root, SPACE, ROOT_ID)
                    .unwrap();
            let bindings = recovery.identity_catalog().load(&catalog_scope).unwrap();
            let exact = bindings
                .iter()
                .filter_map(|binding| match binding {
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
                        && path == &format!("/{NAME}")
                        && remote_id == FILE_ID
                        && etag == ETAG
                        && *size == LENGTH =>
                    {
                        Some(*identity)
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            assert_eq!(exact.len(), 1);
            assert_eq!(observation.opaque_identity, Some(exact[0]));
            assert!(record.progress().recorded_complete && record.progress().local_completed);
            assert_eq!(
                record.progress().remote,
                cf::namespace_intent::NamespacePhase::Verified
            );
            assert_eq!(
                stream[0].state,
                cf::streamed_store::StreamedAttemptState::LocallyAcknowledged {
                    attempt_id: 0,
                    attempts: 0
                }
            );
            assert!(!prepared.has_unresolved().unwrap());
            assert!(
                !prepared
                    .has_unresolved_content_authenticated_legacy()
                    .unwrap()
            );
            assert_eq!(server.gets.load(Ordering::Acquire), 1);
            assert_eq!(
                digest(fs::File::open(personal.join(NAME)).unwrap()),
                (LENGTH, expected)
            );
        }
        assert_eq!(server.rejected.load(Ordering::Acquire), 0);
        report(
            &fixture,
            "CASE.json",
            serde_json::json!({"passed":true,"outcome":format!("{outcome:?}"),"elapsed_ms":started.elapsed().as_millis(),
            "length":LENGTH,"sha256":expected.iter().map(|b|format!("{b:02x}")).collect::<String>(),"file_id":before.local_file.file_index,
            "puts":server.puts.load(Ordering::Acquire),"gets":server.gets.load(Ordering::Acquire),"file_completed":record.progress().recorded_complete,
            "foreground_before_response_release":server.foreground_before_release.load(Ordering::Acquire)}),
        );
    }));
    // Normal shutdown even after an assertion failure; never signal, delete or retry.
    let disconnected = connection.disconnect_in_place().is_ok();
    let close_joined = agent.stop_fresh_close_worker().is_ok();
    let joined = agent.stop_and_join().is_ok();
    if let Some(child) = writer.as_mut() {
        join_child(child);
    }
    let protocol = server.finish();
    let registration_retained = cf::pin_registered_configured_root(&cloud_root, root).is_ok();
    let private_state_retained = state.verify_path().is_ok();
    report(
        &fixture,
        "RESULTS.json",
        serde_json::json!({"selector":selector(held),"passed":result.is_ok()&&disconnected&&close_joined&&joined&&protocol&&registration_retained&&private_state_retained,
        "exercise_passed":result.is_ok(),"normal_disconnect":disconnected,"fresh_close_worker_joined":close_joined,"agent_joined":joined,
        "server_joined":protocol,"forced_cleanup":false,"registration_retained":registration_retained,"private_state_retained":private_state_retained}),
    );
    assert!(
        result.is_ok()
            && disconnected
            && close_joined
            && joined
            && protocol
            && registration_retained
            && private_state_retained,
        "fixture failed; original evidence retained"
    );
}

struct Loopback {
    origin: String,
    stop: Arc<AtomicBool>,
    puts: Arc<AtomicUsize>,
    gets: Arc<AtomicUsize>,
    received: Arc<AtomicUsize>,
    rejected: Arc<AtomicUsize>,
    foreground_before_release: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Loopback {
    fn start(root: &Path, held: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let origin = format!("http://{address}");
        let root = root.to_owned();
        let stop = Arc::new(AtomicBool::new(false));
        let puts = Arc::new(AtomicUsize::new(0));
        let gets = Arc::new(AtomicUsize::new(0));
        let received = Arc::new(AtomicUsize::new(0));
        let rejected = Arc::new(AtomicUsize::new(0));
        let foreground_before_release = Arc::new(AtomicBool::new(false));
        let (st, ps, gs, rc, rj, fg) = (
            stop.clone(),
            puts.clone(),
            gets.clone(),
            received.clone(),
            rejected.clone(),
            foreground_before_release.clone(),
        );
        let worker = thread::spawn(move || {
            let mut created = false;
            let mut records = Vec::new();
            let deadline = Instant::now() + Duration::from_secs(180);
            while !st.load(Ordering::Acquire) && Instant::now() < deadline {
                let mut socket = match listener.accept() {
                    Ok((socket, _)) => socket,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => panic!("fixture accept {:?}", e.kind()),
                };
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(15)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(15)))
                    .unwrap();
                let mut bytes = Vec::new();
                let mut byte = [0];
                while !bytes.ends_with(b"\r\n\r\n") && bytes.len() < 32768 {
                    if socket.read_exact(&mut byte).is_err() {
                        break;
                    }
                    bytes.push(byte[0]);
                }
                if !bytes.ends_with(b"\r\n\r\n") {
                    rj.fetch_add(1, Ordering::AcqRel);
                    continue;
                }
                let text = String::from_utf8(bytes).unwrap();
                let mut line = text.lines().next().unwrap().split_whitespace();
                let method = line.next().unwrap();
                let path = line.next().unwrap();
                let headers = text
                    .lines()
                    .skip(1)
                    .filter_map(|line| {
                        line.split_once(':')
                            .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_owned()))
                    })
                    .collect::<std::collections::HashMap<_, _>>();
                let length = headers
                    .get("content-length")
                    .map_or(0, |s| s.parse::<usize>().unwrap());
                assert!(length <= LENGTH as usize);
                let target = format!("{DAV}{NAME}");
                let is_put = method == "PUT" && path == target;
                let mut body = if is_put {
                    ps.fetch_add(1, Ordering::AcqRel);
                    Some(
                        fs::OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .open(root.join("remote-upload.body"))
                            .unwrap(),
                    )
                } else {
                    None
                };
                let mut remaining = length;
                let mut buffer = [0; 65536];
                let mut hash = Sha256::new();
                while remaining > 0 {
                    let n = remaining.min(buffer.len());
                    socket.read_exact(&mut buffer[..n]).unwrap();
                    hash.update(&buffer[..n]);
                    if let Some(out) = body.as_mut() {
                        out.write_all(&buffer[..n]).unwrap();
                    }
                    remaining -= n;
                }
                if let Some(out) = body.as_mut() {
                    out.sync_all().unwrap();
                    rc.store(length, Ordering::Release);
                }
                drop(body);
                let status;
                let wrote;
                if method == "GET" && path == "/graph/v1.0/me/drives" {
                    status = 200;
                    let body = format!(
                        r#"{{"value":[{{"id":"{SPACE}","name":"Personal","driveType":"personal","root":{{"id":"{ROOT_ID}","webDavUrl":"http://{address}{DAV}"}}}}]}}"#
                    );
                    wrote = response(&mut socket, "200 OK", &body, &[]);
                } else if method == "PROPFIND"
                    && path.trim_end_matches('/') == DAV.trim_end_matches('/')
                {
                    status = 207;
                    let child = created && headers.get("depth").is_some_and(|v| v != "0");
                    let body = xml(path, true, child);
                    wrote = response(&mut socket, "207 Multi-Status", &body, &[]);
                } else if method == "PROPFIND" && path == target {
                    if created {
                        status = 207;
                        wrote = response(
                            &mut socket,
                            "207 Multi-Status",
                            &xml(path, false, false),
                            &[],
                        );
                    } else {
                        status = 404;
                        wrote = response(&mut socket, "404 Not Found", "", &[]);
                    }
                } else if is_put {
                    assert_eq!(ps.load(Ordering::Acquire), 1);
                    assert_eq!(length, LENGTH as usize);
                    assert_eq!(headers.get("if-none-match").map(String::as_str), Some("*"));
                    assert!(!headers.contains_key("if-match"));
                    let condition = headers.get("if").unwrap();
                    assert!(
                        condition.contains(&format!("<http://{address}{DAV}>"))
                            && condition.contains("([\"root-v1\"])")
                    );
                    assert_eq!(
                        <[u8; 32]>::from(hash.finalize()),
                        generated(&mut io::sink())
                    );
                    created = true;
                    if held {
                        report(
                            &root,
                            "PUT-HELD.json",
                            serde_json::json!({"body_received":length,"puts":ps.load(Ordering::Acquire)}),
                        );
                        let until = Instant::now() + Duration::from_secs(12);
                        while !root.join("FOREGROUND.json").is_file() && Instant::now() < until {
                            thread::sleep(Duration::from_millis(5));
                        }
                        fg.store(root.join("FOREGROUND.json").is_file(), Ordering::Release);
                    }
                    status = 201;
                    wrote = response(&mut socket, "201 Created", "", &[("ETag", ETAG)]);
                } else if method == "GET" && path == target && created {
                    assert_eq!(headers.get("if-match").map(String::as_str), Some(ETAG));
                    assert!(!headers.contains_key("range"));
                    gs.fetch_add(1, Ordering::AcqRel);
                    status = 200;
                    let header = write!(
                        socket,
                        "HTTP/1.1 200 OK\r\nContent-Length: {LENGTH}\r\nETag: {ETAG}\r\nConnection: close\r\n\r\n"
                    );
                    wrote = header.is_ok()
                        && io::copy(
                            &mut fs::File::open(root.join("remote-upload.body")).unwrap(),
                            &mut socket,
                        )
                        .is_ok_and(|n| n == LENGTH);
                } else {
                    rj.fetch_add(1, Ordering::AcqRel);
                    status = 405;
                    wrote = response(&mut socket, "405 Method Not Allowed", "", &[]);
                }
                assert!(records.len() < 512);
                records.push(serde_json::json!({"method":method,"path":path,"status_attempted":status,"response_write_succeeded":wrote}));
            }
            report(
                &root,
                "PROTOCOL.json",
                serde_json::json!({"requests":records,"puts":ps.load(Ordering::Acquire),"gets":gs.load(Ordering::Acquire),"received":rc.load(Ordering::Acquire),"rejected":rj.load(Ordering::Acquire),"foreground_before_release":fg.load(Ordering::Acquire)}),
            );
        });
        Self {
            origin,
            stop,
            puts,
            gets,
            received,
            rejected,
            foreground_before_release,
            worker: Some(worker),
        }
    }
    fn finish(mut self) -> bool {
        self.stop.store(true, Ordering::Release);
        self.worker.take().unwrap().join().is_ok()
    }
}
impl Drop for Loopback {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
fn response(socket: &mut TcpStream, status: &str, body: &str, headers: &[(&str, &str)]) -> bool {
    let extra = headers
        .iter()
        .map(|(k, v)| format!("{k}: {v}\r\n"))
        .collect::<String>();
    write!(socket,"HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: application/xml\r\nConnection: close\r\n{extra}\r\n{body}",body.len()).is_ok()
}
fn xml(path: &str, directory: bool, child: bool) -> String {
    let entry = |path: &str, directory: bool| {
        format!(
            r#"<d:response><d:href>{path}</d:href><d:propstat><d:prop><d:resourcetype>{}</d:resourcetype><d:getcontentlength>{}</d:getcontentlength><d:getetag>{}</d:getetag><oc:fileid>{}</oc:fileid><oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"#,
            if directory { "<d:collection/>" } else { "" },
            if directory { 0 } else { LENGTH },
            if directory { "\"root-v1\"" } else { ETAG },
            if directory { ROOT_ID } else { FILE_ID }
        )
    };
    format!(
        "<d:multistatus xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\">{}{}</d:multistatus>",
        entry(path, directory),
        if child {
            entry(&format!("{DAV}{NAME}"), false)
        } else {
            String::new()
        }
    )
}
#[test]
#[ignore = "actual connected create/conversion/CAS; fresh isolated ordinary-user Windows VM contract required"]
fn connected_create_personal_17mib_completes_linked_custody() {
    run(false)
}
#[test]
#[ignore = "actual network-held create/foreground writer break; fresh isolated ordinary-user Windows VM contract required"]
fn connected_create_held_network_foreground_break_retains_unfinished() {
    run(true)
}
