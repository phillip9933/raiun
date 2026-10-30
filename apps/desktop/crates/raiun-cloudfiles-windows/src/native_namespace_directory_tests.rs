use super::*;
use crate::namespace_intent::CapturedAuthorization;
use crate::namespace_reconcile::{DirectoryCreateOutcome, reconcile_directory_create};
use crate::namespace_store::DirectoryIntentStore;
use crate::streamed_store::StorePolicy;
use crate::synthetic_agent_integration;
use std::os::windows::fs::MetadataExt;
use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
const TEST: &str = "tests::native_namespace_directory_tests::explicit_directory_producer_pipeline_and_connection_restart";
const OPT_IN: &str = "RAIUN_RUN_NATIVE_DIRECTORY_FIXTURE";
const SELECTOR: &str = "RAIUN_NATIVE_DIRECTORY_FIXTURE_CASE";
const CASES: [&str; 5] = [
    "personal-success",
    "space-success",
    "personal-forbidden",
    "personal-collision",
    "personal-readback-loss",
];
fn select_cases(value: Option<&str>) -> Result<Vec<&'static str>, ()> {
    match value {
        None => Ok(CASES.to_vec()),
        Some(value) => CASES
            .iter()
            .copied()
            .find(|case| *case == value)
            .map(|case| vec![case])
            .ok_or(()),
    }
}
const CHILD: &str = "RAIUN_NATIVE_DIRECTORY_FIXTURE_CHILD";
const DIRECTORY: &str = "RAIUN_NATIVE_DIRECTORY_FIXTURE_DIR";
const OWNER: &[u8] = b"raiun-native-directory-owned-v1\n";
const CONTENT: &[u8] = b"preserved child of converted directory\0\x01\xff";
const NAME: &str = "new-directory";
fn report(path: &Path, value: serde_json::Value) {
    std::fs::write(path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
}
fn policy() -> StorePolicy {
    StorePolicy {
        max_content_bytes: 32 * 1024 * 1024,
        max_state_bytes: 512 * 1024 * 1024,
        max_entries: 4096,
        max_metadata_bytes_per_scan: 16 * 1024 * 1024,
    }
}

#[test]
#[ignore = "actual configured-root explicit producer only; no automatic observer integration; CONNECTION restart, not separate-process DPAPI"]
fn explicit_directory_producer_pipeline_and_connection_restart() {
    assert!(matches!(
        std::env::var(OPT_IN).as_deref(),
        Ok("fresh-owned-state")
    ));
    let args = std::env::args().collect::<Vec<_>>();
    assert!(
        args.iter().any(|a| a == "--ignored")
            && args.windows(2).any(|a| a[0] == "--exact" && a[1] == TEST)
    );
    let requested = match std::env::var(SELECTOR) {
        Ok(value) => select_cases(Some(&value)),
        Err(std::env::VarError::NotPresent) => select_cases(None),
        Err(_) => Err(()),
    }
    .expect("unknown or empty directory fixture selector");
    if std::env::var(CHILD).as_deref() != Ok("1") {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "raiun-native-directory-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(directory.join("OWNER.txt"), OWNER).unwrap();
        let log = |name| {
            std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(directory.join(name))
                .unwrap()
        };
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                TEST,
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, "1")
            .env(DIRECTORY, &directory)
            .env("RAIUN_HEADLESS_CONTEXT", "1")
            .env("RAIUN_STATE_DIR", directory.join("state"))
            .env_remove("RAIUN_HEADLESS_CONFIG")
            .stdout(log("child.stdout.log"))
            .stderr(log("child.stderr.log"))
            .spawn()
            .unwrap();
        let mut failed_wait = false;
        let status = loop {
            match child.wait() {
                Ok(status) => break status,
                Err(_) => {
                    failed_wait = true;
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
        };
        assert!(
            status.success() && !failed_wait,
            "directory child failed; fixture retained"
        );
        return;
    }
    let directory = PathBuf::from(std::env::var_os(DIRECTORY).unwrap());
    assert!(directory.is_absolute());
    let marker = directory.join("OWNER.txt");
    let metadata = std::fs::symlink_metadata(&marker).unwrap();
    assert!(
        metadata.is_file()
            && metadata.file_attributes() & 0x400 == 0
            && metadata.len() == OWNER.len() as u64
    );
    assert!(std::fs::read(marker).unwrap() == OWNER);
    let context = raiun_control_windows::headless_context()
        .unwrap()
        .expect("fresh child state required");
    assert!(
        std::fs::canonicalize(context.state_root()).unwrap()
            == std::fs::canonicalize(directory.join("state")).unwrap(),
        "headless fixture state must be exact owned child"
    );
    // No current_user/default-state accessor is permitted above this guard.
    let mut cases = Vec::new();
    report(
        &directory.join("RESULTS.json"),
        serde_json::json!({"fixture":"native-directory-explicit-v2","requested_cases":requested,"requested_case_count":requested.len(),"complete_case_count":0,"scope":if requested.len()==5{"full_matrix"}else{"single_case"},"cases":[],"passed":false}),
    );
    for case in requested.iter().copied() {
        let (space, mode) = match case {
            "space-success" => (true, 0),
            "personal-forbidden" => (false, 1),
            "personal-collision" => (false, 2),
            "personal-readback-loss" => (false, 3),
            _ => (false, 0),
        };
        let case_dir = directory.join(case);
        std::fs::create_dir(&case_dir).unwrap();
        let result = run_case(&case_dir, space, mode);
        cases.push(serde_json::json!({"case":case,"passed":result}));
        report(
            &directory.join("RESULTS.json"),
            serde_json::json!({"fixture":"native-directory-explicit-v2","requested_cases":requested,"requested_case_count":requested.len(),"complete_case_count":cases.len(),"scope":if requested.len()==5{"full_matrix"}else{"single_case"},"cases":cases,
            "passed":cases.len()==requested.len()&&cases.iter().all(|c|c["passed"]==true),"explicit_producer":true,"automatic_observer_integration":false,
            "connection_restart_same_process":true,"separate_process_dpapi":false,"forced_cleanup":false,"evidence_retained_without_forced_cleanup":true}),
        );
        assert!(
            result,
            "directory fixture incomplete; all evidence retained"
        );
    }
}

struct Server {
    origin: String,
    stop: Arc<AtomicBool>,
    sent: Arc<AtomicU64>,
    collision: Arc<AtomicBool>,
    graph_reads: Arc<AtomicU64>,
    personal_root_reads: Arc<AtomicU64>,
    project_root_reads: Arc<AtomicU64>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl Server {
    fn new(mode: u64) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let sent = Arc::new(AtomicU64::new(0));
        let collision = Arc::new(AtomicBool::new(false));
        let graph_reads = Arc::new(AtomicU64::new(0));
        let personal_root_reads = Arc::new(AtomicU64::new(0));
        let project_root_reads = Arc::new(AtomicU64::new(0));
        let (g, p, j) = (
            graph_reads.clone(),
            personal_root_reads.clone(),
            project_root_reads.clone(),
        );
        let (st, n, c) = (stop.clone(), sent.clone(), collision.clone());
        let worker = std::thread::spawn(move || {
            let mut child_reads = 0;
            while !st.load(Ordering::Acquire) {
                let (mut stream, _) = match listener.accept() {
                    Ok(v) => v,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(_) => panic!("synthetic directory accept failed"),
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let request = read_http_request(&mut stream);
                let path = request.split_whitespace().nth(1).unwrap_or_default();
                let mut status = "207 Multi-Status";
                let root = if path.starts_with("/dav/projects/") {
                    "project-root"
                } else {
                    "personal-root"
                };
                let body = if request.starts_with("GET /graph/") {
                    g.fetch_add(1, Ordering::AcqRel);
                    status = "200 OK";
                    format!(
                        r#"{{"value":[{{"id":"personal-drive","name":"Personal","driveType":"personal","root":{{"id":"personal-root","webDavUrl":"http://{addr}/dav/personal/"}}}},{{"id":"projects-drive","name":"Projects","driveType":"project","root":{{"id":"project-root","webDavUrl":"http://{addr}/dav/projects/"}}}}]}}"#
                    )
                } else if request.starts_with("MKCOL ") {
                    assert!(path.ends_with(NAME));
                    n.fetch_add(1, Ordering::AcqRel);
                    status = if mode == 1 {
                        "403 Forbidden"
                    } else {
                        "201 Created"
                    };
                    String::new()
                } else if request.starts_with("PROPFIND ") {
                    if path.trim_end_matches('/').ends_with(NAME) {
                        if c.load(Ordering::Acquire) {
                            xml(path, "collision-other", "\"other-v1\"")
                        } else if n.load(Ordering::Acquire) == 0 {
                            status = "404 Not Found";
                            String::new()
                        } else {
                            child_reads += 1;
                            if mode == 3 && child_reads > 2 {
                                status = "404 Not Found";
                                String::new()
                            } else {
                                xml(path, "created-directory", "\"directory-v1\"")
                            }
                        }
                    } else {
                        assert!(
                            matches!(path, "/dav/personal/" | "/dav/projects/"),
                            "unexpected synthetic directory route"
                        );
                        if path == "/dav/projects/" {
                            j.fetch_add(1, Ordering::AcqRel);
                        } else {
                            p.fetch_add(1, Ordering::AcqRel);
                        }
                        xml(path, root, "\"root-v1\"")
                    }
                } else {
                    panic!("unexpected synthetic directory method")
                };
                write!(stream,"HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: application/xml\r\n\r\n{body}",body.len()).unwrap();
            }
        });
        Self {
            origin: format!("http://{addr}"),
            stop,
            sent,
            collision,
            graph_reads,
            personal_root_reads,
            project_root_reads,
            worker: Some(worker),
        }
    }
    fn finish(mut self) {
        self.stop.store(true, Ordering::Release);
        self.worker.take().unwrap().join().unwrap();
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
    }
}
fn xml(path: &str, id: &str, etag: &str) -> String {
    format!(
        "<d:multistatus xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\"><d:response><d:href>{path}</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getetag>{etag}</d:getetag><oc:fileid>{id}</oc:fileid><oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"
    )
}
fn disconnect(conn: &mut synthetic_agent_integration::Connection, path: &Path) -> bool {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut overdue = false;
    loop {
        if conn.disconnect_in_place().is_ok() {
            return !overdue;
        }
        if Instant::now() >= deadline && !overdue {
            overdue = true;
            report(
                &path.join("disconnect-pending.json"),
                serde_json::json!({"passed":false,"owner_retained":true,"forced_stop":false}),
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
fn strict_listing(path: &Path, expected: Option<&str>) -> std::io::Result<()> {
    let entries = std::fs::read_dir(path)?.collect::<std::io::Result<Vec<_>>>()?;
    if expected.is_some_and(|name| !entries.iter().any(|entry| entry.file_name() == name)) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "expected synthetic navigation component absent",
        ));
    }
    Ok(())
}
fn setup_snapshot(
    connection: &synthetic_agent_integration::Connection,
    server: &Server,
    components: &[&str],
) -> serde_json::Value {
    let placeholder = if components.is_empty() {
        None
    } else {
        connection
            .namespace_directory_fixture_observation(components)
            .ok()
    };
    serde_json::json!({"callbacks":connection.namespace_directory_setup_diagnostics(),"placeholder_observed":placeholder.is_some(),"placeholder_state":placeholder.map(|p|p.placeholder_state),"attributes":placeholder.map(|p|p.attributes),"reparse_tag":placeholder.map(|p|p.reparse_tag),"mkcol_count":server.sent.load(Ordering::Acquire),"graph_reads":server.graph_reads.load(Ordering::Acquire),"personal_root_reads":server.personal_root_reads.load(Ordering::Acquire),"project_root_reads":server.project_root_reads.load(Ordering::Acquire),"cfexecute_outcome":"existing guarded callback stderr; no inferred success"})
}
fn setup_io<T>(
    result: std::io::Result<T>,
    phase: &'static str,
    first: &mut Option<serde_json::Value>,
    connection: &synthetic_agent_integration::Connection,
    server: &Server,
    components: &[&str],
) -> T {
    match result {
        Ok(value) => value,
        Err(error) => {
            if first.is_none() {
                *first = Some(
                    serde_json::json!({"phase":phase,"kind":format!("{:?}",error.kind()),"native_code":error.raw_os_error(),"snapshot":setup_snapshot(connection,server,components)}),
                );
            }
            panic!(
                "synthetic directory setup phase={phase} kind={:?} native_code={:?}",
                error.kind(),
                error.raw_os_error()
            );
        }
    }
}
fn run_case(directory: &Path, space: bool, mode: u64) -> bool {
    let server = Server::new(mode);
    let client =
        Arc::new(OpenCloudClient::new(&server.origin, "synthetic-directory-token".into()).unwrap());
    let origin = client.server_origin().unwrap();
    let scope = ProviderScope::new(
        &client,
        "synthetic-directory".into(),
        canonical_test_account_id(&origin, "personal-drive"),
        origin,
    )
    .unwrap();
    let path = directory.join("cloud-root");
    std::fs::create_dir(&path).unwrap();
    let lease = crate::pin_configured_root(&path).unwrap();
    let identity = lease.identity();
    let recovery = Arc::new(
        crate::DurableEditRecoveryProvider::current_user(scope.clone(), identity).unwrap(),
    );
    let backend = Arc::new(
        OpenCloudPlaceholderBackend::new_with_identity_catalog(
            client.clone(),
            scope.clone(),
            identity,
            recovery.identity_catalog(),
        )
        .unwrap(),
    );
    let mut connection = synthetic_agent_integration::connect(
        lease,
        backend.clone(),
        "personal-drive",
        "personal-root",
        recovery,
    )
    .unwrap();
    let parent = if space {
        vec!["Spaces", "Projects"]
    } else {
        vec!["Personal"]
    };
    let mut full = parent.clone();
    full.push(NAME);
    let mut local_path = path.clone();
    let mut setup_phase = "begin_materialization";
    let mut setup_failure = None;
    let mut materialized = Vec::new();
    let exercise = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        for (index, part) in parent.iter().enumerate() {
            setup_phase = if index == 0 {
                "enumerate_root_expect_navigation"
            } else {
                "enumerate_spaces_expect_project"
            };
            setup_io(
                strict_listing(&local_path, Some(part)),
                setup_phase,
                &mut setup_failure,
                &connection,
                &server,
                &materialized,
            );
            local_path.push(part);
            materialized.push(*part);
        }
        setup_phase = "enumerate_destination_parent";
        setup_io(
            strict_listing(&local_path, None),
            setup_phase,
            &mut setup_failure,
            &connection,
            &server,
            &materialized,
        );
        local_path.push(NAME);
        setup_phase = "create_local_directory";
        setup_io(
            std::fs::create_dir(&local_path),
            setup_phase,
            &mut setup_failure,
            &connection,
            &server,
            &materialized,
        );
        setup_phase = "write_retained_child";
        setup_io(
            std::fs::write(local_path.join("retained-child.bin"), CONTENT),
            setup_phase,
            &mut setup_failure,
            &connection,
            &server,
            &materialized,
        );
        if mode == 2 {
            server.collision.store(true, Ordering::Release);
        }
        setup_phase = "native_admission_and_publication";
        let authorization = CapturedAuthorization {
            agent_generation: 1,
            token_generation: client.token_generation(),
        };
        let mut prepared = connection
            .prepare_namespace_directory(&backend, &parent, NAME, authorization, 1)
            .unwrap();
        let before = prepared.observation().unwrap();
        assert_eq!(before.attributes & 0x400, 0);
        assert_eq!(before.placeholder_state, 0);
        let captured_scope = prepared.entry().parent.scope.clone();
        let store = DirectoryIntentStore::current_user(captured_scope.clone(), policy()).unwrap();
        let record = store.publish_intent(prepared.intent()).unwrap().record;
        let mut journal = store.acquire_dispatch(&record.key).unwrap();
        let outcome = backend
            .with_directory_publication_session(
                &record.intent,
                prepared.parent_identity(),
                &|auth| auth == authorization,
                |session| {
                    let mut local = prepared.local(session);
                    reconcile_directory_create(&mut journal, session.remote(), &mut local).unwrap()
                },
            )
            .unwrap();
        drop(journal);
        let after = prepared.observation().unwrap();
        assert_eq!(after.local_file, before.local_file);
        let records = store.discover().unwrap();
        assert_eq!(records.len(), 1);
        let saved = &records[0];
        if mode == 0 {
            assert_eq!(outcome, DirectoryCreateOutcome::LocalCompleted);
            assert!(saved.progress.local_completed);
            assert_ne!(after.attributes & 0x400, 0);
            assert_ne!(after.placeholder_state & 1, 0);
            assert_eq!(after.placeholder_state & 8, 0);
            let cat = crate::ProviderIdentityCatalogScope::new(
                &scope,
                identity,
                "personal-drive",
                "personal-root",
            )
            .unwrap();
            let bindings = backend.scope();
            assert!(bindings == &scope);
            let catalog = crate::DurableEditRecoveryProvider::current_user(scope.clone(), identity)
                .unwrap()
                .identity_catalog();
            assert!(catalog.load(&cat).unwrap().iter().any(|b|matches!(b,crate::ProviderIdentityBinding::Directory{identity,remote_id,..}if Some(*identity)==after.opaque_identity&&remote_id=="created-directory")));
        } else {
            assert!(!saved.progress.local_completed);
            assert_eq!(after.attributes & 0x400, 0);
            assert_eq!(after.placeholder_state, 0);
            assert_eq!(
                outcome,
                match mode {
                    1 => DirectoryCreateOutcome::Deferred,
                    2 => DirectoryCreateOutcome::Conflict,
                    _ => DirectoryCreateOutcome::RemoteVerifiedLocalPending,
                }
            );
        }
        assert!(std::fs::read(local_path.join("retained-child.bin")).unwrap() == CONTENT);
        (
            captured_scope,
            saved.intent.record_id.clone(),
            saved.intent.record_generation,
            saved.commitment,
            after,
        )
    }));
    if exercise.is_err() && setup_failure.is_none() {
        setup_failure = Some(
            serde_json::json!({"phase":setup_phase,"kind":"assertion_or_native_refusal","native_code":null,"snapshot":setup_snapshot(&connection,&server,&materialized)}),
        );
    }
    let stopped = disconnect(&mut connection, directory);
    if let Some(failure) = &setup_failure {
        report(&directory.join("FIRST-FAILURE.json"), failure.clone());
    }
    let mut restarted = false;
    if let Ok((saved_scope, id, generation, commitment, after)) = &exercise {
        let next_recovery = Arc::new(
            crate::DurableEditRecoveryProvider::current_user(scope.clone(), identity).unwrap(),
        );
        let next_backend = Arc::new(
            OpenCloudPlaceholderBackend::new_with_identity_catalog(
                client,
                scope,
                identity,
                next_recovery.identity_catalog(),
            )
            .unwrap(),
        );
        let lease = crate::pin_registered_configured_root(&path, identity).unwrap();
        let mut next = synthetic_agent_integration::connect(
            lease,
            next_backend,
            "personal-drive",
            "personal-root",
            next_recovery,
        )
        .unwrap();
        let current = next.namespace_directory_fixture_observation(&full).unwrap();
        assert_eq!(current.local_file, after.local_file);
        assert_eq!(current.opaque_identity, after.opaque_identity);
        let reopened = DirectoryIntentStore::current_user(saved_scope.clone(), policy()).unwrap();
        let records = reopened.discover().unwrap();
        restarted = records.len() == 1
            && records[0].intent.record_id == *id
            && records[0].intent.record_generation == *generation
            && records[0].commitment == *commitment;
        restarted &= disconnect(&mut next, directory);
    }
    let sends = server.sent.load(Ordering::Acquire);
    server.finish();
    let root_retained = crate::pin_registered_configured_root(&path, identity).is_ok();
    let retained = root_retained
        && std::fs::read(local_path.join("retained-child.bin")).is_ok_and(|bytes| bytes == CONTENT);
    let passed = exercise.is_ok()
        && stopped
        && restarted
        && retained
        && sends == if mode == 2 { 0 } else { 1 };
    report(
        &directory.join("RESULTS.json"),
        serde_json::json!({"passed":passed,"explicit_producer":true,"automatic_observer_integration":false,"connection_restart_same_process":true,
  "separate_process_dpapi":false,"mkcol_count":sends,"local_completed":mode==0&&exercise.is_ok(),"same_fileid":exercise.is_ok(),"catalog_identity_join":mode==0&&exercise.is_ok(),
  "no_in_sync_requested_or_accepted":exercise.is_ok(),"root_registration_retained":root_retained,"retained_child_bytes":retained,"first_failure":setup_failure,"normal_stop":stopped,"durable_record_connection_restart":restarted,"forced_cleanup":false}),
    );
    passed
}

#[test]
fn directory_case_selector_is_exact_and_defaults_to_all_five() {
    assert_eq!(select_cases(None).unwrap(), CASES);
    for case in CASES {
        assert_eq!(select_cases(Some(case)).unwrap(), [case]);
    }
    for bad in ["", "unknown", "SPACE-SUCCESS", "space-success ", "all"] {
        assert!(select_cases(Some(bad)).is_err());
    }
}
