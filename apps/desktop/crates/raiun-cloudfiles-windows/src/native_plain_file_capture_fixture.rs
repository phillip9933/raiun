//! Ignored actual-Windows LOCAL capture fixture. No remote create/conversion.
use super::*;
use crate::streamed_store::{SnapshotStore, StorePolicy};
use raiun_core::backend::CloudBackend;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
const TEST: &str = "native::native_plain_file_capture::tests::fixture::explicit_plain_file_local_capture_and_dpapi_reopen";
const OPT_IN: &str = "RAIUN_RUN_NATIVE_PLAIN_CAPTURE_FIXTURE";
const CHILD: &str = "RAIUN_NATIVE_PLAIN_CAPTURE_FIXTURE_CHILD";
const ROLE: &str = "RAIUN_NATIVE_PLAIN_CAPTURE_FIXTURE_ROLE";
const DIRECTORY: &str = "RAIUN_NATIVE_PLAIN_CAPTURE_FIXTURE_DIR";
const OWNER: &[u8] = b"raiun-native-plain-capture-owned-v1\n";
const NAME: &str = "new-plain-file.bin";
const LENGTH: u64 = 17 * 1024 * 1024 + 7;
#[derive(Clone, Copy, PartialEq, Debug)]
enum Role {
    Capture,
    Reopen,
}
fn role(value: Option<&str>) -> Result<Option<Role>, ()> {
    match value {
        None => Ok(None),
        Some("capture") => Ok(Some(Role::Capture)),
        Some("reopen") => Ok(Some(Role::Reopen)),
        _ => Err(()),
    }
}
fn policy() -> StorePolicy {
    StorePolicy {
        max_content_bytes: 32 * 1024 * 1024,
        max_state_bytes: 512 * 1024 * 1024,
        max_entries: 4096,
        max_metadata_bytes_per_scan: 16 * 1024 * 1024,
    }
}
#[derive(Default)]
struct ReportState {
    failed: std::cell::Cell<bool>,
}
impl ReportState {
    fn ok(&self) -> bool {
        !self.failed.get()
    }
    fn emit(&self, write: impl FnOnce() -> Result<(), ()>) {
        if write().is_err() {
            self.failed.set(true);
        }
    }
    fn report(&self, path: &Path, value: serde_json::Value) {
        self.emit(|| {
            let bytes = serde_json::to_vec_pretty(&value).map_err(|_| ())?;
            std::fs::write(path, bytes).map_err(|_| ())
        });
    }
}
#[derive(Default)]
struct WaitState {
    failed: bool,
    overdue: bool,
}
impl WaitState {
    fn observe(
        &mut self,
        status: Result<Option<bool>, ()>,
        expired: bool,
        reports: &ReportState,
        pending: impl FnOnce(),
    ) -> Option<bool> {
        self.failed |= expired;
        match status {
            Ok(Some(success)) => return Some(success && !self.failed && reports.ok()),
            Err(()) => self.failed = true,
            Ok(None) => {}
        }
        if expired && !self.overdue {
            self.failed = true;
            self.overdue = true;
            pending();
        }
        None
    }
}

fn source_path(root: &Path) -> PathBuf {
    root.join("cloud-root").join("Personal").join(NAME)
}
fn hash_reader(mut reader: impl Read) -> (u64, String) {
    let mut buffer = [0u8; 64 * 1024];
    let mut h = Sha256::new();
    let mut count = 0u64;
    loop {
        let n = reader.read(&mut buffer).unwrap();
        if n == 0 {
            break;
        }
        count += n as u64;
        h.update(&buffer[..n]);
    }
    (count, hex(&h.finalize()))
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}
fn generated_hash() -> String {
    let mut h = Sha256::new();
    let mut offset = 0u64;
    let mut b = [0; 64 * 1024];
    while offset < LENGTH {
        let n = (LENGTH - offset).min(b.len() as u64) as usize;
        for (i, v) in b[..n].iter_mut().enumerate() {
            *v = ((offset + i as u64) % 251) as u8;
        }
        h.update(&b[..n]);
        offset += n as u64;
    }
    hex(&h.finalize())
}
fn source_file(root: &Path) -> std::fs::File {
    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(source_path(root))
        .unwrap()
}
fn expected_source(root: &Path, expected: &Expected) {
    let file = source_file(root);
    let (before, usn) = plain_snapshot(&file).unwrap();
    assert_eq!(before.identity.volume_serial, expected.file.volume_serial);
    assert_eq!(before.identity.file_index, expected.file.file_index);
    assert_eq!(usn, expected.usn);
    assert!(usn > 0);
    assert_eq!(before.placeholder_state, 0);
    assert_eq!(before.reparse_tag, 0);
    assert_eq!(before.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT, 0);
    assert_eq!(hash_reader(&file), (LENGTH, expected.sha256.clone()));
    let (after, after_usn) = plain_snapshot(&file).unwrap();
    assert!(same_edit_snapshot(before, after));
    assert_eq!(usn, after_usn);
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    scope: crate::EditJournalScope,
    join_id: String,
    snapshot_id: String,
    generation: u64,
    commitment: [u8; 32],
    manifest_sha256: String,
    sha256: String,
    file: crate::LocalFileIdentity,
    usn: i64,
}
fn protector_and_state() -> (
    Arc<dyn crate::EditRecordProtector>,
    Arc<crate::recovery_state::RecoveryStateRoot>,
) {
    let protector = Arc::new(crate::DpapiEditRecordProtector::current_user().unwrap());
    let state =
        crate::recovery_state::RecoveryStateRoot::existing_gui(protector.local_state_directory())
            .unwrap();
    (protector, state)
}
fn reopen(root: &Path, reports: &ReportState) {
    let expected: Expected =
        serde_json::from_slice(&std::fs::read(root.join("EXPECTED.json")).unwrap()).unwrap();
    let (protector, state) = protector_and_state();
    let base =
        SnapshotStore::open_existing_admitted(state, expected.scope.clone(), protector, policy())
            .unwrap();
    let files = FileCreateStore::new(base).unwrap();
    let records = files.discover().unwrap();
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.key().record_id(), expected.join_id);
    assert_eq!(record.snapshot_id(), expected.snapshot_id);
    assert_eq!(record.key().generation(), expected.generation);
    assert_eq!(record.key().scope(), &expected.scope);
    assert_eq!(record.manifest_commitment_sha256(), &expected.commitment);
    assert_eq!(record.progress().sequence, 0);
    let verified = files.open_joined(record.key(), &mut || false).unwrap();
    assert_eq!(
        hex(&Sha256::digest(
            serde_json::to_vec(verified.manifest()).unwrap()
        )),
        expected.manifest_sha256
    );
    assert!(verified.manifest().binding().remote.is_none());
    assert_eq!(verified.manifest().binding().relative_path, NAME);
    assert_eq!(verified.manifest().binding().local_file, expected.file);
    assert_eq!(
        verified.manifest().binding().generation,
        expected.generation
    );
    assert_eq!(
        hash_reader(verified.into_reader(Arc::new(|| false)).unwrap()),
        (LENGTH, expected.sha256.clone())
    );
    expected_source(root, &expected);
    reports.report(
        &root.join("REOPEN.json"),
        serde_json::json!({"passed":true,"role":"reopen","separate_process_dpapi":true,"exact_join_and_snapshot":true,"generation":expected.generation,"sha256":expected.sha256,"length":LENGTH,"plain_state":0,"source_fid_usn_unchanged":true,"read_only":true,"submitted":false,"remote_mutations":0,"native_completion":false}),
    );
}
fn wait_terminal(
    child: &mut std::process::Child,
    root: &Path,
    which: &str,
    reports: &ReportState,
) -> bool {
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut wait = WaitState::default();
    loop {
        let status = child
            .try_wait()
            .map(|v| v.map(|s| s.success()))
            .map_err(|_| ());
        if let Some(result) = wait.observe(status, Instant::now() >= deadline, reports, || {
            reports.report(
                &root.join(format!("{which}.WAIT-PENDING.json")),
                serde_json::json!({"passed":false,"owner_retained":true,"forced_stop":false}),
            )
        }) {
            return result;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn spawn(root: &Path, which: &str) -> std::process::Child {
    let log = |suffix| {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join(format!("{which}.{suffix}.log")))
            .unwrap()
    };
    std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            TEST,
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, "1")
        .env(ROLE, which)
        .env(DIRECTORY, root)
        .env("RAIUN_HEADLESS_CONTEXT", "1")
        .env("RAIUN_STATE_DIR", root.join("state"))
        .env_remove("RAIUN_HEADLESS_CONFIG")
        .stdout(log("stdout"))
        .stderr(log("stderr"))
        .spawn()
        .unwrap()
}
#[test]
#[ignore = "actual configured-root Personal17MiB+7 LOCAL capture + separate-process DPAPI reopen only; no create/upload/conversion/IN_SYNC"]
fn explicit_plain_file_local_capture_and_dpapi_reopen() {
    assert_eq!(std::env::var(OPT_IN).as_deref(), Ok("fresh-owned-state"));
    let args = std::env::args().collect::<Vec<_>>();
    assert!(
        args.iter().any(|v| v == "--ignored")
            && args.windows(2).any(|v| v[0] == "--exact" && v[1] == TEST)
    );
    let reports = ReportState::default();
    let selected = match std::env::var(ROLE) {
        Ok(v) => role(Some(&v)),
        Err(std::env::VarError::NotPresent) => role(None),
        Err(_) => Err(()),
    }
    .expect("invalid or empty capture role");
    match std::env::var(CHILD) {
        Err(std::env::VarError::NotPresent) => {
            assert!(selected.is_none());
            assert!(std::env::var_os(DIRECTORY).is_none());
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "raiun-native-plain-capture-{}-{nonce}",
                std::process::id()
            ));
            std::fs::create_dir(&root).unwrap();
            std::fs::write(root.join("OWNER.txt"), OWNER).unwrap();
            println!("NATIVE_PLAIN_CAPTURE_FIXTURE_DIR={}", root.display());
            reports.report(
                &root.join("RESULTS.json"),
                serde_json::json!({"fixture":"native-plain-capture-v1","requested_cases":["personal17MiB-local-capture"],"complete_case_count":0,"passed":false,"forced_cleanup":false}),
            );
            let mut child = spawn(&root, "capture");
            let terminal = wait_terminal(&mut child, &root, "capture", &reports);
            let receipt = std::fs::read(root.join("CAPTURE.json"))
                .ok()
                .and_then(|v| serde_json::from_slice::<serde_json::Value>(&v).ok());
            let passed =
                terminal && reports.ok() && receipt.as_ref().is_some_and(|v| v["passed"] == true);
            reports.report(
                &root.join("RESULTS.json"),
                serde_json::json!({"fixture":"native-plain-capture-v1","requested_cases":["personal17MiB-local-capture"],"requested_case_count":1,"complete_case_count":usize::from(passed),"passed":passed,"capture_process_terminal":true,"capture_process_timely_success":terminal,"capture":receipt,"forced_cleanup":false,"all_evidence_retained":true}),
            );
            assert!(
                passed && reports.ok(),
                "local capture child or report failed; evidence retained"
            );
            return;
        }
        Ok(v) if v == "1" => {}
        _ => panic!("invalid or empty capture child guard"),
    }
    let selected = selected.expect("child requires explicit role");
    let root = PathBuf::from(std::env::var_os(DIRECTORY).unwrap());
    assert!(root.is_absolute());
    assert!(
        root.file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("raiun-native-plain-capture-")
    );
    let _pin = raiun_control_windows::PinnedDirectory::open(&root).unwrap();
    let marker = root.join("OWNER.txt");
    let meta = std::fs::symlink_metadata(&marker).unwrap();
    assert!(
        meta.is_file() && meta.file_attributes() & 0x400 == 0 && meta.len() == OWNER.len() as u64
    );
    assert_eq!(std::fs::read(marker).unwrap(), OWNER);
    let context = raiun_control_windows::headless_context()
        .unwrap()
        .expect("explicit isolated state required");
    assert_eq!(
        std::fs::canonicalize(context.state_root()).unwrap(),
        std::fs::canonicalize(root.join("state")).unwrap()
    );
    // No DPAPI/current_user/default-state access before all guards above.
    match selected {
        Role::Capture => capture(&root, &reports),
        Role::Reopen => reopen(&root, &reports),
    }
    assert!(reports.ok(), "fixture report failed; evidence retained");
}
fn disconnect(
    connection: &mut crate::ConfiguredRootConnection,
    root: &Path,
    reports: &ReportState,
) -> bool {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut late = false;
    loop {
        if connection.disconnect_in_place().is_ok() {
            return !late && Instant::now() < deadline && reports.ok();
        }
        if Instant::now() >= deadline && !late {
            late = true;
            reports.report(
                &root.join("DISCONNECT-PENDING.json"),
                serde_json::json!({"passed":false,"owner_retained":true,"forced_cleanup":false}),
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
fn capture(root: &Path, reports: &ReportState) {
    assert!(!root.join("cloud-root").exists() && !root.join("EXPECTED.json").exists());
    let server = Server::new();
    let client = Arc::new(
        raiun_opencloud::OpenCloudClient::new(&server.origin, "synthetic-local-capture".into())
            .unwrap(),
    );
    let origin = client.server_origin().unwrap();
    let account = format!("{origin}\0personal-drive");
    let scope = crate::ProviderScope::new(
        &client,
        "synthetic-local-capture".into(),
        hex(account.as_bytes()),
        origin,
    )
    .unwrap();
    let cloud = root.join("cloud-root");
    std::fs::create_dir(&cloud).unwrap();
    let lease = crate::pin_configured_root(&cloud).unwrap();
    let identity = lease.identity();
    let recovery = Arc::new(
        crate::DurableEditRecoveryProvider::current_user(scope.clone(), identity).unwrap(),
    );
    let backend = Arc::new(
        crate::OpenCloudPlaceholderBackend::new_with_identity_catalog(
            client.clone(),
            scope,
            identity,
            recovery.identity_catalog(),
        )
        .unwrap(),
    );
    let job = crate::CancellationToken::for_recovery_job(crate::StreamedRecoveryPolicy::default());
    let original_deadline = job.deadline();
    let composite = backend
        .register_composite_root_for("personal-drive", "personal-root")
        .unwrap();
    let runtime =
        crate::prepare_configured_root_runtime(lease, backend.clone(), composite, recovery)
            .unwrap();
    let mut connection = crate::connect_configured_root(runtime).unwrap();
    let exercise = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let entries = std::fs::read_dir(&cloud)
            .unwrap()
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();
        assert!(entries.iter().any(|e| e.file_name() == "Personal"));
        std::fs::read_dir(cloud.join("Personal"))
            .unwrap()
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(source_path(root))
            .unwrap();
        let mut offset = 0u64;
        let mut buffer = [0; 64 * 1024];
        while offset < LENGTH {
            let n = (LENGTH - offset).min(buffer.len() as u64) as usize;
            for (i, v) in buffer[..n].iter_mut().enumerate() {
                *v = ((offset + i as u64) % 251) as u8;
            }
            file.write_all(&buffer[..n]).unwrap();
            offset += n as u64;
        }
        file.sync_all().unwrap();
        drop(file);
        let source = source_file(root);
        let (before, usn) = plain_snapshot(&source).unwrap();
        drop(source);
        assert!(usn > 0);
        assert_eq!(before.placeholder_state, 0);
        let auth = crate::namespace_intent::CapturedAuthorization {
            agent_generation: 1,
            token_generation: client.token_generation(),
        };
        let joined = backend
            .with_plain_file_capture_parent(
                identity,
                &["Personal"],
                auth,
                &job,
                &|a| a == auth,
                |parent| {
                    let (protector, state) = protector_and_state();
                    let base = SnapshotStore::create_or_open_admitted(
                        state,
                        parent.captured().scope.clone(),
                        protector,
                        policy(),
                    )
                    .unwrap();
                    let files = FileCreateStore::new(base).unwrap();
                    let capture = connection
                        .prepare_plain_file_capture(&backend, parent, NAME, 1)
                        .unwrap();
                    let published = capture.capture_and_join(&files).unwrap();
                    let record = published.record().clone();
                    let verified = published.into_verified();
                    let expected = Expected {
                        scope: record.key().scope().clone(),
                        join_id: record.key().record_id().into(),
                        snapshot_id: record.snapshot_id().into(),
                        generation: record.key().generation(),
                        commitment: *record.manifest_commitment_sha256(),
                        manifest_sha256: hex(&Sha256::digest(
                            serde_json::to_vec(verified.manifest()).unwrap(),
                        )),
                        sha256: generated_hash(),
                        file: crate::LocalFileIdentity {
                            volume_serial: before.identity.volume_serial,
                            file_index: before.identity.file_index,
                        },
                        usn,
                    };
                    assert_ne!(expected.join_id, expected.snapshot_id);
                    assert_eq!(record.progress().sequence, 0);
                    assert!(verified.manifest().binding().remote.is_none());
                    assert_eq!(verified.manifest().binding().relative_path, NAME);
                    assert_eq!(verified.manifest().binding().local_file, expected.file);
                    assert_eq!(verified.manifest().binding().generation, 1);
                    assert_eq!(
                        hash_reader(verified.into_reader(Arc::new(|| false)).unwrap()),
                        (LENGTH, expected.sha256.clone())
                    );
                    expected
                },
            )
            .unwrap();
        assert_eq!(job.deadline(), original_deadline);
        assert!(!job.is_stopped());
        expected_source(root, &joined);
        assert!(server.counts.graph.load(Ordering::Acquire) > 0);
        assert!(server.counts.dav.load(Ordering::Acquire) > 0);
        assert_eq!(server.counts.denied.load(Ordering::Acquire), 0);
        std::fs::write(
            root.join("EXPECTED.json"),
            serde_json::to_vec_pretty(&joined).unwrap(),
        )
        .unwrap();
    }));
    let stopped = disconnect(&mut connection, root, reports);
    let retained = crate::pin_registered_configured_root(&cloud, identity).is_ok();
    if exercise.is_err() || !stopped || !retained {
        reports.report(
            &root.join("CAPTURE.json"),
            serde_json::json!({"fixture":"native-plain-capture-v1","requested_cases":["personal17MiB-local-capture"],"complete_case_count":0,"passed":false,"exercise_passed":exercise.is_ok(),"normal_disconnect":stopped,"registration_retained":retained,"forced_cleanup":false}),
        );
        server.finish();
        assert!(
            exercise.is_ok() && stopped && retained && reports.ok(),
            "local capture failed; evidence retained"
        );
        return;
    }
    let mut child = spawn(root, "reopen");
    let reopened = wait_terminal(&mut child, root, "reopen", reports);
    let expected: Expected =
        serde_json::from_slice(&std::fs::read(root.join("EXPECTED.json")).unwrap()).unwrap();
    expected_source(root, &expected);
    let denied = server.counts.denied.load(Ordering::Acquire);
    let graph_reads = server.counts.graph.load(Ordering::Acquire);
    let dav_reads = server.counts.dav.load(Ordering::Acquire);
    let read_only = denied == 0;
    let terminal = server.finish();
    let passed = reopened && read_only && terminal && reports.ok();
    reports.report(
        &root.join("CAPTURE.json"),
        serde_json::json!({"fixture":"native-plain-capture-v1","requested_cases":["personal17MiB-local-capture"],"complete_case_count":usize::from(passed),"passed":passed,"local_capture_only":true,"separate_process_dpapi":reopened,"length":LENGTH,"sha256":expected.sha256,"source_fileid_usn_retained":true,"source_plain_state":0,"normal_disconnect":stopped,"registration_retained":retained,"server_join_succeeded":terminal,"denied_requests":denied,"graph_reads":graph_reads,"dav_reads":dav_reads,"zero_file_get_ranges_mutations":read_only,"submitted":false,"native_completion":false,"forced_cleanup":false,"all_evidence_retained":true}),
    );
    assert!(
        passed && reports.ok(),
        "read-only reopen incomplete or report failed; evidence retained"
    );
}
#[derive(Default)]
struct Counts {
    graph: AtomicU64,
    dav: AtomicU64,
    denied: AtomicU64,
}
struct Server {
    origin: String,
    stop: Arc<AtomicBool>,
    counts: Arc<Counts>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl Server {
    fn new() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let counts = Arc::new(Counts::default());
        let (st, c) = (stop.clone(), counts.clone());
        let worker = std::thread::spawn(move || {
            while !st.load(Ordering::Acquire) {
                let (mut stream, _) = match listener.accept() {
                    Ok(v) => v,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(_) => panic!("localcapture accept failed"),
                };
                configure_accepted(&stream).unwrap();
                let headers = request(&mut stream);
                let line = headers.lines().next().unwrap();
                let (status, body) = if line == "GET /graph/v1.0/me/drives HTTP/1.1"
                    && !headers
                        .lines()
                        .any(|l| l.to_ascii_lowercase().starts_with("range:"))
                {
                    c.graph.fetch_add(1, Ordering::AcqRel);
                    (
                        "200 OK",
                        format!(
                            r#"{{"value":[{{"id":"personal-drive","name":"Personal","driveType":"personal","root":{{"id":"personal-root","webDavUrl":"http://{addr}/dav/personal/"}}}}]}}"#
                        ),
                    )
                } else if line == "PROPFIND /dav/personal/ HTTP/1.1"
                    && !headers
                        .lines()
                        .any(|l| l.to_ascii_lowercase().starts_with("range:"))
                {
                    c.dav.fetch_add(1, Ordering::AcqRel);
                    ("207 Multi-Status","<d:multistatus xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\"><d:response><d:href>/dav/personal/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getetag>\"root-v1\"</d:getetag><oc:fileid>personal-root</oc:fileid><oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>".into())
                } else {
                    c.denied.fetch_add(1, Ordering::AcqRel);
                    ("405 Method Not Allowed", String::new())
                };
                write!(stream,"HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: application/xml\r\n\r\n{body}",body.len()).unwrap();
            }
        });
        Self {
            origin: format!("http://{addr}"),
            stop,
            counts,
            worker: Some(worker),
        }
    }
    fn finish(mut self) -> bool {
        self.stop.store(true, Ordering::Release);
        self.worker.take().unwrap().join().is_ok()
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
fn configure_accepted(stream: &std::net::TcpStream) -> std::io::Result<()> {
    // Windows accept inherits the listener's nonblocking mode. Normalize the
    // owned accepted socket before any blocking request read or timeout.
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))
}

fn request(stream: &mut std::net::TcpStream) -> String {
    let mut bytes = Vec::new();
    let mut chunk = [0; 4096];
    let end = loop {
        if let Some(pos) = bytes.windows(4).position(|b| b == b"\r\n\r\n") {
            break pos + 4;
        }
        assert!(bytes.len() <= 32768);
        let n = stream.read(&mut chunk).unwrap();
        assert_ne!(n, 0);
        bytes.extend_from_slice(&chunk[..n]);
    };
    assert!(end <= 32768);
    let headers = String::from_utf8(bytes[..end].to_vec()).unwrap();
    let body = headers
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    assert!(body <= 32768);
    while bytes.len() < end + body {
        let n = stream.read(&mut chunk).unwrap();
        assert_ne!(n, 0);
        bytes.extend_from_slice(&chunk[..n]);
    }
    headers
}
#[test]
fn role_parser_rejects_present_empty_unknown_and_case_variants() {
    assert_eq!(role(None), Ok(None));
    assert_eq!(role(Some("capture")), Ok(Some(Role::Capture)));
    assert_eq!(role(Some("reopen")), Ok(Some(Role::Reopen)));
    for s in ["", "Capture", "reopen ", "other"] {
        assert!(role(Some(s)).is_err());
    }
}

#[test]
fn failed_pending_report_retains_owner_until_actual_terminal_and_is_sticky() {
    struct Owner<'a>(&'a std::cell::Cell<bool>);
    impl Drop for Owner<'_> {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }
    let dropped = std::cell::Cell::new(false);
    let owner = Owner(&dropped);
    let reports = ReportState::default();
    let mut wait = WaitState::default();
    assert_eq!(
        wait.observe(Ok(None), true, &reports, || reports
            .report(Path::new(""), serde_json::Value::Null)),
        None
    );
    assert!(!reports.ok());
    assert!(!dropped.get());
    assert_eq!(
        wait.observe(Err(()), false, &reports, || panic!("not overdue again")),
        None
    );
    assert!(!dropped.get());
    assert_eq!(
        wait.observe(Ok(Some(true)), false, &reports, || panic!(
            "terminal has no report"
        )),
        Some(false)
    );
    assert!(!dropped.get());
    drop(owner);
    assert!(dropped.get());
    reports.emit(|| Ok(()));
    assert!(
        !reports.ok(),
        "later successful report cannot clear failure"
    );
    let final_report = ReportState::default();
    assert_eq!(
        WaitState::default().observe(Ok(Some(true)), true, &final_report, || panic!(
            "terminal has no pending report"
        )),
        Some(false)
    );
    assert!(final_report.ok());
    final_report.emit(|| Err(()));
    assert!(
        !final_report.ok(),
        "acceptance must check after final write"
    );
}

#[test]
fn accepted_nonblocking_socket_is_configured_before_delayed_request_read() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut stream, _) = listener.accept().unwrap();
    stream.set_nonblocking(true).unwrap();
    let mut empty = [0; 1];
    assert_eq!(
        stream.read(&mut empty).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || -> std::io::Result<()> {
        configure_accepted(&stream)?;
        tx.send(())
            .map_err(|_| std::io::Error::other("read-attempt receiver closed"))?;
        let mut byte = [0; 1];
        stream.read_exact(&mut byte)?;
        stream.write_all(&byte)
    });
    let exercise = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rx.recv_timeout(Duration::from_secs(5)).unwrap();
        // No bytes exist at the server read attempt; allow that call to enter
        // its blocking wait before the first client write. Not a retry.
        std::thread::sleep(Duration::from_millis(20));
        client.write_all(b"x").unwrap();
        let mut echoed = [0; 1];
        client.read_exact(&mut echoed).unwrap();
        assert_eq!(&echoed, b"x");
    }));
    drop(client);
    let terminal = worker.join();
    let server_error = terminal
        .as_ref()
        .ok()
        .and_then(|result| result.as_ref().err())
        .map(std::io::Error::kind);
    assert!(
        matches!(terminal, Ok(Ok(()))),
        "accepted socket read failed after actual server join kind={server_error:?}"
    );
    assert!(
        exercise.is_ok(),
        "delayed client failed after owned server joined"
    );
}
