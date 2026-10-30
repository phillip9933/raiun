use super::*;
use crate::synthetic_agent_integration;
use raiun_control_windows::directory_notifications::{NotificationBatch, ObserverPoll};
use sha2::Digest;
use std::io::{Read, Write};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const TEST: &str = "tests::connected_namespace_observer_tests::gui_connected_root_observer_explicit_state_hints_and_revoked_drain";
const OPT_IN: &str = "RAIUN_RUN_CONNECTED_OBSERVER_FIXTURE";
const CHILD: &str = "RAIUN_CONNECTED_OBSERVER_FIXTURE_CHILD";
const DIRECTORY: &str = "RAIUN_CONNECTED_OBSERVER_FIXTURE_DIR";
const OWNER: &[u8] = b"raiun-gui-connected-observer-explicit-state-owned-v1\n";
const CONTENT: &[u8] = b"synthetic connected observer plain bytes\0\x01\xff";
const FILE: &str = "namespace-observer-owned.bin";

struct Server {
    origin: String,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<(usize, usize, u64)>>,
}
impl Server {
    fn start() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let worker = std::thread::spawn(move || {
            let (mut requests, mut ranges, mut range_bytes) = (0, 0, 0);
            while !stopping.load(Ordering::Acquire) {
                let (mut stream, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("synthetic observer server accept failed: {error:?}"),
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let request = read_http_request(&mut stream);
                // Reuse the existing bounded fixture/parser. Any mutation is a
                // hard test failure, never accepted or silently routed elsewhere.
                let target = request.split_whitespace().nth(1).unwrap_or_default();
                assert!(
                    request.starts_with("GET /graph/")
                        || (request.starts_with("PROPFIND ")
                            && matches!(target, "/dav/personal/" | "/dav/personal/cloud.bin"))
                        || request.starts_with("GET /dav/personal/cloud.bin"),
                    "unexpected synthetic observer request route"
                );
                let (status, headers, body, content_type) = opencloud_response(
                    &request,
                    address,
                    OPEN_CLOUD_PAYLOAD_LEN,
                    &mut ranges,
                    &mut range_bytes,
                );
                write!(stream, "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: {content_type}\r\n{headers}Connection: close\r\n\r\n", body.len()).unwrap();
                stream.write_all(&body).unwrap();
                requests += 1;
            }
            (requests, ranges, range_bytes)
        });
        Self {
            origin: format!("http://{address}"),
            stop,
            worker: Some(worker),
        }
    }
    fn finish(mut self) -> (usize, usize, u64) {
        self.stop.store(true, Ordering::Release);
        self.worker.take().unwrap().join().unwrap()
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
fn report(path: &Path, value: serde_json::Value) {
    std::fs::write(path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
}
fn drain(connection: &mut synthetic_agent_integration::Connection, directory: &Path) -> bool {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut overdue = false;
    loop {
        match connection.stop_namespace_observer(Duration::from_millis(50)) {
            Ok(()) => return !overdue,
            Err(Error::NamespaceObserverDrainPending) => (),
            Err(_) => panic!("unexpected observer drain failure; owned state retained"),
        }
        if Instant::now() >= deadline && !overdue {
            overdue = true;
            report(
                &directory.join("drain-pending.json"),
                serde_json::json!({"passed":false,"owner_retained":true,"forced_stop":false}),
            );
        }
        // A deadline is diagnostic failure, never permission to drop live I/O.
        std::thread::sleep(Duration::from_millis(25));
    }
}
fn disconnect(connection: &mut synthetic_agent_integration::Connection, directory: &Path) -> bool {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut overdue = false;
    loop {
        if connection.disconnect_in_place().is_ok() {
            return !overdue;
        }
        if Instant::now() >= deadline && !overdue {
            overdue = true;
            report(
                &directory.join("disconnect-pending.json"),
                serde_json::json!({"passed":false,"owner_retained":true,"forced_stop":false}),
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
fn backend(
    client: Arc<OpenCloudClient>,
    scope: ProviderScope,
    root: ConfiguredRootIdentity,
    recovery: &Arc<crate::DurableEditRecoveryProvider>,
) -> Arc<OpenCloudPlaceholderBackend> {
    Arc::new(
        OpenCloudPlaceholderBackend::new_with_identity_catalog(
            client,
            scope,
            root,
            recovery.identity_catalog(),
        )
        .unwrap(),
    )
}

#[test]
#[ignore = "explicit fresh-owned-state Windows connected Cloud Files observer fixture; compile is not native acceptance"]
fn gui_connected_root_observer_explicit_state_hints_and_revoked_drain() {
    assert!(matches!(
        std::env::var(OPT_IN).as_deref(),
        Ok("fresh-owned-state")
    ));
    let args = std::env::args().collect::<Vec<_>>();
    assert!(
        args.iter().any(|a| a == "--ignored")
            && args.windows(2).any(|a| a[0] == "--exact" && a[1] == TEST)
    );
    if std::env::var(CHILD).as_deref() != Ok("1") {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "raiun-gui-connected-observer-explicit-state-{}-{nonce}",
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
            "connected observer child failed; fixture retained"
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
    let fixture_pin = raiun_control_windows::PinnedDirectory::open(&directory)
        .expect("pin the exact wrapper-owned fixture directory");
    let requested_state_path = directory.join("state");
    match std::fs::symlink_metadata(&requested_state_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => panic!("explicit fixture state must be absent before creation"),
    }
    let state = Arc::new(
        raiun_control_windows::PrivateDirectory::create_or_open_under(
            &fixture_pin,
            std::ffi::OsStr::new("state"),
        )
        .expect("create exact private state under pinned owned fixture"),
    );
    let state_path = state.path().to_path_buf();
    assert_eq!(state_path, requested_state_path);
    let protector =
        crate::DpapiEditRecordProtector::from_existing_private_directory(Arc::clone(&state))
            .expect("DPAPI protection from exact explicit fixture state");
    assert_eq!(protector.local_state_directory(), state_path.as_path());
    // No default-state, profile or credential/session routing is used.
    let server = Server::start();
    let client =
        Arc::new(OpenCloudClient::new(&server.origin, "synthetic-observer-token".into()).unwrap());
    let origin = client.server_origin().unwrap();
    let scope = ProviderScope::new(
        &client,
        "synthetic-gui-connected-observer".into(),
        canonical_test_account_id(&origin, "drive-personal"),
        origin,
    )
    .unwrap();
    let path = directory.join("cloud-root");
    std::fs::create_dir(&path).unwrap();
    let lease = crate::pin_configured_root(&path).unwrap();
    let identity = lease.identity();
    let recovery = Arc::new(crate::DurableEditRecoveryProvider::new(
        state_path.clone(),
        scope.clone(),
        identity,
        protector,
    ));
    let first_backend = backend(client.clone(), scope.clone(), identity, &recovery);
    let mut connection = synthetic_agent_integration::connect(
        lease,
        first_backend.clone(),
        "drive-personal",
        "root-id",
        recovery.clone(),
    )
    .unwrap();
    let first = connection.attach_namespace_observer().unwrap();
    assert_eq!(first.root_identity(), identity);
    assert!(first.provider_scope() == &scope);
    assert!(first.inventory_unknown());
    assert!(matches!(first.poll(), ObserverPoll::Pending));
    let first_instance = first.instance();
    let exercise = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let file = path.join("Personal").join(FILE);
        let mut writer = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&file)
            .unwrap();
        writer.write_all(CONTENT).unwrap();
        writer.sync_all().unwrap();
        drop(writer);
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut seen = false;
        while Instant::now() < deadline && !seen {
            let observed = connection
                .poll_namespace_observer(Duration::from_millis(50))
                .unwrap();
            assert_eq!(observed.instance(), first_instance);
            assert_eq!(observed.root_identity(), identity);
            assert!(observed.inventory_unknown());
            match observed.poll() {
                ObserverPoll::Batch(NotificationBatch::Hints(hints)) => {
                    seen = hints
                        .iter()
                        .any(|hint| hint.components() == ["Personal", FILE]);
                }
                ObserverPoll::Pending => (),
                _ => panic!("connected observer continuity lost; do not accept partial evidence"),
            }
        }
        assert!(seen, "actual ReadDirectoryChangesW hint missing");
        let mut reader = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x00200000)
            .open(&file)
            .unwrap();
        let before = connection.namespace_observer_fixture_file().unwrap();
        assert_eq!(before.0.volume_serial, identity.volume_serial);
        assert_ne!(before.0.file_index, 0);
        assert_ne!(before.0.file_index, identity.file_index);
        assert_eq!(before.1 & 0x410, 0); // regular, non-reparse
        assert_eq!(before.2 & 9, 0); // no Cloud Files placeholder or IN_SYNC ACK
        assert_eq!(before.3, CONTENT.len() as u64);
        let mut bytes = Vec::new();
        Read::by_ref(&mut reader)
            .take(CONTENT.len() as u64 + 1)
            .read_to_end(&mut bytes)
            .unwrap();
        assert!(bytes == CONTENT, "exact synthetic file bytes required");
        assert_eq!(
            connection.namespace_observer_fixture_file().unwrap(),
            before
        );
        let catalog_scope =
            crate::ProviderIdentityCatalogScope::new(&scope, identity, "drive-personal", "root-id")
                .unwrap();
        let rows = recovery.identity_catalog().load(&catalog_scope).unwrap();
        assert!(rows.iter().all(|row| match row {
            crate::ProviderIdentityBinding::File { path, .. }
            | crate::ProviderIdentityBinding::Directory { path, .. } => !path.ends_with(FILE),
            _ => true,
        }));
        (
            before.0,
            bytes.len(),
            format!("{:x}", sha2::Sha256::digest(&bytes)),
        )
    }));
    // Revocation must prevent polling/rearm but NEVER block physical drain.
    first_backend.revoke();
    assert!(connection.poll_namespace_observer(Duration::ZERO).is_err());
    assert!(connection.attach_namespace_observer().is_err());
    let drained = drain(&mut connection, &directory);
    let disconnected = disconnect(&mut connection, &directory);
    let local_identity = exercise.as_ref().ok().map(|observed| observed.0);
    let mut reconnect_ok = false;
    if exercise.is_ok() && drained && disconnected {
        let lease = crate::pin_registered_configured_root(&path, identity).unwrap();
        let next_backend = backend(client, scope, identity, &recovery);
        let mut next = synthetic_agent_integration::connect(
            lease,
            next_backend,
            "drive-personal",
            "root-id",
            recovery,
        )
        .unwrap();
        let next_observation = next.attach_namespace_observer().unwrap();
        assert_ne!(next_observation.instance(), first_instance);
        assert!(matches!(next_observation.poll(), ObserverPoll::Pending));
        assert_eq!(
            Some(next.namespace_observer_fixture_file().unwrap().0),
            local_identity
        );
        // Exercise finish's own pending-observer cancellation before disconnect.
        reconnect_ok = disconnect(&mut next, &directory);
    }
    let retained = crate::pin_registered_configured_root(&path, identity).is_ok()
        && fixture_pin.verify_path().is_ok()
        && state.verify_path().is_ok()
        && state.path() == state_path.as_path()
        && state_path.exists()
        && std::fs::read(path.join("Personal").join(FILE)).is_ok_and(|b| b == CONTENT);
    let (requests, ranges, range_bytes) = server.finish();
    let passed = exercise.is_ok()
        && drained
        && disconnected
        && reconnect_ok
        && retained
        && ranges == 0
        && range_bytes == 0;
    report(
        &directory.join("RESULTS.json"),
        serde_json::json!({"fixture":"gui-connected-observer-explicit-state-v1","passed":passed,
        "actual_connected_root_verified":true,"hint_and_exact_bytes_fileid":exercise.is_ok(),"same_fileid_reconnect":reconnect_ok,
        "bytes":exercise.as_ref().ok().map(|observed|observed.1),
        "sha256":exercise.as_ref().ok().map(|observed|&observed.2),
        "local_file_id":local_identity.map(|identity|identity.file_index),
        "remote_mutations":0,"metadata_requests":requests,"remote_content_ranges":ranges,"regular_file_not_placeholder_or_in_sync":exercise.is_ok(),
        "inventory_unknown":true,"retired_binding_refused":true,"actual_cancel_drained":drained,"normal_disconnect":disconnected,
        "registration_state_and_bytes_retained":retained,"forced_cleanup":false}),
    );
    assert!(
        passed,
        "connected observer evidence incomplete; no forced cleanup"
    );
}
