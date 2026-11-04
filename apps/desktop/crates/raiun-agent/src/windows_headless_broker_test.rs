//! Public broker gates run before registry mutation or credential decoding.
use super::*;

#[test]
fn headless_broker_refuses_mutation_before_resolve_and_reports_empty_status() {
    const CHILD: &str = "RAIUN_HEADLESS_BROKER_POLICY_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).unwrap();
        let suffix = nonce
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let directory = std::env::temp_dir().join(format!("raiun-headless-broker-policy-{suffix}"));
        std::fs::create_dir(&directory).unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "agent_windows::windows_profiles::windows_headless_broker_test::headless_broker_refuses_mutation_before_resolve_and_reports_empty_status", "--nocapture"])
            .env(CHILD, "1")
            .env("RAIUN_HEADLESS_CONTEXT", "1")
            .env_remove("RAIUN_HEADLESS_CONFIG")
            .env("RAIUN_STATE_DIR", directory.join("state"))
            .stdin(std::process::Stdio::null())
            .output().unwrap();
        assert!(
            output.status.success(),
            "isolated child failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        std::fs::remove_dir_all(directory).unwrap();
        return;
    }
    let storage = DpapiSessionStore::current_user().unwrap();
    let broker = WindowsProfiles::open(storage.clone()).unwrap();
    let registry_before = storage.load_profile_registry().unwrap();
    for request in [
        json!({"action":"account_add","label":"synthetic","required_mode":"desktop"}),
        json!({"action":"account_remove","profile_id":"default","confirm":true}),
        json!({"action":"pair_add","profile_id":"default"}),
        json!({"action":"media_job_set","profile_id":"default"}),
        json!({"action":"vault_unlock","profile_id":"default","password":"synthetic"}),
        json!({"action":"autostart_set","enabled":true}),
    ] {
        assert!(
            broker
                .handle_owned(windows_vault_requests::OwnedControlRequest::new(request))
                .is_err()
        );
        assert_eq!(storage.load_profile_registry().unwrap(), registry_before);
    }
    let status = broker.handle(&json!({"action":"status"})).unwrap().0;
    assert_eq!(status["runtime_mode"], "mount_only");
    assert_eq!(status["credential_storage"], "memory_only");
    assert_eq!(status["folder_sync_enabled"], false);
    assert_eq!(status["connected"], false);
    assert_eq!(status["mounted"], false);
    let accounts = broker.handle(&json!({"action":"accounts"})).unwrap().0;
    assert_eq!(accounts["account_removal_supported"], false);
    assert_eq!(
        accounts["items"][0]["status"]["credential_storage"],
        "memory_only"
    );
    // Exercise the separate empty-registry response shape without permitting
    // account removal through the mount-only control interface.
    {
        let mut state = broker.state.lock().unwrap();
        state.registry = state.registry.with_retired("default", None).unwrap();
    }
    let empty = broker.handle(&json!({"action":"status"})).unwrap().0;
    assert_eq!(empty["accounts_empty"], true);
    assert_eq!(empty["runtime_mode"], "mount_only");
    assert_eq!(empty["credential_storage"], "memory_only");
    assert_eq!(empty["folder_sync_enabled"], false);
    assert_eq!(empty["media_jobs_supported"], false);
    broker.stop_all().unwrap();
}

/// Real DPAPI custody with synthetic read-only HTTP and separate same-user
/// processes. Mounting stays disabled except a queued request explicitly
/// cancelled before dispatch; no Cloud Files registration is attempted.
#[test]
fn configured_app_token_survives_restart_rejects_mismatch_and_logout_removes_it() {
    use std::io::{BufRead, BufReader};
    const PHASE: &str = "RAIUN_HEADLESS_APP_TOKEN_FIXTURE_PHASE";
    const TEST: &str = "agent_windows::windows_profiles::windows_headless_broker_test::configured_app_token_survives_restart_rejects_mismatch_and_logout_removes_it";
    const TOKEN: &str = "synthetic-headless-app-token";
    if let Some(phase) = std::env::var_os(PHASE) {
        let config = crate::headless_runtime::config().unwrap().unwrap();
        let stale_automatic = phase == "stale-auto";
        assert_eq!(config.auto_mount, stale_automatic);
        assert_eq!(config.remember_login, phase != "forget-logout");
        let storage = DpapiSessionStore::current_user().unwrap();
        let raw = storage.for_profile("default").unwrap();
        let broker = WindowsProfiles::open(storage).unwrap();
        let runtime = broker.state.lock().unwrap().runtimes["default"].clone();
        assert_eq!(
            *runtime.provider.mount_preference.lock().unwrap(),
            stale_automatic
        );
        assert!(runtime.state.lock().unwrap().root_configuration.is_none());
        if phase == "forget-logout" || phase == "after-forget" {
            // Disabling persistence must suppress restore, while explicit
            // logout still removes the exact previously remembered identity.
            let state = runtime.state.lock().unwrap();
            assert!(state.session.is_none());
            assert!(!state.online_authenticated);
            drop(state);
            if phase == "forget-logout" {
                assert!(raw.active_identity().unwrap().is_some());
                assert!(
                    raw.load(Some("default"), &config.server, auth::APP_TOKEN_CLIENT_ID)
                        .unwrap()
                        .is_some()
                );
                let result = broker
                    .handle(&json!({"action":"logout","profile_id":"default"}))
                    .unwrap()
                    .0;
                assert_eq!(result["logged_out"], true);
                assert_eq!(result["session_cleanup_uncertain"], false);
            }
            assert!(raw.active_identity().unwrap().is_none());
            assert!(
                raw.load(Some("default"), &config.server, auth::APP_TOKEN_CLIENT_ID)
                    .unwrap()
                    .is_none()
            );
            broker.refresh_all().unwrap();
            assert!(runtime.state.lock().unwrap().session.is_none());
            assert!(!runtime.provider.is_connected());
            broker.stop_all().unwrap();
            return;
        }
        if stale_automatic {
            // Admit only enough synthetic state to queue the auto operation;
            // no provider or HTTP operation is necessary for this race check.
            {
                let mut state = runtime.state.lock().unwrap();
                state.online_authenticated = true;
                state.needs_refresh = false;
            }
            let request = runtime
                .headless_configured_mount_request()
                .unwrap()
                .unwrap();
            assert_eq!(request["automatic_mount"], true);
            runtime.headless_unmount().unwrap();
            assert!(broker.handle(&request).is_err());
            assert!(!*runtime.provider.mount_preference.lock().unwrap());
            assert!(!runtime.provider.is_connected());
            assert!(runtime.state.lock().unwrap().root_configuration.is_none());
            broker.stop_all().unwrap();
            return;
        }
        if phase == "mismatch" {
            let state = runtime.state.lock().unwrap();
            assert!(state.session.is_none());
            assert!(!state.online_authenticated);
            drop(state);
            assert!(raw.active_identity().unwrap().is_some());
            assert!(
                raw.load(Some("default"), &config.server, auth::APP_TOKEN_CLIENT_ID)
                    .unwrap()
                    .is_some()
            );
            broker.stop_all().unwrap();
            return;
        }
        if phase == "login" || phase == "login-again" {
            assert!(runtime.state.lock().unwrap().session.is_none());
            let request = json!({"action":"auth_app_token","required_mode":"mount_only", "profile_id":"default", "server":config.server,"username":config.username,"app_token":TOKEN});
            let started = broker
                .handle_owned(windows_vault_requests::OwnedControlRequest::new(request))
                .unwrap()
                .0;
            assert_eq!(
                started["auth_generation"].as_u64(),
                Some(runtime.state.lock().unwrap().active_generation)
            );
        } else {
            // Startup restored the credential but has not claimed online
            // admission until the same Graph/DAV verification succeeds again.
            let state = runtime.state.lock().unwrap();
            assert!(state.session.as_ref().is_some_and(|session| {
                session.app_token_username.as_deref() == Some("synthetic-user")
            }));
            assert!(!state.online_authenticated);
            drop(state);
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            broker.refresh_all().unwrap();
            let state = runtime.state.lock().unwrap();
            if state.online_authenticated {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "synthetic login did not reach verified online state"
            );
            drop(state);
            thread::sleep(Duration::from_millis(20));
        }
        let saved = raw
            .load(Some("default"), &config.server, auth::APP_TOKEN_CLIENT_ID)
            .unwrap()
            .unwrap();
        let session: auth::Session = serde_json::from_slice(&saved).unwrap();
        assert_eq!(session.access_token, TOKEN);
        assert_eq!(
            session.app_token_username.as_deref(),
            Some("synthetic-user")
        );
        assert!(session.refresh_token.is_none());
        assert!(session.token_endpoint.is_empty());
        assert!(!runtime.provider.is_connected());
        let status = broker
            .handle(&json!({"action":"status","profile_id":"default"}))
            .unwrap()
            .0;
        assert_eq!(status["credential_storage"], "windows_dpapi");
        assert_eq!(status["folder_sync_enabled"], false);
        assert!(!serde_json::to_string(&status).unwrap().contains(TOKEN));
        if phase == "restore-logout" {
            broker
                .handle(&json!({"action":"logout","profile_id":"default"}))
                .unwrap();
            assert!(raw.active_identity().unwrap().is_none());
            assert!(
                raw.load(Some("default"), &config.server, auth::APP_TOKEN_CLIENT_ID)
                    .unwrap()
                    .is_none()
            );
        }
        broker.stop_all().unwrap();
        return;
    }

    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).unwrap();
    let suffix = nonce
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let directory = std::env::temp_dir().join(format!("raiun-headless-app-token-{suffix}"));
    std::fs::create_dir(&directory).unwrap();
    std::fs::create_dir(directory.join("unused-drive")).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = format!("http://{}", listener.local_addr().unwrap());
    let stopping = Arc::new(AtomicBool::new(false));
    let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let worker_stop = stopping.clone();
    let worker_requests = requests.clone();
    let worker_server = server.clone();
    let worker = thread::spawn(move || {
        use base64::Engine as _;
        let authorization = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("synthetic-user:{TOKEN}"))
        );
        while !worker_stop.load(Ordering::Acquire) {
            let (mut stream, _) = match listener.accept() {
                Ok(connection) => connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(_) => panic!("synthetic listener failed"),
            };
            // Accepted sockets must match this fixture's blocking read/write
            // contract; the listener stays nonblocking for bounded shutdown.
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut reader = BufReader::new(&stream);
            let mut first = String::new();
            reader.read_line(&mut first).unwrap();
            let mut length = 0;
            let mut authenticated = false;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                let Some((name, value)) = line.split_once(':') else {
                    panic!("invalid synthetic request header");
                };
                if name.eq_ignore_ascii_case("authorization") {
                    authenticated = value.trim() == authorization;
                }
                if name.eq_ignore_ascii_case("content-length") {
                    length = value.trim().parse::<usize>().unwrap();
                }
                assert!(length < 8192);
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            drop(reader);
            assert!(
                authenticated,
                "synthetic app-token request must use Basic authentication"
            );
            worker_requests.fetch_add(1, Ordering::AcqRel);
            let (status, body) = if first.starts_with("GET /graph/v1.0/me HTTP/") {
                ("200 OK", r#"{"id":"synthetic-user"}"#.to_owned())
            } else if first.starts_with("GET /graph/v1.0/me/drives HTTP/") {
                (
                    "200 OK",
                    format!(
                        r#"{{"value":[{{"id":"synthetic-space","name":"Personal","driveType":"personal","root":{{"id":"synthetic-space!root","webDavUrl":"{worker_server}/dav/spaces/synthetic-space/"}}}}]}}"#
                    ),
                )
            } else if first.starts_with("PROPFIND /dav/spaces/synthetic-space/ HTTP/") {
                ("207 Multi-Status", r#"<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>/dav/spaces/synthetic-space/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getetag>"synthetic-etag"</d:getetag><oc:fileid>synthetic-space!root</oc:fileid><oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#.to_owned())
            } else {
                panic!("synthetic fixture permits Graph identity, drives and DAV metadata only");
            };
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        }
    });
    let config_path = directory.join("headless.json");
    for phase in [
        "login",
        "stale-auto",
        "mismatch",
        "restore-logout",
        "login-again",
        "forget-logout",
        "after-forget",
    ] {
        let username = if phase == "mismatch" {
            "different-synthetic-user"
        } else {
            "synthetic-user"
        };
        let config = json!({"schema_version":1,"server":server,"auth":"app_token","username":username,"mount_path":directory.join("unused-drive"),"auto_mount":phase == "stale-auto","remember_login":phase != "forget-logout","profile":"default","reconnect_interval_seconds":1});
        let config_bytes = serde_json::to_vec(&config).unwrap();
        assert!(!String::from_utf8_lossy(&config_bytes).contains(TOKEN));
        std::fs::write(&config_path, config_bytes).unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env(PHASE, phase)
            .env("RAIUN_HEADLESS_CONTEXT", "1")
            .env("RAIUN_STATE_DIR", directory.join("state"))
            .env("RAIUN_HEADLESS_CONFIG", &config_path)
            .env("NO_PROXY", "127.0.0.1,localhost")
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "isolated synthetic phase failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    stopping.store(true, Ordering::Release);
    worker.join().unwrap();
    assert_eq!(
        requests.load(Ordering::Acquire),
        9,
        "two logins and one remembered restart verify Graph identity/drives and DAV root; logout with persistence disabled prevents another restore"
    );
    std::fs::remove_dir_all(directory).unwrap();
}
