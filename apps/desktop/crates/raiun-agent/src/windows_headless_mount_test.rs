//! Explicit native acceptance only. This module is a child of windows_profiles;
//! ordinary tests skip it and production code has no activation entry point.
use super::*;

const TEST: &str = "agent_windows::windows_profiles::windows_headless_mount_test::synthetic_headless_personal_and_space_hydration";
const DIRECTORY: &str = "RAIUN_HEADLESS_NATIVE_FIXTURE_DIR";
const CHILD: &str = "RAIUN_HEADLESS_NATIVE_FIXTURE_CHILD";
const TOKEN: &str = "synthetic-headless-app-token";

fn stage(directory: &Path, name: &str) {
    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(directory.join("stages.log"))
        .expect("append exact fixture stage");
    let phase = std::env::var(CHILD).unwrap_or_else(|_| "supervisor".into());
    writeln!(file, "{phase}:{name}").expect("write exact fixture stage");
    file.flush().expect("flush exact fixture stage");
}

#[test]
#[ignore = "actual native Cloud Files mount; run only through test-headless-mount-windows.ps1 on the authorized disposable Windows machine"]
fn synthetic_headless_personal_and_space_hydration() {
    let directory = PathBuf::from(
        std::env::var_os(DIRECTORY)
            .expect("explicit fixture runner supplies a new owned directory"),
    );
    assert!(directory.is_absolute() && directory.is_dir());
    assert_eq!(
        std::fs::read_to_string(directory.join("OWNER.txt")).expect("runner ownership receipt"),
        "raiun-headless-native-mount-v1\n"
    );
    if std::env::var_os(CHILD).is_none() {
        assert!(
            std::fs::read_dir(&directory).unwrap().all(|entry| {
                matches!(
                    entry.unwrap().file_name().to_str(),
                    Some(
                        "OWNER.txt"
                            | "runner.json"
                            | "supervisor.stdout.log"
                            | "supervisor.stderr.log"
                    )
                )
            }),
            "fixture directory must contain only its fresh runner receipts"
        );
        let mount = directory.join("cloud-root");
        std::fs::create_dir(&mount).unwrap();
        let (server, fixture) =
            super::super::tests::synthetic_headless_personal_spaces_server(|name| {
                stage(&directory, name)
            });
        let config = directory.join("headless.json");
        std::fs::write(
            &config,
            serde_json::to_vec(&json!({
                "schema_version":1,"server":server,"auth":"app_token","username":"synthetic-user",
                "mount_path":mount,"auto_mount":true,"remember_login":true,
                "reconnect_interval_seconds":1,"profile":"default"
            }))
            .unwrap(),
        )
        .unwrap();
        stage(&directory, "supervisor_spawn_headless_child");
        let mut phase_results = Vec::new();
        let mut passed = true;
        for phase in ["login", "restart"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    TEST,
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD, phase)
                .env(DIRECTORY, &directory)
                .env("RAIUN_HEADLESS_CONTEXT", "1")
                .env("RAIUN_STATE_DIR", directory.join("state"))
                .env("RAIUN_HEADLESS_CONFIG", &config)
                .stdin(std::process::Stdio::null())
                .output()
                .expect("launch exact isolated fixture child");
            std::fs::write(
                directory.join(format!("{phase}.child.stdout.log")),
                &output.stdout,
            )
            .unwrap();
            std::fs::write(
                directory.join(format!("{phase}.child.stderr.log")),
                &output.stderr,
            )
            .unwrap();
            let (personal, project, mismatch, mutations) = fixture.read_counts();
            let markers = std::fs::read_to_string(directory.join("stages.log")).unwrap();
            let shutdown_marker = format!("{phase}:normal_broker_shutdown_complete");
            let read_marker = format!("{phase}:ordinary_os_reads_exact");
            let completed = markers.lines().any(|line| line == shutdown_marker)
                && markers.lines().any(|line| line == read_marker);
            let phase_passed = output.status.success()
                && completed
                && (phase != "login" || (personal > 0 && project > 0))
                && mismatch == 0
                && mutations == 0;
            phase_results.push(json!({"phase":phase,"passed":phase_passed,"child_exit_code":output.status.code(),"personal_get_total":personal,"space_get_total":project}));
            passed &= phase_passed;
            if !phase_passed {
                break;
            }
        }
        let (personal_get, project_get, etag_mismatch, mutations) = fixture.read_counts();
        std::fs::write(directory.join("RESULTS.json"), serde_json::to_vec_pretty(&json!({
            "fixture":"headless-native-read-v1","passed":passed,"phases":phase_results,
            "personal_get_count":personal_get,"space_get_count":project_get,
            "etag_mismatch_count":etag_mismatch,"mutation_attempt_count":mutations,
            "ordinary_os_read_only":true,"explicit_hydration_fallback_used":false,
            "registration_cleanup":if passed { "not_attempted; task-owned root disconnected and retained" } else { "not_attempted; root/state preserved; disconnection not assumed" },
            "boot_session_zero_acceptance":false,"server_core_acceptance":false,"writes_acceptance":false
        })).unwrap()).unwrap();
        fixture.join().expect("join exact synthetic server");
        assert!(
            passed,
            "native fixture failed; inspect retained RESULTS.json, stages and child logs"
        );
        println!(
            "synthetic_headless_native_read=passed,personal_and_space=true,mutations=0,boot_acceptance=false,registration_retained=true"
        );
        return;
    }

    let config = crate::headless_runtime::config()
        .unwrap()
        .expect("exact fixture config");
    assert!(config.server.starts_with("http://127.0.0.1:"));
    assert_eq!(config.mount_path, directory.join("cloud-root"));
    assert_eq!(config.username.as_deref(), Some("synthetic-user"));
    let storage =
        DpapiSessionStore::current_user().expect("real isolated current-user DPAPI store");
    let broker = WindowsProfiles::open(storage).expect("open exact isolated broker");
    let runtime = broker.state.lock().unwrap().runtimes["default"].clone();
    // This ignored fixture is the only opt-in. It is a per-instance test field,
    // never a production environment/configuration activation bypass.
    runtime
        .provider
        .lifecycle_test_activation
        .store(true, Ordering::Release);
    stage(&directory, "broker_ready_native_test_instance_activated");
    let phase = std::env::var(CHILD).expect("phase is supplied");
    if phase == "login" {
        assert!(runtime.state.lock().unwrap().session.is_none());
        let started = broker
            .handle_owned(windows_vault_requests::OwnedControlRequest::new(json!({
                "action":"auth_app_token","required_mode":"mount_only","profile_id":"default",
                "server":config.server,"username":"synthetic-user","app_token":TOKEN
            })))
            .expect("admit synthetic loopback app credential")
            .0;
        assert!(started.get("auth_generation").is_some());
    } else {
        assert_eq!(phase, "restart");
        let state = runtime.state.lock().unwrap();
        assert!(
            state.session.is_some(),
            "restart must restore the synthetic DPAPI session"
        );
        assert!(
            state.root_configuration.is_some(),
            "restart must restore exact root metadata"
        );
        assert!(!state.online_authenticated);
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if phase == "restart" {
            broker
                .refresh_all()
                .expect("normal restore/verify/automount tick");
        }
        let state = runtime.state.lock().unwrap();
        if state.online_authenticated && (phase == "login" || runtime.provider.is_connected()) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "synthetic app-token verification or restart automount did not complete"
        );
        drop(state);
        thread::sleep(Duration::from_millis(20));
    }
    stage(&directory, "synthetic_app_token_verified");
    let late_automatic = if phase == "login" {
        let automatic = runtime
            .headless_configured_mount_request()
            .unwrap()
            .expect("configured automatic mount request");
        let result = broker
            .handle(&automatic)
            .expect("normal broker mounts exact configured synthetic root")
            .0;
        assert_eq!(result["mounted"], true);
        automatic
    } else {
        stage(
            &directory,
            "restart_restored_dpapi_and_automounted_without_explicit_mount",
        );
        json!({"action":"mount","required_mode":"mount_only","profile_id":"default","automatic_mount":true,"expected_generation":runtime.state.lock().unwrap().active_generation})
    };
    assert!(runtime.provider.is_connected());
    assert_eq!(
        runtime.provider.folder_generation.load(Ordering::Acquire),
        0
    );
    stage(&directory, "headless_broker_native_mount_connected");

    // A separate ordinary process triggers Cloud Files callbacks. Explicit
    // CfHydratePlaceholder fallbacks are intentionally not used by this test.
    use base64::Engine as _;
    let script = r#"$ErrorActionPreference='Stop'; try {
$names=@([IO.Directory]::GetFileSystemEntries($env:RAIUN_FIXTURE_ROOT)|ForEach-Object{[IO.Path]::GetFileName($_)}|Sort-Object)
if(($names -join ',') -cne 'Personal,Spaces'){throw 'synthetic namespace mismatch'}
$null=[IO.Directory]::GetFileSystemEntries((Join-Path $env:RAIUN_FIXTURE_ROOT 'Personal'))
$null=[IO.Directory]::GetFileSystemEntries((Join-Path $env:RAIUN_FIXTURE_ROOT 'Spaces'))
$null=[IO.Directory]::GetFileSystemEntries((Join-Path $env:RAIUN_FIXTURE_ROOT 'Spaces\Projects'))
$personal=[Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $env:RAIUN_FIXTURE_ROOT 'Personal\native-read.bin')))
if($personal -cne $env:RAIUN_EXPECT_PERSONAL){throw 'synthetic Personal bytes mismatch'}
$space=[Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $env:RAIUN_FIXTURE_ROOT 'Spaces\Projects\native-read.bin')))
if($space -cne $env:RAIUN_EXPECT_SPACE){throw 'synthetic Space bytes mismatch'}
[Console]::WriteLine('ordinary_os_personal_and_space_exact=true'); exit 0
} catch { [Console]::WriteLine(('native_read_failed_hresult={0}' -f $_.Exception.HResult)); exit 24 }"#;
    let read = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .env("RAIUN_FIXTURE_ROOT", &config.mount_path)
        .env(
            "RAIUN_EXPECT_PERSONAL",
            base64::engine::general_purpose::STANDARD
                .encode(b"synthetic Personal native read bytes"),
        )
        .env(
            "RAIUN_EXPECT_SPACE",
            base64::engine::general_purpose::STANDARD
                .encode(b"synthetic Projects Space native read bytes"),
        )
        .stdin(std::process::Stdio::null())
        .output()
        .expect("ordinary read-only OS child");
    std::fs::write(
        directory.join(format!("{phase}.os-read.stdout.log")),
        &read.stdout,
    )
    .unwrap();
    std::fs::write(
        directory.join(format!("{phase}.os-read.stderr.log")),
        &read.stderr,
    )
    .unwrap();
    stage(
        &directory,
        if read.status.success() {
            "ordinary_os_reads_exact"
        } else {
            "ordinary_os_reads_failed"
        },
    );
    // Even a failed ordinary read must attempt the normal safe disconnect.
    let root_before = runtime.state.lock().unwrap().root_configuration.clone();
    let unmount = broker
        .handle(&json!({"action":"unmount","required_mode":"mount_only","profile_id":"default"}));
    if unmount.is_ok() {
        assert!(!runtime.provider.is_connected());
        assert_eq!(
            runtime.state.lock().unwrap().root_configuration,
            root_before
        );
        stage(&directory, "safe_unmount_complete_registration_preserved");
        assert!(
            broker.handle(&late_automatic).is_err(),
            "queued automatic mount must stay cancelled after unmount"
        );
        broker.refresh_all().expect("normal refresh after unmount");
        assert!(!runtime.provider.is_connected());
        assert!(
            runtime
                .headless_configured_mount_request()
                .unwrap()
                .is_none()
        );
        stage(&directory, "late_automatic_mount_refused");
    }
    let stopped = broker.stop_all();
    if stopped.is_ok() {
        stage(&directory, "normal_broker_shutdown_complete");
    }
    assert!(
        unmount.is_ok(),
        "safe unmount failed; preserve exact root, registration and evidence"
    );
    assert!(
        stopped.is_ok(),
        "normal broker shutdown failed; preserve evidence"
    );
    assert!(
        read.status.success(),
        "ordinary native read failed; no hydration fallback was used"
    );
}
