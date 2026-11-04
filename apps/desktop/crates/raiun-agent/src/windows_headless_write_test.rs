//! Separate opt-in native write acceptance. Never part of ordinary tests or
//! production startup. Every scenario retains its root, registration and state.
use super::*;
use raiun_cloudfiles_windows::{
    DpapiEditRecordProtector, EditJournal, EditJournalScope, RecoveryAttemptState,
};

const TEST: &str = "agent_windows::windows_profiles::windows_headless_write_test::synthetic_headless_ordinary_save_and_failures";
const DIRECTORY: &str = "RAIUN_HEADLESS_WRITE_FIXTURE_DIR";
const CHILD: &str = "RAIUN_HEADLESS_WRITE_FIXTURE_CHILD";
const OWNER: &str = "raiun-headless-native-write-v1\n";
const ORIGINAL: &[u8] = b"original synthetic placeholder bytes";

struct CaseEvidence {
    detail: Value,
    scope: EditJournalScope,
    root: raiun_cloudfiles_windows::ConfiguredRootIdentity,
    record_id: String,
    provider_scope: raiun_cloudfiles_windows::ProviderScope,
}

fn modified() -> Vec<u8> {
    let mut bytes = ORIGINAL.to_vec();
    bytes[0] ^= 0x5a;
    bytes
}

fn stage(directory: &Path, name: &str) {
    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(directory.join("stages.log"))
        .expect("append owned write-fixture stage");
    writeln!(file, "{name}").unwrap();
    file.flush().unwrap();
}

#[test]
#[ignore = "actual native Cloud Files writes; explicit test-headless-write-windows.ps1 opt-in on the authorized disposable machine only"]
fn synthetic_headless_ordinary_save_and_failures() {
    let directory =
        PathBuf::from(std::env::var_os(DIRECTORY).expect("explicit owned fixture directory"));
    assert!(directory.is_absolute() && directory.is_dir());
    assert_eq!(
        std::fs::read_to_string(directory.join("OWNER.txt")).unwrap(),
        OWNER
    );
    if let Ok(scenario) = std::env::var(CHILD) {
        assert!(matches!(
            scenario.as_str(),
            "success" | "forbidden" | "unavailable"
        ));
        run_child(&directory.join(&scenario), &scenario);
        return;
    }
    assert!(
        std::fs::read_dir(&directory).unwrap().all(|entry| matches!(
            entry.unwrap().file_name().to_str(),
            Some("OWNER.txt" | "runner.json" | "supervisor.stdout.log" | "supervisor.stderr.log")
        )),
        "new fixture directory may contain only runner receipts"
    );
    let mut scenarios = Vec::new();
    let mut passed = true;
    for scenario in ["success", "forbidden", "unavailable"] {
        use super::super::tests::SyntheticOrdinaryWriteMode;
        let case = directory.join(scenario);
        std::fs::create_dir(&case).unwrap();
        std::fs::create_dir(case.join("cloud-root")).unwrap();
        let mode = match scenario {
            "success" => SyntheticOrdinaryWriteMode::Success,
            "forbidden" => SyntheticOrdinaryWriteMode::Forbidden,
            _ => SyntheticOrdinaryWriteMode::Unavailable,
        };
        let (server, fixture) = super::super::tests::synthetic_headless_ordinary_write_server(
            |name| stage(&case, name),
            case.join("failure-armed"),
            mode,
        );
        let config = case.join("headless.json");
        std::fs::write(
            &config,
            serde_json::to_vec(&json!({
                "schema_version":1,"server":server,"auth":"app_token","username":"synthetic-user",
                "mount_path":case.join("cloud-root"),"auto_mount":true,"remember_login":true,
                "reconnect_interval_seconds":1,"profile":"default"
            }))
            .unwrap(),
        )
        .unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                TEST,
                "--nocapture",
                "--test-threads=1",
            ])
            .env(DIRECTORY, &directory)
            .env(CHILD, scenario)
            .env("RAIUN_HEADLESS_CONTEXT", "1")
            .env("RAIUN_STATE_DIR", case.join("state"))
            .env("RAIUN_HEADLESS_CONFIG", config)
            .stdin(std::process::Stdio::null())
            .output()
            .expect("launch exact headless write-fixture child");
        std::fs::write(case.join("child.stdout.log"), &output.stdout).unwrap();
        std::fs::write(case.join("child.stderr.log"), &output.stderr).unwrap();
        let remote = fixture.ordinary_write_snapshot();
        let global_mutations = fixture.global_mutation_attempts();
        let remote_passed = match scenario {
            "success" => {
                remote.put_attempt_count == 1
                    && remote.put_count == 1
                    && remote.verified_readback_count >= 2
                    && remote.range_count > 0
                    && remote.last_put_if_match.as_deref() == Some("\"synthetic-file-v1\"")
                    && remote.last_put_attempt_if_match.as_deref() == Some("\"synthetic-file-v1\"")
                    && remote.last_read_if_match.as_deref() == Some("\"synthetic-file-v2\"")
                    && remote.etag == "\"synthetic-file-v2\""
                    && remote.body == modified()
            }
            "forbidden" => {
                remote.put_attempt_count == 1
                    && remote.forbidden_put_count == 1
                    && remote.put_count == 0
                    && remote.body == ORIGINAL
                    && remote.etag == "\"synthetic-file-v1\""
                    && remote.last_put_attempt_if_match.as_deref() == Some("\"synthetic-file-v1\"")
            }
            _ => {
                remote.put_attempt_count == 0
                    && remote.put_count == 0
                    && remote.unavailable_request_count > 0
                    && remote.body == ORIGINAL
                    && remote.etag == "\"synthetic-file-v1\""
            }
        } && global_mutations == remote.put_attempt_count;
        let child: Value = std::fs::read(case.join("CHILD-RESULTS.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or(Value::Null);
        let case_passed = output.status.success() && child["passed"] == true && remote_passed;
        scenarios.push(
            json!({"scenario":scenario,"passed":case_passed,"child_exit_code":output.status.code(),
            "child":child,"remote":remote,"all_mutation_attempt_count":global_mutations,
            "mutation_diagnostics":fixture.mutation_diagnostics()}),
        );
        passed &= case_passed;
        fixture.join().expect("join exact synthetic write server");
        if !case_passed {
            break;
        }
    }
    std::fs::write(directory.join("RESULTS.json"), serde_json::to_vec_pretty(&json!({
        "fixture":"headless-native-write-v1","passed":passed,"scenarios":scenarios,
        "ordinary_os_writes":true,"explicit_hydration_fallback_used":false,
        "registration_cleanup":"not attempted; roots, registrations, edits and DPAPI state retained",
        "folder_sync_enabled":false,"busy_unmount_acceptance":false,"real_server_acceptance":false
    })).unwrap()).unwrap();
    assert!(
        passed,
        "native write fixture failed; preserve all evidence and inspect scenario receipts"
    );
    println!(
        "synthetic_headless_native_write=passed,conditional_save=true,403_retained=true,transport_retained=true,sync=false,unregister=false"
    );
}

fn run_child(directory: &Path, scenario: &str) {
    let config = crate::headless_runtime::config()
        .unwrap()
        .expect("exact write-fixture config");
    assert!(config.server.starts_with("http://127.0.0.1:"));
    assert_eq!(config.mount_path, directory.join("cloud-root"));
    let broker = WindowsProfiles::open(DpapiSessionStore::current_user().unwrap()).unwrap();
    let runtime = broker.state.lock().unwrap().runtimes["default"].clone();
    runtime
        .provider
        .lifecycle_test_activation
        .store(true, Ordering::Release);
    runtime
        .provider
        .initial_save_test_activation
        .store(true, Ordering::Release);
    let exercise = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<CaseEvidence, String> {
        broker.handle_owned(windows_vault_requests::OwnedControlRequest::new(json!({
            "action":"auth_app_token","required_mode":"mount_only","profile_id":"default",
            "server":config.server,"username":"synthetic-user","app_token":"synthetic-headless-app-token"
        }))).expect("admit exact synthetic credential");
        let deadline = Instant::now() + Duration::from_secs(30);
        while !runtime.state.lock().unwrap().online_authenticated {
            assert!(
                Instant::now() < deadline,
                "synthetic authentication did not complete"
            );
            thread::sleep(Duration::from_millis(20));
        }
        let mount = runtime
            .headless_configured_mount_request()
            .unwrap()
            .unwrap();
        assert_eq!(broker.handle(&mount).unwrap().0["mounted"], true);
        assert_eq!(
            runtime.provider.folder_generation.load(Ordering::Acquire),
            0
        );
        stage(
            directory,
            "ordinary_provider_connected_without_folder_worker",
        );
        let verified = runtime
            .prepare_recovery_context()
            .expect("verify exact current recovery identity");
        let project = verified
            .spaces
            .iter()
            .find(|space| space.id == "synthetic-project-drive")
            .unwrap();
        let root = verified
            .client
            .stat_discovered_space_root_with_context(project, verified.context)
            .unwrap();
        assert_eq!(root.id, "synthetic-project-root");
        assert!(root.directory && root.writable && !root.encrypted);
        let scope = EditJournalScope {
            profile_id: verified.provider_scope.profile_id().into(),
            server_origin: verified.provider_scope.server_origin().into(),
            account_subject: verified.provider_scope.account_id().into(),
            space_id: project.id.clone(),
            root_resource_id: root.id.clone(),
            root_volume_serial: verified.local_root_identity.volume_serial,
            root_file_index: verified.local_root_identity.file_index,
        };
        let local = config
            .mount_path
            .join("Spaces/Projects/RecoveryRoot/document.bin");
        // Read the exact baseline and edit through one ordinary handle. The
        // failure marker is armed only after hydration, before write/close.
        // A second dirty read-close must not fabricate another edit snapshot.
        os_file(directory, &local)?;
        stage(directory, "ordinary_os_baseline_read_exact");
        stage(directory, "ordinary_os_write_flush_close_complete");
        let protector = DpapiEditRecordProtector::current_user().unwrap();
        let journal = EditJournal::open(
            protector.local_state_directory(),
            scope.clone(),
            protector.clone(),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        let snapshot = loop {
            let snapshot = journal
                .recover_all()
                .expect("authenticate retained DPAPI journal");
            assert!(
                snapshot.records.len() <= 1,
                "unexpected extra records are preserved"
            );
            if let Some(record) = snapshot.records.first() {
                assert_eq!(record.metadata.scope, scope);
                assert_eq!(record.metadata.relative_path, "RecoveryRoot/document.bin");
                assert_eq!(record.content, modified());
                let state = snapshot.recovery_states.get(&record.metadata.record_id);
                let complete = match scenario {
                    "success" => {
                        matches!(
                            state,
                            Some(RecoveryAttemptState::VerifiedApplied {
                                attempt_id: 1,
                                attempts: 1
                            })
                        ) && !verified.recovery_provider.has_unresolved_edits().unwrap()
                    }
                    "forbidden" => matches!(
                        state,
                        Some(RecoveryAttemptState::Deferred {
                            attempt_id: 1,
                            attempts: 1
                        })
                    ),
                    _ => {
                        state.is_none()
                            && runtime
                                .provider
                                .initial_save_test_observation
                                .lock()
                                .unwrap()
                                .as_ref()
                                .is_some_and(|message| message.starts_with("error:"))
                    }
                };
                if complete {
                    break snapshot;
                }
            }
            assert!(
                Instant::now() < deadline,
                "ordinary save did not reach expected durable outcome; preserve evidence"
            );
            thread::sleep(Duration::from_millis(50));
        };
        let observation = runtime
            .provider
            .read_only_placeholder_observation(
                super::super::NativeRestartProbePath::RecoveryDocument,
            )
            .unwrap();
        let (_, _, flags, size) = observation
            .2
            .expect("read exact placeholder OS flags without hydration");
        assert_eq!(size, modified().len() as u64);
        assert_eq!(
            flags & 0x8 != 0,
            scenario == "success",
            "native IN_SYNC must reflect verified completion only"
        );
        let record = &snapshot.records[0];
        let unresolved = verified.recovery_provider.has_unresolved_edits().unwrap();
        assert_eq!(unresolved, scenario != "success");
        stage(directory, "dpapi_body_and_native_completion_state_verified");
        Ok(CaseEvidence {
            detail: json!({"record_count":snapshot.records.len(),"locally_completed":!unresolved,
                "native_in_sync":flags & 0x8 != 0,"native_size":size,"journal_scope_verified":true}),
            scope,
            root: verified.local_root_identity,
            record_id: record.metadata.record_id.clone(),
            provider_scope: verified.provider_scope.clone(),
        })
    })).unwrap_or_else(|_| Err("native write assertion failed; evidence retained".into()));
    // Always attempt the ordinary lifecycle even after a failed assertion.
    // Never unregister, delete, force-stop a process or claim cleanup on error.
    let unmount = broker
        .handle(&json!({"action":"unmount","required_mode":"mount_only","profile_id":"default"}));
    if unmount.is_ok() {
        stage(directory, "safe_unmount_complete_registration_retained");
    }
    let stopped = broker.stop_all();
    if stopped.is_ok() {
        stage(directory, "normal_broker_shutdown_complete");
    }
    let mut retained = false;
    let mut registration_retained = false;
    let mut journal_retained = false;
    if let Ok(evidence) = &exercise
        && unmount.is_ok()
        && stopped.is_ok()
    {
        retained = std::fs::read(
            config
                .mount_path
                .join("Spaces/Projects/RecoveryRoot/document.bin"),
        )
        .is_ok_and(|bytes| bytes == modified());
        registration_retained =
            pin_registered_configured_root(&config.mount_path, evidence.root).is_ok();
        if let Ok(protector) = DpapiEditRecordProtector::current_user()
            && let Ok(journal) = EditJournal::open(
                protector.local_state_directory(),
                evidence.scope.clone(),
                protector.clone(),
            )
            && let Ok(snapshot) = journal.recover_all()
            && let Ok(recovery) =
                raiun_cloudfiles_windows::DurableEditRecoveryProvider::current_user(
                    evidence.provider_scope.clone(),
                    evidence.root,
                )
            && let Ok(unresolved) = recovery.has_unresolved_edits()
        {
            journal_retained = snapshot.records.len() == 1
                && snapshot.records[0].metadata.record_id == evidence.record_id
                && snapshot.records[0].metadata.scope == evidence.scope
                && snapshot.records[0].content == modified()
                && unresolved == (scenario != "success")
                && match scenario {
                    "success" => matches!(
                        snapshot.recovery_states.get(&evidence.record_id),
                        Some(RecoveryAttemptState::VerifiedApplied {
                            attempt_id: 1,
                            attempts: 1
                        })
                    ),
                    "forbidden" => matches!(
                        snapshot.recovery_states.get(&evidence.record_id),
                        Some(RecoveryAttemptState::Deferred {
                            attempt_id: 1,
                            attempts: 1
                        })
                    ),
                    _ => !snapshot.recovery_states.contains_key(&evidence.record_id),
                };
        }
    }
    let passed = exercise.is_ok()
        && unmount.is_ok()
        && stopped.is_ok()
        && retained
        && registration_retained
        && journal_retained;
    let detail = exercise
        .as_ref()
        .ok()
        .map(|evidence| evidence.detail.clone())
        .unwrap_or(Value::Null);
    std::fs::write(directory.join("CHILD-RESULTS.json"),serde_json::to_vec_pretty(&json!({
        "passed":passed,"scenario":scenario,"detail":detail,"safe_unmount":unmount.is_ok(),
        "exercise_error":exercise.as_ref().err(),
        "normal_shutdown":stopped.is_ok(),"edited_bytes_retained_after_disconnect":retained,
        "exact_registration_retained":registration_retained,"dpapi_journal_retained_after_disconnect":journal_retained,
        "registration_cleanup":"not attempted","folder_generation":runtime.provider.folder_generation.load(Ordering::Acquire)
    })).unwrap()).unwrap();
    assert!(
        passed,
        "write scenario failed; exact root/state and all child evidence remain retained"
    );
}

fn os_file(directory: &Path, path: &Path) -> Result<(), String> {
    let script = r#"$ErrorActionPreference='Stop'; try {
$p=$env:RAIUN_WRITE_FILE
$expected=[Text.Encoding]::UTF8.GetBytes('original synthetic placeholder bytes')
foreach($dir in @((Join-Path $env:RAIUN_WRITE_ROOT 'Spaces'),(Join-Path $env:RAIUN_WRITE_ROOT 'Spaces\Projects'),(Join-Path $env:RAIUN_WRITE_ROOT 'Spaces\Projects\RecoveryRoot'))){$null=[IO.Directory]::GetFileSystemEntries($dir)}
$f=[IO.File]::Open($p,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read)
try{
 $b=New-Object byte[] $expected.Length; $offset=0
 while($offset -lt $b.Length){$n=$f.Read($b,$offset,$b.Length-$offset); if($n -le 0){throw 'short baseline'}; $offset+=$n}
 if($f.Length -ne $b.Length -or [Convert]::ToBase64String($b) -cne [Convert]::ToBase64String($expected)){throw 'baseline mismatch'}
 [Console]::WriteLine('ordinary_os_baseline_exact=true')
 [IO.File]::WriteAllText($env:RAIUN_WRITE_ARM,"armed`n")
 $b[0]=$b[0] -bxor 0x5a; $null=$f.Seek(0,[IO.SeekOrigin]::Begin); $f.Write($b,0,$b.Length); $f.Flush($true)
}finally{$f.Dispose()}
[Console]::WriteLine('ordinary_os_write_flush_close=true'); exit 0
}catch{[Console]::WriteLine(('ordinary_file_failed_hresult={0}' -f $_.Exception.HResult)); exit 24}"#;
    let stdout_path = directory.join("edit.stdout.log");
    let stderr_path = directory.join("edit.stderr.log");
    let new_log = |path: &Path| {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|_| "cannot create owned ordinary OS client log".to_owned())
    };
    let stdout = new_log(&stdout_path)?;
    let stderr = new_log(&stderr_path)?;
    stage(directory, "ordinary_os_client_spawn_begin");
    let mut child = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .env("RAIUN_WRITE_FILE", path)
        .env("RAIUN_WRITE_ROOT", directory.join("cloud-root"))
        .env("RAIUN_WRITE_ARM", directory.join("failure-armed"))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(stdout))
        .stderr(std::process::Stdio::from(stderr))
        .spawn()
        .map_err(|_| "cannot launch ordinary OS client".to_owned())?;
    let pid = child.id();
    let timeout = Duration::from_secs(45);
    let deadline = Instant::now() + timeout;
    let receipt =
        |state: &str, exit_code: Option<i32>| {
            std::fs::write(directory.join("OS-CLIENT.json"), serde_json::to_vec_pretty(&json!({
            "pid":pid,"state":state,"exit_code":exit_code,"timeout_seconds":timeout.as_secs(),
            "stdout":"edit.stdout.log","stderr":"edit.stderr.log","forced_stop":false,
            "registration_cleanup":"not attempted; exact root/state and client logs retained"
        })).expect("fixed ordinary OS client receipt is serializable"))
            .map_err(|_| "cannot retain ordinary OS client PID receipt".to_owned())
        };
    stage(directory, &format!("ordinary_os_client_started_pid_{pid}"));
    receipt("running", None)?;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                receipt("timed_out_child_retained", None)?;
                stage(
                    directory,
                    &format!("ordinary_os_client_timeout_retained_pid_{pid}"),
                );
                // Dropping Child does not kill or join it. Propagate failure
                // before assertions so the caller still attempts normal
                // unmount/shutdown while retaining every byte and the PID.
                return Err(format!(
                    "ordinary OS client exceeded 45 seconds; PID {pid} retained without forced stop"
                ));
            }
            Err(_) => {
                receipt("wait_failed_child_retained", None)?;
                return Err(format!(
                    "ordinary OS client wait failed; PID {pid} retained without forced stop"
                ));
            }
        }
    };
    receipt("exited", status.code())?;
    stage(directory, "ordinary_os_client_exited");
    if !status.success() {
        return Err("ordinary OS file operation failed; no retry or hydration fallback".into());
    }
    let markers = std::fs::read_to_string(stdout_path)
        .map_err(|_| "cannot read retained OS client markers")?;
    if !markers
        .lines()
        .any(|line| line == "ordinary_os_baseline_exact=true")
        || !markers
            .lines()
            .any(|line| line == "ordinary_os_write_flush_close=true")
    {
        return Err(
            "ordinary OS file client omitted an exact baseline or write/flush/close marker".into(),
        );
    }
    Ok(())
}
