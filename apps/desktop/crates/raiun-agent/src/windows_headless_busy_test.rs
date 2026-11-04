//! Opt-in Personal save and open-writer retained-disconnect acceptance.
//! Independent of the accepted C8 fixtures; all native objects remain retained.
use super::*;
use raiun_cloudfiles_windows::{DpapiEditRecordProtector, EditJournal, EditJournalScope};
use std::io::{Read, Seek, SeekFrom, Write};

const TEST: &str = "agent_windows::windows_profiles::windows_headless_busy_test::personal_save_and_open_writer_retained_disconnect";
const DIRECTORY: &str = "RAIUN_HEADLESS_BUSY_FIXTURE_DIR";
const ROLE: &str = "RAIUN_HEADLESS_BUSY_FIXTURE_CHILD";
const ORIGINAL: &[u8] = b"original synthetic placeholder bytes";

fn edited() -> Vec<u8> {
    let mut bytes = ORIGINAL.to_vec();
    bytes[0] ^= 0x5a;
    bytes
}
fn receipt(path: &Path, value: Value) {
    std::fs::write(path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
}
fn stage(directory: &Path, name: &str) {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(directory.join("stages.log"))
        .unwrap();
    writeln!(file, "{name}").unwrap();
    file.sync_all().unwrap();
}
fn wait_until(timeout: Duration, mut ready: impl FnMut() -> bool) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        if ready() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("bounded fixture condition timed out".into());
        }
        thread::sleep(Duration::from_millis(25));
    }
}
fn command(directory: &Path, role: &str) -> std::process::Command {
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--ignored",
            "--exact",
            TEST,
            "--nocapture",
            "--test-threads=1",
        ])
        .env(DIRECTORY, directory)
        .env(ROLE, role)
        .stdin(std::process::Stdio::null());
    command
}
fn spawn(directory: &Path, role: &str) -> Result<std::process::Child, String> {
    let log = |suffix: &str| {
        std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(directory.join(format!("{role}.{suffix}.log")))
            .map_err(|_| "cannot create retained child log".to_owned())
    };
    let child = command(directory, role)
        .stdout(log("stdout")?)
        .stderr(log("stderr")?)
        .spawn()
        .map_err(|_| "cannot start fixture child")?;
    receipt(
        &directory.join(format!("{role}.process.json")),
        json!({"pid":child.id(),"state":"running","forced_stop":false}),
    );
    Ok(child)
}
fn wait_child(
    mut child: std::process::Child,
    directory: &Path,
    role: &str,
    timeout: Duration,
) -> Result<(), String> {
    let pid = child.id();
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                receipt(
                    &directory.join(format!("{role}.process.json")),
                    json!({"pid":pid,"state":"exited","success":status.success(),"forced_stop":false}),
                );
                return if status.success() {
                    Ok(())
                } else {
                    Err("fixture child failed; evidence retained".into())
                };
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
            _ => {
                receipt(
                    &directory.join(format!("{role}.process.json")),
                    json!({"pid":pid,"state":"wait_failed_or_timed_out_retained","forced_stop":false}),
                );
                return Err("child retained without kill or blocking join".into());
            }
        }
    }
}

// Production lifecycle calls cannot be cancelled safely. Bound the failure
// observation, then keep this process/owner alive for the same pending call.
// The supervisor has its independent child deadline and never kills this PID.
fn wait_lifecycle<T>(
    receive: std::sync::mpsc::Receiver<T>,
    directory: &Path,
    role: &str,
    operation: &str,
) -> Result<T, String> {
    match receive.recv_timeout(Duration::from_secs(60)) {
        Ok(result) => Ok(result),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            Err("lifecycle observer stopped".into())
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            let pid = std::process::id();
            let pending = directory.join(format!("{role}.lifecycle-pending.json"));
            receipt(
                &pending,
                json!({"runtime_pid":pid,"operation":operation,"state":"timed_out_retained","forced_stop":false,"second_lifecycle_call_started":false}),
            );
            receipt(
                &directory.join(format!("{role}.RESULTS.json")),
                json!({"passed":false,"role":role,"pending_lifecycle":true,"runtime_pid":pid,"operation":operation,"forced_cleanup":false}),
            );
            stage(
                directory,
                "lifecycle_timeout_failure_recorded_owner_and_pid_retained",
            );
            // Never send a second request behind this stalled call. Retain all
            // ownership until it returns; this wait is not a pass or a retry.
            while let Err(std::sync::mpsc::RecvTimeoutError::Timeout) =
                receive.recv_timeout(Duration::from_secs(1))
            {}
            receipt(
                &pending,
                json!({"runtime_pid":pid,"operation":operation,"state":"observer_finished_after_timeout","forced_stop":false,"acceptance_failed":true}),
            );
            Err("lifecycle exceeded observation deadline; failure remains retained".into())
        }
    }
}
fn normal_unmount(
    broker: &Arc<WindowsProfiles>,
    directory: &Path,
    role: &str,
) -> Result<Value, String> {
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    let broker = Arc::clone(broker);
    thread::spawn(move || {
        let _ = send.send(broker.handle(&request("unmount")).map(|(value, _)| value));
    });
    wait_lifecycle(receive, directory, role, "normal_unmount")?
}

#[test]
#[ignore = "real Cloud Files Personal writes and open writer; new owned NTFS fixture and explicit authorized opt-in required"]
fn personal_save_and_open_writer_retained_disconnect() {
    let directory = PathBuf::from(std::env::var_os(DIRECTORY).expect("explicit fixture directory"));
    assert!(directory.is_absolute() && directory.is_dir());
    assert_eq!(
        std::fs::read_to_string(directory.join("OWNER.txt")).unwrap(),
        "raiun-headless-personal-busy-native-v1\n"
    );
    match std::env::var(ROLE).as_deref() {
        Ok(
            "io-success" | "io-busy" | "io-remount" | "io-restart" | "io-disconnected"
            | "io-final-success" | "io-final-busy" | "io-final-restart",
        ) => {
            os_io(&directory, &std::env::var(ROLE).unwrap());
            return;
        }
        Ok("success" | "busy" | "restart") => {
            runtime(&directory, &std::env::var(ROLE).unwrap());
            return;
        }
        _ => assert!(
            std::env::var_os(ROLE).is_none(),
            "CHILD must be absent for supervisor"
        ),
    }
    assert!(std::fs::read_dir(&directory).unwrap().all(|entry| matches!(
        entry.unwrap().file_name().to_str(),
        Some("OWNER.txt" | "runner.json" | "supervisor.stdout.log" | "supervisor.stderr.log")
    )));
    let mut cases = Vec::new();
    for case in ["success", "busy"] {
        let case_dir = directory.join(case);
        std::fs::create_dir(&case_dir).unwrap();
        std::fs::write(
            case_dir.join("OWNER.txt"),
            b"raiun-headless-personal-busy-native-v1\n",
        )
        .unwrap();
        std::fs::create_dir(case_dir.join("cloud-root")).unwrap();
        let (server, fixture) = super::super::tests::synthetic_headless_personal_write_server(
            |_| {},
            case_dir.join("failure-armed"),
            case == "busy",
        );
        receipt(
            &case_dir.join("config.json"),
            json!({"schema_version":1,"server":server,"auth":"app_token","username":"synthetic-user","mount_path":case_dir.join("cloud-root"),"auto_mount":true,"remember_login":true,"reconnect_interval_seconds":1,"profile":"default"}),
        );
        // Only children admit the state context. The supervisor hosts the synthetic server.
        let run = |role: &str| {
            let mut child = command(&case_dir, role);
            child
                .env("RAIUN_HEADLESS_CONTEXT", "1")
                .env("RAIUN_STATE_DIR", case_dir.join("state"))
                .env("RAIUN_HEADLESS_CONFIG", case_dir.join("config.json"));
            let child = child
                .stdout(std::fs::File::create(case_dir.join(format!("{role}.stdout.log"))).unwrap())
                .stderr(std::fs::File::create(case_dir.join(format!("{role}.stderr.log"))).unwrap())
                .spawn()
                .unwrap();
            receipt(
                &case_dir.join(format!("{role}.process.json")),
                json!({"pid":child.id(),"state":"running","forced_stop":false}),
            );
            wait_child(child, &case_dir, role, Duration::from_secs(240))
        };
        let first = run(case);
        let restarted = if case == "busy" && first.is_ok() {
            run("restart")
        } else {
            Ok(())
        };
        let remote = fixture.ordinary_write_snapshot();
        let first_receipt = read_json(&case_dir.join(format!("{case}.RESULTS.json")));
        let restart_receipt = if case == "busy" {
            read_json(&case_dir.join("restart.RESULTS.json"))
        } else {
            Value::Null
        };
        let remote_ok = if case == "success" {
            remote.put_attempt_count == 1
                && remote.put_count == 1
                && remote.verified_readback_count >= 2
                && remote.body == edited()
                && remote.last_put_if_match.as_deref() == Some("\"synthetic-file-v1\"")
        } else {
            remote.put_count == 0
                && remote.body == ORIGINAL
                && remote.put_attempt_count == remote.forbidden_put_count
        };
        let passed = first.is_ok()
            && restarted.is_ok()
            && first_receipt["passed"] == true
            && (case != "busy" || restart_receipt["passed"] == true)
            && remote_ok
            && fixture.global_mutation_attempts() == remote.put_attempt_count;
        cases.push(json!({"scenario":case,"passed":passed,"first":first_receipt,"restart":restart_receipt,"remote":remote,"global_mutation_attempts":fixture.global_mutation_attempts()}));
        receipt(
            &directory.join("RESULTS.json"),
            json!({"fixture":"headless-personal-busy-native-v1","passed":cases.len()==2 && cases.iter().all(|case|case["passed"]==true),"cases":cases,"forced_cleanup":false,"registration_retained":true}),
        );
        if !passed {
            // A timed-out child may still need this server. Never join or kill it.
            std::mem::forget(fixture);
            panic!("Personal/busy native acceptance incomplete; every root/state/process retained");
        }
        fixture.join().unwrap();
    }
}
fn read_json(path: &Path) -> Value {
    std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or(Value::Null)
}
fn request(action: &str) -> Value {
    json!({"action":action,"required_mode":"mount_only","profile_id":"default"})
}
fn native_flags(agent: &WindowsAgent) -> Result<(u32, u64), String> {
    let observation = agent.provider.read_only_placeholder_observation(
        super::super::NativeRestartProbePath::PersonalOrdinarySave,
    )?;
    let (_, _, flags, size) = observation.2?;
    Ok((flags, size))
}
fn root_identity(agent: &WindowsAgent) -> raiun_cloudfiles_windows::ConfiguredRootIdentity {
    let state = agent.state.lock().unwrap();
    let root = state.root_configuration.as_ref().unwrap();
    raiun_cloudfiles_windows::ConfiguredRootIdentity {
        volume_serial: root.volume_serial,
        file_index: root.file_index,
    }
}
fn runtime(directory: &Path, role: &str) {
    let config = crate::headless_runtime::config().unwrap().unwrap();
    assert_eq!(config.mount_path, directory.join("cloud-root"));
    let broker =
        Arc::new(WindowsProfiles::open(DpapiSessionStore::current_user().unwrap()).unwrap());
    let agent = broker.state.lock().unwrap().runtimes["default"].clone();
    agent
        .provider
        .lifecycle_test_activation
        .store(true, Ordering::Release);
    agent
        .provider
        .initial_save_test_activation
        .store(true, Ordering::Release);
    let mut writer = None;
    let mut unmount_receiver = None;
    let exercise = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<Value, String> {
        if role != "restart" {
            broker.handle_owned(windows_vault_requests::OwnedControlRequest::new(json!({"action":"auth_app_token","required_mode":"mount_only","profile_id":"default","server":config.server,"username":"synthetic-user","app_token":"synthetic-headless-app-token"})))?;
        }
        let mount = if role == "restart" {
            // A restored runtime requires the production broker's normal tick
            // to verify saved credentials and perform automatic mounting.
            let deadline = Instant::now() + Duration::from_secs(45);
            loop {
                broker.refresh_all()?;
                if agent.state.lock().unwrap().online_authenticated && agent.provider.is_connected() {
                    break;
                }
                if Instant::now() >= deadline {
                    return Err("saved-session verification and automatic mounting timed out".into());
                }
                thread::sleep(Duration::from_millis(25));
            }
            stage(directory, "restart_dpapi_restored_and_automounted");
            None
        } else {
            wait_until(Duration::from_secs(45), || agent.state.lock().unwrap().online_authenticated)?;
            let automatic = agent.headless_configured_mount_request()?.ok_or("configured mount unavailable")?;
            broker.handle(&automatic)?;
            Some(automatic)
        };
        assert!(agent.provider.is_connected());
        let identity = root_identity(&agent);
        if role == "restart" {
            let old = read_json(&directory.join("ROOT.json"));
            assert_eq!(old["volume_serial"], identity.volume_serial);
            assert_eq!(old["file_index"], identity.file_index);
        } else {
            receipt(&directory.join("ROOT.json"), json!({"volume_serial":identity.volume_serial,"file_index":identity.file_index}));
        }
        let verified = agent.prepare_recovery_context()?;
        let personal = verified.spaces.iter().find(|space|space.personal).ok_or("Personal drive unavailable")?;
        let remote_root = verified.client.stat_discovered_space_root_with_context(personal, verified.context).map_err(|_|"Personal root unavailable")?;
        let scope = EditJournalScope {
            profile_id:verified.provider_scope.profile_id().into(), server_origin:verified.provider_scope.server_origin().into(),
            account_subject:verified.provider_scope.account_id().into(), space_id:personal.id.clone(),root_resource_id:remote_root.id,
            root_volume_serial:identity.volume_serial,root_file_index:identity.file_index,
        };
        let mut observed_unmount = "not_applicable";
        if role == "busy" {
            writer = Some(spawn(directory, "io-busy")?);
            wait_until(Duration::from_secs(35), || directory.join("WRITER-READY").is_file())?;
            stage(directory, "writer_flushed_and_still_open");
            assert_eq!(native_flags(&agent)?.0 & 0x8, 0, "open dirty writer must not be clean");
            let (send, receive) = std::sync::mpsc::sync_channel(1);
            let other = Arc::clone(&broker);
            let owned = directory.to_owned();
            thread::spawn(move || {
                stage(&owned, "unmount_call_entered_while_writer_open");
                let _ = send.send(other.handle(&request("unmount")).map(|(value, _)| value));
            });
            let early = receive.recv_timeout(Duration::from_secs(1));
            if matches!(early, Err(std::sync::mpsc::RecvTimeoutError::Timeout)) {
                unmount_receiver = Some(receive);
            }
            observed_unmount = match &early { Ok(Ok(_)) => "retained_disconnect_while_open", Ok(Err(_)) => "refused_while_open", Err(std::sync::mpsc::RecvTimeoutError::Timeout) => "waited_until_writer_release", Err(_) => return Err("unmount observer stopped".into()) };
            receipt(&directory.join("UNMOUNT-WHILE-OPEN.json"), json!({"outcome":observed_unmount,"forced_stop":false}));
            // Always release independently of unmount completion; never deadlock cleanup on the open writer.
            std::fs::write(directory.join("WRITER-RELEASE"), b"release\n").unwrap();
            stage(directory, "writer_release_requested");
            wait_child(writer.take().unwrap(), directory, "io-busy", Duration::from_secs(45))?;
            if let Some(receive) = unmount_receiver.take() {
                let _ = wait_lifecycle(receive, directory, role, "unmount_while_writer_open")?;
            }
            // Explicit normal retry handles OS refusal without assuming EBUSY is required.
            normal_unmount(&broker, directory, role)?;
            assert!(!agent.provider.is_connected());
            assert!(!*agent.provider.mount_preference.lock().unwrap());
            assert!(pin_registered_configured_root(&config.mount_path, identity).is_ok());
            wait_child(spawn(directory, "io-disconnected")?, directory, "io-disconnected", Duration::from_secs(45))?;
            stage(directory, "dirty_bytes_preserved_after_disconnect");
            // Unmount must continue rejecting a queued automatic reconnect.
            // This remount is an explicit user action through the normal API.
            let automatic = mount.as_ref().ok_or("initial automatic mount missing")?;
            let refused = broker.handle(automatic).expect_err("late automatic mounting must remain refused");
            assert_eq!(refused, "Automatic mounting was cancelled by unmount");
            assert!(!agent.provider.is_connected());
            assert!(!*agent.provider.mount_preference.lock().unwrap());
            stage(directory, "late_automatic_remount_refused");
            broker.handle(&request("mount"))?;
            assert!(agent.provider.is_connected());
            assert!(*agent.provider.mount_preference.lock().unwrap());
            stage(directory, "explicit_remount_connected");
            assert_eq!(root_identity(&agent), identity);
            wait_child(spawn(directory, "io-remount")?, directory, "io-remount", Duration::from_secs(45))?;
        } else {
            let io = if role == "restart" { "io-restart" } else { "io-success" };
            wait_child(spawn(directory, io)?, directory, io, Duration::from_secs(45))?;
        }
        if role == "success" {
            wait_until(Duration::from_secs(35), || {
                native_flags(&agent).is_ok_and(|(flags,_)|flags & 0x8 != 0)
                    && verified.recovery_provider.has_unresolved_edits().is_ok_and(|pending|!pending)
            })?;
            let protector = DpapiEditRecordProtector::current_user().unwrap();
            let journal = EditJournal::open(protector.local_state_directory(), scope.clone(), protector.clone()).unwrap();
            let snapshot = journal.recover_all().unwrap();
            assert_eq!(snapshot.records.len(), 1);
            assert_eq!(snapshot.records[0].content, edited());
        } else {
            assert_eq!(native_flags(&agent)?.0 & 0x8, 0, "retained dirty bytes must not be marked in sync");
            // Authenticate every available protected record without assuming capture occurred before disconnect.
            let metadata = verified.recovery_provider.unresolved_metadata_bounded().unwrap();
            if !metadata.is_empty() {
                let protector = DpapiEditRecordProtector::current_user().unwrap();
                let journal = EditJournal::open(protector.local_state_directory(), scope.clone(), protector.clone()).unwrap();
                let snapshot = journal.recover_all().unwrap();
                for record in &snapshot.records { assert_eq!(record.metadata.scope, scope); assert_eq!(record.content, edited()); }
            }
        }
        assert_eq!(native_flags(&agent)?.1, edited().len() as u64);
        assert_eq!(agent.provider.folder_generation.load(Ordering::Acquire), 0);
        Ok(json!({"unmount_while_open":observed_unmount,"native_in_sync":native_flags(&agent)?.0 & 0x8 != 0,"expected_bytes":true,"exact_root_identity":true,"independent_dpapi_restore":role=="restart","folder_generation":0}))
    })).unwrap_or_else(|_|Err("Personal/busy fixture assertion failed; evidence retained".into()));
    // Release even after assertion/error. No assertion unwinds past an owned open writer.
    let _ = std::fs::write(directory.join("WRITER-RELEASE"), b"release\n");
    let writer_closed = writer
        .take()
        .map(|child| wait_child(child, directory, "io-busy", Duration::from_secs(45)))
        .unwrap_or(Ok(()));
    // An assertion/child failure may leave the original observer pending.
    // Settle that same call before starting any final lifecycle request.
    if let Some(receive) = unmount_receiver.take() {
        let _ = wait_lifecycle(receive, directory, role, "unmount_after_exercise_failure");
    }
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    let cleanup_broker = Arc::clone(&broker);
    thread::spawn(move || {
        let unmount = cleanup_broker.handle(&request("unmount"));
        let stopped = cleanup_broker.stop_all();
        let _ = send.send((unmount, stopped));
    });
    let (unmount, stopped) = wait_lifecycle(receive, directory, role, "final_unmount_and_stop")
        .unwrap_or_else(|error| (Err(error.clone()), Err(error)));
    let identity = root_identity(&agent);
    let io_role = format!("io-final-{role}");
    let final_read = if unmount.is_ok() && stopped.is_ok() {
        spawn(directory, &io_role)
            .and_then(|child| wait_child(child, directory, &io_role, Duration::from_secs(45)))
    } else {
        Err("normal disconnect incomplete".into())
    };
    let retained = unmount.is_ok()
        && stopped.is_ok()
        && pin_registered_configured_root(&config.mount_path, identity).is_ok()
        && final_read.is_ok();
    let passed =
        exercise.is_ok() && writer_closed.is_ok() && unmount.is_ok() && stopped.is_ok() && retained;
    receipt(
        &directory.join(format!("{role}.RESULTS.json")),
        json!({"passed":passed,"role":role,"detail":exercise.as_ref().ok(),"error":exercise.as_ref().err(),"normal_unmount":unmount.is_ok(),"normal_stop":stopped.is_ok(),"edited_bytes_and_registration_retained":retained,"forced_cleanup":false}),
    );
    assert!(
        passed,
        "Personal/busy acceptance incomplete; root/state/process evidence retained"
    );
}
fn os_io(directory: &Path, role: &str) {
    let root = directory.join("cloud-root");
    // Connected roles must exercise provider enumeration. Disconnected/final
    // retention checks read only the already-hydrated exact file: an on-demand
    // directory listing can require a provider even when file bytes survive.
    if matches!(role, "io-success" | "io-busy" | "io-remount" | "io-restart") {
        for path in [&root, &root.join("Personal")] {
            std::fs::read_dir(path).unwrap().for_each(|entry| {
                entry.unwrap();
            });
        }
    }
    let path = root.join("Personal/ordinary-save.bin");
    if !matches!(role, "io-success" | "io-busy") {
        assert_eq!(std::fs::read(path).unwrap(), edited());
        return;
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, ORIGINAL);
    std::fs::write(directory.join("failure-armed"), b"armed\n").unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    file.write_all(&edited()).unwrap();
    file.sync_all().unwrap();
    if role == "io-busy" {
        std::fs::write(directory.join("WRITER-READY"), b"flushed-open\n").unwrap();
        let released = wait_until(Duration::from_secs(100), || {
            directory.join("WRITER-RELEASE").is_file()
        });
        file.seek(SeekFrom::Start(0)).unwrap();
        bytes.clear();
        file.read_to_end(&mut bytes).unwrap();
        drop(file); // Always close before reporting a missed release or content failure.
        assert_eq!(bytes, edited());
        assert!(
            released.is_ok(),
            "writer release timed out; handle closed normally"
        );
    } else {
        drop(file);
    }
}
