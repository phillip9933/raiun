//! Explicit ignored diagnostic only. No production activation or body logging.
use super::*;
use raiun_cloudfiles_windows::{
    DpapiEditRecordProtector, DurableEditRecoveryProvider, EditJournalScope, JournalError,
    streamed_store::{SnapshotStore, StorePolicy, StreamedAttemptState},
};
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom, Write};

const TEST: &str = "agent_windows::windows_profiles::windows_headless_streamed_test::synthetic_headless_streamed_existing_file_save";
const DIRECTORY: &str = "RAIUN_HEADLESS_STREAMED_FIXTURE_DIR";
const ROLE: &str = "RAIUN_HEADLESS_STREAMED_FIXTURE_CHILD";
const CASE: &str = "RAIUN_HEADLESS_STREAMED_FIXTURE_CASE";
const ALL_CASES: [&str; 4] = [
    "personal-success",
    "space-success",
    "personal-forbidden",
    "space-forbidden",
];
const POLICY_CASES: [&str; 3] = [
    "personal-paced",
    "personal-small-paced",
    "personal-paced-expired",
];
const OWNER: &str = "raiun-headless-native-streamed-v1\n";
const LENGTH: u64 = 17 * 1024 * 1024 + 7;
const SMALL_LENGTH: u64 = 2 * 1024 * 1024 + 7;
const CHUNK: usize = 64 * 1024;

fn requested_cases(input: Option<&std::ffi::OsStr>) -> Result<Vec<&'static str>, &'static str> {
    match input {
        None => Ok(ALL_CASES.to_vec()),
        Some(input) => {
            let value = input.to_str().ok_or("invalid diagnostic case encoding")?;
            let case = ALL_CASES
                .iter()
                .chain(POLICY_CASES.iter())
                .copied()
                .find(|case| *case == value)
                .ok_or("unsupported diagnostic case")?;
            Ok(vec![case])
        }
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
fn same_path(a: &Path, b: &Path) -> bool {
    matches!((std::fs::canonicalize(a),std::fs::canonicalize(b)),(Ok(a),Ok(b)) if a==b)
}
fn owned_marker(directory: &Path) -> bool {
    use std::os::windows::fs::MetadataExt;
    let path = directory.join("OWNER.txt");
    std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_file() && m.file_attributes() & 0x400 == 0)
        && std::fs::read_to_string(path).is_ok_and(|s| s == OWNER)
}
fn valid_invocation(args: &[String]) -> bool {
    args.iter().any(|s| s == "--ignored")
        && args.windows(2).any(|p| p[0] == "--exact" && p[1] == TEST)
}
fn loopback_origin(origin: &str) -> bool {
    origin
        .strip_prefix("http://")
        .and_then(|s| s.parse::<std::net::SocketAddr>().ok())
        .is_some_and(|address| {
            address.ip() == std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                && address.port() != 0
        })
}

/// Parent's two cfg(test,debug_assertions) constructor hooks call only this
/// process-local diagnostic guard. Env absence leaves all defaults untouched.
pub(in super::super) fn maybe_enable_recovery(
    provider: DurableEditRecoveryProvider,
    scope: &raiun_cloudfiles_windows::ProviderScope,
    root: raiun_cloudfiles_windows::ConfiguredRootIdentity,
) -> Result<DurableEditRecoveryProvider, JournalError> {
    let Some(directory) = std::env::var_os(DIRECTORY) else {
        return Ok(provider);
    };
    let directory = PathBuf::from(directory);
    let selected = std::env::var_os(CASE);
    let cases = requested_cases(selected.as_deref()).map_err(|_| JournalError::InvalidScope)?;
    let role = std::env::var(ROLE).map_err(|_| JournalError::InvalidScope)?;
    let args = std::env::args().collect::<Vec<_>>();
    let config = crate::headless_runtime::config()
        .map_err(|_| JournalError::InvalidScope)?
        .ok_or(JournalError::InvalidScope)?;
    let context = raiun_control_windows::headless_context()
        .map_err(|_| JournalError::InvalidScope)?
        .ok_or(JournalError::InvalidScope)?;
    if !matches!(role.as_str(), "save" | "restart")
        || !valid_invocation(&args)
        || !directory.is_absolute()
        || !owned_marker(&directory)
        || !same_path(context.state_root(), &directory.join("state"))
        || !same_path(&config.mount_path, &directory.join("cloud-root"))
        || scope.profile_id() != "default"
        || config.profile != "default"
        || config.auth != raiun_headless::AuthMethod::AppToken
        || config.username.as_deref() != Some("synthetic-user")
        || !directory
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|s| cases.contains(&s))
        || scope.server_origin() != config.server.trim_end_matches('/')
        || !loopback_origin(scope.server_origin())
        || root.file_index == 0
    {
        return Err(JournalError::InvalidScope);
    }
    let pinned = pin_registered_configured_root(&config.mount_path, root)
        .or_else(|_| raiun_cloudfiles_windows::pin_configured_root(&config.mount_path))
        .map_err(|_| JournalError::InvalidScope)?;
    if pinned.identity() != root {
        return Err(JournalError::InvalidScope);
    }
    super::super::windows_recovery_policy::activate_for_diagnostic(provider)
}

fn byte(offset: u64, edited: bool) -> u8 {
    let original = (offset.wrapping_mul(37) % 251) as u8;
    if edited && offset == 0 {
        original ^ 0x5a
    } else {
        original
    }
}
fn generated_hash(length: u64, edited: bool) -> String {
    static ORIGINAL: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    static EDITED: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    static SMALL_ORIGINAL: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    static SMALL_EDITED: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    let cache = match (length, edited) {
        (LENGTH, false) => &ORIGINAL,
        (LENGTH, true) => &EDITED,
        (SMALL_LENGTH, false) => &SMALL_ORIGINAL,
        (SMALL_LENGTH, true) => &SMALL_EDITED,
        _ => panic!("unsupported diagnostic length"),
    };
    cache
        .get_or_init(|| {
            let mut hash = Sha256::new();
            let mut buffer = [0; CHUNK];
            let mut offset = 0;
            while offset < length {
                let count = (length - offset).min(CHUNK as u64) as usize;
                for (i, b) in buffer[..count].iter_mut().enumerate() {
                    *b = byte(offset + i as u64, edited);
                }
                hash.update(&buffer[..count]);
                offset += count as u64;
            }
            format!("{:x}", hash.finalize())
        })
        .clone()
}
fn file_hash(file: &mut std::fs::File, expected_len: u64) -> Result<(u64, String), String> {
    let mut hash = Sha256::new();
    let mut buffer = [0; CHUNK];
    let mut length = 0u64;
    loop {
        let count = file.read(&mut buffer).map_err(|_| "ordinary read failed")?;
        if count == 0 {
            break;
        }
        length = length.checked_add(count as u64).ok_or("length overflow")?;
        if length > expected_len {
            return Err("ordinary file exceeded diagnostic length".into());
        }
        hash.update(&buffer[..count]);
    }
    Ok((length, format!("{:x}", hash.finalize())))
}
fn write_json(path: &Path, value: Value) {
    std::fs::write(path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
}
fn request(action: &str) -> Value {
    json!({"action":action,"required_mode":"mount_only","profile_id":"default"})
}
fn personal(directory: &Path) -> bool {
    directory
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("personal-")
}
fn forbidden(directory: &Path) -> bool {
    directory
        .file_name()
        .unwrap()
        .to_string_lossy()
        .ends_with("-forbidden")
}
fn paced(directory: &Path) -> bool {
    directory
        .file_name()
        .and_then(|s| s.to_str())
        .is_some_and(|name| POLICY_CASES.contains(&name))
}
fn expired(directory: &Path) -> bool {
    directory.file_name().and_then(|s| s.to_str()) == Some("personal-paced-expired")
}
fn pending_case(directory: &Path) -> bool {
    forbidden(directory) || expired(directory)
}
fn job_timeout_seconds(directory: &Path) -> u64 {
    if expired(directory) { 60 } else { 120 }
}
fn case_length(directory: &Path) -> u64 {
    if directory.file_name().and_then(|s| s.to_str()) == Some("personal-small-paced") {
        SMALL_LENGTH
    } else {
        LENGTH
    }
}
fn readback_rate(directory: &Path) -> u64 {
    if case_length(directory) == SMALL_LENGTH || expired(directory) {
        64 * 1024
    } else {
        512 * 1024
    }
}
fn local_file(directory: &Path) -> PathBuf {
    directory.join(if personal(directory) {
        "cloud-root/Personal/ordinary-save.bin"
    } else {
        "cloud-root/Spaces/Projects/RecoveryRoot/document.bin"
    })
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
fn spawn(directory: &Path, role: &str, headless: bool) -> Result<std::process::Child, String> {
    let mut command = command(directory, role);
    if headless {
        command
            .env("RAIUN_HEADLESS_CONTEXT", "1")
            .env("RAIUN_STATE_DIR", directory.join("state"))
            .env("RAIUN_HEADLESS_CONFIG", directory.join("config.json"));
    }
    let log = |suffix| {
        std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(directory.join(format!("{role}.{suffix}.log")))
            .map_err(|_| "cannot create retained child log".to_owned())
    };
    let child = command
        .stdout(log("stdout")?)
        .stderr(log("stderr")?)
        .spawn()
        .map_err(|_| "cannot spawn diagnostic child")?;
    write_json(
        &directory.join(format!("{role}.process.json")),
        json!({"pid":child.id(),"state":"running","forced_stop":false}),
    );
    Ok(child)
}
fn wait_child(mut child: std::process::Child, directory: &Path, role: &str) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(240);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                write_json(
                    &directory.join(format!("{role}.process.json")),
                    json!({"pid":child.id(),"state":"exited","success":status.success(),"forced_stop":false}),
                );
                return if status.success() {
                    Ok(())
                } else {
                    Err("diagnostic child failed; evidence retained".into())
                };
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
            _ => {
                write_json(
                    &directory.join(format!("{role}.process.json")),
                    json!({"pid":child.id(),"state":"timed_out_retained","forced_stop":false}),
                );
                // Retain this supervisor/server while its exact child still runs.
                // A later natural exit does not turn this timed-out run into a pass.
                loop {
                    match child.try_wait() {
                        Ok(Some(status)) => {
                            write_json(
                                &directory.join(format!("{role}.exit-after-timeout.json")),
                                json!({"pid":child.id(),"exited":true,"success":status.success(),"acceptance_failed":true,"forced_stop":false}),
                            );
                            break;
                        }
                        Ok(None) | Err(_) => thread::sleep(Duration::from_secs(1)),
                    }
                }
                return Err("child exceeded observation deadline; no forced stop".into());
            }
        }
    }
}
fn wait_for(
    timeout: Duration,
    mut ready: impl FnMut() -> Result<bool, String>,
) -> Result<(), String> {
    let end = Instant::now() + timeout;
    loop {
        if ready()? {
            return Ok(());
        }
        if Instant::now() >= end {
            return Err("bounded diagnostic observation timed out".into());
        }
        thread::sleep(Duration::from_millis(25));
    }
}

#[test]
#[ignore = "actual Windows Cloud Files streamed17MiB existing-file pipeline; explicit fresh owned fixture and serialized device authorization required"]
fn synthetic_headless_streamed_existing_file_save() {
    let selection = std::env::var_os(CASE);
    let requested = requested_cases(selection.as_deref()).expect("exact allowed diagnostic case");
    let directory = PathBuf::from(std::env::var_os(DIRECTORY).expect("explicit fixture directory"));
    assert!(directory.is_absolute() && owned_marker(&directory));
    if std::env::var_os(ROLE).is_some() {
        assert!(
            directory
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| requested.contains(&s)),
            "child case differs from requested scope"
        );
    }
    match std::env::var(ROLE).as_deref() {
        Ok("save" | "restart") => {
            runtime(&directory, &std::env::var(ROLE).unwrap());
            return;
        }
        Ok("io-edit" | "io-retained" | "io-final-save" | "io-final-restart") => {
            os_io(&directory, &std::env::var(ROLE).unwrap()).unwrap();
            return;
        }
        _ => assert!(
            std::env::var_os(ROLE).is_none(),
            "unsupported diagnostic role"
        ),
    }
    assert!(std::fs::read_dir(&directory).unwrap().all(|entry| matches!(
        entry.unwrap().file_name().to_str(),
        Some("OWNER.txt" | "runner.json" | "supervisor.stdout.log" | "supervisor.stderr.log")
    )));
    let mut results = Vec::new();
    for case in &requested {
        let case_dir = directory.join(case);
        let expected_len = case_length(&case_dir);
        std::fs::create_dir(&case_dir).unwrap();
        std::fs::create_dir(case_dir.join("cloud-root")).unwrap();
        std::fs::write(case_dir.join("OWNER.txt"), OWNER).unwrap();
        use super::super::tests::{
            SyntheticOrdinaryWriteMode, synthetic_headless_ordinary_write_server,
            synthetic_headless_personal_write_server,
        };
        let (server, fixture) = if personal(&case_dir) {
            synthetic_headless_personal_write_server(
                |_| {},
                case_dir.join("failure-armed"),
                forbidden(&case_dir),
            )
        } else {
            synthetic_headless_ordinary_write_server(
                |_| {},
                case_dir.join("failure-armed"),
                if forbidden(&case_dir) {
                    SyntheticOrdinaryWriteMode::Forbidden
                } else {
                    SyntheticOrdinaryWriteMode::Success
                },
            )
        };
        // Supervisor-only server Vec: explicitly outside application worker
        // memory assertions. Do not log/serialize this body or clone snapshots.
        fixture.seed_streamed_existing_file(
            (0..expected_len)
                .map(|offset| byte(offset, false))
                .collect(),
        );
        if paced(&case_dir) {
            fixture.pace_streamed_readback(readback_rate(&case_dir));
        }
        let mut config = json!({"schema_version":1,"server":server,"auth":"app_token","username":"synthetic-user","mount_path":case_dir.join("cloud-root"),"auto_mount":true,"remember_login":true,"reconnect_interval_seconds":1,"profile":"default"});
        if paced(&case_dir) {
            config["windows_recovery"] =
                json!({"total_timeout_seconds":job_timeout_seconds(&case_dir)});
        }
        write_json(&case_dir.join("config.json"), config);
        let save =
            spawn(&case_dir, "save", true).and_then(|child| wait_child(child, &case_dir, "save"));
        let restart = if save.is_ok() {
            spawn(&case_dir, "restart", true)
                .and_then(|child| wait_child(child, &case_dir, "restart"))
        } else {
            Err("save failed; restart not attempted".into())
        };
        let remote = fixture.streamed_write_observation();
        let remote_ok = remote["bytes"] == expected_len
            && remote["sha256"] == generated_hash(expected_len, !forbidden(&case_dir))
            && remote["put_attempts"] == 1
            && fixture.global_mutation_attempts() == 1
            && remote["attempt_if_match"] == "\"synthetic-file-v1\""
            && if forbidden(&case_dir) {
                remote["puts"] == 0
                    && remote["forbidden"] == 1
                    && remote["etag"] == "\"synthetic-file-v1\""
            } else {
                remote["puts"] == 1
                    && remote["readbacks"] == 1
                    && remote["put_if_match"] == "\"synthetic-file-v1\""
                    && remote["read_if_match"] == "\"synthetic-file-v2\""
            };
        let pacing = fixture.paced_readback_observation();
        let pacing_ok = !paced(&case_dir)
            || (pacing["bytes_per_second"] == readback_rate(&case_dir)
                && pacing["elapsed_millis"]
                    .as_u64()
                    .is_some_and(|ms| ms > 30_000)
                && if expired(&case_dir) {
                    pacing["finished"] == false
                        && pacing["sent"]
                            .as_u64()
                            .is_some_and(|sent| sent > 0 && sent < expected_len)
                        && std::fs::read(case_dir.join("save.RESULTS.json"))
                            .ok()
                            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                            .and_then(|report| report["runtime_elapsed_millis"].as_u64())
                            .is_some_and(|ms| ms >= 60_000)
                } else {
                    pacing["finished"] == true && pacing["sent"] == expected_len
                });
        let passed = save.is_ok() && restart.is_ok() && remote_ok && pacing_ok;
        results.push(json!({"case":case,"passed":passed,"save":save,"restart":restart,"remote":remote,"pacing":pacing,"global_mutations":fixture.global_mutation_attempts()}));
        write_json(
            &directory.join("RESULTS.json"),
            json!({"fixture":"headless-native-streamed-v1",
                "requested_cases":requested,"scope":if requested.len()==ALL_CASES.len(){"full_matrix"}else{"focused_case"},
                "passed":results.len()==requested.len() && results.iter().all(|r|r["passed"]==true),
                "full_matrix_passed":requested.len()==ALL_CASES.len() && results.len()==ALL_CASES.len() && results.iter().all(|r|r["passed"]==true),
                "cases":results,"native_execution":true,"live_server":false,"folder_sync":false,"forced_cleanup":false,"registrations_and_state_retained":true,
                "space403_covered":results.iter().any(|r|r["case"]=="space-forbidden" && r["passed"]==true)}),
        );
        fixture.join().unwrap();
        assert!(
            passed,
            "streamed native diagnostic incomplete; preserve all artifacts"
        );
    }
}

fn os_io(directory: &Path, role: &str) -> Result<(), String> {
    let expected_len = case_length(directory);
    if role == "io-edit" {
        let path = local_file(directory);
        let mut parent = path.parent().unwrap().to_path_buf();
        let mut chain = Vec::new();
        while parent.starts_with(directory.join("cloud-root")) {
            chain.push(parent.clone());
            if parent == directory.join("cloud-root") {
                break;
            }
            parent = parent.parent().unwrap().to_path_buf();
        }
        for directory in chain.iter().rev() {
            for entry in std::fs::read_dir(directory).map_err(|_| "ordinary enumeration failed")? {
                entry.map_err(|_| "ordinary enumeration item failed")?;
            }
        }
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|_| "ordinary existing-file open failed")?;
        if file_hash(&mut file, expected_len)?
            != (expected_len, generated_hash(expected_len, false))
        {
            return Err("ordinary original content mismatch".into());
        }
        std::fs::write(directory.join("failure-armed"), b"armed\n")
            .map_err(|_| "cannot arm synthetic refusal")?;
        file.seek(SeekFrom::Start(0))
            .map_err(|_| "ordinary seek failed")?;
        let mut offset = 0;
        let mut buffer = [0; CHUNK];
        while offset < expected_len {
            let count = (expected_len - offset).min(CHUNK as u64) as usize;
            for (i, b) in buffer[..count].iter_mut().enumerate() {
                *b = byte(offset + i as u64, true);
            }
            file.write_all(&buffer[..count])
                .map_err(|_| "ordinary write failed")?;
            offset += count as u64;
        }
        file.sync_all().map_err(|_| "ordinary flush failed")?;
        drop(file);
    } else {
        let mut file =
            std::fs::File::open(local_file(directory)).map_err(|_| "retained file open failed")?;
        if file_hash(&mut file, expected_len)? != (expected_len, generated_hash(expected_len, true))
        {
            return Err("retained ordinary content mismatch".into());
        }
    }
    Ok(())
}

fn root_identity(agent: &WindowsAgent) -> raiun_cloudfiles_windows::ConfiguredRootIdentity {
    let state = agent.state.lock().unwrap();
    let root = state.root_configuration.as_ref().unwrap();
    raiun_cloudfiles_windows::ConfiguredRootIdentity {
        volume_serial: root.volume_serial,
        file_index: root.file_index,
    }
}
fn native_flags(agent: &WindowsAgent, directory: &Path) -> Result<(u32, u64), String> {
    let path = if personal(directory) {
        super::super::NativeRestartProbePath::PersonalOrdinarySave
    } else {
        super::super::NativeRestartProbePath::RecoveryDocument
    };
    let (_, _, flags, length) = agent.provider.read_only_placeholder_observation(path)?.2?;
    Ok((flags, length))
}
fn store(scope: EditJournalScope) -> Result<Option<Arc<SnapshotStore>>, String> {
    let protector =
        DpapiEditRecordProtector::current_user().map_err(|_| "DPAPI protector unavailable")?;
    let path = protector.local_state_directory();
    let parent =
        raiun_control_windows::PinnedDirectory::open(path.parent().ok_or("state parent missing")?)
            .map_err(|_| "state parent pin failed")?;
    let state = Arc::new(
        raiun_control_windows::PrivateDirectory::open_under(
            &parent,
            path.file_name().ok_or("state name missing")?,
        )
        .map_err(|_| "private state unavailable")?,
    );
    match std::fs::symlink_metadata(path.join("cloud-files-edit-journal-v2")) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("v2 root existence check failed".into()),
        Ok(_) => (),
    }
    SnapshotStore::open_existing(state, scope, Arc::new(protector), policy())
        .map(Some)
        .map_err(|_| "protected v2 store unavailable".into())
}
fn lifecycle<T>(
    receive: std::sync::mpsc::Receiver<T>,
    directory: &Path,
    role: &str,
) -> Result<T, String> {
    match receive.recv_timeout(Duration::from_secs(60)) {
        Ok(value) => Ok(value),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            Err("lifecycle observer disconnected".into())
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            write_json(
                &directory.join(format!("{role}.lifecycle-pending.json")),
                json!({"pid":std::process::id(),"pending":true,"forced_stop":false,"passed":false}),
            );
            // Never start a second call or free its owner behind a timeout.
            while let Err(std::sync::mpsc::RecvTimeoutError::Timeout) =
                receive.recv_timeout(Duration::from_secs(1))
            {}
            Err("lifecycle exceeded deadline; failure retained".into())
        }
    }
}
fn runtime(directory: &Path, role: &str) {
    let runtime_started = Instant::now();
    let expected_len = case_length(directory);
    let config = crate::headless_runtime::config().unwrap().unwrap();
    assert!(loopback_origin(config.server.trim_end_matches('/')));
    assert!(same_path(&config.mount_path, &directory.join("cloud-root")));
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
    let exercise=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||->Result<Value,String>{
        if role=="save"{
            broker.handle_owned(windows_vault_requests::OwnedControlRequest::new(json!({"action":"auth_app_token","required_mode":"mount_only","profile_id":"default","server":config.server,"username":"synthetic-user","app_token":"synthetic-headless-app-token"})))?;
            wait_for(Duration::from_secs(45),||Ok(agent.state.lock().unwrap().online_authenticated))?;
            let mount=agent.headless_configured_mount_request()?.ok_or("configured auto mount missing")?;broker.handle(&mount)?;
        }else{wait_for(Duration::from_secs(45),||{broker.refresh_all()?;Ok(agent.state.lock().unwrap().online_authenticated && agent.provider.is_connected())})?;}
        if !agent.provider.is_connected(){return Err("actual provider not connected".into());}
        let identity=root_identity(&agent);
        if role=="save"{write_json(&directory.join("ROOT.json"),json!({"volume":identity.volume_serial,"file":identity.file_index}));}
        else{let saved:Value=serde_json::from_slice(&std::fs::read(directory.join("ROOT.json")).unwrap()).unwrap();if saved["volume"]!=identity.volume_serial || saved["file"]!=identity.file_index{return Err("physical root changed on restart".into());}}
        let verified=agent.prepare_recovery_context()?;
        let space=verified.spaces.iter().find(|s|if personal(directory){s.personal}else{s.id=="synthetic-project-drive"}).ok_or("fixture space missing")?;
        let root=verified.client.stat_discovered_space_root_with_context(space,verified.context).map_err(|_|"verified Space root unavailable")?;
        let scope=EditJournalScope{profile_id:verified.provider_scope.profile_id().into(),server_origin:verified.provider_scope.server_origin().into(),account_subject:verified.provider_scope.account_id().into(),space_id:space.id.clone(),root_resource_id:root.id,root_volume_serial:identity.volume_serial,root_file_index:identity.file_index};
        if role=="save"{wait_child(spawn(directory,"io-edit",false)?,directory,"io-edit")?;}
        let expected_edited_hash=generated_hash(expected_len, true);
        let mut record_summary=Value::Null;
        wait_for(Duration::from_secs(90),||{
            let Some(protected)=store(scope.clone())? else { return Ok(false); };
            let records=match protected.discover_records() {
                Ok(records)=>records,
                Err(raiun_cloudfiles_windows::streamed_store::StoreError::Busy
                    | raiun_cloudfiles_windows::streamed_store::StoreError::IncompleteEvidence)=>return Ok(false),
                Err(_)=>return Err("v2 manifest/history authentication failed".into()),
            };
            if records.is_empty(){return Ok(false);}
            if records.len()!=1{return Err("unexpected extra v2 records retained".into());}
            let record=&records[0];let binding=record.manifest.binding();
            let expected_id=if personal(directory){"synthetic-personal-ordinary-save"}else{"synthetic-recovery-file"};
            let expected_path=if personal(directory){"ordinary-save.bin"}else{"RecoveryRoot/document.bin"};
            if binding.scope!=scope || record.key.scope()!=&scope || binding.generation!=record.key.generation()
                || binding.relative_path!=expected_path || binding.content_len!=expected_len
                || binding.local_file.volume_serial!=identity.volume_serial || binding.local_file.file_index==0
                || binding.local_file.file_index==identity.file_index
                || binding.remote.as_ref().is_none_or(|remote|remote.resource_id!=expected_id || remote.etag!="\"synthetic-file-v1\"" || remote.byte_len!=expected_len)
                || record.manifest.content_sha256().iter().map(|b|format!("{b:02x}")).collect::<String>()!=expected_edited_hash{return Err("authenticated manifest binding/content mismatch".into());}
            let terminal=if pending_case(directory){matches!(record.state,StreamedAttemptState::Deferred{attempt_id:1,attempts:1})}else{matches!(record.state,StreamedAttemptState::LocallyAcknowledged{attempt_id:1,attempts:1})};
            if !terminal{return Ok(false);}
            let(flags,length)=native_flags(&agent,directory)?;if length!=expected_len || ((flags&8)!=0)==pending_case(directory){return Err("native in-sync/dirty state mismatch".into());}
            let pending=verified.recovery_provider.has_unresolved_edits().map_err(|_|"pending recovery summary failed")?;if pending!=pending_case(directory){return Err("v2 pending status mismatch".into());}
            record_summary=json!({"record_id":record.key.record_id(),"generation":record.key.generation(),"commitment":record.key.commitment_sha256().iter().map(|b|format!("{b:02x}")).collect::<String>(),"bytes":expected_len,"sha256":expected_edited_hash,"local_file_index":binding.local_file.file_index,"native_in_sync":flags&8!=0,"durable_v2_ack":!pending_case(directory),"pending":pending,"configured_job_timeout_seconds":config.windows_recovery.as_ref().cloned().unwrap_or_default().total_timeout_seconds});Ok(true)
        })?;
        if role=="save"{write_json(&directory.join("RECORD.json"),record_summary.clone());}else{let previous:Value=serde_json::from_slice(&std::fs::read(directory.join("RECORD.json")).unwrap()).unwrap();if record_summary!=previous{return Err("v2 commitment/generation/state changed across restart".into());}wait_child(spawn(directory,"io-retained",false)?,directory,"io-retained")?;}
        if agent.provider.folder_generation.load(Ordering::Acquire)!=0{return Err("folder worker unexpectedly active".into());}
        Ok(record_summary)
    })).unwrap_or_else(|_|Err("streamed fixture assertion failed; evidence retained".into()));
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    let cleanup = broker.clone();
    thread::spawn(move || {
        let unmount = cleanup.handle(&request("unmount"));
        let stopped = cleanup.stop_all();
        let _ = send.send((unmount, stopped));
    });
    let cleanup = lifecycle(receive, directory, role);
    let normal = cleanup.as_ref().is_ok_and(|(u, s)| u.is_ok() && s.is_ok());
    let final_role = format!("io-final-{role}");
    let retained = if normal {
        let identity = agent
            .state
            .lock()
            .unwrap()
            .root_configuration
            .as_ref()
            .map(|root| raiun_cloudfiles_windows::ConfiguredRootIdentity {
                volume_serial: root.volume_serial,
                file_index: root.file_index,
            });
        identity.is_some_and(|identity| {
            pin_registered_configured_root(&config.mount_path, identity).is_ok()
        }) && spawn(directory, &final_role, false)
            .and_then(|child| wait_child(child, directory, &final_role))
            .is_ok()
    } else {
        false
    };
    let passed = exercise.is_ok() && normal && retained;
    write_json(
        &directory.join(format!("{role}.RESULTS.json")),
        json!({"passed":passed,"detail":exercise.as_ref().ok(),"error":exercise.as_ref().err(),"normal_unmount_stop":normal,"edited_bytes_registration_retained":retained,"forced_cleanup":false,"runtime_elapsed_millis":runtime_started.elapsed().as_millis()}),
    );
    assert!(passed, "streamed fixture incomplete; evidence retained");
}

#[test]
fn diagnostic_guard_and_pattern_parameters_are_exact() {
    assert!(valid_invocation(&[
        "--ignored".into(),
        "--exact".into(),
        TEST.into()
    ]));
    assert!(!valid_invocation(&["--ignored".into(), TEST.into()]));
    for origin in [
        "https://example.test",
        "http://localhost:123",
        "http://127.0.0.1:0",
        "http://127.0.0.1:123/path",
    ] {
        assert!(!loopback_origin(origin));
    }
    assert!(loopback_origin("http://127.0.0.1:123"));
    assert_ne!(generated_hash(LENGTH, false), generated_hash(LENGTH, true));
    assert_ne!(
        generated_hash(SMALL_LENGTH, false),
        generated_hash(SMALL_LENGTH, true)
    );
    assert!(case_length(Path::new("personal-small-paced")) < 16 * 1024 * 1024);
    let expiration = Path::new("personal-paced-expired");
    assert!(expired(expiration) && paced(expiration) && pending_case(expiration));
    assert!(!forbidden(expiration));
    assert_eq!(case_length(expiration), LENGTH);
    assert_eq!(readback_rate(expiration), 64 * 1024);
    assert_eq!(job_timeout_seconds(expiration), 60);
    for success in ["personal-paced", "personal-small-paced"] {
        let path = Path::new(success);
        assert!(!pending_case(path));
        assert_eq!(job_timeout_seconds(path), 120);
    }
    assert_eq!(byte(1, false), byte(1, true));
    assert_ne!(byte(0, false), byte(0, true));
}

#[test]
fn diagnostic_case_selection_is_exact_and_absence_preserves_full_matrix() {
    use std::ffi::OsStr;
    assert_eq!(requested_cases(None).unwrap(), ALL_CASES);
    for case in ALL_CASES.into_iter().chain(POLICY_CASES) {
        assert_eq!(requested_cases(Some(OsStr::new(case))).unwrap(), [case]);
    }
    for invalid in [
        "",
        "all",
        "personal",
        "personal-success ",
        " personal-success",
        "PERSONAL-SUCCESS",
        "personal-success,space-success",
        "../personal-success",
    ] {
        assert!(requested_cases(Some(OsStr::new(invalid))).is_err());
    }
}
