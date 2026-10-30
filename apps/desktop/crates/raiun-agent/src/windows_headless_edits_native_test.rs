//! Future candidate native follow-up; C7 read/write fixtures remain independent.
use super::*;
const TEST: &str = "agent_windows::windows_profiles::windows_headless_edits_native_test::ordinary_403_recovery_requires_current_scope_and_exact_local_file";
const DIRECTORY: &str = "RAIUN_HEADLESS_EDITS_FIXTURE_DIR";
const CHILD: &str = "RAIUN_HEADLESS_EDITS_FIXTURE_CHILD";

#[test]
#[ignore = "actual Cloud Files write/recovery; requires new owned NTFS fixture and explicit authorized Windows execution"]
fn ordinary_403_recovery_requires_current_scope_and_exact_local_file() {
    let directory = PathBuf::from(std::env::var_os(DIRECTORY).expect("explicit fixture directory"));
    assert!(directory.is_absolute() && directory.is_dir());
    assert_eq!(
        std::fs::read_to_string(directory.join("OWNER.txt")).unwrap(),
        "raiun-headless-edits-native-v1\n"
    );
    if std::env::var(CHILD).as_deref() == Ok("os-write") {
        os_write(&directory);
        return;
    }
    if std::env::var(CHILD).as_deref() == Ok("runtime") {
        runtime(&directory);
        return;
    }
    assert!(std::env::var_os(CHILD).is_none());
    assert!(std::fs::read_dir(&directory).unwrap().all(|entry| matches!(
        entry.unwrap().file_name().to_str(),
        Some("OWNER.txt" | "runner.json" | "supervisor.stdout.log" | "supervisor.stderr.log")
    )));
    std::fs::create_dir(directory.join("cloud-root")).unwrap();
    let (server, fixture) = super::super::tests::synthetic_headless_ordinary_write_server(
        |_| {},
        directory.join("failure-armed"),
        super::super::tests::SyntheticOrdinaryWriteMode::Forbidden,
    );
    let config = directory.join("config.json");
    std::fs::write(&config,serde_json::to_vec(&json!({"schema_version":1,"server":server,"auth":"app_token","username":"synthetic-user","mount_path":directory.join("cloud-root"),"auto_mount":true,"remember_login":true,"reconnect_interval_seconds":1,"profile":"default"})).unwrap()).unwrap();
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            TEST,
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, "runtime")
        .env(DIRECTORY, &directory)
        .env("RAIUN_HEADLESS_CONTEXT", "1")
        .env("RAIUN_STATE_DIR", directory.join("state"))
        .env("RAIUN_HEADLESS_CONFIG", config)
        .stdin(std::process::Stdio::null())
        .stdout(std::fs::File::create(directory.join("runtime.stdout.log")).unwrap())
        .stderr(std::fs::File::create(directory.join("runtime.stderr.log")).unwrap())
        .spawn()
        .unwrap();
    let passed = bounded_child(child, &directory, "runtime", Duration::from_secs(240)).is_ok();
    let remote = fixture.ordinary_write_snapshot();
    let receipt: Value = std::fs::read(directory.join("CHILD-RESULTS.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or(Value::Null);
    let passed = passed
        && receipt["passed"] == true
        && remote.put_attempt_count == 2
        && remote.put_count == 1
        && remote.forbidden_put_count == 1
        && fixture.global_mutation_attempts() == 2;
    std::fs::write(directory.join("RESULTS.json"),serde_json::to_vec_pretty(&json!({"passed":passed,"fixture":"headless-edits-native-v1","child":receipt,"remote":remote,"global_mutation_attempts":fixture.global_mutation_attempts(),"request_count":fixture.request_count(),"ordinary_space_only":true,"unregister_attempted":false,"old_generation_completion_supported":false})).unwrap()).unwrap();
    if !passed {
        /* Never join/kill a timed-out runtime that may still need the server. */
        std::mem::forget(fixture);
        panic!("recovery native fixture failed; root/state/process receipts retained");
    }
    fixture.join().unwrap();
}

fn bounded_child(
    mut child: std::process::Child,
    directory: &Path,
    name: &str,
    timeout: Duration,
) -> Result<(), String> {
    let pid = child.id();
    let deadline = Instant::now() + timeout;
    let receipt = |state: &str| {
        std::fs::write(directory.join(format!("{name}.process.json")),serde_json::to_vec(&json!({"pid":pid,"state":state,"forced_stop":false,"timeout_seconds":timeout.as_secs()})).unwrap()).map_err(|_|"cannot save process receipt".to_owned())
    };
    receipt("running")?;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                receipt("exited")?;
                return if status.success() {
                    Ok(())
                } else {
                    Err("fixture child failed".into())
                };
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                receipt("timed_out_retained")?;
                return Err("fixture child timed out without forced stop".into());
            }
            Err(_) => {
                receipt("wait_failed_retained")?;
                return Err("fixture child wait failed".into());
            }
        }
    }
}

fn status_context(broker: &WindowsProfiles) -> Value {
    let status = broker
        .handle(&json!({"action":"status","required_mode":"mount_only","profile_id":"default"}))
        .unwrap()
        .0;
    json!({"required_mode":"mount_only","profile_id":"default","expected_generation":status["auth_generation"],"expected_recovery_scope_token":status["root_configuration"]["recovery_scope_token"]})
}

fn runtime(directory: &Path) {
    let config = crate::headless_runtime::config().unwrap().unwrap();
    assert_eq!(config.mount_path, directory.join("cloud-root"));
    let broker = WindowsProfiles::open(DpapiSessionStore::current_user().unwrap()).unwrap();
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
        broker.handle_owned(windows_vault_requests::OwnedControlRequest::new(json!({"action":"auth_app_token","required_mode":"mount_only","profile_id":"default","server":config.server,"username":"synthetic-user","app_token":"synthetic-headless-app-token"}))).unwrap();
        let deadline=Instant::now()+Duration::from_secs(30);
        while !agent.state.lock().unwrap().online_authenticated { assert!(Instant::now()<deadline);thread::sleep(Duration::from_millis(20)); }
        let mount=agent.headless_configured_mount_request().unwrap().unwrap(); assert_eq!(broker.handle(&mount).unwrap().0["mounted"],true);
        let child=std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--ignored","--exact",TEST,"--nocapture","--test-threads=1"])
            .env(CHILD,"os-write").stdin(std::process::Stdio::null())
            .stdout(std::fs::File::create(directory.join("os.stdout.log")).unwrap()).stderr(std::fs::File::create(directory.join("os.stderr.log")).unwrap())
            .spawn().map_err(|_|"cannot spawn ordinary file child")?;
        bounded_child(child,directory,"os",Duration::from_secs(45))?;
        let deadline=Instant::now()+Duration::from_secs(30);
        loop {
            let status=broker.handle(&json!({"action":"status","required_mode":"mount_only","profile_id":"default"})).unwrap().0;
            if status["ordinary_edits"]["pending_count"]==1 && status["ordinary_edits"]["last_outcome"]=="not_completed" {break;}
            assert!(Instant::now()<deadline,"403 must be visible as retained pending edit"); thread::sleep(Duration::from_millis(30));
        }
        let mut list=status_context(&broker);list["action"]=json!("windows_recovery_list");
        let page=broker.handle(&list).unwrap().0;assert_eq!(page["items"].as_array().unwrap().len(),1);
        let item=&page["items"][0];
        let mut retry=status_context(&broker);retry["action"]=json!("windows_recovery_retry");retry["record_id"]=item["record_id"].clone();retry["generation"]=item["generation"].clone();
        retry["local_components"]=json!(["Spaces","Projects","RecoveryRoot","missing.bin"]);
        // Stale generation and root token reject before any remote request.
        let client=reqwest::blocking::Client::new();
        let count=||client.get(format!("{}/__test/request_count",config.server)).send().unwrap().text().unwrap().parse::<usize>().unwrap();
        let before=count(); let mut stale=retry.clone();stale["expected_generation"]=json!(retry["expected_generation"].as_u64().unwrap()+1);assert!(broker.handle(&stale).is_err());assert_eq!(count(),before+1);
        let before=count();stale=retry.clone();stale["expected_recovery_scope_token"]=json!("0".repeat(64));assert!(broker.handle(&stale).is_err());assert_eq!(count(),before+1);
        std::fs::write(directory.join("failure-armed"),b"released\n").unwrap();
        let wrong=broker.handle(&retry).unwrap().0;assert_eq!(wrong["remote_verified"],true);assert_ne!(wrong["local_completion"],"completed");
        let page=broker.handle(&list).unwrap().0;assert_eq!(page["items"].as_array().unwrap().len(),1,"wrong local path cannot retire protected record");
        let mut correct=status_context(&broker);correct["action"]=json!("windows_recovery_retry");correct["record_id"]=item["record_id"].clone();correct["generation"]=item["generation"].clone();correct["local_components"]=json!(["Spaces","Projects","RecoveryRoot","document.bin"]);
        let completed=broker.handle(&correct).unwrap().0;assert_eq!(completed["remote_verified"],true);assert_eq!(completed["local_completion"],"completed");
        let deadline=Instant::now()+Duration::from_secs(10);
        loop {let status=broker.handle(&json!({"action":"status","required_mode":"mount_only","profile_id":"default"})).unwrap().0;
            if status["ordinary_edits"]["state"]=="known" && status["ordinary_edits"]["pending_count"]==0 {break;}
            assert!(Instant::now()<deadline);thread::sleep(Duration::from_millis(20));}
        assert!(broker.handle(&list).unwrap().0["items"].as_array().unwrap().is_empty());
        assert_eq!(agent.provider.folder_generation.load(Ordering::Acquire),0);
        Ok(json!({"pending_403_detected":true,"stale_generation_and_scope_no_remote_io":true,"wrong_path_retains":true,"exact_path_completed":true,"native_and_journal_completion_required":true}))
    })).unwrap_or_else(|_|Err("native recovery assertion failed".into()));
    let unmount = broker
        .handle(&json!({"action":"unmount","required_mode":"mount_only","profile_id":"default"}));
    let stopped = broker.stop_all();
    let passed = exercise.is_ok() && unmount.is_ok() && stopped.is_ok();
    std::fs::write(directory.join("CHILD-RESULTS.json"),serde_json::to_vec_pretty(&json!({"passed":passed,"detail":exercise.as_ref().ok(),"error":exercise.as_ref().err(),"safe_unmount":unmount.is_ok(),"normal_stop":stopped.is_ok(),"root_state_retained":true})).unwrap()).unwrap();
    assert!(passed, "native recovery fixture failed; evidence retained");
}

fn os_write(directory: &Path) {
    use std::io::{Read, Seek, SeekFrom, Write};
    let root = directory.join("cloud-root");
    for path in [
        root.join("Spaces"),
        root.join("Spaces/Projects"),
        root.join("Spaces/Projects/RecoveryRoot"),
    ] {
        std::fs::read_dir(path).unwrap().for_each(|entry| {
            entry.unwrap();
        });
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join("Spaces/Projects/RecoveryRoot/document.bin"))
        .unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"original synthetic placeholder bytes");
    std::fs::write(directory.join("failure-armed"), b"armed\n").unwrap();
    bytes[0] ^= 0x5a;
    file.seek(SeekFrom::Start(0)).unwrap();
    file.write_all(&bytes).unwrap();
    file.sync_all().unwrap();
    drop(file);
}
