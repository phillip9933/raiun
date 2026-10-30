//! Opt-in acceptance of installed production executables, not an in-process broker.
//! This diagnostic process only supplies the loopback server and observations.
use super::*;
use std::io::{Read as _, Write as _};
use std::process::{Child, Command, Stdio};

const DIRECTORY: &str = "RAIUN_HEADLESS_CLI_FIXTURE_DIR";
const INSTALL: &str = "RAIUN_HEADLESS_CLI_INSTALL_DIR";
const TOKEN: &str = "synthetic-headless-app-token";
const MAX_OUTPUT: u64 = 1024 * 1024;
const LOGON_STARTUP: &str = "RAIUN_HEADLESS_CLI_LOGON_STARTUP";

fn stage(directory: &Path, name: &str) {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(directory.join("stages.log"))
        .expect("open retained stage receipt");
    writeln!(file, "{name}").expect("write stage receipt");
    file.flush().expect("flush stage receipt");
}

fn clean(command: &mut Command) -> &mut Command {
    for name in [
        "RAIUN_HEADLESS_CONTEXT",
        "RAIUN_HEADLESS_CONFIG",
        "RAIUN_STATE_DIR",
        "RAIUN_HEADLESS_NATIVE_FIXTURE_CHILD",
        "RAIUN_HEADLESS_NATIVE_FIXTURE_DIR",
        LOGON_STARTUP,
    ] {
        command.env_remove(name);
    }
    command
}

fn wait(child: &mut Child, directory: &Path, timeout: Duration) -> Result<(), &'static str> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(_)) => return Err("task process exited unsuccessfully"),
            Err(_) => return Err("cannot observe task process"),
            Ok(None) => {}
        }
        if Instant::now() >= deadline {
            stage(
                directory,
                &format!("task_process_timeout_pid_{}", child.id()),
            );
            return Err("task process timeout; process retained, no forced termination");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

// Drain concurrently, bounded, without writing raw output or stdin credentials to logs.
fn capture(command: Command, directory: &Path, token: bool) -> Result<Vec<u8>, &'static str> {
    capture_with_timeout(command, directory, token, Duration::from_secs(100))
}
fn capture_with_timeout(
    command: Command,
    directory: &Path,
    token: bool,
    timeout: Duration,
) -> Result<Vec<u8>, &'static str> {
    let output = capture_output(command, directory, token, timeout)?;
    output.exited?;
    Ok(output.stdout)
}

struct CapturedOutput {
    stdout: Vec<u8>,
    stderr_bytes: usize,
    exited: Result<(), &'static str>,
    exit_code: Option<i32>,
}

fn capture_output(
    mut command: Command,
    directory: &Path,
    token: bool,
    timeout: Duration,
) -> Result<CapturedOutput, &'static str> {
    clean(&mut command)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command.stdin(if token { Stdio::piped() } else { Stdio::null() });
    let mut child = command.spawn().map_err(|_| "cannot launch task process")?;
    let (sender, receiver) = std::sync::mpsc::channel();
    let stdout = child.stdout.take().ok_or("missing task stdout")?;
    let stderr = child.stderr.take().ok_or("missing task stderr")?;
    for (output, pipe) in [
        (true, Box::new(stdout) as Box<dyn std::io::Read + Send>),
        (false, Box::new(stderr) as Box<dyn std::io::Read + Send>),
    ] {
        let sender = sender.clone();
        thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = pipe
                .take(MAX_OUTPUT + 1)
                .read_to_end(&mut bytes)
                .map(|_| bytes);
            let _ = sender.send((output, result));
        });
    }
    drop(sender);
    if token {
        let mut stdin = child.stdin.take().ok_or("missing credential stdin")?;
        writeln!(stdin, "{TOKEN}").map_err(|_| "cannot supply synthetic credential stdin")?;
    }
    let exited = wait(&mut child, directory, timeout);
    // No raw diagnostic/error text is logged, even if a regression echoes stdin.
    // Drain even on nonzero exit so fixed diagnostic JSON can be retained
    // before the caller rejects the operation. A timeout still never kills.
    let exit_code = child
        .try_wait()
        .ok()
        .flatten()
        .and_then(|status| status.code());
    let mut stdout = None;
    let mut stderr_bytes = 0;
    for _ in 0..2 {
        let (output, result) = receiver
            .recv_timeout(Duration::from_secs(3))
            .map_err(|_| "task output did not close")?;
        let bytes = result.map_err(|_| "cannot read bounded task output")?;
        if bytes.len() as u64 > MAX_OUTPUT {
            return Err("task output exceeded bound");
        }
        if bytes
            .windows(TOKEN.len())
            .any(|part| part == TOKEN.as_bytes())
        {
            return Err("task output exposed synthetic credential; raw output withheld");
        }
        if output {
            stdout = Some(bytes);
        } else {
            stderr_bytes = bytes.len();
        }
    }
    Ok(CapturedOutput {
        stdout: stdout.ok_or("task process has no stdout")?,
        stderr_bytes,
        exited,
        exit_code,
    })
}

fn retain_task_observation(directory: &Path, value: &Value) -> Result<(), &'static str> {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(directory.join("TASK-OBSERVATIONS.jsonl"))
        .map_err(|_| "cannot retain fixed task observation")?;
    if file
        .metadata()
        .map_err(|_| "cannot inspect task receipt size")?
        .len()
        > 4 * MAX_OUTPUT
    {
        return Err("fixed task observation receipt exceeded bound");
    }
    serde_json::to_writer(&mut file, value).map_err(|_| "cannot write fixed task observation")?;
    writeln!(file).map_err(|_| "cannot finish fixed task observation")?;
    file.flush()
        .map_err(|_| "cannot flush fixed task observation")
}

fn sanitized_task_observation(value: &Value) -> Result<Value, &'static str> {
    let name = value["stage"]
        .as_str()
        .ok_or("missing task diagnostic stage")?;
    if !matches!(
        name,
        "identity"
            | "connect_com"
            | "open_folder"
            | "lookup_exact_task"
            | "execution_policy"
            | "read_definition"
            | "read_principal_sid"
            | "read_action"
            | "read_trigger_sid"
            | "check_binding"
            | "read_status"
            | "complete"
    ) {
        return Err("unknown task diagnostic stage");
    }
    let ok = value["observation_ok"]
        .as_bool()
        .ok_or("missing task diagnostic result")?;
    if !ok {
        if name == "complete" {
            return Err("failed task observation has a successful stage");
        }
        let hresult = value["hresult"]
            .as_i64()
            .filter(|v| i32::try_from(*v).is_ok())
            .ok_or("invalid task diagnostic HRESULT")?;
        return Ok(json!({"observation_ok":false,"stage":name,"hresult":hresult}));
    }
    if name != "complete" {
        return Err("incomplete successful task observation");
    }
    let policy_state = value["execution_policy_state"]
        .as_str()
        .ok_or("missing task execution policy telemetry state")?;
    let (policy, policy_hresult) = match policy_state {
        "available" => {
            let policy = value["execution_policy"]
                .as_str()
                .filter(|p| {
                    matches!(
                        *p,
                        "AllSigned"
                            | "RemoteSigned"
                            | "Restricted"
                            | "Unrestricted"
                            | "Bypass"
                            | "Undefined"
                    )
                })
                .ok_or("invalid task execution policy observation")?;
            if value.get("execution_policy_hresult") != Some(&Value::Null) {
                return Err("available policy telemetry must not carry an error");
            }
            (json!(policy), Value::Null)
        }
        "unavailable" => {
            if value.get("execution_policy") != Some(&Value::Null) {
                return Err("unavailable policy telemetry must not carry a policy");
            }
            let code = value["execution_policy_hresult"]
                .as_i64()
                .filter(|v| *v < 0 && i32::try_from(*v).is_ok())
                .ok_or("unavailable policy telemetry needs a failed signed HRESULT")?;
            (Value::Null, json!(code))
        }
        _ => return Err("unknown task execution policy telemetry state"),
    };
    let exists = value["exists"]
        .as_bool()
        .ok_or("missing task existence observation")?;
    let valid = value["binding_valid"]
        .as_bool()
        .ok_or("missing task binding observation")?;
    let mut safe = json!({"observation_ok":true,"stage":"complete","exists":exists,
        "binding_valid":valid,"execution_policy":policy,"execution_policy_state":policy_state,
        "execution_policy_hresult":policy_hresult});
    if exists {
        for key in ["state", "last_result", "logon_type"] {
            let number = value[key]
                .as_i64()
                .filter(|v| i32::try_from(*v).is_ok())
                .ok_or("invalid numeric task observation")?;
            safe[key] = json!(number);
        }
        safe["enabled"] = json!(
            value["enabled"]
                .as_bool()
                .ok_or("missing task admission observation")?
        );
    } else if valid {
        return Err("absent task cannot have a valid binding");
    }
    Ok(safe)
}

fn completed_task_observation(safe: Value) -> Result<Value, &'static str> {
    if safe["observation_ok"] != true {
        return Err("exact task inspection failed; inspect fixed task observation receipt");
    }
    Ok(safe)
}

#[test]
fn task_observation_diagnostics_are_bounded_fixed_fields() {
    let failed = sanitized_task_observation(&json!({"observation_ok":false,
        "stage":"connect_com","hresult":-2147024891_i64,"message":"untrusted secret text",
        "stdout":"untrusted stdout","task_xml":"untrusted definition"}))
    .unwrap();
    assert_eq!(
        failed,
        json!({"observation_ok":false,"stage":"connect_com","hresult":-2147024891_i64})
    );
    assert!(
        sanitized_task_observation(
            &json!({"observation_ok":false,"stage":"untrusted text","hresult":-1})
        )
        .is_err()
    );
    assert!(
        sanitized_task_observation(
            &json!({"observation_ok":false,"stage":"connect_com","hresult":i64::MAX})
        )
        .is_err()
    );
    assert!(
        sanitized_task_observation(&json!({"observation_ok":true,"stage":"complete",
        "exists":false,"binding_valid":false,"execution_policy_state":"available",
        "execution_policy_hresult":null,"execution_policy":"untrusted text"}))
        .is_err()
    );
    let absent = sanitized_task_observation(&json!({"observation_ok":true,"stage":"complete",
        "exists":false,"binding_valid":false,"execution_policy":"Restricted",
        "execution_policy_state":"available","execution_policy_hresult":null,"message":"discard me"})).unwrap();
    assert_eq!(absent.as_object().unwrap().len(), 7);
    assert_eq!(absent["execution_policy"], "Restricted");
    assert!(
        sanitized_task_observation(&json!({"observation_ok":true,"stage":"complete",
        "exists":false,"binding_valid":true,"execution_policy":"Restricted",
        "execution_policy_state":"available","execution_policy_hresult":null}))
        .is_err()
    );
}

#[test]
fn task_policy_telemetry_can_be_unavailable_without_bypassing_task_admission() {
    let observed = json!({"observation_ok":true,"stage":"complete","exists":true,
        "binding_valid":true,"state":4,"enabled":true,"last_result":267009,"logon_type":3,
        "execution_policy":null,"execution_policy_state":"unavailable",
        "execution_policy_hresult":-2146233087_i64});
    let safe = sanitized_task_observation(&observed).unwrap();
    assert_eq!(safe["execution_policy"], Value::Null);
    assert_eq!(safe["execution_policy_hresult"], -2146233087_i64);
    assert_eq!(
        completed_task_observation(safe).unwrap()["binding_valid"],
        true
    );

    let mut unbound = observed.clone();
    unbound["binding_valid"] = json!(false);
    assert_eq!(
        sanitized_task_observation(&unbound).unwrap()["binding_valid"],
        false,
        "optional telemetry must not turn a foreign binding into an owned one"
    );
    let mut com_error = observed.clone();
    com_error["observation_ok"] = json!(false);
    com_error["stage"] = json!("connect_com");
    com_error["hresult"] = json!(-2147024891_i64);
    assert!(completed_task_observation(sanitized_task_observation(&com_error).unwrap()).is_err());

    for (state, policy, error) in [
        ("unavailable", json!("Restricted"), json!(-2146233087_i64)),
        ("unavailable", Value::Null, Value::Null),
        ("unavailable", Value::Null, json!(0)),
        ("unavailable", Value::Null, json!(i64::MIN)),
        ("available", Value::Null, Value::Null),
        ("available", json!("Restricted"), json!(-2146233087_i64)),
        ("unknown", Value::Null, json!(-2146233087_i64)),
    ] {
        let mut malformed = observed.clone();
        malformed["execution_policy_state"] = json!(state);
        malformed["execution_policy"] = policy;
        malformed["execution_policy_hresult"] = error;
        assert!(sanitized_task_observation(&malformed).is_err());
    }
    for missing in [
        "execution_policy",
        "execution_policy_hresult",
        "execution_policy_state",
    ] {
        let mut malformed = observed.clone();
        malformed.as_object_mut().unwrap().remove(missing);
        assert!(sanitized_task_observation(&malformed).is_err());
    }
}

#[test]
fn task_observation_capture_keeps_failed_child_output_without_accepting_it() {
    const CHILD: &str = "RAIUN_TASK_OBSERVATION_CAPTURE_TEST_CHILD";
    const TEST: &str = "agent_windows::windows_profiles::windows_headless_cli_test::task_observation_capture_keeps_failed_child_output_without_accepting_it";
    if std::env::var(CHILD).as_deref() == Ok("1") {
        println!("fixed_nonzero_observation_marker");
        std::io::stdout().flush().unwrap();
        std::process::exit(31);
    }
    let directory = std::env::temp_dir().join(format!(
        "raiun-observation-capture-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
        .env(CHILD, "1");
    let output = capture_output(command, &directory, false, Duration::from_secs(20)).unwrap();
    assert_eq!(output.exit_code, Some(31));
    assert!(
        output.exited.is_err(),
        "nonzero exit must still fail acceptance"
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("fixed_nonzero_observation_marker"),
        "nonzero child output must be drained before rejection"
    );
    std::fs::remove_dir(&directory).unwrap();
}

struct Installed {
    cli: PathBuf,
    directory: PathBuf,
    config: PathBuf,
    state: PathBuf,
    mount: PathBuf,
}
impl Installed {
    fn command(&self, arguments: &[&str]) -> Command {
        let mut command = Command::new(&self.cli);
        command
            .arg("--config")
            .arg(&self.config)
            .arg("drive")
            .arg("--state-dir")
            .arg(&self.state)
            .arg("--json")
            .args(arguments);
        command
    }
    fn drive(&self, arguments: &[&str], token: bool) -> Result<Value, &'static str> {
        let bytes = capture(self.command(arguments), &self.directory, token)?;
        serde_json::from_slice(&bytes).map_err(|_| "installed CLI returned invalid JSON")
    }
    fn status_until(&self, mounted: bool) -> Result<Value, &'static str> {
        let deadline = Instant::now() + Duration::from_secs(75);
        loop {
            if let Ok(status) = self.drive(&["status"], false) {
                if status["runtime_mode"] != "mount_only" {
                    return Err("wrong production agent mode");
                }
                if status["connected"] == true && status["mounted"] == mounted {
                    return Ok(status);
                }
            }
            if Instant::now() >= deadline {
                return Err("installed agent did not become ready");
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
    fn ordinary_reads(&self) -> Result<(), &'static str> {
        // External ordinary OS reads must hydrate through the production provider.
        // No explicit CfHydratePlaceholder fallback is used.
        let script = r#"$ErrorActionPreference='Stop'; try {
$root=$env:RAIUN_CLI_READ_ROOT
$names=@([IO.Directory]::GetFileSystemEntries($root)|ForEach-Object{[IO.Path]::GetFileName($_)}|Sort-Object)
if(($names -join ',') -cne 'Personal,Spaces'){throw 'namespace mismatch'}
$null=[IO.Directory]::GetFileSystemEntries((Join-Path $root 'Personal'))
$null=[IO.Directory]::GetFileSystemEntries((Join-Path $root 'Spaces'))
$null=[IO.Directory]::GetFileSystemEntries((Join-Path $root 'Spaces\Projects'))
$p=[Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes((Join-Path $root 'Personal\native-read.bin')))
$s=[Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes((Join-Path $root 'Spaces\Projects\native-read.bin')))
if($p -cne 'synthetic Personal native read bytes' -or $s -cne 'synthetic Projects Space native read bytes'){throw 'byte mismatch'}
[Console]::WriteLine('ordinary_os_reads_exact');exit 0
} catch {[Console]::WriteLine('ordinary_os_reads_failed');exit 24}"#;
        let mut command = Command::new("powershell.exe");
        command
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .env("RAIUN_CLI_READ_ROOT", &self.mount);
        let output = capture(command, &self.directory, false)?;
        if String::from_utf8_lossy(&output).trim() != "ordinary_os_reads_exact" {
            return Err("ordinary read completion missing");
        }
        Ok(())
    }
    fn task_id(&self) -> String {
        // Same opaque state identifier as startup.rs, never the admission proof.
        let key = self
            .state
            .to_string_lossy()
            .replace('/', "\\")
            .to_lowercase();
        let mut hash = 0xcbf29ce484222325_u64;
        for byte in key.as_bytes() {
            hash = (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3);
        }
        format!("{hash:016x}")
    }
    fn task_observation(&self) -> Result<Value, &'static str> {
        // Read-only COM inspection. Return only fixed observations, never task
        // XML, credential data, raw errors or other users' task inventory.
        let script = r#"$ErrorActionPreference='Stop'; $stage='identity'; try {
function Sid([string]$value) {
 if($value -match '^S-[0-9]-'){return ([Security.Principal.SecurityIdentifier]::new($value)).Value}
 return ([Security.Principal.NTAccount]::new($value)).Translate([Security.Principal.SecurityIdentifier]).Value
}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent(); $sid=$identity.User.Value
$stage='connect_com'; $service=New-Object -ComObject 'Schedule.Service'; $service.Connect()
$stage='open_folder'; $folder=$service.GetFolder('\')
$task=$null
$stage='lookup_exact_task'
try{$task=$folder.GetTask($env:RAIUN_TASK_NAME)}catch{
 $lookup=$_.Exception; while($null -ne $lookup.InnerException){$lookup=$lookup.InnerException}
 if($lookup.HResult -ne -2147024894){throw}
}
$stage='execution_policy'
# Optional telemetry only. Failure here is not a task-admission or status result.
$policy=$null; $policyState='unavailable'; $policyHResult=$null
try { $policy=[string](Get-ExecutionPolicy); $policyState='available' }
catch {
 $policyFailure=$_.Exception; while($null -ne $policyFailure.InnerException){$policyFailure=$policyFailure.InnerException}
 $policy=$null; $policyHResult=[int]$policyFailure.HResult
}
if($null -eq $task){@{observation_ok=$true;stage='complete';exists=$false;binding_valid=$false;
 execution_policy=$policy;execution_policy_state=$policyState;execution_policy_hresult=$policyHResult}|ConvertTo-Json -Compress;exit 0}
$stage='read_definition'
$d=$task.Definition
$stage='read_principal_sid'; $principalSid=Sid $d.Principal.UserId
$stage='read_action'; $action=$d.Actions.Item(1)
$stage='read_trigger_sid'; $trigger=$d.Triggers.Item(1); $triggerSid=Sid $trigger.UserId
$stage='check_binding'
$bound=(($d.RegistrationInfo.Source -ceq $env:RAIUN_TASK_SOURCE) -and ($principalSid -ceq $sid) -and
 $d.Principal.LogonType -eq 3 -and $d.Principal.RunLevel -eq 0 -and $d.Actions.Count -eq 1 -and
 $action.Type -eq 0 -and $action.Path -ceq $env:RAIUN_TASK_EXE -and
 $action.Arguments -ceq $env:RAIUN_TASK_ARGS -and $action.WorkingDirectory -ceq $env:RAIUN_TASK_CWD -and
 $d.Triggers.Count -eq 1 -and $trigger.Type -eq 9 -and $triggerSid -ceq $sid -and
 $trigger.Enabled -and $trigger.Delay -ceq 'PT10S' -and -not $d.Settings.AllowHardTerminate -and
 $d.Settings.MultipleInstances -eq 2 -and $d.Settings.ExecutionTimeLimit -ceq 'PT0S' -and
 $d.Settings.RestartInterval -ceq 'PT1M' -and $d.Settings.RestartCount -eq 999)
$stage='read_status'
@{observation_ok=$true;stage='complete';exists=$true;binding_valid=[bool]$bound;state=[int]$task.State;enabled=[bool]$task.Enabled;
 last_result=[long]$task.LastTaskResult;logon_type=[int]$d.Principal.LogonType;
 execution_policy=$policy;execution_policy_state=$policyState;execution_policy_hresult=$policyHResult}|ConvertTo-Json -Compress
} catch {
 $failure=$_.Exception; while($null -ne $failure.InnerException){$failure=$failure.InnerException}
 @{observation_ok=$false;stage=$stage;hresult=[int]$failure.HResult}|ConvertTo-Json -Compress
 exit 31
}"#;
        let mut command = Command::new("powershell.exe");
        command
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .env(
                "RAIUN_TASK_NAME",
                format!("Raiun Headless CLI {}", self.task_id()),
            )
            .env(
                "RAIUN_TASK_SOURCE",
                format!("RaiunHeadlessCLI-v1:{}", self.task_id()),
            )
            .env("RAIUN_TASK_EXE", &self.cli)
            .env(
                "RAIUN_TASK_CWD",
                self.cli.parent().ok_or("missing installed CLI directory")?,
            )
            // These fixture-owned absolute paths end in ordinary names; Windows
            // forbids embedded quotes, and neither argument has a trailing slash.
            .env(
                "RAIUN_TASK_ARGS",
                format!(
                    "--config \"{}\" drive --state-dir \"{}\" serve",
                    self.config.display(),
                    self.state.display()
                ),
            );
        let output = match capture_output(command, &self.directory, false, Duration::from_secs(100))
        {
            Ok(output) => output,
            Err(error) => {
                retain_task_observation(
                    &self.directory,
                    &json!({"observation_ok":false,
                    "stage":"capture","failure":error,"hresult":null}),
                )?;
                return Err(error);
            }
        };
        let safe = serde_json::from_slice(&output.stdout)
            .ok()
            .and_then(|value| sanitized_task_observation(&value).ok());
        let Some(mut safe) = safe else {
            retain_task_observation(
                &self.directory,
                &json!({"observation_ok":false,
                "stage":"decode","child_exit_code":output.exit_code,"stdout_bytes":output.stdout.len(),"stderr_bytes":output.stderr_bytes,
                "hresult":null}),
            )?;
            return Err("exact task inspection returned invalid fixed diagnostic JSON");
        };
        safe["child_exit_code"] = json!(output.exit_code);
        safe["stderr_bytes"] = json!(output.stderr_bytes);
        // Retain only allowlisted fixed fields BEFORE rejecting a failed child.
        // Raw stdout/stderr, task XML, names, account names and tokens stay out.
        retain_task_observation(&self.directory, &safe)?;
        output.exited?;
        completed_task_observation(safe)
    }
    fn startup(&self, action: &str) -> Result<(), &'static str> {
        // Task Scheduler observations independently validate the result; do
        // not depend on startup command output formatting.
        capture_with_timeout(
            self.command(&["startup", action, "--mode", "logon"]),
            &self.directory,
            false,
            Duration::from_secs(360),
        )
        .map(|_| ())
    }
    fn logon_round(&self, round: usize) -> Value {
        let initial = match self.task_observation() {
            Ok(value) if value["exists"] == false => value,
            Ok(_) => {
                return json!({"round":round,"passed":false,"registration_attempted":false,"failure":"preexisting task preserved"});
            }
            Err(error) => {
                return json!({"round":round,"passed":false,"registration_attempted":false,"failure":error});
            }
        };
        stage(
            &self.directory,
            &format!("logon_{round}:exact_task_absent_before_enable"),
        );
        // Even a failed registration/start can leave a task. Inspect its exact
        // binding and attempt normal disable in the cleanup path below.
        let enabled = self.startup("enable");
        let mut last_observation = initial.clone();
        let tested = (|| {
            enabled.map_err(|_| "installed CLI logon startup enable failed")?;
            let deadline = Instant::now() + Duration::from_secs(75);
            loop {
                last_observation = self.task_observation()?;
                if last_observation["exists"] == true && last_observation["binding_valid"] != true {
                    return Err("task binding changed; unrelated task must be preserved");
                }
                let result = last_observation["last_result"].as_i64();
                if last_observation["binding_valid"] == true
                    && last_observation["enabled"] == true
                    && last_observation["state"] == 4
                    && matches!(result, Some(0 | 267_009))
                {
                    break;
                }
                if Instant::now() >= deadline {
                    return Err("exact same-user logon task did not reach Running");
                }
                thread::sleep(Duration::from_millis(100));
            }
            stage(
                &self.directory,
                &format!("logon_{round}:same_user_interactive_task_running"),
            );
            let status = self.status_until(true)?;
            if status["folder_sync_enabled"] != false
                || status["credential_storage"] != "windows_dpapi"
            {
                return Err("scheduled runtime did not retain isolated DPAPI mount-only policy");
            }
            self.ordinary_reads()?;
            let observed = self.task_observation()?;
            if observed["binding_valid"] != true || observed["state"] != 4 {
                return Err("exact task was not running after ordinary reads");
            }
            stage(
                &self.directory,
                &format!("logon_{round}:restored_dpapi_automount_and_ordinary_reads_exact"),
            );
            Ok(())
        })();
        let mut task_removed = false;
        let mut registered = last_observation["binding_valid"] == true;
        let cleanup = match self.task_observation() {
            Ok(observed) if observed["exists"] == false => {
                task_removed = true;
                Ok(())
            }
            Ok(observed) if observed["binding_valid"] == true => {
                registered = true;
                last_observation = observed;
                self.startup("disable").and_then(|_| {
                    let after = self.task_observation()?;
                    if after["exists"] != false {
                        return Err("task retained after normal startup disable");
                    }
                    task_removed = true;
                    stage(
                        &self.directory,
                        &format!("logon_{round}:normal_stop_and_exact_task_removal_complete"),
                    );
                    Ok(())
                })
            }
            Ok(_) => Err("cleanup refused foreign task binding; task and state preserved"),
            Err(_) => Err("cleanup could not verify exact task; task and state preserved"),
        };
        json!({"round":round,"passed":tested.is_ok() && cleanup.is_ok(),"registration_attempted":true,
            "registration_observed":registered,"failure":tested.err(),"cleanup_failure":cleanup.err(),"task_removed":task_removed,
            "execution_policy":initial["execution_policy"],"last_task_observation":last_observation,
            "execution_policy_state":initial["execution_policy_state"],"execution_policy_hresult":initial["execution_policy_hresult"],
            "owner_password_used":false,"forced_task_stop":false})
    }
    fn logon_startup(&self) -> Value {
        let mut rounds = Vec::new();
        for round in 1..=2 {
            let result = self.logon_round(round);
            let passed = result["passed"] == true;
            rounds.push(result);
            if !passed {
                break;
            }
        }
        let passed = rounds.len() == 2 && rounds.iter().all(|round| round["passed"] == true);
        json!({"requested":true,"attempted":true,"passed":passed,"rounds":rounds,
            "task_name":format!("Raiun Headless CLI {}",self.task_id()),"manual_task_start":true,
            "task_observation_receipt":"TASK-OBSERVATIONS.jsonl",
            "actual_logon_trigger_delivery":false,"boot_session_zero_acceptance":false,"password_used":false})
    }

    fn phase(&self, phase: &str) -> Result<(), &'static str> {
        let mut command = self.command(&["serve"]);
        clean(&mut command).stdin(Stdio::null());
        // Only production agent diagnostics, never credential command stdout.
        for (name, stdout) in [("stdout", true), ("stderr", false)] {
            let file =
                std::fs::File::create(self.directory.join(format!("{phase}.agent.{name}.log")))
                    .map_err(|_| "cannot create retained production process log")?;
            if stdout {
                command.stdout(file);
            } else {
                command.stderr(file);
            }
        }
        let mut service = command
            .spawn()
            .map_err(|_| "cannot launch installed CLI serve")?;
        stage(
            &self.directory,
            &format!("{phase}:installed_serve_pid_{}", service.id()),
        );
        let tested = (|| {
            if phase == "login" {
                let deadline = Instant::now() + Duration::from_secs(45);
                loop {
                    if let Ok(status) = self.drive(&["status"], false) {
                        if status["runtime_mode"] != "mount_only" || status["connected"] != false {
                            return Err("fresh installed agent state was not signed out");
                        }
                        break;
                    }
                    if Instant::now() >= deadline {
                        return Err("fresh installed agent unavailable");
                    }
                    thread::sleep(Duration::from_millis(100));
                }
                let login = self.drive(&["login", "--app-token", "--token-stdin"], true)?;
                if login["connected"] != true || login["authentication"] != "app_token" {
                    return Err("stdin login did not report final verified completion");
                }
                stage(
                    &self.directory,
                    "login:installed_cli_stdin_completion_verified",
                );
            }
            let status = self.status_until(true)?;
            if status["folder_sync_enabled"] != false {
                return Err("folder sync must be disabled");
            }
            if phase == "restart" {
                stage(
                    &self.directory,
                    "restart:remembered_session_and_automount_without_login",
                );
            }
            let spaces = self.drive(&["spaces"], false)?;
            let serialized = spaces.to_string();
            if !serialized.contains("synthetic-personal-drive")
                || !serialized.contains("synthetic-project-drive")
            {
                return Err("installed CLI did not discover both expected Spaces");
            }
            self.ordinary_reads()?;
            stage(&self.directory, &format!("{phase}:ordinary_os_reads_exact"));
            Ok(())
        })();
        // Always attempt normal unmount and stop after any assertion failure.
        let unmounted = self.drive(&["unmount"], false).and_then(|_| {
            let status = self.drive(&["status"], false)?;
            if status["mounted"] != false {
                return Err("safe unmount left provider connected");
            }
            thread::sleep(Duration::from_millis(1200));
            let status = self.drive(&["status"], false)?;
            if status["mounted"] != false {
                return Err("late automatic remount after unmount");
            }
            Ok(())
        });
        if unmounted.is_ok() {
            stage(
                &self.directory,
                &format!("{phase}:cli_safe_unmount_complete"),
            );
        }
        let stopped = self.drive(&["stop"], false);
        let exited = wait(&mut service, &self.directory, Duration::from_secs(30));
        if stopped.is_ok() && exited.is_ok() {
            stage(
                &self.directory,
                &format!("{phase}:cli_stop_and_foreground_exit_complete"),
            );
        }
        tested?;
        unmounted?;
        stopped?;
        exited
    }
}

#[test]
#[ignore = "actual installed CLI/native Cloud Files read; only test-headless-cli-windows.ps1 on authorized disposable Windows"]
fn installed_cli_personal_spaces_and_remembered_restart() {
    let directory =
        PathBuf::from(std::env::var_os(DIRECTORY).expect("explicit runner evidence directory"));
    let install = PathBuf::from(std::env::var_os(INSTALL).expect("explicit runner fresh install"));
    assert!(directory.is_absolute() && install.is_absolute());
    assert_eq!(
        std::fs::read_to_string(directory.join("OWNER.txt")).unwrap(),
        "raiun-headless-installed-cli-v1\n"
    );
    assert!(std::fs::read_dir(&directory).unwrap().all(|entry| matches!(
        entry.unwrap().file_name().to_str(),
        Some("OWNER.txt" | "runner.json" | "supervisor.stdout.log" | "supervisor.stderr.log")
    )));
    assert!(install.join("raiun.exe").is_file() && install.join("raiun-agent.exe").is_file());
    assert!(std::env::var_os("RAIUN_HEADLESS_CONTEXT").is_none());
    assert!(std::env::var_os("RAIUN_HEADLESS_CONFIG").is_none());
    assert!(std::env::var_os("RAIUN_STATE_DIR").is_none());
    let mount = directory.join("cloud-root");
    std::fs::create_dir(&mount).unwrap();
    let (server, fixture) =
        super::super::tests::synthetic_headless_personal_spaces_server(|name| {
            stage(&directory, name)
        });
    let installed = Installed {
        cli: install.join("raiun.exe"),
        state: directory.join("state"),
        config: directory.join("headless.json"),
        mount,
        directory: directory.clone(),
    };
    std::fs::write(
        &installed.config,
        serde_json::to_vec(&json!({
            "schema_version":1,"server":server,"auth":"app_token","username":"synthetic-user",
            "mount_path":installed.mount,"auto_mount":true,"remember_login":true,
            "reconnect_interval_seconds":1,"profile":"default"
        }))
        .unwrap(),
    )
    .unwrap();
    let mut phases = Vec::new();
    for phase in ["login", "restart"] {
        let result = installed.phase(phase);
        phases.push(json!({"phase":phase,"passed":result.is_ok(),"failure":result.err()}));
        if result.is_err() {
            break;
        }
    }
    let direct_passed = phases.len() == 2 && phases.iter().all(|phase| phase["passed"] == true);
    let startup_requested = std::env::var(LOGON_STARTUP).as_deref() == Ok("1");
    let startup = if startup_requested && direct_passed {
        installed.logon_startup()
    } else {
        json!({"requested":startup_requested,"attempted":false,"passed":false,"rounds":[],"failure":if startup_requested { Some("direct CLI phases failed; startup not attempted") } else { None }})
    };
    std::fs::write(
        directory.join("LOGON-STARTUP.json"),
        serde_json::to_vec_pretty(&startup).unwrap(),
    )
    .unwrap();
    let (personal, project, mismatch, legacy_mutations) = fixture.read_counts();
    let mutations = fixture.global_mutation_attempts();
    let passed = (!startup_requested || startup["passed"] == true)
        && phases.len() == 2
        && phases.iter().all(|phase| phase["passed"] == true)
        && personal > 0
        && project > 0
        && mismatch == 0
        && mutations == 0;
    std::fs::write(directory.join("RESULTS.json"), serde_json::to_vec_pretty(&json!({
        "fixture":"installed-headless-cli-v1","passed":passed,"phases":phases,"direct_cli_passed":direct_passed,
        "logon_startup":startup,
        "production_executables":true,"named_pipe_cli":direct_passed,"stdin_login_completion":phases.first().is_some_and(|phase| phase["passed"] == true),
        "personal_get_count":personal,"space_get_count":project,"etag_mismatch_count":mismatch,
        "mutation_attempt_count":mutations,"legacy_native_read_mutation_attempt_count":legacy_mutations,"ordinary_os_reads":direct_passed,"explicit_hydration_fallback":false,
        "registration_cleanup":"not attempted; roots, registrations, state, install and logs retained",
        "real_accounts_used":false,"boot_session_zero_acceptance":false,"writes_acceptance":false
    })).unwrap()).unwrap();
    fixture.join().expect("join synthetic loopback server");
    assert!(
        passed,
        "installed production CLI fixture failed; inspect retained receipts, no forced cleanup occurred"
    );
}
