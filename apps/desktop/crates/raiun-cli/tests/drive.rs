//! Synthetic sibling-process tests. No real agent, mounts, or sign-ins are used.
#![cfg(target_os = "linux")]
use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};
use tempfile::TempDir;

// Overlay-backed test directories can briefly report ETXTBSY immediately after
// installing an executable fixture. Retry only that OS launch error; command
// failures and all other errors are returned unchanged.
trait FixtureOutput {
    fn fixture_output(&mut self) -> std::io::Result<Output>;
}
impl FixtureOutput for Command {
    fn fixture_output(&mut self) -> std::io::Result<Output> {
        for _ in 0..20 {
            match self.output() {
                Err(error) if error.raw_os_error() == Some(26) => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                result => return result,
            }
        }
        self.output()
    }
}

struct Fixture {
    dir: TempDir,
    exe: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("raiun");
        fs::hard_link(env!("CARGO_BIN_EXE_raiun"), &exe)
            .or_else(|_| fs::copy(env!("CARGO_BIN_EXE_raiun"), &exe).map(|_| ()))
            .unwrap();
        let stub = dir.path().join("raiun-agent");
        fs::write(
            &stub,
            r#"#!/bin/sh
printf '%s\n' "$RAIUN_STATE_DIR" "$1" "$2" >> "$CAPTURE"
printf '%s\n' "$RAIUN_HEADLESS_CONFIG" >> "$CONFIG_CAPTURE"
if [ "$1" = serve ]; then exit 0; fi
if [ "$1" = request-stdin ]; then cat > "$INPUT_CAPTURE"; fi
case "$2" in
  *'"profile_id"'*) ;;
  *'"action":"status"'*) printf '%s\n' "$PROBE_REPLY"; exit 0 ;;
esac
if [ -n "$LOGIN_STATUS_FIRST" ]; then
  case "$2" in
    *'"action":"status"'*)
      count=0
      if [ -f "$STATUS_COUNT" ]; then count=$(cat "$STATUS_COUNT"); fi
      printf '%s' "$((count + 1))" > "$STATUS_COUNT"
      if [ "$count" = 0 ]; then printf '%s\n' "$LOGIN_STATUS_FIRST"; else printf '%s\n' "$LOGIN_STATUS_NEXT"; fi
      exit 0 ;;
  esac
fi
if [ "$FLOOD" = yes ]; then head -c 1048577 /dev/zero; exit 0; fi
if [ "$FAIL" = yes ]; then echo 'synthetic private diagnostic' >&2; exit 1; fi
printf '%s\n' "$REPLY"
"#,
        )
        .unwrap();
        fs::set_permissions(stub, fs::Permissions::from_mode(0o700)).unwrap();
        Self { dir, exe }
    }
    fn command(&self) -> Command {
        let mut command = Command::new(&self.exe);
        command
            .env("CAPTURE", self.dir.path().join("capture"))
            .env("CONFIG_CAPTURE", self.dir.path().join("config-capture"))
            .env("INPUT_CAPTURE", self.dir.path().join("input-capture"))
            .env("STATUS_COUNT", self.dir.path().join("status-count"))
            .env("HOME", self.dir.path())
            .env_remove("RAIUN_STATE_DIR")
            .env_remove("RAIUN_HEADLESS_CONFIG")
            .env_remove("XDG_STATE_HOME")
            .env(
                "PROBE_REPLY",
                r#"{"ok":true,"data":{"runtime_mode":"mount_only"}}"#,
            )
            .env("REPLY", r#"{"ok":true,"data":{"synthetic":true}}"#)
            .arg("drive");
        command
    }
    fn requests(&self) -> Vec<Value> {
        fs::read_to_string(self.dir.path().join("capture"))
            .unwrap()
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect()
    }
}
fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}
fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn state_is_isolated_and_profile_is_explicit() {
    let f = Fixture::new();
    let result = f
        .command()
        .args(["status", "--profile", "account-2", "--json"])
        .fixture_output()
        .unwrap();
    assert!(result.status.success(), "{}", stderr(&result));
    assert_eq!(
        serde_json::from_slice::<Value>(&result.stdout).unwrap(),
        json!({"synthetic":true})
    );
    let capture = fs::read_to_string(f.dir.path().join("capture")).unwrap();
    assert!(
        capture.contains(
            &f.dir
                .path()
                .join(".local/state/raiun-headless")
                .display()
                .to_string()
        )
    );
    assert_eq!(
        f.requests()[1],
        json!({"action":"status","profile_id":"account-2","required_mode":"mount_only"})
    );
}
#[test]
fn explicit_state_overrides_environment_and_mount_configures_before_enable() {
    let f = Fixture::new();
    let state = f.dir.path().join("explicit");
    let root = f.dir.path().join("mount");
    let result = f
        .command()
        .env("RAIUN_STATE_DIR", f.dir.path().join("wrong"))
        .arg("--state-dir")
        .arg(&state)
        .arg("mount")
        .arg("--path")
        .arg(&root)
        .fixture_output()
        .unwrap();
    assert!(result.status.success(), "{}", stderr(&result));
    let requests = f.requests();
    assert_eq!(
        requests[1],
        json!({"action":"configure","cloud_root":root,"profile_id":"default","required_mode":"mount_only"})
    );
    assert_eq!(requests[2]["action"], "mount");
    let capture = fs::read_to_string(f.dir.path().join("capture")).unwrap();
    assert_eq!(capture.lines().next().unwrap(), state.to_str().unwrap());
}
#[test]
fn relative_paths_fail_before_any_agent_request() {
    for args in [
        vec!["--state-dir", "relative", "status"],
        vec!["mount", "--path", "relative"],
        vec!["accounts", "add", "--label", "Work", "--path", "relative"],
    ] {
        let f = Fixture::new();
        let result = f.command().args(args).fixture_output().unwrap();
        assert!(!result.status.success());
        assert!(stderr(&result).contains("absolute path"));
        assert!(!f.dir.path().join("capture").exists());
    }
}
#[test]
fn envelope_errors_and_malformed_success_fail() {
    for reply in [
        r#"{"ok":false,"error":"synthetic denied"}"#,
        r#"{"ok":true}"#,
        r#"{"data":{}}"#,
        "not json",
    ] {
        let f = Fixture::new();
        let result = f
            .command()
            .env("REPLY", reply)
            .arg("spaces")
            .fixture_output()
            .unwrap();
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
    }
}
#[test]
fn legacy_desktop_agent_cannot_receive_mutation() {
    let f = Fixture::new();
    let result = f
        .command()
        .env("PROBE_REPLY", r#"{"ok":true,"data":{"connected":true}}"#)
        .args(["login", "--server", "cloud.invalid"])
        .fixture_output()
        .unwrap();
    assert!(!result.status.success());
    assert!(stderr(&result).contains("not running in mount-only mode"));
    assert_eq!(f.requests().len(), 1);
}
#[test]
fn login_prints_only_authorization_url_and_loopback_forwarding_guidance() {
    let f = Fixture::new();
    let url = "https://id.invalid/authorize?redirect_uri=http%3A%2F%2F127.0.0.1%3A43219%2Fcallback&state=synthetic";
    let reply = json!({"ok":true,"data":{"url":url,"expires_in":180}}).to_string();
    let browser = f.dir.path().join("browser-was-called");
    let result = f
        .command()
        .env("REPLY", reply)
        .env("BROWSER", &browser)
        .args([
            "login",
            "--server",
            "cloud.invalid",
            "--client-id",
            "synthetic-client",
            "--profile",
            "work",
        ])
        .fixture_output()
        .unwrap();
    assert!(result.status.success(), "{}", stderr(&result));
    assert_eq!(stdout(&result), format!("{url}\n"));
    assert!(stderr(&result).contains("ssh -N -L 43219:127.0.0.1:43219 USER@AGENT_HOST"));
    assert!(!browser.exists());
    assert_eq!(
        f.requests()[1],
        json!({"action":"auth_begin","server":"cloud.invalid","client_id":"synthetic-client","profile_id":"work","required_mode":"mount_only"})
    );
}
#[test]
fn accounts_and_stop_use_broker_actions() {
    let f = Fixture::new();
    let root = f.dir.path().join("cloud");
    let result = f
        .command()
        .args(["accounts", "add", "--label", "Work"])
        .arg("--path")
        .arg(&root)
        .fixture_output()
        .unwrap();
    assert!(result.status.success(), "{}", stderr(&result));
    assert_eq!(
        f.requests()[1],
        json!({"action":"account_add","label":"Work","cloud_root":root,"required_mode":"mount_only"})
    );
    let result = f.command().arg("stop").fixture_output().unwrap();
    assert!(result.status.success());
    assert_eq!(
        f.requests().last().unwrap(),
        &json!({"action":"shutdown","required_mode":"mount_only"})
    );
}
#[test]
fn serve_runs_foreground_mount_only_and_does_not_probe() {
    let f = Fixture::new();
    let result = f.command().arg("serve").fixture_output().unwrap();
    assert!(result.status.success(), "{}", stderr(&result));
    let capture = fs::read_to_string(f.dir.path().join("capture")).unwrap();
    assert!(capture.contains("\nserve\n--mount-only\n"));
}
#[test]
fn disconnected_errors_do_not_echo_private_agent_stderr() {
    let f = Fixture::new();
    let result = f
        .command()
        .env("FAIL", "yes")
        .arg("status")
        .fixture_output()
        .unwrap();
    assert!(!result.status.success());
    assert!(stderr(&result).contains("same --state-dir"));
    assert!(!stderr(&result).contains("private diagnostic"));
}
#[test]
fn output_is_bounded() {
    let f = Fixture::new();
    let result = f
        .command()
        .env("FLOOD", "yes")
        .arg("status")
        .fixture_output()
        .unwrap();
    assert!(!result.status.success());
    assert!(stderr(&result).contains("1 MiB limit"));
}
#[test]
fn help_and_unknown_commands() {
    let f = Fixture::new();
    let result = f.command().arg("--help").fixture_output().unwrap();
    assert!(result.status.success());
    assert!(stdout(&result).contains("--state-dir"));
    assert!(stdout(&result).contains("login"));
    let result = f
        .command()
        .arg("sign-in-with-password")
        .fixture_output()
        .unwrap();
    assert!(!result.status.success());
    assert!(stderr(&result).contains("unrecognized subcommand"));
}

#[test]
fn xdg_and_environment_state_are_respected_without_desktop_fallback() {
    for environment in ["XDG_STATE_HOME", "RAIUN_STATE_DIR"] {
        let f = Fixture::new();
        let root = f.dir.path().join("custom");
        let result = f
            .command()
            .env(environment, &root)
            .arg("status")
            .fixture_output()
            .unwrap();
        assert!(result.status.success(), "{}", stderr(&result));
        let expected = if environment == "XDG_STATE_HOME" {
            root.join("raiun-headless")
        } else {
            root
        };
        let capture = fs::read_to_string(f.dir.path().join("capture")).unwrap();
        assert_eq!(capture.lines().next().unwrap(), expected.to_str().unwrap());
    }
}

#[test]
fn login_rejects_missing_or_nonloopback_callback_before_printing_url() {
    for url in [
        "https://id.invalid/auth",
        "https://id.invalid/auth?redirect_uri=https%3A%2F%2Fevil.invalid%3A123%2Fcallback",
    ] {
        let f = Fixture::new();
        let reply = json!({"ok":true,"data":{"url":url}}).to_string();
        let result = f
            .command()
            .env("REPLY", reply)
            .args(["login", "--server", "cloud.invalid"])
            .fixture_output()
            .unwrap();
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
    }
}

fn write_config(f: &Fixture, profile: &str) -> PathBuf {
    let path = f.dir.path().join("headless.json");
    fs::write(
        &path,
        serde_json::to_vec(&json!({
            "schema_version":1,"server":"https://cloud.example.test","auth":"app_token",
            "username":"synthetic-user","mount_path":f.dir.path().join("cloud"),"profile":profile
        }))
        .unwrap(),
    )
    .unwrap();
    path
}

#[test]
fn explicit_config_is_absolute_required_and_validated_before_agent_access() {
    for path in [
        PathBuf::from("relative.json"),
        PathBuf::from("/synthetic-missing-headless-config.json"),
    ] {
        let f = Fixture::new();
        let result = f
            .command()
            .arg("--config")
            .arg(path)
            .arg("status")
            .fixture_output()
            .unwrap();
        assert!(!result.status.success());
        assert!(!f.dir.path().join("capture").exists());
    }
}

#[test]
fn config_commands_are_local_strict_and_preserve_existing_file() {
    let f = Fixture::new();
    let config = f.dir.path().join("config.json");
    let result = f
        .command()
        .arg("--config")
        .arg(&config)
        .args([
            "config",
            "init",
            "--server",
            "https://cloud.example.test",
            "--auth",
            "app_token",
            "--username",
            "synthetic-user",
            "--mount-path",
        ])
        .arg(f.dir.path().join("mount"))
        .fixture_output()
        .unwrap();
    assert!(result.status.success(), "{}", stderr(&result));
    let before = fs::read(&config).unwrap();
    for command in ["show", "check"] {
        let result = f
            .command()
            .arg("--config")
            .arg(&config)
            .args(["config", command])
            .fixture_output()
            .unwrap();
        assert!(result.status.success(), "{}", stderr(&result));
    }
    let result = f
        .command()
        .arg("--config")
        .arg(&config)
        .args([
            "config",
            "init",
            "--server",
            "https://other.example.test",
            "--mount-path",
        ])
        .arg(f.dir.path().join("other"))
        .fixture_output()
        .unwrap();
    assert!(!result.status.success());
    assert_eq!(fs::read(&config).unwrap(), before);
    assert!(!f.dir.path().join("capture").exists());
}

#[test]
fn config_supplies_profile_mount_path_and_serve_environment() {
    let f = Fixture::new();
    let profile = "profile-00000000000000000000000000000001";
    let path = write_config(&f, profile);
    let result = f
        .command()
        .arg("--config")
        .arg(&path)
        .arg("mount")
        .fixture_output()
        .unwrap();
    assert!(result.status.success(), "{}", stderr(&result));
    assert_eq!(f.requests()[1]["profile_id"], profile);
    assert_eq!(
        f.requests()[1]["cloud_root"],
        json!(f.dir.path().join("cloud"))
    );
    let result = f
        .command()
        .arg("--config")
        .arg(&path)
        .args(["--profile", "default", "status"])
        .fixture_output()
        .unwrap();
    assert!(!result.status.success());
    assert!(stderr(&result).contains("must match"));
    let result = f
        .command()
        .arg("--config")
        .arg(&path)
        .arg("serve")
        .fixture_output()
        .unwrap();
    assert!(result.status.success(), "{}", stderr(&result));
    assert_eq!(
        fs::read_to_string(f.dir.path().join("config-capture"))
            .unwrap()
            .lines()
            .last()
            .unwrap(),
        path.to_str().unwrap()
    );
}

#[test]
fn app_token_is_only_transmitted_through_bounded_stdin() {
    let f = Fixture::new();
    let config = write_config(&f, "default");
    let token_path = f.dir.path().join("synthetic-input");
    fs::write(&token_path, b"synthetic-private-token\r\n").unwrap();
    let result = f
        .command()
        .arg("--config")
        .arg(&config)
        .env(
            "REPLY",
            r#"{"ok":true,"data":{"connected":true,"auth_generation":7}}"#,
        )
        .env(
            "LOGIN_STATUS_FIRST",
            r#"{"ok":true,"data":{"connected":true,"auth_generation":7,"authenticating":false}}"#,
        )
        .args(["login", "--app-token", "--token-stdin"])
        .stdin(fs::File::open(&token_path).unwrap())
        .fixture_output()
        .unwrap();
    assert!(result.status.success(), "{}", stderr(&result));
    let arguments = fs::read_to_string(f.dir.path().join("capture")).unwrap();
    assert!(arguments.contains("request-stdin"));
    assert!(!arguments.contains("synthetic-private-token"));
    assert!(!arguments.contains("app_token"));
    let transport = fs::read(f.dir.path().join("input-capture")).unwrap();
    assert_eq!(
        transport.last(),
        Some(&b'\n'),
        "request-stdin uses the agent's JSON-line frame"
    );
    assert_eq!(transport.iter().filter(|byte| **byte == b'\n').count(), 1);
    let request: Value = serde_json::from_slice(&transport).unwrap();
    assert_eq!(
        request,
        json!({"action":"auth_app_token","required_mode":"mount_only","profile_id":"default","server":"https://cloud.example.test","username":"synthetic-user","app_token":"synthetic-private-token"})
    );
    assert!(!stdout(&result).contains("synthetic-private-token"));
    assert!(!stderr(&result).contains("synthetic-private-token"));
}

fn app_token_command(f: &Fixture) -> Command {
    let config = write_config(f, "default");
    let input = f.dir.path().join("synthetic-input");
    fs::write(&input, b"synthetic-private-token\n").unwrap();
    let mut command = f.command();
    command
        .arg("--config")
        .arg(config)
        .args(["login", "--app-token", "--token-stdin", "--json"])
        .env(
            "REPLY",
            r#"{"ok":true,"data":{"started":true,"auth_generation":7}}"#,
        )
        .stdin(fs::File::open(input).unwrap());
    command
}

fn assert_one_secret_submission(f: &Fixture) {
    let capture = fs::read_to_string(f.dir.path().join("capture")).unwrap();
    assert_eq!(
        capture
            .lines()
            .filter(|line| *line == "request-stdin")
            .count(),
        1
    );
    assert!(!capture.contains("synthetic-private-token"));
}

#[test]
fn app_token_waits_for_matching_generation_and_prints_final_result_once() {
    let f = Fixture::new();
    let result=app_token_command(&f)
        .env("LOGIN_STATUS_FIRST",r#"{"ok":true,"data":{"connected":false,"auth_generation":7,"authenticating":true}}"#)
        .env("LOGIN_STATUS_NEXT",r#"{"ok":true,"data":{"connected":true,"auth_generation":7,"authenticating":false,"mounted":false,"provider_supported":false,"error":"unrelated provider error synthetic-private-token c3ludGhldGljLXByaXZhdGUtdG9rZW4="}}"#)
        .fixture_output().unwrap();
    assert!(result.status.success(), "{}", stderr(&result));
    assert_eq!(
        serde_json::from_slice::<Value>(&result.stdout).unwrap(),
        json!({"connected":true,"authentication":"app_token","auth_generation":7,"profile_id":"default","mounted":false,"provider_supported":false})
    );
    assert_eq!(stdout(&result).lines().count(), 1);
    assert_eq!(
        fs::read_to_string(f.dir.path().join("status-count")).unwrap(),
        "2"
    );
    assert_one_secret_submission(&f);
    for secret in [
        "synthetic-private-token",
        "c3ludGhldGljLXByaXZhdGUtdG9rZW4=",
    ] {
        assert!(!stdout(&result).contains(secret));
        assert!(!stderr(&result).contains(secret));
    }
}

#[test]
fn app_token_async_rejection_or_disconnect_is_nonzero_without_secret_error_echo() {
    for status in [
        r#"{"ok":true,"data":{"connected":false,"auth_generation":7,"authenticating":false,"error":"invalid synthetic-private-token c3ludGhldGljLXByaXZhdGUtdG9rZW4="}}"#,
        r#"{"ok":true,"data":{"connected":false,"auth_generation":7,"authenticating":false,"error":null}}"#,
        r#"{"ok":false,"error":"synthetic-private-token c3ludGhldGljLXByaXZhdGUtdG9rZW4="}"#,
    ] {
        let f = Fixture::new();
        let result=app_token_command(&f)
            .env("LOGIN_STATUS_FIRST",r#"{"ok":true,"data":{"connected":false,"auth_generation":7,"authenticating":true}}"#)
            .env("LOGIN_STATUS_NEXT",status)
            .fixture_output().unwrap();
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        for secret in [
            "synthetic-private-token",
            "c3ludGhldGljLXByaXZhdGUtdG9rZW4=",
        ] {
            assert!(!stderr(&result).contains(secret));
        }
        assert_one_secret_submission(&f);
    }
}

#[test]
fn app_token_cannot_accept_a_replacement_account_generation_or_missing_generation() {
    for (response, status, expected) in [
        (
            r#"{"ok":true,"data":{"started":true,"auth_generation":7}}"#,
            r#"{"ok":true,"data":{"connected":true,"auth_generation":8,"authenticating":false}}"#,
            "account change",
        ),
        (
            r#"{"ok":true,"data":{"started":true}}"#,
            r#"{"ok":true,"data":{"connected":true,"auth_generation":7}}"#,
            "did not identify",
        ),
    ] {
        let f = Fixture::new();
        let result = app_token_command(&f)
            .env("REPLY", response)
            .env("LOGIN_STATUS_FIRST", status)
            .fixture_output()
            .unwrap();
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert!(stderr(&result).contains(expected));
        assert_one_secret_submission(&f);
    }
}

#[test]
fn app_token_submission_error_does_not_echo_remote_raw_or_encoded_token() {
    let f = Fixture::new();
    let result = app_token_command(&f)
        .env(
            "REPLY",
            r#"{"ok":false,"error":"synthetic-private-token c3ludGhldGljLXByaXZhdGUtdG9rZW4="}"#,
        )
        .fixture_output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(!stderr(&result).contains("synthetic-private-token"));
    assert!(!stderr(&result).contains("c3ludGhldGljLXByaXZhdGUtdG9rZW4="));
    assert_one_secret_submission(&f);
}

#[test]
fn app_token_rejects_empty_multiline_and_oversized_input_without_secret_request() {
    for token in [
        Vec::new(),
        b"synthetic\nsecond".to_vec(),
        vec![b'x'; 16 * 1024 + 1],
    ] {
        let f = Fixture::new();
        let config = write_config(&f, "default");
        let input = f.dir.path().join("synthetic-input");
        fs::write(&input, token).unwrap();
        let result = f
            .command()
            .arg("--config")
            .arg(&config)
            .args(["login", "--app-token", "--token-stdin"])
            .stdin(fs::File::open(input).unwrap())
            .fixture_output()
            .unwrap();
        assert!(!result.status.success());
        assert!(!f.dir.path().join("input-capture").exists());
    }
}

#[test]
fn app_token_flag_cannot_override_browser_config_authentication() {
    let f = Fixture::new();
    let config = write_config(&f, "default");
    let mut value: Value = serde_json::from_slice(&fs::read(&config).unwrap()).unwrap();
    value["auth"] = "browser".into();
    fs::write(&config, serde_json::to_vec(&value).unwrap()).unwrap();
    let result = f
        .command()
        .arg("--config")
        .arg(config)
        .args(["login", "--app-token", "--token-stdin"])
        .fixture_output()
        .unwrap();
    assert!(!result.status.success());
    assert!(stderr(&result).contains("must match auth=app_token"));
    assert!(!f.dir.path().join("capture").exists());
}

#[test]
fn windows_edits_cli_validates_schema_and_linux_refuses_before_agent_access() {
    for arguments in [
        vec!["edits", "list", "--limit", "0"],
        vec!["edits", "list", "--limit", "101"],
        vec![
            "edits",
            "retry",
            "--id",
            "a19f",
            "--generation",
            "0",
            "--local-relative-path",
            "Personal/a.bin",
        ],
        vec!["edits", "retry", "--id", "a19f", "--generation", "7"],
        vec!["edits", "list"],
        vec![
            "edits",
            "retry",
            "--id",
            "a19f",
            "--generation",
            "7",
            "--local-relative-path",
            "Spaces/Projects/a.bin",
        ],
    ] {
        let fixture = Fixture::new();
        let output = fixture.command().args(arguments).fixture_output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!fixture.dir.path().join("capture").exists());
    }
    let fixture = Fixture::new();
    let output = fixture
        .command()
        .args(["edits", "retry", "--help"])
        .fixture_output()
        .unwrap();
    assert!(output.status.success());
    assert!(stdout(&output).contains("--local-relative-path"));
    assert!(stdout(&output).contains("--generation"));
    assert!(stdout(&output).contains("Explicitly approve"));
}
