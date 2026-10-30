//! Explicit startup registration for the isolated foreground CLI. Merely
//! installing binaries or rendering a plan never changes service/task state.
use clap::{Args, Subcommand, ValueEnum};
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::io::Write;
use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Args)]
pub(crate) struct StartupArgs {
    /// Boot starts without an interactive login; logon uses the user session.
    #[arg(long, global = true, value_enum, default_value_t = StartupMode::Boot)]
    mode: StartupMode,
    /// Print the registration/removal plan without changing anything.
    #[arg(long, global = true)]
    dry_run: bool,
    #[command(subcommand)]
    command: StartupCommand,
}

#[derive(Debug, Subcommand)]
enum StartupCommand {
    /// Register startup and start the configured isolated agent now.
    Enable,
    /// Disable startup and ask the isolated agent to stop safely; preserve state.
    Disable,
    /// Inspect startup registration and runtime status.
    Status,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum StartupMode {
    Boot,
    Logon,
}

pub(crate) fn run(
    args: StartupArgs,
    config_path: &Path,
    state: &Path,
    cli_executable: &Path,
) -> Result<(), String> {
    for (name, path) in [
        ("configuration", config_path),
        ("state", state),
        ("CLI executable", cli_executable),
    ] {
        validate_absolute(name, path)?;
    }
    #[cfg(target_os = "linux")]
    {
        linux_run(&args, config_path, state, cli_executable)
    }
    #[cfg(windows)]
    {
        windows_run(&args, config_path, state, cli_executable)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = args;
        Err("Startup registration currently requires Linux or Windows".into())
    }
}

fn validate_absolute(name: &str, path: &Path) -> Result<(), String> {
    let value = path
        .to_str()
        .ok_or_else(|| format!("The {name} path must be valid Unicode"))?;
    if !path.is_absolute() || value.chars().any(char::is_control) {
        return Err(format!(
            "The {name} path must be absolute and contain no control characters"
        ));
    }
    Ok(())
}

// A stable identifier, not a trust boundary: existing definitions are checked
// before modification. State, rather than config, identifies one agent owner.
fn instance_id(state: &Path) -> String {
    let value = state.to_string_lossy();
    #[cfg(windows)]
    let value = value.replace('/', "\\").to_lowercase();
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in value.as_bytes() {
        hash = (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

#[cfg(any(target_os = "linux", test))]
fn systemd_quote(value: &str) -> String {
    format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
            .replace('$', "$$")
    )
}

#[cfg(any(target_os = "linux", test))]
fn linux_unit(config: &Path, state: &Path, executable: &Path) -> String {
    let command = format!(
        "{} --config {} drive --state-dir {}",
        systemd_quote(&executable.to_string_lossy()),
        systemd_quote(&config.to_string_lossy()),
        systemd_quote(&state.to_string_lossy())
    );
    // The agent handles SIGTERM through its normal guarded shutdown path.
    // An ExecStop broker request can fail after an intentional clean exit,
    // turning that successful stop into an on-failure service restart.
    format!(
        "# Raiun headless CLI startup v1\n[Unit]\nDescription=Raiun isolated headless drive ({})\nAfter=network-online.target\n\n[Service]\nType=simple\nUMask=0077\nExecStart={command} serve\nKillSignal=SIGTERM\nRestart=on-failure\nRestartSec=15s\nTimeoutStopSec=330s\nSendSIGKILL=no\n\n[Install]\nWantedBy=default.target\n",
        instance_id(state)
    )
}

#[cfg(target_os = "linux")]
fn unit_directory() -> Result<PathBuf, String> {
    let root = match std::env::var_os("XDG_CONFIG_HOME").filter(|path| !path.is_empty()) {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from(
            std::env::var_os("HOME")
                .filter(|path| !path.is_empty())
                .ok_or("HOME or XDG_CONFIG_HOME is required for user services")?,
        )
        .join(".config"),
    };
    validate_absolute("user service directory", &root)?;
    Ok(root.join("systemd/user"))
}

#[cfg(target_os = "linux")]
fn existing_unit(path: &Path, expected: &str) -> Result<bool, String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("Cannot inspect the startup unit: {error}")),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 128 * 1024 {
        return Err(
            "Existing startup entry is not an ordinary Raiun unit; it was preserved".into(),
        );
    }
    if fs::read_to_string(path).map_err(|error| format!("Cannot read the startup unit: {error}"))?
        != expected
    {
        return Err("Existing startup unit has different settings; it was preserved. Inspect it before updating the startup configuration".into());
    }
    Ok(true)
}

#[cfg(target_os = "linux")]
fn systemctl(arguments: &[&str]) -> Result<(), String> {
    let result = Command::new("systemctl")
        .arg("--user")
        .args(arguments)
        .status()
        .map_err(|error| format!("Cannot run systemctl --user: {error}"))?;
    if !result.success() {
        return Err("User service operation failed. Run this command as the intended account with its systemd user manager available; inspect journalctl --user for this unit".into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_linux_linger(
    uid: u32,
    mut loginctl: impl FnMut(&[&str]) -> std::io::Result<std::process::Output>,
) -> Result<(), String> {
    let uid = uid.to_string();
    let query = loginctl(&["show-user", &uid, "--property=Linger", "--value"]);
    if query.is_ok_and(|output| {
        output.status.success()
            && output.stderr.is_empty()
            && matches!(output.stdout.as_slice(), b"yes" | b"yes\n")
    }) {
        return Ok(());
    }
    let enabled = loginctl(&["enable-linger", &uid])
        .map_err(|error| format!("Cannot enable boot startup through loginctl: {error}"))?;
    if !enabled.status.success() {
        return Err(format!(
            "Boot startup needs lingering for OS user {uid}. Ask an administrator to run: sudo loginctl enable-linger {uid}; then rerun startup enable as that account. No service was enabled"
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_run(
    args: &StartupArgs,
    config: &Path,
    state: &Path,
    executable: &Path,
) -> Result<(), String> {
    let uid = raiun_headless::effective_user_id();
    let name = format!("raiun-headless-{}.service", instance_id(state));
    let path = unit_directory()?.join(&name);
    let unit = linux_unit(config, state, executable);
    if args.dry_run {
        println!("Unit: {}\n{unit}", path.display());
        match args.command {
            StartupCommand::Enable => {
                if args.mode == StartupMode::Boot {
                    println!(
                        "Action: loginctl show-user {uid} --property=Linger --value; if not confirmed yes, loginctl enable-linger {uid}"
                    );
                }
                println!(
                    "Action: write the unit if absent, then systemctl --user daemon-reload && systemctl --user enable --now {name}"
                );
            }
            StartupCommand::Disable => println!(
                "Action: systemctl --user disable --now {name}; retain the unit, config, credentials and state; preserve global lingering"
            ),
            StartupCommand::Status => println!(
                "Action: inspect systemctl --user show {name} and loginctl show-user {uid} --property=Linger"
            ),
        }
        return Ok(());
    }
    match args.command {
        StartupCommand::Enable => {
            if !executable.is_file() || !config.is_file() {
                return Err("The installed CLI and validated configuration must exist before startup is enabled".into());
            }
            let exists = existing_unit(&path, &unit)?;
            if args.mode == StartupMode::Boot {
                ensure_linux_linger(uid, |arguments| {
                    Command::new("loginctl").args(arguments).output()
                })?;
            }
            if !exists {
                fs::create_dir_all(path.parent().ok_or("Invalid user unit path")?)
                    .map_err(|error| format!("Cannot create the user unit directory: {error}"))?;
                let mut temporary =
                    tempfile::NamedTempFile::new_in(path.parent().ok_or("Invalid user unit path")?)
                        .map_err(|error| error.to_string())?;
                temporary
                    .write_all(unit.as_bytes())
                    .map_err(|error| error.to_string())?;
                temporary
                    .as_file()
                    .sync_all()
                    .map_err(|error| error.to_string())?;
                temporary.persist_noclobber(&path).map_err(|error| {
                    format!(
                        "Could not create startup unit without replacing an existing file: {}",
                        error.error
                    )
                })?;
            }
            systemctl(&["daemon-reload"])?;
            systemctl(&["enable", "--now", &name])?;
            println!(
                "Enabled {name} for {:?}. Startup uses {} and preserves the Desktop installation.",
                args.mode,
                config.display()
            );
            if args.mode == StartupMode::Logon {
                println!(
                    "Lingering was not changed; if it was already enabled, this user service can also start at boot."
                );
            }
        }
        StartupCommand::Disable => {
            if !existing_unit(&path, &unit)? {
                println!("No matching startup unit is installed; state was preserved.");
                return Ok(());
            }
            // The agent's SIGTERM handler performs normal guarded shutdown;
            // systemd waits without forcing a still-busy instance to exit.
            systemctl(&["disable", "--now", &name])?;
            println!(
                "Disabled {name}. Unit, configuration, credentials, local files and lingering preference were preserved."
            );
        }
        StartupCommand::Status => {
            println!(
                "Unit: {}\nConfig: {}\nState: {}",
                path.display(),
                config.display(),
                state.display()
            );
            let status = Command::new("systemctl")
                .args([
                    "--user",
                    "show",
                    &name,
                    "--property=LoadState,ActiveState,SubState,UnitFileState",
                ])
                .status()
                .map_err(|error| format!("Cannot inspect user startup: {error}"))?;
            if !status.success() {
                return Err(
                    "Cannot inspect the user service manager; no startup state was changed".into(),
                );
            }
            let linger = Command::new("loginctl")
                .args(["show-user", &uid.to_string(), "--property=Linger"])
                .status()
                .map_err(|error| format!("Cannot inspect lingering: {error}"))?;
            if !linger.success() {
                return Err("Startup unit was inspected, but the current account's lingering status is unavailable".into());
            }
        }
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn windows_quote(value: &str) -> String {
    // CommandLineToArgvW/CRT-compatible quoting, including trailing slashes.
    let mut quoted = String::from("\"");
    let mut backslashes = 0;
    for character in value.chars() {
        if character == '\\' {
            backslashes += 1;
            continue;
        }
        if character == '"' {
            quoted.push_str(&"\\".repeat(backslashes * 2 + 1));
        } else {
            quoted.push_str(&"\\".repeat(backslashes));
        }
        quoted.push(character);
        backslashes = 0;
    }
    quoted.push_str(&"\\".repeat(backslashes * 2));
    quoted.push('"');
    quoted
}

#[cfg(any(windows, test))]
fn windows_arguments(config: &Path, state: &Path, action: &str) -> String {
    format!(
        "--config {} drive --state-dir {} {action}",
        windows_quote(&config.to_string_lossy()),
        windows_quote(&state.to_string_lossy())
    )
}

/// A data-only plan: no COM connection, SID lookup, password prompt or files.
#[cfg(any(windows, test))]
fn windows_plan(
    args: &StartupArgs,
    config: &Path,
    state: &Path,
    executable: &Path,
) -> serde_json::Value {
    let mode = if args.mode == StartupMode::Boot {
        "boot"
    } else {
        "logon"
    };
    let action = match args.command {
        StartupCommand::Enable => "enable",
        StartupCommand::Disable => "disable",
        StartupCommand::Status => "status",
    };
    serde_json::json!({
        "backend":"native_task_scheduler", "dry_run":true,"action":action,"mode":mode,
        "task_name":format!("Raiun Headless CLI {}", instance_id(state)),
        "registration_source":format!("RaiunHeadlessCLI-v1:{}", instance_id(state)),
        "account":"current_process_windows_account","account_resolved":false,
        "executable":executable,"arguments":windows_arguments(config,state,"serve"),
        "argument_vector":["--config",config.to_string_lossy(),"drive","--state-dir",state.to_string_lossy(),"serve"],
        "working_directory":executable.parent(),"configuration":config,"state_directory":state,
        "trigger":if args.mode == StartupMode::Boot { "boot_after_30_seconds" } else { "current_user_logon_after_10_seconds" },
        "logon_type":if args.mode == StartupMode::Boot { "password" } else { "interactive_token" },
        "run_level":"least_privilege",
        "same_account_elevation_required":args.mode == StartupMode::Boot && matches!(args.command,StartupCommand::Enable),
        "new_task_password_input":if args.mode == StartupMode::Boot && matches!(args.command,StartupCommand::Enable) { "hidden_console" } else { "none" },
        "password_in_arguments_or_files":false,"script_host_required":false,
        "disable_sequence":["disable_exact_task_admission","normal_cli_stop","observe_disabled_inactive_task","remove_exact_task"],
        "normal_stop_argument_vector":["--config",config.to_string_lossy(),"drive","--state-dir",state.to_string_lossy(),"stop"],
        "inactive_wait_seconds":330,"forced_termination":false,"state_preserved":true
    })
}

#[cfg(any(windows, test))]
fn disable_windows_owned(
    mut disable_admission: impl FnMut() -> Result<bool, String>,
    mut normal_stop: impl FnMut() -> Result<(), String>,
    mut wait_inactive: impl FnMut() -> Result<(), String>,
    mut remove_exact: impl FnMut() -> Result<(), String>,
) -> Result<bool, String> {
    if !disable_admission()? {
        return Ok(false);
    }
    // Any failure leaves the disabled registration and all state intact.
    normal_stop()?;
    wait_inactive()?;
    remove_exact()?;
    Ok(true)
}

#[cfg(windows)]
fn windows_status_json(
    spec: &raiun_control_windows::startup::OwnedTaskSpec,
    status: Option<&raiun_control_windows::startup::TaskStatus>,
) -> serde_json::Value {
    match status {
        None => {
            serde_json::json!({"backend":"native_task_scheduler","task_name":spec.task_name(),"installed":false,"agent_status_included":false})
        }
        Some(status) => serde_json::json!({
            "backend":"native_task_scheduler","task_name":spec.task_name(),"installed":true,
            "enabled":status.enabled,"state":status.state,"last_task_result":status.last_task_result,
            "active_instance_count":status.active_instance_count,"active":status.is_active(),
            "mode":if status.kind == raiun_control_windows::startup::StartupKind::Boot { "boot" } else { "logon" },
            "user_sid":status.user_sid,"agent_status_included":false
        }),
    }
}

#[cfg(windows)]
fn normal_windows_cli_stop(config: &Path, state: &Path, executable: &Path) -> Result<(), String> {
    use std::{
        process::Stdio,
        time::{Duration, Instant},
    };
    let mut child=Command::new(executable)
        .arg("--config").arg(config).arg("drive").arg("--state-dir").arg(state).arg("stop")
        .env_remove("RAIUN_HEADLESS_CONFIG").env_remove("RAIUN_STATE_DIR").env_remove("RAIUN_HEADLESS_CONTEXT")
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().map_err(|_| "Startup admission is disabled, but normal CLI stop could not start; disabled task and state preserved")?;
    let deadline = Instant::now() + Duration::from_secs(330);
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success()=>return Ok(()),
            Ok(Some(_))=>return Err("Startup admission is disabled, but safe agent stop was not confirmed (the agent may already be offline); disabled task and all state preserved. Inspect drive status before another explicit action".into()),
            Err(_)=>return Err("Cannot observe the normal stop process; disabled task and all state preserved".into()),
            Ok(None)=>{}
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "Normal CLI stop exceeded its bounded wait; process {} and disabled task/state preserved. No process was terminated",
                child.id()
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(windows)]
fn windows_run(
    args: &StartupArgs,
    config: &Path,
    state: &Path,
    executable: &Path,
) -> Result<(), String> {
    use raiun_control_windows::startup::{OwnedTaskSpec, StartupKind, TaskScheduler};
    use zeroize::Zeroizing;
    // Keep the pure plan before all Task Scheduler/account/credential access.
    if args.dry_run {
        println!(
            "{}",
            serde_json::to_string_pretty(&windows_plan(args, config, state, executable))
                .map_err(|_| "Cannot encode startup plan")?
        );
        return Ok(());
    }
    let spec = OwnedTaskSpec::new(
        &instance_id(state),
        executable,
        &windows_arguments(config, state, "serve"),
        executable
            .parent()
            .ok_or("Installed CLI requires a working directory")?,
    )
    .map_err(|error| error.to_string())?;
    let scheduler = TaskScheduler::connect().map_err(|error| error.to_string())?;
    let kind = if args.mode == StartupMode::Boot {
        StartupKind::Boot
    } else {
        StartupKind::Logon
    };
    match args.command {
        StartupCommand::Status => {
            let status = scheduler
                .inspect_owned(&spec)
                .map_err(|error| error.to_string())?;
            println!("{}", windows_status_json(&spec, status.as_ref()));
        }
        StartupCommand::Enable => {
            let existing = scheduler
                .inspect_owned(&spec)
                .map_err(|error| error.to_string())?;
            if existing.as_ref().is_some_and(|status| status.kind != kind) {
                return Err("Existing startup mode differs; explicitly disable it before changing mode. Task and state preserved".into());
            }
            if kind == StartupKind::Boot
                && !scheduler
                    .boot_is_elevated()
                    .map_err(|error| error.to_string())?
            {
                return Err("Boot startup requires an elevated terminal under this same Windows account; no password was requested and no startup state changed".into());
            }
            // Existing exact-owned password tasks already have Scheduler's
            // credential. Only a new boot task needs another password prompt.
            let password = if kind == StartupKind::Boot && existing.is_none() {
                eprintln!(
                    "Registering boot startup for {}. Enter that Windows account's password, not a Hello PIN or OpenCloud token",
                    scheduler.current_account()
                );
                let password=Zeroizing::new(rpassword::prompt_password("Windows account password: ")
                    .map_err(|_| "Cannot read a hidden Windows account password from the console; startup was not registered")?);
                if password.is_empty()
                    || password.contains('\0')
                    || password.encode_utf16().count() > 4096
                {
                    return Err("A nonempty bounded Windows account password is required; startup was not registered".into());
                }
                Some(password)
            } else {
                None
            };
            let status = scheduler
                .enable(
                    &spec,
                    kind,
                    password.as_ref().map(|password| password.as_str()),
                )
                .map_err(|error| error.to_string())?;
            drop(password);
            let mut result = windows_status_json(&spec, Some(&status));
            result["immediate_run_requested"] = serde_json::json!(true);
            result["boot_provider_acceptance"] =
                serde_json::json!("not_established_by_registration");
            println!("{result}");
        }
        StartupCommand::Disable => {
            let removed = disable_windows_owned(
                || {
                    scheduler
                        .disable_admission(&spec)
                        .map(|status| status.is_some())
                        .map_err(|error| error.to_string())
                },
                || normal_windows_cli_stop(config, state, executable),
                || {
                    scheduler
                        .wait_observed(&spec, std::time::Duration::from_secs(330))
                        .map(|_| ())
                        .map_err(|error| error.to_string())
                },
                || {
                    scheduler
                        .remove_exact(&spec)
                        .map_err(|error| error.to_string())
                },
            )?;
            println!(
                "{}",
                serde_json::json!({"backend":"native_task_scheduler","task_name":spec.task_name(),
                "installed":false,"removed":removed,"state_preserved":true,"forced_termination":false})
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        startup: StartupArgs,
    }

    #[test]
    fn startup_defaults_to_boot_and_accepts_dry_run_after_subcommand() {
        let args = TestCli::try_parse_from(["startup", "enable", "--dry-run"])
            .unwrap()
            .startup;
        assert_eq!(args.mode, StartupMode::Boot);
        assert!(args.dry_run);
        assert!(matches!(args.command, StartupCommand::Enable));
        assert_eq!(
            TestCli::try_parse_from(["startup", "status", "--mode", "logon"])
                .unwrap()
                .startup
                .mode,
            StartupMode::Logon
        );
        assert!(TestCli::try_parse_from(["startup", "enable", "--mode", "daily"]).is_err());
    }

    #[test]
    fn systemd_execution_quotes_literals_and_runs_only_the_exact_foreground_cli() {
        let unit = linux_unit(
            Path::new("/config/space $HOME%a'\".json"),
            Path::new("/state/with space\\slash"),
            Path::new("/bin/raiun"),
        );
        assert!(unit.contains("ExecStart=\"/bin/raiun\" --config \"/config/space $$HOME%%a'\\\".json\" drive --state-dir \"/state/with space\\\\slash\" serve"));
        assert!(!unit.contains("ExecStop="));
        assert!(unit.contains("KillSignal=SIGTERM"));
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("RestartSec=15s"));
        assert!(unit.contains("TimeoutStopSec=330s"));
        assert!(unit.contains("SendSIGKILL=no"));
        assert!(!unit.contains("raiun-desktop"));
        assert!(!unit.contains("User=root"));
        assert!(validate_absolute("state", Path::new("relative")).is_err());
        assert!(validate_absolute("state", Path::new("/state\nExecStart=evil")).is_err());
    }

    #[cfg(target_os = "linux")]
    fn loginctl_output(code: i32, stdout: &[u8], stderr: &[u8]) -> std::process::Output {
        use std::os::unix::process::ExitStatusExt;
        std::process::Output {
            status: std::process::ExitStatus::from_raw(code << 8),
            stdout: stdout.to_vec(),
            stderr: stderr.to_vec(),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn nonlogin_linger_query_uses_explicit_numeric_os_account_and_skips_only_exact_yes() {
        for yes in [b"yes".as_slice(), b"yes\n".as_slice()] {
            let mut calls = Vec::new();
            ensure_linux_linger(1000, |arguments| {
                calls.push(
                    arguments
                        .iter()
                        .map(|value| (*value).to_owned())
                        .collect::<Vec<_>>(),
                );
                assert_eq!(
                    calls.len(),
                    1,
                    "already lingered user must not need another policy authorization"
                );
                Ok(loginctl_output(0, yes, b""))
            })
            .unwrap();
            assert_eq!(
                calls,
                [vec!["show-user", "1000", "--property=Linger", "--value"]]
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn no_failed_or_ambiguous_query_still_requires_successful_enable_for_same_uid() {
        for (code, stdout, stderr) in [
            (0, b"no\n".as_slice(), b"".as_slice()),
            (1, b"yes\n".as_slice(), b"".as_slice()),
            (0, b"".as_slice(), b"".as_slice()),
            (0, b"yes\nno\n".as_slice(), b"".as_slice()),
            (0, b"Linger=yes\n".as_slice(), b"".as_slice()),
            (0, b"yes\n".as_slice(), b"warning".as_slice()),
        ] {
            for enable_success in [true, false] {
                let mut calls = Vec::new();
                let result = ensure_linux_linger(1234, |arguments| {
                    calls.push(
                        arguments
                            .iter()
                            .map(|value| (*value).to_owned())
                            .collect::<Vec<_>>(),
                    );
                    Ok(if calls.len() == 1 {
                        loginctl_output(code, stdout, stderr)
                    } else {
                        loginctl_output(i32::from(!enable_success), b"", b"")
                    })
                });
                assert_eq!(result.is_ok(), enable_success);
                assert_eq!(
                    calls,
                    [
                        vec!["show-user", "1234", "--property=Linger", "--value"],
                        vec!["enable-linger", "1234"],
                    ]
                );
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unavailable_linger_query_is_not_confirmation_and_enable_spawn_failure_is_strict() {
        for enable_success in [true, false] {
            let mut calls = Vec::new();
            let result = ensure_linux_linger(4567, |arguments| {
                calls.push(
                    arguments
                        .iter()
                        .map(|value| (*value).to_owned())
                        .collect::<Vec<_>>(),
                );
                if calls.len() == 1 || !enable_success {
                    Err(std::io::Error::from(std::io::ErrorKind::NotFound))
                } else {
                    Ok(loginctl_output(0, b"", b""))
                }
            });
            assert_eq!(result.is_ok(), enable_success);
            assert_eq!(
                calls,
                [
                    vec!["show-user", "4567", "--property=Linger", "--value"],
                    vec!["enable-linger", "4567"],
                ]
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn existing_preview_and_edited_startup_units_are_preserved() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("raiun-headless-test.service");
        let expected = linux_unit(
            Path::new("/config.json"),
            Path::new("/state"),
            Path::new("/bin/raiun"),
        );
        assert!(!existing_unit(&path, &expected).unwrap());
        let preview = expected.replace(
            "KillSignal=SIGTERM\n",
            "ExecStop=\"/bin/raiun\" --config \"/config.json\" drive --state-dir \"/state\" stop\n",
        );
        for retained in [preview, expected.replace("RestartSec=15s", "RestartSec=2s")] {
            fs::write(&path, &retained).unwrap();
            assert!(existing_unit(&path, &expected).is_err());
            assert_eq!(fs::read_to_string(&path).unwrap(), retained);
        }
        fs::write(&path, &expected).unwrap();
        assert!(existing_unit(&path, &expected).unwrap());
        assert_eq!(fs::read_to_string(&path).unwrap(), expected);
    }

    #[test]
    fn windows_native_plan_preserves_commandline_boundaries_without_script_or_com() {
        assert_eq!(
            windows_quote(r"C:\path with spaces\"),
            "\"C:\\path with spaces\\\\\""
        );
        assert_eq!(windows_quote("a\\\"b"), "\"a\\\\\\\"b\"");
        let args = TestCli::try_parse_from(["startup", "enable", "--dry-run"])
            .unwrap()
            .startup;
        let config = Path::new(r"C:\owner's & <config>.json");
        let state = Path::new(r"C:\state with space\");
        let executable = Path::new(r"C:\Apps & Tools\raiun.exe");
        let plan = windows_plan(&args, config, state, executable);
        assert_eq!(plan["backend"], "native_task_scheduler");
        assert_eq!(plan["dry_run"], true);
        assert_eq!(plan["account_resolved"], false);
        assert_eq!(plan["script_host_required"], false);
        assert_eq!(plan["new_task_password_input"], "hidden_console");
        assert_eq!(plan["password_in_arguments_or_files"], false);
        assert_eq!(plan["executable"], executable.to_str().unwrap());
        assert_eq!(
            plan["argument_vector"],
            serde_json::json!([
                "--config",
                config.to_str().unwrap(),
                "drive",
                "--state-dir",
                state.to_str().unwrap(),
                "serve"
            ])
        );
        assert_eq!(plan["arguments"], windows_arguments(config, state, "serve"));
        assert!(
            plan["arguments"]
                .as_str()
                .unwrap()
                .ends_with("\\\\\" serve")
        );
        assert!(!plan.to_string().contains("powershell"));
        assert!(!plan.to_string().contains("Get-Credential"));
        assert_eq!(plan["inactive_wait_seconds"], 330);
        assert_eq!(plan["forced_termination"], false);
        let logon = TestCli::try_parse_from(["startup", "enable", "--mode", "logon", "--dry-run"])
            .unwrap()
            .startup;
        let plan = windows_plan(&logon, config, state, executable);
        assert_eq!(plan["logon_type"], "interactive_token");
        assert_eq!(plan["new_task_password_input"], "none");
        assert_eq!(plan["same_account_elevation_required"], false);
        assert_eq!(instance_id(state), instance_id(state));
        assert_ne!(
            instance_id(Path::new("state-a")),
            instance_id(Path::new("state-b"))
        );
    }

    #[test]
    fn windows_disable_never_removes_after_an_unconfirmed_stop_or_inactive_state() {
        use std::cell::RefCell;
        for failure in [None, Some("stop"), Some("wait"), Some("admission")] {
            let calls = RefCell::new(Vec::new());
            let result = disable_windows_owned(
                || {
                    calls.borrow_mut().push("admission");
                    if failure == Some("admission") {
                        Err("foreign task".into())
                    } else {
                        Ok(true)
                    }
                },
                || {
                    calls.borrow_mut().push("stop");
                    if failure == Some("stop") {
                        Err("stop failed".into())
                    } else {
                        Ok(())
                    }
                },
                || {
                    calls.borrow_mut().push("wait");
                    if failure == Some("wait") {
                        Err("still active".into())
                    } else {
                        Ok(())
                    }
                },
                || {
                    calls.borrow_mut().push("remove");
                    Ok(())
                },
            );
            assert_eq!(result.is_ok(), failure.is_none());
            assert_eq!(
                calls.into_inner(),
                match failure {
                    Some("admission") => vec!["admission"],
                    Some("stop") => vec!["admission", "stop"],
                    Some("wait") => vec!["admission", "stop", "wait"],
                    _ => vec!["admission", "stop", "wait", "remove"],
                }
            );
        }
        let calls = RefCell::new(Vec::new());
        assert!(
            !disable_windows_owned(
                || Ok(false),
                || {
                    calls.borrow_mut().push("stop");
                    Ok(())
                },
                || Ok(()),
                || {
                    calls.borrow_mut().push("remove");
                    Ok(())
                }
            )
            .unwrap()
        );
        assert!(calls.into_inner().is_empty());
    }
}
