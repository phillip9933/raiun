//! Headless drive control. This deliberately does not load the offline sync config.
use std::env;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use clap::{Args, Subcommand, ValueEnum};
use raiun_headless::{AuthMethod, HeadlessConfig};
use serde_json::{Value, json};
use url::Url;
use zeroize::Zeroizing;

const MAX_OUTPUT: u64 = 1024 * 1024;
const APP_TOKEN_LOGIN_TIMEOUT: Duration = Duration::from_secs(75);
const APP_TOKEN_STATUS_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Debug, Args)]
pub(crate) struct DriveArgs {
    /// Isolated agent state directory (absolute); overrides RAIUN_STATE_DIR.
    #[arg(long, global = true, value_name = "ABS")]
    state_dir: Option<PathBuf>,
    /// Explicit account profile ID; never follows the desktop's selected account.
    #[arg(long, global = true)]
    profile: Option<String>,
    /// Print the successful agent response as JSON. Errors go to stderr, exit nonzero.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: DriveCommand,
}

#[derive(Debug, Subcommand)]
enum DriveCommand {
    /// Run the sibling agent in the foreground, without folder-pair sync.
    /// Configured agents may restore their private remembered login.
    Serve,
    /// Show this profile's connection and mount status.
    Status,
    /// List remote spaces for this profile.
    Spaces,
    /// Enable the on-demand cloud drive, optionally configuring its absolute root first.
    Mount {
        #[arg(long, value_name = "ABS")]
        path: Option<PathBuf>,
    },
    /// Disable this profile's cloud drive.
    Unmount,
    /// Begin PKCE sign-in; print the URL for manual opening, never launch a browser.
    Login {
        #[arg(long, value_name = "HOST")]
        server: Option<String>,
        #[arg(long, value_name = "ID")]
        client_id: Option<String>,
        /// Authenticate using an app token, prompted without echo by default.
        #[arg(long)]
        app_token: bool,
        #[arg(long, requires = "app_token")]
        token_stdin: bool,
        #[arg(long)]
        username: Option<String>,
    },
    /// Sign out this profile using the agent's normal safety checks.
    Logout,
    /// Safely stop the entire isolated agent, including all its profiles.
    Stop,
    /// List or add isolated account profiles.
    Accounts {
        #[command(subcommand)]
        command: AccountCommand,
    },
    /// Create, show or validate this isolated agent's nonsecret configuration.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Inspect, check cloud bytes or explicitly retry Windows ordinary saved edits.
    Edits {
        #[command(subcommand)]
        command: EditCommand,
    },
    /// Manage explicit per-user background startup using a valid configuration.
    Startup(crate::startup::StartupArgs),
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ConfigAuth {
    Browser,
    #[value(name = "app_token")]
    AppToken,
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    Init {
        #[arg(long)]
        server: String,
        #[arg(long, value_name = "ABS")]
        mount_path: PathBuf,
        #[arg(long, value_enum, default_value = "browser")]
        auth: ConfigAuth,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        client_id: Option<String>,
        #[arg(long)]
        no_auto_mount: bool,
        #[arg(long)]
        no_remember_login: bool,
        #[arg(long, default_value_t = 30)]
        reconnect_interval_seconds: u64,
    },
    Show,
    Check,
}

#[derive(Debug, Subcommand)]
enum AccountCommand {
    List,
    /// Add an account profile. Linux requires --path; Windows sets its root at mount.
    Add {
        #[arg(long)]
        label: String,
        #[arg(long, value_name = "ABS")]
        path: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum EditCommand {
    /// Read one bounded page of retained ordinary edits. Windows only.
    List {
        #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u16).range(1..=100))]
        limit: u16,
        /// Opaque next_after value from the previous page; pass it unchanged.
        #[arg(long, value_name = "OPAQUE")]
        after: Option<String>,
    },
    /// Compare one retained snapshot with current cloud bytes without saving or completing it.
    /// A match is informational; the original local snapshot stays retained.
    Check {
        #[arg(long, value_name = "HEX")]
        id: String,
        /// Immutable record generation from edits list (not auth_generation).
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        generation: u64,
    },
    /// Explicitly approve retry of one immutable saved edit and its selected local file.
    /// No automatic replay, overwrite bypass, folder sync or vault retry is enabled.
    Retry {
        #[arg(long, value_name = "HEX")]
        id: String,
        /// Immutable record generation from edits list (not auth_generation).
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        generation: u64,
        /// Explicit path relative to this drive root, e.g. Spaces/Projects/path.bin.
        #[arg(long, value_name = "ROOT_RELATIVE")]
        local_relative_path: String,
    },
}

pub(crate) fn run(mut args: DriveArgs, config_arg: Option<PathBuf>) -> Result<(), String> {
    if !cfg!(any(target_os = "linux", windows)) {
        return Err("Headless drive commands currently require Linux or Windows".into());
    }
    let state = state_dir(args.state_dir.clone())?;
    let explicit_config =
        config_arg.or_else(|| env::var_os("RAIUN_HEADLESS_CONFIG").map(PathBuf::from));
    let config_path = explicit_config
        .clone()
        .unwrap_or_else(|| state.join("config.json"));
    absolute(&config_path, "Headless configuration")?;
    if let DriveCommand::Config { command } = &args.command {
        return config_command(command, &config_path, args.profile.as_deref());
    }
    let config = if explicit_config.is_some() {
        Some(raiun_headless::load(&config_path).map_err(|error| error.to_string())?)
    } else {
        raiun_headless::load_optional(&config_path).map_err(|error| error.to_string())?
    };
    let selected_profile = match (&args.profile, &config) {
        (Some(profile), Some(config)) if *profile != config.profile => {
            return Err("--profile must match the selected headless configuration profile".into());
        }
        (Some(profile), _) => profile.clone(),
        (_, Some(config)) => config.profile.clone(),
        _ => "default".into(),
    };
    if selected_profile.trim().is_empty() {
        return Err("--profile cannot be empty".into());
    }
    args.profile = Some(selected_profile.clone());
    if let DriveCommand::Startup(startup) = args.command {
        if config.is_none() {
            return Err(
                "Startup requires a valid headless configuration; run drive config init first"
                    .into(),
            );
        }
        let executable = env::current_exe().map_err(|_| "Cannot locate CLI executable")?;
        return crate::startup::run(startup, &config_path, &state, &executable);
    }
    if let DriveCommand::Mount { path } = &mut args.command
        && path.is_none()
        && let Some(config) = &config
    {
        *path = Some(config.mount_path.clone());
    }
    if let DriveCommand::Login {
        server,
        client_id,
        username,
        app_token,
        ..
    } = &mut args.command
    {
        if let Some(config) = &config {
            if *app_token && config.auth != AuthMethod::AppToken {
                return Err("--app-token must match auth=app_token in the selected configuration; edit the config and restart first".into());
            }
            if server.is_none() {
                *server = Some(config.server.clone());
            }
            if client_id.is_none() {
                *client_id = config.client_id.clone();
            }
            if username.is_none() {
                *username = config.username.clone();
            }
            if config.auth == AuthMethod::AppToken {
                *app_token = true;
            }
        }
        if server.is_none() {
            return Err("login requires --server or a headless configuration".into());
        }
        if *app_token && username.as_ref().is_none_or(|name| name.trim().is_empty()) {
            return Err("App-token login requires --username or a configured username".into());
        }
        if *app_token {
            raiun_headless::validate_server(server.as_deref().unwrap())
                .map_err(|error| error.to_string())?;
            let name = username.as_deref().unwrap();
            if name.len() > 512
                || name.trim() != name
                || name.contains(':')
                || name.chars().any(char::is_control)
            {
                return Err("App-token username must be at most 512 bytes without colon, control characters or surrounding whitespace".into());
            }
        }
    }
    // Validate every local argument before contacting the agent.
    let requests = requests(&args)?;
    let executable = sibling_agent()?;
    if matches!(args.command, DriveCommand::Serve) {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::process::CommandExt;
            // Replace the foreground CLI so signals reach the agent directly.
            let mut command = Command::new(executable);
            command
                .args(["serve", "--mount-only"])
                .env("RAIUN_STATE_DIR", state);
            if config.is_some() {
                command.env("RAIUN_HEADLESS_CONFIG", &config_path);
            } else {
                command.env_remove("RAIUN_HEADLESS_CONFIG");
            }
            let error = command.exec();
            return Err(format!("cannot start sibling raiun-agent: {error}"));
        }
        #[cfg(windows)]
        {
            let mut command = Command::new(executable);
            command
                .args(["serve", "--mount-only"])
                .env("RAIUN_STATE_DIR", state)
                .env("RAIUN_HEADLESS_CONTEXT", "1");
            if config.is_some() {
                command.env("RAIUN_HEADLESS_CONFIG", &config_path);
            } else {
                command.env_remove("RAIUN_HEADLESS_CONFIG");
            }
            let status = command
                .status()
                .map_err(|error| format!("cannot start sibling raiun-agent: {error}"))?;
            return if status.success() {
                Ok(())
            } else {
                Err(format!("raiun-agent exited with {status}"))
            };
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        return Err("Headless agent startup is unavailable on this platform".into());
    }

    // Older desktop agents ignore unknown fields. Probe before any mutation.
    // A broker status is safe even when no profile is selected.
    let probe = json!({"action":"status","required_mode":"mount_only"});
    let status = request_agent(&executable, &state, &probe)?;
    if status.get("runtime_mode").and_then(Value::as_str) != Some("mount_only") {
        return Err("Agent is not running in mount-only mode; use a separate --state-dir and start raiun drive serve".into());
    }
    let login = matches!(
        args.command,
        DriveCommand::Login {
            app_token: false,
            ..
        }
    );
    let mut data = Value::Null;
    if let DriveCommand::Edits { command } = &args.command {
        data = execute_edits(command, &selected_profile, cfg!(windows), |request| {
            request_agent(&executable, &state, request)
        })?;
    }
    if let DriveCommand::Login {
        server,
        username,
        app_token: true,
        token_stdin,
        ..
    } = &args.command
    {
        let token = read_app_token(*token_stdin)?;
        #[derive(serde::Serialize)]
        struct AppTokenRequest<'a> {
            action: &'static str,
            required_mode: &'static str,
            profile_id: &'a str,
            server: &'a str,
            username: &'a str,
            app_token: &'a str,
        }
        let request = AppTokenRequest {
            action: "auth_app_token",
            required_mode: "mount_only",
            profile_id: &selected_profile,
            server: server.as_deref().unwrap(),
            username: username.as_deref().unwrap(),
            app_token: &token,
        };
        let mut bytes = Zeroizing::new(
            serde_json::to_vec(&request).map_err(|_| "Cannot encode app-token request")?,
        );
        bytes.push(b'\n');
        let deadline = Instant::now() + APP_TOKEN_LOGIN_TIMEOUT;
        let response = request_agent_stdin(&executable, &state, &bytes, deadline).map_err(
            |_| "App-token sign-in request failed; check the agent and account before retrying",
        )?;
        drop(bytes);
        drop(token);
        data = await_app_token_login(
            response,
            &selected_profile,
            deadline,
            APP_TOKEN_STATUS_INTERVAL,
            |deadline| {
                request_agent_until(
                    &executable,
                    &state,
                    &json!({"action":"status","profile_id":selected_profile,"required_mode":"mount_only"}),
                    deadline,
                )
            },
        )?;
    }
    for mut request in requests {
        request["required_mode"] = json!("mount_only");
        data = request_agent(&executable, &state, &request)?;
    }
    if login {
        let url = data
            .get("url")
            .and_then(Value::as_str)
            .ok_or("Agent sign-in response has no authorization URL")?;
        let port = callback_port(url)?;
        if args.json {
            println!(
                "{}",
                serde_json::to_string(&data).map_err(|error| error.to_string())?
            );
        } else {
            println!("{url}");
        }
        eprintln!(
            "Open this URL manually in your browser. For a remote agent, first forward its loopback callback from your browser machine: ssh -N -L {port}:127.0.0.1:{port} USER@AGENT_HOST"
        );
        if let Some(seconds) = data.get("expires_in").and_then(Value::as_u64) {
            eprintln!("Authorization expires in {seconds} seconds.");
        }
        eprintln!(
            "Keep the forwarding session open during sign-in. Check completion with raiun drive status using the same state directory and profile."
        );
        if config.as_ref().is_some_and(|config| config.remember_login) {
            eprintln!(
                "This configuration enables login persistence in the isolated agent state directory."
            );
        } else {
            eprintln!("This agent keeps login in memory; sign in again after agent restart.");
        }
    } else {
        if !args.json
            && matches!(
                args.command,
                DriveCommand::Edits {
                    command: EditCommand::Check { .. }
                }
            )
        {
            eprintln!(
                "Cloud checks are informational: a match verifies remote bytes only. The original local snapshot is retained and local completion stays unchanged."
            );
        }
        return write_drive_result(
            &data,
            args.json,
            matches!(
                args.command,
                DriveCommand::Edits {
                    command: EditCommand::Retry { .. }
                }
            ),
            std::io::stdout().lock(),
        );
    }
    Ok(())
}

fn write_drive_result(
    data: &Value,
    json: bool,
    edit_retry: bool,
    mut output: impl Write,
) -> Result<(), String> {
    let encoded = if json {
        serde_json::to_string(data)
    } else {
        serde_json::to_string_pretty(data)
    }
    .map_err(|_| "Cannot encode CLI result")?;
    writeln!(output, "{encoded}").map_err(|_| "Cannot write CLI result")?;
    // Keep the structured outcome on stdout even when the requested save did
    // not complete. A successful RPC is not a successful remote + local save.
    if edit_retry {
        edit_retry_exit_status(data)?;
    }
    Ok(())
}

fn edit_retry_exit_status(response: &Value) -> Result<(), String> {
    if response["continued_create"] == true
        && response["original_snapshot_retained"] == true
        && response["retained"] == true
        && response["state"] == "review_required"
        && response["remote_verified"] == false
        && response["local_completion"] == "unavailable"
    {
        return Err("This saved file was acknowledged earlier. Its recovery history needs review; nothing was uploaded.".into());
    }
    if response["continued_create"] == true
        && response["original_snapshot_retained"] == true
        && response["retained"] == true
        && response["state"] == "historical_link_completed"
        && response["remote_verified"] == false
        && response["local_completion"] == "unavailable"
    {
        return Err("Recovery history reconciled. The saved copy is retained; this did not upload or freshly verify the file.".into());
    }
    if response["remote_verified"] == true && response["local_completion"] == "completed" {
        Ok(())
    } else {
        Err("Saved edit was not fully completed; inspect remote_verified and local_completion in the structured result before another explicit retry".into())
    }
}

fn app_token_timeout() -> String {
    "App-token sign-in timed out; check drive status before retrying. The token was submitted only once".into()
}

/// A single deadline covers submission and every status request. Polling never
/// resubmits credentials or prints remote error/status text that could echo one.
fn await_app_token_login(
    response: Value,
    profile: &str,
    deadline: Instant,
    interval: Duration,
    mut status_request: impl FnMut(Instant) -> Result<Value, String>,
) -> Result<Value, String> {
    let expected_generation = response
        .get("auth_generation")
        .and_then(Value::as_u64)
        .filter(|generation| *generation != 0)
        .ok_or("Agent did not identify the app-token sign-in generation; login completion could not be confirmed")?;
    if response.get("started").and_then(Value::as_bool) != Some(true)
        && response.get("connected").and_then(Value::as_bool) != Some(true)
    {
        return Err("Agent did not start or complete app-token sign-in".into());
    }
    loop {
        if Instant::now() >= deadline {
            return Err(app_token_timeout());
        }
        let status = status_request(deadline).map_err(|_| {
            if Instant::now() >= deadline { app_token_timeout() }
            else { "Could not confirm app-token sign-in status; check the agent and account before retrying".into() }
        })?;
        if Instant::now() >= deadline {
            return Err(app_token_timeout());
        }
        let generation = status
            .get("auth_generation")
            .and_then(Value::as_u64)
            .ok_or("Agent status did not identify the app-token sign-in generation")?;
        if generation != expected_generation
            || status
                .get("profile_id")
                .and_then(Value::as_str)
                .is_some_and(|current| current != profile)
        {
            return Err("App-token sign-in was superseded by an account change; inspect drive status before retrying".into());
        }
        let active = |name| match status.get(name) {
            None | Some(Value::Null) => Ok(false),
            Some(Value::Bool(value)) => Ok(*value),
            _ => Err("Agent returned invalid app-token sign-in status"),
        };
        if active("session_cleanup_uncertain")? || active("account_removing")? {
            return Err("App-token sign-in could not establish a usable account session".into());
        }
        let connected = status
            .get("connected")
            .and_then(Value::as_bool)
            .ok_or("Agent returned incomplete app-token sign-in status")?;
        let pending = active("authenticating")? || active("refreshing")? || active("restoring")?;
        if connected && !pending {
            // Login success is independent of unrelated provider/mount errors.
            // Return an allowlist rather than remote diagnostic/account text.
            let mut result = json!({"connected":true,"authentication":"app_token","auth_generation":generation,"profile_id":profile});
            for name in ["mounted", "provider_supported"] {
                if let Some(value) = status.get(name).and_then(Value::as_bool) {
                    result[name] = json!(value);
                }
            }
            return Ok(result);
        }
        if !pending {
            return Err("App-token sign-in was rejected or the account disconnected; verify the token and server, then sign in again".into());
        }
        std::thread::sleep(interval.min(deadline.saturating_duration_since(Instant::now())));
    }
}

fn requests(args: &DriveArgs) -> Result<Vec<Value>, String> {
    requests_for_platform(args, cfg!(windows))
}

fn requests_for_platform(args: &DriveArgs, windows: bool) -> Result<Vec<Value>, String> {
    let profile = |action: &str| json!({"action":action,"profile_id":args.profile});
    Ok(match &args.command {
        DriveCommand::Serve | DriveCommand::Config { .. } | DriveCommand::Startup(_) => vec![],
        DriveCommand::Edits { command } => {
            validate_edit_inputs(command, windows)?;
            vec![]
        }
        DriveCommand::Status => vec![profile("status")],
        DriveCommand::Spaces => vec![profile("spaces")],
        DriveCommand::Mount { path } if windows => {
            let mut request = profile("mount");
            if let Some(path) = path {
                absolute(path, "--path")?;
                request["cloud_root"] = json!(path);
            }
            vec![request]
        }
        DriveCommand::Mount { path } => {
            let mut requests = Vec::new();
            if let Some(path) = path {
                absolute(path, "--path")?;
                let mut request = profile("configure");
                request["cloud_root"] = json!(path);
                requests.push(request);
            }
            requests.push(profile("mount"));
            requests
        }
        DriveCommand::Unmount => vec![profile("unmount")],
        DriveCommand::Login {
            app_token: true, ..
        } => vec![],
        DriveCommand::Login {
            server, client_id, ..
        } => {
            let mut request = profile("auth_begin");
            request["server"] = json!(
                server
                    .as_ref()
                    .ok_or("login requires --server or a headless configuration")?
            );
            if let Some(client_id) = client_id {
                request["client_id"] = json!(client_id);
            }
            vec![request]
        }
        DriveCommand::Logout => vec![profile("logout")],
        DriveCommand::Stop => vec![json!({"action":"shutdown"})],
        DriveCommand::Accounts { command } => match command {
            AccountCommand::List => vec![json!({"action":"accounts"})],
            AccountCommand::Add { label, path } if windows => {
                if path.is_some() {
                    return Err("On Windows, add the account without --path, sign in, then choose its root with drive mount --path".into());
                }
                vec![json!({"action":"account_add","label":label})]
            }
            AccountCommand::Add { label, path } => {
                let path = path
                    .as_ref()
                    .ok_or("Linux account creation requires --path /absolute/root")?;
                absolute(path, "--path")?;
                vec![json!({"action":"account_add","label":label,"cloud_root":path})]
            }
        },
    })
}

fn valid_edit_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_scope_token(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn bounded_edit_cursor(value: &str) -> bool {
    !value.is_empty() && value.len() <= 16_384 && !value.chars().any(char::is_control)
}

fn local_edit_components(path: &str) -> Result<Vec<&str>, String> {
    let invalid = || {
        "--local-relative-path must be a bounded path relative to the drive root, with ordinary Windows filename components".to_string()
    };
    if path.is_empty() || path.len() > 32_768 {
        return Err(invalid());
    }
    let components = path.split(['/', '\\']).collect::<Vec<_>>();
    if components.len() > 256
        || components.iter().any(|component| {
            component.is_empty()
                || component.len() > 255
                || matches!(*component, "." | "..")
                || component.ends_with(['.', ' '])
                || component
                    .chars()
                    .any(|character| character.is_control() || "<>:\"|?*".contains(character))
                || {
                    let stem = component
                        .split('.')
                        .next()
                        .unwrap_or_default()
                        .to_ascii_uppercase();
                    matches!(
                        stem.as_str(),
                        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
                    ) || ["COM", "LPT"].iter().any(|prefix| {
                        stem.strip_prefix(prefix).is_some_and(|suffix| {
                            matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
                        })
                    })
                }
        })
    {
        return Err(invalid());
    }
    Ok(components)
}

fn validate_edit_inputs(command: &EditCommand, windows: bool) -> Result<(), String> {
    if !windows {
        return Err("drive edits currently requires Windows; Linux edit recovery is not exposed by this command".into());
    }
    match command {
        EditCommand::List { limit, after } => {
            if !(1..=100).contains(limit)
                || after
                    .as_ref()
                    .is_some_and(|cursor| !bounded_edit_cursor(cursor))
            {
                return Err(
                    "edits list requires --limit 1..100 and a bounded opaque --after value".into(),
                );
            }
        }
        EditCommand::Check { id, generation } => {
            if !valid_edit_id(id) || *generation == 0 {
                return Err("edits check requires the hexadecimal --id and positive immutable --generation from edits list".into());
            }
        }
        EditCommand::Retry {
            id,
            generation,
            local_relative_path,
        } => {
            if !valid_edit_id(id) || *generation == 0 {
                return Err("edits retry requires the hexadecimal --id and positive immutable --generation from edits list".into());
            }
            local_edit_components(local_relative_path)?;
        }
    }
    Ok(())
}

fn edit_context(status: &Value, profile: &str) -> Result<(u64, String), String> {
    let invalid = || {
        "Saved edits require fresh connected Windows drive status for the selected profile and registered root; check drive status".to_string()
    };
    if status["runtime_mode"] != "mount_only"
        || status["profile_id"] != profile
        || status["connected"] != true
    {
        return Err(invalid());
    }
    for field in [
        "authenticating",
        "refreshing",
        "restoring",
        "offline",
        "needs_refresh",
        "session_cleanup_uncertain",
        "account_removing",
    ] {
        if !matches!(
            status.get(field),
            None | Some(Value::Null) | Some(Value::Bool(false))
        ) {
            return Err(invalid());
        }
    }
    let generation = status
        .get("auth_generation")
        .and_then(Value::as_u64)
        .filter(|value| *value != 0)
        .ok_or_else(invalid)?;
    let root = &status["root_configuration"];
    if root["valid"] != true
        || root["identity_bound"] != true
        || root["registration_state"] != "registered"
    {
        return Err(invalid());
    }
    let token = root
        .get("recovery_scope_token")
        .and_then(Value::as_str)
        .filter(|token| valid_scope_token(token))
        .ok_or_else(invalid)?;
    Ok((generation, token.to_owned()))
}

fn execute_edits(
    command: &EditCommand,
    profile: &str,
    windows: bool,
    mut request: impl FnMut(&Value) -> Result<Value, String>,
) -> Result<Value, String> {
    validate_edit_inputs(command, windows)?;
    // Broker status may describe another selected profile. Fetch a fresh explicit
    // profile status; the agent then rechecks its generation and root nonce.
    let status =
        request(&json!({"action":"status","profile_id":profile,"required_mode":"mount_only"}))?;
    let (generation, scope) = edit_context(&status, profile)?;
    let mut rpc = json!({"profile_id":profile,"required_mode":"mount_only", "expected_generation":generation,"expected_recovery_scope_token":scope});
    match command {
        EditCommand::List { limit, after } => {
            rpc["action"] = json!("windows_recovery_list");
            rpc["limit"] = json!(limit);
            if let Some(after) = after {
                rpc["after"] = json!(after);
            }
        }
        EditCommand::Check { id, generation } => {
            if status["windows_recovery_cloud_check_supported"] != true {
                return Err("This Windows agent does not support read-only saved-edit cloud checks; update the agent before using edits check".into());
            }
            rpc["action"] = json!("windows_recovery_check_cloud");
            rpc["record_id"] = json!(id);
            rpc["generation"] = json!(generation);
        }
        EditCommand::Retry {
            id,
            generation,
            local_relative_path,
        } => {
            rpc["action"] = json!("windows_recovery_retry");
            rpc["record_id"] = json!(id);
            rpc["generation"] = json!(generation);
            rpc["local_components"] = json!(local_edit_components(local_relative_path)?);
        }
    }
    // Exactly one explicit request. A stale context/error is surfaced;
    // credentials or edits are never automatically replayed against newer state.
    let response = request(&rpc)?;
    validate_edit_response(command, &response, profile, generation, &scope)?;
    Ok(response)
}

fn validate_edit_response(
    command: &EditCommand,
    response: &Value,
    profile: &str,
    generation: u64,
    scope: &str,
) -> Result<(), String> {
    let invalid = || {
        "Agent returned invalid or stale saved-edit metadata; inspect drive status before another explicit request".to_string()
    };
    match command {
        EditCommand::List { limit, .. } => {
            if response["profile_id"] != profile
                || response["auth_generation"] != generation
                || response["recovery_scope_token"] != scope
                || response["read_only"] != true
            {
                return Err(invalid());
            }
            let items = response
                .get("items")
                .and_then(Value::as_array)
                .filter(|items| items.len() <= usize::from(*limit))
                .ok_or_else(invalid)?;
            if items.iter().any(|item| {
                item.get("record_id")
                    .and_then(Value::as_str)
                    .is_none_or(|id| !valid_edit_id(id))
                    || item
                        .get("generation")
                        .and_then(Value::as_u64)
                        .is_none_or(|generation| generation == 0)
            }) {
                return Err(invalid());
            }
            match response.get("next_after") {
                Some(Value::Null) => {}
                Some(Value::String(cursor)) if bounded_edit_cursor(cursor) => {}
                _ => return Err(invalid()),
            }
        }
        EditCommand::Check {
            id,
            generation: record_generation,
        } => {
            const KEYS: [&str; 11] = [
                "profile_id",
                "auth_generation",
                "recovery_scope_token",
                "record_id",
                "generation",
                "result",
                "bytes",
                "read_only",
                "cloud_mutated",
                "local_completion",
                "original_snapshot_retained",
            ];
            let object = response.as_object().ok_or_else(invalid)?;
            if object.len() != KEYS.len()
                || !KEYS.iter().all(|key| object.contains_key(*key))
                || response["profile_id"] != profile
                || response["auth_generation"].as_u64() != Some(generation)
                || response["recovery_scope_token"] != scope
                || response["record_id"].as_str() != Some(id.as_str())
                || response["generation"].as_u64() != Some(*record_generation)
                || response["read_only"] != true
                || response["cloud_mutated"] != false
                || response["local_completion"] != "unchanged"
                || response["original_snapshot_retained"] != true
            {
                return Err(invalid());
            }
            match response["result"].as_str() {
                Some("matched") if response["bytes"].as_u64().is_some() => {}
                Some("missing" | "different" | "unavailable") if response["bytes"].is_null() => {}
                _ => return Err(invalid()),
            }
        }
        EditCommand::Retry { .. } => {
            if response.get("continued_create").is_some()
                || response.get("original_snapshot_retained").is_some()
            {
                const KEYS: [&str; 9] = [
                    "profile_id",
                    "auth_generation",
                    "recovery_scope_token",
                    "state",
                    "retained",
                    "remote_verified",
                    "local_completion",
                    "continued_create",
                    "original_snapshot_retained",
                ];
                let object = response.as_object().ok_or_else(invalid)?;
                let freshly_completed = response["state"] == "verified_applied"
                    && response["remote_verified"] == true
                    && response["local_completion"] == "completed";
                let historically_linked = response["state"] == "historical_link_completed"
                    && response["remote_verified"] == false
                    && response["local_completion"] == "unavailable";
                let review_required = response["state"] == "review_required"
                    && response["remote_verified"] == false
                    && response["local_completion"] == "unavailable";
                if object.len() != KEYS.len()
                    || !KEYS.iter().all(|key| object.contains_key(*key))
                    || response["profile_id"] != profile
                    || response["auth_generation"].as_u64() != Some(generation)
                    || response["recovery_scope_token"] != scope
                    || response["retained"] != true
                    || response["continued_create"] != true
                    || response["original_snapshot_retained"] != true
                    || !(freshly_completed || historically_linked || review_required)
                {
                    return Err(invalid());
                }
                return Ok(());
            }
            let state = response
                .get("state")
                .and_then(Value::as_str)
                .ok_or_else(invalid)?;
            let verified = response
                .get("remote_verified")
                .and_then(Value::as_bool)
                .ok_or_else(invalid)?;
            let completion = response
                .get("local_completion")
                .and_then(Value::as_str)
                .ok_or_else(invalid)?;
            if !matches!(
                state,
                "verified_applied" | "conflict" | "outcome_unknown" | "not_completed"
            ) || !matches!(
                completion,
                "completed" | "not_requested" | "unavailable" | "uncertain"
            ) || verified != (state == "verified_applied")
                || (completion == "completed" && !verified)
                || response["retained"] != true
            {
                return Err(invalid());
            }
        }
    }
    Ok(())
}

fn config_command(
    command: &ConfigCommand,
    path: &Path,
    profile: Option<&str>,
) -> Result<(), String> {
    match command {
        ConfigCommand::Init {
            server,
            mount_path,
            auth,
            username,
            client_id,
            no_auto_mount,
            no_remember_login,
            reconnect_interval_seconds,
        } => {
            let config = HeadlessConfig {
                schema_version: 1,
                server: server.clone(),
                auth: match auth {
                    ConfigAuth::Browser => AuthMethod::Browser,
                    ConfigAuth::AppToken => AuthMethod::AppToken,
                },
                username: username.clone(),
                client_id: client_id.clone(),
                mount_path: mount_path.clone(),
                auto_mount: !*no_auto_mount,
                remember_login: !*no_remember_login,
                reconnect_interval_seconds: *reconnect_interval_seconds,
                profile: profile.unwrap_or("default").into(),
                windows_recovery: None,
            };
            config.validate().map_err(|error| error.to_string())?;
            let parent = path
                .parent()
                .ok_or("Configuration requires an absolute file path")?;
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder
                .create(parent)
                .map_err(|_| "Cannot create configuration directory")?;
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open(path)
                .map_err(|_| "Cannot create configuration file; existing files are preserved")?;
            let mut bytes =
                serde_json::to_vec_pretty(&config).map_err(|_| "Cannot encode configuration")?;
            bytes.push(b'\n');
            file.write_all(&bytes)
                .and_then(|()| file.sync_all())
                .map_err(|_| "Cannot save configuration")?;
            println!("Created {}", path.display());
        }
        ConfigCommand::Show => {
            let config = raiun_headless::load(path).map_err(|error| error.to_string())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&config).map_err(|_| "Cannot encode configuration")?
            );
        }
        ConfigCommand::Check => {
            raiun_headless::load(path).map_err(|error| error.to_string())?;
            println!("Configuration is valid");
        }
    }
    Ok(())
}

fn read_app_token(from_stdin: bool) -> Result<Zeroizing<String>, String> {
    const MAX_TOKEN: usize = 16 * 1024;
    let token = if from_stdin {
        let mut bytes = Zeroizing::new(Vec::new());
        std::io::stdin()
            .lock()
            .take(MAX_TOKEN as u64 + 3)
            .read_to_end(&mut bytes)
            .map_err(|_| "Cannot read app token from stdin")?;
        // A single conventional line ending is accepted, never interior lines.
        if bytes.ends_with(b"\n") {
            bytes.pop();
            if bytes.ends_with(b"\r") {
                bytes.pop();
            }
        }
        if bytes.is_empty() || bytes.len() > MAX_TOKEN {
            return Err("App token is empty or exceeds 16 KiB".into());
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| "App token must be UTF-8 text")?;
        Zeroizing::new(text.to_owned())
    } else {
        Zeroizing::new(rpassword::prompt_password("App token: ").map_err(
            |_| "Cannot prompt for app token; use --token-stdin with a private input stream",
        )?)
    };
    if token.is_empty() || token.len() > MAX_TOKEN || token.chars().any(char::is_control) {
        return Err("App token must be one nonempty line of at most 16 KiB".into());
    }
    Ok(token)
}

fn absolute(path: &Path, flag: &str) -> Result<(), String> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(format!("{flag} must be an absolute path"))
    }
}

fn state_dir(explicit: Option<PathBuf>) -> Result<PathBuf, String> {
    let path = if let Some(path) =
        explicit.or_else(|| env::var_os("RAIUN_STATE_DIR").map(PathBuf::from))
    {
        path
    } else {
        #[cfg(windows)]
        {
            PathBuf::from(env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA must be set")?)
                .join("RaiunHeadless")
        }
        #[cfg(not(windows))]
        {
            if let Some(root) = env::var_os("XDG_STATE_HOME") {
                PathBuf::from(root).join("raiun-headless")
            } else {
                PathBuf::from(env::var_os("HOME").ok_or("HOME must be set")?)
                    .join(".local/state/raiun-headless")
            }
        }
    };
    absolute(&path, "Headless state directory")?;
    Ok(path)
}

fn sibling_agent() -> Result<PathBuf, String> {
    let exe = env::current_exe().map_err(|error| error.to_string())?;
    Ok(exe
        .parent()
        .ok_or("Cannot locate CLI executable directory")?
        .join(if cfg!(windows) {
            "raiun-agent.exe"
        } else {
            "raiun-agent"
        }))
}

fn callback_port(authorization: &str) -> Result<u16, String> {
    let url =
        Url::parse(authorization).map_err(|_| "Agent returned an invalid authorization URL")?;
    if url.scheme() != "https" && url.scheme() != "http" {
        return Err("Agent returned an unsupported authorization URL".into());
    }
    let redirect = url
        .query_pairs()
        .find(|(key, _)| key == "redirect_uri")
        .map(|(_, value)| value.into_owned())
        .ok_or("Authorization URL has no redirect_uri")?;
    let redirect = Url::parse(&redirect).map_err(|_| "Invalid sign-in redirect_uri")?;
    if redirect.scheme() != "http"
        || !matches!(
            redirect.host_str(),
            Some("127.0.0.1" | "localhost" | "[::1]")
        )
    {
        return Err("Sign-in redirect_uri must use an HTTP loopback callback".into());
    }
    redirect
        .port()
        .ok_or_else(|| "Sign-in redirect_uri has no explicit callback port".into())
}

fn envelope(bytes: &[u8]) -> Result<Value, String> {
    let response: Value =
        serde_json::from_slice(bytes).map_err(|_| "Agent returned invalid JSON")?;
    match response.get("ok").and_then(Value::as_bool) {
        Some(true) => response
            .get("data")
            .cloned()
            .ok_or_else(|| "Agent response has no data".into()),
        Some(false) => Err(response
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("Agent rejected the request")
            .to_owned()),
        None => Err("Agent response has no boolean ok field".into()),
    }
}

fn request_agent(executable: &Path, state: &Path, request: &Value) -> Result<Value, String> {
    let timeout = match request["action"].as_str() {
        Some("auth_begin") => Duration::from_secs(75),
        Some("shutdown") => Duration::from_secs(310),
        // Full conditional readback can use the configured recovery job's
        // maximum 24-hour allowance. Only this read-only action gets that
        // deadline plus bounded relay overhead; mutation timeouts stay intact.
        Some("windows_recovery_check_cloud") => Duration::from_secs(86_400 + 60),
        _ => Duration::from_secs(40),
    };
    request_agent_until(executable, state, request, Instant::now() + timeout)
}

fn request_agent_until(
    executable: &Path,
    state: &Path,
    request: &Value,
    deadline: Instant,
) -> Result<Value, String> {
    let mut command = Command::new(executable);
    command
        .arg("request")
        .arg(request.to_string())
        .stdin(Stdio::null());
    run_agent_request(command, state, deadline, None)
}

fn request_agent_stdin(
    executable: &Path,
    state: &Path,
    bytes: &[u8],
    deadline: Instant,
) -> Result<Value, String> {
    if bytes.len() > 64 * 1024 {
        return Err("Secret request exceeds 64 KiB".into());
    }
    let mut command = Command::new(executable);
    command.arg("request-stdin").stdin(Stdio::piped());
    run_agent_request(command, state, deadline, Some(bytes))
}

fn run_agent_request(
    mut command: Command,
    state: &Path,
    deadline: Instant,
    secret: Option<&[u8]>,
) -> Result<Value, String> {
    if Instant::now() >= deadline {
        return Err("Agent request timed out".into());
    }
    let mut child = command
        .env("RAIUN_STATE_DIR", state)
        .env("RAIUN_HEADLESS_CONTEXT", if cfg!(windows) { "1" } else { "0" })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("cannot run sibling raiun-agent: {error}; install it beside raiun and start raiun drive serve"))?;
    // Write concurrently with bounded stdout/stderr collection. Even a sibling
    // that stops reading stdin cannot block the deadline/child cleanup path.
    let (input_sender, input_receiver) = mpsc::channel();
    let mut input_done = secret.is_none();
    if let Some(bytes) = secret {
        let bytes = Zeroizing::new(bytes.to_vec());
        let pipe = child.stdin.take();
        std::thread::spawn(move || {
            let result = pipe
                .ok_or(())
                .and_then(|mut pipe| pipe.write_all(&bytes).map_err(|_| ()));
            let _ = input_sender.send(result);
        });
    }
    let (sender, receiver) = mpsc::channel();
    let stdout = child.stdout.take().ok_or("Agent stdout unavailable")?;
    let stderr = child.stderr.take().ok_or("Agent stderr unavailable")?;
    for (is_stdout, pipe) in [
        (true, Box::new(stdout) as Box<dyn Read + Send>),
        (false, Box::new(stderr) as Box<dyn Read + Send>),
    ] {
        let sender = sender.clone();
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = pipe
                .take(MAX_OUTPUT + 1)
                .read_to_end(&mut bytes)
                .map(|_| bytes);
            let _ = sender.send((is_stdout, result));
        });
    }
    drop(sender);
    let mut stdout = None;
    let mut received = 0;
    let result = (|| {
        loop {
            if Instant::now() >= deadline {
                return Err("Agent request timed out; its operation may still be running. Check drive status before retrying".into());
            }
            if !input_done && let Ok(result) = input_receiver.try_recv() {
                result.map_err(|()| "Cannot deliver app-token request through stdin")?;
                input_done = true;
            }
            while let Ok((is_stdout, result)) = receiver.try_recv() {
                let bytes = result.map_err(|_| "Cannot read agent output")?;
                if bytes.len() as u64 > MAX_OUTPUT {
                    return Err("Agent output exceeds the 1 MiB limit".into());
                }
                if is_stdout {
                    stdout = Some(bytes);
                }
                received += 1;
            }
            if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
                if !status.success() {
                    return Err("Agent request failed; check that raiun drive serve is running with the same --state-dir (and required platform mount support is installed)".into());
                }
                if received == 2 && input_done {
                    return envelope(stdout.as_deref().ok_or("Agent returned no output")?);
                }
            }
            if Instant::now() >= deadline {
                return Err("Agent request timed out; its operation may still be running. Check drive status before retrying".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    })();
    if result.is_err() {
        let _ = child.kill();
    }
    let _ = child.wait();
    result
}

#[cfg(test)]
mod platform_tests {
    use super::*;
    fn args(command: DriveCommand) -> DriveArgs {
        DriveArgs {
            state_dir: None,
            profile: Some("chosen".into()),
            json: true,
            command,
        }
    }
    #[test]
    fn app_token_wait_keeps_one_deadline_and_refuses_late_completion() {
        let deadline = Instant::now() + Duration::from_millis(25);
        let mut polls = 0;
        let error = await_app_token_login(
            json!({"started":true,"auth_generation":7}),
            "default",
            deadline,
            Duration::from_millis(2),
            |actual_deadline| {
                assert_eq!(actual_deadline, deadline);
                polls += 1;
                Ok(json!({"connected":false,"auth_generation":7,"authenticating":true}))
            },
        )
        .unwrap_err();
        assert!(polls > 0);
        assert!(error.contains("timed out"));
        let error = await_app_token_login(
            json!({"started":true,"auth_generation":7}),
            "default",
            Instant::now() + Duration::from_millis(5),
            Duration::ZERO,
            |_| {
                std::thread::sleep(Duration::from_millis(10));
                Ok(json!({"connected":true,"auth_generation":7}))
            },
        )
        .unwrap_err();
        assert!(error.contains("timed out"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn app_token_poll_child_cannot_extend_the_total_deadline() {
        let state = tempfile::tempdir().unwrap();
        let started = Instant::now();
        let deadline = started + Duration::from_millis(40);
        let error = await_app_token_login(
            json!({"started":true,"auth_generation":7}),
            "default",
            deadline,
            Duration::ZERO,
            |deadline| {
                let mut command = Command::new("sh");
                command.args(["-c", "exec sleep 2"]).stdin(Stdio::null());
                run_agent_request(command, state.path(), deadline, None)
            },
        )
        .unwrap_err();
        assert!(error.contains("timed out"));
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "the child received the remaining total budget"
        );
    }
    #[test]
    fn windows_mount_is_one_explicit_request_and_account_creation_has_no_root() {
        let mount = requests_for_platform(
            &args(DriveCommand::Mount {
                path: Some(env::current_dir().unwrap().join("synthetic")),
            }),
            true,
        )
        .unwrap();
        assert_eq!(mount.len(), 1);
        assert_eq!(mount[0]["action"], "mount");
        assert_eq!(mount[0]["profile_id"], "chosen");
        assert!(mount[0]["cloud_root"].is_string());
        let add = requests_for_platform(
            &args(DriveCommand::Accounts {
                command: AccountCommand::Add {
                    label: "Synthetic".into(),
                    path: None,
                },
            }),
            true,
        )
        .unwrap();
        assert_eq!(
            add,
            vec![json!({"action":"account_add","label":"Synthetic"})]
        );
        assert!(
            requests_for_platform(
                &args(DriveCommand::Accounts {
                    command: AccountCommand::Add {
                        label: "Synthetic".into(),
                        path: Some(env::current_dir().unwrap())
                    }
                }),
                true
            )
            .is_err()
        );
    }
    #[test]
    fn linux_still_requires_an_explicit_account_root() {
        assert!(
            requests_for_platform(
                &args(DriveCommand::Accounts {
                    command: AccountCommand::Add {
                        label: "Synthetic".into(),
                        path: None
                    }
                }),
                false
            )
            .is_err()
        );
    }

    fn edit_status() -> Value {
        json!({"runtime_mode":"mount_only","profile_id":"chosen","connected":true,
            "auth_generation":9,"authenticating":false,"refreshing":false,
            "root_configuration":{"valid":true,"identity_bound":true,"registration_state":"registered",
                "recovery_scope_token":"a".repeat(64)}})
    }

    fn edit_page() -> Value {
        json!({"profile_id":"chosen","auth_generation":9,"recovery_scope_token":"a".repeat(64),
            "read_only":true,"items":[{"record_id":"a19f","generation":7}],"next_after":null})
    }

    fn retry_command(path: &str) -> EditCommand {
        EditCommand::Retry {
            id: "a19f".into(),
            generation: 7,
            local_relative_path: path.into(),
        }
    }

    #[test]
    fn windows_edit_list_binds_fresh_explicit_profile_context_and_keeps_cursor_opaque() {
        let cursor = r#"{"opaque":"unchanged"}"#;
        let command = EditCommand::List {
            limit: 3,
            after: Some(cursor.into()),
        };
        let mut requests = Vec::new();
        let result = execute_edits(&command, "chosen", true, |request| {
            requests.push(request.clone());
            Ok(if requests.len() == 1 {
                edit_status()
            } else {
                edit_page()
            })
        })
        .unwrap();
        assert_eq!(result, edit_page());
        assert_eq!(
            requests,
            vec![
                json!({"action":"status","profile_id":"chosen","required_mode":"mount_only"}),
                json!({"action":"windows_recovery_list","profile_id":"chosen","required_mode":"mount_only",
                "expected_generation":9,"expected_recovery_scope_token":"a".repeat(64),"limit":3,"after":cursor})
            ]
        );
    }

    #[test]
    fn windows_edit_retry_uses_selected_local_components_and_immutable_record_generation() {
        let command = retry_command(r"Spaces\Projects/資料.txt");
        let response = json!({"state":"verified_applied","remote_verified":true,
            "local_completion":"uncertain","retained":true,"attempts":1});
        let mut requests = Vec::new();
        let result = execute_edits(&command, "chosen", true, |request| {
            requests.push(request.clone());
            Ok(if requests.len() == 1 {
                edit_status()
            } else {
                response.clone()
            })
        })
        .unwrap();
        assert_eq!(result["remote_verified"], true);
        assert_eq!(result["local_completion"], "uncertain");
        assert_eq!(
            requests[1],
            json!({"action":"windows_recovery_retry","profile_id":"chosen",
            "required_mode":"mount_only","expected_generation":9,"expected_recovery_scope_token":"a".repeat(64),
            "record_id":"a19f","generation":7,"local_components":["Spaces","Projects","資料.txt"]})
        );
    }

    #[test]
    fn edit_commands_refuse_linux_before_any_ipc() {
        for command in [
            EditCommand::List {
                limit: 50,
                after: None,
            },
            retry_command("Personal/a.bin"),
        ] {
            assert!(
                requests_for_platform(&args(DriveCommand::Edits { command }), false)
                    .unwrap_err()
                    .contains("requires Windows")
            );
        }
        let mut calls = 0;
        assert!(
            execute_edits(&retry_command("Personal/a.bin"), "chosen", false, |_| {
                calls += 1;
                Ok(edit_status())
            })
            .is_err()
        );
        assert_eq!(calls, 0);
    }

    #[test]
    fn edit_local_paths_reject_windows_escape_ambiguity_and_resource_exhaustion() {
        for path in [
            "",
            "/Personal/a",
            r"\Personal\a",
            r"C:\Personal\a",
            "Personal/../a",
            "Personal/./a",
            "Personal//a",
            "Personal/a/",
            "Personal/a:stream",
            "Personal/a\n",
            "Personal/a.",
            "Personal/a ",
            "Personal/CON.txt",
            "Personal/LPT1",
            "Personal/a?b",
        ] {
            assert!(
                local_edit_components(path).is_err(),
                "unsafe fixture path admitted: {path:?}"
            );
        }
        assert!(local_edit_components(&format!("Personal/{}", "a".repeat(256))).is_err());
        assert!(local_edit_components(&format!("Personal/{}", "界".repeat(86))).is_err());
        assert!(local_edit_components(&vec!["a"; 257].join("/")).is_err());
        assert_eq!(
            local_edit_components(r"Spaces\Exact Name/Document.bin").unwrap(),
            ["Spaces", "Exact Name", "Document.bin"]
        );
    }

    #[test]
    fn malformed_or_transitioning_edit_status_never_dispatches_the_retry() {
        let mut statuses = Vec::new();
        for (field, value) in [
            ("profile_id", json!("different")),
            ("auth_generation", json!(0)),
            ("connected", json!(false)),
            ("runtime_mode", json!("desktop")),
            ("refreshing", json!(true)),
            ("session_cleanup_uncertain", json!(true)),
            ("authenticating", json!("false")),
        ] {
            let mut status = edit_status();
            status[field] = value;
            statuses.push(status);
        }
        for (field, value) in [
            ("valid", json!(false)),
            ("identity_bound", json!(false)),
            ("registration_state", json!("prepared_not_registered")),
            ("recovery_scope_token", json!("A".repeat(64))),
            ("recovery_scope_token", Value::Null),
        ] {
            let mut status = edit_status();
            status["root_configuration"][field] = value;
            statuses.push(status);
        }
        for status in statuses {
            let mut calls = 0;
            assert!(
                execute_edits(&retry_command("Personal/a.bin"), "chosen", true, |_| {
                    calls += 1;
                    Ok(status.clone())
                })
                .is_err()
            );
            assert_eq!(calls, 1, "unsafe context dispatched mutation");
        }
    }

    #[test]
    fn stale_page_or_agent_refusal_is_not_replayed_with_new_context() {
        let command = EditCommand::List {
            limit: 50,
            after: None,
        };
        for (field, value) in [
            ("auth_generation", json!(10)),
            ("recovery_scope_token", json!("b".repeat(64))),
            ("profile_id", json!("another")),
            ("read_only", json!(false)),
            ("items", json!({})),
            ("next_after", json!(23)),
        ] {
            let mut page = edit_page();
            page[field] = value;
            let mut calls = 0;
            assert!(
                execute_edits(&command, "chosen", true, |_| {
                    calls += 1;
                    Ok(if calls == 1 {
                        edit_status()
                    } else {
                        page.clone()
                    })
                })
                .is_err()
            );
            assert_eq!(calls, 2);
        }
        let mut calls = 0;
        let error = execute_edits(&retry_command("Personal/a.bin"), "chosen", true, |_| {
            calls += 1;
            if calls == 1 {
                Ok(edit_status())
            } else {
                Err("synthetic stale admission".into())
            }
        })
        .unwrap_err();
        assert!(error.contains("stale admission"));
        assert_eq!(calls, 2, "an explicit retry must never auto-replay");
    }

    #[test]
    fn retry_schema_distinguishes_remote_verification_from_local_completion() {
        let command = retry_command("Personal/a.bin");
        for completion in ["completed", "unavailable", "uncertain", "not_requested"] {
            let outcome = json!({"state":"verified_applied","remote_verified":true,"local_completion":completion,"retained":true});
            assert_eq!(
                edit_retry_exit_status(&outcome).is_ok(),
                completion == "completed"
            );
            assert!(
                validate_edit_response(
                    &command,
                    &json!({"state":"verified_applied","remote_verified":true,
                "local_completion":completion,"retained":true}),
                    "chosen",
                    9,
                    &"a".repeat(64)
                )
                .is_ok()
            );
        }
        for state in ["conflict", "outcome_unknown", "not_completed"] {
            let outcome = json!({"state":state,"remote_verified":false,"local_completion":"not_requested","retained":true});
            let preserved = outcome.clone();
            let error = edit_retry_exit_status(&outcome).unwrap_err();
            assert!(error.contains("not fully completed"));
            assert_eq!(
                outcome, preserved,
                "failed exit must preserve the structured outcome"
            );
            assert!(
                validate_edit_response(
                    &command,
                    &json!({"state":state,"remote_verified":false,
                "local_completion":"not_requested","retained":true}),
                    "chosen",
                    9,
                    &"a".repeat(64)
                )
                .is_ok()
            );
            assert!(
                validate_edit_response(
                    &command,
                    &json!({"state":state,"remote_verified":false,
                "local_completion":"completed","retained":true}),
                    "chosen",
                    9,
                    &"a".repeat(64)
                )
                .is_err()
            );
        }
        for reply in [
            json!({"state":"verified_applied","retained":true}),
            json!({"state":"verified_applied","remote_verified":false,"local_completion":"completed","retained":true}),
            json!({"state":"verified_applied","remote_verified":true,"local_completion":"clean","retained":true}),
        ] {
            assert!(
                validate_edit_response(&command, &reply, "chosen", 9, &"a".repeat(64)).is_err()
            );
        }
    }

    #[test]
    fn malformed_edit_arguments_do_not_request_context() {
        for command in [
            EditCommand::List {
                limit: 0,
                after: None,
            },
            EditCommand::List {
                limit: 101,
                after: None,
            },
            EditCommand::List {
                limit: 1,
                after: Some("x".repeat(16_385)),
            },
            EditCommand::Retry {
                id: "not-hex".into(),
                generation: 7,
                local_relative_path: "Personal/a".into(),
            },
            EditCommand::Retry {
                id: "a19f".into(),
                generation: 0,
                local_relative_path: "Personal/a".into(),
            },
        ] {
            let mut calls = 0;
            assert!(
                execute_edits(&command, "chosen", true, |_| {
                    calls += 1;
                    Ok(edit_status())
                })
                .is_err()
            );
            assert_eq!(calls, 0);
        }
    }
    #[test]
    fn retry_stdout_is_preserved_for_scriptable_nonzero_and_completed_outcomes() {
        for (state, verified, completion, successful) in [
            ("verified_applied", true, "completed", true),
            ("verified_applied", true, "unavailable", false),
            ("verified_applied", true, "uncertain", false),
            ("conflict", false, "not_requested", false),
            ("not_completed", false, "not_requested", false),
            ("outcome_unknown", false, "not_requested", false),
        ] {
            let outcome = json!({"state":state,"remote_verified":verified,"local_completion":completion,"retained":true});
            let mut stdout = Vec::new();
            let result = write_drive_result(&outcome, true, true, &mut stdout);
            assert_eq!(result.is_ok(), successful);
            assert_eq!(serde_json::from_slice::<Value>(&stdout).unwrap(), outcome);
            if let Err(error) = result {
                assert!(error.len() < 256 && error.contains("not fully completed"));
            }
        }
    }
}
