#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod desktop_updates;
mod desktop_updates_policy;
mod lifecycle;

#[cfg(target_os = "linux")]
use lifecycle::agent_start_action;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use lifecycle::sibling_agent_path;
use lifecycle::{
    agent_action_waits_for_completion, agent_response_timeout, has_background_argument,
    should_prevent_exit, should_show_initial_window, tray_status_label,
};
#[cfg(any(target_os = "linux", target_os = "windows"))]
use raiun_control::{encode_json_line, read_json_line};
use serde_json::{Value, json};
use std::fs::OpenOptions;
use std::io::Write;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::time::Duration;
use tauri::menu::{IconMenuItem, Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_opener::OpenerExt;
use url::Url;
use zeroize::Zeroize;
#[cfg(target_os = "windows")]
use zeroize::Zeroizing;

const TRAY_STATUS_POLL_INTERVAL: Duration = Duration::from_secs(15);
const DEFAULT_WINDOW_SIZE: (u32, u32) = (1000, 720);
const MIN_WINDOW_SIZE: (u32, u32) = (760, 600);
static STATUS_REQUEST_LOCK: Mutex<()> = Mutex::new(());
static MEDIA_SCAN_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Debug, PartialEq, Eq)]
struct UnlockIntent {
    profile_id: String,
    space_id: String,
    root_resource_id: String,
}

#[derive(Default)]
struct ShellState {
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    agent: Mutex<Option<Child>>,
    shutting_down: AtomicBool,
    tray: Mutex<Option<tauri::tray::TrayIcon<tauri::Wry>>>,
    tray_available: AtomicBool,
    main_window_open: AtomicBool,
    tray_status_revision: AtomicU64,
    pause_action_busy: AtomicBool,
    sync_action_busy: AtomicBool,
    tray_status_stop: Mutex<Option<Sender<()>>>,
    pending_error: Mutex<Option<String>>,
    pending_navigation: Mutex<Option<String>>,
    pending_unlock_intent: Mutex<Option<UnlockIntent>>,
}

fn valid_unlock_profile_id(value: &str) -> bool {
    value == "default"
        || value.strip_prefix("profile-").is_some_and(|suffix| {
            suffix.len() == 32
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

fn valid_unlock_hint(value: &str) -> bool {
    !value.is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control)
}

fn parse_unlock_intent(raw: &str) -> Option<UnlockIntent> {
    if raw.len() > 4096 {
        return None;
    }
    let raw_target = raw.split_once('?').map_or(raw, |(target, _)| target);
    if !matches!(raw_target, "raiun://unlock" | "raiun://unlock/") {
        return None;
    }
    let uri = Url::parse(raw).ok()?;
    if uri.scheme() != "raiun"
        || uri.host_str() != Some("unlock")
        || !uri.username().is_empty()
        || uri.password().is_some()
        || uri.port().is_some()
        || !(uri.path().is_empty() || uri.path() == "/")
        || uri.fragment().is_some()
    {
        return None;
    }
    let mut fields = std::collections::BTreeMap::new();
    for (key, value) in uri.query_pairs() {
        if !matches!(
            key.as_ref(),
            "v" | "profile_id" | "space_id" | "root_resource_id"
        ) || fields
            .insert(key.into_owned(), value.into_owned())
            .is_some()
        {
            return None;
        }
    }
    if fields.len() != 4 || fields.get("v")? != "1" {
        return None;
    }
    let profile_id = fields.remove("profile_id")?;
    let space_id = fields.remove("space_id")?;
    let root_resource_id = fields.remove("root_resource_id")?;
    if !valid_unlock_profile_id(&profile_id)
        || !valid_unlock_hint(&space_id)
        || !valid_unlock_hint(&root_resource_id)
    {
        return None;
    }
    Some(UnlockIntent {
        profile_id,
        space_id,
        root_resource_id,
    })
}

fn queue_unlock_intent(app: &AppHandle, args: &[String]) {
    let Some(intent) = args.iter().find_map(|arg| parse_unlock_intent(arg)) else {
        return;
    };
    let Some(state) = app.try_state::<ShellState>() else {
        return;
    };
    if let Ok(mut pending) = state.pending_unlock_intent.lock() {
        *pending = Some(intent);
    }
    show_window(app);
    let _ = app.emit("raiun:unlock-intent", ());
}

struct TrayMenuState {
    // Regular items keep GTK's visible label in sync with set_text. muda's
    // GTK IconMenuItem uses a custom child label that its setter misses.
    pause: MenuItem<tauri::Wry>,
    sync: MenuItem<tauri::Wry>,
    quit: IconMenuItem<tauri::Wry>,
}

#[cfg(target_os = "linux")]
fn wait_for_linux_agent(
    socket: &std::path::Path,
    process: &mut Option<Child>,
) -> Result<(), String> {
    use std::os::unix::net::UnixStream;
    use std::time::Instant;

    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if UnixStream::connect(socket).is_ok() {
            return Ok(());
        }
        let exit_status = process
            .as_mut()
            .map(Child::try_wait)
            .transpose()
            .map_err(|error| format!("Could not inspect the Raiun agent process: {error}"))?;
        if let Some(Some(status)) = exit_status {
            *process = None;
            return Err(format!(
                "Raiun agent exited before its control socket became available (status {status}); try again to restart it"
            ));
        }
        if Instant::now() >= deadline {
            return Err(
                "Raiun agent process is running, but its control socket is not ready; try again after startup completes"
                    .into(),
            );
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

impl ShellState {
    fn begin_agent_shutdown(&self) -> Result<bool, String> {
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        let _process = self
            .agent
            .lock()
            .map_err(|_| "Raiun process state is unavailable".to_string())?;
        Ok(!self.shutting_down.swap(true, Ordering::AcqRel))
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    fn begin_agent_update_shutdown(&self) -> Result<(), String> {
        let mut agent = self
            .agent
            .lock()
            .map_err(|_| "Raiun process state is unavailable".to_string())?;
        let child = require_owned_agent(agent.as_mut())?;
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("Could not verify the Raiun agent before shutdown: {error}"))?
        {
            *agent = None;
            return Err(format!(
                "The owned Raiun agent had already exited ({status}); its shutdown cannot be tied to this update"
            ));
        }
        if self.shutting_down.swap(true, Ordering::AcqRel) {
            return Err("Raiun is already shutting down".into());
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    fn begin_agent_update_shutdown(&self) -> Result<(), String> {
        Err("Desktop updates are supported on Linux and Windows only".into())
    }

    fn clear_agent_shutdown_after_failure(&self) {
        self.shutting_down.store(false, Ordering::Release);
    }

    #[cfg(target_os = "linux")]
    fn start_agent_if_socket_absent(&self) -> Result<(), String> {
        let socket = socket_path()?;
        self.start_agent_at(&socket, || {
            sibling_agent_path(
                &std::env::current_exe()
                    .map_err(|error| format!("Could not locate Raiun Desktop: {error}"))?,
            )
        })
    }

    #[cfg(target_os = "linux")]
    fn start_agent_at(
        &self,
        socket: &std::path::Path,
        resolve_executable: impl FnOnce() -> Result<std::path::PathBuf, String>,
    ) -> Result<(), String> {
        use std::os::unix::net::UnixStream;

        let mut process = self
            .agent
            .lock()
            .map_err(|_| "Raiun process state is unavailable".to_string())?;
        if self.shutting_down.load(Ordering::Acquire) {
            return Err("Raiun Desktop is shutting down; wait and try again".into());
        }
        let endpoint_available = UnixStream::connect(socket).is_ok();
        let owned_process_running = process
            .as_mut()
            .map(|child| child.try_wait())
            .transpose()
            .map_err(|error| format!("Could not inspect the Raiun agent process: {error}"))?
            .is_some_and(|status| status.is_none());

        match agent_start_action(endpoint_available, owned_process_running) {
            lifecycle::AgentStartAction::UseExistingEndpoint => return Ok(()),
            lifecycle::AgentStartAction::WaitForOwnedProcess => {
                return wait_for_linux_agent(socket, &mut process);
            }
            lifecycle::AgentStartAction::SpawnAgent => {
                // Reap an exited child before replacing the handle.
                *process = None;
            }
        }

        let executable = resolve_executable()?;
        if !executable.is_file() {
            return Err(format!(
                "Raiun agent is unavailable: expected sibling executable {}",
                executable.display()
            ));
        }
        let child = Command::new(&executable)
            .arg("serve")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| {
                format!(
                    "Could not start sibling Raiun agent {}: {error}",
                    executable.display()
                )
            })?;
        *process = Some(child);
        wait_for_linux_agent(socket, &mut process)
    }

    #[cfg(windows)]
    fn start_agent_if_socket_absent(&self) -> Result<(), String> {
        use raiun_control_windows::connect_current_user;
        use std::os::windows::process::CommandExt;

        let mut process = self
            .agent
            .lock()
            .map_err(|_| "Raiun process state is unavailable".to_string())?;
        if self.shutting_down.load(Ordering::Acquire) {
            return Err("Raiun Desktop is shutting down; wait and try again".into());
        }
        if connect_current_user(Duration::from_millis(150)).is_ok() {
            return Ok(());
        }
        if let Some(child) = process.as_mut() {
            if child
                .try_wait()
                .map_err(|error| format!("Could not inspect the Raiun agent process: {error}"))?
                .is_none()
            {
                return Ok(());
            }
            *process = None;
        }
        let executable = sibling_agent_path(
            &std::env::current_exe()
                .map_err(|error| format!("Could not locate Raiun Desktop: {error}"))?,
        )?;
        if !executable.is_file() {
            return Err(format!(
                "Raiun agent is unavailable: expected sibling executable {}",
                executable.display()
            ));
        }
        let child = Command::new(&executable)
            .arg("serve")
            .creation_flags(0x0800_0000) // CREATE_NO_WINDOW: the agent is headless.
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| format!("Could not start Raiun agent: {error}"))?;
        *process = Some(child);
        for _ in 0..80 {
            if connect_current_user(Duration::from_millis(100)).is_ok() {
                return Ok(());
            }
            if let Some(child) = process.as_mut()
                && let Some(status) = child.try_wait().map_err(|error| {
                    format!("Could not inspect the Raiun agent process: {error}")
                })?
            {
                return Err(format!(
                    "Raiun agent exited during startup with status {status}"
                ));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Err("Raiun agent did not open its current-user control pipe".into())
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    fn start_agent_if_socket_absent(&self) -> Result<(), String> {
        Err("Raiun Desktop agent startup is currently supported on Linux and Windows only".into())
    }
}

#[tauri::command]
async fn preview_media_scan(
    source: String,
    destination_root: String,
    filter: raiun_core::media_plan::MediaFilter,
    organization: raiun_core::media_plan::MediaOrganization,
    filesystem_mtime_utc: bool,
) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let _scan = MEDIA_SCAN_LOCK
            .try_lock()
            .map_err(|_| "A media preview is already running")?;
        use raiun_core::media_plan::{MediaPlanOptions, MediaPlanOutcome, plan_media_import};
        use raiun_core::media_scan::{MediaScanOptions, scan_media_folder};
        let options = MediaPlanOptions {
            destination_root,
            filter,
            organization,
        };
        // Reject invalid destinations before inspecting a source directory.
        plan_media_import(&[], &options, &[]).map_err(|error| error.to_string())?;
        let scan = scan_media_folder(
            std::path::Path::new(&source),
            MediaScanOptions {
                filesystem_mtime_utc,
                exclusions: Vec::new(),
            },
        )
        .map_err(|error| error.to_string())?;
        let mut rows =
            plan_media_import(&scan.sources, &options, &[]).map_err(|error| error.to_string())?;
        let mut totals = json!({"scanned":scan.entries_scanned,"sources":scan.sources.len(),
            "planned":0,"filtered":0,"missing_date":0,"collisions":0,"rejected":0});
        for row in &rows {
            let key = match &row.outcome {
                MediaPlanOutcome::Planned { .. } => "planned",
                MediaPlanOutcome::Filtered => "filtered",
                MediaPlanOutcome::MissingUtcDate => "missing_date",
                MediaPlanOutcome::Collision { .. } => "collisions",
                MediaPlanOutcome::Rejected { .. } => "rejected",
            };
            totals[key] = json!(totals[key].as_u64().unwrap_or(0) + 1);
        }
        let rows_truncated = rows.len() > 100;
        rows.truncate(100);
        let mut warnings = scan.warnings;
        let warnings_omitted = scan.warnings_omitted + warnings.len().saturating_sub(20);
        warnings.truncate(20);
        Ok(
            json!({"rows":rows,"rows_truncated":rows_truncated,"totals":totals,
            "complete":scan.complete,"truncated":scan.truncated,
            "warnings":warnings,"warnings_omitted":warnings_omitted}),
        )
    })
    .await
    .map_err(|_| "The media preview worker stopped unexpectedly".to_string())?
}

#[tauri::command]
fn take_shell_error(app: AppHandle) -> Option<String> {
    app.state::<ShellState>().pending_error.lock().ok()?.take()
}

#[tauri::command]
fn take_shell_navigation(app: AppHandle) -> Option<String> {
    app.state::<ShellState>()
        .pending_navigation
        .lock()
        .ok()?
        .take()
}

#[tauri::command]
fn take_shell_unlock_intent(app: AppHandle) -> Option<Value> {
    app.state::<ShellState>()
        .pending_unlock_intent
        .lock()
        .ok()?
        .take()
        .map(|intent| {
            json!({
                "profile_id": intent.profile_id,
                "space_id": intent.space_id,
                "root_resource_id": intent.root_resource_id,
            })
        })
}

fn navigate_window(app: &AppHandle, page: &str) {
    if let Some(state) = app.try_state::<ShellState>()
        && !state.main_window_open.load(Ordering::Acquire)
        && let Ok(mut pending) = state.pending_navigation.lock()
    {
        *pending = Some(page.to_owned());
    }
    show_window(app);
    let _ = app.emit("navigate", page);
}

fn report_tray_error(app: &AppHandle, error: String) {
    if let Some(state) = app.try_state::<ShellState>()
        && !state.main_window_open.load(Ordering::Acquire)
        && let Ok(mut pending) = state.pending_error.lock()
    {
        *pending = Some(error.clone());
    }
    show_window(app);
    let _ = app.emit("raiun:tray-error", error);
}

#[tauri::command]
async fn save_conflict_copy(
    app: AppHandle,
    profile_id: Option<String>,
    space_id: String,
    write_id: String,
    suggested_name: Option<String>,
) -> Result<Value, String> {
    save_local_edit_copy(app, profile_id, space_id, None, write_id, suggested_name).await
}

#[tauri::command]
async fn save_saved_edit_copy(
    app: AppHandle,
    profile_id: String,
    space_id: String,
    root_resource_id: String,
    expected_binding: (u64, String),
    write_id: String,
    suggested_name: Option<String>,
) -> Result<Value, String> {
    let (expected_generation, expected_account_scope) = expected_binding;
    if root_resource_id.trim().is_empty()
        || root_resource_id.len() > 16 * 1024
        || root_resource_id.chars().any(char::is_control)
    {
        return Err("The saved location identity is invalid".into());
    }
    if expected_account_scope.len() != 64
        || !expected_account_scope
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("Refresh the saved account identity".into());
    }
    save_local_edit_copy(
        app,
        Some(profile_id),
        space_id,
        Some((
            root_resource_id,
            expected_generation,
            expected_account_scope,
        )),
        write_id,
        suggested_name,
    )
    .await
}

fn validate_protected_recovery_binding(
    response: Value,
    profile_id: &str,
    expected_generation: u64,
    expected_scope: &str,
) -> Result<(), String> {
    if response.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(
            "Could not verify the current account and Windows drive before saving the copy".into(),
        );
    }
    let status = response
        .get("data")
        .filter(|value| value.is_object())
        .ok_or("The Windows agent returned an invalid drive status")?;
    let root = status
        .get("root_configuration")
        .filter(|value| value.is_object())
        .ok_or("The registered Windows drive folder is unavailable")?;
    if status.get("profile_id").and_then(Value::as_str) != Some(profile_id)
        || status.get("connected").and_then(Value::as_bool) != Some(true)
        || status.get("auth_generation").and_then(Value::as_u64) != Some(expected_generation)
        || root.get("valid").and_then(Value::as_bool) != Some(true)
        || root.get("identity_bound").and_then(Value::as_bool) != Some(true)
        || root.get("registration_state").and_then(Value::as_str) != Some("registered")
        || root.get("recovery_scope_token").and_then(Value::as_str) != Some(expected_scope)
    {
        return Err("The account or registered Windows drive changed. Refresh saved vault edits before saving.".into());
    }
    Ok(())
}

fn validate_selected_profile(response: Value, expected_profile: &str) -> Result<(), String> {
    if response.get("ok").and_then(Value::as_bool) != Some(true)
        || response.pointer("/data/selected").and_then(Value::as_str) != Some(expected_profile)
    {
        return Err(
            "The selected account changed. Reopen the saved vault edits list before saving.".into(),
        );
    }
    Ok(())
}

fn validate_protected_copy_receipt(
    response: &Value,
    expected_body_length: u64,
) -> Result<(), String> {
    let receipt = response
        .get("data")
        .filter(|value| has_exact_keys(value, &["schema_version", "body_length", "read_only"]))
        .ok_or("Raiun returned an invalid Save Copy receipt")?;
    if receipt.get("schema_version").and_then(Value::as_u64) != Some(1)
        || receipt.get("body_length").and_then(Value::as_u64) != Some(expected_body_length)
        || receipt.get("read_only").and_then(Value::as_bool) != Some(true)
    {
        return Err("Raiun could not confirm the saved plaintext copy. Check the destination before trying again.".into());
    }
    Ok(())
}

#[tauri::command]
async fn save_protected_vault_capture_copy(
    app: AppHandle,
    request: Value,
) -> Result<Value, String> {
    if !has_exact_keys(
        &request,
        &[
            "profileId",
            "expectedGeneration",
            "expectedRecoveryScopeToken",
            "spaceId",
            "rootResourceId",
            "remoteRoot",
            "itemToken",
            "expectedBodyLength",
            "suggestedName",
        ],
    ) {
        return Err(
            "The selected saved vault edit is invalid. Refresh the list and choose it again."
                .into(),
        );
    }
    let required_string = |name: &str| -> Result<String, String> {
        request
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| {
                "The selected saved vault edit is invalid. Refresh the list and choose it again."
                    .to_owned()
            })
    };
    let profile_id = required_string("profileId")?;
    let expected_recovery_scope_token = required_string("expectedRecoveryScopeToken")?;
    let space_id = required_string("spaceId")?;
    let root_resource_id = required_string("rootResourceId")?;
    let remote_root = required_string("remoteRoot")?;
    let item_token = required_string("itemToken")?;
    let suggested_name = required_string("suggestedName")?;
    let expected_generation = request
        .get("expectedGeneration")
        .and_then(Value::as_u64)
        .ok_or("The selected saved vault edit is invalid. Refresh the list and choose it again")?;
    let expected_body_length = request
        .get("expectedBodyLength")
        .and_then(Value::as_u64)
        .ok_or("The selected saved vault edit is invalid. Refresh the list and choose it again")?;
    if !valid_unlock_profile_id(&profile_id)
        || expected_generation == 0
        || expected_recovery_scope_token.len() != 64
        || !expected_recovery_scope_token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || item_token.len() != 48
        || !item_token.bytes().all(|byte| byte.is_ascii_hexdigit())
        || [
            space_id.as_str(),
            root_resource_id.as_str(),
            remote_root.as_str(),
        ]
        .iter()
        .any(|value| value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control))
        || suggested_name.is_empty()
        || suggested_name.len() > 96
        || suggested_name == "."
        || suggested_name == ".."
        || suggested_name
            .chars()
            .any(|character| matches!(character, '/' | '\\' | ':'))
        || suggested_name.chars().any(char::is_control)
    {
        return Err(
            "The selected saved vault edit is invalid. Refresh the list and choose it again."
                .into(),
        );
    }
    tauri::async_runtime::spawn_blocking(move || {
        use tauri_plugin_dialog::DialogExt;

        validate_selected_profile(request_agent(json!({"action":"accounts"}))?, &profile_id)?;
        validate_protected_recovery_binding(
            request_agent(json!({"action":"status","profile_id":profile_id}))?,
            &profile_id,
            expected_generation,
            &expected_recovery_scope_token,
        )?;
        let selected = app
            .dialog()
            .file()
            .set_title("Save a readable plaintext copy of this encrypted-file edit")
            .set_file_name(&suggested_name)
            .blocking_save_file()
            .map(|path| {
                path.into_path()
                    .map_err(|_| "Choose a local file path for Save Copy".to_owned())
            })
            .transpose()?;
        let Some(destination) = selected else {
            return Ok(json!({"cancelled":true}));
        };
        validate_selected_profile(request_agent(json!({"action":"accounts"}))?, &profile_id)?;
        validate_protected_recovery_binding(
            request_agent(json!({"action":"status","profile_id":profile_id}))?,
            &profile_id,
            expected_generation,
            &expected_recovery_scope_token,
        )?;
        let response = request_agent(json!({
            "action":"windows_vault_capture_save_copy",
            "profile_id":profile_id,
            "expected_generation":expected_generation,
            "expected_recovery_scope_token":expected_recovery_scope_token,
            "space_id":space_id,
            "root_resource_id":root_resource_id,
            "remote_root":remote_root,
            "item_token":item_token,
            "destination":destination,
        }))?;
        if response.get("ok").and_then(Value::as_bool) != Some(true) {
            return Err(response
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("Raiun could not confirm Save Copy")
                .to_owned());
        }
        validate_protected_copy_receipt(&response, expected_body_length)?;
        Ok(json!({"saved":true,"body_length":expected_body_length}))
    })
    .await
    .map_err(|_| "The protected recovery Save Copy worker stopped unexpectedly".to_string())?
}

async fn save_local_edit_copy(
    app: AppHandle,
    profile_id: Option<String>,
    space_id: String,
    root_resource_id: Option<(String, u64, String)>,
    write_id: String,
    suggested_name: Option<String>,
) -> Result<Value, String> {
    if space_id.is_empty() || space_id.len() > 1024 {
        return Err("The selected Space is invalid".into());
    }
    if write_id.is_empty()
        || write_id.len() > 32
        || !write_id.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("The selected conflict is invalid".into());
    }
    let suggested_name = suggested_name
        .as_deref()
        .and_then(|name| {
            let path = std::path::Path::new(name);
            let base = path.file_name()?.to_str()?;
            (!base.is_empty()
                && base.len() <= 255
                && base != "."
                && base != ".."
                && !base.chars().any(char::is_control))
            .then(|| base.to_owned())
        })
        .unwrap_or_else(|| "saved-edit-copy".into());
    let dialog_app = app.clone();
    let selected = tauri::async_runtime::spawn_blocking(move || {
        use tauri_plugin_dialog::DialogExt;
        dialog_app
            .dialog()
            .file()
            .set_title("Save a local copy of the saved edit")
            .set_file_name(suggested_name)
            .blocking_save_file()
            .map(|path| {
                path.into_path()
                    .map_err(|_| "The selected location is not a local file path".to_owned())
            })
            .transpose()
    })
    .await
    .map_err(|_| "The Save dialog worker stopped unexpectedly".to_string())??;
    let Some(destination) = selected else {
        return Ok(json!({"cancelled": true}));
    };
    let mut message = json!({
        "action": "cache_conflict_export",
        "space_id": space_id,
        "write_id": write_id,
        "destination_path": destination,
    });
    if let Some((root_resource_id, expected_generation, expected_account_scope)) = root_resource_id
    {
        message["expected_generation"] = json!(expected_generation);
        message["expected_account_scope"] = json!(expected_account_scope);
        message["action"] = json!("cache_saved_write_export");
        message["root_resource_id"] = json!(root_resource_id);
    }
    if let Some(profile_id) = profile_id {
        message["profile_id"] = json!(profile_id);
    }
    let response = tauri::async_runtime::spawn_blocking(move || request_agent(message))
        .await
        .map_err(|_| "The conflict-copy request worker stopped unexpectedly".to_string())??;
    if response.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(response
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("Raiun could not save the conflict copy")
            .to_owned());
    }
    Ok(response.get("data").cloned().unwrap_or_else(|| json!({})))
}

fn diagnostics_agent_data(response: Value) -> Result<Value, String> {
    if response.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err("The local agent could not prepare this diagnostics report".into());
    }
    response
        .get("data")
        .filter(|data| data.is_object())
        .cloned()
        .ok_or_else(|| "The local agent returned an invalid diagnostics response".into())
}

#[tauri::command]
async fn export_diagnostics(app: AppHandle, profile_id: String) -> Result<Value, String> {
    if !valid_unlock_profile_id(&profile_id) {
        return Err("The selected account is invalid".into());
    }
    tauri::async_runtime::spawn_blocking(move || {
        use tauri_plugin_dialog::DialogExt;
        let before = diagnostics_agent_data(request_agent(json!({"action":"accounts"}))?)?;
        if before.get("selected").and_then(Value::as_str) != Some(profile_id.as_str()) {
            return Err("The selected account changed. Choose the report again.".to_string());
        }
        let selected = app
            .dialog()
            .file()
            .set_title("Export redacted Raiun diagnostics")
            .set_file_name("raiun-diagnostics.json")
            .blocking_save_file()
            .map(|path| {
                path.into_path().map_err(|_| {
                    "Choose a local file location for the diagnostics report".to_owned()
                })
            })
            .transpose()?;
        let Some(destination) = selected else {
            return Ok(json!({"cancelled": true}));
        };
        let after_dialog = diagnostics_agent_data(request_agent(json!({"action":"accounts"}))?)?;
        if after_dialog.get("selected").and_then(Value::as_str) != Some(profile_id.as_str()) {
            return Err("The selected account changed. Choose the report again.".to_string());
        }
        let report = diagnostics_agent_data(request_agent(
            json!({"action":"diagnostics","profile_id":profile_id}),
        )?)?;
        let bytes = sanitize_diagnostics_report(&report)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(destination).map_err(|_| {
            "Could not create the diagnostics file. Choose a new local file path.".to_string()
        })?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| "Could not write the diagnostics file".to_string())?;
        Ok(json!({"exported": true}))
    })
    .await
    .map_err(|_| "The diagnostics export worker stopped unexpectedly".to_string())?
}

fn has_exact_keys(value: &Value, keys: &[&str]) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
}

fn safe_diagnostic_count(value: &Value, optional: bool) -> Result<Value, String> {
    if optional && value.is_null() {
        return Ok(Value::Null);
    }
    let count = value
        .as_u64()
        .filter(|count| *count <= 1_000_000)
        .ok_or_else(|| "The agent returned an invalid diagnostics count".to_string())?;
    Ok(json!(count))
}

// Export only bounded public release-version syntax, not arbitrary text from
// an agent response. A mismatched older agent is useful diagnostic information.
fn safe_diagnostic_version(value: &Value) -> Result<String, String> {
    let text = value
        .as_str()
        .filter(|text| text.len() <= 64)
        .ok_or("The agent returned invalid diagnostics metadata")?;
    let version = semver::Version::parse(text)
        .map_err(|_| "The agent returned invalid diagnostics metadata")?;
    let pre = version.pre.as_str();
    let public_pre = pre.is_empty()
        || ["alpha.", "beta.", "rc."].iter().any(|prefix| {
            pre.strip_prefix(prefix).is_some_and(|number| {
                !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
            })
        });
    if !version.build.is_empty() || !public_pre {
        return Err("The agent returned invalid diagnostics metadata".into());
    }
    Ok(text.to_owned())
}

fn sanitize_diagnostics_report(value: &Value) -> Result<Vec<u8>, String> {
    if !has_exact_keys(
        value,
        &[
            "schema_version",
            "app_version",
            "target_os",
            "target_arch",
            "profile_scope",
            "profile_count",
            "profile_config",
            "runtime",
        ],
    ) || value.get("schema_version").and_then(Value::as_u64) != Some(1)
        || value.get("profile_scope").and_then(Value::as_str) != Some("selected_profile")
    {
        return Err("The agent returned an unsupported diagnostics report".into());
    }
    let agent_version = safe_diagnostic_version(&value["app_version"])?;
    if value["target_os"].as_str() != Some(std::env::consts::OS)
        || value["target_arch"].as_str() != Some(std::env::consts::ARCH)
    {
        return Err("The agent returned invalid diagnostics metadata".into());
    }
    let profile_count = safe_diagnostic_count(&value["profile_count"], false)?;
    if profile_count.as_u64().is_none_or(|count| count > 16) {
        return Err("The agent returned an invalid diagnostics count".into());
    }
    let config = &value["profile_config"];
    if !has_exact_keys(
        config,
        &[
            "parse_valid",
            "folder_pair_count",
            "mode_counts",
            "vault_pair_count",
        ],
    ) {
        return Err("The agent returned an unsupported diagnostics report".into());
    }
    let parse_valid = match config.get("parse_valid") {
        Some(Value::Bool(value)) => json!(value),
        Some(Value::Null) => Value::Null,
        _ => return Err("The agent returned invalid diagnostics metadata".into()),
    };
    let folder_pair_count = safe_diagnostic_count(&config["folder_pair_count"], true)?;
    let vault_pair_count = safe_diagnostic_count(&config["vault_pair_count"], true)?;
    let mode_counts = if config["mode_counts"].is_null() {
        Value::Null
    } else {
        let modes = &config["mode_counts"];
        if !has_exact_keys(modes, &["two_way", "upload_only", "download_only"]) {
            return Err("The agent returned invalid diagnostics metadata".into());
        }
        json!({
            "two_way": safe_diagnostic_count(&modes["two_way"], false)?,
            "upload_only": safe_diagnostic_count(&modes["upload_only"], false)?,
            "download_only": safe_diagnostic_count(&modes["download_only"], false)?,
        })
    };
    let runtime = &value["runtime"];
    // Windows adds a cleanup extension. It is deliberately omitted from the
    // public report, whose projection remains the three reviewed safe fields.
    if !(has_exact_keys(runtime, &["connected", "mounted", "sync_paused"])
        || has_exact_keys(
            runtime,
            &["connected", "mounted", "sync_paused", "vault_cleanup"],
        ))
        || !runtime["connected"].is_boolean()
        || !runtime["mounted"].is_boolean()
        || (!runtime["sync_paused"].is_boolean() && !runtime["sync_paused"].is_null())
    {
        return Err("The agent returned invalid diagnostics metadata".into());
    }
    let report = json!({
        "schema_version": 1,
        "app_version": env!("CARGO_PKG_VERSION"),
        "agent_version": agent_version,
        "target_os": std::env::consts::OS,
        "target_arch": std::env::consts::ARCH,
        "profile_scope": "selected_profile",
        "profile_count": profile_count,
        "profile_config": {
            "parse_valid": parse_valid,
            "folder_pair_count": folder_pair_count,
            "mode_counts": mode_counts,
            "vault_pair_count": vault_pair_count,
        },
        "runtime": {
            "connected": runtime["connected"],
            "mounted": runtime["mounted"],
            "sync_paused": runtime["sync_paused"],
        },
    });
    let mut bytes = serde_json::to_vec_pretty(&report)
        .map_err(|_| "Could not encode redacted diagnostics".to_string())?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[tauri::command]
async fn open_cloud_folder(app: AppHandle, profile_id: Option<String>) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        let mut message = json!({"action": "status"});
        if let Some(profile_id) = profile_id {
            message["profile_id"] = json!(profile_id);
        }
        let response = request_agent(message)?;
        if response.get("ok").and_then(Value::as_bool) != Some(true) {
            return Err(response
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("The Raiun agent rejected this request")
                .to_owned());
        }
        let path = response
            .pointer("/data/cloud_root")
            .and_then(Value::as_str)
            .ok_or_else(|| "Raiun has not configured a cloud folder yet".to_string())?;
        app.opener()
            .open_path(path, None::<&str>)
            .map_err(|error| format!("Could not open the cloud folder: {error}"))
    })
    .await
    .map_err(|_| "The cloud folder request worker stopped unexpectedly".to_string())?
}

#[tauri::command]
async fn open_recovery_folder(app: AppHandle, profile_id: Option<String>) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        let mut message = json!({"action": "status"});
        if let Some(profile_id) = profile_id {
            message["profile_id"] = json!(profile_id);
        }
        let response = request_agent(message)?;
        let path = response
            .pointer("/data/recovery_folder")
            .and_then(Value::as_str)
            .ok_or("Sign in before opening saved upload copies")?;
        if !std::path::Path::new(path).is_dir() {
            return Err("There are no saved upload copies yet".into());
        }
        app.opener()
            .open_path(path, None::<&str>)
            .map_err(|e| format!("Could not open saved upload copies: {e}"))
    })
    .await
    .map_err(|_| "Recovery folder worker stopped unexpectedly".to_owned())?
}

#[tauri::command]
async fn open_encrypted_edit_recovery_folder(
    app: AppHandle,
    profile_id: Option<String>,
) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        let mut message = json!({"action": "encrypted_edit_recovery_folder"});
        if let Some(profile_id) = profile_id {
            message["profile_id"] = json!(profile_id);
        }
        let response = request_agent(message)?;
        let path = response
            .pointer("/data/path")
            .and_then(Value::as_str)
            .ok_or("There are no saved encrypted-file edits yet")?;
        let path = std::path::Path::new(path);
        if !path.is_dir() {
            return Err("The saved encrypted-file edits folder is unavailable".into());
        }
        app.opener()
            .open_path(path.to_string_lossy().into_owned(), None::<&str>)
            .map_err(|_| "Could not open the saved encrypted-file edits folder".to_owned())
    })
    .await
    .map_err(|_| "Saved encrypted-file edits folder worker stopped unexpectedly".to_owned())?
}

#[tauri::command]
async fn request(app: AppHandle, message: Value) -> Result<Value, String> {
    let message = AgentRequest {
        value: message,
        contains_secret: true,
    };
    let action = message
        .get("action")
        .and_then(Value::as_str)
        .ok_or_else(|| "Request must include a string action".to_string())?
        .to_owned();
    if message.get("password").is_some()
        || matches!(action.as_str(), "vault_unlock" | "vault_create")
    {
        return Err("Vault password requests must use the dedicated secret command".into());
    }
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    let should_ensure_agent = action != "shutdown";
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    let shell_app = app.clone();
    let response = tauri::async_runtime::spawn_blocking(move || {
        // The status/retry path can recover an agent that exited after the
        // initial setup attempt. The process mutex and endpoint recheck inside
        // this method serialize concurrent UI requests and avoid duplicates.
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        if should_ensure_agent {
            let state = shell_app
                .try_state::<ShellState>()
                .ok_or_else(|| "Raiun Desktop process state is unavailable".to_string())?;
            state.start_agent_if_socket_absent()?;
        }
        request_agent_guarded(message)
    })
    .await
    .map_err(|_| "The local Raiun agent request worker stopped unexpectedly".to_string())??;

    if response.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(response
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("The Raiun agent rejected this request")
            .to_owned());
    }

    if action == "auth_begin" {
        let returned_url = response
            .get("data")
            .and_then(|data| data.get("url"))
            .and_then(Value::as_str)
            .ok_or_else(|| "The agent did not return a sign-in URL".to_string())?;
        let parsed = url::Url::parse(returned_url)
            .map_err(|_| "The agent returned an invalid sign-in URL".to_string())?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return Err(
                "The agent returned an unsafe sign-in URL; expected a verified HTTPS URL".into(),
            );
        }
        app.opener()
            .open_url(parsed.as_str(), None::<&str>)
            .map_err(|error| format!("Could not open the sign-in page: {error}"))?;
    }
    if matches!(
        action.as_str(),
        "pause"
            | "sync_now"
            | "logout"
            | "account_select"
            | "account_add"
            | "configure"
            | "mount"
            | "unmount"
    ) {
        // The window action handler refreshes its own UI after this request.
        // Update the tray label without emitting a duplicate window refresh.
        update_tray_status(&app, false);
    }
    Ok(response.get("data").cloned().unwrap_or(Value::Null))
}

/// Secret-bearing vault requests use a dedicated IPC path and wipe the local
/// JSON string and encoded socket buffer as soon as they have been sent.
#[tauri::command]
async fn vault_secret(message: Value) -> Result<Value, String> {
    let message = validate_vault_secret_request(message)?;
    tauri::async_runtime::spawn_blocking(move || request_agent_guarded(message))
        .await
        .map_err(|_| "Vault secret request worker stopped unexpectedly".to_owned())?
        .and_then(|response| {
            if response.get("ok").and_then(Value::as_bool) != Some(true) {
                return Err(response
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("The agent rejected the vault request")
                    .to_owned());
            }
            Ok(response.get("data").cloned().unwrap_or(Value::Null))
        })
}

fn validate_vault_secret_request(message: Value) -> Result<AgentRequest, String> {
    // Mark the request secret-bearing before any fallible validation. This
    // ensures rejected passwords take the same zeroizing Drop path as sent
    // requests.
    let message = AgentRequest {
        value: message,
        contains_secret: true,
    };
    let action = message
        .get("action")
        .and_then(Value::as_str)
        .ok_or_else(|| "Vault request must include a string action".to_string())?;
    if !matches!(
        action,
        "vault_unlock" | "vault_unlock_offline" | "vault_create"
    ) {
        return Err("Only vault unlock, offline unlock, and create may use secret IPC".into());
    }

    let use_saved = message
        .get("use_saved")
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| "use_saved must be a boolean".to_string())
        })
        .transpose()?
        .unwrap_or(false);
    let password = message.get("password");
    if use_saved {
        if action == "vault_create" {
            return Err("A saved key cannot be used to create a vault".into());
        }
        if password.is_some() {
            return Err("A password cannot be combined with use_saved".into());
        }
    } else {
        let password = password
            .and_then(Value::as_str)
            .ok_or_else(|| "Vault password is missing".to_string())?;
        if password.is_empty() || password.len() > 4096 {
            return Err("Vault password is empty or too long".into());
        }
    }

    Ok(message)
}

fn request_agent(message: Value) -> Result<Value, String> {
    request_agent_guarded(AgentRequest {
        value: message,
        contains_secret: false,
    })
}

struct AgentRequest {
    value: Value,
    contains_secret: bool,
}

impl std::ops::Deref for AgentRequest {
    type Target = Value;
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl std::ops::DerefMut for AgentRequest {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.value
    }
}

impl AgentRequest {
    fn wipe_password(&mut self) {
        if self.contains_secret {
            wipe_request_password(&mut self.value);
            self.contains_secret = false;
        }
    }
}

impl Drop for AgentRequest {
    fn drop(&mut self) {
        self.wipe_password();
    }
}

fn wipe_request_password(message: &mut Value) {
    if let Some(Value::String(password)) = message.get_mut("password") {
        password.zeroize();
    }
}

fn request_agent_guarded(mut message: AgentRequest) -> Result<Value, String> {
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    let contains_secret = message.contains_secret;
    let action = message.get("action").and_then(Value::as_str).unwrap_or("");
    let _status_guard = if action == "status" {
        Some(
            STATUS_REQUEST_LOCK
                .lock()
                .map_err(|_| "Raiun status request lock is poisoned".to_string())?,
        )
    } else {
        None
    };
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::net::UnixStream;
        let socket = socket_path()?;
        let mut stream = UnixStream::connect(&socket).map_err(|error| {
            format!(
                "Raiun agent is not running (could not connect to {}): {error}",
                socket.display()
            )
        })?;
        let action = message.get("action").and_then(Value::as_str).unwrap_or("");
        stream
            .set_read_timeout(if agent_action_waits_for_completion(action) {
                // Shutdown drains writes and unmounts; Space pause waits for an
                // active folder sync to finish before acknowledging the pause.
                // A short IPC timeout could report failure while either continues.
                None
            } else {
                Some(agent_response_timeout(action))
            })
            .map_err(|error| format!("Could not set agent response timeout: {error}"))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .map_err(|error| format!("Could not set agent request timeout: {error}"))?;
        let mut encoded = encode_json_line(&message.value)
            .map_err(|error| format!("Could not encode agent request: {error}"))?;
        message.wipe_password();
        stream
            .write_all(&encoded)
            .map_err(|error| format!("Could not send request to Raiun agent: {error}"))?;
        if contains_secret {
            encoded.zeroize();
        }
        let response = read_json_line(&mut stream)
            .map_err(|error| format!("Could not read Raiun agent response: {error}"))?;
        serde_json::from_slice(&response)
            .map_err(|error| format!("Raiun agent returned invalid JSON: {error}"))
    }
    #[cfg(target_os = "windows")]
    {
        use raiun_control_windows::connect_current_user;
        let timeout = if agent_action_waits_for_completion(action) {
            Duration::from_secs(300)
        } else {
            agent_response_timeout(action)
        };
        let mut stream = connect_current_user(timeout)
            .map_err(|error| format!("Could not connect to the Raiun agent pipe: {error}"))?;
        let mut encoded = Zeroizing::new(
            encode_json_line(&message.value)
                .map_err(|error| format!("Could not encode agent request: {error}"))?,
        );
        message.wipe_password();
        stream
            .write_all(&encoded)
            .map_err(|error| format!("Could not send request to Raiun agent: {error}"))?;
        if !contains_secret {
            encoded.zeroize();
        }
        let response = read_json_line(&mut stream)
            .map_err(|error| format!("Could not read Raiun agent response: {error}"))?;
        serde_json::from_slice(&response)
            .map_err(|error| format!("Raiun agent returned invalid JSON: {error}"))
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Err("Raiun Desktop control IPC is currently supported on Linux and Windows only".into())
    }
}

#[cfg(target_os = "linux")]
fn socket_path() -> Result<std::path::PathBuf, String> {
    use std::path::PathBuf;
    if let Some(state_dir) = std::env::var_os("RAIUN_STATE_DIR") {
        return Ok(PathBuf::from(state_dir).join("control.sock"));
    }
    if let Some(state_home) = std::env::var_os("XDG_STATE_HOME") {
        return Ok(PathBuf::from(state_home)
            .join("raiun-desktop")
            .join("control.sock"));
    }
    let home = std::env::var_os("HOME")
        .ok_or_else(|| "Neither RAIUN_STATE_DIR, XDG_STATE_HOME nor HOME is set".to_string())?;
    Ok(PathBuf::from(home).join(".local/state/raiun-desktop/control.sock"))
}

fn show_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
        if let Some(state) = app.try_state::<ShellState>() {
            state.main_window_open.store(true, Ordering::Release);
        }
        return;
    }
    let preferences = load_window_preferences(app).unwrap_or_default();
    let (width, height) = restored_window_size(&preferences);
    if tauri::WebviewWindowBuilder::new(app, "main", tauri::WebviewUrl::App("index.html".into()))
        .title("Raiun Desktop")
        .inner_size(width as f64, height as f64)
        .min_inner_size(MIN_WINDOW_SIZE.0 as f64, MIN_WINDOW_SIZE.1 as f64)
        .center()
        .maximized(preferences.maximized)
        .build()
        .is_ok()
        && let Some(state) = app.try_state::<ShellState>()
    {
        state.main_window_open.store(true, Ordering::Release);
    }
}

#[derive(Default)]
struct WindowPreferences {
    width: Option<u32>,
    height: Option<u32>,
    maximized: bool,
}

fn window_preferences_path(app: &AppHandle) -> Option<std::path::PathBuf> {
    app.path()
        .app_config_dir()
        .ok()
        .map(|path| path.join("window.json"))
}

fn load_window_preferences(app: &AppHandle) -> Option<WindowPreferences> {
    let bytes = std::fs::read(window_preferences_path(app)?).ok()?;
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    Some(WindowPreferences {
        width: value
            .get("width")
            .and_then(Value::as_u64)
            .map(|size| size as u32),
        height: value
            .get("height")
            .and_then(Value::as_u64)
            .map(|size| size as u32),
        maximized: value
            .get("maximized")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

fn save_window_preferences(window: &tauri::Window) {
    let Some(path) = window_preferences_path(window.app_handle()) else {
        return;
    };
    let Ok(size) = window.inner_size() else {
        return;
    };
    let scale_factor = window.scale_factor().unwrap_or(1.0);
    let maximized = window.is_maximized().unwrap_or(false);
    let existing = load_window_preferences(window.app_handle()).unwrap_or_default();
    let preferences = WindowPreferences {
        width: if maximized {
            existing.width
        } else {
            Some((size.width as f64 / scale_factor).round() as u32)
        },
        height: if maximized {
            existing.height
        } else {
            Some((size.height as f64 / scale_factor).round() as u32)
        },
        maximized,
    };
    let Some(parent) = path.parent() else {
        return;
    };
    if std::fs::create_dir_all(parent).is_err() {
        return;
    }
    let temporary = path.with_extension("json.tmp");
    if let Ok(bytes) = serde_json::to_vec(&json!({
        "width": preferences.width,
        "height": preferences.height,
        "maximized": preferences.maximized,
    })) && std::fs::write(&temporary, bytes).is_ok()
        && std::fs::rename(&temporary, &path).is_err()
    {
        let _ = std::fs::copy(&temporary, &path);
        let _ = std::fs::remove_file(temporary);
    }
}

fn restore_window_preferences(window: &tauri::WebviewWindow) {
    let Some(preferences) = load_window_preferences(window.app_handle()) else {
        return;
    };
    let (width, height) = restored_window_size(&preferences);
    let _ = window.set_size(tauri::Size::Logical(tauri::LogicalSize {
        width: width as f64,
        height: height as f64,
    }));
    if preferences.maximized {
        let _ = window.maximize();
    }
}

fn restored_window_size(preferences: &WindowPreferences) -> (u32, u32) {
    (
        preferences
            .width
            .unwrap_or(DEFAULT_WINDOW_SIZE.0)
            .max(MIN_WINDOW_SIZE.0),
        preferences
            .height
            .unwrap_or(DEFAULT_WINDOW_SIZE.1)
            .max(MIN_WINDOW_SIZE.1),
    )
}

fn close_window_to_tray(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let webview: &tauri::Webview = window.as_ref();
        save_window_preferences(&webview.window());
        // Release the WebView when no window is visible. The tray and agent
        // remain alive; reopening restores the saved window geometry.
        let _ = window.destroy();
    }
    if let Some(state) = app.try_state::<ShellState>() {
        state.main_window_open.store(false, Ordering::Release);
    }
}

fn tray_request(action: &str, args: Value) -> Result<Value, String> {
    let mut message = json!({"action": action});
    if let (Some(object), Some(extra)) = (message.as_object_mut(), args.as_object()) {
        object.extend(extra.clone());
    }
    request_agent(message)
}

fn tray_action(action: &str, args: Value) -> Result<Value, String> {
    let response = tray_request(action, args)?;
    if response.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(response
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("Raiun rejected the tray action")
            .to_owned());
    }
    Ok(response.get("data").cloned().unwrap_or(Value::Null))
}

fn update_tray_status(app: &AppHandle, notify_ui: bool) {
    let app = app.clone();
    let revision = app
        .try_state::<ShellState>()
        .map(|state| state.tray_status_revision.fetch_add(1, Ordering::AcqRel) + 1);
    tauri::async_runtime::spawn_blocking(move || {
        let response = tray_request("status", Value::Null);
        if let (Some(revision), Some(state)) = (revision, app.try_state::<ShellState>())
            && state.tray_status_revision.load(Ordering::Acquire) != revision
        {
            return;
        }
        let available = response
            .as_ref()
            .is_ok_and(|value| value.get("ok").and_then(Value::as_bool) == Some(true));
        let data = response.as_ref().ok().and_then(|value| value.get("data"));
        let has_error = data
            .and_then(|value| value.get("error"))
            .is_some_and(|value| !value.is_null());
        let connected = data
            .and_then(|value| value.get("connected"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let paused = data
            .and_then(|value| value.get("paused"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let label = tray_status_label(available, has_error, connected, paused);
        let account = data
            .and_then(|value| value.get("profile_label"))
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(str::to_owned)
            .or_else(|| {
                data.and_then(|value| value.get("server"))
                    .and_then(Value::as_str)
                    .and_then(|server| url::Url::parse(server).ok())
                    .and_then(|url| url.host_str().map(str::to_owned))
            });
        let label = account.map_or_else(|| label.to_owned(), |name| format!("{label} · {name}"));
        if let Some(item) = app.try_state::<MenuItem<tauri::Wry>>() {
            let _ = item.set_text(label);
        }
        if let Some(items) = app.try_state::<TrayMenuState>() {
            let (pause_busy, sync_busy) = app
                .try_state::<ShellState>()
                .map(|state| {
                    (
                        state.pause_action_busy.load(Ordering::Acquire),
                        state.sync_action_busy.load(Ordering::Acquire),
                    )
                })
                .unwrap_or_default();
            let _ = items.pause.set_text(if pause_busy {
                "Updating sync…"
            } else {
                lifecycle::tray_pause_menu_label(paused)
            });
            let _ = items
                .pause
                .set_enabled(available && connected && !pause_busy);
            let _ = items.sync.set_enabled(available && connected && !sync_busy);
        }
        if notify_ui {
            let _ = app.emit("raiun:status-changed", json!({"source":"tray"}));
        }
    });
}

fn emit_tray_action(app: &AppHandle, action: &str, phase: &str) {
    let _ = app.emit(
        "raiun:status-changed",
        json!({"source":"tray", "action":action, "phase":phase}),
    );
}

#[derive(Clone, Copy)]
enum TrayGlyph {
    Folder,
    Transfers,
    Power,
}

fn tray_item_icon(glyph: TrayGlyph, color: [u8; 4]) -> tauri::image::Image<'static> {
    let mut pixels = vec![0_u8; 16 * 16 * 4];
    for y in 2..14 {
        for x in 2..14 {
            let dx = x as f32 - 7.5;
            let dy = y as f32 - 7.5;
            let radius = (dx * dx + dy * dy).sqrt();
            let on = match glyph {
                TrayGlyph::Folder => {
                    (y == 6 && (2..=13).contains(&x))
                        || ((7..=12).contains(&y) && (2..=13).contains(&x))
                        || (y == 5 && (3..=7).contains(&x))
                }
                TrayGlyph::Transfers => {
                    (y == 5 && (3..=11).contains(&x))
                        || (x == 10 && (3..=7).contains(&y))
                        || (x == 9 && (4..=6).contains(&y))
                        || (x == 11 && (4..=6).contains(&y))
                        || (y == 10 && (4..=12).contains(&x))
                        || (x == 5 && (8..=12).contains(&y))
                        || (x == 4 && (9..=11).contains(&y))
                        || (x == 6 && (9..=11).contains(&y))
                }
                TrayGlyph::Power => {
                    ((5.0..=6.0).contains(&radius) && !((6..=9).contains(&x) && y <= 4))
                        || ((7..=8).contains(&x) && (2..=8).contains(&y))
                }
            };
            if !on {
                continue;
            }
            let index = (y * 16 + x) * 4;
            pixels[index..index + 4].copy_from_slice(&color);
        }
    }
    tauri::image::Image::new_owned(pixels, 16, 16)
}

fn run_pause_action(app: &AppHandle) {
    if let Some(state) = app.try_state::<ShellState>()
        && state.pause_action_busy.swap(true, Ordering::AcqRel)
    {
        return;
    }
    if let Some(items) = app.try_state::<TrayMenuState>() {
        let _ = items.pause.set_text("Updating sync…");
        let _ = items.pause.set_enabled(false);
    }
    emit_tray_action(app, "pause", "working");
    let app = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let result = (|| {
            let status = tray_request("status", Value::Null)?;
            let paused = status
                .pointer("/data/paused")
                .and_then(Value::as_bool)
                .ok_or_else(|| "Raiun did not report the sync state".to_string())?;
            let profile_id = status
                .pointer("/data/profile_id")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .ok_or_else(|| "Raiun did not report the selected account".to_string())?;
            tray_action(
                "pause",
                json!({"profile_id": profile_id, "paused": !paused}),
            )
        })();
        emit_tray_action(
            &app,
            "pause",
            if result.is_ok() { "complete" } else { "failed" },
        );
        if let Some(state) = app.try_state::<ShellState>() {
            state.pause_action_busy.store(false, Ordering::Release);
        }
        if let Err(error) = result {
            report_tray_error(&app, format!("Could not change sync state: {error}"));
        }
        update_tray_status(&app, true);
    });
}

fn run_sync_action(app: &AppHandle) {
    if let Some(state) = app.try_state::<ShellState>()
        && state.sync_action_busy.swap(true, Ordering::AcqRel)
    {
        return;
    }
    if let Some(items) = app.try_state::<TrayMenuState>() {
        let _ = items.sync.set_text("Syncing…");
        let _ = items.sync.set_enabled(false);
    }
    emit_tray_action(app, "sync", "working");
    let app = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let result = (|| {
            let status = tray_request("status", Value::Null)?;
            let profile_id = status
                .pointer("/data/profile_id")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .ok_or_else(|| "Raiun did not report the selected account".to_string())?;
            tray_action("sync_now", json!({"profile_id": profile_id}))
        })();
        if let Some(items) = app.try_state::<TrayMenuState>() {
            let _ = items.sync.set_text(if result.is_ok() {
                "Sync requested"
            } else {
                "Sync failed · retry"
            });
        }
        emit_tray_action(
            &app,
            "sync",
            if result.is_ok() { "accepted" } else { "failed" },
        );
        if let Err(error) = &result {
            report_tray_error(&app, format!("Could not request sync: {error}"));
        }
        if result.is_ok() {
            update_tray_status(&app, true);
            std::thread::sleep(Duration::from_secs(3));
            if let Some(items) = app.try_state::<TrayMenuState>() {
                let _ = items.sync.set_text(lifecycle::TRAY_SYNC_IDLE_LABEL);
            }
        }
        if let Some(state) = app.try_state::<ShellState>() {
            state.sync_action_busy.store(false, Ordering::Release);
        }
        update_tray_status(&app, result.is_err());
    });
}

fn run_quit_action(app: &AppHandle) {
    let Some(state) = app.try_state::<ShellState>() else {
        report_tray_error(app, "Raiun Desktop process state is unavailable".into());
        return;
    };
    match state.begin_agent_shutdown() {
        Ok(true) => {}
        Ok(false) => return,
        Err(error) => {
            report_tray_error(app, error);
            return;
        }
    }
    if let Some(items) = app.try_state::<TrayMenuState>() {
        let _ = items.quit.set_enabled(false);
        let _ = items.quit.set_text("Stopping sync…");
    }
    emit_tray_action(app, "quit", "working");
    stop_tray_status_poller(app);
    let app = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let result = (|| {
            let response = tray_action("shutdown", Value::Null)?;
            if response.get("stopping").and_then(Value::as_bool) != Some(true) {
                return Err("Raiun did not confirm that shutdown started".to_string());
            }
            wait_for_agent_socket_removal()?;
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            wait_for_owned_agent_exit(&app, false)?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                emit_tray_action(&app, "quit", "complete");
                if let Some(state) = app.try_state::<ShellState>()
                    && let Ok(mut tray) = state.tray.lock()
                {
                    tray.take();
                }
                app.exit(0);
            }
            Err(error) => {
                if let Some(state) = app.try_state::<ShellState>() {
                    // Shutdown failed only after the socket/process state was
                    // rechecked. Allow a later explicit retry to contact it.
                    state.clear_agent_shutdown_after_failure();
                }
                if let Some(items) = app.try_state::<TrayMenuState>() {
                    let _ = items.quit.set_text("Quit failed · retry");
                    let _ = items.quit.set_enabled(true);
                }
                emit_tray_action(&app, "quit", "failed");
                report_tray_error(&app, error);
                update_tray_status(&app, true);
                start_tray_status_poller(&app);
            }
        }
    });
}

#[tauri::command]
async fn install_desktop_update(app: AppHandle) -> Result<(), String> {
    let install_app = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _update_busy = desktop_updates::begin_install(&install_app)?;
        let update_state = install_app
            .try_state::<desktop_updates::DesktopUpdateState>()
            .ok_or_else(|| "Desktop update settings are unavailable".to_string())?;
        let _update_transition = update_state.lock_transition()?;
        let (update, bytes, _tag) = desktop_updates::cached_for_install(&install_app)?;
        let state = install_app
            .try_state::<ShellState>()
            .ok_or_else(|| "Raiun Desktop process state is unavailable".to_string())?;
        state.begin_agent_update_shutdown()?;
        stop_tray_status_poller(&install_app);
        let stop_result = (|| {
            let response = tray_action("shutdown", Value::Null)?;
            if response.get("stopping").and_then(Value::as_bool) != Some(true) {
                return Err("Raiun did not confirm that shutdown started".to_string());
            }
            wait_for_agent_socket_removal()?;
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            wait_for_owned_agent_exit(&install_app, true)?;
            Ok(())
        })();
        if let Err(error) = stop_result {
            state.clear_agent_shutdown_after_failure();
            start_tray_status_poller(&install_app);
            return Err(format!(
                "Raiun could not stop safely; the update was not started: {error}"
            ));
        }

        match update.install(bytes) {
            Ok(()) => {
                #[cfg(target_os = "linux")]
                {
                    install_app.restart()
                }
                #[cfg(windows)]
                {
                    Ok(())
                }
                #[cfg(not(any(target_os = "linux", target_os = "windows")))]
                {
                    Err("Desktop updates are supported on Linux and Windows only".into())
                }
            }
            Err(error) => {
                state.clear_agent_shutdown_after_failure();
                start_tray_status_poller(&install_app);
                Err(format!(
                    "The signed Desktop update could not be installed: {error}"
                ))
            }
        }
    })
    .await
    .map_err(|_| "The Desktop update installer worker stopped unexpectedly".to_string())?
}

#[cfg(target_os = "linux")]
fn wait_for_agent_socket_removal() -> Result<(), String> {
    use std::os::unix::net::UnixStream;

    let socket = socket_path()?;
    for _ in 0..150 {
        if !socket.exists() && UnixStream::connect(&socket).is_err() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err("Raiun acknowledged shutdown but its control socket remained active".into())
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn require_owned_agent<T>(process: Option<&mut T>) -> Result<&mut T, String> {
    process.ok_or_else(|| {
        "Raiun Desktop does not own a provable agent process; the update was not started".into()
    })
}

fn validate_owned_agent_exit(
    status: std::process::ExitStatus,
    require_success: bool,
) -> Result<(), String> {
    if require_success && !status.success() {
        return Err(format!(
            "Raiun agent exited unsuccessfully ({status}); the update was not started"
        ));
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn wait_for_owned_agent_exit(app: &AppHandle, require_success: bool) -> Result<(), String> {
    let Some(state) = app.try_state::<ShellState>() else {
        return Err("Raiun process state is unavailable; agent exit cannot be proven".into());
    };
    let mut agent = state
        .agent
        .lock()
        .map_err(|_| "Raiun agent process state is unavailable".to_string())?;
    let child = require_owned_agent(agent.as_mut())?;
    for _ in 0..150 {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("Could not confirm Raiun agent exit: {error}"))?
        {
            *agent = None;
            return validate_owned_agent_exit(status, require_success);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err("Raiun unmounted its drive but the agent process did not exit".into())
}

#[cfg(windows)]
fn wait_for_agent_socket_removal() -> Result<(), String> {
    use raiun_control_windows::connect_current_user;
    for _ in 0..150 {
        match connect_current_user(Duration::from_millis(100)) {
            Ok(_) => std::thread::sleep(Duration::from_millis(100)),
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => return Ok(()),
            Err(error) => return Err(format!("Could not confirm Raiun agent shutdown: {error}")),
        }
    }
    Err("Raiun acknowledged shutdown but its control pipe remained active".into())
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn wait_for_agent_socket_removal() -> Result<(), String> {
    Err("Agent shutdown confirmation is currently supported on Linux and Windows only".into())
}

fn start_tray_status_poller(app: &AppHandle) {
    let (stop, receiver) = mpsc::channel();
    if let Some(state) = app.try_state::<ShellState>()
        && let Ok(mut slot) = state.tray_status_stop.lock()
    {
        *slot = Some(stop);
    }
    update_tray_status(app, true);
    let app = app.clone();
    std::thread::spawn(move || tray_status_poll_loop(&app, receiver));
}

fn tray_status_poll_loop(app: &AppHandle, stop: Receiver<()>) {
    loop {
        match stop.recv_timeout(TRAY_STATUS_POLL_INTERVAL) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => break,
            Err(RecvTimeoutError::Timeout) => update_tray_status(app, true),
        }
    }
}

fn stop_tray_status_poller(app: &AppHandle) {
    if let Some(state) = app.try_state::<ShellState>()
        && let Ok(mut slot) = state.tray_status_stop.lock()
        && let Some(stop) = slot.take()
    {
        let _ = stop.send(());
    }
}

fn main() {
    let launch_args = std::env::args().skip(1).collect::<Vec<_>>();
    let background_launch = has_background_argument(&launch_args);
    let initial_unlock_intent = launch_args.iter().find_map(|arg| parse_unlock_intent(arg));
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            if args.iter().any(|arg| parse_unlock_intent(arg).is_some()) {
                queue_unlock_intent(app, &args);
            } else if !has_background_argument(&args) {
                show_window(app);
            }
        }))
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(desktop_updates::updater_plugin())
        .invoke_handler(tauri::generate_handler![request, vault_secret, save_conflict_copy, save_saved_edit_copy, save_protected_vault_capture_copy, export_diagnostics, open_cloud_folder, open_recovery_folder, open_encrypted_edit_recovery_folder, take_shell_error, take_shell_navigation, take_shell_unlock_intent, preview_media_scan, desktop_updates::desktop_update_status, desktop_updates::set_desktop_update_preferences, desktop_updates::dismiss_desktop_update, desktop_updates::open_desktop_release, desktop_updates::check_desktop_update, desktop_updates::download_desktop_update, install_desktop_update])
        .on_window_event(|window, event| {
            if window.label() != "main" {
                return;
            }
            match event {
                tauri::WindowEvent::CloseRequested { api, .. } => {
                    let tray_available = window
                        .app_handle()
                        .try_state::<ShellState>()
                        .is_some_and(|state| state.tray_available.load(Ordering::Acquire));
                    api.prevent_close();
                    if tray_available {
                        close_window_to_tray(window.app_handle());
                    } else {
                        run_quit_action(window.app_handle());
                    }
                }
                tauri::WindowEvent::Resized(_) => save_window_preferences(window),
                tauri::WindowEvent::Destroyed => {
                    if let Some(state) = window.app_handle().try_state::<ShellState>() {
                        state.main_window_open.store(false, Ordering::Release);
                    }
                }
                _ => {}
            }
        })
        .setup(move |app| {
            let state = ShellState::default();
            if let Some(intent) = initial_unlock_intent.clone()
                && let Ok(mut pending) = state.pending_unlock_intent.lock()
            {
                *pending = Some(intent);
            }
            if let Err(error) = state.start_agent_if_socket_absent() {
                eprintln!("Raiun agent startup: {error}");
            }
            app.manage(state);
            app.manage(desktop_updates::DesktopUpdateState::load(app.handle()));
            if let Some(window) = app.get_webview_window("main") {
                restore_window_preferences(&window);
            }

            let status =
                MenuItem::with_id(app, "status", "Status · Checking…", false, None::<&str>)?;
            app.manage(status.clone());
            let open = IconMenuItem::with_id(app, "open", "Open Raiun", true, Some(tray_logo_image()), None::<&str>)?;
            let folders = IconMenuItem::with_id(app, "folders", "Synced Folders", true, Some(tray_item_icon(TrayGlyph::Folder, [81, 129, 73, 255])), None::<&str>)?;
            let transfers = IconMenuItem::with_id(app, "transfers", "Transfers", true, Some(tray_item_icon(TrayGlyph::Transfers, [92, 111, 168, 255])), None::<&str>)?;
            let pause = MenuItem::with_id(app, "pause", "Pause sync", true, None::<&str>)?;
            let sync = MenuItem::with_id(
                app,
                "sync",
                lifecycle::TRAY_SYNC_IDLE_LABEL,
                true,
                None::<&str>,
            )?;
            let quit = IconMenuItem::with_id(app, "quit", "Quit Raiun", true, Some(tray_item_icon(TrayGlyph::Power, [177, 69, 68, 255])), None::<&str>)?;
            app.manage(TrayMenuState {
                pause: pause.clone(),
                sync: sync.clone(),
                quit: quit.clone(),
            });
            let menu = Menu::with_items(
                app,
                &[
                    &status, &open, &folders, &transfers, &pause, &sync, &quit,
                ],
            )?;
            let icon = tray_logo_image();
            let tray = TrayIconBuilder::new()
                .icon(icon)
                .tooltip("Raiun Desktop")
                .menu(&menu)
                .on_menu_event(move |app, event| {
                    match event.id().as_ref() {
                        "status" => update_tray_status(app, true),
                        "open" => show_window(app),
                        "folders" => navigate_window(app, "folders"),
                        "transfers" => navigate_window(app, "transfers"),
                        "pause" => run_pause_action(app),
                        "sync" => run_sync_action(app),
                        "quit" => run_quit_action(app),
                        _ => {}
                    }
                    update_tray_status(app, true);
                })
                .on_tray_icon_event(move |tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        show_window(tray.app_handle());
                    }
                })
                .build(app);
            let tray_available = match tray {
                Ok(tray) => {
                    if let Some(state) = app.try_state::<ShellState>()
                        && let Ok(mut stored_tray) = state.tray.lock()
                    {
                        *stored_tray = Some(tray);
                        state.tray_available.store(true, Ordering::Release);
                    }
                    true
                }
                Err(error) => {
                    eprintln!("System tray is unavailable; closing the window will exit Raiun Desktop: {error}");
                    false
                }
            };
            if should_show_initial_window(background_launch, tray_available) {
                show_window(app.handle());
            }
            if tray_available {
                start_tray_status_poller(app.handle());
            }
            Ok(())
        });

    match builder.build(tauri::generate_context!()) {
        Ok(app) => app.run(|app, event| match event {
            tauri::RunEvent::ExitRequested { code, api, .. } => {
                let tray_available = app
                    .try_state::<ShellState>()
                    .is_some_and(|state| state.tray_available.load(Ordering::Acquire));
                if should_prevent_exit(code, tray_available) {
                    api.prevent_exit();
                }
            }
            tauri::RunEvent::Exit => stop_tray_status_poller(app),
            _ => {}
        }),
        Err(error) => eprintln!("Raiun Desktop could not start: {error}"),
    }
}

fn tray_pixels() -> Vec<u8> {
    include_bytes!("../icons/tray.rgba").to_vec()
}

fn tray_logo_image() -> tauri::image::Image<'static> {
    tauri::image::Image::new_owned(tray_pixels(), 32, 32)
}

#[cfg(test)]
mod shell_tests {
    use super::{
        DEFAULT_WINDOW_SIZE, MIN_WINDOW_SIZE, WindowPreferences, diagnostics_agent_data,
        parse_unlock_intent, require_owned_agent, restored_window_size,
        sanitize_diagnostics_report, validate_protected_copy_receipt,
        validate_protected_recovery_binding, validate_selected_profile,
        validate_vault_secret_request,
    };
    use serde_json::json;

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[test]
    fn update_shutdown_requires_a_shell_owned_agent_handle() {
        use super::ShellState;
        use std::sync::atomic::Ordering;

        let mut no_process: Option<u8> = None;
        assert!(require_owned_agent(no_process.as_mut()).is_err());

        let mut owned_process = Some(7_u8);
        assert_eq!(*require_owned_agent(owned_process.as_mut()).unwrap(), 7);

        let shell = ShellState::default();
        assert!(shell.begin_agent_update_shutdown().is_err());
        assert!(!shell.shutting_down.load(Ordering::Acquire));
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn updater_requires_a_successful_owned_agent_exit() {
        use super::validate_owned_agent_exit;
        use std::process::Command;

        #[cfg(target_os = "linux")]
        let mut successful_child = Command::new("sh")
            .args(["-c", "exit 0"])
            .spawn()
            .expect("spawn successful synthetic child");
        #[cfg(windows)]
        let mut successful_child = Command::new("cmd")
            .args(["/C", "exit 0"])
            .spawn()
            .expect("spawn successful synthetic child");
        let successful_status = successful_child.wait().expect("wait for child");
        assert!(successful_status.success());
        assert!(validate_owned_agent_exit(successful_status, true).is_ok());

        #[cfg(target_os = "linux")]
        let mut unsuccessful_child = Command::new("sh")
            .args(["-c", "exit 1"])
            .spawn()
            .expect("spawn unsuccessful synthetic child");
        #[cfg(windows)]
        let mut unsuccessful_child = Command::new("cmd")
            .args(["/C", "exit 1"])
            .spawn()
            .expect("spawn unsuccessful synthetic child");
        let unsuccessful_status = unsuccessful_child.wait().expect("wait for child");
        assert!(!unsuccessful_status.success());
        let error = validate_owned_agent_exit(unsuccessful_status, true)
            .expect_err("installer must not run after failed agent shutdown");
        assert!(error.contains("exited unsuccessfully"));

        #[cfg(target_os = "linux")]
        let mut ordinary_quit_child = Command::new("sh")
            .args(["-c", "exit 1"])
            .spawn()
            .expect("spawn ordinary quit child");
        #[cfg(windows)]
        let mut ordinary_quit_child = Command::new("cmd")
            .args(["/C", "exit 1"])
            .spawn()
            .expect("spawn ordinary quit child");
        let ordinary_status = ordinary_quit_child.wait().expect("wait for child");
        assert!(validate_owned_agent_exit(ordinary_status, false).is_ok());
    }

    fn protected_recovery_status() -> serde_json::Value {
        json!({
            "ok": true,
            "data": {
                "profile_id": "default",
                "connected": true,
                "auth_generation": 7,
                "root_configuration": {
                    "valid": true,
                    "identity_bound": true,
                    "registration_state": "registered",
                    "recovery_scope_token": "b".repeat(64)
                }
            }
        })
    }

    #[test]
    fn protected_copy_requires_the_exact_live_registered_root_binding() {
        validate_protected_recovery_binding(
            protected_recovery_status(),
            "default",
            7,
            &"b".repeat(64),
        )
        .expect("matching current registered root is valid");

        for (field, value) in [
            ("profile_id", json!("profile-".to_owned() + &"c".repeat(32))),
            ("connected", json!(false)),
            ("auth_generation", json!(8)),
        ] {
            let mut response = protected_recovery_status();
            response["data"][field] = value;
            assert!(
                validate_protected_recovery_binding(response, "default", 7, &"b".repeat(64))
                    .is_err()
            );
        }
        for (field, value) in [
            ("valid", json!(false)),
            ("identity_bound", json!(false)),
            ("registration_state", json!("prepared_not_registered")),
            ("recovery_scope_token", json!("c".repeat(64))),
        ] {
            let mut response = protected_recovery_status();
            response["data"]["root_configuration"][field] = value;
            assert!(
                validate_protected_recovery_binding(response, "default", 7, &"b".repeat(64))
                    .is_err()
            );
        }
    }

    #[test]
    fn protected_copy_requires_selected_profile_to_remain_current() {
        validate_selected_profile(json!({"ok":true,"data":{"selected":"default"}}), "default")
            .expect("selected account matches");
        assert!(
            validate_selected_profile(json!({"ok":true,"data":{"selected":"other"}}), "default")
                .is_err()
        );
        assert!(
            validate_selected_profile(json!({"ok":false,"data":{"selected":"default"}}), "default")
                .is_err()
        );
    }

    #[test]
    fn protected_copy_receipt_must_confirm_exact_body_length_and_read_only_shape() {
        validate_protected_copy_receipt(
            &json!({"ok":true,"data":{"schema_version":1,"body_length":17,"read_only":true}}),
            17,
        )
        .expect("exact read-only receipt matches the selected row");
        for response in [
            json!({"ok":true,"data":{"schema_version":1,"body_length":18,"read_only":true}}),
            json!({"ok":true,"data":{"schema_version":1,"body_length":17,"read_only":false}}),
            json!({"ok":true,"data":{"schema_version":1,"body_length":17,"read_only":true,"destination":"private-path"}}),
        ] {
            assert!(validate_protected_copy_receipt(&response, 17).is_err());
        }
    }

    #[cfg(target_os = "linux")]
    struct SidecarTestCleanup {
        state: std::sync::Arc<super::ShellState>,
        root: std::path::PathBuf,
    }

    #[cfg(target_os = "linux")]
    impl Drop for SidecarTestCleanup {
        fn drop(&mut self) {
            if let Ok(mut process) = self.state.agent.lock() {
                if let Some(child) = process.as_mut() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                *process = None;
            }
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn diagnostic_fixture() -> serde_json::Value {
        json!({
            "schema_version": 1,
            "app_version": env!("CARGO_PKG_VERSION"),
            "target_os": std::env::consts::OS,
            "target_arch": std::env::consts::ARCH,
            "profile_scope": "selected_profile",
            "profile_count": 2,
            "profile_config": {
                "parse_valid": true,
                "folder_pair_count": 3,
                "mode_counts": {"two_way": 1, "upload_only": 1, "download_only": 1},
                "vault_pair_count": 1,
            },
            "runtime": {"connected": false, "mounted": true, "sync_paused": false},
        })
    }

    #[test]
    fn diagnostics_agent_envelope_is_unwrapped_before_profile_and_report_checks() {
        let data =
            diagnostics_agent_data(json!({"ok":true,"data":{"selected":"default"}})).unwrap();
        assert_eq!(data["selected"], "default");
        for response in [
            json!({"selected":"default"}),
            json!({"ok":false,"data":{"selected":"default"},"error":"private server detail"}),
            json!({"ok":true,"data":null}),
            json!({"ok":true,"data":[{"selected":"default"}]}),
        ] {
            let error = diagnostics_agent_data(response).unwrap_err();
            assert!(!error.contains("private server detail"));
        }
    }

    #[test]
    fn diagnostics_export_strictly_allowlists_safe_selected_profile_fields() {
        let report = sanitize_diagnostics_report(&diagnostic_fixture()).unwrap();
        let text = String::from_utf8(report).unwrap();
        assert!(text.contains("\"profile_scope\": \"selected_profile\""));
        assert!(text.contains("\"folder_pair_count\": 3"));
        assert!(text.contains("\"connected\": false"));
        assert!(!text.contains("profile-"));
        assert!(!text.contains("server.example"));

        let mut expanded = diagnostic_fixture();
        expanded["private_path"] = json!("CANARY_PRIVATE_PATH");
        assert!(sanitize_diagnostics_report(&expanded).is_err());
        assert!(
            !sanitize_diagnostics_report(&expanded)
                .unwrap_err()
                .contains("CANARY_PRIVATE_PATH")
        );
    }

    #[test]
    fn diagnostics_export_preserves_unknown_pause_and_older_agent_version() {
        let mut fixture = diagnostic_fixture();
        fixture["app_version"] = json!("0.7.0-beta.2");
        fixture["runtime"]["sync_paused"] = serde_json::Value::Null;
        let report: serde_json::Value =
            serde_json::from_slice(&sanitize_diagnostics_report(&fixture).unwrap()).unwrap();
        assert_eq!(report["app_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(report["agent_version"], "0.7.0-beta.2");
        assert!(report["runtime"]["sync_paused"].is_null());
        assert_eq!(report["runtime"]["connected"], false);
        fixture["runtime"]["sync_paused"] = json!("CANARY_PRIVATE_VALUE");
        assert!(sanitize_diagnostics_report(&fixture).is_err());
    }

    #[test]
    fn diagnostics_export_accepts_windows_disconnected_shape_without_copying_cleanup_data() {
        let mut fixture = diagnostic_fixture();
        fixture["app_version"] = json!("0.7.0-beta.3");
        fixture["profile_config"] = json!({"parse_valid":null,"folder_pair_count":null,"mode_counts":null,"vault_pair_count":null});
        fixture["runtime"] = json!({"connected":false,"mounted":false,"sync_paused":null,"vault_cleanup":{"private_path":"CANARY_PRIVATE_PATH","token":"CANARY_SECRET_TOKEN"}});
        let bytes = sanitize_diagnostics_report(&fixture).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(!text.contains("CANARY"));
        assert!(!text.contains("vault_cleanup"));
        let report: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(report["agent_version"], "0.7.0-beta.3");
        assert!(report["runtime"]["sync_paused"].is_null());
        fixture["runtime"]["unexpected_secret"] = json!("CANARY_SECRET");
        assert!(sanitize_diagnostics_report(&fixture).is_err());
    }

    #[test]
    fn diagnostics_version_rejects_arbitrary_private_strings_and_build_metadata() {
        for version in [
            "CANARY_PRIVATE_PATH",
            "0.7.4+CANARY_PRIVATE_VALUE",
            "0.7.4-CANARY_PRIVATE_VALUE",
            "https://private.example.test",
        ] {
            let mut fixture = diagnostic_fixture();
            fixture["app_version"] = json!(version);
            let error = sanitize_diagnostics_report(&fixture).unwrap_err();
            assert!(!error.contains("CANARY"));
            assert!(!error.contains("private.example"));
        }
    }

    #[test]
    fn diagnostics_export_rejects_invalid_counts_and_untrusted_platform_metadata() {
        let mut report = diagnostic_fixture();
        report["profile_config"]["folder_pair_count"] = json!(1_000_001);
        assert!(sanitize_diagnostics_report(&report).is_err());
        let mut report = diagnostic_fixture();
        report["target_arch"] = json!("CANARY_SECRET_PATH");
        assert!(sanitize_diagnostics_report(&report).is_err());
        assert!(
            !sanitize_diagnostics_report(&report)
                .unwrap_err()
                .contains("CANARY_SECRET_PATH")
        );
        let mut report = diagnostic_fixture();
        report["profile_count"] = json!(17);
        assert!(sanitize_diagnostics_report(&report).is_err());
    }

    #[test]
    fn reopened_window_uses_saved_size_and_preserves_maximized_state() {
        let prefs = WindowPreferences {
            width: Some(1280),
            height: Some(840),
            maximized: true,
        };
        assert_eq!(restored_window_size(&prefs), (1280, 840));
        assert!(prefs.maximized);
    }

    #[test]
    fn restored_window_size_uses_defaults_and_enforces_minimums() {
        assert_eq!(
            restored_window_size(&WindowPreferences::default()),
            DEFAULT_WINDOW_SIZE
        );
        assert_eq!(
            restored_window_size(&WindowPreferences {
                width: Some(300),
                height: Some(200),
                maximized: false,
            }),
            MIN_WINDOW_SIZE
        );
    }

    #[test]
    fn pathless_unlock_link_parses_bounded_identity_hints() {
        let intent = parse_unlock_intent(
            "raiun://unlock?v=1&profile_id=default&space_id=space%2Fid&root_resource_id=root-1",
        )
        .unwrap();
        assert_eq!(intent.profile_id, "default");
        assert_eq!(intent.space_id, "space/id");
        assert_eq!(intent.root_resource_id, "root-1");
    }

    #[test]
    fn unlock_link_rejects_unknown_duplicate_path_and_secret_fields() {
        for uri in [
            "raiun://unlock?v=1&profile_id=default&space_id=s&root_resource_id=r&extra=x",
            "raiun://unlock?v=1&profile_id=default&profile_id=default&space_id=s&root_resource_id=r",
            "raiun://unlock/private?v=1&profile_id=default&space_id=s&root_resource_id=r",
            "raiun://unlock/..?v=1&profile_id=default&space_id=s&root_resource_id=r",
            "raiun://unlock/%2e%2e?v=1&profile_id=default&space_id=s&root_resource_id=r",
            "raiun://unlock?v=1&profile_id=default&space_id=s&root_resource_id=r&password=secret",
            "https://unlock?v=1&profile_id=default&space_id=s&root_resource_id=r",
            "raiun://user@unlock?v=1&profile_id=default&space_id=s&root_resource_id=r",
            "raiun://unlock?v=1&profile_id=default&space_id=s&root_resource_id=r#fragment",
        ] {
            assert!(parse_unlock_intent(uri).is_none(), "accepted {uri}");
        }
    }

    #[test]
    fn unlock_link_rejects_unknown_profiles_and_oversized_hints() {
        assert!(
            parse_unlock_intent(
                "raiun://unlock?v=1&profile_id=not-a-profile&space_id=s&root_resource_id=r"
            )
            .is_none()
        );
        let huge = "x".repeat(1025);
        let uri =
            format!("raiun://unlock?v=1&profile_id=default&space_id={huge}&root_resource_id=r");
        assert!(parse_unlock_intent(&uri).is_none());
        assert!(parse_unlock_intent(&format!("raiun://unlock?{}", "x".repeat(4097))).is_none());
    }

    #[test]
    fn secret_ipc_allows_saved_key_only_for_explicit_online_or_offline_unlock() {
        for action in ["vault_unlock", "vault_unlock_offline"] {
            let request = validate_vault_secret_request(json!({
                "action": action,
                "use_saved": true,
                "profile_id": "default",
                "space_id": "space-test",
                "root_resource_id": "root-test"
            }))
            .unwrap();
            assert!(request.contains_secret);
            assert_eq!(
                request.get("action").and_then(serde_json::Value::as_str),
                Some(action)
            );
            assert_eq!(
                request
                    .get("use_saved")
                    .and_then(serde_json::Value::as_bool),
                Some(true)
            );
            assert!(request.get("password").is_none());
        }

        for message in [
            json!({"action":"vault_unlock"}),
            json!({"action":"vault_unlock_offline", "use_saved":false}),
            json!({"action":"vault_unlock", "use_saved":"true"}),
            json!({"action":"vault_unlock", "use_saved":true, "password":"secret"}),
            json!({"action":"vault_create", "use_saved":true}),
            json!({"action":"vault_forget", "use_saved":true}),
        ] {
            assert!(validate_vault_secret_request(message).is_err());
        }
    }

    #[test]
    fn secret_ipc_keeps_password_unlock_and_create_on_secret_bearing_path() {
        for action in ["vault_unlock", "vault_unlock_offline", "vault_create"] {
            let request = validate_vault_secret_request(json!({
                "action": action,
                "password": "synthetic-test-password",
                "profile_id": "default",
                "space_id": "space-test",
                "root_resource_id": "root-test"
            }))
            .unwrap();
            assert!(request.contains_secret);
            assert_eq!(
                request.get("password").and_then(serde_json::Value::as_str),
                Some("synthetic-test-password")
            );
        }

        assert!(
            validate_vault_secret_request(json!({
                "action":"vault_unlock",
                "password":""
            }))
            .is_err()
        );
        assert!(
            validate_vault_secret_request(json!({
                "action":"vault_create",
                "password":"x".repeat(4097)
            }))
            .is_err()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn failed_agent_startup_is_reported_and_reaped_for_a_later_retry() {
        use super::wait_for_linux_agent;
        use std::process::Command;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        let socket = std::env::temp_dir().join(format!(
            "raiun-shell-retry-{}-{nonce}.sock",
            std::process::id()
        ));
        let mut child = Some(
            Command::new("sh")
                .args(["-c", "sleep 0.05; exit 7"])
                .spawn()
                .expect("spawn synthetic exiting child"),
        );

        let error = wait_for_linux_agent(&socket, &mut child).expect_err("startup must fail");
        assert!(error.contains("exited before its control socket"));
        assert!(error.contains("status exit status: 7"));
        assert!(
            child.is_none(),
            "exited children must be reaped before retry"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn quit_latch_waits_for_start_guard_and_prevents_respawn_while_draining() {
        use super::ShellState;
        use std::sync::{Arc, mpsc};
        use std::time::Duration;

        let state = Arc::new(ShellState::default());
        let process_guard = state.agent.lock().expect("agent process lock");
        let worker_state = Arc::clone(&state);
        let (attempted_tx, attempted_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            attempted_tx.send(()).expect("signal shutdown attempt");
            result_tx
                .send(worker_state.begin_agent_shutdown())
                .expect("send shutdown result");
        });

        attempted_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("shutdown attempt started");
        assert!(matches!(
            result_rx.recv_timeout(Duration::from_millis(25)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        drop(process_guard);
        assert!(
            result_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("shutdown completes after start guard releases")
                .expect("shutdown latch is available")
        );
        worker.join().expect("shutdown worker");

        let retry = state.start_agent_if_socket_absent();
        assert!(retry.is_err());
        assert!(retry.unwrap_err().contains("is shutting down"));
        assert!(state.agent.lock().expect("agent process lock").is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn retry_restarts_failed_sidecar_then_reuses_live_socket() {
        use super::ShellState;
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("raiun-shell-retry-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&root).expect("create isolated sidecar directory");
        let state = std::sync::Arc::new(ShellState::default());
        let _cleanup = SidecarTestCleanup {
            state: std::sync::Arc::clone(&state),
            root: root.clone(),
        };
        let socket = root.join("agent.sock");
        let first_start_marker = root.join("first-start");
        let executable = root.join("raiun-agent");
        let script = format!(
            "#!/bin/sh\nMARKER='{}'\nSOCKET='{}'\nif [ ! -e \"$MARKER\" ]; then : > \"$MARKER\"; exit 17; fi\nexec python3 - \"$SOCKET\" <<'PY'\nimport socket, sys\ns = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\ns.bind(sys.argv[1])\ns.listen(4)\nwhile True:\n    connection, _ = s.accept()\n    connection.close()\nPY\n",
            first_start_marker.display(),
            socket.display()
        );
        std::fs::write(&executable, script).expect("write synthetic sidecar");
        let mut permissions = std::fs::metadata(&executable)
            .expect("synthetic sidecar metadata")
            .permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&executable, permissions).expect("make sidecar executable");

        let first = state.start_agent_at(&socket, || Ok(executable.clone()));
        assert!(first.is_err(), "the first synthetic launch must fail");
        assert!(
            first_start_marker.is_file(),
            "the first launch was attempted"
        );
        assert!(state.agent.lock().expect("agent process lock").is_none());

        state
            .start_agent_at(&socket, || Ok(executable.clone()))
            .expect("retry should start the sidecar");
        assert!(socket.exists(), "successful retry publishes the socket");
        let running_pid = state
            .agent
            .lock()
            .expect("agent process lock")
            .as_ref()
            .expect("owned sidecar child")
            .id();

        state
            .start_agent_at(&socket, || panic!("live endpoint must not resolve/spawn"))
            .expect("a live endpoint should be reused");
        assert_eq!(
            state
                .agent
                .lock()
                .expect("agent process lock")
                .as_ref()
                .expect("same owned sidecar child")
                .id(),
            running_pid,
            "retry must not duplicate a live sidecar"
        );
    }
}
