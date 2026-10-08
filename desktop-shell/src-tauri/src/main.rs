#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod lifecycle;

#[cfg(target_os = "linux")]
use lifecycle::sibling_agent_path;
use lifecycle::{
    agent_response_timeout, has_background_argument, should_prevent_exit,
    should_show_initial_window, tray_status_label,
};
use serde_json::{Value, json};
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::time::Duration;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_opener::OpenerExt;

const MAX_MESSAGE: usize = 1024 * 1024;
const TRAY_STATUS_POLL_INTERVAL: Duration = Duration::from_secs(15);
static STATUS_REQUEST_LOCK: Mutex<()> = Mutex::new(());

#[derive(Default)]
struct ShellState {
    #[cfg(target_os = "linux")]
    agent: Mutex<Option<Child>>,
    tray: Mutex<Option<tauri::tray::TrayIcon<tauri::Wry>>>,
    tray_available: AtomicBool,
    main_window_open: AtomicBool,
    tray_status_stop: Mutex<Option<Sender<()>>>,
}

impl ShellState {
    #[cfg(target_os = "linux")]
    fn start_agent_if_socket_absent(&self) -> Result<(), String> {
        use std::os::unix::net::UnixStream;

        let socket = socket_path()?;
        if UnixStream::connect(&socket).is_ok() {
            return Ok(());
        }

        let mut process = self
            .agent
            .lock()
            .map_err(|_| "Raiun process state is unavailable".to_string())?;
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
        for _ in 0..40 {
            if UnixStream::connect(&socket).is_ok() {
                break;
            }
            if let Some(child) = process.as_mut() {
                if let Some(status) = child.try_wait().map_err(|error| {
                    format!("Could not inspect the Raiun agent process: {error}")
                })? {
                    return Err(format!(
                        "Raiun agent exited during startup with status {status}"
                    ));
                }
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn start_agent_if_socket_absent(&self) -> Result<(), String> {
        Err("Raiun Desktop agent startup is currently supported on Linux only".into())
    }
}

#[tauri::command]
async fn open_cloud_folder(app: AppHandle) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        let response = request_agent(json!({"action": "status"}))?;
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
async fn open_recovery_folder(app: AppHandle) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        let response = request_agent(json!({"action": "status"}))?;
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
async fn request(app: AppHandle, message: Value) -> Result<Value, String> {
    let action = message
        .get("action")
        .and_then(Value::as_str)
        .ok_or_else(|| "Request must include a string action".to_string())?
        .to_owned();
    let response = tauri::async_runtime::spawn_blocking(move || request_agent(message))
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
    Ok(response.get("data").cloned().unwrap_or(Value::Null))
}

fn request_agent(message: Value) -> Result<Value, String> {
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
            .set_read_timeout(Some(agent_response_timeout(action)))
            .map_err(|error| format!("Could not set agent response timeout: {error}"))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .map_err(|error| format!("Could not set agent request timeout: {error}"))?;
        let mut encoded = serde_json::to_vec(&message)
            .map_err(|error| format!("Could not encode agent request: {error}"))?;
        if encoded.len() > MAX_MESSAGE {
            return Err("Agent request exceeds the 1 MiB message limit".into());
        }
        encoded.push(b'\n');
        stream
            .write_all(&encoded)
            .map_err(|error| format!("Could not send request to Raiun agent: {error}"))?;
        let mut response = Vec::with_capacity(4096);
        let mut chunk = [0_u8; 8192];
        loop {
            let read = stream
                .read(&mut chunk)
                .map_err(|error| format!("Could not read Raiun agent response: {error}"))?;
            if read == 0 {
                break;
            }
            let newline = chunk[..read].iter().position(|byte| *byte == b'\n');
            let available = newline.unwrap_or(read);
            if response.len() + available > MAX_MESSAGE {
                return Err("Raiun agent response exceeds the 1 MiB message limit".into());
            }
            response.extend_from_slice(&chunk[..available]);
            if newline.is_some() {
                break;
            }
        }
        serde_json::from_slice(&response)
            .map_err(|error| format!("Raiun agent returned invalid JSON: {error}"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = message;
        Err("Raiun Desktop control IPC is currently supported on Linux only".into())
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
    if tauri::WebviewWindowBuilder::new(app, "main", tauri::WebviewUrl::App("index.html".into()))
        .title("Raiun Desktop")
        .inner_size(920.0, 680.0)
        .min_inner_size(700.0, 560.0)
        .center()
        .build()
        .is_ok()
    {
        if let Some(state) = app.try_state::<ShellState>() {
            state.main_window_open.store(true, Ordering::Release);
        }
    }
}

fn tray_request(action: &str, args: Value) -> Result<Value, String> {
    let mut message = json!({"action": action});
    if let (Some(object), Some(extra)) = (message.as_object_mut(), args.as_object()) {
        object.extend(extra.clone());
    }
    request_agent(message)
}

fn update_tray_status(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let response = tray_request("status", Value::Null);
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
        if let Some(item) = app.try_state::<MenuItem<tauri::Wry>>() {
            let _ = item.set_text(label);
        }
    });
}

fn start_tray_status_poller(app: &AppHandle) {
    let (stop, receiver) = mpsc::channel();
    if let Some(state) = app.try_state::<ShellState>()
        && let Ok(mut slot) = state.tray_status_stop.lock()
    {
        *slot = Some(stop);
    }
    update_tray_status(app);
    let app = app.clone();
    std::thread::spawn(move || tray_status_poll_loop(&app, receiver));
}

fn tray_status_poll_loop(app: &AppHandle, stop: Receiver<()>) {
    loop {
        match stop.recv_timeout(TRAY_STATUS_POLL_INTERVAL) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => break,
            Err(RecvTimeoutError::Timeout) => update_tray_status(app),
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

fn open_remote_or_local(app: &AppHandle, kind: &str) {
    let app = app.clone();
    let kind = kind.to_owned();
    tauri::async_runtime::spawn_blocking(move || {
        let Ok(response) = tray_request("status", Value::Null) else {
            show_window(&app);
            return;
        };
        if response.get("ok").and_then(Value::as_bool) != Some(true) {
            show_window(&app);
            return;
        }
        let Some(data) = response.get("data") else {
            show_window(&app);
            return;
        };
        if kind == "folder" {
            if let Some(path) = data.get("cloud_root").and_then(Value::as_str) {
                let _ = app.opener().open_path(path, None::<&str>);
            } else {
                show_window(&app);
            }
        } else if let Some(server) = data.get("server").and_then(Value::as_str) {
            if url::Url::parse(server)
                .is_ok_and(|url| url.scheme() == "https" && url.host_str().is_some())
            {
                let _ = app.opener().open_url(server, None::<&str>);
            } else {
                show_window(&app);
            }
        } else {
            show_window(&app);
        }
    });
}

fn main() {
    let background_launch = has_background_argument(&std::env::args().skip(1).collect::<Vec<_>>());
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            if !has_background_argument(&args) {
                show_window(app);
            }
        }))
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![request, open_cloud_folder, open_recovery_folder])
        .on_window_event(|window, event| {
            if window.label() == "main" && matches!(event, tauri::WindowEvent::Destroyed) {
                if let Some(state) = window.app_handle().try_state::<ShellState>() {
                    state.main_window_open.store(false, Ordering::Release);
                }
            }
        })
        .setup(move |app| {
            let state = ShellState::default();
            if let Err(error) = state.start_agent_if_socket_absent() {
                eprintln!("Raiun agent startup: {error}");
            }
            app.manage(state);

            let status =
                MenuItem::with_id(app, "status", "Status · Checking…", false, None::<&str>)?;
            app.manage(status.clone());
            let open = MenuItem::with_id(app, "open", "Open Raiun Desktop", true, None::<&str>)?;
            let folders = MenuItem::with_id(app, "folders", "Sync folders", true, None::<&str>)?;
            let transfers = MenuItem::with_id(app, "transfers", "Transfers", true, None::<&str>)?;
            let pause = MenuItem::with_id(app, "pause", "Pause sync", true, None::<&str>)?;
            let sync = MenuItem::with_id(app, "sync", "Sync now", true, None::<&str>)?;
            let cloud = MenuItem::with_id(app, "cloud", "Open cloud folder", true, None::<&str>)?;
            let web = MenuItem::with_id(app, "web", "Open OpenCloud", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit Raiun Desktop (agent continues)", true, None::<&str>)?;
            let menu = Menu::with_items(
                app,
                &[
                    &status, &open, &folders, &transfers, &pause, &sync, &cloud, &web, &quit,
                ],
            )?;
            let rgba = tray_pixels();
            let icon = tauri::image::Image::new_owned(rgba, 32, 32);
            let tray = TrayIconBuilder::new()
                .icon(icon)
                .tooltip("Raiun Desktop")
                .menu(&menu)
                .on_menu_event(move |app, event| {
                    match event.id().as_ref() {
                        "status" => update_tray_status(app),
                        "open" => show_window(app),
                        "folders" => {
                            show_window(app);
                            if let Some(window) = app.get_webview_window("main") {
                                let _ = window.emit("navigate", "folders");
                            }
                        }
                        "transfers" => {
                            show_window(app);
                            if let Some(window) = app.get_webview_window("main") {
                                let _ = window.emit("navigate", "transfers");
                            }
                        }
                        "pause" => {
                            tauri::async_runtime::spawn_blocking(|| {
                                if let Ok(status) = tray_request("status", Value::Null) {
                                    let paused = status
                                        .pointer("/data/paused")
                                        .and_then(Value::as_bool)
                                        .unwrap_or(false);
                                    let _ = tray_request("pause", json!({"paused": !paused}));
                                }
                            });
                        }
                        "sync" => {
                            tauri::async_runtime::spawn_blocking(|| {
                                let _ = tray_request("sync_now", Value::Null);
                            });
                        }
                        "cloud" => open_remote_or_local(app, "folder"),
                        "web" => open_remote_or_local(app, "web"),
                        "quit" => app.exit(0),
                        _ => {}
                    }
                    update_tray_status(app);
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
                    if let Some(state) = app.try_state::<ShellState>() {
                        if let Ok(mut stored_tray) = state.tray.lock() {
                            *stored_tray = Some(tray);
                            state.tray_available.store(true, Ordering::Release);
                        }
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
    let mut pixels = vec![0_u8; 32 * 32 * 4];
    for y in 0..32 {
        for x in 0..32 {
            let dx = x as f32 - 15.5;
            let dy = y as f32 - 15.5;
            let distance = (dx * dx + dy * dy).sqrt();
            if distance <= 14.0 {
                let index = (y * 32 + x) * 4;
                let crest = x > 8 && x < 23 && y > 5 && y < 25 && (y < 18 || x > 11 && x < 20);
                let color = if crest {
                    [246, 248, 250, 255]
                } else {
                    [0, 103, 127, 255]
                };
                pixels[index..index + 4].copy_from_slice(&color);
            }
        }
    }
    pixels
}
