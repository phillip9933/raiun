//! Per-user control socket and scheduler for the desktop engine.
mod auth;
mod autostart;
mod storage;

use clap::{Parser, Subcommand};
use raiun_core::{FolderPair, backend::CloudBackend, validate_config};
use raiun_engine::{Engine, SyncReport};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use storage::Settings;

const MAX_SOCKET_MESSAGE: usize = 1_048_576;
const MAX_SOCKET_RESPONSE: usize = 1_048_576;

struct AuthState {
    engine: Option<Engine>,
    session: Option<auth::Session>,
    client: Option<raiun_opencloud::OpenCloudClient>,
    account_id: Option<String>,
    session_unsaved: bool,
}

trait MountedCloud: Send {
    fn unmount(&mut self) -> Result<(), String>;
    fn is_mounted(&self) -> bool;
}

impl MountedCloud for raiun_fuse::MountHandle {
    fn unmount(&mut self) -> Result<(), String> {
        raiun_fuse::MountHandle::unmount(self)
    }

    fn is_mounted(&self) -> bool {
        raiun_fuse::MountHandle::is_mounted(self)
    }
}

trait SessionStore: Send + Sync {
    fn save(&self, session: &auth::Session) -> Result<(), String>;
    fn load(&self, server: &str, client_id: &str) -> Result<Option<auth::Session>, String>;
}

struct SecretServiceStore;

impl SessionStore for SecretServiceStore {
    fn save(&self, session: &auth::Session) -> Result<(), String> {
        auth::save_session(session)
    }

    fn load(&self, server: &str, client_id: &str) -> Result<Option<auth::Session>, String> {
        auth::load_session(server, client_id)
    }
}

#[derive(Clone, serde::Serialize)]
struct PairSyncStatus {
    report: SyncReport,
    message: Option<String>,
    updated_at: u64,
}

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Serve,
    Request { message: String },
}

struct Runtime {
    dir: PathBuf,
    settings: Mutex<Settings>,
    auth_state: Mutex<AuthState>,
    error: Mutex<Option<String>>,
    refresh_error: Mutex<Option<String>>,
    pair_reports: Mutex<BTreeMap<String, PairSyncStatus>>,
    wake: AtomicBool,
    mount: Mutex<Option<Box<dyn MountedCloud>>>,
    authenticating: AtomicBool,
    restoring: AtomicBool,
    shutdown: AtomicBool,
    session_store: Arc<dyn SessionStore>,
}
impl Runtime {
    fn install_session(&self, session: auth::Session) -> Result<(), String> {
        let client =
            raiun_opencloud::OpenCloudClient::new(&session.server, session.access_token.clone())
                .map_err(|e| e.to_string())?;
        let spaces = client
            .spaces()
            .map_err(|error| auth::graph_error_with_issuer_hint(&error.to_string(), &session))?;
        let personal: Vec<_> = spaces.iter().filter(|space| space.personal).collect();
        if personal.len() != 1 || personal[0].id.trim().is_empty() {
            return Err("The server did not identify exactly one personal drive".into());
        }
        if !personal[0].writable || personal[0].encrypted {
            return Err("The personal drive is read-only or encrypted and cannot be synced".into());
        }
        let account_id = account_identity(&session.server, &personal[0].id);
        let engine_dir = account_engine_dir(&self.dir, &account_id);
        let engine =
            Engine::open(&engine_dir, Arc::new(client.clone())).map_err(|e| e.to_string())?;

        // Lock order is settings -> auth_state -> mount. The other paths read
        // each lock separately, so sign-in cannot expose a mixed account.
        let mut settings = self.settings.lock().map_err(|_| "Settings poisoned")?;
        if settings
            .account_id
            .as_ref()
            .is_some_and(|old| old != &account_id)
            && !settings.config.pairs.is_empty()
        {
            return Err("This state has folder pairs for another account. Remove those pairs before switching accounts.".into());
        }
        let mut auth_state = self
            .auth_state
            .lock()
            .map_err(|_| "Authentication state poisoned")?;
        if auth_state.engine.is_some()
            || self
                .mount
                .lock()
                .map_err(|_| "Mount state poisoned")?
                .is_some()
        {
            return Err(
                "Sign out or restart the agent before authenticating another account".into(),
            );
        }

        let mut next = settings.clone();
        next.server = Some(session.server.clone());
        next.client_id = session.client_id.clone();
        next.account_id = Some(account_id.clone());
        self.session_store.save(&session)?;
        next.save(&self.dir)?;
        *settings = next;
        auth_state.client = Some(client);
        engine.set_sync_paused(settings.paused);
        auth_state.engine = Some(engine);
        auth_state.account_id = Some(account_id);
        auth_state.session = Some(session);
        auth_state.session_unsaved = false;
        *self.error.lock().map_err(|_| "Error state poisoned")? = None;
        self.wake.store(true, Ordering::Release);
        drop(auth_state);
        drop(settings);
        self.mount_if_enabled()?;
        Ok(())
    }

    fn mount_if_enabled(&self) -> Result<(), String> {
        // Serialize restoration with explicit unmount/configuration updates.
        // Otherwise a stale enabled snapshot could remount after unmount wins.
        let settings = self.settings.lock().map_err(|_| "Settings poisoned")?;
        if !settings.mount_enabled {
            return Ok(());
        }
        let (engine, account_id) = {
            let auth = self
                .auth_state
                .lock()
                .map_err(|_| "Authentication state poisoned")?;
            (
                auth.engine.clone().ok_or("Sign in first")?,
                auth.account_id
                    .clone()
                    .ok_or("Account identity is unavailable; sign in again")?,
            )
        };
        self.mount_engine(engine, &settings, &account_id)
    }

    fn mount_engine(
        &self,
        engine: Engine,
        settings: &Settings,
        account_id: &str,
    ) -> Result<(), String> {
        let account_dir = account_engine_dir(&self.dir, account_id);
        let root = ensure_cloud_root(&settings.config, &self.dir, &account_dir)?;
        let mut mounted = self.mount.lock().map_err(|_| "Mount state poisoned")?;
        if self.shutdown.load(Ordering::Acquire) {
            return Err("Agent is shutting down".into());
        }
        if mounted.as_ref().is_some_and(|handle| !handle.is_mounted()) {
            *mounted = None;
        }
        if mounted.is_none() {
            *mounted = Some(Box::new(raiun_fuse::mount(engine, &root, &account_dir)?));
        }
        Ok(())
    }

    fn enable_mount(&self) -> Result<(), String> {
        let mut settings = self.settings.lock().map_err(|_| "Settings poisoned")?;
        let (engine, account_id) = {
            let auth = self
                .auth_state
                .lock()
                .map_err(|_| "Authentication state poisoned")?;
            (
                auth.engine.clone().ok_or("Sign in first")?,
                auth.account_id
                    .clone()
                    .ok_or("Account identity is unavailable; sign in again")?,
            )
        };
        self.mount_engine(engine, &settings, &account_id)?;
        if !settings.mount_enabled {
            let mut next = settings.clone();
            next.mount_enabled = true;
            next.save(&self.dir)?;
            *settings = next;
        }
        Ok(())
    }

    fn disable_mount(&self) -> Result<(), String> {
        let mut settings = self.settings.lock().map_err(|_| "Settings poisoned")?;
        let mut mounted = self.mount.lock().map_err(|_| "Mount state poisoned")?;
        let mut detached_with_error = None;
        if let Some(handle) = mounted.as_mut() {
            match handle.unmount() {
                Ok(()) => *mounted = None,
                Err(error) if handle.is_mounted() => {
                    return Err(format!(
                        "Could not unmount cloud root; mount remains active: {error}"
                    ));
                }
                Err(error) => {
                    // Detach succeeded but the FUSE worker reported a shutdown
                    // error. Reflect the actual unmounted state, then surface it.
                    *mounted = None;
                    detached_with_error = Some(error);
                }
            }
        }
        if settings.mount_enabled {
            let mut next = settings.clone();
            next.mount_enabled = false;
            next.save(&self.dir)?;
            *settings = next;
        }
        detached_with_error.map_or(Ok(()), Err)
    }

    fn refresh_session(&self) -> Result<(), String> {
        let mut state = self
            .auth_state
            .lock()
            .map_err(|_| "Authentication state poisoned")?;
        if state.session.is_none() {
            return Ok(());
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "System clock is invalid")?
            .as_secs();
        let (token, refreshed) = {
            let session = state.session.as_mut().ok_or("Session disappeared")?;
            if session.expires_at <= now + 120 {
                session.refresh()?;
                (Some(session.access_token.clone()), true)
            } else {
                (None, false)
            }
        };
        if refreshed {
            state.session_unsaved = true;
        }
        if let Some(token) = token {
            if let Some(client) = state.client.as_ref() {
                client.set_bearer_token(token).map_err(|e| e.to_string())?;
            }
        }
        if state.session_unsaved {
            self.session_store
                .save(state.session.as_ref().ok_or("Session disappeared")?)?;
            state.session_unsaved = false;
        }
        *self
            .refresh_error
            .lock()
            .map_err(|_| "Refresh status poisoned")? = None;
        Ok(())
    }

    fn engine(&self) -> Result<Engine, String> {
        self.auth_state
            .lock()
            .map_err(|_| "Authentication state poisoned")?
            .engine
            .clone()
            .ok_or("Sign in first".into())
    }
    fn update(&self, edit: impl FnOnce(&mut Settings) -> Result<(), String>) -> Result<(), String> {
        let mut current = self.settings.lock().map_err(|_| "Settings poisoned")?;
        let mut next = current.clone();
        edit(&mut next)?;
        next.save(&self.dir)?;
        *current = next;
        self.wake.store(true, Ordering::Release);
        Ok(())
    }
    fn record_pair_report(
        &self,
        pair: &FolderPair,
        report: Option<SyncReport>,
        error: Option<String>,
    ) {
        let Ok(mut reports) = self.pair_reports.lock() else {
            return;
        };
        let last = reports.get(&pair.id).map(|status| status.report.clone());
        let report = report.or(last).unwrap_or_else(|| SyncReport {
            pair_id: pair.id.clone(),
            ..SyncReport::default()
        });
        let message = error.or_else(|| {
            if report.conflicts > 0 || report.needs_attention > 0 {
                Some(format!(
                    "Pair '{}' at {} has {} conflicts and {} items needing attention. No deletions were applied.",
                    pair.id, pair.remote_path, report.conflicts, report.needs_attention
                ))
            } else {
                None
            }
        });
        reports.insert(
            pair.id.clone(),
            PairSyncStatus {
                report,
                message,
                updated_at: now_unix(),
            },
        );
    }

    fn handle(self: &Arc<Self>, request: Value) -> Result<Value, String> {
        let text = |key: &str| {
            request
                .get(key)
                .and_then(Value::as_str)
                .ok_or_else(|| format!("Missing {key}"))
        };
        let action = text("action")?;
        if self.shutdown.load(Ordering::Acquire) && action != "shutdown" {
            return Err("Agent is shutting down".into());
        }
        match action {
            "status" => {
                let s = self
                    .settings
                    .lock()
                    .map_err(|_| "Settings poisoned")?
                    .clone();
                let (connected, session_expires_at, session_last_refresh_at) = {
                    let auth = self
                        .auth_state
                        .lock()
                        .map_err(|_| "Authentication state poisoned")?;
                    (
                        auth.engine.is_some(),
                        auth.session.as_ref().map(|session| session.expires_at),
                        auth.session
                            .as_ref()
                            .and_then(|session| session.last_refresh_at),
                    )
                };
                let mounted = self
                    .mount
                    .lock()
                    .map_err(|_| "Mount state poisoned")?
                    .as_ref()
                    .is_some_and(|handle| handle.is_mounted());
                let error = self
                    .error
                    .lock()
                    .map_err(|_| "Error state poisoned")?
                    .clone();
                let refresh_error = self
                    .refresh_error
                    .lock()
                    .map_err(|_| "Refresh status poisoned")?
                    .clone();
                let reports = self
                    .pair_reports
                    .lock()
                    .map_err(|_| "Pair report state poisoned")?
                    .clone();
                let displayed_error = error
                    .or(refresh_error)
                    .or_else(|| reports.values().find_map(|report| report.message.clone()));
                let recovery_folder = s
                    .account_id
                    .as_deref()
                    .map(|account| account_spool_dir(&self.dir, account));
                Ok(json!({
                    "connected": connected,
                    "session_expires_at": session_expires_at,
                    "session_last_refresh_at": session_last_refresh_at,
                    "server": s.server,
                    "client_id": s.server.as_ref().map(|_| s.client_id.as_str()),
                    "paused": s.paused,
                    "mounted": mounted,
                    "cloud_root": s.config.cloud_root,
                    "recovery_folder": recovery_folder,
                    "autostart": autostart::is_enabled(),
                    "error": displayed_error,
                    "pair_reports": reports,
                    "authenticating": self.authenticating.load(Ordering::Acquire),
                    "restoring": self.restoring.load(Ordering::Acquire),
                }))
            }
            "auth_begin" => {
                if self.restoring.load(Ordering::Acquire) {
                    return Err("Checking the saved session; retry sign-in in a moment".into());
                }
                if self
                    .auth_state
                    .lock()
                    .map_err(|_| "Authentication state poisoned")?
                    .engine
                    .is_some()
                    || self
                        .mount
                        .lock()
                        .map_err(|_| "Mount state poisoned")?
                        .is_some()
                {
                    return Err(
                        "This agent is already connected. Restart it before signing in again"
                            .into(),
                    );
                }
                if self.authenticating.swap(true, Ordering::AcqRel) {
                    return Err("Sign-in is already in progress".into());
                }
                let result = (|| {
                    let raw = text("server")?;
                    let server = if raw.contains("://") {
                        raw.to_owned()
                    } else {
                        format!("https://{raw}")
                    };
                    let settings = self
                        .settings
                        .lock()
                        .map_err(|_| "Settings poisoned")?
                        .clone();
                    let client_id = request
                        .get("client_id")
                        .and_then(Value::as_str)
                        .unwrap_or(&settings.client_id);
                    let requested_server = normalize_server_input(&server)?;
                    let existing_server = settings
                        .server
                        .as_deref()
                        .map(normalize_server_input)
                        .transpose()?;
                    if !settings.config.pairs.is_empty()
                        && existing_server
                            .as_deref()
                            .is_some_and(|old| old != requested_server)
                    {
                        return Err("Remove existing folder pairs before changing servers".into());
                    }
                    let flow = auth::AuthFlow::begin(&server, client_id)?;
                    if !settings.config.pairs.is_empty() && flow.client_id() != settings.client_id {
                        return Err(
                            "Remove existing folder pairs before changing OAuth clients".into()
                        );
                    }
                    let info = flow.public_info();
                    let runtime = self.clone();
                    std::thread::spawn(move || {
                        let result = flow
                            .wait()
                            .and_then(|session| runtime.install_session(session));
                        if let Err(error) = result {
                            if let Ok(mut state) = runtime.error.lock() {
                                *state = Some(error);
                            }
                        }
                        runtime.authenticating.store(false, Ordering::Release);
                    });
                    Ok(info)
                })();
                if result.is_err() {
                    self.authenticating.store(false, Ordering::Release);
                }
                result
            }
            "pairs" => Ok(json!(
                self.settings
                    .lock()
                    .map_err(|_| "Settings poisoned")?
                    .config
                    .pairs
            )),
            "recoveries" => {
                let after = match request.get("after") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(cursor)) => Some(cursor.as_str()),
                    Some(_) => return Err("after must be a string".into()),
                };
                let limit = match request.get("limit") {
                    None => 50,
                    Some(Value::Number(number)) => number
                        .as_u64()
                        .ok_or("limit must be an unsigned integer")?
                        .min(100) as usize,
                    Some(_) => return Err("limit must be an unsigned integer".into()),
                };
                if limit == 0 {
                    return Err("limit must be between 1 and 100".into());
                }
                let account_id = self
                    .settings
                    .lock()
                    .map_err(|_| "Settings poisoned")?
                    .account_id
                    .clone();
                let page = if let Some(account_id) = account_id {
                    raiun_fuse::recovery::list_recoveries(
                        &account_spool_dir(&self.dir, &account_id),
                        after,
                        limit,
                    )
                    .map_err(|error| error.to_string())?
                } else {
                    raiun_fuse::recovery::RecoveryPage {
                        items: Vec::new(),
                        next_after: None,
                        scanned_entries: 0,
                        warning_count: 0,
                        unrecognized_entries: 0,
                        truncated: false,
                    }
                };
                serde_json::to_value(page).map_err(|_| "Could not encode recovery page".into())
            }
            "conflicts" | "resolve_conflict" => {
                let pair_id = text("pair_id")?;
                let pair = self
                    .settings
                    .lock()
                    .map_err(|_| "Settings poisoned")?
                    .config
                    .pairs
                    .iter()
                    .find(|pair| pair.id == pair_id)
                    .cloned()
                    .ok_or("Folder pair no longer exists")?;
                let engine = self.engine()?;
                if action == "conflicts" {
                    let after = request.get("after").and_then(Value::as_str);
                    let limit = request
                        .get("limit")
                        .and_then(Value::as_u64)
                        .unwrap_or(100)
                        .min(1000) as usize;
                    Ok(json!(
                        engine
                            .conflicts(&pair, after, limit)
                            .map_err(|error| error.to_string())?
                    ))
                } else {
                    let choice: raiun_engine::ConflictChoice = serde_json::from_value(
                        request.get("choice").cloned().ok_or("Missing choice")?,
                    )
                    .map_err(|_| "Choose keep_local or keep_remote")?;
                    let resolved = engine
                        .resolve_conflict(
                            &pair,
                            text("path")?,
                            choice,
                            text("expected_local_hash")?,
                            text("expected_remote_etag")?,
                        )
                        .map_err(|error| error.to_string())?;
                    self.wake.store(true, Ordering::Release);
                    Ok(json!(resolved))
                }
            }
            "pair_add" => {
                let mut body = request.clone();
                body.as_object_mut()
                    .ok_or("Invalid request")?
                    .remove("action");
                let pair: FolderPair = serde_json::from_value(body).map_err(|e| e.to_string())?;
                self.update(|s| {
                    if s.retired_pair_ids.iter().any(|retired| retired == &pair.id) {
                        return Err("Pair ID has been retired and cannot be reused".into());
                    }
                    if s.config.pairs.iter().any(|p| p.id == pair.id) {
                        return Err("Pair ID already exists".into());
                    }
                    s.config.pairs.push(pair);
                    let errors = validate_config(&s.config);
                    if !errors.is_empty() {
                        return Err(errors.join("; "));
                    }
                    Ok(())
                })?;
                Ok(json!({}))
            }
            "pair_remove" => {
                let id = text("id")?;
                self.update(|s| {
                    if s.config.pairs.iter().any(|pair| pair.id == id)
                        && !s.retired_pair_ids.iter().any(|retired| retired == id)
                    {
                        if s.retired_pair_ids.len() >= 100_000 {
                            return Err("Retired pair ID limit reached; remove old history before deleting more pairs".into());
                        }
                        s.retired_pair_ids.push(id.to_owned());
                    }
                    s.config.pairs.retain(|p| p.id != id);
                    Ok(())
                })?;
                self.pair_reports
                    .lock()
                    .map_err(|_| "Pair report state poisoned")?
                    .remove(id);
                Ok(json!({}))
            }
            "mount" => {
                self.enable_mount()?;
                Ok(json!({}))
            }
            "unmount" => {
                self.disable_mount()?;
                Ok(json!({}))
            }
            "configure" => {
                if self
                    .mount
                    .lock()
                    .map_err(|_| "Mount state poisoned")?
                    .is_some()
                {
                    return Err("Unmount before changing the cloud folder".into());
                }
                let root = PathBuf::from(text("cloud_root")?);
                self.update(|s| {
                    s.config.cloud_root = root;
                    let errors = validate_config(&s.config);
                    if errors.is_empty() {
                        Ok(())
                    } else {
                        Err(errors.join("; "))
                    }
                })?;
                Ok(json!({}))
            }
            "pause" => {
                let paused = request
                    .get("paused")
                    .and_then(Value::as_bool)
                    .ok_or("Missing paused")?;
                self.update(|s| {
                    s.paused = paused;
                    Ok(())
                })?;
                if let Ok(engine) = self.engine() {
                    engine.set_sync_paused(paused);
                }
                Ok(json!({}))
            }
            "set_autostart" => {
                autostart::configure(
                    request
                        .get("enabled")
                        .and_then(Value::as_bool)
                        .ok_or("Missing enabled")?,
                )?;
                Ok(json!({}))
            }
            "shutdown" => {
                self.shutdown.store(true, Ordering::Release);
                Ok(json!({"stopping":true}))
            }
            "sync_now" => {
                self.engine()?;
                self.wake.store(true, Ordering::Release);
                Ok(json!({}))
            }
            "spaces" => Ok(json!(self.engine()?.spaces().map_err(|e| e.to_string())?)),
            "list" | "browse" => Ok(json!(
                self.engine()?
                    .list(text("space_id")?, text("path")?)
                    .map_err(|e| e.to_string())?
            )),
            "transfers" => Ok(json!(
                self.engine()?.transfers(500).map_err(|e| e.to_string())?
            )),
            _ => Err("This action is not yet available".into()),
        }
    }
}

fn normalize_server_input(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    let value = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("https://{raw}")
    };
    let mut url = url::Url::parse(&value).map_err(|_| "Invalid server URL".to_string())?;
    let loopback = url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if !(url.scheme() == "https" || (url.scheme() == "http" && loopback))
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("Server must use HTTPS (HTTP is allowed only for loopback tests)".into());
    }
    url.set_fragment(None);
    Ok(url.to_string().trim_end_matches('/').to_string())
}

fn account_identity(server: &str, personal_drive_id: &str) -> String {
    let identity = format!("{server}\0{personal_drive_id}");
    let mut encoded = String::with_capacity(identity.len() * 2);
    for byte in identity.bytes() {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn account_engine_dir(state_dir: &std::path::Path, account_id: &str) -> PathBuf {
    let mut path = state_dir.join("engine").join("accounts");
    if account_id.is_empty()
        || account_id.len() % 2 != 0
        || !account_id.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return path.join("invalid-account-id");
    }
    for component in account_id.as_bytes().chunks(180) {
        // The identity is ASCII hexadecimal, so 180-byte chunks are safe path
        // components while keeping individual components below NAME_MAX.
        path.push(std::str::from_utf8(component).unwrap_or("invalid-account-id"));
    }
    path
}

fn account_spool_dir(state_dir: &Path, account_id: &str) -> PathBuf {
    account_engine_dir(state_dir, account_id).join("provider-spool")
}

fn ensure_cloud_root(
    config: &raiun_core::Config,
    state_dir: &Path,
    account_dir: &Path,
) -> Result<PathBuf, String> {
    let errors = validate_config(config);
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    let root_candidate = resolve_without_symlinks(&config.cloud_root)?;
    let state = fs::canonicalize(state_dir).map_err(|error| error.to_string())?;
    let account = fs::canonicalize(account_dir).map_err(|error| error.to_string())?;
    if paths_overlap(&root_candidate, &state) || paths_overlap(&root_candidate, &account) {
        return Err(
            "Cloud root must not overlap Raiun's private state or provider recovery data".into(),
        );
    }
    create_directories_without_symlinks(&config.cloud_root)?;
    let root = fs::canonicalize(&config.cloud_root).map_err(|error| error.to_string())?;
    if root != root_candidate {
        return Err("Cloud root changed while it was being prepared; retry the mount".into());
    }
    let state = fs::canonicalize(state_dir).map_err(|error| error.to_string())?;
    let account = fs::canonicalize(account_dir).map_err(|error| error.to_string())?;
    if paths_overlap(&root, &state) || paths_overlap(&root, &account) {
        return Err(
            "Cloud root must not overlap Raiun's private state or provider recovery data".into(),
        );
    }
    Ok(root)
}

fn resolve_without_symlinks(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| part == std::path::Component::ParentDir)
    {
        return Err("Cloud and state paths must be absolute and must not contain '..'".into());
    }
    let mut resolved = PathBuf::new();
    let mut missing = false;
    for component in path.components() {
        match component {
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                resolved.push(component.as_os_str());
            }
            std::path::Component::Normal(name) => {
                resolved.push(name);
                if missing {
                    continue;
                }
                match fs::symlink_metadata(&resolved) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        return Err(format!(
                            "Path '{}' contains a symbolic link",
                            resolved.display()
                        ));
                    }
                    Ok(metadata) if !metadata.is_dir() => {
                        return Err(format!("Path '{}' is not a directory", resolved.display()));
                    }
                    Ok(_) => {
                        resolved = fs::canonicalize(&resolved).map_err(|error| error.to_string())?
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => missing = true,
                    Err(error) => {
                        return Err(format!(
                            "Could not inspect '{}': {error}",
                            resolved.display()
                        ));
                    }
                }
            }
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => return Err("Path must not contain '..'".into()),
        }
    }
    Ok(resolved)
}

fn create_directories_without_symlinks(path: &Path) -> Result<(), String> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| part == std::path::Component::ParentDir)
    {
        return Err("Cloud root must be an absolute path without '..'".into());
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!(
                    "Cloud root '{}' contains a symbolic link",
                    current.display()
                ));
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(format!(
                    "Cloud root component '{}' is not a directory",
                    current.display()
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match fs::create_dir(&current) {
                    Ok(()) => {}
                    Err(create_error)
                        if create_error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(create_error) => {
                        return Err(format!(
                            "Could not create cloud root '{}': {create_error}",
                            current.display()
                        ));
                    }
                }
                let metadata = fs::symlink_metadata(&current).map_err(|error| error.to_string())?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(format!(
                        "Cloud root component '{}' is unsafe",
                        current.display()
                    ));
                }
            }
            Err(error) => {
                return Err(format!(
                    "Could not inspect '{}': {error}",
                    current.display()
                ));
            }
        }
    }
    Ok(())
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn scheduler_loop(scheduler: Arc<Runtime>) {
    let mut ticks = 0u32;
    loop {
        std::thread::sleep(Duration::from_secs(1));
        if scheduler.shutdown.load(Ordering::Acquire) {
            break;
        }
        ticks += 1;
        if !scheduler.wake.swap(false, Ordering::AcqRel) && ticks < 30 {
            continue;
        }
        ticks = 0;
        if let Err(error) = scheduler.refresh_session() {
            if let Ok(mut state) = scheduler.refresh_error.lock() {
                *state = Some(error);
            }
            continue;
        }
        let Ok(settings) = scheduler.settings.lock().map(|s| s.clone()) else {
            break;
        };
        if settings.paused {
            continue;
        }
        let Ok(engine) = scheduler.engine() else {
            continue;
        };
        for pair in settings.config.pairs {
            if scheduler.shutdown.load(Ordering::Acquire) {
                break;
            }
            if scheduler.settings.lock().map(|s| s.paused).unwrap_or(true) {
                break;
            }
            match engine.sync_pair(&pair) {
                Ok(report) => scheduler.record_pair_report(&pair, Some(report), None),
                Err(error) => {
                    if scheduler.settings.lock().map(|s| s.paused).unwrap_or(true) {
                        break;
                    }
                    scheduler.record_pair_report(&pair, None, Some(error.to_string()));
                }
            }
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Raiun: {error}");
        std::process::exit(1);
    }
}

#[cfg(unix)]
fn run() -> Result<(), String> {
    use fs2::FileExt;
    use std::os::unix::{
        fs::{FileTypeExt, OpenOptionsExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    };
    let args = Args::parse();
    let dir = storage::state_dir()?;
    let socket = dir.join("control.sock");
    if let Command::Request { message } = args.command {
        let request: Value = serde_json::from_str(&message).map_err(|e| e.to_string())?;
        let mut stream = UnixStream::connect(socket).map_err(|e| e.to_string())?;
        let response_timeout =
            if request.get("action").and_then(Value::as_str) == Some("auth_begin") {
                Duration::from_secs(65)
            } else {
                Duration::from_secs(30)
            };
        stream
            .set_read_timeout(Some(response_timeout))
            .map_err(|e| e.to_string())?;
        writeln!(stream, "{message}").map_err(|e| e.to_string())?;
        let mut response = String::new();
        BufReader::new(stream)
            .take((MAX_SOCKET_RESPONSE + 1) as u64)
            .read_line(&mut response)
            .map_err(|e| e.to_string())?;
        if response.len() > MAX_SOCKET_RESPONSE || !response.ends_with('\n') {
            return Err("Agent response is oversized or incomplete".into());
        }
        println!("{response}");
        return Ok(());
    }
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(dir.join("agent.lock"))
        .map_err(|e| e.to_string())?;
    lock.try_lock_exclusive()
        .map_err(|_| "An agent is already running")?;
    match fs::symlink_metadata(&socket) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            fs::remove_file(&socket).map_err(|e| e.to_string())?;
        }
        Ok(_) => return Err("Refusing to replace a non-socket control path".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
    let listener = UnixListener::bind(&socket).map_err(|e| e.to_string())?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    let runtime = Arc::new(Runtime {
        settings: Mutex::new(Settings::load(&dir)?),
        dir,
        auth_state: Mutex::new(AuthState {
            engine: None,
            session: None,
            client: None,
            account_id: None,
            session_unsaved: false,
        }),
        error: Mutex::new(None),
        refresh_error: Mutex::new(None),
        pair_reports: Mutex::new(BTreeMap::new()),
        wake: AtomicBool::new(true),
        mount: Mutex::new(None),
        authenticating: AtomicBool::new(false),
        restoring: AtomicBool::new(true),
        shutdown: AtomicBool::new(false),
        session_store: Arc::new(SecretServiceStore),
    });
    let signal_shutdown = runtime.clone();
    ctrlc::set_handler(move || {
        signal_shutdown.shutdown.store(true, Ordering::Release);
    })
    .map_err(|error| format!("Could not install shutdown signal handlers: {error}"))?;
    let restore = runtime.clone();
    std::thread::spawn(move || {
        let result = (|| {
            let settings = restore
                .settings
                .lock()
                .map_err(|_| "Settings poisoned")?
                .clone();
            if let Some(server) = settings.server {
                let Some(mut session) = restore.session_store.load(&server, &settings.client_id)?
                else {
                    return Err(
                        "No saved session is available in the keyring; sign in again".into(),
                    );
                };
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| "System clock is invalid")?
                    .as_secs();
                if session.expires_at <= now + 120 {
                    session.refresh()?;
                }
                restore.install_session(session)?;
            }
            Ok::<(), String>(())
        })();
        if let Err(error) = result {
            if let Ok(mut state) = restore.error.lock() {
                *state = Some(error);
            }
        }
        restore.restoring.store(false, Ordering::Release);
    });
    let scheduler = runtime.clone();
    std::thread::spawn(move || scheduler_loop(scheduler));
    // A bounded number of workers avoids an unbounded thread per socket request.
    let connections = Arc::new(Mutex::new(listener));
    let mut workers = Vec::new();
    for _ in 0..4 {
        let connections = connections.clone();
        let runtime = runtime.clone();
        workers.push(std::thread::spawn(move || {
            loop {
                let stream = match connections.lock() {
                    Ok(listener) => listener.accept(),
                    Err(_) => return,
                };
                let Ok((mut stream, _)) = stream else {
                    continue;
                };
                if runtime.shutdown.load(Ordering::Acquire) {
                    break;
                }
                let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
                let mut line = String::new();
                let result = BufReader::new(&stream)
                    .take((MAX_SOCKET_MESSAGE + 1) as u64)
                    .read_line(&mut line)
                    .map_err(|e| e.to_string())
                    .and_then(|_| {
                        if line.len() > MAX_SOCKET_MESSAGE || !line.ends_with('\n') {
                            return Err("Invalid or oversized request".into());
                        }
                        let request =
                            serde_json::from_str(&line).map_err(|_| "Invalid request JSON")?;
                        runtime.handle(request)
                    });
                let response = match result {
                    Ok(data) => json!({"ok":true,"data":data}),
                    Err(error) => json!({"ok":false,"error":error}),
                };
                let mut encoded = serde_json::to_vec(&response).unwrap_or_else(|_| {
                    b"{\"ok\":false,\"error\":\"Could not encode response\"}".to_vec()
                });
                if encoded.len() > MAX_SOCKET_RESPONSE {
                    encoded = b"{\"ok\":false,\"error\":\"Response exceeds size limit\"}".to_vec();
                }
                encoded.push(b'\n');
                let _ = stream.write_all(&encoded);
            }
        }));
    }
    loop {
        if runtime.shutdown.load(Ordering::Acquire) {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    // Dropping the mount handle before process exit asks FUSE to unmount
    // cleanly. Its durable provider spool remains on disk for recovery.
    let mount = runtime
        .mount
        .lock()
        .map_err(|_| "Mount state poisoned")?
        .take();
    drop(mount);

    // Wake workers blocked in accept, then join only the bounded socket pool.
    // The scheduler may be inside an active cloud request; process exit ends
    // that worker without discarding provider spool files or DB journals.
    for _ in 0..4 {
        let _ = UnixStream::connect(&socket);
    }
    for worker in workers {
        let _ = worker.join();
    }
    match fs::symlink_metadata(&socket) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            fs::remove_file(&socket).map_err(|error| error.to_string())?;
        }
        Ok(_) => return Err("Control socket path was replaced during shutdown".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
    Ok(())
}

#[cfg(not(unix))]
fn run() -> Result<(), String> {
    Err("This MVP agent requires Linux".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeMount {
        mounted: bool,
        fail_while_mounted: bool,
        fail_after_detach: bool,
    }

    impl MountedCloud for FakeMount {
        fn unmount(&mut self) -> Result<(), String> {
            if self.fail_while_mounted {
                return Err("fixture unmount failure".into());
            }
            self.mounted = false;
            if self.fail_after_detach {
                return Err("fixture worker join failure".into());
            }
            Ok(())
        }

        fn is_mounted(&self) -> bool {
            self.mounted
        }
    }

    fn runtime_for_mount_test(
        state_dir: PathBuf,
        mount_enabled: bool,
        mount: Option<Box<dyn MountedCloud>>,
    ) -> Runtime {
        Runtime {
            dir: state_dir.clone(),
            settings: Mutex::new(Settings {
                config: Config {
                    schema_version: CONFIG_SCHEMA_VERSION,
                    cloud_root: state_dir.join("cloud"),
                    pairs: Vec::new(),
                },
                server: None,
                client_id: "OpenCloudDesktop".into(),
                account_id: None,
                retired_pair_ids: Vec::new(),
                paused: false,
                mount_enabled,
            }),
            auth_state: Mutex::new(AuthState {
                engine: None,
                session: None,
                client: None,
                account_id: None,
                session_unsaved: false,
            }),
            error: Mutex::new(None),
            refresh_error: Mutex::new(None),
            pair_reports: Mutex::new(BTreeMap::new()),
            wake: AtomicBool::new(false),
            mount: Mutex::new(mount),
            authenticating: AtomicBool::new(false),
            restoring: AtomicBool::new(false),
            shutdown: AtomicBool::new(false),
            session_store: Arc::new(FakeSecretService::default()),
        }
    }

    #[test]
    fn failed_unmount_keeps_mount_and_persisted_intent_for_retry() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = runtime_for_mount_test(
            dir.path().to_path_buf(),
            true,
            Some(Box::new(FakeMount {
                mounted: true,
                fail_while_mounted: true,
                fail_after_detach: false,
            })),
        );

        let error = runtime.disable_mount().unwrap_err();

        assert!(error.contains("mount remains active"));
        assert!(runtime.settings.lock().unwrap().mount_enabled);
        assert!(runtime.mount.lock().unwrap().as_ref().unwrap().is_mounted());
        assert!(!dir.path().join("settings.json").exists());
    }

    #[test]
    fn persistence_failure_after_detach_reports_actual_unmounted_state() {
        let dir = tempfile::tempdir().unwrap();
        let missing_state_dir = dir.path().join("not-created");
        let runtime = runtime_for_mount_test(
            missing_state_dir,
            true,
            Some(Box::new(FakeMount {
                mounted: true,
                fail_while_mounted: false,
                fail_after_detach: false,
            })),
        );

        assert!(runtime.disable_mount().is_err());

        assert!(runtime.settings.lock().unwrap().mount_enabled);
        assert!(runtime.mount.lock().unwrap().is_none());
    }

    #[test]
    fn shutdown_error_after_detach_clears_intent_but_reports_error() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = runtime_for_mount_test(
            dir.path().to_path_buf(),
            true,
            Some(Box::new(FakeMount {
                mounted: true,
                fail_while_mounted: false,
                fail_after_detach: true,
            })),
        );

        assert!(
            runtime
                .disable_mount()
                .unwrap_err()
                .contains("worker join failure")
        );

        assert!(!runtime.settings.lock().unwrap().mount_enabled);
        assert!(runtime.mount.lock().unwrap().is_none());
        assert!(!Settings::load(dir.path()).unwrap().mount_enabled);
    }

    #[test]
    fn recoveries_action_returns_an_empty_page_without_a_saved_account() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = Arc::new(runtime_for_mount_test(
            dir.path().to_path_buf(),
            false,
            None,
        ));

        let page = runtime.handle(json!({"action":"recoveries"})).unwrap();

        assert_eq!(page["items"], json!([]));
        assert!(page["next_after"].is_null());
        assert_eq!(page["scanned_entries"], 0);
        assert_eq!(page["warning_count"], 0);
        assert_eq!(page["unrecognized_entries"], 0);
        assert_eq!(page["truncated"], false);
        assert!(
            runtime
                .handle(json!({"action":"recoveries", "limit":0}))
                .unwrap_err()
                .contains("between 1 and 100")
        );
    }

    #[test]
    fn recoveries_action_lists_saved_account_spool_while_disconnected() {
        let dir = tempfile::tempdir().unwrap();
        let account_id = "aabb";
        let spool = account_spool_dir(dir.path(), account_id);
        fs::create_dir_all(&spool).unwrap();
        let space = "drive-1";
        let remote_path = "/folder/photo.jpg";
        let hash = format!(
            "{:016x}",
            format!("{space}\0{remote_path}")
                .bytes()
                .fold(0xcbf29ce484222325u64, |hash, byte| {
                    (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3)
                })
        );
        fs::write(
            spool.join(format!("{hash}.meta")),
            serde_json::to_vec(&[space, remote_path, "match", "private-etag"]).unwrap(),
        )
        .unwrap();
        fs::write(spool.join(format!("{hash}.data")), b"saved local bytes").unwrap();
        let runtime = Arc::new(runtime_for_mount_test(
            dir.path().to_path_buf(),
            false,
            None,
        ));
        runtime.settings.lock().unwrap().account_id = Some(account_id.into());

        let page = runtime
            .handle(json!({"action":"recoveries", "limit":500}))
            .unwrap();

        assert_eq!(page["items"].as_array().unwrap().len(), 1);
        let item = &page["items"][0];
        assert_eq!(item["space_id"], space);
        assert_eq!(item["remote_path"], remote_path);
        assert_eq!(item["bytes"], b"saved local bytes".len());
        assert_eq!(item["condition"], "match");
        assert!(item["local_data_path"].as_str().is_some());
        assert!(!page.to_string().contains("private-etag"));
    }
    use raiun_core::{CONFIG_SCHEMA_VERSION, Config};
    use std::{
        io::{Read, Write},
        net::TcpListener,
        time::Instant,
    };

    #[derive(Default)]
    struct FakeSecretService {
        sessions: Mutex<BTreeMap<(String, String), Vec<u8>>>,
        fail_next_save: AtomicBool,
    }

    impl SessionStore for FakeSecretService {
        fn save(&self, session: &auth::Session) -> Result<(), String> {
            if self.fail_next_save.swap(false, Ordering::AcqRel) {
                return Err("synthetic Secret Service write failure".into());
            }
            let bytes = serde_json::to_vec(session)
                .map_err(|_| "fake Secret Service could not serialize a session")?;
            self.sessions
                .lock()
                .map_err(|_| "fake Secret Service lock was poisoned")?
                .insert((session.server.clone(), session.client_id.clone()), bytes);
            Ok(())
        }

        fn load(&self, server: &str, client_id: &str) -> Result<Option<auth::Session>, String> {
            self.sessions
                .lock()
                .map_err(|_| "fake Secret Service lock was poisoned")?
                .get(&(server.to_owned(), client_id.to_owned()))
                .map(|bytes| {
                    serde_json::from_slice(bytes)
                        .map_err(|_| "fake Secret Service stored invalid session data".into())
                })
                .transpose()
        }
    }

    fn token_fixture(
        listener: TcpListener,
        responses: Vec<(u16, &'static str)>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            for (status, response) in responses {
                let (mut stream, _) = listener.accept().expect("refresh request");
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .expect("read timeout");
                let mut headers = Vec::new();
                let mut byte = [0];
                while !headers.ends_with(b"\r\n\r\n") {
                    stream.read_exact(&mut byte).expect("read request headers");
                    headers.push(byte[0]);
                    assert!(headers.len() < 16 * 1024, "bounded test headers");
                }
                let header_text = String::from_utf8(headers).expect("HTTP headers");
                let length = header_text
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .expect("form content length");
                assert!(length < 4096);
                let mut body = vec![0; length];
                stream.read_exact(&mut body).expect("read refresh form");
                let body = String::from_utf8(body).expect("form body");
                assert!(body.contains("grant_type=refresh_token"));
                assert!(body.contains("refresh_token=fixture-old-refresh"));
                write!(
                    stream,
                    "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response.len(),
                    response
                )
                .expect("write refresh response");
            }
        })
    }

    fn runtime_for_refresh(
        dir: &Path,
        session: auth::Session,
        client: raiun_opencloud::OpenCloudClient,
        session_store: Arc<dyn SessionStore>,
    ) -> Arc<Runtime> {
        let settings = Settings {
            config: Config {
                schema_version: CONFIG_SCHEMA_VERSION,
                cloud_root: dir.join("cloud"),
                pairs: Vec::new(),
            },
            server: Some(session.server.clone()),
            client_id: session.client_id.clone(),
            account_id: None,
            retired_pair_ids: Vec::new(),
            paused: true,
            mount_enabled: false,
        };
        Arc::new(Runtime {
            dir: dir.to_path_buf(),
            settings: Mutex::new(settings),
            auth_state: Mutex::new(AuthState {
                engine: None,
                session: Some(session),
                client: Some(client),
                account_id: None,
                session_unsaved: false,
            }),
            error: Mutex::new(None),
            refresh_error: Mutex::new(None),
            pair_reports: Mutex::new(BTreeMap::new()),
            wake: AtomicBool::new(true),
            mount: Mutex::new(None),
            authenticating: AtomicBool::new(false),
            restoring: AtomicBool::new(false),
            shutdown: AtomicBool::new(false),
            session_store,
        })
    }

    #[test]
    fn account_directories_isolate_engine_and_provider_spools() {
        let state = Path::new("/private/state");
        let account_a = "7365727665722d757365722d61";
        let account_b = "7365727665722d757365722d62";
        let first = account_engine_dir(state, account_a);
        let second = account_engine_dir(state, account_b);
        assert_ne!(first, second);
        assert_eq!(
            account_spool_dir(state, account_a),
            first.join("provider-spool")
        );
        assert_ne!(
            account_spool_dir(state, account_a),
            account_spool_dir(state, account_b)
        );
        assert!(account_engine_dir(state, "../../outside").starts_with(state));
        assert!(account_spool_dir(state, "../../outside").starts_with(state));
    }

    #[test]
    fn legacy_settings_do_not_enable_mount_on_restart() {
        let settings: Settings = serde_json::from_value(json!({
            "config": {
                "schema_version": CONFIG_SCHEMA_VERSION,
                "cloud_root": "/home/test/OpenCloud",
                "pairs": []
            },
            "server": null,
            "client_id": "OpenCloudDesktop",
            "account_id": null,
            "retired_pair_ids": [],
            "paused": false
        }))
        .expect("deserialize settings saved before mount intent existed");
        assert!(!settings.mount_enabled);
    }

    #[test]
    fn status_exposes_saved_client_id_only_with_saved_server() {
        let dir = PathBuf::from("/tmp/raiun-status-client-id-test");
        let runtime = Arc::new(Runtime {
            dir: dir.clone(),
            settings: Mutex::new(Settings {
                config: Config {
                    schema_version: CONFIG_SCHEMA_VERSION,
                    cloud_root: dir.join("cloud"),
                    pairs: Vec::new(),
                },
                server: None,
                client_id: "OpenCloudDesktop".into(),
                account_id: None,
                retired_pair_ids: Vec::new(),
                paused: false,
                mount_enabled: false,
            }),
            auth_state: Mutex::new(AuthState {
                engine: None,
                session: None,
                client: None,
                account_id: None,
                session_unsaved: false,
            }),
            error: Mutex::new(None),
            refresh_error: Mutex::new(None),
            pair_reports: Mutex::new(BTreeMap::new()),
            wake: AtomicBool::new(false),
            mount: Mutex::new(None),
            authenticating: AtomicBool::new(false),
            restoring: AtomicBool::new(false),
            shutdown: AtomicBool::new(false),
            session_store: Arc::new(FakeSecretService::default()),
        });
        let status = runtime.handle(json!({"action":"status"})).unwrap();
        assert!(status["client_id"].is_null());
    }

    #[test]
    fn creates_only_a_valid_non_symlink_cloud_root_outside_private_state() {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("state");
        let account = state.join("engine/accounts/account");
        fs::create_dir_all(&account).unwrap();
        let root = temp.path().join("home/OpenCloud");
        let config = Config {
            schema_version: CONFIG_SCHEMA_VERSION,
            cloud_root: root.clone(),
            pairs: Vec::new(),
        };
        let prepared = ensure_cloud_root(&config, &state, &account).unwrap();
        assert!(prepared.is_dir());
        assert_eq!(prepared, fs::canonicalize(root).unwrap());

        let nested_state_root = state.join("hidden-mount");
        let invalid = Config {
            cloud_root: nested_state_root.clone(),
            ..config.clone()
        };
        assert!(ensure_cloud_root(&invalid, &state, &account).is_err());
        assert!(!nested_state_root.exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let alias = temp.path().join("home/Alias");
            symlink(prepared, &alias).unwrap();
            let invalid = Config {
                cloud_root: alias,
                ..config
            };
            assert!(ensure_cloud_root(&invalid, &state, &account).is_err());
        }
    }

    #[test]
    fn scheduler_refreshes_short_lived_session_persists_it_and_exposes_safe_status() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind token fixture");
        let server = format!("http://{}", listener.local_addr().unwrap());
        let token_endpoint = format!("{server}/token");
        let token_server = token_fixture(
            listener,
            vec![(
                200,
                r#"{"access_token":"fixture-new-access","refresh_token":"fixture-new-refresh","expires_in":3600}"#,
            )],
        );
        let initial_expiry = now_unix() + 1;
        let session = auth::Session {
            server: server.clone(),
            client_id: "OpenCloudDesktop".into(),
            access_token: "fixture-old-access".into(),
            refresh_token: Some("fixture-old-refresh".into()),
            expires_at: initial_expiry,
            token_endpoint,
            expected_issuer: Some("https://issuer.example".into()),
            last_refresh_at: None,
        };
        let client = raiun_opencloud::OpenCloudClient::new(&server, "fixture-old-access".into())
            .expect("fixture cloud client");
        let store = Arc::new(FakeSecretService::default());
        let runtime = runtime_for_refresh(
            Path::new("/tmp/raiun-refresh-test"),
            session,
            client,
            store.clone(),
        );

        let scheduler = runtime.clone();
        let scheduler_thread = std::thread::spawn(move || scheduler_loop(scheduler));
        let deadline = Instant::now() + Duration::from_secs(4);
        let persisted = loop {
            if let Some(session) = store
                .load(&server, "OpenCloudDesktop")
                .expect("load fake keyring session")
            {
                break session;
            }
            assert!(
                Instant::now() < deadline,
                "scheduler did not persist refresh; status error: {:?}",
                runtime.error.lock().unwrap().as_deref()
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        let status = runtime.handle(json!({"action":"status"})).unwrap();
        runtime.shutdown.store(true, Ordering::Release);
        scheduler_thread.join().expect("scheduler thread");
        token_server.join().expect("token fixture thread");

        assert_eq!(persisted.access_token, "fixture-new-access");
        assert_eq!(
            persisted.refresh_token.as_deref(),
            Some("fixture-new-refresh")
        );
        assert!(persisted.expires_at > initial_expiry);
        assert!(persisted.last_refresh_at.is_some());

        assert_eq!(status["session_expires_at"], persisted.expires_at);
        assert_eq!(status["client_id"], "OpenCloudDesktop");
        assert_eq!(
            status["session_last_refresh_at"],
            persisted.last_refresh_at.unwrap()
        );
        let status_text = status.to_string();
        assert!(!status_text.contains("fixture-new-access"));
        assert!(!status_text.contains("fixture-new-refresh"));
        assert!(!status_text.contains("issuer.example"));
    }

    #[test]
    fn scheduler_retries_refresh_and_unsaved_session_persistence() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind token fixture");
        let server = format!("http://{}", listener.local_addr().unwrap());
        let token_server = token_fixture(
            listener,
            vec![
                (500, r#"{"error":"temporarily_unavailable"}"#),
                (
                    200,
                    r#"{"access_token":"fixture-new-access","refresh_token":"fixture-new-refresh","expires_in":3600}"#,
                ),
            ],
        );
        let session = auth::Session {
            server: server.clone(),
            client_id: "OpenCloudDesktop".into(),
            access_token: "fixture-old-access".into(),
            refresh_token: Some("fixture-old-refresh".into()),
            expires_at: now_unix() + 1,
            token_endpoint: format!("{server}/token"),
            expected_issuer: Some("https://issuer.example".into()),
            last_refresh_at: None,
        };
        let client = raiun_opencloud::OpenCloudClient::new(&server, "fixture-old-access".into())
            .expect("fixture cloud client");
        let store = Arc::new(FakeSecretService::default());
        store.fail_next_save.store(true, Ordering::Release);
        let runtime = runtime_for_refresh(
            Path::new("/tmp/raiun-refresh-retry-test"),
            session,
            client,
            store.clone(),
        );

        let scheduler = runtime.clone();
        let scheduler_thread = std::thread::spawn(move || scheduler_loop(scheduler));
        let deadline = Instant::now() + Duration::from_secs(6);
        while runtime.refresh_error.lock().unwrap().is_none() {
            assert!(
                Instant::now() < deadline,
                "first refresh failure not observed"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        runtime.wake.store(true, Ordering::Release);
        while runtime
            .refresh_error
            .lock()
            .unwrap()
            .as_ref()
            .is_none_or(|error| !error.contains("synthetic Secret Service"))
        {
            assert!(
                Instant::now() < deadline,
                "persistence failure not observed"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        runtime.wake.store(true, Ordering::Release);
        let persisted = loop {
            if let Some(session) = store
                .load(&server, "OpenCloudDesktop")
                .expect("load fake keyring session")
            {
                break session;
            }
            assert!(
                Instant::now() < deadline,
                "scheduler did not save refreshed session"
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        token_server.join().expect("token fixture thread");
        assert_eq!(persisted.access_token, "fixture-new-access");
        assert!(persisted.last_refresh_at.is_some());
        assert!(runtime.refresh_error.lock().unwrap().is_none());
        runtime.shutdown.store(true, Ordering::Release);
        scheduler_thread.join().expect("scheduler thread");
    }
}
