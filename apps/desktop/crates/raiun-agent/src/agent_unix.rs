// Per-user control socket and scheduler for the desktop engine.
mod auth;
mod autostart;
mod encrypted_edit_recovery;
mod namespace;
mod offline_cache;
mod ordinary_write_recovery;
mod profiles;
mod storage;
mod vault_edit_jobs;
mod vault_mount;
mod vault_pin_jobs;
mod vault_secrets;
mod vaults;

use clap::{Parser, Subcommand};
use profiles::ProfileManager;
use raiun_cache::AvailabilityPolicy;
use raiun_control::{read_json_line, read_json_value, write_json_line};
use raiun_core::{
    FolderPair, MediaImportJob,
    backend::{CloudBackend, RemoteEntry},
    validate_config, validate_media_import_jobs, validate_remote_path, windows_name_warnings,
};
use raiun_engine::{
    Engine, MEDIA_STABLE_FILE_SECONDS, MediaImportRecoveryCursor, MediaImportRunStatus, SyncReport,
};
use raiun_opencloud::transfer_budget::{TransferBudget, TransferLimits};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use storage::Settings;

const MAX_PENDING_SPACE_SYNCS: usize = 256;

fn remote_listing_response(entries: Vec<RemoteEntry>) -> Result<Value, String> {
    let warnings = windows_name_warnings(&entries);
    let mut response = serde_json::to_value(entries).map_err(|error| error.to_string())?;
    let Some(rows) = response.as_array_mut() else {
        return Err("remote listing could not be serialized".into());
    };
    for row in rows {
        let Some(path) = row.get("path").and_then(Value::as_str) else {
            continue;
        };
        let Some(entry_warnings) = warnings.get(path) else {
            continue;
        };
        let Some(object) = row.as_object_mut() else {
            continue;
        };
        object.insert(
            "windows_portability_warnings".into(),
            serde_json::to_value(entry_warnings).map_err(|error| error.to_string())?,
        );
    }
    Ok(response)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingMediaJob {
    revision: u64,
    auth_generation: u64,
}

fn select_queued_media_job(
    settings: &Settings,
    pending: &BTreeMap<String, PendingMediaJob>,
    generation: u64,
    active_account: &str,
) -> Option<MediaImportJob> {
    pending.iter().find_map(|(id, binding)| {
        if binding.auth_generation != generation {
            return None;
        }
        settings
            .media_jobs
            .iter()
            .find(|job| {
                job.id == *id
                    && job.revision == binding.revision
                    && job.account_id == active_account
                    && job.enabled
                    && !settings
                        .paused_space_ids
                        .iter()
                        .any(|space| space == &job.space_id)
            })
            .cloned()
    })
}

fn media_job_is_due(
    status: Option<&MediaImportRunStatus>,
    now: i64,
    interval_seconds: u32,
) -> bool {
    let Some(status) = status else {
        return true;
    };
    if !matches!(status.state.as_str(), "completed" | "interrupted") {
        return false;
    }
    let delay = if status.state == "completed" && status.waiting_for_stability > 0 {
        i64::from(interval_seconds.min(MEDIA_STABLE_FILE_SECONDS as u32))
    } else {
        i64::from(interval_seconds)
    };
    now.saturating_sub(status.updated_unix) >= delay
}

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
    fn load_classified(
        &self,
        server: &str,
        client_id: &str,
    ) -> Result<Option<auth::Session>, auth::SessionLoadError> {
        self.load(server, client_id)
            .map_err(auth::SessionLoadError::Invalid)
    }
    fn remove(&self, server: &str, client_id: &str) -> Result<(), String>;
}

struct SecretServiceStore {
    scope: Option<String>,
}

impl SessionStore for SecretServiceStore {
    fn save(&self, session: &auth::Session) -> Result<(), String> {
        match self.scope.as_deref() {
            Some(scope) => auth::save_session_scoped(session, Some(scope)),
            None => auth::save_session(session),
        }
    }

    fn load(&self, server: &str, client_id: &str) -> Result<Option<auth::Session>, String> {
        self.load_classified(server, client_id)
            .map_err(|error| error.to_string())
    }

    fn load_classified(
        &self,
        server: &str,
        client_id: &str,
    ) -> Result<Option<auth::Session>, auth::SessionLoadError> {
        match self.scope.as_deref() {
            Some(scope) => auth::load_session_scoped_classified(server, client_id, Some(scope)),
            None => auth::load_session_scoped_classified(server, client_id, None),
        }
    }

    fn remove(&self, server: &str, client_id: &str) -> Result<(), String> {
        match self.scope.as_deref() {
            Some(scope) => auth::remove_session_scoped(server, client_id, Some(scope)),
            None => auth::remove_session(server, client_id),
        }
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
    transfer_budget: Mutex<Option<(String, TransferBudget)>>,
    auth_state: Mutex<AuthState>,
    error: Mutex<Option<String>>,
    refresh_error: Mutex<Option<String>>,
    pair_reports: Mutex<BTreeMap<String, PairSyncStatus>>,
    wake: AtomicBool,
    pending_space_syncs: Mutex<BTreeSet<String>>,
    pending_media_jobs: Mutex<BTreeMap<String, PendingMediaJob>>,
    mount: Mutex<Option<Box<dyn MountedCloud>>>,
    sync_gate: Mutex<()>,
    authenticating: AtomicBool,
    auth_generation: Arc<AtomicU64>,
    restoring: AtomicBool,
    shutdown: Arc<AtomicBool>,
    auth_transition: Arc<AtomicBool>,
    offline_namespace: AtomicBool,
    offline_namespace_probe_unix: AtomicU64,
    session_store: Arc<dyn SessionStore>,
    vaults: Arc<raiun_vault::session::VaultSessionCoordinator>,
    vault_mounts: raiun_fuse::VaultMountRegistry,
    vault_account_id: String,
    /// Opaque local registry profile ID used only for local UI routing.
    /// Kept separate from server/account identity and vault key scope.
    local_profile_id: String,
    cache_jobs: Arc<offline_cache::CacheJobs>,
    write_reconcile_jobs: Arc<offline_cache::WriteReconcileJobs>,
    vault_edit_reconcile_jobs: Arc<vault_edit_jobs::VaultEditReconcileJobs>,
    vault_pin_jobs: Arc<vault_pin_jobs::VaultPinJobs>,
    cache_error: Mutex<Option<String>>,
    vault_cleanup_uncertain: AtomicBool,
}

#[derive(Clone, Debug)]
struct RestoreBinding {
    server: String,
    client_id: String,
    proxy: raiun_opencloud::ProxyConfig,
    proxy_account_id: Option<String>,
    account_id: Option<String>,
}

#[derive(Debug)]
enum RestoreFailure {
    Retryable(String),
    Permanent(String),
}

impl std::fmt::Display for RestoreFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Retryable(message) | Self::Permanent(message) => formatter.write_str(message),
        }
    }
}
/// Reject new authentication/vault work throughout logout and shutdown,
/// including requests arriving after the generation has been invalidated.
struct AuthTransition<'a>(&'a AtomicBool);
impl<'a> AuthTransition<'a> {
    fn begin(flag: &'a AtomicBool) -> Result<Self, String> {
        flag.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| "An account transition is already in progress".to_owned())?;
        Ok(Self(flag))
    }
}
impl Drop for AuthTransition<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Closes transfer admission while an account transition is in progress.
/// Existing clients share this controller, so pausing blocks new body chunks
/// and the generation bump cancels requests that already captured a
/// cancellation handle. Rollback restores the previous admission state;
/// committed logout/shutdown keeps the retired controller paused.
struct TransferAdmissionFence {
    budget: Option<TransferBudget>,
    was_paused: bool,
    committed: bool,
}

impl TransferAdmissionFence {
    fn begin(budget: Option<TransferBudget>) -> Self {
        let was_paused = budget.as_ref().is_some_and(TransferBudget::is_paused);
        if let Some(budget) = &budget {
            budget.set_paused(true);
            budget.cancel_waiters();
        }
        Self {
            budget,
            was_paused,
            committed: false,
        }
    }

    fn activate_and_commit(&mut self) {
        if let Some(budget) = &self.budget {
            budget.set_paused(false);
        }
        self.committed = true;
    }

    fn commit_paused(&mut self) {
        self.committed = true;
    }
}

impl Drop for TransferAdmissionFence {
    fn drop(&mut self) {
        if !self.committed
            && let Some(budget) = &self.budget
        {
            budget.set_paused(self.was_paused);
        }
    }
}

impl Runtime {
    fn operation_generation(&self) -> Result<u64, String> {
        // Capture generation before checking the transition flag. A later
        // transition must then invalidate this snapshot even if it completes
        // before the operation acquires its execution gate.
        let generation = self.auth_generation.load(Ordering::Acquire);
        if self.auth_transition.load(Ordering::Acquire) || self.shutdown.load(Ordering::Acquire) {
            return Err("An account transition is in progress".into());
        }
        Ok(generation)
    }

    fn transfer_budget_for_account(
        &self,
        account_id: &str,
        limits: TransferLimits,
    ) -> Result<TransferBudget, String> {
        let budget = self
            .transfer_budget
            .lock()
            .map_err(|_| "Transfer budget state poisoned")?
            .as_ref()
            .filter(|(owner, _)| owner == account_id)
            .map(|(_, budget)| budget.clone())
            .unwrap_or_default();
        budget.set_limits(limits);
        Ok(budget)
    }

    fn fence_transfer_admission(&self) -> Result<TransferAdmissionFence, String> {
        let budget = self
            .transfer_budget
            .lock()
            .map_err(|_| "Transfer budget state poisoned")?
            .as_ref()
            .map(|(_, budget)| budget.clone());
        Ok(TransferAdmissionFence::begin(budget))
    }

    fn install_session(
        &self,
        session: auth::Session,
        expected_generation: u64,
    ) -> Result<(), String> {
        if self.auth_generation.load(Ordering::Acquire) != expected_generation
            || self.auth_transition.load(Ordering::Acquire)
            || self.shutdown.load(Ordering::Acquire)
        {
            return Err("Agent is shutting down".into());
        }
        let client = raiun_opencloud::OpenCloudClient::new_with_proxy(
            &session.server,
            session.access_token.clone(),
            &session.proxy,
        )
        .map_err(|e| e.to_string())?;
        let spaces = client
            .spaces()
            .map_err(|error| auth::graph_error_with_issuer_hint(&error.to_string(), &session))?;
        self.install_session_with_spaces(session, expected_generation, client, spaces, false, None)
    }

    fn install_restored_session(
        &self,
        session: &auth::Session,
        expected_generation: u64,
        binding: &RestoreBinding,
    ) -> Result<(), RestoreFailure> {
        if self.auth_generation.load(Ordering::Acquire) != expected_generation
            || self.auth_transition.load(Ordering::Acquire)
            || self.shutdown.load(Ordering::Acquire)
        {
            return Err(RestoreFailure::Permanent(
                "Saved-session restore was canceled".into(),
            ));
        }
        // Startup must distinguish an unavailable server from revoked
        // authorization, but the ordinary OpenCloud client allows long body
        // transfer deadlines. Bound this one namespace probe so an accepted
        // TCP connection that never responds cannot leave the app restoring
        // forever. The installed Engine receives a normal-timeout client for
        // later recovery and user operations.
        let probe_client = raiun_opencloud::OpenCloudClient::new_for_namespace_probe_with_proxy(
            &session.server,
            session.access_token.clone(),
            &session.proxy,
        )
        .map_err(|error| RestoreFailure::Permanent(error.to_string()))?;
        let (spaces, offline) = match probe_client.spaces() {
            Ok(spaces) => (spaces, false),
            Err(error) if error.kind == raiun_core::backend::ErrorKind::Offline => {
                let spaces = self.load_account_namespace(session).map_err(|error| {
                    RestoreFailure::Retryable(format!(
                        "OpenCloud is unavailable and no verified saved namespace can be loaded: {error}"
                    ))
                })?;
                (spaces, true)
            }
            Err(error) => {
                return Err(RestoreFailure::Permanent(
                    auth::graph_error_with_issuer_hint(&error.to_string(), session),
                ));
            }
        };
        if !restore_is_current(self, expected_generation, binding) {
            return Err(RestoreFailure::Permanent(
                "Saved-session restore was canceled or its account settings changed".into(),
            ));
        }
        let client = raiun_opencloud::OpenCloudClient::new_with_proxy(
            &session.server,
            session.access_token.clone(),
            &session.proxy,
        )
        .map_err(|error| RestoreFailure::Permanent(error.to_string()))?;
        self.install_session_with_spaces(
            session.clone(),
            expected_generation,
            client,
            spaces,
            offline,
            Some(binding),
        )
        .map_err(RestoreFailure::Permanent)
    }

    /// Persist an OAuth refresh performed before Graph recovery. Hold the same
    /// settings -> auth locks as session installation so logout cannot clear
    /// the store and then have a stale restore write credentials back.
    fn persist_restored_refresh(
        &self,
        session: &auth::Session,
        expected_generation: u64,
        binding: &RestoreBinding,
    ) -> Result<(), String> {
        let settings = self.settings.lock().map_err(|_| "Settings poisoned")?;
        if !restore_binding_matches(&settings, binding)
            || self.auth_generation.load(Ordering::Acquire) != expected_generation
            || self.auth_transition.load(Ordering::Acquire)
            || self.shutdown.load(Ordering::Acquire)
        {
            return Err("Saved-session restore was canceled".into());
        }
        let auth_state = self
            .auth_state
            .lock()
            .map_err(|_| "Authentication state poisoned")?;
        if auth_state.engine.is_some()
            || auth_state.session.is_some()
            || self.auth_generation.load(Ordering::Acquire) != expected_generation
            || self.auth_transition.load(Ordering::Acquire)
            || self.shutdown.load(Ordering::Acquire)
        {
            return Err("Saved-session restore was canceled".into());
        }
        self.session_store.save(session)
    }

    fn load_account_namespace(
        &self,
        session: &auth::Session,
    ) -> Result<Vec<raiun_core::backend::CloudSpace>, String> {
        let settings = self
            .settings
            .lock()
            .map_err(|_| "Settings poisoned")?
            .clone();
        if settings.server.as_deref() != Some(session.server.as_str())
            || settings.client_id != session.client_id
        {
            return Err("Saved account namespace does not match the configured server".into());
        }
        let account_id = settings
            .account_id
            .ok_or("No saved account namespace is available")?;
        namespace::load(
            &account_engine_dir(&self.dir, &account_id),
            &account_id,
            &session.server,
        )
    }

    fn install_session_with_spaces(
        &self,
        session: auth::Session,
        expected_generation: u64,
        client: raiun_opencloud::OpenCloudClient,
        spaces: Vec<raiun_core::backend::CloudSpace>,
        offline: bool,
        restore_binding: Option<&RestoreBinding>,
    ) -> Result<(), String> {
        if self.auth_generation.load(Ordering::Acquire) != expected_generation
            || self.auth_transition.load(Ordering::Acquire)
            || self.shutdown.load(Ordering::Acquire)
        {
            return Err("Agent is shutting down".into());
        }
        let personal: Vec<_> = spaces.iter().filter(|space| space.personal).collect();
        if personal.len() != 1 || personal[0].id.trim().is_empty() {
            return Err("The server did not identify exactly one personal drive".into());
        }
        if !personal[0].writable || personal[0].encrypted {
            return Err("The personal drive is read-only or encrypted and cannot be synced".into());
        }
        let account_id = account_identity(&session.server, &personal[0].id);
        let transport_settings = self
            .settings
            .lock()
            .map_err(|_| "Settings poisoned")?
            .clone();
        let bandwidth_limits =
            if transport_settings.bandwidth_account_id.as_deref() == Some(account_id.as_str()) {
                transport_settings.bandwidth_limits
            } else {
                TransferLimits::default()
            };
        let transfer_budget = self.transfer_budget_for_account(&account_id, bandwidth_limits)?;
        let mut transfer_fence = TransferAdmissionFence::begin(Some(transfer_budget.clone()));
        let client = client.with_transfer_budget(transfer_budget.clone());
        if transport_settings
            .network_proxy_account_id
            .as_deref()
            .is_some_and(|bound| bound != account_id)
            && transport_settings.network_proxy != raiun_opencloud::ProxyConfig::System
        {
            return Err(
                "Proxy settings belong to a different account; reset them before switching accounts".into(),
            );
        }
        if offline
            && self
                .settings
                .lock()
                .map_err(|_| "Settings poisoned")?
                .account_id
                .as_deref()
                != Some(account_id.as_str())
        {
            return Err("Saved account namespace does not match the authenticated account".into());
        }
        let engine_dir = account_engine_dir(&self.dir, &account_id);
        let base_engine =
            Engine::open(&engine_dir, Arc::new(client.clone())).map_err(|e| e.to_string())?;
        let (engine, mut cache_error) = attach_optional_cache(
            base_engine,
            &engine_dir,
            &account_id,
            client.server_origin(),
        );
        let engine = engine
            .with_offline_spaces(spaces.clone())
            .map_err(|error| error.to_string())?;
        if offline {
            engine
                .mark_namespace_transport_unavailable()
                .map_err(|error| error.to_string())?;
        }
        // Seed the Engine's admission fence from the persisted profile before
        // the scheduler can dispatch any pair using this new backend.
        let persisted_policies = self
            .settings
            .lock()
            .map_err(|_| "Settings poisoned")?
            .clone();
        for pair in &persisted_policies.config.pairs {
            engine
                .publish_pair_policy(pair)
                .map_err(|error| error.to_string())?;
        }
        for retired_id in &persisted_policies.retired_pair_ids {
            engine
                .retire_pair_policy(retired_id)
                .map_err(|error| error.to_string())?;
        }
        if !offline {
            if let Err(error) = namespace::save(&engine_dir, &account_id, &session.server, &spaces)
            {
                cache_error = Some(match cache_error {
                    Some(previous) => format!("{previous}; account namespace unavailable: {error}"),
                    None => format!("Account namespace unavailable: {error}"),
                });
            }
        }

        // Pending work precedes settings so queue insertion and account
        // replacement cannot invert their lock order. Settings and auth remain
        // committed together to prevent a mixed account from being exposed.
        let mut pending = self
            .pending_space_syncs
            .lock()
            .map_err(|_| "Pending Space sync state poisoned")?;
        let mut settings = self.settings.lock().map_err(|_| "Settings poisoned")?;
        if self.shutdown.load(Ordering::Acquire)
            || self.auth_generation.load(Ordering::Acquire) != expected_generation
            || self.auth_transition.load(Ordering::Acquire)
            || restore_binding.is_some_and(|binding| !restore_binding_matches(&settings, binding))
        {
            return Err("Sign-in or saved-session restore was canceled".into());
        }
        if settings
            .account_id
            .as_ref()
            .is_some_and(|old| old != &account_id)
            && !settings.config.pairs.is_empty()
        {
            return Err("This state has folder pairs for another account. Remove those pairs before switching accounts.".into());
        }
        let account_changed = settings
            .account_id
            .as_ref()
            .is_some_and(|old| old != &account_id);
        let mut auth_state = self
            .auth_state
            .lock()
            .map_err(|_| "Authentication state poisoned")?;
        if self.shutdown.load(Ordering::Acquire)
            || self.auth_generation.load(Ordering::Acquire) != expected_generation
            || self.auth_transition.load(Ordering::Acquire)
        {
            return Err("Sign-in was canceled".into());
        }
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
        next.network_proxy_account_id = Some(account_id.clone());
        if next.bandwidth_account_id.as_deref() != Some(account_id.as_str()) {
            next.bandwidth_limits = TransferLimits::default();
            next.bandwidth_account_id = Some(account_id.clone());
            next.bandwidth_revision = next
                .bandwidth_revision
                .checked_add(1)
                .ok_or("Bandwidth settings revision limit reached")?;
        }
        if account_changed {
            next.paused_space_ids.clear();
            pending.clear();
        }
        self.session_store.save(&session)?;
        next.save(&self.dir)?;
        *self
            .transfer_budget
            .lock()
            .map_err(|_| "Transfer budget state poisoned")? =
            Some((account_id.clone(), transfer_budget));
        *settings = next;
        auth_state.client = Some(client);
        // A restored namespace permits read-only shell browsing while offline,
        // but it must never admit sync writes against an unverified Space map.
        engine.set_sync_paused(settings.paused || offline);
        auth_state.engine = Some(engine);
        auth_state.account_id = Some(account_id);
        auth_state.session = Some(session);
        auth_state.session_unsaved = false;
        self.offline_namespace.store(offline, Ordering::Release);
        transfer_fence.activate_and_commit();
        *self
            .cache_error
            .lock()
            .map_err(|_| "Cache status poisoned")? = cache_error;
        *self.error.lock().map_err(|_| "Error state poisoned")? = None;
        self.wake.store(true, Ordering::Release);
        drop(auth_state);
        drop(settings);
        drop(pending);
        self.mount_if_enabled(expected_generation).map_err(|error| {
            if error == "Sign-in was canceled" || error == "Agent is shutting down" {
                error
            } else {
                format!(
                    "Sign-in succeeded, but the configured OpenCloud drive could not be mounted: {error}"
                )
            }
        })?;
        Ok(())
    }

    fn mount_if_enabled(&self, expected_generation: u64) -> Result<(), String> {
        // Serialize restoration with explicit unmount/configuration updates.
        // Otherwise a stale enabled snapshot could remount after unmount wins.
        let settings = self.settings.lock().map_err(|_| "Settings poisoned")?;
        if self.shutdown.load(Ordering::Acquire)
            || self.auth_generation.load(Ordering::Acquire) != expected_generation
            || self.auth_transition.load(Ordering::Acquire)
        {
            return Err("Sign-in was canceled".into());
        }
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
        raiun_fuse::recover_stale_mount(&settings.config.cloud_root, &account_dir)?;
        let root = ensure_cloud_root(&settings.config, &self.dir, &account_dir)?;
        if !self.offline_namespace.load(Ordering::Acquire) {
            self.configure_vault_mount_routes(settings, account_id)?;
        }
        let mut mounted = self.mount.lock().map_err(|_| "Mount state poisoned")?;
        if self.shutdown.load(Ordering::Acquire) {
            return Err("Agent is shutting down".into());
        }
        if mounted.as_ref().is_some_and(|handle| !handle.is_mounted()) {
            *mounted = None;
        }
        if mounted.is_none() {
            *mounted = Some(Box::new(raiun_fuse::mount_with_vault_registry_for_profile(
                engine,
                &root,
                &account_dir,
                &self.local_profile_id,
                self.vault_mounts.clone(),
            )?));
        }
        drop(mounted);
        *self.error.lock().map_err(|_| "Error state poisoned")? = None;
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
        // Stop exposing decrypted route snapshots before the mount is detached.
        // The verified session remains unlocked for sync and a later remount.
        self.revoke_all_vault_mount_routes()?;
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
        if mounted.is_none() {
            if let Some(account_id) = settings.account_id.as_deref() {
                raiun_fuse::unmount_profile_mount(
                    &settings.config.cloud_root,
                    &account_engine_dir(&self.dir, account_id),
                )?;
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

    fn logout(&self) -> Result<(), String> {
        let _transition = AuthTransition::begin(&self.auth_transition)?;
        self.auth_generation.fetch_add(1, Ordering::AcqRel);
        let mut transfer_fence = self.fence_transfer_admission()?;
        self.vault_edit_reconcile_jobs.cancel_all_and_wait()?;
        self.vault_pin_jobs.cancel_all_and_wait()?;
        self.cache_jobs.cancel_active();
        self.write_reconcile_jobs.cancel_active();
        self.clear_pending_space_syncs()?;
        let route_error = self.revoke_all_vault_mount_routes().err();
        self.vaults
            .logout_account(&self.vault_account_id)
            .map_err(|e| e.to_string())?;
        if let Some(error) = route_error {
            return Err(error);
        }
        let prior_paused = self
            .settings
            .lock()
            .map_err(|_| "Settings poisoned")?
            .paused;
        if let Some(engine) = self
            .auth_state
            .lock()
            .map_err(|_| "Authentication state poisoned")?
            .engine
            .as_ref()
        {
            engine.set_sync_paused(true);
        }
        if let Err(error) = self.disable_mount() {
            if let Some(engine) = self
                .auth_state
                .lock()
                .map_err(|_| "Authentication state poisoned")?
                .engine
                .as_ref()
            {
                engine.set_sync_paused(prior_paused);
            }
            return Err(error);
        }
        self.vault_mounts
            .clear_revoked()
            .map_err(|error| error.to_string())?;
        // Match sign-in's settings -> auth lock order to avoid restore/logout deadlocks.
        // The sync gate must precede settings/auth so scheduler rechecks can
        // acquire a fresh settings snapshot without a lock-order cycle.
        let _sync = self.sync_gate.lock().map_err(|_| "Sync state poisoned")?;
        let mut settings = self.settings.lock().map_err(|_| "Settings poisoned")?;
        let mut auth_state = self
            .auth_state
            .lock()
            .map_err(|_| "Authentication state poisoned")?;
        if let Some(engine) = auth_state.engine.as_ref() {
            engine.set_sync_paused(true);
        }
        if let Some(account_id) = settings.account_id.as_deref() {
            namespace::remove(&account_engine_dir(&self.dir, account_id))?;
        }
        if let Some(server) = settings.server.as_deref() {
            if let Err(error) = self.session_store.remove(server, &settings.client_id) {
                if let Some(engine) = auth_state.engine.as_ref() {
                    engine.set_sync_paused(prior_paused);
                }
                return Err(error);
            }
        }
        let mut next = settings.clone();
        next.server = None;
        if let Err(error) = next.save(&self.dir) {
            if let Some(session) = auth_state.session.as_ref() {
                if let Err(restore_error) = self.session_store.save(session) {
                    if let Some(engine) = auth_state.engine.as_ref() {
                        engine.set_sync_paused(prior_paused);
                    }
                    return Err(format!(
                        "Could not save sign-out state ({error}); could not restore the saved session ({restore_error})"
                    ));
                }
            }
            if let Some(engine) = auth_state.engine.as_ref() {
                engine.set_sync_paused(prior_paused);
            }
            return Err(format!("Could not save sign-out state: {error}"));
        }
        *settings = next;
        auth_state.engine = None;
        auth_state.session = None;
        auth_state.client = None;
        auth_state.account_id = None;
        auth_state.session_unsaved = false;
        *self.error.lock().map_err(|_| "Error state poisoned")? = None;
        *self
            .refresh_error
            .lock()
            .map_err(|_| "Refresh status poisoned")? = None;
        self.pair_reports
            .lock()
            .map_err(|_| "Pair report state poisoned")?
            .clear();
        drop(auth_state);
        drop(settings);
        #[cfg(not(test))]
        match vault_secrets::revoke_profile(&self.dir, &self.vault_account_id) {
            Ok(cleanup) => self.vault_cleanup_uncertain.store(
                cleanup == vault_secrets::CredentialCleanup::Uncertain,
                Ordering::Release,
            ),
            Err(error) => {
                return Err(format!(
                    "Signed out, but remembered vault-password access could not be revoked: {error}"
                ));
            }
        }
        self.wake.store(true, Ordering::Release);
        transfer_fence.commit_paused();
        Ok(())
    }

    fn shutdown_safely(&self) -> Result<(), String> {
        if self.shutdown.load(Ordering::Acquire) {
            return Ok(());
        }
        let _transition = AuthTransition::begin(&self.auth_transition)?;
        self.auth_generation.fetch_add(1, Ordering::AcqRel);
        let mut transfer_fence = self.fence_transfer_admission()?;
        self.vault_edit_reconcile_jobs.cancel_all_and_wait()?;
        self.vault_pin_jobs.cancel_all_and_wait()?;
        self.cache_jobs.cancel_active();
        self.write_reconcile_jobs.cancel_active();
        self.clear_pending_space_syncs()?;
        let route_error = self.revoke_all_vault_mount_routes().err();
        self.vaults
            .logout_account(&self.vault_account_id)
            .map_err(|e| e.to_string())?;
        if let Some(error) = route_error {
            return Err(error);
        }
        let engine = self
            .auth_state
            .lock()
            .map_err(|_| "Authentication state poisoned")?
            .engine
            .clone();
        if let Some(engine) = engine {
            engine.set_sync_paused(true);
        }
        let _sync = self.sync_gate.lock().map_err(|_| "Sync state poisoned")?;
        let settings = self
            .settings
            .lock()
            .map_err(|_| "Settings poisoned")?
            .clone();
        let auth_state = self
            .auth_state
            .lock()
            .map_err(|_| "Authentication state poisoned")?;
        let mut mount = self.mount.lock().map_err(|_| "Mount state poisoned")?;
        if let Some(handle) = mount.as_mut() {
            match handle.unmount() {
                Ok(()) => *mount = None,
                Err(error) if handle.is_mounted() => {
                    if let Some(engine) = auth_state.engine.as_ref() {
                        engine.set_sync_paused(settings.paused);
                    }
                    return Err(format!(
                        "Could not stop Raiun because the cloud root is still mounted: {error}"
                    ));
                }
                Err(error) => {
                    *mount = None;
                    if let Ok(mut status_error) = self.error.lock() {
                        *status_error = Some(format!(
                            "Cloud root unmounted with a shutdown error: {error}"
                        ));
                    }
                }
            }
        }
        if mount.is_none() {
            if let Some(account_id) = settings.account_id.as_deref() {
                if let Err(error) = raiun_fuse::unmount_profile_mount(
                    &settings.config.cloud_root,
                    &account_engine_dir(&self.dir, account_id),
                ) {
                    if let Some(engine) = auth_state.engine.as_ref() {
                        engine.set_sync_paused(settings.paused);
                    }
                    return Err(format!(
                        "Could not stop Raiun because the cloud root is still mounted: {error}"
                    ));
                }
            }
        }
        self.vault_mounts
            .clear_revoked()
            .map_err(|error| error.to_string())?;
        self.shutdown.store(true, Ordering::Release);
        transfer_fence.commit_paused();
        Ok(())
    }

    fn refresh_session(&self) -> Result<(), String> {
        if self.shutdown.load(Ordering::Acquire) {
            return Ok(());
        }
        let settings = self
            .settings
            .lock()
            .map_err(|_| "Settings poisoned")?
            .clone();
        if settings
            .network_proxy_account_id
            .as_deref()
            .is_some_and(|bound| settings.account_id.as_deref() != Some(bound))
        {
            return Err("Proxy configuration is bound to a different account".into());
        }
        settings
            .network_proxy
            .validate()
            .map_err(|_| "Proxy configuration is invalid")?;
        let settings_paused = settings.paused;
        let mut state = self
            .auth_state
            .lock()
            .map_err(|_| "Authentication state poisoned")?;
        if state.session.is_none() {
            return Ok(());
        }
        if let Some(engine) = state.engine.as_ref() {
            self.observe_engine_namespace_state(engine);
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "System clock is invalid")?
            .as_secs();
        let (token, refreshed) = {
            let session = state.session.as_mut().ok_or("Session disappeared")?;
            session.proxy = settings.network_proxy.clone();
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
        let offline_namespace = self.offline_namespace.load(Ordering::Acquire);
        let last_probe = self.offline_namespace_probe_unix.load(Ordering::Acquire);
        let namespace_probe_due = offline_namespace
            && (refreshed || now.saturating_sub(last_probe) >= 60)
            && self
                .offline_namespace_probe_unix
                .compare_exchange(last_probe, now, Ordering::AcqRel, Ordering::Acquire)
                .is_ok();
        if namespace_probe_due {
            let session = state.session.as_ref().ok_or("Session disappeared")?;
            let engine = state.engine.as_ref().ok_or("Offline engine disappeared")?;
            // A successful refresh is not enough to trust a new namespace.
            // Probe without publishing so the application-specific account
            // identity check below runs before mounted Engine clones can see
            // any changed Space map.
            let probe_client = state.client.as_ref().ok_or("Offline client disappeared")?;
            let snapshot = probe_client
                .with_bounded_namespace_probe(|| engine.probe_live_namespace())
                .map_err(|error| error.to_string())?;
            let spaces = snapshot.spaces();
            let personal: Vec<_> = spaces.iter().filter(|space| space.personal).collect();
            if personal.len() != 1
                || !personal[0].writable
                || personal[0].encrypted
                || account_identity(&session.server, &personal[0].id)
                    != state.account_id.as_deref().unwrap_or_default()
            {
                engine
                    .reject_live_namespace(snapshot)
                    .map_err(|error| error.to_string())?;
                return Err("Authenticated account identity changed while offline".into());
            }
            let account_id = state
                .account_id
                .as_deref()
                .ok_or("Account identity is unavailable")?;
            let engine_dir = account_engine_dir(&self.dir, account_id);
            let spaces = engine
                .publish_live_namespace(snapshot)
                .map_err(|error| error.to_string())?;
            if let Err(error) = namespace::save(&engine_dir, account_id, &session.server, &spaces) {
                *self
                    .cache_error
                    .lock()
                    .map_err(|_| "Cache status poisoned")? =
                    Some(format!("Could not update account namespace: {error}"));
            }
            // Offline mode gated sync temporarily without changing the saved
            // pause preference. Reconnect releases only that temporary gate.
            engine.set_sync_paused(settings_paused);
            self.offline_namespace.store(false, Ordering::Release);
            self.offline_namespace_probe_unix
                .store(0, Ordering::Release);
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
        let engine = self
            .auth_state
            .lock()
            .map_err(|_| "Authentication state poisoned")?
            .engine
            .clone()
            .ok_or_else(|| "Sign in first".to_owned())?;
        self.observe_engine_namespace_state(&engine);
        Ok(engine)
    }

    /// Promote the Engine's shared transport-offline signal into Runtime's
    /// account/session state. Mounted Engine clones can discover an outage
    /// from a namespace read without going through Runtime; reflect that
    /// result in status and arm the authenticated recovery probe on the next
    /// scheduler pass. Only validated recovery clears this Runtime flag.
    fn observe_engine_namespace_state(&self, engine: &Engine) -> bool {
        if engine.namespace_transport_unavailable() {
            self.offline_namespace.store(true, Ordering::Release);
        }
        self.offline_namespace.load(Ordering::Acquire)
    }

    fn saved_write_account_scope(settings: &Settings) -> Option<String> {
        use sha2::{Digest, Sha256};
        let server = settings.server.as_deref()?;
        let account = settings.account_id.as_deref()?;
        let bytes = serde_json::to_vec(&("raiun-saved-edit-account-v1", server, account)).ok()?;
        Some(format!("{:x}", Sha256::digest(bytes)))
    }

    fn pending_write_page(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<raiun_cache::PendingWritePage, String> {
        if let Ok(engine) = self.engine() {
            return engine
                .pending_file_writes(after, limit)
                .map_err(|error| error.to_string());
        }
        let account_id = self
            .settings
            .lock()
            .map_err(|_| "Settings poisoned")?
            .account_id
            .clone()
            .ok_or("No saved account cache is available")?;
        let engine_dir = account_engine_dir(&self.dir, &account_id);
        let cache_dir = engine_dir.join("offline-cache-state");
        match fs::symlink_metadata(&cache_dir) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(raiun_cache::PendingWritePage {
                    items: Vec::new(),
                    pending_count: 0,
                    conflict_count: 0,
                    next_after: None,
                    truncated: false,
                });
            }
            Err(error) => return Err(error.to_string()),
            Ok(metadata) if !metadata.is_dir() || metadata.file_type().is_symlink() => {
                return Err("Offline cache directory is unsafe".into());
            }
            Ok(_) => {}
        }
        let cache = raiun_cache::Cache::open(&cache_dir, offline_cache::DEFAULT_CACHE_QUOTA_BYTES)
            .map_err(|error| error.to_string())?;
        cache
            .pending_write_page_for_account(&account_id, after, limit)
            .map_err(|error| error.to_string())
    }

    fn space_is_known(&self, space_id: &str) -> Result<bool, String> {
        if self
            .settings
            .lock()
            .map_err(|_| "Settings poisoned")?
            .config
            .pairs
            .iter()
            .any(|pair| pair.space_id == space_id)
        {
            return Ok(true);
        }
        Ok(self
            .engine()?
            .spaces()
            .map_err(|error| error.to_string())?
            .iter()
            .any(|space| space.id == space_id))
    }

    fn active_media_engine(
        &self,
        expected_account: Option<&str>,
    ) -> Result<(u64, String, Engine), String> {
        let generation = self.operation_generation()?;
        if self.offline_namespace.load(Ordering::Acquire) {
            return Err("Media backup needs a freshly connected account".into());
        }
        let account_id = self
            .settings
            .lock()
            .map_err(|_| "Settings poisoned")?
            .account_id
            .clone()
            .ok_or("Sign in to the account that owns this backup")?;
        if expected_account.is_some_and(|expected| expected != account_id) {
            return Err(
                "The selected account changed; reload Media backups before continuing".into(),
            );
        }
        let state = self
            .auth_state
            .lock()
            .map_err(|_| "Authentication state poisoned")?;
        if state.account_id.as_deref() != Some(account_id.as_str()) {
            return Err("The authenticated account does not match the selected profile".into());
        }
        let engine = state.engine.clone().ok_or("Sign in first")?;
        if self.auth_generation.load(Ordering::Acquire) != generation
            || self.auth_transition.load(Ordering::Acquire)
        {
            return Err("The active account changed; retry the media request".into());
        }
        Ok((generation, account_id, engine))
    }

    fn validate_live_media_destination(
        &self,
        engine: &Engine,
        space_id: &str,
        path: &str,
    ) -> Result<raiun_core::backend::RemoteEntry, String> {
        validate_space_id(space_id)?;
        validate_remote_path(path).map_err(|_| "Choose a valid existing destination folder")?;
        if path == "/" {
            return Err("Choose a folder below the location root".into());
        }
        let spaces = engine.live_spaces().map_err(|error| error.to_string())?;
        let space = spaces
            .iter()
            .find(|space| space.id == space_id)
            .ok_or("The selected location is no longer available")?;
        if !space.writable || space.encrypted {
            return Err("Media backup needs a writable, unencrypted location".into());
        }
        let entry = engine
            .live_stat(space_id, path)
            .map_err(|error| error.to_string())?;
        if entry.path != path || !entry.directory || !entry.writable || entry.encrypted {
            return Err("Choose an existing writable folder in an unencrypted location".into());
        }
        Ok(entry)
    }

    fn media_jobs_value(&self) -> Result<Value, String> {
        let settings = self
            .settings
            .lock()
            .map_err(|_| "Settings poisoned")?
            .clone();
        let active_account = if self.auth_transition.load(Ordering::Acquire) {
            None
        } else {
            let auth_account = self
                .auth_state
                .lock()
                .map_err(|_| "Authentication state poisoned")?
                .account_id
                .clone();
            settings
                .account_id
                .clone()
                .filter(|account| auth_account.as_deref() == Some(account.as_str()))
        };
        let generation = self.auth_generation.load(Ordering::Acquire);
        let queued = self
            .pending_media_jobs
            .lock()
            .map_err(|_| "Media job queue poisoned")?
            .clone();
        let jobs = settings
            .media_jobs
            .iter()
            .map(|job| {
                let active = active_account.as_deref() == Some(job.account_id.as_str());
                let status = Engine::media_import_status_at(
                    &account_engine_dir(&self.dir, &job.account_id),
                    &job.id,
                )
                .map_err(|error| error.to_string())?;
                let is_queued = active
                    && queued.get(&job.id).is_some_and(|pending| {
                        pending.revision == job.revision && pending.auth_generation == generation
                    });
                Ok(json!({
                    "job": job,
                    "status": status,
                    "queued": is_queued,
                    "active_account": active,
                }))
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(json!({"account_id": active_account, "jobs": jobs}))
    }

    fn media_job_recovery_value(&self, request: &Value) -> Result<Value, String> {
        let job_id = request
            .get("job_id")
            .and_then(Value::as_str)
            .ok_or("Missing job_id")?;
        let expected_revision = request
            .get("expected_revision")
            .and_then(Value::as_u64)
            .ok_or("Missing expected_revision")?;
        let expected_account = request
            .get("expected_account_id")
            .and_then(Value::as_str)
            .ok_or("Missing expected_account_id")?;
        let limit = request
            .get("limit")
            .and_then(Value::as_u64)
            .and_then(|limit| usize::try_from(limit).ok())
            .ok_or("Missing or invalid limit")?;
        let cursor = request
            .get("cursor")
            .filter(|value| !value.is_null())
            .cloned()
            .map(serde_json::from_value::<MediaImportRecoveryCursor>)
            .transpose()
            .map_err(|_| "Invalid recovery cursor")?;
        let generation = self.auth_generation.load(Ordering::Acquire);
        if self.auth_transition.load(Ordering::Acquire) {
            return Err("An account transition is in progress".into());
        }
        let settings = self
            .settings
            .lock()
            .map_err(|_| "Settings poisoned")?
            .clone();
        if settings.account_id.as_deref() != Some(expected_account) {
            return Err("Media recovery belongs to another saved account".into());
        }
        let job = settings
            .media_jobs
            .iter()
            .find(|job| job.id == job_id)
            .ok_or("Media backup was not found")?;
        if job.account_id != expected_account || job.revision != expected_revision {
            return Err("Media backup changed or belongs to another account".into());
        }
        let page = Engine::media_import_recovery_at(
            &account_engine_dir(&self.dir, expected_account),
            job_id,
            expected_account,
            limit,
            cursor.as_ref(),
        )
        .map_err(|_| "Could not read local media recovery status")?;
        if self.auth_transition.load(Ordering::Acquire)
            || self.auth_generation.load(Ordering::Acquire) != generation
        {
            return Err("The active account changed while reading media recovery status".into());
        }
        let current = self.settings.lock().map_err(|_| "Settings poisoned")?;
        if current.account_id.as_deref() != Some(expected_account)
            || current
                .media_jobs
                .iter()
                .find(|candidate| candidate.id == job_id)
                .is_none_or(|candidate| {
                    candidate.account_id != expected_account
                        || candidate.revision != expected_revision
                })
        {
            return Err("Media backup changed while reading recovery status".into());
        }
        Ok(json!({
            "job_id": job_id,
            "account_id": expected_account,
            "revision": expected_revision,
            "page": page,
        }))
    }

    fn media_job_verify_upload(&self, request: &Value) -> Result<Value, String> {
        let job_id = request
            .get("job_id")
            .and_then(Value::as_str)
            .ok_or("Missing job_id")?;
        let revision = request
            .get("expected_revision")
            .and_then(Value::as_u64)
            .ok_or("Missing expected_revision")?;
        let expected_account = request
            .get("expected_account_id")
            .and_then(Value::as_str)
            .ok_or("Missing expected_account_id")?;
        let attempt = request
            .get("attempt_generation")
            .and_then(Value::as_u64)
            .filter(|value| *value > 0 && *value <= i64::MAX as u64)
            .ok_or("Invalid attempt_generation")?;
        let source = request
            .get("source_relative_path")
            .and_then(Value::as_str)
            .ok_or("Missing source_relative_path")?;
        let destination = request
            .get("destination_path")
            .and_then(Value::as_str)
            .ok_or("Missing destination_path")?;
        let (generation, account, engine) = self.active_media_engine(Some(expected_account))?;
        let _sync = self.sync_gate.lock().map_err(|_| "Sync state poisoned")?;
        let settings = self
            .settings
            .lock()
            .map_err(|_| "Settings poisoned")?
            .clone();
        let job = settings
            .media_jobs
            .iter()
            .find(|job| job.id == job_id && job.account_id == account && job.revision == revision)
            .ok_or("Media backup changed; reload retained copies")?;
        let job_settings_root = settings.config.cloud_root.clone();
        let current = || -> Result<(), String> {
            if self.auth_transition.load(Ordering::Acquire)
                || self.shutdown.load(Ordering::Acquire)
                || self.offline_namespace.load(Ordering::Acquire)
                || self.auth_generation.load(Ordering::Acquire) != generation
            {
                return Err("The active account changed during verification".into());
            }
            let settings = self.settings.lock().map_err(|_| "Settings poisoned")?;
            if settings.account_id.as_deref() != Some(account.as_str())
                || settings.config.cloud_root != job_settings_root
                || settings
                    .media_jobs
                    .iter()
                    .find(|candidate| candidate.id == job_id)
                    != Some(job)
            {
                return Err("Media backup changed during verification".into());
            }
            Ok(())
        };
        current()?;
        // No queueing, receipt commit or cleanup, even when the bytes match.
        let verified = engine.verify_media_import_upload(job, attempt, source, destination);
        current()?;
        let matched = verified.map_err(
            |_| "Could not safely verify the uploaded copy. Retained recovery is unchanged.",
        )?;
        Ok(
            json!({"job_id":job_id,"account_id":account,"revision":revision,
            "attempt_generation":attempt,"source_relative_path":source,"destination_path":destination,
            "status":if matched { "matched" } else { "not_matched" },
            "recovery_retained":true,"backup_resumed":false}),
        )
    }

    fn media_destination(&self, request: &Value) -> Result<Value, String> {
        let space_id = request
            .get("space_id")
            .and_then(Value::as_str)
            .ok_or("Missing space_id")?;
        let path = request
            .get("path")
            .and_then(Value::as_str)
            .ok_or("Missing path")?;
        let (generation, account_id, engine) = self.active_media_engine(None)?;
        let entry = self.validate_live_media_destination(&engine, space_id, path)?;
        if self.auth_generation.load(Ordering::Acquire) != generation
            || self.auth_transition.load(Ordering::Acquire)
        {
            return Err("The active account changed during destination validation".into());
        }
        Ok(json!({"id":entry.id,"path":entry.path,"space_id":space_id,"account_id":account_id}))
    }

    fn media_job_set(&self, request: &Value) -> Result<Value, String> {
        let expected_revision = request
            .get("expected_revision")
            .and_then(Value::as_u64)
            .ok_or("Missing expected_revision")?;
        let expected_account = request
            .get("expected_account_id")
            .and_then(Value::as_str)
            .ok_or("Missing expected_account_id")?;
        let mut job: MediaImportJob =
            serde_json::from_value(request.get("job").cloned().ok_or("Missing job")?)
                .map_err(|_| "Invalid media job")?;
        let generation = self.operation_generation()?;
        let _sync = self.sync_gate.lock().map_err(|_| "Sync state poisoned")?;
        if self.auth_transition.load(Ordering::Acquire)
            || self.shutdown.load(Ordering::Acquire)
            || self.auth_generation.load(Ordering::Acquire) != generation
        {
            return Err("Media job update was canceled by an account change".into());
        }
        let snapshot = self
            .settings
            .lock()
            .map_err(|_| "Settings poisoned")?
            .clone();
        let existing = snapshot
            .media_jobs
            .iter()
            .find(|item| item.id == job.id)
            .cloned();
        match existing.as_ref() {
            Some(old) => {
                if old.revision != expected_revision || old.account_id != expected_account {
                    return Err("Media backup changed; refresh and try again".into());
                }
                if job.account_id != old.account_id {
                    return Err("A media backup cannot be moved between accounts".into());
                }
                job.revision = old
                    .revision
                    .checked_add(1)
                    .ok_or("Media backup revision is exhausted")?;
            }
            None => {
                if expected_revision != 0 || job.revision != 0 {
                    return Err("A new media backup must start at revision zero".into());
                }
                if job.account_id != expected_account {
                    return Err(
                        "Media backup account binding does not match the destination".into(),
                    );
                }
                job.revision = 1;
            }
        }
        let enabled_only = existing.as_ref().is_some_and(|old| {
            let mut comparable = old.clone();
            comparable.enabled = job.enabled;
            comparable.revision = job.revision;
            comparable == job
        });
        let active_account = snapshot.account_id.as_deref() == Some(expected_account);
        if job.enabled || !enabled_only {
            if !active_account || job.account_id != expected_account {
                return Err(
                    "Only pause or removal is allowed for a backup owned by another account".into(),
                );
            }
            if self.offline_namespace.load(Ordering::Acquire) {
                return Err("Connect before creating or changing a media backup".into());
            }
            let (auth_account, engine) = {
                let auth = self
                    .auth_state
                    .lock()
                    .map_err(|_| "Authentication state poisoned")?;
                (auth.account_id.clone(), auth.engine.clone())
            };
            if auth_account.as_deref() != Some(expected_account) {
                return Err("The authenticated account changed; reload Media backups".into());
            }
            let engine = engine.ok_or("Sign in first")?;
            let entry = self.validate_live_media_destination(
                &engine,
                &job.space_id,
                &job.destination_root,
            )?;
            if entry.id != job.destination_root_resource_id {
                return Err("The destination folder identity changed; choose it again".into());
            }
            self.validate_media_source_overlap(&snapshot, &job, Some(&job.id))?;
        }
        let mut current = self.settings.lock().map_err(|_| "Settings poisoned")?;
        if current.account_id != snapshot.account_id
            || current.media_jobs.iter().find(|item| item.id == job.id) != existing.as_ref()
            || self.auth_transition.load(Ordering::Acquire)
            || self.auth_generation.load(Ordering::Acquire) != generation
        {
            return Err(
                "Media backup changed while it was being validated; refresh and try again".into(),
            );
        }
        let mut next = current.clone();
        if let Some(existing_index) = next.media_jobs.iter().position(|item| item.id == job.id) {
            next.media_jobs[existing_index] = job.clone();
        } else {
            next.media_jobs.push(job.clone());
        }
        validate_media_import_jobs(&next.media_jobs)?;
        next.save(&self.dir)?;
        *current = next;
        self.pending_media_jobs
            .lock()
            .map_err(|_| "Media job queue poisoned")?
            .remove(&job.id);
        self.wake.store(true, Ordering::Release);
        Ok(json!({"job":job}))
    }

    fn validate_media_source_overlap(
        &self,
        settings: &Settings,
        candidate: &MediaImportJob,
        excluding_id: Option<&str>,
    ) -> Result<(), String> {
        for (label, path) in std::iter::once(("cloud folder", settings.config.cloud_root.as_path()))
            .chain(std::iter::once(("agent state", self.dir.as_path())))
            .chain(
                settings
                    .config
                    .pairs
                    .iter()
                    .map(|pair| ("folder pair", pair.local_path.as_path())),
            )
        {
            if paths_overlap_existing(&candidate.source_root, path) {
                return Err(format!("Media source overlaps the configured {label}"));
            }
        }
        for other in settings.media_jobs.iter().filter(|other| {
            Some(other.id.as_str()) != excluding_id && other.account_id == candidate.account_id
        }) {
            if paths_overlap_existing(&candidate.source_root, &other.source_root) {
                return Err("Media source overlaps another backup source".into());
            }
            if other.space_id == candidate.space_id
                && other.destination_root == candidate.destination_root
            {
                return Err(
                    "Another backup already targets this source and destination binding".into(),
                );
            }
        }
        Ok(())
    }

    fn media_job_run(&self, request: &Value) -> Result<Value, String> {
        let job_id = request
            .get("job_id")
            .and_then(Value::as_str)
            .ok_or("Missing job_id")?;
        let expected_revision = request
            .get("expected_revision")
            .and_then(Value::as_u64)
            .ok_or("Missing expected_revision")?;
        let expected_account = request
            .get("expected_account_id")
            .and_then(Value::as_str)
            .ok_or("Missing expected_account_id")?;
        let (generation, account_id, _) = self.active_media_engine(Some(expected_account))?;
        let _sync = self.sync_gate.lock().map_err(|_| "Sync state poisoned")?;
        if self.auth_transition.load(Ordering::Acquire)
            || self.auth_generation.load(Ordering::Acquire) != generation
        {
            return Err(
                "The active account changed; reload Media backups before running it".into(),
            );
        }
        let settings = self
            .settings
            .lock()
            .map_err(|_| "Settings poisoned")?
            .clone();
        let job = settings
            .media_jobs
            .iter()
            .find(|job| job.id == job_id)
            .ok_or("Media backup was not found")?;
        if job.revision != expected_revision || job.account_id != account_id {
            return Err(
                "Media backup changed or belongs to another account; refresh and try again".into(),
            );
        }
        if !job.enabled
            || settings.paused
            || settings
                .paused_space_ids
                .iter()
                .any(|space| space == &job.space_id)
        {
            return Err("Resume this media backup and unpause its Space before running it".into());
        }
        if self.auth_transition.load(Ordering::Acquire)
            || self.auth_generation.load(Ordering::Acquire) != generation
        {
            return Err(
                "The active account changed; reload Media backups before running it".into(),
            );
        }
        let mut pending = self
            .pending_media_jobs
            .lock()
            .map_err(|_| "Media job queue poisoned")?;
        if let Some(active) = pending.get(job_id) {
            if active.revision == expected_revision && active.auth_generation == generation {
                return Ok(
                    json!({"accepted":true,"job_id":job_id,"revision":expected_revision,"queued":true}),
                );
            }
        }
        pending.insert(
            job_id.to_owned(),
            PendingMediaJob {
                revision: expected_revision,
                auth_generation: generation,
            },
        );
        self.wake.store(true, Ordering::Release);
        Ok(json!({"accepted":true,"job_id":job_id,"revision":expected_revision,"queued":true}))
    }

    fn media_job_remove(&self, request: &Value) -> Result<Value, String> {
        let job_id = request
            .get("job_id")
            .and_then(Value::as_str)
            .ok_or("Missing job_id")?;
        let expected_revision = request
            .get("expected_revision")
            .and_then(Value::as_u64)
            .ok_or("Missing expected_revision")?;
        let expected_account = request
            .get("expected_account_id")
            .and_then(Value::as_str)
            .ok_or("Missing expected_account_id")?;
        if job_id.is_empty() || job_id.len() > 128 {
            return Err("Invalid media job ID".into());
        }
        let generation = self.operation_generation()?;
        let _sync = self.sync_gate.lock().map_err(|_| "Sync state poisoned")?;
        if self.auth_transition.load(Ordering::Acquire)
            || self.auth_generation.load(Ordering::Acquire) != generation
        {
            return Err("Media backup removal was canceled by an account change".into());
        }
        let mut current = self.settings.lock().map_err(|_| "Settings poisoned")?;
        let job = current
            .media_jobs
            .iter()
            .find(|job| job.id == job_id)
            .cloned()
            .ok_or("Media backup was not found")?;
        if job.revision != expected_revision || job.account_id != expected_account {
            return Err("Media backup changed; refresh and try again".into());
        }
        let account_dir = account_engine_dir(&self.dir, &job.account_id);
        if Engine::media_import_has_unresolved_at(&account_dir, job_id)
            .map_err(|error| error.to_string())?
        {
            return Err("This backup has a retained upload or recovery copy. Resolve it before removing the schedule.".into());
        }
        let mut next = current.clone();
        next.media_jobs.retain(|entry| entry.id != job_id);
        next.save(&self.dir)?;
        *current = next;
        self.pending_media_jobs
            .lock()
            .map_err(|_| "Media job queue poisoned")?
            .remove(job_id);
        Ok(json!({"removed":true,"job_id":job_id}))
    }

    fn run_media_imports(&self, generation: u64, allow_recurring: bool) {
        let Ok(settings) = self.settings.lock().map(|settings| settings.clone()) else {
            return;
        };
        let active_account = settings.account_id.clone();
        if settings.paused
            || active_account.is_none()
            || self.offline_namespace.load(Ordering::Acquire)
        {
            return;
        }
        let queued = self.pending_media_jobs.lock().ok().and_then(|pending| {
            select_queued_media_job(
                &settings,
                &pending,
                generation,
                active_account.as_deref().unwrap_or_default(),
            )
        });
        let recurring = if queued.is_none() && allow_recurring {
            let now = now_unix() as i64;
            settings
                .media_jobs
                .iter()
                .find(|job| {
                    job.enabled
                        && job.account_id == active_account.as_deref().unwrap_or_default()
                        && !settings
                            .paused_space_ids
                            .iter()
                            .any(|space| space == &job.space_id)
                        && Engine::media_import_status_at(
                            &account_engine_dir(&self.dir, &job.account_id),
                            &job.id,
                        )
                        .ok()
                        .flatten()
                        .is_none_or(|status| {
                            media_job_is_due(Some(&status), now, job.interval_seconds)
                        })
                        && !Engine::media_import_has_unresolved_at(
                            &account_engine_dir(&self.dir, &job.account_id),
                            &job.id,
                        )
                        .unwrap_or(true)
                })
                .cloned()
        } else {
            None
        };
        let Some(job) = queued.or(recurring) else {
            return;
        };
        if !job.enabled
            || settings
                .paused_space_ids
                .iter()
                .any(|space| space == &job.space_id)
        {
            return;
        }
        let Ok(_sync) = self.sync_gate.lock() else {
            return;
        };
        if !schedule_generation_is_current(
            generation,
            self.auth_generation.load(Ordering::Acquire),
            self.auth_transition.load(Ordering::Acquire),
            self.shutdown.load(Ordering::Acquire),
        ) {
            return;
        }
        let Ok(current) = self.settings.lock().map(|settings| settings.clone()) else {
            return;
        };
        let Some(current_job) = current
            .media_jobs
            .iter()
            .find(|candidate| candidate.id == job.id)
        else {
            return;
        };
        if current_job != &job
            || current.account_id.as_deref() != Some(job.account_id.as_str())
            || current.paused
            || current
                .paused_space_ids
                .iter()
                .any(|space| space == &job.space_id)
        {
            return;
        }
        if self.offline_namespace.load(Ordering::Acquire) {
            return;
        }
        let Ok(engine) = self.engine() else {
            return;
        };
        if let Err(error) = self.validate_media_source_overlap(&current, &job, Some(&job.id)) {
            let _ = engine.record_media_import_attention(&job.id, &error);
            if let Ok(mut pending) = self.pending_media_jobs.lock()
                && pending.get(&job.id).is_some_and(|binding| {
                    binding.revision == job.revision && binding.auth_generation == generation
                })
            {
                pending.remove(&job.id);
            }
            return;
        }
        let result = engine.run_media_import_job_cancellable(&job, &|| {
            if self.shutdown.load(Ordering::Acquire)
                || self.auth_transition.load(Ordering::Acquire)
                || self.auth_generation.load(Ordering::Acquire) != generation
                || self.offline_namespace.load(Ordering::Acquire)
            {
                return true;
            }
            self.settings
                .lock()
                .map(|settings| {
                    settings.paused
                        || settings
                            .paused_space_ids
                            .iter()
                            .any(|space| space == &job.space_id)
                        || !settings
                            .media_jobs
                            .iter()
                            .any(|candidate| candidate == &job)
                })
                .unwrap_or(true)
        });
        if result.is_err() {
            // Engine status contains the truthful interrupted/attention state.
        }
        if let Ok(mut pending) = self.pending_media_jobs.lock() {
            if pending.get(&job.id).is_some_and(|binding| {
                binding.revision == job.revision && binding.auth_generation == generation
            }) {
                pending.remove(&job.id);
            }
        }
    }

    fn clear_pending_space_syncs(&self) -> Result<(), String> {
        self.pending_space_syncs
            .lock()
            .map_err(|_| "Pending Space sync state poisoned")?
            .clear();
        Ok(())
    }

    fn network_proxy_value(&self) -> Result<Value, String> {
        let settings = self.settings.lock().map_err(|_| "Settings poisoned")?;
        Ok(json!({
            "proxy": settings.network_proxy,
            "account_id": settings.account_id,
            "revision": settings.network_proxy_revision,
            "apply_requires_reconnect": true,
        }))
    }

    fn set_network_proxy(&self, request: &Value) -> Result<Value, String> {
        if self.auth_transition.load(Ordering::Acquire)
            || self.authenticating.load(Ordering::Acquire)
            || self.restoring.load(Ordering::Acquire)
            || self.shutdown.load(Ordering::Acquire)
        {
            return Err("Disconnect and reconnect before changing proxy settings".into());
        }
        let proxy_value = request
            .get("proxy")
            .cloned()
            .ok_or("Missing proxy configuration")?;
        let proxy: raiun_opencloud::ProxyConfig =
            serde_json::from_value(proxy_value).map_err(|_| "Proxy configuration is invalid")?;
        proxy
            .validate()
            .map_err(|_| "Proxy configuration is invalid")?;
        let expected_revision = request
            .get("expected_revision")
            .and_then(Value::as_u64)
            .ok_or("Missing proxy configuration revision")?;
        let expected_account_id = match request.get("expected_account_id") {
            Some(Value::String(account_id)) => Some(account_id.as_str()),
            Some(Value::Null) => None,
            _ => return Err("Missing proxy account binding".into()),
        };

        let mut settings = self.settings.lock().map_err(|_| "Settings poisoned")?;
        if settings.network_proxy_revision != expected_revision
            || settings.account_id.as_deref() != expected_account_id
        {
            return Err("Proxy settings changed; refresh and try again".into());
        }
        if self.authenticating.load(Ordering::Acquire)
            || self.auth_transition.load(Ordering::Acquire)
            || self.restoring.load(Ordering::Acquire)
        {
            return Err("Disconnect and reconnect before changing proxy settings".into());
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
            return Err("Disconnect and reconnect before changing proxy settings".into());
        }
        if settings.network_proxy_revision.checked_add(1).is_none() {
            return Err("Proxy settings revision limit reached".into());
        }
        let mut next = settings.clone();
        next.network_proxy = proxy;
        next.network_proxy_account_id = next.account_id.clone();
        next.network_proxy_revision += 1;
        next.save(&self.dir)?;
        let value = json!({
            "proxy": next.network_proxy,
            "account_id": next.account_id,
            "revision": next.network_proxy_revision,
            "apply_requires_reconnect": true,
        });
        *settings = next;
        Ok(value)
    }

    fn bandwidth_limits_value(&self) -> Result<Value, String> {
        let settings = self.settings.lock().map_err(|_| "Settings poisoned")?;
        let account_id = settings.account_id.clone();
        let limits = if settings.bandwidth_account_id == account_id {
            settings.bandwidth_limits
        } else {
            TransferLimits::default()
        };
        let active_owner = {
            let auth = self
                .auth_state
                .lock()
                .map_err(|_| "Authentication state poisoned")?;
            if auth.engine.is_some() && auth.client.is_some() {
                auth.account_id.clone()
            } else {
                None
            }
        };
        let applied_immediately = active_owner == account_id
            && self
                .transfer_budget
                .lock()
                .map_err(|_| "Transfer budget state poisoned")?
                .as_ref()
                .is_some_and(|(owner, _)| Some(owner) == account_id.as_ref());
        Ok(json!({
            "limits": limits,
            "account_id": account_id,
            "revision": settings.bandwidth_revision,
            "apply_immediately": applied_immediately,
        }))
    }

    fn set_bandwidth_limits(&self, request: &Value) -> Result<Value, String> {
        if self.auth_transition.load(Ordering::Acquire)
            || self.authenticating.load(Ordering::Acquire)
            || self.restoring.load(Ordering::Acquire)
            || self.shutdown.load(Ordering::Acquire)
        {
            return Err(
                "Wait for the current account connection before changing bandwidth limits".into(),
            );
        }
        let limits_value = request
            .get("limits")
            .cloned()
            .ok_or("Missing bandwidth limits")?;
        let limits: TransferLimits =
            serde_json::from_value(limits_value).map_err(|_| "Bandwidth limits are invalid")?;
        limits
            .validate()
            .map_err(|_| "Bandwidth limits are invalid")?;
        let expected_revision = request
            .get("expected_revision")
            .and_then(Value::as_u64)
            .ok_or("Missing bandwidth configuration revision")?;
        let expected_account_id = match request.get("expected_account_id") {
            Some(Value::String(account_id)) if !account_id.is_empty() => account_id.as_str(),
            _ => return Err("Missing bandwidth account binding".into()),
        };

        let mut settings = self.settings.lock().map_err(|_| "Settings poisoned")?;
        if settings.bandwidth_revision != expected_revision
            || settings.account_id.as_deref() != Some(expected_account_id)
            || (settings.bandwidth_account_id.is_some()
                && settings.bandwidth_account_id.as_deref() != Some(expected_account_id))
        {
            return Err("Bandwidth settings changed; refresh and try again".into());
        }
        if self.authenticating.load(Ordering::Acquire)
            || self.auth_transition.load(Ordering::Acquire)
            || self.restoring.load(Ordering::Acquire)
            || self.shutdown.load(Ordering::Acquire)
        {
            return Err(
                "Wait for the current account connection before changing bandwidth limits".into(),
            );
        }
        let next_revision = settings
            .bandwidth_revision
            .checked_add(1)
            .ok_or("Bandwidth settings revision limit reached")?;
        let mut next = settings.clone();
        next.bandwidth_limits = limits;
        next.bandwidth_account_id = Some(expected_account_id.to_owned());
        next.bandwidth_revision = next_revision;
        next.save(&self.dir)?;

        let mut applied_immediately = false;
        let active_owner = {
            let auth = self
                .auth_state
                .lock()
                .map_err(|_| "Authentication state poisoned")?;
            if auth.engine.is_some() && auth.client.is_some() {
                auth.account_id.clone()
            } else {
                None
            }
        };
        if active_owner.as_deref() == Some(expected_account_id)
            && let Some((owner, budget)) = self
                .transfer_budget
                .lock()
                .map_err(|_| "Transfer budget state poisoned")?
                .as_ref()
            && owner == expected_account_id
        {
            budget.set_limits(limits);
            applied_immediately = true;
        }
        let value = json!({
            "limits": next.bandwidth_limits,
            "account_id": next.bandwidth_account_id,
            "revision": next.bandwidth_revision,
            "apply_immediately": applied_immediately,
        });
        *settings = next;
        Ok(value)
    }

    fn update(&self, edit: impl FnOnce(&mut Settings) -> Result<(), String>) -> Result<(), String> {
        self.update_with_wake(edit, true)
    }

    fn update_with_wake(
        &self,
        edit: impl FnOnce(&mut Settings) -> Result<(), String>,
        wake_scheduler: bool,
    ) -> Result<(), String> {
        let mut current = self.settings.lock().map_err(|_| "Settings poisoned")?;
        let mut next = current.clone();
        edit(&mut next)?;
        next.save(&self.dir)?;
        *current = next;
        if wake_scheduler {
            self.wake.store(true, Ordering::Release);
        }
        Ok(())
    }
    fn record_pair_report(
        &self,
        expected_generation: u64,
        pair: &FolderPair,
        report: Option<SyncReport>,
        error: Option<String>,
    ) {
        let Ok(mut reports) = self.pair_reports.lock() else {
            return;
        };
        // Serialize report publication with logout's generation bump and
        // subsequent clear. If an older sync wins this lock first, logout
        // clears its report; if logout bumps first, this rejects the stale
        // publication.
        if self.auth_generation.load(Ordering::Acquire) != expected_generation {
            return;
        }
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
        if request
            .get("action")
            .and_then(Value::as_str)
            .is_some_and(|a| a.starts_with("vault_"))
        {
            return self.handle_vault(request, None);
        }
        let text = |key: &str| {
            request
                .get(key)
                .and_then(Value::as_str)
                .ok_or_else(|| format!("Missing {key}"))
        };
        let action = text("action")?;
        if self.auth_transition.load(Ordering::Acquire)
            && !matches!(
                action,
                "status"
                    | "pairs"
                    | "transfers"
                    | "recoveries"
                    | "encrypted_edit_recoveries"
                    | "encrypted_edit_recovery_folder"
                    | "media_jobs"
                    | "media_job_status"
                    | "media_job_recovery"
            )
        {
            return Err("An account transition is in progress".into());
        }
        if self.shutdown.load(Ordering::Acquire) && action != "shutdown" {
            return Err("Agent is shutting down".into());
        }
        match action {
            "network_proxy" => self.network_proxy_value(),
            "network_proxy_set" => self.set_network_proxy(&request),
            "bandwidth_limits" => self.bandwidth_limits_value(),
            "bandwidth_limits_set" => self.set_bandwidth_limits(&request),
            "media_jobs" => self.media_jobs_value(),
            "media_destination" => self.media_destination(&request),
            "media_job_set" => self.media_job_set(&request),
            "media_job_run" => self.media_job_run(&request),
            "media_job_remove" => self.media_job_remove(&request),
            "media_job_recovery" => self.media_job_recovery_value(&request),
            "media_job_verify_upload" => self.media_job_verify_upload(&request),
            "media_job_status" => {
                let job_id = text("job_id")?;
                let jobs = self.media_jobs_value()?;
                jobs["jobs"]
                    .as_array()
                    .and_then(|rows| rows.iter().find(|row| row["job"]["id"] == job_id))
                    .cloned()
                    .ok_or_else(|| "Media backup was not found".into())
            }
            "status" => {
                let generation = self.operation_generation()?;
                let s = self
                    .settings
                    .lock()
                    .map_err(|_| "Settings poisoned")?
                    .clone();
                let (connected, offline_namespace, session_expires_at, session_last_refresh_at) = {
                    let auth = self
                        .auth_state
                        .lock()
                        .map_err(|_| "Authentication state poisoned")?;
                    let engine_offline = auth
                        .engine
                        .as_ref()
                        .is_some_and(Engine::namespace_transport_unavailable);
                    if engine_offline {
                        self.offline_namespace.store(true, Ordering::Release);
                    }
                    let offline_namespace = self.offline_namespace.load(Ordering::Acquire);
                    (
                        auth.engine.is_some() && !offline_namespace,
                        offline_namespace,
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
                let encrypted_edit_recovery_available =
                    s.account_id.as_deref().is_some_and(|account| {
                        encrypted_edit_recovery::existing_root(&account_spool_dir(
                            &self.dir, account,
                        ))
                        .ok()
                        .flatten()
                        .is_some()
                    });
                let cache_error = self
                    .cache_error
                    .lock()
                    .map_err(|_| "Cache status poisoned")?
                    .clone();
                let offline_cache = match self.engine() {
                    Ok(engine) => match engine.offline_cache_usage() {
                        Ok(usage) => json!({
                            "available": true,
                            "session_connected": connected,
                            "quota_bytes": usage.quota_bytes,
                            "used_bytes": usage.used_bytes,
                            "pinned_bytes": usage.pinned_bytes,
                            "protected_bytes": usage.protected_bytes,
                            "over_quota": usage.over_quota,
                        }),
                        Err(error) => json!({
                            "available": false,
                            "reason": cache_error.clone().unwrap_or_else(|| error.to_string()),
                        }),
                    },
                    Err(_) => match s.account_id.as_deref() {
                        Some(account_id) => match offline_cache_state_dir(&account_engine_dir(
                            &self.dir, account_id,
                        )) {
                            Ok(cache_state_dir) => match raiun_cache::Cache::open(
                                &cache_state_dir,
                                offline_cache::DEFAULT_CACHE_QUOTA_BYTES,
                            ) {
                                Ok(cache) => match cache.usage() {
                                    Ok(usage) => json!({
                                        "available": true,
                                        "session_connected": false,
                                        "quota_bytes": usage.quota_bytes,
                                        "used_bytes": usage.used_bytes,
                                        "pinned_bytes": usage.pinned_bytes,
                                        "protected_bytes": usage.protected_bytes,
                                        "over_quota": usage.over_quota,
                                    }),
                                    Err(error) => {
                                        json!({"available":false,"reason":error.to_string()})
                                    }
                                },
                                Err(error) => {
                                    json!({"available":false,"reason":cache_error.unwrap_or_else(||error.to_string())})
                                }
                            },
                            Err(error) => {
                                json!({"available":false,"reason":cache_error.unwrap_or_else(||error.to_string())})
                            }
                        },
                        None => json!({
                            "available": false,
                            "quota_bytes": offline_cache::DEFAULT_CACHE_QUOTA_BYTES,
                            "used_bytes": 0,
                            "pinned_bytes": 0,
                            "protected_bytes": 0,
                            "over_quota": false,
                            "reason": cache_error.unwrap_or_else(|| "Connect an account to initialize offline cache".into()),
                        }),
                    },
                };
                let mut paused_space_ids = s.paused_space_ids.clone();
                paused_space_ids.sort();
                // Never attach a new account generation to observations taken
                // before an authentication transition. Mutation RPCs still
                // independently validate the caller's expected generation.
                if self.operation_generation()? != generation {
                    return Err("Status was canceled by an account change".into());
                }
                Ok(json!({
                    "auth_generation": generation,
                    "connected": connected,
                    "offline_namespace": offline_namespace,
                    "session_expires_at": session_expires_at,
                    "session_last_refresh_at": session_last_refresh_at,
                    "server": s.server,
                    "client_id": s.server.as_ref().map(|_| s.client_id.as_str()),
                    "paused": s.paused,
                    "paused_space_ids": paused_space_ids,
                    "mounted": mounted,
                    "cloud_root": s.config.cloud_root,
                    "recovery_folder": recovery_folder,
                    "encrypted_edit_recovery_available": encrypted_edit_recovery_available,
                    "offline_cache": offline_cache,
                    "vault_password_cleanup_uncertain": self.vault_cleanup_uncertain.load(Ordering::Acquire),
                    "autostart": autostart::is_enabled(),
                    "error": displayed_error,
                    "pair_reports": reports,
                    "authenticating": self.authenticating.load(Ordering::Acquire),
                    "restoring": self.restoring.load(Ordering::Acquire),
                }))
            }
            "auth_begin" => {
                let initial_generation = self.operation_generation()?;
                self.clear_pending_space_syncs()?;
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
                    settings
                        .network_proxy
                        .validate()
                        .map_err(|_| "Proxy configuration is invalid")?;
                    let flow = auth::AuthFlow::begin_with_proxy(
                        &server,
                        client_id,
                        settings.network_proxy.clone(),
                    )?;
                    if !settings.config.pairs.is_empty() && flow.client_id() != settings.client_id {
                        return Err(
                            "Remove existing folder pairs before changing OAuth clients".into()
                        );
                    }
                    let info = flow.public_info();
                    if self.auth_transition.load(Ordering::Acquire)
                        || self.shutdown.load(Ordering::Acquire)
                    {
                        return Err("Sign-in was canceled by an account transition".into());
                    }
                    let generation = initial_generation
                        .checked_add(1)
                        .ok_or("Account generation exhausted")?;
                    self.auth_generation
                        .compare_exchange(
                            initial_generation,
                            generation,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .map_err(|_| "Sign-in was canceled by an account transition".to_owned())?;
                    let runtime = self.clone();
                    std::thread::spawn(move || {
                        let result = flow
                            .wait()
                            .and_then(|session| runtime.install_session(session, generation));
                        if let Err(error) = result {
                            if runtime.auth_generation.load(Ordering::Acquire) == generation
                                && !runtime.shutdown.load(Ordering::Acquire)
                            {
                                if let Ok(mut state) = runtime.error.lock() {
                                    *state = Some(error);
                                }
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
            "logout" => {
                self.logout()?;
                Ok(json!({}))
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
            "encrypted_edit_recoveries" => {
                let after = match request.get("after") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(cursor)) => Some(cursor.as_str()),
                    Some(_) => return Err("after must be a string".into()),
                };
                let limit = match request.get("limit") {
                    None => None,
                    Some(Value::Number(number)) => {
                        Some(number.as_u64().ok_or("limit must be an unsigned integer")? as usize)
                    }
                    Some(_) => return Err("limit must be an unsigned integer".into()),
                };
                let settings = self
                    .settings
                    .lock()
                    .map_err(|_| "Settings poisoned")?
                    .clone();
                let origin = settings.server.as_deref().and_then(|server| {
                    url::Url::parse(server)
                        .ok()
                        .map(|url| url.origin().ascii_serialization())
                });
                let page = if let Some(account_id) = settings.account_id.as_deref() {
                    encrypted_edit_recovery::list(
                        &account_spool_dir(&self.dir, account_id),
                        &self.vault_account_id,
                        origin.as_deref(),
                        after,
                        limit,
                    )?
                } else {
                    encrypted_edit_recovery::empty_page(limit)?
                };
                serde_json::to_value(page)
                    .map_err(|_| "Could not encode saved encrypted-file edit list".into())
            }
            "encrypted_edit_recovery_folder" => {
                let account_id = self
                    .settings
                    .lock()
                    .map_err(|_| "Settings poisoned")?
                    .account_id
                    .clone()
                    .ok_or("Sign in before opening saved encrypted-file edits")?;
                let path = encrypted_edit_recovery::existing_root(&account_spool_dir(
                    &self.dir,
                    &account_id,
                ))?
                .ok_or("There are no saved encrypted-file edits yet")?;
                Ok(json!({"path": path}))
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
                let generation = self.operation_generation()?;
                let engine = self.engine_for_pair(&pair)?;
                let _sync = self.sync_gate.lock().map_err(|_| "Sync state poisoned")?;
                if self.auth_generation.load(Ordering::Acquire) != generation
                    || self.shutdown.load(Ordering::Acquire)
                    || self.auth_transition.load(Ordering::Acquire)
                {
                    return Err("Conflict operation was canceled".into());
                }
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
                let generation = self.operation_generation()?;
                let mut body = request.clone();
                body.as_object_mut()
                    .ok_or("Invalid request")?
                    .remove("action");
                let pair: FolderPair = serde_json::from_value(body).map_err(|e| e.to_string())?;
                {
                    let settings = self.settings.lock().map_err(|_| "Settings poisoned")?;
                    if settings
                        .media_jobs
                        .iter()
                        .any(|job| paths_overlap_existing(&job.source_root, &pair.local_path))
                    {
                        return Err("Folder pair overlaps a configured media backup source".into());
                    }
                }
                if pair.vault.is_some() {
                    // Validate the exact root and verified session before persisting a pair.
                    let destination = self
                        .engine_for_pair(&pair)?
                        .stat(&pair.space_id, &pair.remote_path)
                        .map_err(|e| e.to_string())?;
                    if !destination.directory {
                        return Err("Select a directory inside the vault".into());
                    }
                    if !destination.writable && pair.mode != raiun_core::SyncMode::DownloadOnly {
                        return Err(
                            "This encrypted folder is read only; choose Download only".into()
                        );
                    }
                }
                self.update(|s| {
                    if self.auth_transition.load(Ordering::Acquire)
                        || self.auth_generation.load(Ordering::Acquire) != generation
                    {
                        return Err("Folder pair addition was canceled by an account change".into());
                    }
                    if s.media_jobs
                        .iter()
                        .any(|job| paths_overlap_existing(&job.source_root, &pair.local_path))
                    {
                        return Err("Folder pair overlaps a configured media backup source".into());
                    }
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
                self.clear_pending_space_syncs()?;
                Ok(json!({}))
            }
            "pair_exclusions_set" => {
                let generation = self.operation_generation()?;
                let id = text("id")?;
                let excluded_paths: Vec<String> = serde_json::from_value(
                    request
                        .get("excluded_paths")
                        .cloned()
                        .ok_or("Missing excluded_paths")?,
                )
                .map_err(|_| "excluded_paths must be an array of paths")?;
                let original = self
                    .settings
                    .lock()
                    .map_err(|_| "Settings poisoned")?
                    .config
                    .pairs
                    .iter()
                    .find(|pair| pair.id == id)
                    .cloned()
                    .ok_or("Folder pair was not found")?;
                let mut updated = original.clone();
                updated.excluded_paths = excluded_paths;
                updated
                    .validate_exclusions()
                    .map_err(|error| format!("Invalid exclusions: {error}"))?;
                let engine = self.engine_for_pair(&updated)?;

                // Match scheduler lock order: Runtime gate, then Engine
                // admission fence, then durable settings. The engine policy
                // remains old until the settings write succeeds.
                let _sync = self.sync_gate.lock().map_err(|_| "Sync state poisoned")?;
                if self.auth_transition.load(Ordering::Acquire)
                    || self.auth_generation.load(Ordering::Acquire) != generation
                {
                    return Err("Folder policy update was canceled by an account change".into());
                }
                let publication = engine
                    .prepare_pair_policy(&updated)
                    .map_err(|error| error.to_string())?;
                self.update_with_wake(
                    |settings| {
                        if self.auth_transition.load(Ordering::Acquire)
                            || self.auth_generation.load(Ordering::Acquire) != generation
                        {
                            return Err(
                                "Folder policy update was canceled by an account change".into()
                            );
                        }
                        let pair = settings
                            .config
                            .pairs
                            .iter_mut()
                            .find(|pair| pair.id == id)
                            .ok_or("Folder pair was removed")?;
                        if pair != &original {
                            return Err("Folder pair changed before exclusions were saved".into());
                        }
                        pair.excluded_paths = updated.excluded_paths.clone();
                        let errors = validate_config(&settings.config);
                        if errors.is_empty() {
                            Ok(())
                        } else {
                            Err(errors.join("; "))
                        }
                    },
                    false,
                )?;
                publication.publish();
                self.wake.store(true, Ordering::Release);
                self.clear_pending_space_syncs()?;
                Ok(json!({"pair_id":id,"excluded_paths":updated.excluded_paths}))
            }
            "pair_remove" => {
                let generation = self.operation_generation()?;
                let id = text("id")?;
                let existing = self
                    .settings
                    .lock()
                    .map_err(|_| "Settings poisoned")?
                    .config
                    .pairs
                    .iter()
                    .find(|pair| pair.id == id)
                    .cloned();
                let engine = if existing.is_some() {
                    self.engine().ok()
                } else {
                    None
                };
                let _sync = self.sync_gate.lock().map_err(|_| "Sync state poisoned")?;
                if self.auth_transition.load(Ordering::Acquire)
                    || self.auth_generation.load(Ordering::Acquire) != generation
                {
                    return Err("Folder pair removal was canceled by an account change".into());
                }
                let retirement = engine
                    .as_ref()
                    .map(|engine| engine.prepare_pair_retirement(id))
                    .transpose()
                    .map_err(|error| error.to_string())?;
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
                if let Some(retirement) = retirement {
                    retirement.publish();
                }
                self.clear_pending_space_syncs()?;
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
                    if s.media_jobs
                        .iter()
                        .any(|job| paths_overlap_existing(&job.source_root, &root))
                    {
                        return Err("Cloud folder overlaps a configured media backup source".into());
                    }
                    s.config.cloud_root = root;
                    let errors = validate_config(&s.config);
                    if errors.is_empty() {
                        Ok(())
                    } else {
                        Err(errors.join("; "))
                    }
                })?;
                self.clear_pending_space_syncs()?;
                Ok(json!({}))
            }
            "pause" => {
                let paused = request
                    .get("paused")
                    .and_then(Value::as_bool)
                    .ok_or("Missing paused")?;
                if paused {
                    // Publish the pause before waiting for the worker gate so
                    // a bounded reconcile pass stops after its current file.
                    self.write_reconcile_jobs.cancel_active();
                    self.vault_edit_reconcile_jobs.cancel_all_and_wait()?;
                    self.update(|settings| {
                        settings.paused = true;
                        Ok(())
                    })?;
                    self.clear_pending_space_syncs()?;
                    if let Ok(engine) = self.engine() {
                        engine.set_sync_paused(true);
                    }
                    // Do not acknowledge pause while a sync/reconciliation
                    // network operation that already passed its check remains
                    // in flight. Future work sees the persisted pause first.
                    let _sync = self.sync_gate.lock().map_err(|_| "Sync state poisoned")?;
                    // A scheduler may have passed its last pause check while
                    // the flag was being published; catch any job registered
                    // in that narrow interval before acknowledging pause.
                    self.vault_edit_reconcile_jobs.cancel_all_and_wait()?;
                } else {
                    // For resume, serialize the change before making work
                    // eligible again.
                    let _sync = self.sync_gate.lock().map_err(|_| "Sync state poisoned")?;
                    self.update(|settings| {
                        settings.paused = false;
                        Ok(())
                    })?;
                    if let Ok(engine) = self.engine() {
                        engine.set_sync_paused(false);
                    }
                }
                Ok(json!({}))
            }
            "space_disconnect" => {
                let generation = self.operation_generation()?;
                let space_id = text("space_id")?;
                validate_space_id(space_id)?;
                let _sync = self.sync_gate.lock().map_err(|_| "Sync state poisoned")?;
                if self.auth_transition.load(Ordering::Acquire)
                    || self.auth_generation.load(Ordering::Acquire) != generation
                {
                    return Err("Space disconnect was canceled by an account change".into());
                }
                let ids = self
                    .settings
                    .lock()
                    .map_err(|_| "Settings poisoned")?
                    .config
                    .pairs
                    .iter()
                    .filter(|pair| pair.space_id == space_id)
                    .map(|pair| pair.id.clone())
                    .collect::<BTreeSet<_>>();
                let ids_vec = ids.iter().cloned().collect::<Vec<_>>();
                let engine = self.engine().ok();
                let retirement = engine
                    .as_ref()
                    .map(|engine| engine.prepare_pair_retirements(&ids_vec))
                    .transpose()
                    .map_err(|error| error.to_string())?;
                self.update_with_wake(
                    |settings| {
                        if self.auth_transition.load(Ordering::Acquire)
                            || self.auth_generation.load(Ordering::Acquire) != generation
                        {
                            return Err("Space disconnect was canceled by an account change".into());
                        }
                        let current = settings
                            .config
                            .pairs
                            .iter()
                            .filter(|pair| pair.space_id == space_id)
                            .map(|pair| pair.id.clone())
                            .collect::<BTreeSet<_>>();
                        if current != ids {
                            return Err(
                                "Space connections changed; refresh before disconnecting".into()
                            );
                        }
                        let mut retired = settings
                            .retired_pair_ids
                            .iter()
                            .cloned()
                            .collect::<BTreeSet<_>>();
                        retired.extend(ids.iter().cloned());
                        if retired.len() > 100_000 {
                            return Err("Retired pair ID limit reached".into());
                        }
                        settings.retired_pair_ids = retired.into_iter().collect();
                        settings.config.pairs.retain(|pair| !ids.contains(&pair.id));
                        Ok(())
                    },
                    false,
                )?;
                if let Some(retirement) = retirement {
                    retirement.publish();
                }
                self.pending_space_syncs
                    .lock()
                    .map_err(|_| "Pending Space sync state poisoned")?
                    .remove(space_id);
                self.pair_reports
                    .lock()
                    .map_err(|_| "Pair report state poisoned")?
                    .retain(|id, _| !ids.contains(id));
                Ok(json!({"space_id":space_id,"removed_pair_ids":ids_vec}))
            }
            "space_pause" => {
                let generation = self.operation_generation()?;
                let space_id = text("space_id")?;
                validate_space_id(space_id)?;
                let paused = request
                    .get("paused")
                    .and_then(Value::as_bool)
                    .ok_or("Missing paused")?;
                if !self.space_is_known(space_id)? {
                    return Err("Selected Space is no longer available".into());
                }
                if paused {
                    // The write retry polls persisted pause and cancellation
                    // between conditional uploads. Mark it before waiting on
                    // the gate held by its current request.
                    self.write_reconcile_jobs.cancel_space(space_id);
                    self.vault_edit_reconcile_jobs
                        .cancel_space_and_wait(space_id)?;
                    self.update_with_wake(
                        |settings| {
                            if self.auth_transition.load(Ordering::Acquire)
                                || self.auth_generation.load(Ordering::Acquire) != generation
                            {
                                return Err("Space pause was canceled by an account change".into());
                            }
                            let mut paused_ids = settings
                                .paused_space_ids
                                .iter()
                                .cloned()
                                .collect::<BTreeSet<_>>();
                            paused_ids.insert(space_id.to_owned());
                            if paused_ids.len() > storage::MAX_PAUSED_SPACE_IDS {
                                return Err("Paused Space limit reached".into());
                            }
                            settings.paused_space_ids = paused_ids.into_iter().collect();
                            Ok(())
                        },
                        false,
                    )?;
                    self.pending_space_syncs
                        .lock()
                        .map_err(|_| "Pending Space sync state poisoned")?
                        .remove(space_id);
                    let _sync = self.sync_gate.lock().map_err(|_| "Sync state poisoned")?;
                    self.vault_edit_reconcile_jobs
                        .cancel_space_and_wait(space_id)?;
                    let mut paused_space_ids = self
                        .settings
                        .lock()
                        .map_err(|_| "Settings poisoned")?
                        .paused_space_ids
                        .clone();
                    paused_space_ids.sort();
                    return Ok(json!({
                        "space_id": space_id,
                        "paused": true,
                        "paused_space_ids": paused_space_ids,
                    }));
                }
                // Serialize the persisted pause with the scheduler's final
                // per-pair recheck. A successful response therefore means no
                // later pair operation can begin for this Space.
                let _sync = self.sync_gate.lock().map_err(|_| "Sync state poisoned")?;
                let mut pending = self
                    .pending_space_syncs
                    .lock()
                    .map_err(|_| "Pending Space sync state poisoned")?;
                self.update_with_wake(
                    |settings| {
                        if self.auth_transition.load(Ordering::Acquire)
                            || self.auth_generation.load(Ordering::Acquire) != generation
                        {
                            return Err("Space pause was canceled by an account change".into());
                        }
                        let mut paused_ids = settings
                            .paused_space_ids
                            .iter()
                            .cloned()
                            .collect::<BTreeSet<_>>();
                        if paused {
                            paused_ids.insert(space_id.to_owned());
                        } else {
                            paused_ids.remove(space_id);
                        }
                        if paused_ids.len() > storage::MAX_PAUSED_SPACE_IDS {
                            return Err("Paused Space limit reached".into());
                        }
                        settings.paused_space_ids = paused_ids.into_iter().collect();
                        Ok(())
                    },
                    false,
                )?;
                if paused {
                    pending.remove(space_id);
                }
                drop(pending);
                let mut paused_space_ids = self
                    .settings
                    .lock()
                    .map_err(|_| "Settings poisoned")?
                    .paused_space_ids
                    .clone();
                paused_space_ids.sort();
                Ok(json!({
                    "space_id": space_id,
                    "paused": paused,
                    "paused_space_ids": paused_space_ids,
                }))
            }
            "space_sync_now" => {
                let generation = self.operation_generation()?;
                let space_id = text("space_id")?;
                validate_space_id(space_id)?;
                self.engine()?;
                let settings = self
                    .settings
                    .lock()
                    .map_err(|_| "Settings poisoned")?
                    .clone();
                if settings.paused {
                    return Err("Sync is paused globally".into());
                }
                if settings.paused_space_ids.iter().any(|id| id == space_id) {
                    return Err("Sync is paused for this Space".into());
                }
                if !settings
                    .config
                    .pairs
                    .iter()
                    .any(|pair| pair.space_id == space_id)
                {
                    return Err("No folder pairs are configured for this Space".into());
                }
                let mut pending = self
                    .pending_space_syncs
                    .lock()
                    .map_err(|_| "Pending Space sync state poisoned")?;
                if self.auth_transition.load(Ordering::Acquire)
                    || self.auth_generation.load(Ordering::Acquire) != generation
                    || self.shutdown.load(Ordering::Acquire)
                {
                    return Err("Space sync request was canceled by an account change".into());
                }
                let current = self.settings.lock().map_err(|_| "Settings poisoned")?;
                if current.paused {
                    return Err("Sync is paused globally".into());
                }
                if current.paused_space_ids.iter().any(|id| id == space_id) {
                    return Err("Sync is paused for this Space".into());
                }
                if !current
                    .config
                    .pairs
                    .iter()
                    .any(|pair| pair.space_id == space_id)
                {
                    return Err("No folder pairs are configured for this Space".into());
                }
                if !pending.contains(space_id) && pending.len() >= MAX_PENDING_SPACE_SYNCS {
                    return Err("Too many pending Space sync requests".into());
                }
                pending.insert(space_id.to_owned());
                Ok(json!({"accepted":true,"space_id":space_id}))
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
                self.shutdown_safely()?;
                Ok(json!({"stopping":true}))
            }
            "sync_now" => {
                self.engine()?;
                self.wake.store(true, Ordering::Release);
                Ok(json!({}))
            }
            "spaces" => Ok(json!(self.engine()?.spaces().map_err(|e| e.to_string())?)),
            "list" | "browse" => remote_listing_response(
                self.engine()?
                    .list(text("space_id")?, text("path")?)
                    .map_err(|e| e.to_string())?,
            ),
            "cache_policy_set" => {
                let generation = self.operation_generation()?;
                let space = text("space_id")?;
                let path = text("path")?;
                let policy = parse_cache_policy(text("policy")?)?;
                let engine = self.engine()?;
                engine
                    .set_availability_policy(space, path, policy)
                    .map_err(|error| error.to_string())?;
                let (effective_policy, availability_state) = engine
                    .availability_status(space, path)
                    .map_err(|error| error.to_string())?;
                ensure_generation(&self.auth_generation, generation)?;
                Ok(
                    json!({"space_id":space,"path":path,"policy":cache_policy_name(effective_policy),"availability_state":availability_state.map(cache_target_state_name)}),
                )
            }
            "cache_policy_get" => {
                let generation = self.operation_generation()?;
                let space = text("space_id")?;
                let path = text("path")?;
                let engine = self.engine()?;
                let (policy, availability_state) = engine
                    .availability_status(space, path)
                    .map_err(|error| error.to_string())?;
                ensure_generation(&self.auth_generation, generation)?;
                Ok(
                    json!({"space_id":space,"path":path,"policy":cache_policy_name(policy),"availability_state":availability_state.map(cache_target_state_name)}),
                )
            }
            "cache_pin_start" => {
                let generation = self.operation_generation()?;
                let engine = self.engine()?;
                engine
                    .offline_cache_usage()
                    .map_err(|error| error.to_string())?;
                let status = self.cache_jobs.start(
                    engine,
                    self.auth_generation.clone(),
                    generation,
                    text("space_id")?.to_owned(),
                    text("path")?.to_owned(),
                )?;
                ensure_generation(&self.auth_generation, generation)?;
                serde_json::to_value(status)
                    .map_err(|_| "Could not encode offline pin status".into())
            }
            "cache_pin_status" => {
                let generation = self.operation_generation()?;
                let status = self.cache_jobs.status(text("job_id")?, generation)?;
                if status.space_id != text("space_id")? {
                    return Err("Offline pin job belongs to a different Space".into());
                }
                ensure_generation(&self.auth_generation, generation)?;
                serde_json::to_value(status)
                    .map_err(|_| "Could not encode offline pin status".into())
            }
            "cache_pin_cancel" => {
                let generation = self.operation_generation()?;
                let space = text("space_id")?;
                let engine = self.engine()?;
                let result = if let Some(job_id) = request.get("job_id").and_then(Value::as_str) {
                    let status = self.cache_jobs.status(job_id, generation)?;
                    if status.space_id != space {
                        return Err("Offline pin job belongs to a different Space".into());
                    }
                    if !matches!(status.state.as_str(), "preparing" | "building") {
                        return Err("Offline pin job is no longer running".into());
                    }
                    self.cache_jobs.cancel(job_id, generation)?;
                    json!({"job_id":job_id,"cancel_requested":true})
                } else {
                    let pin_id = text("pin_id")?;
                    engine
                        .cancel_offline_pin(space, pin_id)
                        .map_err(|error| error.to_string())?;
                    json!({"pin_id":pin_id,"cancelled":true})
                };
                Ok(result)
            }
            "cache_pins" => {
                let engine = self.engine()?;
                let pins = engine
                    .offline_pins(text("space_id")?)
                    .map_err(|error| error.to_string())?;
                Ok(json!(
                    pins.into_iter()
                        .map(|pin| {
                            json!({
                                "pin_id":pin.id,
                                "root_resource_id":pin.root_resource_id,
                                "path":pin.root_path,
                                "state":offline_pin_state_name(pin.state),
                                "item_count":pin.item_count,
                                "files_done":pin.ready_content_count,
                                "files_total":pin.required_content_count,
                            })
                        })
                        .collect::<Vec<_>>()
                ))
            }
            "cache_pending_writes" => {
                let generation = self.operation_generation()?;
                let saved_settings = self
                    .settings
                    .lock()
                    .map_err(|_| "Settings poisoned")?
                    .clone();
                let after = request.get("after").and_then(Value::as_str);
                let limit = request
                    .get("limit")
                    .and_then(Value::as_u64)
                    .unwrap_or(50)
                    .clamp(1, 100) as usize;
                let page = self.pending_write_page(after, limit)?;
                ensure_generation(&self.auth_generation, generation)?;
                let latest = self.settings.lock().map_err(|_| "Settings poisoned")?;
                if latest.server != saved_settings.server
                    || latest.account_id != saved_settings.account_id
                {
                    return Err("Account changed while checking saved edits".into());
                }
                Ok(json!({
                    "auth_generation": generation,
                    "account_scope": Self::saved_write_account_scope(&saved_settings),
                    "items": page.items.into_iter().map(|item| json!({
                        "space_id": item.space_id,
                        "root_resource_id": item.root_resource_id,
                        "write_id": item.write_id.to_string(),
                        "path": item.path,
                        "state": match item.state {
                            raiun_cache::WriteState::Pending => "pending",
                            raiun_cache::WriteState::Conflict => "conflict",
                            raiun_cache::WriteState::Verified => "verified",
                        },
                        "bytes": item.bytes,
                        "created_at_unix": item.created_at_unix,
                    })).collect::<Vec<_>>(),
                    "next_after": page.next_after,
                    "pending_count": page.pending_count,
                    "conflict_count": page.conflict_count,
                    "truncated": page.truncated,
                }))
            }
            "cache_conflict_export" => {
                let generation = self.operation_generation()?;
                let space_id = text("space_id")?.to_owned();
                validate_space_id(&space_id)?;
                let write_id = text("write_id")?
                    .parse::<i64>()
                    .ok()
                    .filter(|id| *id > 0)
                    .ok_or("Conflict write identifier is invalid")?;
                let destination = PathBuf::from(text("destination_path")?);
                let settings = self
                    .settings
                    .lock()
                    .map_err(|_| "Settings poisoned")?
                    .clone();
                let account_id = settings
                    .account_id
                    .clone()
                    .ok_or("No saved account cache is available")?;
                let engine_dir = account_engine_dir(&self.dir, &account_id);
                let cache_dir = offline_cache_state_dir(&engine_dir)
                    .map_err(|_| "Offline cache directory is unavailable or unsafe")?;
                let cache =
                    raiun_cache::Cache::open(&cache_dir, offline_cache::DEFAULT_CACHE_QUOTA_BYTES)
                        .map_err(|_| "Offline cache is unavailable")?;
                let protected = vec![
                    self.dir.clone(),
                    engine_dir,
                    account_spool_dir(&self.dir, &account_id),
                    settings.config.cloud_root.clone(),
                ];
                let item = ordinary_write_recovery::export_conflict_copy(
                    &cache,
                    &account_id,
                    &space_id,
                    write_id,
                    &destination,
                    &protected,
                    || {
                        ensure_generation(&self.auth_generation, generation)?;
                        let latest = self.settings.lock().map_err(|_| "Settings poisoned")?;
                        if latest.account_id != settings.account_id
                            || latest.config.cloud_root != settings.config.cloud_root
                        {
                            return Err(
                                "Account or cloud-folder settings changed while saving the copy"
                                    .into(),
                            );
                        }
                        Ok(())
                    },
                )?;
                ensure_generation(&self.auth_generation, generation)?;
                Ok(json!({
                    "exported": true,
                    "space_id": item.space_id,
                    "write_id": item.write_id.to_string(),
                    "path": item.path,
                    "bytes": item.bytes,
                    "destination": destination,
                }))
            }
            "cache_saved_write_export" => {
                let generation = self.operation_generation()?;
                let expected_generation = request
                    .get("expected_generation")
                    .and_then(Value::as_u64)
                    .ok_or("Refresh saved edits before saving a copy")?;
                if generation != expected_generation {
                    return Err("Account changed; refresh saved edits".into());
                }
                let expected_scope = text("expected_account_scope")?;
                let space_id = text("space_id")?.to_owned();
                validate_space_id(&space_id)?;
                let write_id = text("write_id")?
                    .parse::<i64>()
                    .ok()
                    .filter(|id| *id > 0)
                    .ok_or("Conflict write identifier is invalid")?;
                let root_resource_id = text("root_resource_id")?.to_owned();
                if root_resource_id.trim().is_empty()
                    || root_resource_id.len() > 16 * 1024
                    || root_resource_id.chars().any(char::is_control)
                {
                    return Err("Saved root identity is invalid".into());
                }
                let destination = PathBuf::from(text("destination_path")?);
                let settings = self
                    .settings
                    .lock()
                    .map_err(|_| "Settings poisoned")?
                    .clone();
                if Self::saved_write_account_scope(&settings).as_deref() != Some(expected_scope) {
                    return Err("Account changed; refresh saved edits".into());
                }
                let account_id = settings
                    .account_id
                    .clone()
                    .ok_or("No saved account cache is available")?;
                let saved_scope = raiun_cache::CacheScope::new(
                    settings
                        .server
                        .as_deref()
                        .ok_or("No saved account server is available")?,
                    &account_id,
                    &space_id,
                    &root_resource_id,
                    raiun_cache::ScopeProtection::PlaintextAllowed,
                )
                .map_err(|_| "Saved edit scope is invalid")?;
                let engine_dir = account_engine_dir(&self.dir, &account_id);
                let cache_dir = offline_cache_state_dir(&engine_dir)
                    .map_err(|_| "Offline cache directory is unavailable or unsafe")?;
                let cache =
                    raiun_cache::Cache::open(&cache_dir, offline_cache::DEFAULT_CACHE_QUOTA_BYTES)
                        .map_err(|_| "Offline cache is unavailable")?;
                let protected = vec![
                    self.dir.clone(),
                    engine_dir,
                    account_spool_dir(&self.dir, &account_id),
                    settings.config.cloud_root.clone(),
                ];
                let item = ordinary_write_recovery::export_saved_copy(
                    &cache,
                    &saved_scope,
                    write_id,
                    &destination,
                    &protected,
                    || {
                        ensure_generation(&self.auth_generation, generation)?;
                        let latest = self.settings.lock().map_err(|_| "Settings poisoned")?;
                        if latest.server != settings.server
                            || latest.account_id != settings.account_id
                            || latest.config.cloud_root != settings.config.cloud_root
                        {
                            return Err(
                                "Account or cloud-folder settings changed while saving the copy"
                                    .into(),
                            );
                        }
                        Ok(())
                    },
                )?;
                ensure_generation(&self.auth_generation, generation)?;
                Ok(json!({
                    "exported": true,
                    "space_id": item.space_id,
                    "root_resource_id": item.root_resource_id,
                    "journal_preserved": true,
                    "write_id": item.write_id.to_string(),
                    "path": item.path,
                    "bytes": item.bytes,
                    "destination": destination,
                }))
            }
            "cache_reconcile_writes" => {
                let generation = self.operation_generation()?;
                let space = text("space_id")?.to_owned();
                validate_space_id(&space)?;
                let settings = self
                    .settings
                    .lock()
                    .map_err(|_| "Settings poisoned")?
                    .clone();
                if settings.paused || settings.paused_space_ids.iter().any(|id| id == &space) {
                    return Err(
                        "Resume sync for this account and Space before retrying uploads".into(),
                    );
                }
                let engine = self.engine()?;
                let selected = engine
                    .spaces()
                    .map_err(|error| error.to_string())?
                    .into_iter()
                    .find(|candidate| candidate.id == space)
                    .ok_or("Selected Space is no longer available")?;
                if selected.encrypted {
                    return Err(
                        "Encrypted Space writes are not part of the ordinary offline journal"
                            .into(),
                    );
                }
                let runtime = self.clone();
                let worker_engine = engine.clone();
                let status = self.write_reconcile_jobs.start(
                    generation,
                    space.clone(),
                    move |cancelled| {
                        let _sync = runtime
                            .sync_gate
                            .lock()
                            .map_err(|_| "Sync state poisoned".to_owned())?;
                        runtime.cache_jobs.run_serialized(|| {
                            let report = worker_engine
                                .reconcile_pending_file_writes_cancellable(&space, 64, || {
                                    let paused = runtime
                                        .settings
                                        .lock()
                                        .map(|settings| {
                                            settings.paused
                                                || settings
                                                    .paused_space_ids
                                                    .iter()
                                                    .any(|id| id == &space)
                                        })
                                        .unwrap_or(true);
                                    cancelled.load(Ordering::Acquire)
                                        || runtime.auth_generation.load(Ordering::Acquire)
                                            != generation
                                        || runtime.auth_transition.load(Ordering::Acquire)
                                        || runtime.shutdown.load(Ordering::Acquire)
                                        || paused
                                })
                                .map_err(|error| error.to_string())?;
                            if runtime.auth_generation.load(Ordering::Acquire) != generation {
                                return Err("Write retry was cancelled by an account change".into());
                            }
                            Ok(report)
                        })
                    },
                )?;
                ensure_generation(&self.auth_generation, generation)?;
                serde_json::to_value(status)
                    .map_err(|_| "Could not encode write retry status".into())
            }
            "cache_reconcile_status" => {
                let generation = self.operation_generation()?;
                let status = self
                    .write_reconcile_jobs
                    .status(text("job_id")?, generation)?;
                ensure_generation(&self.auth_generation, generation)?;
                serde_json::to_value(status)
                    .map_err(|_| "Could not encode write retry status".into())
            }
            "cache_reconcile_cancel" => {
                let generation = self.operation_generation()?;
                let status = self
                    .write_reconcile_jobs
                    .cancel(text("job_id")?, generation)?;
                ensure_generation(&self.auth_generation, generation)?;
                serde_json::to_value(status)
                    .map_err(|_| "Could not encode write retry status".into())
            }
            "create_folder" => {
                let space_id = text("space_id")?;
                let parent_path = text("parent_path")?;
                let name = text("name")?;
                validate_remote_folder_request(parent_path, name)?;
                let engine = self.engine()?;
                let spaces = engine.spaces().map_err(|error| error.to_string())?;
                let space = spaces
                    .iter()
                    .find(|space| space.id == space_id)
                    .ok_or("Selected Space is no longer available")?;
                if !space.writable || space.encrypted {
                    return Err("Selected Space is read-only or encrypted".into());
                }
                let parent = if parent_path == "/" {
                    None
                } else {
                    Some(
                        engine
                            .stat(space_id, parent_path)
                            .map_err(|e| e.to_string())?,
                    )
                };
                if parent
                    .as_ref()
                    .is_some_and(|entry| !entry.directory || entry.encrypted || !entry.writable)
                {
                    return Err(
                        "Selected parent folder is read-only, encrypted, or unavailable".into(),
                    );
                }
                let path = if parent_path == "/" {
                    format!("/{name}")
                } else {
                    format!("{}/{name}", parent_path.trim_end_matches('/'))
                };
                let entry = engine
                    .mkdir(space_id, &path)
                    .map_err(|error| error.to_string())?;
                Ok(json!(entry))
            }
            "transfers" => Ok(json!(
                self.engine()?.transfers(500).map_err(|e| e.to_string())?
            )),
            _ => Err("This action is not yet available".into()),
        }
    }
}

fn validate_remote_folder_request(parent_path: &str, name: &str) -> Result<(), String> {
    if !valid_remote_path(parent_path) {
        return Err("Parent path must be an absolute cloud folder path without empty, dot, or parent components".into());
    }
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.chars().any(char::is_control)
        || name.trim() != name
    {
        return Err("Folder name is invalid".into());
    }
    Ok(())
}

fn valid_remote_path(path: &str) -> bool {
    path == "/"
        || (path.starts_with('/')
            && !path.ends_with('/')
            && path[1..].split('/').all(|component| {
                !component.is_empty()
                    && component != "."
                    && component != ".."
                    && !component.chars().any(char::is_control)
                    && !component.contains('\\')
            }))
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

fn parse_cache_policy(value: &str) -> Result<AvailabilityPolicy, String> {
    match value {
        "recent" => Ok(AvailabilityPolicy::Recent),
        "always_offline" => Ok(AvailabilityPolicy::AlwaysOffline),
        "cloud_only" => Ok(AvailabilityPolicy::CloudOnly),
        _ => Err("policy must be recent, always_offline, or cloud_only".into()),
    }
}

fn cache_policy_name(policy: AvailabilityPolicy) -> &'static str {
    match policy {
        AvailabilityPolicy::Recent => "recent",
        AvailabilityPolicy::AlwaysOffline => "always_offline",
        AvailabilityPolicy::CloudOnly => "cloud_only",
    }
}

fn cache_target_state_name(state: raiun_cache::TargetState) -> &'static str {
    match state {
        raiun_cache::TargetState::Ready => "ready",
        raiun_cache::TargetState::Stale => "stale",
        raiun_cache::TargetState::Unavailable => "unavailable",
    }
}

fn offline_pin_state_name(state: raiun_cache::PinState) -> &'static str {
    match state {
        raiun_cache::PinState::Building => "building",
        raiun_cache::PinState::Ready => "ready",
        raiun_cache::PinState::Stale => "stale",
        raiun_cache::PinState::Unavailable => "unavailable",
    }
}

fn ensure_generation(generation: &AtomicU64, expected: u64) -> Result<(), String> {
    if generation.load(Ordering::Acquire) == expected {
        Ok(())
    } else {
        Err("Account changed while the offline-cache operation was running".into())
    }
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

fn offline_cache_state_dir(engine_dir: &Path) -> Result<PathBuf, std::io::Error> {
    use std::io::{Error, ErrorKind};
    let parent = fs::symlink_metadata(engine_dir)?;
    if !parent.is_dir() || parent.file_type().is_symlink() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "account cache parent is not a real directory",
        ));
    }
    let path = engine_dir.join("offline-cache-state");
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "cache state path is not a real directory",
                ));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o077 != 0 {
                    return Err(Error::new(
                        ErrorKind::PermissionDenied,
                        "cache state directory is not private",
                    ));
                }
            }
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                let mut builder = fs::DirBuilder::new();
                builder.mode(0o700).create(&path)?;
            }
            #[cfg(not(unix))]
            {
                fs::create_dir(&path)?;
            }
            fs::File::open(engine_dir)?.sync_all()?;
        }
        Err(error) => return Err(error),
    }
    Ok(path)
}

fn attach_optional_cache(
    engine: Engine,
    engine_dir: &Path,
    account_id: &str,
    origin: Option<String>,
) -> (Engine, Option<String>) {
    let Some(origin) = origin else {
        return (engine, Some("Cloud server origin is unavailable".into()));
    };
    let engine = match engine.with_account_scope(account_id.to_owned(), origin.clone()) {
        Ok(engine) => engine,
        Err(error) => return (engine, Some(error.to_string())),
    };
    let cache = offline_cache_state_dir(engine_dir)
        .map_err(|error| error.to_string())
        .and_then(|cache_dir| {
            raiun_cache::Cache::open(&cache_dir, offline_cache::DEFAULT_CACHE_QUOTA_BYTES)
                .map_err(|error| error.to_string())
        });
    match cache {
        Ok(cache) => match engine.with_offline_cache(cache, account_id.to_owned(), origin) {
            Ok(engine) => (engine, None),
            Err(error) => (engine, Some(error.to_string())),
        },
        Err(error) => (engine, Some(error)),
    }
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

fn paths_overlap_existing(left: &Path, right: &Path) -> bool {
    if paths_overlap(left, right) {
        return true;
    }
    match (fs::canonicalize(left), fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => paths_overlap(&left, &right),
        _ => false,
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn validate_space_id(space_id: &str) -> Result<(), String> {
    if space_id.trim().is_empty()
        || space_id.trim() != space_id
        || space_id.len() > storage::MAX_SPACE_ID_BYTES
        || space_id.chars().any(char::is_control)
    {
        return Err("Space ID must be nonempty, bounded, and contain no control characters".into());
    }
    Ok(())
}

fn pair_is_scheduled(
    settings: &Settings,
    pair: &FolderPair,
    target_spaces: Option<&BTreeSet<String>>,
) -> bool {
    !settings.paused
        && !settings
            .paused_space_ids
            .iter()
            .any(|space_id| space_id == &pair.space_id)
        && settings.config.pairs.contains(pair)
        && target_spaces.is_none_or(|spaces| spaces.contains(&pair.space_id))
}

fn schedule_generation_is_current(
    expected: u64,
    current: u64,
    transitioning: bool,
    shutting_down: bool,
) -> bool {
    !transitioning && !shutting_down && current == expected
}

fn scheduler_loop(scheduler: Arc<Runtime>) {
    let mut ticks = 0u32;
    let mut last_offline_refresh: Option<std::time::Instant> = None;
    let mut last_refresh_generation: Option<u64> = None;
    loop {
        std::thread::sleep(Duration::from_secs(1));
        if scheduler.shutdown.load(Ordering::Acquire) {
            break;
        }
        let Ok(schedule_generation) = scheduler.operation_generation() else {
            continue;
        };
        if last_refresh_generation != Some(schedule_generation) {
            last_offline_refresh = None;
            last_refresh_generation = Some(schedule_generation);
        }
        ticks += 1;
        let forced = scheduler.wake.swap(false, Ordering::AcqRel);
        let periodic = ticks >= 30;
        let full_sync = forced || periodic;
        let target_spaces = if full_sync {
            if periodic || forced {
                ticks = 0;
            }
            if let Ok(mut pending) = scheduler.pending_space_syncs.lock() {
                pending.clear();
            }
            None
        } else {
            let Ok(mut pending) = scheduler.pending_space_syncs.lock() else {
                continue;
            };
            if pending.is_empty() {
                if ticks >= 30 {
                    ticks = 0;
                }
                continue;
            }
            Some(std::mem::take(&mut *pending))
        };
        if !full_sync && target_spaces.as_ref().is_none_or(BTreeSet::is_empty) {
            continue;
        }
        if let Err(error) = scheduler.refresh_session() {
            if let Ok(mut state) = scheduler.refresh_error.lock() {
                *state = Some(error);
            }
            continue;
        }
        if !schedule_generation_is_current(
            schedule_generation,
            scheduler.auth_generation.load(Ordering::Acquire),
            scheduler.auth_transition.load(Ordering::Acquire),
            scheduler.shutdown.load(Ordering::Acquire),
        ) {
            continue;
        }
        let generation = schedule_generation;
        if periodic && !forced {
            // Encrypted pins refresh only from the authenticated periodic
            // online scheduler, and only for routes still unlocked now.
            scheduler.refresh_due_vault_pins(generation);
        }
        if full_sync {
            // Queued encrypted edits retry after authenticated cycles, but
            // only for routes whose keys are already unlocked in memory.
            scheduler.retry_due_vault_edits(generation);
        }
        let offline_refresh_due = forced
            || last_offline_refresh
                .is_none_or(|last| last.elapsed() >= Duration::from_secs(5 * 60));
        if full_sync && offline_refresh_due {
            let engine = scheduler.engine();
            if let Ok(engine) = engine {
                if let Ok(_sync) = scheduler.sync_gate.lock() {
                    scheduler.cache_jobs.run_serialized(|| {
                        if schedule_generation_is_current(
                            generation,
                            scheduler.auth_generation.load(Ordering::Acquire),
                            scheduler.auth_transition.load(Ordering::Acquire),
                            scheduler.shutdown.load(Ordering::Acquire),
                        ) {
                            if let Ok(spaces) = engine.spaces() {
                                for space in spaces.into_iter().filter(|space| !space.encrypted) {
                                    if scheduler.shutdown.load(Ordering::Acquire)
                                        || scheduler.auth_transition.load(Ordering::Acquire)
                                        || scheduler.auth_generation.load(Ordering::Acquire)
                                            != generation
                                    {
                                        break;
                                    }
                                    // Cache refresh is best effort. Each Engine
                                    // call leaves stale/unavailable state durable
                                    // when a target cannot be safely refreshed.
                                    let _ = engine.refresh_offline_availability_cancellable(
                                        &space.id,
                                        || {
                                            scheduler.shutdown.load(Ordering::Acquire)
                                                || scheduler.auth_transition.load(Ordering::Acquire)
                                                || scheduler.auth_generation.load(Ordering::Acquire)
                                                    != generation
                                        },
                                    );
                                }
                            }
                        }
                    });
                }
            }
            last_offline_refresh = Some(std::time::Instant::now());
        }
        let Ok(settings) = scheduler.settings.lock().map(|s| s.clone()) else {
            break;
        };
        let Ok(_) = scheduler.engine() else {
            continue;
        };
        let pairs = settings
            .config
            .pairs
            .iter()
            .filter(|pair| pair_is_scheduled(&settings, pair, target_spaces.as_ref()))
            .cloned()
            .collect::<Vec<_>>();
        for pair in pairs {
            if scheduler.shutdown.load(Ordering::Acquire) {
                break;
            }
            // Constructing a per-pair backend may perform discovery, so do it
            // before taking the gate. Recheck persisted selection after taking
            // the gate immediately before the operation.
            let engine_result = scheduler.engine_for_pair(&pair);
            let Ok(_sync) = scheduler.sync_gate.lock() else {
                break;
            };
            if scheduler.shutdown.load(Ordering::Acquire)
                || scheduler.auth_transition.load(Ordering::Acquire)
                || scheduler.auth_generation.load(Ordering::Acquire) != generation
            {
                break;
            }
            let Ok(current_settings) = scheduler.settings.lock().map(|s| s.clone()) else {
                break;
            };
            if !pair_is_scheduled(&current_settings, &pair, target_spaces.as_ref()) {
                continue;
            }
            let engine = match engine_result {
                Ok(engine) => engine,
                Err(error) => {
                    scheduler.record_pair_report(generation, &pair, None, Some(error));
                    continue;
                }
            };
            let result = engine.sync_pair(&pair);
            drop(_sync);
            if scheduler.auth_generation.load(Ordering::Acquire) != generation {
                break;
            }
            match result {
                Ok(report) => scheduler.record_pair_report(generation, &pair, Some(report), None),
                Err(error) => {
                    scheduler.record_pair_report(generation, &pair, None, Some(error.to_string()));
                }
            }
        }
        // Periodic/full sync is also the bounded reconnect trigger for the
        // ordinary offline edit journal. Only exact-base conditional uploads
        // are attempted; pause/logout checks run between individual files.
        if full_sync && !settings.paused {
            if let Ok(engine) = scheduler.engine() {
                if let Ok(spaces) = engine.spaces() {
                    for space in spaces.into_iter().filter(|space| !space.encrypted) {
                        if scheduler.shutdown.load(Ordering::Acquire)
                            || scheduler.auth_transition.load(Ordering::Acquire)
                            || scheduler.auth_generation.load(Ordering::Acquire) != generation
                        {
                            break;
                        }
                        let Ok(_sync) = scheduler.sync_gate.lock() else {
                            break;
                        };
                        let current_settings = match scheduler.settings.lock() {
                            Ok(settings) => settings.clone(),
                            Err(_) => break,
                        };
                        if current_settings.paused
                            || current_settings
                                .paused_space_ids
                                .iter()
                                .any(|id| id == &space.id)
                        {
                            continue;
                        }
                        scheduler.cache_jobs.run_serialized(|| {
                            let _ = engine.reconcile_pending_file_writes_cancellable(
                                &space.id,
                                32,
                                || {
                                    let paused = scheduler
                                        .settings
                                        .lock()
                                        .map(|settings| {
                                            settings.paused
                                                || settings
                                                    .paused_space_ids
                                                    .iter()
                                                    .any(|id| id == &space.id)
                                        })
                                        .unwrap_or(true);
                                    paused
                                        || scheduler.shutdown.load(Ordering::Acquire)
                                        || scheduler.auth_transition.load(Ordering::Acquire)
                                        || scheduler.auth_generation.load(Ordering::Acquire)
                                            != generation
                                },
                            );
                        });
                    }
                }
            }
            scheduler.run_media_imports(generation, periodic);
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Raiun: {error}");
        std::process::exit(1);
    }
}

fn new_runtime(
    dir: PathBuf,
    scope: Option<String>,
    vaults: Arc<raiun_vault::session::VaultSessionCoordinator>,
) -> Result<Arc<Runtime>, String> {
    let local_profile_id = scope.clone().unwrap_or_else(|| "default".into());
    Ok(Arc::new(Runtime {
        settings: Mutex::new(Settings::load(&dir)?),
        transfer_budget: Mutex::new(None),
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
        pending_space_syncs: Mutex::new(BTreeSet::new()),
        pending_media_jobs: Mutex::new(BTreeMap::new()),
        mount: Mutex::new(None),
        sync_gate: Mutex::new(()),
        authenticating: AtomicBool::new(false),
        auth_generation: Arc::new(AtomicU64::new(0)),
        restoring: AtomicBool::new(true),
        shutdown: Arc::new(AtomicBool::new(false)),
        auth_transition: Arc::new(AtomicBool::new(false)),
        offline_namespace: AtomicBool::new(false),
        offline_namespace_probe_unix: AtomicU64::new(0),
        vault_account_id: scope.clone().unwrap_or_else(|| "default".into()),
        local_profile_id,
        cache_jobs: Arc::new(offline_cache::CacheJobs::default()),
        write_reconcile_jobs: Arc::new(offline_cache::WriteReconcileJobs::default()),
        vault_edit_reconcile_jobs: Arc::new(vault_edit_jobs::VaultEditReconcileJobs::default()),
        vault_pin_jobs: Arc::new(vault_pin_jobs::VaultPinJobs::default()),
        cache_error: Mutex::new(None),
        vault_cleanup_uncertain: AtomicBool::new(false),
        vaults,
        vault_mounts: raiun_fuse::VaultMountRegistry::new(),
        session_store: Arc::new(SecretServiceStore { scope }),
    }))
}

fn start_runtime(runtime: Arc<Runtime>) {
    let restore_generation = runtime.auth_generation.load(Ordering::Acquire);
    let restore = runtime.clone();
    std::thread::spawn(move || {
        let binding = capture_restore_binding(&restore);
        let mut session = None;
        let mut refreshed_session_needs_persist = false;
        let mut retry_number = 0u32;
        let mut first_attempt = true;

        loop {
            let result = match &binding {
                Ok(Some(binding)) => restore_saved_session_once(
                    &restore,
                    restore_generation,
                    binding,
                    &mut session,
                    &mut refreshed_session_needs_persist,
                ),
                Ok(None) => Ok(()),
                Err(error) => Err(RestoreFailure::Permanent(error.clone())),
            };

            // Sign-in remains available while a transient restore retries.
            if first_attempt {
                restore.restoring.store(false, Ordering::Release);
                first_attempt = false;
            }

            match result {
                Ok(()) => break,
                Err(RestoreFailure::Permanent(error)) => {
                    publish_restore_error(&restore, restore_generation, &binding, error);
                    break;
                }
                Err(RestoreFailure::Retryable(error)) => {
                    publish_restore_error(&restore, restore_generation, &binding, error);
                    let Some(binding) = binding.as_ref().ok().and_then(Option::as_ref) else {
                        break;
                    };
                    let delay = restore_retry_delay(retry_number);
                    retry_number = retry_number.saturating_add(1);
                    if !wait_for_restore_retry(&restore, restore_generation, binding, delay) {
                        break;
                    }
                }
            }
        }
        restore.restoring.store(false, Ordering::Release);
    });
    let scheduler = runtime.clone();
    std::thread::spawn(move || scheduler_loop(scheduler));
}

fn capture_restore_binding(runtime: &Runtime) -> Result<Option<RestoreBinding>, String> {
    let settings = runtime.settings.lock().map_err(|_| "Settings poisoned")?;
    let Some(server) = settings.server.clone() else {
        return Ok(None);
    };
    settings
        .network_proxy
        .validate()
        .map_err(|_| "Saved proxy configuration is invalid")?;
    if settings
        .network_proxy_account_id
        .as_deref()
        .is_some_and(|bound| settings.account_id.as_deref() != Some(bound))
    {
        return Err("Proxy configuration is bound to a different account".into());
    }
    Ok(Some(RestoreBinding {
        server,
        client_id: settings.client_id.clone(),
        proxy: settings.network_proxy.clone(),
        proxy_account_id: settings.network_proxy_account_id.clone(),
        account_id: settings.account_id.clone(),
    }))
}

fn restore_binding_matches(settings: &Settings, binding: &RestoreBinding) -> bool {
    settings.server.as_deref() == Some(binding.server.as_str())
        && settings.client_id == binding.client_id
        && settings.network_proxy == binding.proxy
        && settings.network_proxy_account_id == binding.proxy_account_id
        && settings.account_id == binding.account_id
}

fn restore_is_current(runtime: &Runtime, generation: u64, binding: &RestoreBinding) -> bool {
    if runtime.auth_generation.load(Ordering::Acquire) != generation
        || runtime.auth_transition.load(Ordering::Acquire)
        || runtime.shutdown.load(Ordering::Acquire)
    {
        return false;
    }
    runtime
        .settings
        .lock()
        .is_ok_and(|settings| restore_binding_matches(&settings, binding))
}

fn restore_saved_session_once(
    runtime: &Runtime,
    generation: u64,
    binding: &RestoreBinding,
    retained_session: &mut Option<auth::Session>,
    refreshed_session_needs_persist: &mut bool,
) -> Result<(), RestoreFailure> {
    if !restore_is_current(runtime, generation, binding) {
        return Err(RestoreFailure::Permanent(
            "Saved-session restore was canceled or its account settings changed".into(),
        ));
    }

    if retained_session.is_none() {
        let loaded = runtime
            .session_store
            .load_classified(&binding.server, &binding.client_id)
            .map_err(|error| match error {
                auth::SessionLoadError::Unavailable(message) => RestoreFailure::Retryable(message),
                auth::SessionLoadError::Invalid(message) => RestoreFailure::Permanent(message),
            })?;
        if !restore_is_current(runtime, generation, binding) {
            return Err(RestoreFailure::Permanent(
                "Saved-session restore was canceled or its account settings changed".into(),
            ));
        }
        let Some(session) = loaded else {
            return Err(RestoreFailure::Permanent(
                "No saved session is available in the keyring; sign in again".into(),
            ));
        };
        if session.server != binding.server || session.client_id != binding.client_id {
            return Err(RestoreFailure::Permanent(
                "Stored session does not match the configured account".into(),
            ));
        }
        *retained_session = Some(session);
    }

    let session = retained_session
        .as_mut()
        .ok_or_else(|| RestoreFailure::Permanent("Stored session is unavailable".into()))?;
    session.proxy = binding.proxy.clone();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| RestoreFailure::Permanent("System clock is invalid".into()))?
        .as_secs();
    if session.expires_at <= now + 120 {
        match session.refresh_classified() {
            Ok(()) => *refreshed_session_needs_persist = true,
            // A token-endpoint transport failure may be transient. The
            // authenticated Graph probe still decides whether this token is
            // accepted; its 401/403 is always terminal below.
            Err(auth::RefreshError::Transport) => {}
            Err(error) => return Err(RestoreFailure::Permanent(error.to_string())),
        }
    }

    if !restore_is_current(runtime, generation, binding) {
        return Err(RestoreFailure::Permanent(
            "Saved-session restore was canceled or its account settings changed".into(),
        ));
    }
    if *refreshed_session_needs_persist {
        runtime
            .persist_restored_refresh(session, generation, binding)
            .map_err(RestoreFailure::Retryable)?;
        *refreshed_session_needs_persist = false;
    }

    runtime.install_restored_session(session, generation, binding)
}

fn restore_retry_delay(retry_number: u32) -> Duration {
    let multiplier = 1u64.checked_shl(retry_number.min(10)).unwrap_or(u64::MAX);
    Duration::from_millis(500u64.saturating_mul(multiplier).min(300_000))
}

fn wait_for_restore_retry(
    runtime: &Runtime,
    generation: u64,
    binding: &RestoreBinding,
    delay: Duration,
) -> bool {
    let deadline = std::time::Instant::now() + delay;
    loop {
        if !restore_is_current(runtime, generation, binding) {
            return false;
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return true;
        }
        std::thread::sleep(remaining.min(Duration::from_millis(100)));
    }
}

fn publish_restore_error(
    runtime: &Runtime,
    generation: u64,
    binding: &Result<Option<RestoreBinding>, String>,
    error: String,
) {
    if runtime.auth_generation.load(Ordering::Acquire) != generation
        || runtime.auth_transition.load(Ordering::Acquire)
        || runtime.shutdown.load(Ordering::Acquire)
    {
        return;
    }
    if let Ok(Some(binding)) = binding
        && !restore_is_current(runtime, generation, binding)
    {
        return;
    }
    if let Ok(mut state) = runtime.error.lock() {
        *state = Some(error);
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
        if request.get("password").is_some()
            || request
                .get("action")
                .and_then(Value::as_str)
                .is_some_and(|a| matches!(a, "vault_unlock" | "vault_create"))
        {
            return Err(
                "Enter vault passwords in Raiun Desktop, never in command-line arguments".into(),
            );
        }
        let mut stream = UnixStream::connect(socket).map_err(|e| e.to_string())?;
        let response_timeout =
            if request.get("action").and_then(Value::as_str) == Some("auth_begin") {
                Duration::from_secs(65)
            } else if request.get("action").and_then(Value::as_str) == Some("shutdown") {
                Duration::from_secs(300)
            } else {
                Duration::from_secs(30)
            };
        stream
            .set_read_timeout(Some(response_timeout))
            .map_err(|e| e.to_string())?;
        write_json_line(&mut stream, &request)?;
        let response = read_json_line(&mut stream)?;
        let response = std::str::from_utf8(&response)
            .map_err(|_| "Agent response is not valid UTF-8".to_string())?;
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
    let signal_requested = Arc::new(AtomicBool::new(false));
    let signal = signal_requested.clone();
    ctrlc::set_handler(move || {
        signal.store(true, Ordering::Release);
    })
    .map_err(|error| format!("Could not install shutdown signal handlers: {error}"))?;
    let manager = ProfileManager::open(dir)?;
    // A bounded number of workers avoids an unbounded thread per socket request.
    let connections = Arc::new(Mutex::new(listener));
    let mut workers = Vec::new();
    for _ in 0..4 {
        let connections = connections.clone();
        let manager = manager.clone();
        workers.push(std::thread::spawn(move || {
            loop {
                let stream = match connections.lock() {
                    Ok(listener) => listener.accept(),
                    Err(_) => return,
                };
                let Ok((mut stream, _)) = stream else {
                    continue;
                };
                if manager.shutdown_requested() {
                    break;
                }
                let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
                let result =
                    read_json_value(&mut stream).and_then(|request| manager.handle(request));
                let response = match result {
                    Ok(data) => json!({"ok":true,"data":data}),
                    Err(error) => json!({"ok":false,"error":error}),
                };
                if write_json_line(&mut stream, &response).is_err() {
                    let _ = write_json_line(
                        &mut stream,
                        &json!({"ok":false,"error":"Could not encode bounded response"}),
                    );
                }
            }
        }));
    }
    loop {
        if signal_requested.swap(false, Ordering::AcqRel) {
            if let Err(error) = manager.request_shutdown() {
                eprintln!("Raiun: {error}");
            }
        }
        if manager.shutdown_requested() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

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
    use raiun_core::WindowsNameWarning;

    #[test]
    fn listing_response_adds_advisories_without_changing_remote_names() {
        let entries = vec![
            RemoteEntry {
                id: "remote-1".into(),
                path: "/Photos/CON.txt".into(),
                directory: true,
                size: 0,
                etag: String::new(),
                modified_unix: 0,
                writable: true,
                encrypted: false,
            },
            RemoteEntry {
                id: "remote-2".into(),
                path: "/Photos/con.TXT".into(),
                directory: false,
                size: 4,
                etag: String::new(),
                modified_unix: 0,
                writable: true,
                encrypted: false,
            },
            RemoteEntry {
                id: "remote-3".into(),
                path: "/Photos/linux name.txt".into(),
                directory: false,
                size: 4,
                etag: String::new(),
                modified_unix: 0,
                writable: true,
                encrypted: false,
            },
        ];
        let response = remote_listing_response(entries).unwrap();
        assert_eq!(response[0]["path"], "/Photos/CON.txt");
        assert_eq!(
            response[0]["windows_portability_warnings"],
            json!([
                WindowsNameWarning::ReservedDeviceName,
                WindowsNameWarning::CaseCollision
            ])
        );
        assert_eq!(
            response[1]["windows_portability_warnings"],
            json!([
                WindowsNameWarning::ReservedDeviceName,
                WindowsNameWarning::CaseCollision
            ])
        );
        assert!(response[2].get("windows_portability_warnings").is_none());
        assert_eq!(response[2]["path"], "/Photos/linux name.txt");
    }

    #[test]
    fn offline_pin_ipc_preserves_stale_state() {
        assert_eq!(
            offline_pin_state_name(raiun_cache::PinState::Building),
            "building"
        );
        assert_eq!(
            offline_pin_state_name(raiun_cache::PinState::Ready),
            "ready"
        );
        assert_eq!(
            offline_pin_state_name(raiun_cache::PinState::Stale),
            "stale"
        );
    }

    #[test]
    fn control_request_is_bounded_and_stops_at_one_json_line() {
        let mut input = &b"{\"action\":\"status\"}\nignored"[..];
        let decoded: Value = read_json_value(&mut input).unwrap();
        assert_eq!(decoded["action"], "status");
        let oversized = vec![b'x'; raiun_control::MAX_CONTROL_MESSAGE_BYTES + 1];
        assert!(read_json_line(&mut oversized.as_slice()).is_err());
    }

    #[test]
    fn pair_exclusions_are_persisted_before_new_policy_dispatches() {
        let dir = tempfile::tempdir().unwrap();
        let mut pair = test_pair("selective", "space-a");
        pair.local_path = dir.path().join("selective");
        fs::create_dir(&pair.local_path).unwrap();
        let runtime = Arc::new(runtime_for_mount_test(
            dir.path().to_path_buf(),
            false,
            None,
        ));
        *runtime.settings.lock().unwrap() = test_settings(vec![pair.clone()]);
        runtime.settings.lock().unwrap().save(dir.path()).unwrap();
        let engine =
            Engine::open(&dir.path().join("engine"), Arc::new(OfflineCacheFixture)).unwrap();
        runtime.auth_state.lock().unwrap().engine = Some(engine.clone());
        engine.publish_pair_policy(&pair).unwrap();

        let result = runtime
            .handle(json!({
                "action":"pair_exclusions_set",
                "id":"selective",
                "excluded_paths":["archive", "private/notes.txt"]
            }))
            .unwrap();
        assert_eq!(result["pair_id"], "selective");
        assert_eq!(
            result["excluded_paths"],
            json!(["archive", "private/notes.txt"])
        );
        let persisted = Settings::load(dir.path()).unwrap();
        assert_eq!(
            persisted.config.pairs[0].excluded_paths,
            vec!["archive", "private/notes.txt"]
        );
        assert_eq!(
            engine.sync_pair(&pair).unwrap_err().kind,
            raiun_core::backend::ErrorKind::Conflict
        );
        let updated = FolderPair {
            excluded_paths: vec!["archive".into(), "private/notes.txt".into()],
            ..pair
        };
        runtime
            .handle(json!({"action":"pair_remove","id":"selective"}))
            .unwrap();
        assert!(Settings::load(dir.path()).unwrap().config.pairs.is_empty());
        assert_eq!(
            engine.sync_pair(&updated).unwrap_err().kind,
            raiun_core::backend::ErrorKind::Conflict,
            "a stale snapshot cannot reactivate a retired ID"
        );
    }

    #[test]
    fn invalid_pair_exclusions_leave_persisted_and_dispatch_policy_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let mut pair = test_pair("selective-invalid", "space-a");
        pair.local_path = dir.path().join("local");
        fs::create_dir(&pair.local_path).unwrap();
        pair.remote_path = "/folder".into();
        pair.mode = raiun_core::SyncMode::UploadOnly;
        let runtime = Arc::new(runtime_for_mount_test(
            dir.path().to_path_buf(),
            false,
            None,
        ));
        *runtime.settings.lock().unwrap() = test_settings(vec![pair.clone()]);
        runtime.settings.lock().unwrap().save(dir.path()).unwrap();
        let engine =
            Engine::open(&dir.path().join("engine"), Arc::new(OfflineCacheFixture)).unwrap();
        runtime.auth_state.lock().unwrap().engine = Some(engine.clone());
        engine.publish_pair_policy(&pair).unwrap();

        assert!(
            runtime
                .handle(json!({
                    "action":"pair_exclusions_set",
                    "id":"selective-invalid",
                    "excluded_paths":["../outside"]
                }))
                .is_err()
        );
        assert!(
            Settings::load(dir.path()).unwrap().config.pairs[0]
                .excluded_paths
                .is_empty()
        );
        engine.sync_pair(&pair).unwrap();
    }

    #[test]
    fn settings_save_failure_does_not_publish_an_unsaved_exclusion_policy() {
        let dir = tempfile::tempdir().unwrap();
        let mut pair = test_pair("selective-save-fail", "space-a");
        pair.local_path = dir.path().join("local");
        fs::create_dir(&pair.local_path).unwrap();
        pair.remote_path = "/folder".into();
        pair.mode = raiun_core::SyncMode::UploadOnly;
        let runtime = Arc::new(runtime_for_mount_test(
            dir.path().to_path_buf(),
            false,
            None,
        ));
        *runtime.settings.lock().unwrap() = test_settings(vec![pair.clone()]);
        runtime.settings.lock().unwrap().save(dir.path()).unwrap();
        let engine =
            Engine::open(&dir.path().join("engine"), Arc::new(OfflineCacheFixture)).unwrap();
        runtime.auth_state.lock().unwrap().engine = Some(engine.clone());
        engine.publish_pair_policy(&pair).unwrap();

        fs::remove_file(dir.path().join("settings.json")).unwrap();
        fs::create_dir(dir.path().join("settings.json")).unwrap();
        assert!(
            runtime
                .handle(json!({
                    "action":"pair_exclusions_set",
                    "id":"selective-save-fail",
                    "excluded_paths":["private"]
                }))
                .is_err()
        );
        assert!(
            runtime.settings.lock().unwrap().config.pairs[0]
                .excluded_paths
                .is_empty()
        );
        engine
            .sync_pair(&pair)
            .expect("failed settings write must leave old dispatch policy active");
    }

    #[test]
    fn space_disconnect_retires_only_target_connections_and_keeps_files() {
        let dir = tempfile::tempdir().unwrap();
        let mut pairs = vec![
            test_pair("first", "space-a"),
            test_pair("second", "space-a"),
            test_pair("other", "space-b"),
        ];
        for pair in &mut pairs {
            pair.local_path = dir.path().join(&pair.id);
            fs::create_dir(&pair.local_path).unwrap();
            fs::write(pair.local_path.join("keep.txt"), pair.id.as_bytes()).unwrap();
        }
        let runtime = Arc::new(runtime_for_mount_test(
            dir.path().to_path_buf(),
            false,
            None,
        ));
        *runtime.settings.lock().unwrap() = test_settings(pairs.clone());
        runtime.settings.lock().unwrap().save(dir.path()).unwrap();
        let engine =
            Engine::open(&dir.path().join("engine"), Arc::new(OfflineCacheFixture)).unwrap();
        for pair in &pairs {
            engine.publish_pair_policy(pair).unwrap();
        }
        runtime.auth_state.lock().unwrap().engine = Some(engine.clone());
        let response = runtime
            .handle(json!({"action":"space_disconnect","space_id":"space-a"}))
            .unwrap();
        assert_eq!(response["removed_pair_ids"], json!(["first", "second"]));
        let persisted = Settings::load(dir.path()).unwrap();
        assert_eq!(persisted.config.pairs.len(), 1);
        assert_eq!(persisted.config.pairs[0].id, "other");
        assert!(persisted.retired_pair_ids.contains(&"first".into()));
        assert!(persisted.retired_pair_ids.contains(&"second".into()));
        for pair in &pairs {
            assert_eq!(
                fs::read(pair.local_path.join("keep.txt")).unwrap(),
                pair.id.as_bytes()
            );
        }
        for pair in &pairs[..2] {
            assert_eq!(
                engine.sync_pair(pair).unwrap_err().kind,
                raiun_core::backend::ErrorKind::Conflict
            );
        }
        engine
            .publish_pair_policy(&pairs[2])
            .expect("other Space remains connected");
        assert_eq!(
            runtime
                .handle(json!({"action":"space_disconnect","space_id":"space-a"}))
                .unwrap()["removed_pair_ids"],
            json!([])
        );
    }

    #[test]
    fn space_disconnect_persistence_failure_keeps_every_connection_active() {
        let dir = tempfile::tempdir().unwrap();
        let mut pair = test_pair("retained", "space-a");
        pair.local_path = dir.path().join("local");
        fs::create_dir(&pair.local_path).unwrap();
        let runtime = Arc::new(runtime_for_mount_test(
            dir.path().to_path_buf(),
            false,
            None,
        ));
        *runtime.settings.lock().unwrap() = test_settings(vec![pair.clone()]);
        runtime.settings.lock().unwrap().save(dir.path()).unwrap();
        let engine =
            Engine::open(&dir.path().join("engine"), Arc::new(OfflineCacheFixture)).unwrap();
        engine.publish_pair_policy(&pair).unwrap();
        runtime.auth_state.lock().unwrap().engine = Some(engine.clone());
        fs::remove_file(dir.path().join("settings.json")).unwrap();
        fs::create_dir(dir.path().join("settings.json")).unwrap();
        assert!(
            runtime
                .handle(json!({"action":"space_disconnect","space_id":"space-a"}))
                .is_err()
        );
        let settings = runtime.settings.lock().unwrap();
        assert_eq!(settings.config.pairs.len(), 1);
        assert!(settings.retired_pair_ids.is_empty());
        drop(settings);
        engine
            .publish_pair_policy(&pair)
            .expect("failed durable write must not publish retirement");
    }

    fn test_pair(id: &str, space_id: &str) -> FolderPair {
        FolderPair {
            id: id.into(),
            local_path: PathBuf::from(format!("/tmp/{id}")),
            space_id: space_id.into(),
            vault: None,
            remote_path: "/Documents".into(),
            mode: raiun_core::SyncMode::TwoWay,
            excluded_paths: Vec::new(),
        }
    }

    fn test_settings(pairs: Vec<FolderPair>) -> Settings {
        Settings {
            config: Config {
                schema_version: CONFIG_SCHEMA_VERSION,
                cloud_root: PathBuf::from("/tmp/cloud"),
                pairs,
            },
            server: None,
            client_id: "OpenCloudDesktop".into(),
            account_id: None,
            retired_pair_ids: Vec::new(),
            paused: false,
            paused_space_ids: Vec::new(),
            mount_enabled: false,
            media_jobs: Vec::new(),
            network_proxy: raiun_opencloud::ProxyConfig::System,
            network_proxy_account_id: None,
            network_proxy_revision: 1,
            bandwidth_limits: TransferLimits::default(),
            bandwidth_account_id: None,
            bandwidth_revision: 1,
        }
    }

    #[test]
    fn proxy_settings_are_revisioned_validated_and_require_reconnect() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = Arc::new(runtime_for_mount_test(
            dir.path().to_path_buf(),
            false,
            None,
        ));
        let initial = runtime.handle(json!({"action":"network_proxy"})).unwrap();
        assert_eq!(initial["proxy"]["mode"], "system");
        assert_eq!(initial["revision"], 1);
        assert_eq!(initial["apply_requires_reconnect"], true);

        let invalid = runtime.handle(json!({
            "action":"network_proxy_set",
            "expected_revision":1,
            "expected_account_id":null,
            "proxy":{"mode":"explicit","url":"http://user:secret@proxy.example"}
        }));
        let error = invalid.unwrap_err();
        assert!(error.contains("invalid"));
        assert!(!error.contains("secret"));

        let updated = runtime
            .handle(json!({
                "action":"network_proxy_set",
                "expected_revision":1,
                "expected_account_id":null,
                "proxy":{"mode":"direct"}
            }))
            .unwrap();
        assert_eq!(updated["proxy"]["mode"], "direct");
        assert_eq!(updated["revision"], 2);
        assert_eq!(updated["account_id"], Value::Null);

        let stale = runtime.handle(json!({
            "action":"network_proxy_set",
            "expected_revision":1,
            "expected_account_id":null,
            "proxy":{"mode":"system"}
        }));
        assert!(stale.unwrap_err().contains("changed"));
        let saved = Settings::load(dir.path()).unwrap();
        assert_eq!(saved.network_proxy, raiun_opencloud::ProxyConfig::Direct);
        assert_eq!(saved.network_proxy_revision, 2);
    }

    #[test]
    fn bandwidth_settings_apply_to_current_streams_and_fence_account_revision() {
        use std::{io::Read, num::NonZeroU64, thread, time::Instant};

        let dir = tempfile::tempdir().unwrap();
        let runtime = Arc::new(runtime_for_mount_test(
            dir.path().to_path_buf(),
            false,
            None,
        ));
        let old_rate = NonZeroU64::new(1).unwrap();
        let new_rate = NonZeroU64::new(8192).unwrap();
        let budget = TransferBudget::new();
        budget.set_limits(TransferLimits {
            upload_bytes_per_second: Some(old_rate),
            download_bytes_per_second: None,
        });
        *runtime.transfer_budget.lock().unwrap() = Some(("account-a".into(), budget.clone()));
        let client = raiun_opencloud::OpenCloudClient::new(
            "https://cloud.example.test",
            "synthetic-token".into(),
        )
        .unwrap();
        let engine = Engine::open(&dir.path().join("engine"), Arc::new(client.clone())).unwrap();
        {
            let mut auth = runtime.auth_state.lock().unwrap();
            auth.account_id = Some("account-a".into());
            auth.client = Some(client);
            auth.engine = Some(engine);
        }
        {
            let mut settings = runtime.settings.lock().unwrap();
            settings.account_id = Some("account-a".into());
            settings.bandwidth_account_id = Some("account-a".into());
            settings.bandwidth_limits = budget.limits();
            settings.save(dir.path()).unwrap();
        }

        let mut reader = budget.reader(
            raiun_opencloud::transfer_budget::TransferDirection::Upload,
            &[1, 2][..],
        );
        let mut first = [0];
        reader.read_exact(&mut first).unwrap();
        let waiting = thread::spawn(move || {
            let started = Instant::now();
            let mut rest = Vec::new();
            reader.read_to_end(&mut rest).unwrap();
            (started.elapsed(), rest)
        });
        thread::sleep(Duration::from_millis(30));
        let saved = runtime
            .handle(json!({
                "action":"bandwidth_limits_set",
                "expected_account_id":"account-a",
                "expected_revision":1,
                "limits":{
                    "upload_bytes_per_second":8192,
                    "download_bytes_per_second":null
                }
            }))
            .unwrap();
        assert_eq!(saved["revision"], 2);
        assert_eq!(saved["apply_immediately"], true);
        let (elapsed, rest) = waiting.join().unwrap();
        assert!(elapsed < Duration::from_millis(500));
        assert_eq!(rest, vec![2]);
        assert_eq!(budget.limits().upload_bytes_per_second, Some(new_rate));

        let persisted = Settings::load(dir.path()).unwrap();
        assert_eq!(persisted.bandwidth_account_id.as_deref(), Some("account-a"));
        assert_eq!(persisted.bandwidth_revision, 2);
        assert_eq!(
            persisted.bandwidth_limits.upload_bytes_per_second,
            Some(new_rate)
        );
        assert!(
            runtime
                .handle(json!({
                    "action":"bandwidth_limits_set",
                    "expected_account_id":"account-b",
                    "expected_revision":2,
                    "limits":{"upload_bytes_per_second":null,"download_bytes_per_second":null}
                }))
                .is_err()
        );
        assert!(
            runtime
                .handle(json!({
                    "action":"bandwidth_limits_set",
                    "expected_account_id":"account-a",
                    "expected_revision":1,
                    "limits":{"upload_bytes_per_second":null,"download_bytes_per_second":null}
                }))
                .is_err()
        );
        assert_eq!(budget.limits().upload_bytes_per_second, Some(new_rate));
    }

    #[test]
    fn account_switch_creates_a_separate_transfer_controller() {
        use std::num::NonZeroU64;

        let runtime =
            runtime_for_mount_test(PathBuf::from("/tmp/bandwidth-account-scope"), false, None);
        let previous = TransferBudget::new();
        previous.set_limits(TransferLimits {
            upload_bytes_per_second: Some(NonZeroU64::new(64).unwrap()),
            download_bytes_per_second: None,
        });
        *runtime.transfer_budget.lock().unwrap() = Some(("account-a".into(), previous.clone()));
        let next = runtime
            .transfer_budget_for_account("account-b", TransferLimits::default())
            .unwrap();
        assert_ne!(previous.limits(), next.limits());
        assert_eq!(
            previous.limits().upload_bytes_per_second,
            NonZeroU64::new(64)
        );
        assert_eq!(next.limits(), TransferLimits::default());
        assert_eq!(
            runtime.transfer_budget.lock().unwrap().as_ref().unwrap().0,
            "account-a",
            "a candidate account must not replace the active controller before commit"
        );
    }

    #[test]
    fn media_jobs_do_not_follow_a_profile_into_a_different_account() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        fs::create_dir(&source).unwrap();
        let runtime = Arc::new(runtime_for_mount_test(
            dir.path().to_path_buf(),
            false,
            None,
        ));
        {
            let mut settings = runtime.settings.lock().unwrap();
            settings.account_id = Some("bbbbbbbb".into());
            settings.media_jobs.push(MediaImportJob {
                id: "old-account-backup".into(),
                revision: 1,
                account_id: "aaaaaaaa".into(),
                source_root: source.clone(),
                space_id: "same-space-id".into(),
                destination_root: "/Photos".into(),
                destination_root_resource_id: "same-folder-id".into(),
                filter: raiun_core::MediaFilter::Photos,
                organization: raiun_core::MediaOrganization::PreserveRelativePath,
                filesystem_mtime_utc: false,
                interval_seconds: 3600,
                enabled: true,
            });
        }

        // A profile can sign in as another user who happens to expose the
        // same Space and folder IDs. The stored account binding still blocks
        // both automatic admission and a stale destination-save request.
        runtime.run_media_imports(0, true);
        assert!(
            Engine::media_import_status_at(
                &account_engine_dir(dir.path(), "aaaaaaaa"),
                "old-account-backup"
            )
            .unwrap()
            .is_none()
        );
        assert!(runtime.pending_media_jobs.lock().unwrap().is_empty());
        let listed = runtime.media_jobs_value().unwrap();
        assert!(listed["account_id"].is_null());
        assert_eq!(listed["jobs"][0]["active_account"], false);

        let result = runtime.handle(json!({
            "action":"media_job_set",
            "expected_account_id":"aaaaaaaa",
            "expected_revision":0,
            "job":{
                "id":"new-backup",
                "revision":0,
                "account_id":"aaaaaaaa",
                "source_root":source,
                "space_id":"same-space-id",
                "destination_root":"/Photos",
                "destination_root_resource_id":"same-folder-id",
                "filter":"photos",
                "organization":"preserve_relative_path",
                "filesystem_mtime_utc":false,
                "interval_seconds":3600,
                "enabled":true
            }
        }));
        assert!(result.is_err());
        assert_eq!(runtime.settings.lock().unwrap().media_jobs.len(), 1);
    }

    #[test]
    fn media_upload_verification_rejects_stale_requests_without_queueing_or_waking() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = Arc::new(runtime_for_mount_test(
            dir.path().to_path_buf(),
            false,
            None,
        ));
        let engine = Engine::open(&dir.path().join("engine"), Arc::new(OfflineCacheFixture))
            .unwrap()
            .with_account_scope("account-a".into(), "https://fixture.example.test".into())
            .unwrap();
        {
            let mut auth = runtime.auth_state.lock().unwrap();
            auth.account_id = Some("account-a".into());
            auth.engine = Some(engine);
        }
        let job = MediaImportJob {
            id: "verify-backup".into(),
            revision: 7,
            account_id: "account-a".into(),
            source_root: dir.path().join("source"),
            space_id: "space-a".into(),
            destination_root: "/folder".into(),
            destination_root_resource_id: "folder".into(),
            filter: raiun_core::MediaFilter::Photos,
            organization: raiun_core::MediaOrganization::PreserveRelativePath,
            filesystem_mtime_utc: false,
            interval_seconds: 3600,
            enabled: false,
        };
        {
            let mut settings = runtime.settings.lock().unwrap();
            settings.account_id = Some("account-a".into());
            settings.media_jobs = vec![job.clone()];
        }
        let request = json!({"action":"media_job_verify_upload","job_id":job.id,
            "expected_account_id":"account-a","expected_revision":7,"attempt_generation":1,
            "source_relative_path":"photo.jpg","destination_path":"/folder/photo.jpg"});
        for (field, value) in [
            ("expected_account_id", json!("other-account")),
            ("expected_revision", json!(6)),
            ("attempt_generation", json!(true)),
            ("attempt_generation", json!(0)),
        ] {
            let mut stale = request.clone();
            stale[field] = value;
            assert!(runtime.handle(stale).is_err());
        }
        // No retained row exists; this must remain a sanitized observation failure.
        let error = runtime.handle(request.clone()).unwrap_err();
        assert_eq!(
            error,
            "Could not safely verify the uploaded copy. Retained recovery is unchanged."
        );
        runtime.auth_transition.store(true, Ordering::Release);
        assert!(runtime.handle(request).is_err());
        assert!(runtime.pending_media_jobs.lock().unwrap().is_empty());
        assert_eq!(runtime.settings.lock().unwrap().media_jobs, vec![job]);
    }

    #[test]
    fn media_recovery_listing_is_scoped_to_saved_job_revision_and_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        fs::create_dir(&source).unwrap();
        let runtime = Arc::new(runtime_for_mount_test(
            dir.path().to_path_buf(),
            false,
            None,
        ));
        let mut settings = test_settings(Vec::new());
        settings.account_id = Some("account-hash".into());
        settings.media_jobs.push(MediaImportJob {
            id: "backup-one".into(),
            revision: 7,
            account_id: "account-hash".into(),
            source_root: source,
            space_id: "space-one".into(),
            destination_root: "/Photos".into(),
            destination_root_resource_id: "photos-folder".into(),
            filter: raiun_core::MediaFilter::Photos,
            organization: raiun_core::MediaOrganization::PreserveRelativePath,
            filesystem_mtime_utc: false,
            interval_seconds: 3600,
            enabled: true,
        });
        *runtime.settings.lock().unwrap() = settings;

        let request = json!({
            "action":"media_job_recovery",
            "job_id":"backup-one",
            "expected_revision":7,
            "expected_account_id":"account-hash",
            "limit":100,
            "cursor":null
        });
        let page = runtime.handle(request.clone()).unwrap();
        assert_eq!(page["job_id"], "backup-one");
        assert_eq!(page["account_id"], "account-hash");
        assert_eq!(page["revision"], 7);
        assert!(page["page"]["items"].as_array().unwrap().is_empty());
        assert_eq!(page["page"]["has_more"], false);
        assert_eq!(page["page"]["account_has_unindexed_stage"], false);

        let mut stale = request.clone();
        stale["expected_revision"] = json!(6);
        assert!(runtime.handle(stale).is_err());
        let mut wrong_account = request.clone();
        wrong_account["expected_account_id"] = json!("other-account");
        assert!(runtime.handle(wrong_account).is_err());
        let mut oversized = request;
        oversized["limit"] = json!(101);
        assert!(runtime.handle(oversized).is_err());
    }

    #[test]
    fn paused_queued_media_job_does_not_starve_later_runnable_job() {
        let mut settings = test_settings(Vec::new());
        settings.account_id = Some("account-a".into());
        settings.paused_space_ids = vec!["paused-space".into()];
        let make_job = |id: &str, space_id: &str| MediaImportJob {
            id: id.into(),
            revision: 1,
            account_id: "account-a".into(),
            source_root: PathBuf::from("/tmp/media-source"),
            space_id: space_id.into(),
            destination_root: "/Photos".into(),
            destination_root_resource_id: "photos-folder".into(),
            filter: raiun_core::MediaFilter::Photos,
            organization: raiun_core::MediaOrganization::PreserveRelativePath,
            filesystem_mtime_utc: false,
            interval_seconds: 3_600,
            enabled: true,
        };
        settings
            .media_jobs
            .push(make_job("a-paused", "paused-space"));
        settings
            .media_jobs
            .push(make_job("b-runnable", "active-space"));
        let pending = BTreeMap::from([
            (
                "a-paused".into(),
                PendingMediaJob {
                    revision: 1,
                    auth_generation: 7,
                },
            ),
            (
                "b-runnable".into(),
                PendingMediaJob {
                    revision: 1,
                    auth_generation: 7,
                },
            ),
        ]);

        let selected = select_queued_media_job(&settings, &pending, 7, "account-a").unwrap();
        assert_eq!(selected.id, "b-runnable");
        assert!(pending.contains_key("a-paused"));
    }

    #[test]
    fn waiting_for_stability_revisits_at_stability_window_not_full_interval() {
        let status = MediaImportRunStatus {
            job_id: "backup".into(),
            generation: 1,
            state: "completed".into(),
            scanned: 1,
            waiting_for_stability: 1,
            uploaded: 0,
            unchanged: 0,
            conflicts: 0,
            needs_attention: 0,
            last_error: None,
            updated_unix: 100,
        };
        assert!(!media_job_is_due(Some(&status), 109, 3_600));
        assert!(media_job_is_due(Some(&status), 110, 3_600));

        let mut settled = status;
        settled.waiting_for_stability = 0;
        assert!(!media_job_is_due(Some(&settled), 110, 3_600));
        assert!(media_job_is_due(Some(&settled), 3_700, 3_600));
    }

    #[cfg(unix)]
    #[test]
    fn media_source_overlap_checks_existing_symlink_aliases() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real-source");
        let alias = dir.path().join("alias-source");
        fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        assert!(paths_overlap_existing(&alias, &real));
        assert!(!paths_overlap_existing(
            &alias,
            &dir.path().join("unrelated")
        ));
    }

    struct OfflineCacheFixture;

    impl CloudBackend for OfflineCacheFixture {
        fn server_origin(&self) -> Option<String> {
            Some("https://fixture.example.test".into())
        }

        fn spaces(
            &self,
        ) -> Result<Vec<raiun_core::backend::CloudSpace>, raiun_core::backend::CloudError> {
            Ok(vec![raiun_core::backend::CloudSpace {
                id: "space-a".into(),
                name: "Space A".into(),
                dav_url: "https://fixture.example.test/dav/space-a".into(),
                personal: true,
                writable: true,
                encrypted: false,
            }])
        }

        fn list(
            &self,
            _: &str,
            path: &str,
            visit: &mut dyn FnMut(
                raiun_core::backend::RemoteEntry,
            ) -> Result<(), raiun_core::backend::CloudError>,
        ) -> Result<(), raiun_core::backend::CloudError> {
            let children = match path {
                "/" => vec![fixture_entry("folder", "/folder", true, 0)],
                "/folder" => vec![fixture_entry("file-v1", "/folder/file.txt", false, 4)],
                _ => Vec::new(),
            };
            for entry in children {
                visit(entry)?;
            }
            Ok(())
        }

        fn stat(
            &self,
            _: &str,
            path: &str,
        ) -> Result<raiun_core::backend::RemoteEntry, raiun_core::backend::CloudError> {
            match path {
                "/" => Ok(fixture_entry("root-a", "/", true, 0)),
                "/folder" => Ok(fixture_entry("folder", "/folder", true, 0)),
                "/folder/file.txt" => Ok(fixture_entry("file-v1", "/folder/file.txt", false, 4)),
                _ => Err(raiun_core::backend::CloudError::new(
                    raiun_core::backend::ErrorKind::NotFound,
                    "fixture path not found",
                )),
            }
        }

        fn download(
            &self,
            _: &str,
            path: &str,
            expected_etag: Option<&str>,
            destination: &Path,
        ) -> Result<raiun_core::backend::RemoteEntry, raiun_core::backend::CloudError> {
            if path != "/folder/file.txt" || expected_etag.is_some_and(|etag| etag != "etag-v1") {
                return Err(raiun_core::backend::CloudError::new(
                    raiun_core::backend::ErrorKind::Conflict,
                    "fixture version mismatch",
                ));
            }
            fs::write(destination, b"data").map_err(|error| {
                raiun_core::backend::CloudError::new(
                    raiun_core::backend::ErrorKind::Io,
                    error.to_string(),
                )
            })?;
            self.stat("space-a", path)
        }

        fn upload(
            &self,
            _: &str,
            _: &str,
            _: &Path,
            _: raiun_core::backend::WriteCondition,
        ) -> Result<raiun_core::backend::RemoteEntry, raiun_core::backend::CloudError> {
            unreachable!("offline cache fixture is read-only")
        }

        fn mkdir(
            &self,
            _: &str,
            _: &str,
        ) -> Result<raiun_core::backend::RemoteEntry, raiun_core::backend::CloudError> {
            unreachable!("offline cache fixture is read-only")
        }

        fn delete(&self, _: &str, _: &str, _: &str) -> Result<(), raiun_core::backend::CloudError> {
            unreachable!("offline cache fixture is read-only")
        }

        fn rename(
            &self,
            _: &str,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<raiun_core::backend::RemoteEntry, raiun_core::backend::CloudError> {
            unreachable!("offline cache fixture is read-only")
        }
    }

    fn fixture_entry(
        id: &str,
        path: &str,
        directory: bool,
        size: u64,
    ) -> raiun_core::backend::RemoteEntry {
        raiun_core::backend::RemoteEntry {
            id: id.into(),
            path: path.into(),
            directory,
            size,
            etag: if directory {
                format!("{id}-dir")
            } else {
                "etag-v1".into()
            },
            modified_unix: 1,
            writable: true,
            encrypted: false,
        }
    }

    #[test]
    fn offline_cache_ipc_policy_and_recursive_pin_are_profile_scoped() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = Arc::new(runtime_for_mount_test(
            dir.path().to_path_buf(),
            false,
            None,
        ));
        let account_id = account_identity("https://fixture.example.test", "personal-drive");
        let engine_dir = account_engine_dir(dir.path(), &account_id);
        let base = Engine::open(&engine_dir, Arc::new(OfflineCacheFixture)).unwrap();
        let cache_state = offline_cache_state_dir(&engine_dir).unwrap();
        let cache =
            raiun_cache::Cache::open(&cache_state, offline_cache::DEFAULT_CACHE_QUOTA_BYTES)
                .unwrap();
        let engine = base
            .with_offline_cache(
                cache,
                account_id.clone(),
                "https://fixture.example.test".into(),
            )
            .unwrap();
        runtime.settings.lock().unwrap().account_id = Some(account_id.clone());
        runtime.settings.lock().unwrap().server = Some("https://fixture.example.test".into());
        runtime.auth_state.lock().unwrap().engine = Some(engine);

        let policy = runtime
            .handle(json!({
                "action":"cache_policy_set",
                "space_id":"space-a",
                "path":"/folder/file.txt",
                "policy":"always_offline"
            }))
            .unwrap();
        assert_eq!(policy["policy"], "always_offline");
        let persisted = runtime
            .handle(json!({
                "action":"cache_policy_get",
                "space_id":"space-a",
                "path":"/folder/file.txt"
            }))
            .unwrap();
        assert_eq!(persisted["policy"], "always_offline");

        let started = runtime
            .handle(json!({
                "action":"cache_pin_start",
                "space_id":"space-a",
                "path":"/folder"
            }))
            .unwrap();
        let job_id = started["job_id"].as_str().unwrap().to_owned();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let status = loop {
            let status = runtime
                .handle(json!({
                    "action":"cache_pin_status",
                    "space_id":"space-a",
                    "job_id":job_id
                }))
                .unwrap();
            if status["state"] == "ready" || status["state"] == "failed" {
                break status;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "pin job did not finish"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(status["state"], "ready", "{status}");
        assert_eq!(status["files_done"], 1);
        let edit = dir.path().join("pending-edit.bin");
        fs::write(&edit, b"offline local edit").unwrap();
        runtime
            .engine()
            .unwrap()
            .queue_offline_file_write(
                "space-a",
                "/folder/file.txt",
                &edit,
                raiun_core::backend::WriteCondition::Match("etag-v1".into()),
            )
            .expect("seed local pending-write journal");
        let pending = runtime
            .handle(json!({"action":"cache_pending_writes","limit":10}))
            .unwrap();
        assert_eq!(pending["pending_count"], 1);
        assert_eq!(pending["conflict_count"], 0);
        assert_eq!(pending["items"][0]["space_id"], "space-a");
        assert_eq!(pending["items"][0]["root_resource_id"], "root-a");
        assert_eq!(pending["items"][0]["path"], "/folder/file.txt");
        assert_eq!(pending["items"][0]["state"], "pending");
        assert_eq!(pending["items"][0]["bytes"], b"offline local edit".len());
        let pins = runtime
            .handle(json!({"action":"cache_pins","space_id":"space-a"}))
            .unwrap();
        assert_eq!(pins.as_array().unwrap().len(), 1);
        let reopened = Engine::open(&engine_dir, Arc::new(OfflineCacheFixture)).unwrap();
        let reopened_cache =
            raiun_cache::Cache::open(&cache_state, offline_cache::DEFAULT_CACHE_QUOTA_BYTES)
                .unwrap();
        let reopened = reopened
            .with_offline_cache(
                reopened_cache,
                account_id.clone(),
                "https://fixture.example.test".into(),
            )
            .unwrap();
        assert_eq!(
            reopened
                .availability_policy("space-a", "/folder/file.txt")
                .unwrap(),
            AvailabilityPolicy::AlwaysOffline
        );
        assert_eq!(reopened.offline_pins("space-a").unwrap().len(), 1);
        let cache_status = runtime.handle(json!({"action":"status"})).unwrap();
        assert_eq!(cache_status["offline_cache"]["available"], true);
        assert_eq!(cache_status["offline_cache"]["pinned_bytes"], 4);
        runtime.auth_state.lock().unwrap().engine = None;
        let offline_journal = runtime
            .handle(json!({"action":"cache_pending_writes","limit":10}))
            .expect("pending transfer list remains local after sign-out");
        assert_eq!(offline_journal["pending_count"], 1);
        assert_eq!(offline_journal["items"][0]["path"], "/folder/file.txt");
        assert_eq!(offline_journal["items"][0]["root_resource_id"], "root-a");

        let write_id = offline_journal["items"][0]["write_id"]
            .as_str()
            .unwrap()
            .parse::<i64>()
            .unwrap();
        let cache =
            raiun_cache::Cache::open(&cache_state, offline_cache::DEFAULT_CACHE_QUOTA_BYTES)
                .unwrap();
        let scope = raiun_cache::CacheScope::new(
            "https://fixture.example.test/",
            &account_id,
            "space-a",
            "root-a",
            raiun_cache::ScopeProtection::PlaintextAllowed,
        )
        .unwrap();
        let saved_generation = offline_journal["auth_generation"].as_u64().unwrap();
        let saved_account_scope = offline_journal["account_scope"]
            .as_str()
            .unwrap()
            .to_owned();
        let saved_destination_dir = tempfile::tempdir().unwrap();
        let saved_destination = saved_destination_dir.path().join("saved-pending-copy.txt");
        for action in ["cache_conflict_export", "cache_saved_write_export"] {
            assert!(
                runtime
                    .handle(json!({"action":action, "space_id":"space-a", "expected_generation":saved_generation, "expected_account_scope":saved_account_scope,
                "root_resource_id":"wrong-root", "write_id":write_id.to_string(),
                "destination_path":saved_destination}))
                    .is_err()
            );
            assert!(!saved_destination.exists());
        }
        let saved = runtime
            .handle(json!({"action":"cache_saved_write_export", "expected_generation":saved_generation, "expected_account_scope":saved_account_scope,
            "space_id":"space-a", "root_resource_id":"root-a", "write_id":write_id.to_string(),
            "destination_path":saved_destination}))
            .expect("saved pending bytes remain exportable without a live engine");
        assert_eq!(saved["root_resource_id"], "root-a");
        assert_eq!(saved["journal_preserved"], true);
        assert_eq!(fs::read(&saved_destination).unwrap(), b"offline local edit");
        assert_eq!(
            cache.pending_writes(&scope).unwrap()[0].state,
            raiun_cache::WriteState::Pending
        );
        assert!(runtime.auth_state.lock().unwrap().engine.is_none());
        assert!(
            runtime
                .handle(json!({"action":"cache_saved_write_export", "expected_generation":saved_generation, "expected_account_scope":saved_account_scope,
            "space_id":"space-a", "root_resource_id":"root-a", "write_id":write_id.to_string(),
            "destination_path":saved_destination}))
                .is_err(),
            "never overwrite an existing chosen file"
        );
        let stale_destination = saved_destination_dir.path().join("stale-copy.txt");
        let stale_request = json!({"action":"cache_saved_write_export", "space_id":"space-a",
            "expected_generation":saved_generation, "expected_account_scope":saved_account_scope,
            "root_resource_id":"root-a", "write_id":write_id.to_string(), "destination_path":stale_destination});
        runtime
            .auth_generation
            .store(saved_generation + 1, Ordering::Release);
        assert!(runtime.handle(stale_request.clone()).is_err());
        assert!(!stale_destination.exists());
        runtime
            .auth_generation
            .store(saved_generation, Ordering::Release);
        runtime.settings.lock().unwrap().account_id =
            Some("another-account-with-the-same-write-id".into());
        assert!(runtime.handle(stale_request).is_err());
        assert!(!stale_destination.exists());
        runtime.settings.lock().unwrap().account_id = Some(account_id.clone());
        cache.mark_write_conflict(&scope, write_id).unwrap();
        let destination_dir = tempfile::tempdir().unwrap();
        let destination = destination_dir.path().join("offline-copy.txt");
        let exported = runtime
            .handle(json!({
                "action":"cache_conflict_export",
                "space_id":"space-a",
                "write_id":write_id.to_string(),
                "destination_path":destination,
            }))
            .unwrap();
        assert_eq!(exported["exported"], true);
        assert_eq!(fs::read(&destination).unwrap(), b"offline local edit");
        assert_eq!(
            cache.pending_writes(&scope).unwrap()[0].state,
            raiun_cache::WriteState::Conflict
        );
    }

    #[test]
    fn offline_pending_write_ipc_preserves_distinct_saved_roots_for_the_same_path() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = Arc::new(runtime_for_mount_test(
            dir.path().to_path_buf(),
            false,
            None,
        ));
        let account_id = account_identity("https://fixture.example.test", "personal-drive");
        runtime.settings.lock().unwrap().account_id = Some(account_id.clone());
        let engine_dir = account_engine_dir(dir.path(), &account_id);
        let _engine = Engine::open(&engine_dir, Arc::new(OfflineCacheFixture)).unwrap();
        let cache_state = offline_cache_state_dir(&engine_dir).unwrap();
        let cache =
            raiun_cache::Cache::open(&cache_state, offline_cache::DEFAULT_CACHE_QUOTA_BYTES)
                .unwrap();
        for (account, root) in [
            (account_id.as_str(), "saved-root-a"),
            (account_id.as_str(), "saved-root-b"),
            ("another-account", "unrelated-root"),
        ] {
            let scope = raiun_cache::CacheScope::new(
                "https://fixture.example.test",
                account,
                "space-a",
                root,
                raiun_cache::ScopeProtection::PlaintextAllowed,
            )
            .unwrap();
            cache.publish_listing(&scope, root, &[], 1).unwrap();
            cache
                .queue_conditional_write(
                    &scope,
                    raiun_cache::ConditionalWriteRequest {
                        parent_resource_id: root.into(),
                        name: "same.txt".into(),
                        logical_path: "/same.txt".into(),
                        resource_id: None,
                        base: raiun_core::backend::WriteCondition::Absent,
                        expected_len: 4,
                        protection: raiun_cache::ContentProtection::Plaintext,
                    },
                    &mut std::io::Cursor::new(b"edit"),
                )
                .unwrap();
        }
        // No live Engine or listing query: identities come from the retained journal.
        let first = runtime
            .handle(json!({"action":"cache_pending_writes","limit":1}))
            .unwrap();
        assert_eq!(first["pending_count"], 2);
        assert_eq!(first["items"][0]["root_resource_id"], "saved-root-a");
        let second = runtime
            .handle(json!({
                "action":"cache_pending_writes","limit":1,"after":first["next_after"],
            }))
            .unwrap();
        assert_eq!(second["items"].as_array().unwrap().len(), 1);
        assert_eq!(second["items"][0]["root_resource_id"], "saved-root-b");
        assert_eq!(first["items"][0]["path"], second["items"][0]["path"]);
        assert_ne!(
            first["items"][0]["write_id"],
            second["items"][0]["write_id"]
        );
        assert_eq!(second["truncated"], false);
        assert_eq!(
            cache
                .pending_write_page_for_account(&account_id, None, 10)
                .unwrap()
                .pending_count,
            2
        );
    }

    #[test]
    fn cache_reconcile_ipc_returns_bounded_async_status_and_rejects_paused_space() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = Arc::new(runtime_for_mount_test(
            dir.path().to_path_buf(),
            false,
            None,
        ));
        let account_id = account_identity("https://fixture.example.test", "personal-drive");
        let engine_dir = account_engine_dir(dir.path(), &account_id);
        let engine = Engine::open(&engine_dir, Arc::new(OfflineCacheFixture)).unwrap();
        let cache_state = offline_cache_state_dir(&engine_dir).unwrap();
        let cache =
            raiun_cache::Cache::open(&cache_state, offline_cache::DEFAULT_CACHE_QUOTA_BYTES)
                .unwrap();
        let engine = engine
            .with_offline_cache(
                cache,
                account_id.clone(),
                "https://fixture.example.test".into(),
            )
            .unwrap();
        engine.list("space-a", "/").unwrap();
        runtime.settings.lock().unwrap().account_id = Some(account_id);
        runtime.auth_state.lock().unwrap().engine = Some(engine);

        let started = runtime
            .handle(json!({
                "action":"cache_reconcile_writes",
                "space_id":"space-a"
            }))
            .unwrap();
        let job_id = started["job_id"].as_str().unwrap().to_owned();
        assert_eq!(started["space_id"], "space-a");
        assert!(matches!(
            started["state"].as_str(),
            Some("queued" | "running")
        ));
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let status = loop {
            let status = runtime
                .handle(json!({
                    "action":"cache_reconcile_status",
                    "job_id":job_id
                }))
                .unwrap();
            if matches!(
                status["state"].as_str(),
                Some("complete" | "failed" | "cancelled")
            ) {
                break status;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "retry job did not finish"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(status["state"], "complete", "{status}");
        assert_eq!(status["uploaded"], 0);
        assert_eq!(status["conflicts"], 0);
        assert_eq!(status["remaining"], 0);

        runtime
            .handle(json!({"action":"space_pause","space_id":"space-a","paused":true}))
            .unwrap();
        let rejected = runtime
            .handle(json!({
                "action":"cache_reconcile_writes",
                "space_id":"space-a"
            }))
            .unwrap_err();
        assert!(rejected.contains("Resume sync"));
    }

    #[test]
    fn global_pause_cancels_active_write_retry_before_acknowledging() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = Arc::new(runtime_for_mount_test(
            dir.path().to_path_buf(),
            false,
            None,
        ));
        let generation = runtime.operation_generation().unwrap();
        let vault_scope = raiun_vault::session::VaultSessionScope::new(
            &runtime.vault_account_id,
            "https://example.invalid",
            "space-a",
            "root-a",
        )
        .unwrap();
        let (vault_started_tx, vault_started_rx) = std::sync::mpsc::channel();
        let vault_job = vault_edit_jobs::VaultEditReconcileJobs::start(
            &runtime.vault_edit_reconcile_jobs,
            &vault_scope,
            Arc::clone(&runtime.auth_generation),
            generation,
            Arc::clone(&runtime.vault_pin_jobs),
            true,
            move |cancelled, _| {
                vault_started_tx.send(()).unwrap();
                while !cancelled.load(Ordering::Acquire) {
                    std::thread::yield_now();
                }
                Err("cancelled by pause".into())
            },
        )
        .unwrap();
        vault_started_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (continue_tx, continue_rx) = std::sync::mpsc::channel();
        let upload_attempted = Arc::new(AtomicBool::new(false));
        let upload_attempted_worker = upload_attempted.clone();
        let runtime_worker = runtime.clone();
        let status = runtime
            .write_reconcile_jobs
            .start(generation, "space-a".into(), move |cancelled| {
                let _gate = runtime_worker.sync_gate.lock().unwrap();
                started_tx.send(()).unwrap();
                continue_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                if !cancelled.load(Ordering::Acquire) {
                    upload_attempted_worker.store(true, Ordering::Release);
                }
                Ok(raiun_engine::WriteReconcileReport::default())
            })
            .unwrap();
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();

        let pausing_runtime = runtime.clone();
        let (pause_done_tx, pause_done_rx) = std::sync::mpsc::channel();
        let pause = std::thread::spawn(move || {
            pause_done_tx
                .send(pausing_runtime.handle(json!({"action":"pause","paused":true})))
                .unwrap();
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let current = runtime
                .write_reconcile_jobs
                .status(&status.job_id, generation)
                .unwrap();
            if current.cancel_requested {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "pause did not cancel retry"
            );
            std::thread::yield_now();
        }
        assert!(matches!(
            pause_done_rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        continue_tx.send(()).unwrap();
        pause_done_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap();
        pause.join().unwrap();
        assert!(!upload_attempted.load(Ordering::Acquire));
        assert!(runtime.settings.lock().unwrap().paused);
        assert_eq!(
            runtime
                .vault_edit_reconcile_jobs
                .status(&vault_scope, &vault_job.job_id, generation)
                .unwrap()
                .state,
            "cancelled"
        );
        assert_eq!(
            runtime
                .write_reconcile_jobs
                .status(&status.job_id, generation)
                .unwrap()
                .state,
            "cancelled"
        );
    }

    #[test]
    fn logout_cancels_active_write_retry_and_invalidates_its_ipc_generation() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = Arc::new(runtime_for_mount_test(
            dir.path().to_path_buf(),
            false,
            None,
        ));
        let generation = runtime.operation_generation().unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (continue_tx, continue_rx) = std::sync::mpsc::channel();
        let upload_attempted = Arc::new(AtomicBool::new(false));
        let upload_attempted_worker = upload_attempted.clone();
        let runtime_worker = runtime.clone();
        let status = runtime
            .write_reconcile_jobs
            .start(generation, "space-a".into(), move |cancelled| {
                let _gate = runtime_worker.sync_gate.lock().unwrap();
                started_tx.send(()).unwrap();
                continue_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                if !cancelled.load(Ordering::Acquire) {
                    upload_attempted_worker.store(true, Ordering::Release);
                }
                Ok(raiun_engine::WriteReconcileReport::default())
            })
            .unwrap();
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();

        let logout_runtime = runtime.clone();
        let logout = std::thread::spawn(move || logout_runtime.logout());
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let current = runtime
                .write_reconcile_jobs
                .status(&status.job_id, generation)
                .unwrap();
            if current.cancel_requested {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "logout did not cancel retry"
            );
            std::thread::yield_now();
        }
        assert!(runtime.operation_generation().is_err());
        continue_tx.send(()).unwrap();
        logout.join().unwrap().unwrap();
        assert!(!upload_attempted.load(Ordering::Acquire));
        assert_eq!(
            runtime
                .write_reconcile_jobs
                .status(&status.job_id, generation)
                .unwrap()
                .state,
            "cancelled"
        );
        assert!(
            runtime
                .handle(json!({"action":"cache_reconcile_status","job_id":status.job_id}))
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_optional_cache_keeps_online_engine_usable_and_reports_unavailable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let engine_dir = dir.path().join("account-engine");
        let engine = Engine::open(&engine_dir, Arc::new(OfflineCacheFixture)).unwrap();
        let cache_state = engine_dir.join("offline-cache-state");
        fs::create_dir(&cache_state).unwrap();
        fs::set_permissions(&cache_state, fs::Permissions::from_mode(0o755)).unwrap();

        let (online_engine, unavailable) = attach_optional_cache(
            engine,
            &engine_dir,
            "account-a",
            Some("https://fixture.example.test".into()),
        );
        assert!(
            unavailable
                .as_deref()
                .is_some_and(|reason| reason.contains("not private"))
        );
        assert_eq!(online_engine.spaces().unwrap().len(), 1);
        assert!(online_engine.offline_cache_usage().is_err());
    }

    #[test]
    fn scheduler_selection_is_space_targeted_and_honors_both_pause_levels() {
        let personal_pair = test_pair("personal-pair", "personal");
        let team_pair = test_pair("team-pair", "team-1");
        let mut settings = test_settings(vec![personal_pair.clone(), team_pair.clone()]);
        let target = BTreeSet::from(["team-1".to_owned()]);

        assert!(!pair_is_scheduled(&settings, &personal_pair, Some(&target)));
        assert!(pair_is_scheduled(&settings, &team_pair, Some(&target)));
        settings.paused_space_ids.push("team-1".into());
        assert!(!pair_is_scheduled(&settings, &team_pair, Some(&target)));
        assert!(pair_is_scheduled(&settings, &personal_pair, None));
        settings.paused = true;
        assert!(!pair_is_scheduled(&settings, &personal_pair, None));
    }

    #[test]
    fn drained_space_request_is_invalidated_by_account_generation_change() {
        let mut pending = BTreeSet::from(["space-old-account".to_owned()]);
        let drained = std::mem::take(&mut pending);
        assert!(pending.is_empty());
        assert!(schedule_generation_is_current(7, 7, false, false));
        assert!(!schedule_generation_is_current(7, 8, false, false));
        assert!(!schedule_generation_is_current(7, 7, true, false));
        assert!(!schedule_generation_is_current(7, 7, false, true));
        assert_eq!(drained, BTreeSet::from(["space-old-account".to_owned()]));
    }

    #[test]
    fn space_pause_persists_and_does_not_wake_a_full_sync() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = Arc::new(runtime_for_mount_test(
            dir.path().to_path_buf(),
            false,
            None,
        ));
        runtime
            .settings
            .lock()
            .unwrap()
            .config
            .pairs
            .push(test_pair("pair-1", "team-1"));

        let response = runtime
            .handle(json!({
                "action":"space_pause",
                "space_id":"team-1",
                "paused":true
            }))
            .unwrap();

        assert_eq!(response["paused_space_ids"], json!(["team-1"]));
        assert!(!runtime.wake.load(Ordering::Acquire));
        assert_eq!(
            Settings::load(dir.path()).unwrap().paused_space_ids,
            ["team-1"]
        );
    }

    #[test]
    fn space_pause_waits_for_an_operation_that_passed_its_final_recheck() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = Arc::new(runtime_for_mount_test(
            dir.path().to_path_buf(),
            false,
            None,
        ));
        let pair = test_pair("pair-1", "team-1");
        runtime
            .settings
            .lock()
            .unwrap()
            .config
            .pairs
            .push(pair.clone());

        let (rechecked_tx, rechecked_rx) = std::sync::mpsc::channel();
        let (finish_operation_tx, finish_operation_rx) = std::sync::mpsc::channel();
        let operation_runtime = runtime.clone();
        let operation_complete = Arc::new(AtomicBool::new(false));
        let operation_complete_for_thread = operation_complete.clone();
        let operation = std::thread::spawn(move || {
            let _gate = operation_runtime.sync_gate.lock().unwrap();
            let settings = operation_runtime.settings.lock().unwrap().clone();
            assert!(pair_is_scheduled(&settings, &pair, None));
            rechecked_tx.send(()).unwrap();
            finish_operation_rx
                .recv_timeout(Duration::from_secs(2))
                .unwrap();
            operation_complete_for_thread.store(true, Ordering::Release);
        });
        rechecked_rx.recv_timeout(Duration::from_secs(2)).unwrap();

        let (pause_started_tx, pause_started_rx) = std::sync::mpsc::channel();
        let (pause_result_tx, pause_result_rx) = std::sync::mpsc::channel();
        let pause_runtime = runtime.clone();
        let pause_complete_for_thread = operation_complete.clone();
        let pause = std::thread::spawn(move || {
            pause_started_tx.send(()).unwrap();
            let result = pause_runtime.handle(json!({
                "action":"space_pause",
                "space_id":"team-1",
                "paused":true
            }));
            pause_result_tx
                .send((result, pause_complete_for_thread.load(Ordering::Acquire)))
                .unwrap();
        });
        pause_started_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        let early_response = pause_result_rx.recv_timeout(Duration::from_millis(100));
        let pause_returned_early = early_response.is_ok();
        finish_operation_tx.send(()).unwrap();

        operation.join().unwrap();
        let (result, operation_was_complete) = match early_response {
            Ok(result) => result,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => pause_result_rx
                .recv_timeout(Duration::from_secs(2))
                .unwrap(),
            Err(error) => panic!("unexpected pause response channel error: {error}"),
        };
        pause.join().unwrap();
        assert!(
            !pause_returned_early,
            "pause returned while sync gate was held"
        );
        assert!(operation_was_complete);
        assert_eq!(result.unwrap()["paused"], true);
    }

    #[test]
    fn logout_and_queued_pair_recheck_follow_gate_then_settings_order() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = Arc::new(runtime_for_mount_test(
            dir.path().to_path_buf(),
            false,
            None,
        ));
        let pair = test_pair("pair-1", "team-1");
        runtime
            .settings
            .lock()
            .unwrap()
            .config
            .pairs
            .push(pair.clone());

        let (gate_held_tx, gate_held_rx) = std::sync::mpsc::channel();
        let (recheck_tx, recheck_rx) = std::sync::mpsc::channel();
        let operation_runtime = runtime.clone();
        let operation = std::thread::spawn(move || {
            let _gate = operation_runtime.sync_gate.lock().unwrap();
            gate_held_tx.send(()).unwrap();
            recheck_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            let settings = operation_runtime.settings.lock().unwrap().clone();
            pair_is_scheduled(&settings, &pair, None)
        });
        gate_held_rx.recv_timeout(Duration::from_secs(2)).unwrap();

        let logout_runtime = runtime.clone();
        let logout = std::thread::spawn(move || logout_runtime.logout());
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !runtime.auth_transition.load(Ordering::Acquire) {
            assert!(std::time::Instant::now() < deadline, "logout did not begin");
            std::thread::yield_now();
        }
        std::thread::sleep(Duration::from_millis(25));
        recheck_tx.send(()).unwrap();

        assert!(operation.join().unwrap());
        logout.join().unwrap().unwrap();
    }

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
            transfer_budget: Mutex::new(None),
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
                paused_space_ids: Vec::new(),
                mount_enabled,
                media_jobs: Vec::new(),
                network_proxy: raiun_opencloud::ProxyConfig::System,
                network_proxy_account_id: None,
                network_proxy_revision: 1,
                bandwidth_limits: TransferLimits::default(),
                bandwidth_account_id: None,
                bandwidth_revision: 1,
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
            pending_space_syncs: Mutex::new(BTreeSet::new()),
            pending_media_jobs: Mutex::new(BTreeMap::new()),
            mount: Mutex::new(mount),
            sync_gate: Mutex::new(()),
            authenticating: AtomicBool::new(false),
            auth_generation: Arc::new(AtomicU64::new(0)),
            restoring: AtomicBool::new(false),
            shutdown: Arc::new(AtomicBool::new(false)),
            auth_transition: Arc::new(AtomicBool::new(false)),
            offline_namespace: AtomicBool::new(false),
            offline_namespace_probe_unix: AtomicU64::new(0),
            vaults: Arc::new(raiun_vault::session::VaultSessionCoordinator::new()),
            vault_mounts: raiun_fuse::VaultMountRegistry::new(),
            vault_account_id: "test".into(),
            local_profile_id: "test-profile".into(),
            cache_jobs: Arc::new(offline_cache::CacheJobs::default()),
            write_reconcile_jobs: Arc::new(offline_cache::WriteReconcileJobs::default()),
            vault_edit_reconcile_jobs: Arc::new(vault_edit_jobs::VaultEditReconcileJobs::default()),
            vault_pin_jobs: Arc::new(vault_pin_jobs::VaultPinJobs::default()),
            cache_error: Mutex::new(None),
            vault_cleanup_uncertain: AtomicBool::new(false),
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
    fn logout_does_not_clear_session_when_unmount_fails() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = Arc::new(runtime_for_mount_test(
            dir.path().to_path_buf(),
            true,
            Some(Box::new(FakeMount {
                mounted: true,
                fail_while_mounted: true,
                fail_after_detach: false,
            })),
        ));
        runtime.settings.lock().unwrap().server = Some("https://cloud.example.test".into());
        runtime.settings.lock().unwrap().save(dir.path()).unwrap();
        let transfer_budget = TransferBudget::new();
        *runtime.transfer_budget.lock().unwrap() =
            Some(("test-account".into(), transfer_budget.clone()));

        let error = runtime.handle(json!({"action":"logout"})).unwrap_err();

        assert!(error.contains("mount remains active"));
        assert_eq!(
            runtime.settings.lock().unwrap().server.as_deref(),
            Some("https://cloud.example.test")
        );
        assert!(runtime.mount.lock().unwrap().as_ref().unwrap().is_mounted());
        assert!(!runtime.shutdown.load(Ordering::Acquire));
        assert!(
            !transfer_budget.is_paused(),
            "failed logout must restore transfer admission for the retained session"
        );
    }

    #[test]
    fn account_transition_fences_admission_cancels_old_handles_and_rolls_back() {
        use raiun_opencloud::transfer_budget::TransferDirection;
        use std::{io::Read, num::NonZeroU64};

        let budget = TransferBudget::new();
        budget.set_limits(TransferLimits {
            upload_bytes_per_second: Some(NonZeroU64::new(1).unwrap()),
            download_bytes_per_second: None,
        });
        let old_handle = budget.cancellation();
        {
            let fence = TransferAdmissionFence::begin(Some(budget.clone()));
            assert!(budget.is_paused());
            assert!(old_handle.is_cancelled());
            let new_handle = budget.cancellation();
            let mut reader =
                budget.reader_with_cancellation(TransferDirection::Upload, &b"x"[..], new_handle);
            let error = reader
                .read(&mut [0; 1])
                .expect_err("paused transition must reject new body admission");
            assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
            drop(fence);
        }
        assert!(
            !budget.is_paused(),
            "rollback restores prior admission state"
        );
        assert!(
            old_handle.is_cancelled(),
            "rollback cannot revive stale handles"
        );
        let fresh = budget.cancellation();
        let mut reader =
            budget.reader_with_cancellation(TransferDirection::Upload, &b"x"[..], fresh);
        reader
            .read_exact(&mut [0; 1])
            .expect("a fresh request can enter after rollback");

        let mut committed = TransferAdmissionFence::begin(Some(budget.clone()));
        committed.commit_paused();
        drop(committed);
        assert!(
            budget.is_paused(),
            "committed logout keeps retired budget closed"
        );
    }

    #[test]
    fn logout_and_shutdown_cancel_paced_transfer_before_waiting_for_sync_gate() {
        use std::io::Read;
        use std::num::NonZeroU64;
        use std::sync::mpsc;
        use std::thread;
        use std::time::Instant;

        for shutdown in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let runtime = Arc::new(runtime_for_mount_test(
                dir.path().to_path_buf(),
                false,
                None,
            ));
            let budget = TransferBudget::new();
            budget.set_limits(TransferLimits {
                upload_bytes_per_second: Some(NonZeroU64::new(1).unwrap()),
                download_bytes_per_second: None,
            });
            *runtime.transfer_budget.lock().unwrap() =
                Some(("test-account".into(), budget.clone()));

            let transfer_cancellation = budget.cancellation();
            let mut reader = budget.reader_with_cancellation(
                raiun_opencloud::transfer_budget::TransferDirection::Upload,
                b"xy".as_slice(),
                transfer_cancellation.clone(),
            );
            let mut first = [0];
            reader.read_exact(&mut first).unwrap();
            let worker_runtime = runtime.clone();
            let (waiting_tx, waiting_rx) = mpsc::channel();
            let (cancelled_tx, cancelled_rx) = mpsc::channel();
            let worker = thread::spawn(move || {
                let _sync = worker_runtime.sync_gate.lock().unwrap();
                waiting_tx.send(()).unwrap();
                let mut rest = [0];
                let result = reader.read_exact(&mut rest);
                cancelled_tx.send(result.is_err()).unwrap();
            });
            waiting_rx.recv_timeout(Duration::from_secs(1)).unwrap();
            thread::sleep(Duration::from_millis(30));

            let transition_runtime = runtime.clone();
            let (done_tx, done_rx) = mpsc::channel();
            let transition = thread::spawn(move || {
                let result = if shutdown {
                    transition_runtime.shutdown_safely()
                } else {
                    transition_runtime.logout()
                };
                done_tx.send(result).unwrap();
            });
            let started = Instant::now();
            let fence_deadline = started + Duration::from_millis(300);
            while !budget.is_paused() && Instant::now() < fence_deadline {
                if let Ok(result) = done_rx.try_recv() {
                    panic!("transition returned before transfer fence: {result:?}");
                }
                thread::yield_now();
            }
            assert!(
                budget.is_paused(),
                "transition did not close transfer admission"
            );
            let mut admission_probe = budget.reader(
                raiun_opencloud::transfer_budget::TransferDirection::Upload,
                &b"x"[..],
            );
            assert_eq!(
                admission_probe.read(&mut [0; 1]).unwrap_err().kind(),
                std::io::ErrorKind::ConnectionAborted,
                "paused controller rejects newly admitted readers"
            );
            let cancellation_result = cancelled_rx.recv_timeout(Duration::from_millis(500));
            assert!(
                cancellation_result.unwrap_or_else(|error| {
                    panic!(
                        "transition did not cancel the paced body; paused={}, handle_cancelled={}, transition={:?}, recv={error:?}",
                        budget.is_paused(),
                        transfer_cancellation.is_cancelled(),
                        done_rx.try_recv()
                    )
                }),
                "transition did not cancel the paced body"
            );
            done_rx
                .recv_timeout(Duration::from_millis(500))
                .expect("transition must finish after the body releases the sync gate")
                .unwrap();
            assert!(started.elapsed() < Duration::from_millis(500));
            worker.join().unwrap();
            transition.join().unwrap();
            assert!(budget.is_paused());
        }
    }

    #[test]
    fn logout_clears_only_session_identity_and_preserves_recovery_and_pairs() {
        let dir = tempfile::tempdir().unwrap();
        let server = "https://cloud.example.test";
        let account_id = account_identity(server, "personal-drive");
        let runtime = Arc::new(runtime_for_mount_test(
            dir.path().to_path_buf(),
            false,
            None,
        ));
        {
            let mut settings = runtime.settings.lock().unwrap();
            settings.server = Some(server.into());
            settings.account_id = Some(account_id.clone());
            settings.config.pairs.push(FolderPair {
                id: "pair-1".into(),
                local_path: dir.path().join("local"),
                space_id: "personal".into(),
                vault: None,
                remote_path: "/Documents".into(),
                mode: raiun_core::SyncMode::TwoWay,
                excluded_paths: Vec::new(),
            });
            settings.save(dir.path()).unwrap();
        }

        namespace::save(
            &account_engine_dir(dir.path(), &account_id),
            &account_id,
            server,
            &namespace_test_spaces(server),
        )
        .unwrap();

        runtime.handle(json!({"action":"logout"})).unwrap();

        let settings = Settings::load(dir.path()).unwrap();
        assert!(settings.server.is_none());
        assert_eq!(settings.account_id.as_deref(), Some(account_id.as_str()));
        assert_eq!(settings.config.pairs.len(), 1);
        assert!(!settings.mount_enabled);
        assert!(
            !account_engine_dir(dir.path(), &account_id)
                .join("namespace-v1.json")
                .exists()
        );
    }

    #[test]
    fn shutdown_failure_keeps_agent_live_and_preserves_mount_intent() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = Arc::new(runtime_for_mount_test(
            dir.path().to_path_buf(),
            true,
            Some(Box::new(FakeMount {
                mounted: true,
                fail_while_mounted: true,
                fail_after_detach: false,
            })),
        ));

        let error = runtime.handle(json!({"action":"shutdown"})).unwrap_err();

        assert!(error.contains("cloud root is still mounted"));
        assert!(!runtime.shutdown.load(Ordering::Acquire));
        assert!(runtime.settings.lock().unwrap().mount_enabled);
        assert!(runtime.mount.lock().unwrap().as_ref().unwrap().is_mounted());
    }

    #[test]
    fn shutdown_success_unmounts_and_keeps_mount_intent_for_next_launch() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = Arc::new(runtime_for_mount_test(
            dir.path().to_path_buf(),
            true,
            Some(Box::new(FakeMount {
                mounted: true,
                fail_while_mounted: false,
                fail_after_detach: false,
            })),
        ));

        runtime.settings.lock().unwrap().save(dir.path()).unwrap();
        let response = runtime.handle(json!({"action":"shutdown"})).unwrap();

        assert_eq!(response["stopping"], true);
        assert!(runtime.shutdown.load(Ordering::Acquire));
        assert!(runtime.mount.lock().unwrap().is_none());
        assert!(runtime.settings.lock().unwrap().mount_enabled);
        assert!(Settings::load(dir.path()).unwrap().mount_enabled);
    }

    #[test]
    fn remote_folder_request_rejects_unsafe_paths_and_names() {
        assert!(validate_remote_folder_request("/", "New folder").is_ok());
        assert!(validate_remote_folder_request("/Team/Docs", "Drafts").is_ok());
        for path in ["relative", "/Team/../Secrets", "/Team//Docs", "/Team/"] {
            assert!(validate_remote_folder_request(path, "Drafts").is_err());
        }
        for name in ["", ".", "..", "a/b", "a\\b", " Drafts", "Drafts\n"] {
            assert!(validate_remote_folder_request("/Team", name).is_err());
        }
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
        net::{TcpListener, TcpStream},
        time::Instant,
    };

    #[derive(Default)]
    struct FakeSecretService {
        sessions: Mutex<BTreeMap<(String, String), Vec<u8>>>,
        fail_next_save: AtomicBool,
        fail_next_load: AtomicBool,
        invalid_next_load: AtomicBool,
        load_count: std::sync::atomic::AtomicUsize,
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
            self.load_classified(server, client_id)
                .map_err(|error| error.to_string())
        }

        fn load_classified(
            &self,
            server: &str,
            client_id: &str,
        ) -> Result<Option<auth::Session>, auth::SessionLoadError> {
            self.load_count.fetch_add(1, Ordering::AcqRel);
            if self.invalid_next_load.swap(false, Ordering::AcqRel) {
                return Err(auth::SessionLoadError::Invalid(
                    "synthetic corrupt session".into(),
                ));
            }
            if self.fail_next_load.swap(false, Ordering::AcqRel) {
                return Err(auth::SessionLoadError::Unavailable(
                    "synthetic locked keyring".into(),
                ));
            }
            self.sessions
                .lock()
                .map_err(|_| {
                    auth::SessionLoadError::Unavailable(
                        "fake Secret Service lock was poisoned".into(),
                    )
                })?
                .get(&(server.to_owned(), client_id.to_owned()))
                .map(|bytes| {
                    serde_json::from_slice(bytes).map_err(|_| {
                        auth::SessionLoadError::Invalid(
                            "fake Secret Service stored invalid session data".into(),
                        )
                    })
                })
                .transpose()
        }

        fn remove(&self, server: &str, client_id: &str) -> Result<(), String> {
            self.sessions
                .lock()
                .map_err(|_| "fake Secret Service lock was poisoned")?
                .remove(&(server.to_owned(), client_id.to_owned()));
            Ok(())
        }
    }

    #[derive(Default)]
    struct BlockingSessionStoreState {
        load_started: bool,
        released: bool,
        session: Option<auth::Session>,
        save_count: usize,
    }

    #[derive(Default)]
    struct BlockingSessionStore {
        state: Mutex<BlockingSessionStoreState>,
        changed: std::sync::Condvar,
    }

    impl BlockingSessionStore {
        fn wait_until_load_starts(&self) {
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            let mut state = self.state.lock().unwrap();
            while !state.load_started && std::time::Instant::now() < deadline {
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                let (next, _) = self.changed.wait_timeout(state, remaining).unwrap();
                state = next;
            }
            assert!(state.load_started, "restore did not enter the keyring load");
        }

        fn release_load(&self) {
            let mut state = self.state.lock().unwrap();
            state.released = true;
            self.changed.notify_all();
        }
    }

    impl SessionStore for BlockingSessionStore {
        fn save(&self, session: &auth::Session) -> Result<(), String> {
            let mut state = self.state.lock().map_err(|_| "store lock poisoned")?;
            state.save_count += 1;
            state.session = Some(session.clone());
            Ok(())
        }

        fn load(&self, server: &str, client_id: &str) -> Result<Option<auth::Session>, String> {
            self.load_classified(server, client_id)
                .map_err(|error| error.to_string())
        }

        fn load_classified(
            &self,
            _server: &str,
            _client_id: &str,
        ) -> Result<Option<auth::Session>, auth::SessionLoadError> {
            let mut state = self
                .state
                .lock()
                .map_err(|_| auth::SessionLoadError::Unavailable("store lock poisoned".into()))?;
            state.load_started = true;
            self.changed.notify_all();
            while !state.released {
                state = self.changed.wait(state).map_err(|_| {
                    auth::SessionLoadError::Unavailable("store wait poisoned".into())
                })?;
            }
            Ok(state.session.clone())
        }

        fn remove(&self, _server: &str, _client_id: &str) -> Result<(), String> {
            let mut state = self.state.lock().map_err(|_| "store lock poisoned")?;
            state.session = None;
            Ok(())
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
            paused_space_ids: Vec::new(),
            mount_enabled: false,
            media_jobs: Vec::new(),
            network_proxy: raiun_opencloud::ProxyConfig::System,
            network_proxy_account_id: None,
            network_proxy_revision: 1,
            bandwidth_limits: TransferLimits::default(),
            bandwidth_account_id: None,
            bandwidth_revision: 1,
        };
        Arc::new(Runtime {
            dir: dir.to_path_buf(),
            transfer_budget: Mutex::new(None),
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
            pending_space_syncs: Mutex::new(BTreeSet::new()),
            pending_media_jobs: Mutex::new(BTreeMap::new()),
            mount: Mutex::new(None),
            sync_gate: Mutex::new(()),
            authenticating: AtomicBool::new(false),
            auth_generation: Arc::new(AtomicU64::new(0)),
            restoring: AtomicBool::new(false),
            shutdown: Arc::new(AtomicBool::new(false)),
            auth_transition: Arc::new(AtomicBool::new(false)),
            offline_namespace: AtomicBool::new(false),
            offline_namespace_probe_unix: AtomicU64::new(0),
            session_store,
            vaults: Arc::new(raiun_vault::session::VaultSessionCoordinator::new()),
            vault_mounts: raiun_fuse::VaultMountRegistry::new(),
            vault_account_id: "test".into(),
            local_profile_id: "test-profile".into(),
            cache_jobs: Arc::new(offline_cache::CacheJobs::default()),
            write_reconcile_jobs: Arc::new(offline_cache::WriteReconcileJobs::default()),
            vault_edit_reconcile_jobs: Arc::new(vault_edit_jobs::VaultEditReconcileJobs::default()),
            vault_pin_jobs: Arc::new(vault_pin_jobs::VaultPinJobs::default()),
            cache_error: Mutex::new(None),
            vault_cleanup_uncertain: AtomicBool::new(false),
        })
    }

    fn runtime_for_namespace_restore(
        dir: &Path,
        server: &str,
        account_id: &str,
        session_store: Arc<dyn SessionStore>,
    ) -> Arc<Runtime> {
        Arc::new(Runtime {
            dir: dir.to_path_buf(),
            transfer_budget: Mutex::new(None),
            settings: Mutex::new(Settings {
                config: Config {
                    schema_version: CONFIG_SCHEMA_VERSION,
                    cloud_root: dir.join("cloud"),
                    pairs: Vec::new(),
                },
                server: Some(server.to_owned()),
                client_id: "OpenCloudDesktop".into(),
                account_id: Some(account_id.to_owned()),
                retired_pair_ids: Vec::new(),
                paused: false,
                paused_space_ids: Vec::new(),
                mount_enabled: false,
                media_jobs: Vec::new(),
                network_proxy: raiun_opencloud::ProxyConfig::System,
                network_proxy_account_id: Some(account_id.to_owned()),
                network_proxy_revision: 1,
                bandwidth_limits: TransferLimits::default(),
                bandwidth_account_id: None,
                bandwidth_revision: 1,
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
            pending_space_syncs: Mutex::new(BTreeSet::new()),
            pending_media_jobs: Mutex::new(BTreeMap::new()),
            mount: Mutex::new(None),
            sync_gate: Mutex::new(()),
            authenticating: AtomicBool::new(false),
            auth_generation: Arc::new(AtomicU64::new(0)),
            restoring: AtomicBool::new(true),
            shutdown: Arc::new(AtomicBool::new(false)),
            auth_transition: Arc::new(AtomicBool::new(false)),
            offline_namespace: AtomicBool::new(false),
            offline_namespace_probe_unix: AtomicU64::new(0),
            session_store,
            vaults: Arc::new(raiun_vault::session::VaultSessionCoordinator::new()),
            vault_mounts: raiun_fuse::VaultMountRegistry::new(),
            vault_account_id: account_id.to_owned(),
            local_profile_id: "test-profile".into(),
            cache_jobs: Arc::new(offline_cache::CacheJobs::default()),
            write_reconcile_jobs: Arc::new(offline_cache::WriteReconcileJobs::default()),
            vault_edit_reconcile_jobs: Arc::new(vault_edit_jobs::VaultEditReconcileJobs::default()),
            vault_pin_jobs: Arc::new(vault_pin_jobs::VaultPinJobs::default()),
            cache_error: Mutex::new(None),
            vault_cleanup_uncertain: AtomicBool::new(false),
        })
    }

    fn namespace_test_spaces(server: &str) -> Vec<raiun_core::backend::CloudSpace> {
        vec![
            raiun_core::backend::CloudSpace {
                id: "personal-drive".into(),
                name: "Personal".into(),
                dav_url: format!("{server}/remote.php/dav/personal/personal-drive"),
                personal: true,
                writable: true,
                encrypted: false,
            },
            raiun_core::backend::CloudSpace {
                id: "project-drive".into(),
                name: "Projects".into(),
                dav_url: format!("{server}/remote.php/dav/spaces/project-drive"),
                personal: false,
                writable: true,
                encrypted: false,
            },
        ]
    }

    fn read_fixture_request(stream: &mut TcpStream) -> Vec<u8> {
        stream
            .set_read_timeout(Some(Duration::from_secs(4)))
            .expect("set fixture read timeout");
        let mut request = Vec::new();
        let mut byte = [0];
        while !request.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).expect("read fixture request");
            request.push(byte[0]);
            assert!(request.len() < 16 * 1024, "bounded fixture request");
        }
        request
    }

    fn serve_graph_restore_responses(
        listener: TcpListener,
        server: String,
        responses: Vec<bool>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            for respond in responses {
                let (mut stream, _) = listener.accept().expect("Graph restore request");
                let request = read_fixture_request(&mut stream);
                assert!(request.starts_with(b"GET /graph/v1.0/me/drives"));
                if respond {
                    let body = format!(
                        r#"{{"value":[{{"id":"personal-drive","name":"Personal","driveType":"personal","root":{{"id":"personal-root","webDavUrl":"{server}/remote.php/dav/personal/personal-drive"}}}},{{"id":"project-drive","name":"Projects","driveType":"project","root":{{"id":"project-root","webDavUrl":"{server}/remote.php/dav/spaces/project-drive"}}}}]}}"#
                    );
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                    .expect("write Graph response");
                }
            }
        })
    }

    fn wait_for_restored_engine(runtime: &Runtime) {
        let deadline = std::time::Instant::now() + Duration::from_secs(6);
        while std::time::Instant::now() < deadline {
            if runtime
                .auth_state
                .lock()
                .is_ok_and(|state| state.engine.is_some())
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!(
            "saved session was not restored; error={:?}",
            *runtime.error.lock().unwrap()
        );
    }

    fn saved_session(server: &str, token_endpoint: String, expires_at: u64) -> auth::Session {
        auth::Session {
            server: server.to_owned(),
            client_id: "OpenCloudDesktop".into(),
            access_token: "fixture-access".into(),
            refresh_token: Some("fixture-old-refresh".into()),
            expires_at,
            token_endpoint,
            expected_issuer: None,
            last_refresh_at: None,
            proxy: raiun_opencloud::ProxyConfig::System,
        }
    }

    #[test]
    fn startup_uses_bound_namespace_only_when_graph_transport_is_offline() {
        let dir = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").expect("temporary local port");
        let server = format!("http://{}", listener.local_addr().unwrap());
        let graph_probe = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("Graph namespace probe");
            stream
                .set_read_timeout(Some(Duration::from_secs(6)))
                .expect("set stalled Graph deadline");
            let mut request = Vec::new();
            let mut byte = [0];
            while !request.ends_with(b"\r\n\r\n") {
                if stream.read_exact(&mut byte).is_err() {
                    return;
                }
                request.push(byte[0]);
                assert!(request.len() < 16 * 1024);
            }
            assert!(request.starts_with(b"GET "));
            // The endpoint accepts the connection but never responds. The
            // startup-only OpenCloud client must time out and restore the
            // verified namespace without waiting for the normal 120s client.
            let mut byte = [0];
            let _ = stream.read(&mut byte);
        });
        let account_id = account_identity(&server, "personal-drive");
        let store = Arc::new(FakeSecretService::default());
        let session = auth::Session {
            server: server.clone(),
            client_id: "OpenCloudDesktop".into(),
            access_token: "fixture-access".into(),
            refresh_token: None,
            expires_at: now_unix().saturating_add(600),
            token_endpoint: format!("{server}/token"),
            expected_issuer: None,
            last_refresh_at: None,
            proxy: raiun_opencloud::ProxyConfig::System,
        };
        store.save(&session).unwrap();
        namespace::save(
            &account_engine_dir(dir.path(), &account_id),
            &account_id,
            &server,
            &namespace_test_spaces(&server),
        )
        .unwrap();
        let runtime = runtime_for_namespace_restore(dir.path(), &server, &account_id, store);

        start_runtime(runtime.clone());
        let started = std::time::Instant::now();
        let deadline = started + Duration::from_secs(6);
        while runtime.restoring.load(Ordering::Acquire) && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !runtime.restoring.load(Ordering::Acquire),
            "bounded startup restore timed out"
        );
        assert!(
            started.elapsed() < Duration::from_secs(6),
            "stalled startup Graph probe exceeded its bound: {:?}",
            started.elapsed()
        );
        assert_eq!(
            *runtime.error.lock().unwrap(),
            None,
            "startup restore error"
        );
        assert!(
            runtime.offline_namespace.load(Ordering::Acquire),
            "offline flag was not set; status error={:?}",
            *runtime.error.lock().unwrap()
        );
        let engine = runtime.engine().unwrap();
        assert!(
            engine.namespace_transport_unavailable(),
            "restored offline state must reach every mounted Engine clone"
        );
        let spaces = engine.spaces().expect("offline namespace is available");
        assert_eq!(
            spaces
                .iter()
                .map(|space| space.id.as_str())
                .collect::<Vec<_>>(),
            vec!["personal-drive", "project-drive"]
        );
        assert!(spaces.iter().all(|space| !space.writable));
        let status = runtime.handle(json!({"action":"status"})).unwrap();
        assert_eq!(status["connected"], false);
        assert_eq!(status["offline_namespace"], true);
        assert_eq!(
            status["paused"], false,
            "saved Pause preference stays unchanged"
        );
        assert!(!runtime.settings.lock().unwrap().paused);
        assert!(
            engine
                .sync_pair(&test_pair("offline-pair", "personal-drive"))
                .unwrap_err()
                .to_string()
                .contains("paused")
        );
        graph_probe
            .join()
            .expect("stalled Graph probe exits when the request deadline closes");
    }

    #[test]
    fn namespace_probe_timeout_is_reported_without_sync_pairs_and_only_validated_probe_clears_it() {
        let dir = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind Graph fixture");
        let server = format!("http://{}", listener.local_addr().unwrap());
        let graph_url = server.clone();
        let (recovery_probe_tx, recovery_probe_rx) = std::sync::mpsc::channel();
        let graph_server = std::thread::spawn(move || {
            for request_index in 0..3 {
                let (mut stream, _) = listener.accept().expect("Graph request");
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .expect("set read timeout");
                let mut request = Vec::new();
                let mut byte = [0];
                while !request.ends_with(b"\r\n\r\n") {
                    stream.read_exact(&mut byte).expect("read Graph headers");
                    request.push(byte[0]);
                    assert!(request.len() < 16 * 1024);
                }
                assert!(request.starts_with(b"GET /graph/v1.0/me/drives"));
                if request_index == 1 {
                    recovery_probe_tx
                        .send(())
                        .expect("signal stalled recovery probe");
                    stream
                        .set_read_timeout(Some(Duration::from_secs(8)))
                        .expect("set stalled Graph deadline");
                    let mut byte = [0];
                    while stream.read(&mut byte).unwrap_or(0) > 0 {}
                } else if request_index == 2 {
                    let body = format!(
                        r#"{{"value":[{{"id":"personal-drive","name":"Personal","driveType":"personal","root":{{"id":"personal-root","webDavUrl":"{graph_url}/remote.php/dav/personal/personal-drive"}}}},{{"id":"recovered-project","name":"Recovered project","driveType":"project","root":{{"id":"project-root","webDavUrl":"{graph_url}/remote.php/dav/spaces/recovered-project"}}}}]}}"#
                    );
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                    .expect("write recovered Graph namespace");
                }
                // The initial namespace read sees an immediate transport
                // outage; recovery probe #1 stalls, then probe #2 succeeds.
            }
        });

        let account_id = account_identity(&server, "personal-drive");
        let client = raiun_opencloud::OpenCloudClient::new(&server, "fixture-access".into())
            .expect("normal timeout OpenCloud client");
        let origin = client.server_origin().expect("canonical origin");
        let engine = Engine::open(&dir.path().join("engine"), Arc::new(client.clone()))
            .expect("open Engine")
            .with_account_scope(account_id.clone(), origin)
            .expect("bind account")
            .with_offline_spaces(namespace_test_spaces(&server))
            .expect("attach verified namespace");
        let mounted_engine = engine.clone();
        let runtime = runtime_for_namespace_restore(
            dir.path(),
            &server,
            &account_id,
            Arc::new(FakeSecretService::default()),
        );
        {
            let mut state = runtime.auth_state.lock().unwrap();
            state.engine = Some(engine);
            state.session = Some(auth::Session {
                server: server.clone(),
                client_id: "OpenCloudDesktop".into(),
                access_token: "fixture-access".into(),
                refresh_token: None,
                expires_at: now_unix().saturating_add(600),
                token_endpoint: format!("{server}/token"),
                expected_issuer: None,
                last_refresh_at: Some(now_unix()),
                proxy: raiun_opencloud::ProxyConfig::System,
            });
            state.client = Some(client);
            state.account_id = Some(account_id);
        }
        runtime.restoring.store(false, Ordering::Release);
        assert!(
            runtime.settings.lock().unwrap().config.pairs.is_empty(),
            "the regression must not depend on a sync pair"
        );

        let cached_spaces = mounted_engine
            .spaces()
            .expect("verified saved namespace remains available on transport outage");
        assert!(mounted_engine.namespace_transport_unavailable());
        assert!(
            !runtime.offline_namespace.load(Ordering::Acquire),
            "the mounted Engine discovers the outage independently of Runtime"
        );
        assert!(cached_spaces.iter().all(|space| !space.writable));

        let status = runtime.handle(json!({"action":"status"})).unwrap();
        assert_eq!(status["connected"], false);
        assert_eq!(status["offline_namespace"], true);
        assert!(runtime.offline_namespace.load(Ordering::Acquire));

        let recovery_runtime = runtime.clone();
        let recovery = std::thread::spawn(move || {
            let started = std::time::Instant::now();
            let result = recovery_runtime.refresh_session();
            (result, started.elapsed())
        });
        recovery_probe_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("bounded recovery probe reaches the stalled fixture");
        let status_started = std::time::Instant::now();
        let during_probe = runtime.handle(json!({"action":"status"})).unwrap();
        let status_elapsed = status_started.elapsed();
        assert!(
            status_elapsed < Duration::from_secs(8),
            "status remained blocked beyond the bounded namespace probe: {status_elapsed:?}"
        );
        assert_eq!(during_probe["connected"], false);
        assert_eq!(during_probe["offline_namespace"], true);
        let (probe_result, probe_elapsed) = recovery.join().unwrap();
        assert!(
            probe_result.is_err(),
            "a stalled Graph probe must remain offline"
        );
        assert!(
            probe_elapsed < Duration::from_secs(8),
            "recovery probe exceeded its bounded deadline: {probe_elapsed:?}"
        );
        assert!(runtime.offline_namespace.load(Ordering::Acquire));

        // The production retry cadence is at least one minute. Reset only the
        // test clock to exercise the next scheduled recovery without sleeping.
        runtime
            .offline_namespace_probe_unix
            .store(0, Ordering::Release);
        runtime
            .refresh_session()
            .expect("authenticated namespace recovery");
        graph_server.join().expect("Graph fixture completes");
        assert!(!runtime.offline_namespace.load(Ordering::Acquire));
        assert!(!mounted_engine.namespace_transport_unavailable());
        let recovered = runtime.handle(json!({"action":"status"})).unwrap();
        assert_eq!(recovered["connected"], true);
        assert_eq!(recovered["offline_namespace"], false);
        assert!(
            mounted_engine
                .spaces()
                .unwrap()
                .iter()
                .any(|space| space.id == "recovered-project")
        );
    }

    #[test]
    fn reconnect_refreshes_mounted_namespace_and_restores_only_saved_pause() {
        for user_paused in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind Graph fixture");
            let server = format!("http://{}", listener.local_addr().unwrap());
            let graph_url = server.clone();
            let graph_server = std::thread::spawn(move || {
                // One authenticated live namespace probe, followed by a
                // transport outage that forces the mounted clone to consult
                // its newly published fallback snapshot.
                for request_index in 0..2 {
                    let (mut stream, _) = listener.accept().expect("Graph request");
                    stream
                        .set_read_timeout(Some(Duration::from_secs(3)))
                        .unwrap();
                    let mut request = Vec::new();
                    let mut byte = [0];
                    while !request.ends_with(b"\r\n\r\n") {
                        stream.read_exact(&mut byte).unwrap();
                        request.push(byte[0]);
                        assert!(request.len() < 16 * 1024);
                    }
                    assert!(request.starts_with(b"GET /graph/v1.0/me/drives"));
                    if request_index == 0 {
                        let body = format!(
                            r#"{{"value":[{{"id":"personal-drive","name":"Personal","driveType":"personal","root":{{"id":"personal-root","webDavUrl":"{graph_url}/remote.php/dav/personal/personal-drive"}}}},{{"id":"refreshed-project","name":"Refreshed project","driveType":"project","root":{{"id":"project-root","webDavUrl":"{graph_url}/remote.php/dav/spaces/refreshed-project"}}}}]}}"#
                        );
                        write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        )
                        .unwrap();
                    }
                    // The second stream is intentionally closed without a
                    // response to exercise transport-only snapshot fallback.
                }
            });
            let account_id = account_identity(&server, "personal-drive");
            let client = raiun_opencloud::OpenCloudClient::new(&server, "fixture-access".into())
                .expect("OpenCloud client");
            let origin = client.server_origin().expect("canonical origin");
            let engine = Engine::open(&dir.path().join("engine"), Arc::new(client.clone()))
                .expect("open Engine")
                .with_account_scope(account_id.clone(), origin)
                .expect("bind account");
            let engine = engine
                .with_offline_spaces(namespace_test_spaces(&server))
                .expect("attach restored offline namespace");
            engine.set_sync_paused(true); // temporary offline gate
            let mounted_engine = engine.clone();

            let store = Arc::new(FakeSecretService::default());
            let runtime = runtime_for_namespace_restore(dir.path(), &server, &account_id, store);
            runtime.settings.lock().unwrap().paused = user_paused;
            let mut session = auth::Session {
                server: server.clone(),
                client_id: "OpenCloudDesktop".into(),
                access_token: "fixture-access".into(),
                refresh_token: None,
                expires_at: now_unix().saturating_add(600),
                token_endpoint: format!("{server}/token"),
                expected_issuer: None,
                last_refresh_at: None,
                proxy: raiun_opencloud::ProxyConfig::System,
            };
            session.last_refresh_at = Some(now_unix());
            {
                let mut state = runtime.auth_state.lock().unwrap();
                state.engine = Some(engine.clone());
                state.session = Some(session);
                state.client = Some(client);
                state.account_id = Some(account_id.clone());
            }
            runtime.offline_namespace.store(true, Ordering::Release);
            runtime.restoring.store(false, Ordering::Release);

            runtime.refresh_session().expect("authenticated reconnect");
            assert!(!runtime.offline_namespace.load(Ordering::Acquire));
            assert_eq!(runtime.settings.lock().unwrap().paused, user_paused);

            let spaces = mounted_engine
                .spaces()
                .expect("mounted Engine clone sees refreshed fallback after outage");
            graph_server.join().unwrap();
            assert_eq!(spaces[0].id, "personal-drive");
            assert!(spaces.iter().any(|space| space.id == "refreshed-project"));
            assert!(spaces.iter().all(|space| !space.writable));

            let sync_error = mounted_engine
                .sync_pair(&test_pair("reconnect-policy", "personal-drive"))
                .expect_err("fixture does not serve DAV sync");
            if user_paused {
                assert!(sync_error.to_string().contains("paused"), "{sync_error}");
            } else {
                assert!(
                    !sync_error.to_string().contains("paused"),
                    "offline pause was not cleared after reconnect: {sync_error}"
                );
            }
        }
    }

    #[test]
    fn reconnect_does_not_publish_namespace_for_a_different_personal_drive() {
        let dir = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind Graph fixture");
        let server = format!("http://{}", listener.local_addr().unwrap());
        let graph_url = server.clone();
        let graph_server = std::thread::spawn(move || {
            for request_index in 0..2 {
                let (mut stream, _) = listener.accept().expect("Graph request");
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut request = Vec::new();
                let mut byte = [0];
                while !request.ends_with(b"\r\n\r\n") {
                    stream.read_exact(&mut byte).unwrap();
                    request.push(byte[0]);
                    assert!(request.len() < 16 * 1024);
                }
                assert!(request.starts_with(b"GET /graph/v1.0/me/drives"));
                if request_index == 0 {
                    let body = format!(
                        r#"{{"value":[{{"id":"switched-personal","name":"Personal","driveType":"personal","root":{{"id":"new-root","webDavUrl":"{graph_url}/remote.php/dav/personal/switched-personal"}}}},{{"id":"untrusted-project","name":"Untrusted project","driveType":"project","root":{{"id":"project-root","webDavUrl":"{graph_url}/remote.php/dav/spaces/untrusted-project"}}}}]}}"#
                    );
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                    .unwrap();
                }
            }
        });
        let account_id = account_identity(&server, "personal-drive");
        let client = raiun_opencloud::OpenCloudClient::new(&server, "fixture-access".into())
            .expect("OpenCloud client");
        let origin = client.server_origin().expect("canonical origin");
        let engine = Engine::open(&dir.path().join("engine"), Arc::new(client.clone()))
            .expect("open Engine")
            .with_account_scope(account_id.clone(), origin)
            .expect("bind account")
            .with_offline_spaces(namespace_test_spaces(&server))
            .expect("attach saved namespace");
        engine.set_sync_paused(true);
        let mounted_engine = engine.clone();
        let runtime = runtime_for_namespace_restore(
            dir.path(),
            &server,
            &account_id,
            Arc::new(FakeSecretService::default()),
        );
        {
            let mut state = runtime.auth_state.lock().unwrap();
            state.engine = Some(engine);
            state.session = Some(auth::Session {
                server: server.clone(),
                client_id: "OpenCloudDesktop".into(),
                access_token: "fixture-access".into(),
                refresh_token: None,
                expires_at: now_unix().saturating_add(600),
                token_endpoint: format!("{server}/token"),
                expected_issuer: None,
                last_refresh_at: None,
                proxy: raiun_opencloud::ProxyConfig::System,
            });
            state.client = Some(client);
            state.account_id = Some(account_id);
        }
        runtime.offline_namespace.store(true, Ordering::Release);
        runtime.restoring.store(false, Ordering::Release);

        let error = runtime
            .refresh_session()
            .expect_err("a changed Personal drive must stop reconnect");
        assert!(error.contains("identity changed"), "{error}");
        assert!(runtime.offline_namespace.load(Ordering::Acquire));
        let spaces = mounted_engine
            .spaces()
            .expect("transport fallback still uses prior bound snapshot");
        graph_server.join().unwrap();
        assert_eq!(spaces[0].id, "personal-drive");
        assert!(spaces.iter().any(|space| space.id == "project-drive"));
        assert!(!spaces.iter().any(|space| space.id == "untrusted-project"));
        assert!(spaces.iter().all(|space| !space.writable));
    }

    #[test]
    fn startup_never_uses_namespace_after_graph_authorization_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind Graph fixture");
        let server = format!("http://{}", listener.local_addr().unwrap());
        let refresh_listener = TcpListener::bind("127.0.0.1:0").expect("bind refresh port");
        let token_endpoint = format!("http://{}/token", refresh_listener.local_addr().unwrap());
        drop(refresh_listener);
        let graph = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("Graph request");
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut request = Vec::new();
            let mut byte = [0];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
                assert!(request.len() < 16 * 1024);
            }
            let body = r#"{"error":{"message":"denied"}}"#;
            write!(
                stream,
                "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });
        let dir = tempfile::tempdir().unwrap();
        let account_id = account_identity(&server, "personal-drive");
        namespace::save(
            &account_engine_dir(dir.path(), &account_id),
            &account_id,
            &server,
            &namespace_test_spaces(&server),
        )
        .unwrap();
        let store = Arc::new(FakeSecretService::default());
        let session = auth::Session {
            server,
            client_id: "OpenCloudDesktop".into(),
            access_token: "fixture-access".into(),
            refresh_token: Some("fixture-refresh".into()),
            expires_at: now_unix().saturating_sub(1),
            token_endpoint,
            expected_issuer: None,
            last_refresh_at: None,
            proxy: raiun_opencloud::ProxyConfig::System,
        };
        store.save(&session).unwrap();
        let runtime =
            runtime_for_namespace_restore(dir.path(), &session.server, &account_id, store.clone());
        start_runtime(runtime.clone());
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while runtime.restoring.load(Ordering::Acquire) && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        graph.join().unwrap();
        assert!(
            !runtime.restoring.load(Ordering::Acquire),
            "restore timed out"
        );
        let error = runtime.error.lock().unwrap().clone().unwrap();
        assert!(
            error.contains("HTTP 403"),
            "unexpected startup error: {error}"
        );
        assert!(runtime.auth_state.lock().unwrap().engine.is_none());
        assert!(!runtime.offline_namespace.load(Ordering::Acquire));
        assert_eq!(store.load_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn startup_retries_transient_keyring_unavailability_without_requiring_sign_in() {
        let dir = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind Graph fixture");
        let server = format!("http://{}", listener.local_addr().unwrap());
        let graph = serve_graph_restore_responses(listener, server.clone(), vec![true]);
        let account_id = account_identity(&server, "personal-drive");
        let store = Arc::new(FakeSecretService::default());
        store
            .save(&saved_session(
                &server,
                format!("{server}/token"),
                now_unix().saturating_add(600),
            ))
            .unwrap();
        store.fail_next_load.store(true, Ordering::Release);
        let runtime =
            runtime_for_namespace_restore(dir.path(), &server, &account_id, store.clone());

        start_runtime(runtime.clone());
        let initial_attempt_deadline = std::time::Instant::now() + Duration::from_secs(2);
        while runtime.restoring.load(Ordering::Acquire)
            && std::time::Instant::now() < initial_attempt_deadline
        {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(!runtime.restoring.load(Ordering::Acquire));
        assert_eq!(store.load_count.load(Ordering::Acquire), 1);
        wait_for_restored_engine(&runtime);
        graph.join().unwrap();

        assert_eq!(store.load_count.load(Ordering::Acquire), 2);
        assert!(!runtime.restoring.load(Ordering::Acquire));
        assert!(!runtime.offline_namespace.load(Ordering::Acquire));
        assert!(runtime.error.lock().unwrap().is_none());
        assert_eq!(
            runtime.settings.lock().unwrap().server.as_deref(),
            Some(server.as_str())
        );
    }

    #[test]
    fn startup_retries_graph_transport_and_persists_rotated_refresh_token_once() {
        let dir = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind Graph fixture");
        let server = format!("http://{}", listener.local_addr().unwrap());
        let graph = serve_graph_restore_responses(listener, server.clone(), vec![false, true]);
        let token_listener = TcpListener::bind("127.0.0.1:0").expect("bind token fixture");
        let token_endpoint = format!("http://{}/token", token_listener.local_addr().unwrap());
        let tokens = token_fixture(
            token_listener,
            vec![(
                200,
                r#"{"access_token":"rotated-access","refresh_token":"rotated-refresh","expires_in":3600}"#,
            )],
        );
        let account_id = account_identity(&server, "personal-drive");
        let store = Arc::new(FakeSecretService::default());
        store
            .save(&saved_session(
                &server,
                token_endpoint,
                now_unix().saturating_sub(1),
            ))
            .unwrap();
        let runtime =
            runtime_for_namespace_restore(dir.path(), &server, &account_id, store.clone());

        start_runtime(runtime.clone());
        wait_for_restored_engine(&runtime);
        graph.join().unwrap();
        tokens.join().unwrap();

        assert_eq!(store.load_count.load(Ordering::Acquire), 1);
        let stored_bytes = store
            .sessions
            .lock()
            .unwrap()
            .get(&(server.clone(), "OpenCloudDesktop".into()))
            .cloned()
            .expect("refreshed session persisted");
        let stored: auth::Session = serde_json::from_slice(&stored_bytes).unwrap();
        assert_eq!(stored.access_token, "rotated-access");
        assert_eq!(stored.refresh_token.as_deref(), Some("rotated-refresh"));
    }

    #[test]
    fn startup_does_not_retry_a_corrupt_saved_session() {
        let dir = tempfile::tempdir().unwrap();
        let server = "http://127.0.0.1:1";
        let account_id = account_identity(server, "personal-drive");
        let store = Arc::new(FakeSecretService::default());
        store.invalid_next_load.store(true, Ordering::Release);
        let runtime = runtime_for_namespace_restore(dir.path(), server, &account_id, store.clone());

        start_runtime(runtime.clone());
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while runtime.restoring.load(Ordering::Acquire) && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        std::thread::sleep(Duration::from_millis(600));

        assert!(!runtime.restoring.load(Ordering::Acquire));
        assert_eq!(store.load_count.load(Ordering::Acquire), 1);
        assert!(runtime.auth_state.lock().unwrap().engine.is_none());
        assert!(
            runtime
                .error
                .lock()
                .unwrap()
                .as_deref()
                .is_some_and(|e| e.contains("corrupt"))
        );
    }

    #[test]
    fn logout_during_blocked_restore_prevents_session_or_credential_resurrection() {
        let dir = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind unused Graph endpoint");
        listener.set_nonblocking(true).unwrap();
        let server = format!("http://{}", listener.local_addr().unwrap());
        let account_id = account_identity(&server, "personal-drive");
        let store = Arc::new(BlockingSessionStore::default());
        store.state.lock().unwrap().session = Some(saved_session(
            &server,
            format!("{server}/token"),
            now_unix().saturating_add(600),
        ));
        let runtime =
            runtime_for_namespace_restore(dir.path(), &server, &account_id, store.clone());

        start_runtime(runtime.clone());
        store.wait_until_load_starts();
        runtime.handle(json!({"action":"logout"})).unwrap();
        store.release_load();

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while runtime.restoring.load(Ordering::Acquire) && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        std::thread::sleep(Duration::from_millis(100));

        assert!(!runtime.restoring.load(Ordering::Acquire));
        assert!(runtime.settings.lock().unwrap().server.is_none());
        let state = runtime.auth_state.lock().unwrap();
        assert!(state.engine.is_none());
        assert!(state.session.is_none());
        drop(state);
        assert_eq!(store.state.lock().unwrap().save_count, 0);
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "stale restore must not make a Graph request after logout"
        );
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
            transfer_budget: Mutex::new(None),
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
                paused_space_ids: Vec::new(),
                mount_enabled: false,
                media_jobs: Vec::new(),
                network_proxy: raiun_opencloud::ProxyConfig::System,
                network_proxy_account_id: None,
                network_proxy_revision: 1,
                bandwidth_limits: TransferLimits::default(),
                bandwidth_account_id: None,
                bandwidth_revision: 1,
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
            pending_space_syncs: Mutex::new(BTreeSet::new()),
            pending_media_jobs: Mutex::new(BTreeMap::new()),
            mount: Mutex::new(None),
            sync_gate: Mutex::new(()),
            authenticating: AtomicBool::new(false),
            auth_generation: Arc::new(AtomicU64::new(0)),
            restoring: AtomicBool::new(false),
            shutdown: Arc::new(AtomicBool::new(false)),
            auth_transition: Arc::new(AtomicBool::new(false)),
            offline_namespace: AtomicBool::new(false),
            offline_namespace_probe_unix: AtomicU64::new(0),
            vaults: Arc::new(raiun_vault::session::VaultSessionCoordinator::new()),
            vault_mounts: raiun_fuse::VaultMountRegistry::new(),
            vault_account_id: "test".into(),
            local_profile_id: "test-profile".into(),
            cache_jobs: Arc::new(offline_cache::CacheJobs::default()),
            write_reconcile_jobs: Arc::new(offline_cache::WriteReconcileJobs::default()),
            vault_edit_reconcile_jobs: Arc::new(vault_edit_jobs::VaultEditReconcileJobs::default()),
            vault_pin_jobs: Arc::new(vault_pin_jobs::VaultPinJobs::default()),
            cache_error: Mutex::new(None),
            vault_cleanup_uncertain: AtomicBool::new(false),
            session_store: Arc::new(FakeSecretService::default()),
        });
        let status = runtime.handle(json!({"action":"status"})).unwrap();
        assert!(status["client_id"].is_null());
        assert_eq!(status["auth_generation"], 0);
        runtime.auth_generation.store(7, Ordering::Release);
        assert_eq!(
            runtime.handle(json!({"action":"status"})).unwrap()["auth_generation"],
            7
        );
        runtime.auth_transition.store(true, Ordering::Release);
        assert!(runtime.handle(json!({"action":"status"})).is_err());
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
            proxy: raiun_opencloud::ProxyConfig::System,
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
            proxy: raiun_opencloud::ProxyConfig::System,
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
