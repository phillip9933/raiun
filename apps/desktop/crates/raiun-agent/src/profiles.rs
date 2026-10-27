//! Broker multiple independent OpenCloud accounts over one agent.
//!
//! The `default` profile deliberately reuses the pre-profile state directory,
//! settings file, and unscoped keyring entry. Additional profiles receive
//! private state directories and independent keyring scopes.

use super::{Runtime, new_runtime, start_runtime};
use raiun_core::{CONFIG_SCHEMA_VERSION, Config, FolderPair, MediaImportJob, validate_config};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

const REGISTRY_FILE: &str = "profiles.json";
const PROFILES_DIR: &str = "profiles";
const DEFAULT_ID: &str = "default";
const REGISTRY_VERSION: u32 = 1;
const MAX_REGISTRY_BYTES: usize = 1_048_576;
const MAX_PROFILES: usize = 16;
const MAX_LABEL_BYTES: usize = 256;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileRecord {
    label: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    version: u32,
    selected: String,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    removed: BTreeSet<String>,
    profiles: BTreeMap<String, ProfileRecord>,
}

struct ManagerState {
    registry: Registry,
    runtimes: BTreeMap<String, Arc<Runtime>>,
}

/// Owns the selected profile and each profile's independent engine runtime.
pub struct ProfileManager {
    state_dir: PathBuf,
    vaults: Arc<raiun_vault::session::VaultSessionCoordinator>,
    state: Mutex<ManagerState>,
    /// Serialize changes that can create cross-profile path overlaps.
    mutation_gate: Mutex<()>,
    shutdown_requested: AtomicBool,
}

impl ProfileManager {
    /// Load the registry and start all saved profiles.
    pub fn open(state_dir: PathBuf) -> Result<Arc<Self>, String> {
        if !state_dir.is_absolute() {
            return Err("State directory must be absolute".into());
        }
        ensure_real_directory(&state_dir, false)?;
        let registry_path = state_dir.join(REGISTRY_FILE);
        let registry = load_registry(&registry_path)?;
        ensure_profiles_root(&state_dir)?;

        let vaults = Arc::new(raiun_vault::session::VaultSessionCoordinator::new());
        let mut runtimes = BTreeMap::new();
        for id in registry.profiles.keys() {
            let dir = profile_dir(&state_dir, id);
            if id != DEFAULT_ID {
                ensure_profile_directory(&state_dir, id)?;
            }
            let scope = (id != DEFAULT_ID).then(|| id.clone());
            let runtime = new_runtime(dir, scope, vaults.clone())?;
            if registry.removed.contains(id) {
                runtime.retiring.store(true, Ordering::Release);
                runtime.shutdown.store(true, Ordering::Release);
                runtime.restoring.store(false, Ordering::Release);
            }
            runtimes.insert(id.clone(), runtime);
        }
        validate_profile_separation(&profile_paths(&ManagerState {
            registry: registry.clone(),
            runtimes: runtimes.clone(),
        })?)?;
        let manager = Arc::new(Self {
            state_dir,
            vaults,
            state: Mutex::new(ManagerState { registry, runtimes }),
            mutation_gate: Mutex::new(()),
            shutdown_requested: AtomicBool::new(false),
        });
        let runtimes = manager
            .state
            .lock()
            .map_err(|_| "Profile state poisoned")?
            .runtimes
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for runtime in runtimes {
            if !runtime.retiring.load(Ordering::Acquire) {
                start_runtime(runtime);
            }
        }
        Ok(manager)
    }

    /// Route a control request to the selected profile or an explicit profile.
    pub fn handle(self: &Arc<Self>, mut request: Value) -> Result<Value, String> {
        // Move, do not clone, password storage into a wiping owner before any
        // profile validation can fail. The raw socket input is wiped separately.
        let password = match request.as_object_mut().and_then(|o| o.remove("password")) {
            Some(Value::String(value)) => Some(zeroize::Zeroizing::new(value)),
            Some(_) => return Err("Password must be text".into()),
            None => None,
        };
        if request
            .get("action")
            .and_then(Value::as_str)
            .is_some_and(|a| matches!(a, "vault_unlock" | "vault_unlock_offline" | "vault_create"))
        {
            self.ensure_running()?;
            let (_, runtime) = self.resolve_runtime(&request)?;
            return runtime.handle_vault(strip_profile_id(request), password);
        }
        if request.get("action").and_then(Value::as_str) == Some("vault_resolve_unlock_target") {
            self.ensure_running()?;
            if password.is_some() {
                return Err("Password is not accepted by the unlock target resolver".into());
            }
            if !matches!(request.get("profile_id"), Some(Value::String(_))) {
                return Err("profile_id is required for unlock target resolution".into());
            }
            let (profile_id, runtime) = self.resolve_runtime(&request)?;
            let mut response = runtime.handle_vault(strip_profile_id(request), None)?;
            response
                .as_object_mut()
                .ok_or("Unlock target response is invalid")?
                .insert("profile_id".into(), Value::String(profile_id));
            return Ok(response);
        }
        if password.is_some() {
            return Err("Password is only accepted by a vault operation".into());
        }
        let action = request
            .get("action")
            .and_then(Value::as_str)
            .ok_or("Missing action")?;
        match action {
            "accounts" => self.accounts(),
            "diagnostics" => {
                self.ensure_running()?;
                let (_id, runtime) = self.resolve_runtime(&request)?;
                self.diagnostics(&runtime)
            }
            "account_add" => self.add_account(&request),
            "account_select" => self.select_account(&request),
            "account_rename" => self.rename_account(&request),
            "account_remove" => self.remove_account(&request),
            "account_restore" => self.restore_account(&request),
            "shutdown" => self.request_shutdown(),
            "status" => {
                if request.get("profile_id").is_none() && self.selected_profile()?.is_none() {
                    return Ok(
                        json!({"connected":false,"mounted":false,"account_switch_supported":true,"accounts_empty":true,"agent_version":env!("CARGO_PKG_VERSION")}),
                    );
                }
                let (id, runtime) = self.resolve_runtime(&request)?;
                self.profile_status(&id, &runtime)
            }
            "configure" | "pair_add" | "pair_exclusions_set" | "media_job_set" => {
                let _gate = self
                    .mutation_gate
                    .lock()
                    .map_err(|_| "Profile mutation gate poisoned")?;
                self.ensure_running()?;
                let (id, runtime) = self.resolve_runtime(&request)?;
                match action {
                    "configure" => self.check_configure_overlap(&id, &runtime, &request)?,
                    "pair_add" => self.check_pair_overlap(&id, &runtime, &request)?,
                    "media_job_set" => self.check_media_source_overlap(&id, &request)?,
                    // Exclusions change only which pair-relative paths are
                    // scanned; root overlap validation is unchanged.
                    "pair_exclusions_set" => {}
                    _ => unreachable!(),
                }
                runtime.handle(strip_profile_id(request))
            }
            _ => {
                let (_, runtime) = self.resolve_runtime(&request)?;
                runtime.handle(strip_profile_id(request))
            }
        }
    }

    /// True once every profile has completed its safe shutdown.
    pub fn shutdown_requested(&self) -> bool {
        self.shutdown_requested.load(Ordering::Acquire)
    }

    fn accounts(&self) -> Result<Value, String> {
        let _gate = self
            .mutation_gate
            .lock()
            .map_err(|_| "Profile mutation gate poisoned")?;
        let (selected, profiles) = {
            let state = self.state.lock().map_err(|_| "Profile state poisoned")?;
            let profiles = state
                .registry
                .profiles
                .iter()
                .filter(|(id, _)| !state.registry.removed.contains(*id))
                .map(|(id, record)| {
                    (
                        id.clone(),
                        record.label.clone(),
                        state.runtimes.get(id).cloned(),
                    )
                })
                .collect::<Vec<_>>();
            (state.registry.selected.clone(), profiles)
        };
        let mut items = Vec::with_capacity(profiles.len());
        for (id, label, runtime) in profiles {
            let status = match runtime {
                Some(runtime) => self.profile_status(&id, &runtime)?,
                None => json!({"error":"Profile runtime is unavailable"}),
            };
            items.push(json!({"id":id,"label":label,"status":status}));
        }
        let state = self.state.lock().map_err(|_| "Profile state poisoned")?;
        let removed_items = state.registry.removed.iter().map(|id| {
            json!({"id":id,"label":state.registry.profiles[id].label,"local_data_preserved":true})
        }).collect::<Vec<_>>();
        let selected = (!state.registry.removed.contains(&selected)).then_some(selected);
        Ok(
            json!({"selected":selected,"items":items,"removed_items":removed_items,"account_removal_supported":true}),
        )
    }

    fn diagnostics(&self, runtime: &Arc<Runtime>) -> Result<Value, String> {
        let profile_count = self
            .state
            .lock()
            .map_err(|_| "Profile state poisoned")?
            .registry
            .profiles
            .len();
        let settings = runtime
            .settings
            .lock()
            .map_err(|_| "Settings poisoned")?
            .clone();
        let mut mode_counts = BTreeMap::from([
            ("two_way", 0usize),
            ("upload_only", 0usize),
            ("download_only", 0usize),
        ]);
        for pair in &settings.config.pairs {
            let key = match pair.mode {
                raiun_core::SyncMode::TwoWay => "two_way",
                raiun_core::SyncMode::UploadOnly => "upload_only",
                raiun_core::SyncMode::DownloadOnly => "download_only",
            };
            *mode_counts
                .get_mut(key)
                .expect("all sync modes are present") += 1;
        }
        let connected = {
            let auth = runtime
                .auth_state
                .lock()
                .map_err(|_| "Authentication state poisoned")?;
            auth.engine.is_some() && !runtime.offline_namespace.load(Ordering::Acquire)
        };
        let mounted = runtime
            .mount
            .lock()
            .map_err(|_| "Mount state poisoned")?
            .as_ref()
            .is_some_and(|handle| handle.is_mounted());
        Ok(json!({
            "schema_version": 1,
            "app_version": env!("CARGO_PKG_VERSION"),
            "target_os": std::env::consts::OS,
            "target_arch": std::env::consts::ARCH,
            "profile_scope": "selected_profile",
            "profile_count": profile_count,
            "profile_config": {
                "parse_valid": validate_config(&settings.config).is_empty(),
                "folder_pair_count": settings.config.pairs.len(),
                "mode_counts": mode_counts,
                "vault_pair_count": settings.config.pairs.iter().filter(|pair| pair.vault.is_some()).count(),
            },
            "runtime": {
                "connected": connected,
                "mounted": mounted,
                "sync_paused": settings.paused,
            },
        }))
    }

    fn add_account(&self, request: &Value) -> Result<Value, String> {
        let _gate = self
            .mutation_gate
            .lock()
            .map_err(|_| "Profile mutation gate poisoned")?;
        self.ensure_running()?;
        let label = request
            .get("label")
            .and_then(Value::as_str)
            .ok_or("Missing label")?;
        validate_label(label)?;
        let cloud_root = request
            .get("cloud_root")
            .and_then(Value::as_str)
            .ok_or("Missing cloud_root")?;
        let root = PathBuf::from(cloud_root);
        validate_cloud_root(&root)?;

        let mut state = self.state.lock().map_err(|_| "Profile state poisoned")?;
        if state.registry.profiles.len() >= MAX_PROFILES {
            return Err("Profile limit reached".into());
        }
        let existing = profile_paths(&state)?;
        reject_root_overlaps(&root, &existing)?;

        let id = random_profile_id(&state.registry.profiles)?;
        let dir = ensure_profile_directory(&self.state_dir, &id)?;
        let runtime = new_runtime(dir, Some(id.clone()), self.vaults.clone())?;
        runtime.handle(strip_profile_id(
            json!({"action":"configure","cloud_root":root}),
        ))?;
        enable_mount_for_new_profile(&runtime)?;

        let mut next = state.registry.clone();
        next.profiles.insert(
            id.clone(),
            ProfileRecord {
                label: label.trim().to_owned(),
            },
        );
        if next.removed.contains(&next.selected) {
            next.selected = id.clone();
        }
        validate_registry(&next)?;
        save_registry(&self.state_dir.join(REGISTRY_FILE), &next)?;
        state.registry = next;
        state.runtimes.insert(id.clone(), runtime.clone());
        drop(state);
        start_runtime(runtime);
        Ok(json!({"id":id}))
    }

    fn select_account(&self, request: &Value) -> Result<Value, String> {
        let _gate = self
            .mutation_gate
            .lock()
            .map_err(|_| "Profile mutation gate poisoned")?;
        self.ensure_running()?;
        let id = request
            .get("profile_id")
            .and_then(Value::as_str)
            .ok_or("Missing profile_id")?;
        let mut state = self.state.lock().map_err(|_| "Profile state poisoned")?;
        if !state.registry.profiles.contains_key(id) || state.registry.removed.contains(id) {
            return Err("Unknown or removed profile_id".into());
        }
        let mut next = state.registry.clone();
        next.selected = id.to_owned();
        save_registry(&self.state_dir.join(REGISTRY_FILE), &next)?;
        state.registry = next;
        Ok(json!({}))
    }

    fn rename_account(&self, request: &Value) -> Result<Value, String> {
        let _gate = self
            .mutation_gate
            .lock()
            .map_err(|_| "Profile mutation gate poisoned")?;
        self.ensure_running()?;
        let id = request
            .get("profile_id")
            .and_then(Value::as_str)
            .ok_or("Missing profile_id")?;
        let expected = request
            .get("expected_label")
            .and_then(Value::as_str)
            .ok_or("Missing expected_label")?;
        let label = request
            .get("label")
            .and_then(Value::as_str)
            .ok_or("Missing label")?;
        validate_label(label)?;
        let mut state = self.state.lock().map_err(|_| "Profile state poisoned")?;
        if state.registry.selected != id || state.registry.removed.contains(id) {
            return Err("The selected account changed; review its name again".into());
        }
        let current = state
            .registry
            .profiles
            .get(id)
            .ok_or("Unknown profile_id")?;
        if current.label != expected {
            return Err("The account name changed; refresh and try again".into());
        }
        let mut next = state.registry.clone();
        next.profiles.get_mut(id).ok_or("Unknown profile_id")?.label = label.trim().to_owned();
        save_registry(&self.state_dir.join(REGISTRY_FILE), &next)?;
        state.registry = next;
        Ok(json!({"renamed_profile_id":id,"label":label.trim(),"selected":id}))
    }

    fn selected_profile(&self) -> Result<Option<String>, String> {
        let state = self.state.lock().map_err(|_| "Profile state poisoned")?;
        Ok((!state.registry.removed.contains(&state.registry.selected))
            .then(|| state.registry.selected.clone()))
    }

    fn remove_account(&self, request: &Value) -> Result<Value, String> {
        let _gate = self
            .mutation_gate
            .lock()
            .map_err(|_| "Profile mutation gate poisoned")?;
        self.ensure_running()?;
        if request.get("confirm").and_then(Value::as_bool) != Some(true) {
            return Err("Confirm account removal before continuing".into());
        }
        let id = request
            .get("profile_id")
            .and_then(Value::as_str)
            .ok_or("Missing profile_id")?;
        let generation = request
            .get("expected_auth_generation")
            .and_then(Value::as_u64)
            .ok_or("Refresh the account before removing it")?;
        let runtime = {
            let state = self.state.lock().map_err(|_| "Profile state poisoned")?;
            if state.registry.selected != id || state.registry.removed.contains(id) {
                return Err("The selected account changed; review removal again".into());
            }
            state
                .runtimes
                .get(id)
                .cloned()
                .ok_or("Unknown profile_id")?
        };
        if runtime.retiring.swap(true, Ordering::AcqRel) {
            return Err("Account removal is already in progress".into());
        }
        let result = (|| {
            runtime.logout_for_removal(Some(generation))?;
            if runtime.vault_cleanup_uncertain.load(Ordering::Acquire) {
                return Err(
                    "Signed out, but remembered password cleanup is uncertain; retry removal"
                        .into(),
                );
            }
            runtime.shutdown_safely()?;
            let mut state = self.state.lock().map_err(|_| "Profile state poisoned")?;
            let mut next = state.registry.clone();
            next.removed.insert(id.to_owned());
            if let Some(replacement) = next
                .profiles
                .keys()
                .find(|other| !next.removed.contains(*other))
            {
                next.selected = replacement.clone();
            }
            save_registry(&self.state_dir.join(REGISTRY_FILE), &next)?;
            let selected = (!next.removed.contains(&next.selected)).then(|| next.selected.clone());
            state.registry = next;
            Ok(
                json!({"removed_profile_id":id,"selected":selected,"local_data_preserved":true,"credentials_revoked":true}),
            )
        })();
        if result.is_err() {
            runtime.retiring.store(false, Ordering::Release);
        }
        result
    }

    fn restore_account(&self, request: &Value) -> Result<Value, String> {
        let _gate = self
            .mutation_gate
            .lock()
            .map_err(|_| "Profile mutation gate poisoned")?;
        self.ensure_running()?;
        if request.get("confirm").and_then(Value::as_bool) != Some(true) {
            return Err("Confirm restoring the removed account".into());
        }
        let id = request
            .get("profile_id")
            .and_then(Value::as_str)
            .ok_or("Missing profile_id")?;
        let mut state = self.state.lock().map_err(|_| "Profile state poisoned")?;
        if !state.registry.removed.contains(id) {
            return Err("Unknown removed profile_id".into());
        }
        let dir = profile_dir(&self.state_dir, id);
        let runtime = new_runtime(
            dir,
            (id != DEFAULT_ID).then(|| id.to_owned()),
            self.vaults.clone(),
        )?;
        if runtime
            .settings
            .lock()
            .map_err(|_| "Settings poisoned")?
            .server
            .is_some()
        {
            return Err(
                "Removed account sign-out state is uncertain; it cannot be restored automatically"
                    .into(),
            );
        }
        let mut next = state.registry.clone();
        next.removed.remove(id);
        if next.removed.contains(&next.selected) {
            next.selected = id.to_owned();
        }
        save_registry(&self.state_dir.join(REGISTRY_FILE), &next)?;
        let selected = next.selected.clone();
        state.registry = next;
        state.runtimes.insert(id.to_owned(), runtime.clone());
        drop(state);
        start_runtime(runtime);
        Ok(json!({"restored_profile_id":id,"selected":selected,"sign_in_required":true}))
    }

    /// Stop every profile. The process-level flag changes only after all stop.
    pub fn request_shutdown(&self) -> Result<Value, String> {
        if self.shutdown_requested.load(Ordering::Acquire) {
            return Ok(json!({"stopping":true}));
        }
        let _gate = self
            .mutation_gate
            .lock()
            .map_err(|_| "Profile mutation gate poisoned")?;
        let runtimes = self
            .state
            .lock()
            .map_err(|_| "Profile state poisoned")?
            .runtimes
            .iter()
            .map(|(id, runtime)| (id.clone(), runtime.clone()))
            .collect::<Vec<_>>();
        let labels = {
            let state = self.state.lock().map_err(|_| "Profile state poisoned")?;
            state.registry.profiles.clone()
        };
        let mut errors = Vec::new();
        for (id, runtime) in runtimes {
            if runtime.retiring.load(Ordering::Acquire) {
                continue;
            }
            if let Err(error) = runtime.handle(json!({"action":"shutdown"})) {
                let label = labels
                    .get(&id)
                    .map(|profile| profile.label.as_str())
                    .unwrap_or("Unknown profile");
                errors.push(format!("{label}: {error}"));
            }
        }
        if errors.is_empty() {
            self.shutdown_requested.store(true, Ordering::Release);
            Ok(json!({"stopping":true}))
        } else {
            Err(format!(
                "Some accounts stopped; {} could not stop. Resolve the issue and retry Quit.",
                errors.join("; ")
            ))
        }
    }

    fn resolve_runtime(&self, request: &Value) -> Result<(String, Arc<Runtime>), String> {
        let state = self.state.lock().map_err(|_| "Profile state poisoned")?;
        let id = match request.get("profile_id") {
            None => state.registry.selected.clone(),
            Some(Value::String(id)) => id.clone(),
            Some(_) => return Err("profile_id must be a string".into()),
        };
        if state.registry.removed.contains(&id) {
            return Err("This account has been removed; restore it before signing in".into());
        }
        let runtime = state
            .runtimes
            .get(&id)
            .cloned()
            .ok_or("Unknown profile_id")?;
        Ok((id, runtime))
    }

    fn ensure_running(&self) -> Result<(), String> {
        if self.shutdown_requested.load(Ordering::Acquire) {
            Err("Agent is stopping".into())
        } else {
            Ok(())
        }
    }

    fn profile_status(&self, id: &str, runtime: &Arc<Runtime>) -> Result<Value, String> {
        let label = self
            .state
            .lock()
            .map_err(|_| "Profile state poisoned")?
            .registry
            .profiles
            .get(id)
            .map(|profile| profile.label.clone())
            .ok_or("Unknown profile_id")?;
        let mut status = if runtime.shutdown.load(Ordering::Acquire) {
            json!({"stopped":true,"connected":false,"mounted":false,"agent_version":env!("CARGO_PKG_VERSION"),"auth_generation":runtime.auth_generation.load(Ordering::Acquire)})
        } else {
            match runtime.handle(json!({"action":"status"})) {
                Ok(status) => status,
                Err(_) if runtime.shutdown.load(Ordering::Acquire) => {
                    json!({"stopped":true,"connected":false,"mounted":false,"agent_version":env!("CARGO_PKG_VERSION"),"auth_generation":runtime.auth_generation.load(Ordering::Acquire)})
                }
                Err(error) => return Err(error),
            }
        };
        let object = status.as_object_mut().ok_or("Runtime status is invalid")?;
        object.insert("profile_id".into(), json!(id));
        object.insert("profile_label".into(), json!(label));
        Ok(status)
    }

    fn check_configure_overlap(
        &self,
        id: &str,
        runtime: &Arc<Runtime>,
        request: &Value,
    ) -> Result<(), String> {
        let root = request
            .get("cloud_root")
            .and_then(Value::as_str)
            .ok_or("Missing cloud_root")?;
        let root = validate_cloud_root(Path::new(root))?;
        let current = runtime
            .settings
            .lock()
            .map_err(|_| "Settings poisoned")?
            .clone();
        let existing_media_sources = active_media_sources(&current.media_jobs)?;
        let mut candidate_local_paths = vec![root.clone()];
        candidate_local_paths.extend(
            current
                .config
                .pairs
                .iter()
                .map(|pair| canonical_existing_directory(&pair.local_path))
                .collect::<Result<Vec<_>, _>>()?,
        );
        reject_profile_paths_against_media(&candidate_local_paths, &existing_media_sources)?;
        let candidate = Config {
            schema_version: CONFIG_SCHEMA_VERSION,
            cloud_root: root.clone(),
            pairs: current.config.pairs,
        };
        let errors = validate_config(&candidate);
        if !errors.is_empty() {
            return Err(errors.join("; "));
        }
        let state = self.state.lock().map_err(|_| "Profile state poisoned")?;
        let other_paths = profile_paths_except(&state, id)?;
        reject_root_overlaps(&root, &other_paths)
    }

    fn check_pair_overlap(
        &self,
        id: &str,
        runtime: &Arc<Runtime>,
        request: &Value,
    ) -> Result<(), String> {
        let mut body = request.clone();
        let object = body.as_object_mut().ok_or("Invalid request")?;
        object.remove("action");
        object.remove("profile_id");
        let pair: FolderPair = serde_json::from_value(body).map_err(|e| e.to_string())?;
        let settings = runtime
            .settings
            .lock()
            .map_err(|_| "Settings poisoned")?
            .clone();
        let mut candidate = settings.config.clone();
        candidate.pairs.push(pair.clone());
        let errors = validate_config(&candidate);
        if !errors.is_empty() {
            return Err(errors.join("; "));
        }
        let pair_path = canonical_existing_directory(&pair.local_path)?;
        let existing_media_sources = active_media_sources(&settings.media_jobs)?;
        reject_profile_paths_against_media(
            std::slice::from_ref(&pair_path),
            &existing_media_sources,
        )?;
        let state = self.state.lock().map_err(|_| "Profile state poisoned")?;
        reject_pair_overlaps(&pair_path, id, &profile_paths(&state)?)
    }

    fn check_media_source_overlap(&self, profile_id: &str, request: &Value) -> Result<(), String> {
        let job: MediaImportJob =
            serde_json::from_value(request.get("job").cloned().ok_or("Missing job")?)
                .map_err(|_| "Invalid media job")?;
        let state = self.state.lock().map_err(|_| "Profile state poisoned")?;
        let expected_revision = request.get("expected_revision").and_then(Value::as_u64);
        let expected_account = request.get("expected_account_id").and_then(Value::as_str);
        let runtime = state
            .runtimes
            .get(profile_id)
            .ok_or("Profile runtime is unavailable")?;
        let current_jobs = runtime
            .settings
            .lock()
            .map_err(|_| "Settings poisoned")?
            .media_jobs
            .clone();
        // The only overlapping-path exception is the exact saved job being
        // paused. A new disabled job or a disabled edit cannot reserve a
        // conflicting source and leave an invalid persisted profile behind.
        if is_exact_media_pause(&current_jobs, &job, expected_revision, expected_account) {
            return Ok(());
        }
        let source = resolve_directory(&job.source_root, true)?;
        reject_media_source_overlaps(&source, profile_id, &job.id, &profile_paths(&state)?)
    }
}

/// A newly added account has an explicit cloud root selected in the setup
/// flow, so persist the intent to mount it as soon as authentication succeeds.
/// Existing profiles keep their previously saved mount preference.
fn enable_mount_for_new_profile(runtime: &Runtime) -> Result<(), String> {
    let mut settings = runtime.settings.lock().map_err(|_| "Settings poisoned")?;
    if !settings.mount_enabled {
        let mut next = settings.clone();
        next.mount_enabled = true;
        next.save(&runtime.dir)?;
        *settings = next;
    }
    Ok(())
}

fn profile_dir(state_dir: &Path, id: &str) -> PathBuf {
    if id == DEFAULT_ID {
        state_dir.to_owned()
    } else {
        state_dir.join(PROFILES_DIR).join(id)
    }
}

fn ensure_profiles_root(state_dir: &Path) -> Result<PathBuf, String> {
    let path = state_dir.join(PROFILES_DIR);
    match fs::symlink_metadata(&path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err("Profiles directory must not be a symbolic link".into());
        }
        Ok(meta) if !meta.is_dir() => return Err("Profiles path is not a directory".into()),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(&path).map_err(|e| e.to_string())?;
        }
        Err(error) => return Err(error.to_string()),
    }
    set_private_directory(&path)?;
    Ok(path)
}

fn ensure_profile_directory(state_dir: &Path, id: &str) -> Result<PathBuf, String> {
    if !valid_profile_id(id) || id == DEFAULT_ID {
        return Err("Invalid profile id".into());
    }
    let root = ensure_profiles_root(state_dir)?;
    let path = root.join(id);
    match fs::symlink_metadata(&path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err("Profile directory must not be a symbolic link".into());
        }
        Ok(meta) if !meta.is_dir() => return Err("Profile path is not a directory".into()),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(&path).map_err(|e| e.to_string())?;
        }
        Err(error) => return Err(error.to_string()),
    }
    set_private_directory(&path)?;
    Ok(path)
}

fn ensure_real_directory(path: &Path, create: bool) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err("State directory must not be a symbolic link".into());
        }
        Ok(meta) if !meta.is_dir() => return Err("State path is not a directory".into()),
        Ok(_) => {}
        Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path).map_err(|e| e.to_string())?;
        }
        Err(error) => return Err(error.to_string()),
    }
    Ok(())
}

#[cfg(unix)]
fn set_private_directory(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())
}

#[cfg(not(unix))]
fn set_private_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}

fn load_registry(path: &Path) -> Result<Registry, String> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let registry = Registry {
                version: REGISTRY_VERSION,
                removed: BTreeSet::new(),
                selected: DEFAULT_ID.into(),
                profiles: BTreeMap::from([(
                    DEFAULT_ID.into(),
                    ProfileRecord {
                        label: "Default".into(),
                    },
                )]),
            };
            save_registry(path, &registry)?;
            Ok(registry)
        }
        Err(error) => Err(error.to_string()),
        Ok(meta) if meta.file_type().is_symlink() || !meta.is_file() => {
            Err("Profiles registry must be a regular file".into())
        }
        Ok(_) => {
            let mut bytes = Vec::new();
            fs::File::open(path)
                .map_err(|e| e.to_string())?
                .take((MAX_REGISTRY_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
            if bytes.len() > MAX_REGISTRY_BYTES {
                return Err("Profiles registry exceeds size limit".into());
            }
            let registry: Registry =
                serde_json::from_slice(&bytes).map_err(|_| "Profiles registry is invalid")?;
            validate_registry(&registry)?;
            Ok(registry)
        }
    }
}

fn save_registry(path: &Path, registry: &Registry) -> Result<(), String> {
    validate_registry(registry)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err("Profiles registry must be a regular file".into());
        }
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            return Err(error.to_string());
        }
        _ => {}
    }
    let bytes = serde_json::to_vec_pretty(registry).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_REGISTRY_BYTES {
        return Err("Profiles registry exceeds size limit".into());
    }
    let parent = path
        .parent()
        .ok_or("Profiles registry has no parent directory")?;
    let mut file = tempfile::NamedTempFile::new_in(parent).map_err(|e| e.to_string())?;
    file.write_all(&bytes).map_err(|e| e.to_string())?;
    file.as_file().sync_all().map_err(|e| e.to_string())?;
    file.persist(path).map_err(|e| e.to_string())?;
    fs::File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|e| e.to_string())
}

fn validate_registry(registry: &Registry) -> Result<(), String> {
    if registry.version != REGISTRY_VERSION {
        return Err("Unsupported profiles registry version".into());
    }
    if registry.profiles.is_empty() || registry.profiles.len() > MAX_PROFILES {
        return Err("Profiles registry has an invalid profile count".into());
    }
    if !registry.profiles.contains_key(DEFAULT_ID) {
        return Err("Profiles registry is missing the default profile".into());
    }
    if !registry.profiles.contains_key(&registry.selected) {
        return Err("Selected profile is missing from the registry".into());
    }
    if registry
        .removed
        .iter()
        .any(|id| !registry.profiles.contains_key(id))
    {
        return Err("Removed account is missing its retained profile".into());
    }
    if registry.removed.contains(&registry.selected)
        && registry
            .profiles
            .keys()
            .any(|id| !registry.removed.contains(id))
    {
        return Err("Selected account must be active".into());
    }
    for (id, record) in &registry.profiles {
        if id != DEFAULT_ID && !valid_profile_id(id) {
            return Err("Profiles registry contains an invalid profile id".into());
        }
        validate_label(&record.label)?;
    }
    Ok(())
}

fn validate_label(label: &str) -> Result<(), String> {
    let trimmed = label.trim();
    if trimmed.is_empty()
        || trimmed.len() > MAX_LABEL_BYTES
        || trimmed.chars().any(char::is_control)
    {
        return Err("Profile label must contain 1 to 256 non-control bytes".into());
    }
    Ok(())
}

fn valid_profile_id(id: &str) -> bool {
    id.strip_prefix("profile-").is_some_and(|suffix| {
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn random_profile_id(profiles: &BTreeMap<String, ProfileRecord>) -> Result<String, String> {
    for _ in 0..8 {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| "Could not generate profile id")?;
        let mut id = String::from("profile-");
        for byte in bytes {
            use std::fmt::Write as _;
            write!(&mut id, "{byte:02x}").map_err(|_| "Could not generate profile id")?;
        }
        if !profiles.contains_key(&id) {
            return Ok(id);
        }
    }
    Err("Could not allocate a unique profile id".into())
}

type ComparedProfilePaths = (
    String,
    PathBuf,
    Vec<PathBuf>,
    Vec<(String, PathBuf)>,
    PathBuf,
);

fn profile_paths(state: &ManagerState) -> Result<Vec<ComparedProfilePaths>, String> {
    let mut paths = Vec::new();
    for (id, runtime) in &state.runtimes {
        let settings = runtime
            .settings
            .lock()
            .map_err(|_| "Settings poisoned")?
            .clone();
        let root = resolve_directory(&settings.config.cloud_root, true)?;
        let pairs = settings
            .config
            .pairs
            .iter()
            .map(|pair| canonical_existing_directory(&pair.local_path))
            .collect::<Result<Vec<_>, _>>()?;
        // Only enabled jobs reserve source paths. A deliberately paused job
        // cannot scan or upload from its source; when it is enabled again,
        // `check_media_source_overlap` re-resolves and validates the path.
        // This also lets an exact pause remain loadable if a mount/alias
        // changed while the job was active, without admitting a new disabled
        // overlapping job through the mutation path.
        let media_sources = active_media_sources(&settings.media_jobs)?;
        let profile_state = resolve_directory(&runtime.dir, true)?;
        paths.push((id.clone(), root, pairs, media_sources, profile_state));
    }
    Ok(paths)
}

fn active_media_sources(jobs: &[MediaImportJob]) -> Result<Vec<(String, PathBuf)>, String> {
    jobs.iter()
        .filter(|job| job.enabled)
        .map(|job| Ok((job.id.clone(), resolve_directory(&job.source_root, true)?)))
        .collect()
}

fn reject_profile_paths_against_media(
    candidate_paths: &[PathBuf],
    media_sources: &[(String, PathBuf)],
) -> Result<(), String> {
    if candidate_paths.iter().any(|candidate| {
        media_sources
            .iter()
            .any(|(_, source)| paths_overlap(candidate, source))
    }) {
        return Err("Cloud and folder-pair paths cannot overlap an enabled media source".into());
    }
    Ok(())
}

fn validate_profile_separation(profiles: &[ComparedProfilePaths]) -> Result<(), String> {
    for (index, (id, root, pairs, media_sources, profile_state)) in profiles.iter().enumerate() {
        if media_sources.iter().any(|(_, source)| {
            paths_overlap(source, root)
                || pairs.iter().any(|pair| paths_overlap(source, pair))
                || paths_overlap(source, profile_state)
        }) || media_sources
            .iter()
            .enumerate()
            .any(|(source_index, (_, source))| {
                media_sources
                    .iter()
                    .skip(source_index + 1)
                    .any(|(_, other)| paths_overlap(source, other))
            })
        {
            return Err(format!(
                "Profile '{}' has overlapping media, cloud, or folder-pair paths",
                id
            ));
        }
        for (other_id, other_root, other_pairs, other_media_sources, other_state) in
            profiles.iter().skip(index + 1)
        {
            if paths_overlap(root, other_root)
                || pairs.iter().any(|pair| paths_overlap(pair, other_root))
                || other_pairs.iter().any(|pair| paths_overlap(root, pair))
                || pairs.iter().any(|pair| {
                    other_pairs
                        .iter()
                        .any(|other_pair| paths_overlap(pair, other_pair))
                })
                || media_sources.iter().any(|(_, source)| {
                    paths_overlap(source, other_root)
                        || other_pairs.iter().any(|pair| paths_overlap(source, pair))
                        || paths_overlap(source, other_state)
                        || other_media_sources
                            .iter()
                            .any(|(_, other)| paths_overlap(source, other))
                })
                || other_media_sources.iter().any(|(_, source)| {
                    paths_overlap(source, root)
                        || pairs.iter().any(|pair| paths_overlap(source, pair))
                        || paths_overlap(source, profile_state)
                })
            {
                return Err(format!(
                    "Profiles '{}' and '{}' have overlapping cloud, folder-pair, or media folders",
                    id, other_id
                ));
            }
        }
    }
    Ok(())
}

fn reject_media_source_overlaps(
    candidate: &Path,
    candidate_profile: &str,
    candidate_job_id: &str,
    profiles: &[ComparedProfilePaths],
) -> Result<(), String> {
    for (profile_id, root, pairs, media_sources, profile_state) in profiles {
        let overlaps = paths_overlap(candidate, root)
            || pairs.iter().any(|pair| paths_overlap(candidate, pair))
            || paths_overlap(candidate, profile_state)
            || media_sources.iter().any(|(job_id, source)| {
                !(profile_id == candidate_profile && job_id == candidate_job_id)
                    && paths_overlap(candidate, source)
            });
        if overlaps {
            return Err(format!(
                "Media source overlaps configured data in profile '{profile_id}'"
            ));
        }
    }
    Ok(())
}

fn is_exact_media_pause(
    saved_jobs: &[MediaImportJob],
    candidate: &MediaImportJob,
    expected_revision: Option<u64>,
    expected_account: Option<&str>,
) -> bool {
    if candidate.enabled {
        return false;
    }
    let Some(saved) = saved_jobs.iter().find(|job| job.id == candidate.id) else {
        return false;
    };
    if !saved.enabled
        || expected_revision != Some(saved.revision)
        || expected_account != Some(saved.account_id.as_str())
        || candidate.revision != saved.revision
    {
        return false;
    }
    let mut paused = saved.clone();
    paused.enabled = false;
    paused == *candidate
}

fn reject_pair_overlaps(
    candidate: &Path,
    candidate_profile: &str,
    profiles: &[ComparedProfilePaths],
) -> Result<(), String> {
    for (profile_id, root, pairs, media_sources, profile_state) in profiles {
        if profile_id != candidate_profile
            && (paths_overlap(candidate, root)
                || pairs.iter().any(|pair| paths_overlap(candidate, pair))
                || paths_overlap(candidate, profile_state)
                || media_sources
                    .iter()
                    .any(|(_, source)| paths_overlap(candidate, source)))
        {
            return Err(format!(
                "Folder pair overlaps profile '{}' data; choose a separate local folder",
                profile_id
            ));
        }
    }
    Ok(())
}

fn profile_paths_except(
    state: &ManagerState,
    excluded: &str,
) -> Result<Vec<ComparedProfilePaths>, String> {
    Ok(profile_paths(state)?
        .into_iter()
        .filter(|(id, _, _, _, _)| id != excluded)
        .collect())
}

fn reject_root_overlaps(candidate: &Path, profiles: &[ComparedProfilePaths]) -> Result<(), String> {
    let candidate = resolve_directory(candidate, true)?;
    for (id, root, pairs, media_sources, _profile_state) in profiles {
        if paths_overlap(&candidate, root)
            || pairs.iter().any(|pair| paths_overlap(&candidate, pair))
            || media_sources
                .iter()
                .any(|(_, source)| paths_overlap(&candidate, source))
        {
            return Err(format!(
                "Cloud folder overlaps profile '{}' data; choose a separate folder",
                id
            ));
        }
    }
    Ok(())
}

fn validate_cloud_root(path: &Path) -> Result<PathBuf, String> {
    let config = Config {
        schema_version: CONFIG_SCHEMA_VERSION,
        cloud_root: path.to_owned(),
        pairs: Vec::new(),
    };
    let errors = validate_config(&config);
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    resolve_directory(path, true)
}

fn canonical_existing_directory(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() || path.components().any(|part| part == Component::ParentDir) {
        return Err("Profile path is not a safe absolute path".into());
    }
    let resolved = fs::canonicalize(path).map_err(|_| "Profile path cannot be resolved")?;
    if !fs::metadata(&resolved)
        .map_err(|_| "Profile path cannot be inspected")?
        .is_dir()
    {
        return Err("Profile path is not a directory".into());
    }
    Ok(resolved)
}

fn resolve_directory(path: &Path, allow_missing: bool) -> Result<PathBuf, String> {
    if !path.is_absolute() || path.components().any(|part| part == Component::ParentDir) {
        return Err("Profile path is not a safe absolute path".into());
    }
    if !allow_missing {
        return canonical_existing_directory(path);
    }
    let mut ancestor = path;
    let mut suffix = Vec::new();
    loop {
        match fs::symlink_metadata(ancestor) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let name = ancestor
                    .file_name()
                    .ok_or("Profile path cannot be resolved")?;
                suffix.push(name.to_owned());
                ancestor = ancestor.parent().ok_or("Profile path cannot be resolved")?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotConnected => {
                let name = ancestor
                    .file_name()
                    .ok_or("Profile path cannot be resolved")?;
                suffix.push(name.to_owned());
                ancestor = ancestor.parent().ok_or("Profile path cannot be resolved")?;
            }
            Err(_) => return Err("Profile path cannot be inspected".into()),
        }
    }
    if !fs::metadata(ancestor)
        .map_err(|_| "Profile path cannot be inspected")?
        .is_dir()
    {
        return Err("Profile path ancestor is not a directory".into());
    }
    let mut resolved = fs::canonicalize(ancestor).map_err(|_| "Profile path cannot be resolved")?;
    for component in suffix.iter().rev() {
        resolved.push(component);
    }
    Ok(resolved)
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    path_starts_with(left, right) || path_starts_with(right, left)
}

fn path_starts_with(path: &Path, ancestor: &Path) -> bool {
    let path = path.components().collect::<Vec<_>>();
    let ancestor = ancestor.components().collect::<Vec<_>>();
    path.len() >= ancestor.len()
        && path.iter().zip(ancestor.iter()).all(|(left, right)| {
            #[cfg(windows)]
            {
                left.as_os_str()
                    .to_string_lossy()
                    .eq_ignore_ascii_case(&right.as_os_str().to_string_lossy())
            }
            #[cfg(not(windows))]
            {
                left == right
            }
        })
}

fn strip_profile_id(mut request: Value) -> Value {
    if let Some(object) = request.as_object_mut() {
        object.remove("profile_id");
    }
    request
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Settings;
    use tempfile::tempdir;

    struct RemovalStore {
        removed: Arc<Mutex<Vec<String>>>,
        fail: bool,
    }
    impl super::super::SessionStore for RemovalStore {
        fn save(&self, _: &super::super::auth::Session) -> Result<(), String> {
            Ok(())
        }
        fn load(&self, _: &str, _: &str) -> Result<Option<super::super::auth::Session>, String> {
            Ok(None)
        }
        fn remove(&self, server: &str, _: &str) -> Result<(), String> {
            if self.fail {
                return Err("synthetic credential store failure".into());
            }
            self.removed.lock().unwrap().push(server.into());
            Ok(())
        }
    }

    // No runtime is started: synthetic settings and fake credential stores keep
    // account-removal tests independent of the host keyring, cloud and mounts.
    fn removal_fixture(root: &Path, fail: bool) -> (Arc<ProfileManager>, Arc<Mutex<Vec<String>>>) {
        let dir = root.join("state");
        fs::create_dir_all(&dir).unwrap();
        let mut settings = Settings::load(&dir).unwrap();
        settings.config.cloud_root = root.join("cloud");
        fs::create_dir_all(&settings.config.cloud_root).unwrap();
        settings.server = Some("https://synthetic.example.test".into());
        settings.mount_enabled = false;
        settings.save(&dir).unwrap();
        let vaults = Arc::new(raiun_vault::session::VaultSessionCoordinator::new());
        let mut runtime = new_runtime(dir.clone(), None, vaults.clone()).unwrap();
        let removed = Arc::new(Mutex::new(Vec::new()));
        Arc::get_mut(&mut runtime).unwrap().session_store = Arc::new(RemovalStore {
            removed: removed.clone(),
            fail,
        });
        runtime.restoring.store(false, Ordering::Release);
        let registry = load_registry(&dir.join(REGISTRY_FILE)).unwrap();
        let manager = Arc::new(ProfileManager {
            state_dir: dir,
            vaults,
            state: Mutex::new(ManagerState {
                registry,
                runtimes: BTreeMap::from([(DEFAULT_ID.into(), runtime)]),
            }),
            mutation_gate: Mutex::new(()),
            shutdown_requested: AtomicBool::new(false),
        });
        (manager, removed)
    }

    #[test]
    fn removal_preserves_legacy_data_and_reservations_across_restart_and_restore() {
        let temp = tempdir().unwrap();
        let (manager, credentials) = removal_fixture(temp.path(), false);
        let dir = manager.state_dir.clone();
        let canary = dir.join("retained-recovery-canary");
        fs::write(&canary, b"unuploaded synthetic edit").unwrap();
        let old_runtime = manager.state.lock().unwrap().runtimes[DEFAULT_ID].clone();
        let result = manager.handle(json!({"action":"account_remove","profile_id":"default","expected_auth_generation":0,"confirm":true})).unwrap();
        assert!(result["selected"].is_null());
        assert_eq!(
            credentials.lock().unwrap().as_slice(),
            &["https://synthetic.example.test"]
        );
        assert_eq!(fs::read(&canary).unwrap(), b"unuploaded synthetic edit");
        assert!(old_runtime.handle(json!({"action":"pairs"})).is_err());
        assert!(
            manager
                .handle(json!({"action":"status","profile_id":"default"}))
                .is_err()
        );
        let accounts = manager.accounts().unwrap();
        assert!(accounts["items"].as_array().unwrap().is_empty());
        assert_eq!(accounts["removed_items"][0]["id"], "default");
        assert!(
            manager.handle(json!({"action":"status"})).unwrap()["accounts_empty"]
                .as_bool()
                .unwrap()
        );
        let reopened = ProfileManager::open(dir).unwrap();
        let retained = reopened.state.lock().unwrap().runtimes[DEFAULT_ID].clone();
        assert!(retained.shutdown.load(Ordering::Acquire));
        assert!(retained.retiring.load(Ordering::Acquire));
        assert!(reopened.accounts().unwrap()["selected"].is_null());
        // Retired roots remain exclusion reservations for future account setup.
        let paths = profile_paths(&reopened.state.lock().unwrap()).unwrap();
        assert!(reject_root_overlaps(&temp.path().join("cloud"), &paths).is_err());
        let restored = reopened
            .handle(json!({"action":"account_restore","profile_id":"default","confirm":true}))
            .unwrap();
        assert_eq!(restored["selected"], "default");
        assert_eq!(restored["sign_in_required"], true);
        assert!(
            reopened.state.lock().unwrap().runtimes[DEFAULT_ID]
                .settings
                .lock()
                .unwrap()
                .server
                .is_none()
        );
        assert_eq!(fs::read(&canary).unwrap(), b"unuploaded synthetic edit");
        reopened.request_shutdown().unwrap();
    }

    #[test]
    fn removal_rejects_stale_generation_and_failed_credentials_without_hiding_profile() {
        let temp = tempdir().unwrap();
        let (manager, _) = removal_fixture(temp.path(), true);
        assert!(manager.handle(json!({"action":"account_remove","profile_id":"default","expected_auth_generation":99,"confirm":true})).unwrap_err().contains("account changed"));
        assert!(manager.handle(json!({"action":"account_remove","profile_id":"default","expected_auth_generation":0,"confirm":true})).unwrap_err().contains("credential store"));
        assert_eq!(manager.accounts().unwrap()["items"][0]["id"], "default");
        assert!(
            manager.accounts().unwrap()["removed_items"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(
            !manager.state.lock().unwrap().runtimes[DEFAULT_ID]
                .retiring
                .load(Ordering::Acquire)
        );
        assert!(
            manager
                .handle(json!({"action":"account_remove","profile_id":"default","confirm":false}))
                .is_err()
        );
        manager.request_shutdown().unwrap();
    }

    #[test]
    fn removal_persistence_failure_keeps_visible_profile_and_can_retry_without_data_loss() {
        let temp = tempdir().unwrap();
        let (manager, _) = removal_fixture(temp.path(), false);
        let path = manager.state_dir.join(REGISTRY_FILE);
        let saved = fs::read(&path).unwrap();
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(manager.handle(json!({"action":"account_remove","profile_id":"default","expected_auth_generation":0,"confirm":true})).is_err());
        assert_eq!(manager.accounts().unwrap()["items"][0]["id"], "default");
        assert!(
            manager.accounts().unwrap()["removed_items"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        fs::remove_dir(&path).unwrap();
        fs::write(&path, saved).unwrap();
        let generation = manager.accounts().unwrap()["items"][0]["status"]["auth_generation"]
            .as_u64()
            .unwrap();
        manager.handle(json!({"action":"account_remove","profile_id":"default","expected_auth_generation":generation,"confirm":true})).unwrap();
        assert!(manager.accounts().unwrap()["selected"].is_null());
    }

    #[test]
    fn removal_selects_peer_and_keeps_removed_roots_reserved() {
        let temp = tempdir().unwrap();
        let (manager, credentials) = removal_fixture(temp.path(), false);
        let peer = manager.handle(json!({"action":"account_add","label":"Team","cloud_root":temp.path().join("peer-cloud")})).unwrap()["id"].as_str().unwrap().to_owned();
        assert!(manager.handle(json!({"action":"account_remove","profile_id":peer,"expected_auth_generation":0,"confirm":true})).is_err());
        let removed = manager.handle(json!({"action":"account_remove","profile_id":"default","expected_auth_generation":0,"confirm":true})).unwrap();
        assert_eq!(removed["selected"], peer);
        assert_eq!(
            manager.accounts().unwrap()["items"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(credentials.lock().unwrap().len(), 1);
        assert_eq!(
            manager.state.lock().unwrap().runtimes[&peer]
                .auth_generation
                .load(Ordering::Acquire),
            0
        );
        assert!(manager.handle(json!({"action":"account_add","label":"Unsafe reuse","cloud_root":temp.path().join("cloud")})).is_err());
        let restored = manager
            .handle(json!({"action":"account_restore","profile_id":"default","confirm":true}))
            .unwrap();
        assert_eq!(restored["selected"], peer);
        assert_eq!(
            manager.accounts().unwrap()["items"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        manager.request_shutdown().unwrap();
    }

    #[test]
    fn removal_uncertain_password_cleanup_keeps_profile_visible() {
        let temp = tempdir().unwrap();
        let (manager, _) = removal_fixture(temp.path(), false);
        manager.state.lock().unwrap().runtimes[DEFAULT_ID]
            .vault_cleanup_uncertain
            .store(true, Ordering::Release);
        let error = manager.handle(json!({"action":"account_remove","profile_id":"default","expected_auth_generation":0,"confirm":true})).unwrap_err();
        assert!(error.contains("cleanup is uncertain"));
        assert_eq!(manager.accounts().unwrap()["items"][0]["id"], "default");
        assert!(
            manager.accounts().unwrap()["removed_items"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        manager.request_shutdown().unwrap();
    }

    #[test]
    fn rename_changes_label_only_and_rejects_stale_labels_and_invalid_names() {
        let temp = tempdir().unwrap();
        let (manager, credentials) = removal_fixture(temp.path(), false);
        let runtime = manager.state.lock().unwrap().runtimes[DEFAULT_ID].clone();
        let settings = fs::read(manager.state_dir.join("settings.json")).unwrap();
        let result = manager.handle(json!({"action":"account_rename","profile_id":"default","expected_label":"Default","label":"  Personal  "})).unwrap();
        assert_eq!(result["label"], "Personal");
        assert_eq!(result["renamed_profile_id"], "default");
        assert_eq!(manager.accounts().unwrap()["items"][0]["label"], "Personal");
        assert!(Arc::ptr_eq(
            &runtime,
            &manager.state.lock().unwrap().runtimes[DEFAULT_ID]
        ));
        assert_eq!(runtime.auth_generation.load(Ordering::Acquire), 0);
        assert_eq!(
            fs::read(manager.state_dir.join("settings.json")).unwrap(),
            settings
        );
        assert!(credentials.lock().unwrap().is_empty());
        assert!(manager.handle(json!({"action":"account_rename","profile_id":"default","expected_label":"Default","label":"Stale overwrite"})).is_err());
        for label in ["", "bad\nname"] {
            assert!(manager.handle(json!({"action":"account_rename","profile_id":"default","expected_label":"Personal","label":label})).is_err());
        }
        assert_eq!(
            load_registry(&manager.state_dir.join(REGISTRY_FILE))
                .unwrap()
                .profiles[DEFAULT_ID]
                .label,
            "Personal"
        );
        manager.request_shutdown().unwrap();
    }

    #[test]
    fn registry_rejects_unknown_or_missing_profile_ids() {
        let registry = Registry {
            version: REGISTRY_VERSION,
            removed: BTreeSet::new(),
            selected: "missing".into(),
            profiles: BTreeMap::from([(
                DEFAULT_ID.into(),
                ProfileRecord {
                    label: "Default".into(),
                },
            )]),
        };
        assert!(validate_registry(&registry).is_err());
    }

    #[test]
    fn unlock_target_resolution_never_falls_back_to_selected_profile() {
        let temp = tempdir().expect("state directory");
        let manager = ProfileManager::open(temp.path().to_path_buf()).expect("profile manager");
        let missing = manager
            .handle(json!({
                "action":"vault_resolve_unlock_target",
                "space_id":"space-a",
                "root_resource_id":"root-a"
            }))
            .unwrap_err();
        assert!(missing.contains("profile_id is required"));

        let unknown = manager
            .handle(json!({
                "action":"vault_resolve_unlock_target",
                "profile_id":"unknown-profile",
                "space_id":"space-a",
                "root_resource_id":"root-a"
            }))
            .unwrap_err();
        assert!(unknown.contains("Unknown profile"));
    }

    #[test]
    fn password_bearing_online_offline_and_create_actions_cross_profile_boundary() {
        let temp = tempdir().expect("state directory");
        let manager = ProfileManager::open(temp.path().to_path_buf()).expect("profile manager");

        for action in ["vault_unlock", "vault_unlock_offline", "vault_create"] {
            let result = manager.handle(json!({
                "action": action,
                "space_id": "synthetic-space",
                "root_path": "/Synthetic.vault",
                "root_resource_id": "synthetic-root",
                "password": "test-only-password"
            }));
            let error = result.expect_err("synthetic profile has no session or cached root");
            assert_ne!(
                error, "Password is only accepted by a vault operation",
                "password-bearing {action} must be routed into the vault runtime"
            );
        }

        let saved_unlock = manager
            .handle(json!({
                "action":"vault_unlock_offline",
                "space_id":"synthetic-space",
                "root_path":"/Synthetic.vault",
                "root_resource_id":"synthetic-root",
                "use_saved":true
            }))
            .expect_err("no synthetic offline root or remembered password exists");
        assert_ne!(
            saved_unlock, "Unknown action",
            "saved offline unlock must reach the vault runtime through the same profile boundary"
        );

        let non_vault = manager
            .handle(json!({"action":"status","password":"test-only-password"}))
            .expect_err("non-vault actions must reject passwords");
        assert_eq!(non_vault, "Password is only accepted by a vault operation");
        manager.request_shutdown().expect("stop profile runtimes");
    }

    #[test]
    fn diagnostics_are_scoped_to_exact_profile_and_omit_profile_identity() {
        let temp = tempdir().expect("state directory");
        let manager = ProfileManager::open(temp.path().to_path_buf()).expect("profile manager");
        let cloud_root = temp.path().join("CANARY_PRIVATE_CLOUD_ROOT");
        let added = manager
            .handle(json!({
                "action":"account_add",
                "label":"CANARY_ACCOUNT_LABEL",
                "cloud_root":cloud_root,
            }))
            .expect("add profile");
        let profile_id = added["id"].as_str().expect("profile id").to_owned();
        let runtime = manager
            .state
            .lock()
            .unwrap()
            .runtimes
            .get(&profile_id)
            .cloned()
            .unwrap();
        runtime.settings.lock().unwrap().paused = true;

        let report = manager
            .handle(json!({"action":"diagnostics","profile_id":profile_id}))
            .expect("profile-scoped diagnostics");
        assert_eq!(report["schema_version"], 1);
        assert_eq!(report["profile_scope"], "selected_profile");
        assert_eq!(report["profile_count"], 2);
        assert_eq!(report["profile_config"]["folder_pair_count"], 0);
        assert_eq!(report["runtime"]["sync_paused"], true);
        let serialized = report.to_string();
        assert!(!serialized.contains(&profile_id));
        assert!(!serialized.contains("CANARY_ACCOUNT_LABEL"));
        assert!(!serialized.contains("CANARY_PRIVATE_CLOUD_ROOT"));
        manager.request_shutdown().expect("stop profile runtimes");
    }

    #[test]
    fn registry_requires_safe_nondefault_ids_and_bounded_labels() {
        let mut profiles = BTreeMap::from([(
            DEFAULT_ID.into(),
            ProfileRecord {
                label: "Default".into(),
            },
        )]);
        profiles.insert(
            "../../escape".into(),
            ProfileRecord {
                label: "Work".into(),
            },
        );
        let registry = Registry {
            version: REGISTRY_VERSION,
            removed: BTreeSet::new(),
            selected: DEFAULT_ID.into(),
            profiles,
        };
        assert!(validate_registry(&registry).is_err());
        assert!(validate_label(&"x".repeat(MAX_LABEL_BYTES + 1)).is_err());
    }

    #[test]
    fn newly_added_profile_persists_mount_intent_without_changing_existing_profiles() {
        let temp = tempdir().expect("state directory");
        let manager = ProfileManager::open(temp.path().to_path_buf()).expect("profile manager");
        let cloud_root = temp.path().join("work-cloud");
        let added = manager
            .handle(json!({
                "action":"account_add",
                "label":"Work",
                "cloud_root":cloud_root,
            }))
            .expect("add profile");
        let id = added["id"].as_str().expect("profile id").to_owned();
        let profile_dir = profile_dir(temp.path(), &id);

        assert!(Settings::load(&profile_dir).unwrap().mount_enabled);
        assert!(!Settings::load(temp.path()).unwrap().mount_enabled);
        assert_eq!(
            manager
                .handle(json!({"action":"status", "profile_id":id}))
                .unwrap()["mounted"],
            false,
            "mount intent must not claim a mount before sign-in"
        );

        manager.request_shutdown().expect("stop fixture runtimes");
    }

    #[test]
    fn path_comparisons_canonicalize_existing_ancestors_and_detect_parent_overlap() {
        let temp = tempdir().expect("tempdir");
        let cloud = temp.path().join("cloud");
        let pair = temp.path().join("pair");
        fs::create_dir(&cloud).expect("cloud");
        fs::create_dir(&pair).expect("pair");
        let cloud_child = cloud.join("nested");
        let resolved = resolve_directory(&cloud_child, true).expect("resolved missing child");
        assert!(paths_overlap(
            &resolved,
            &fs::canonicalize(&cloud).expect("canonical cloud")
        ));

        let profiles = vec![(
            "other".into(),
            fs::canonicalize(&cloud).unwrap(),
            vec![],
            vec![],
            temp.path().join("other-state"),
        )];
        assert!(reject_root_overlaps(&cloud_child, &profiles).is_err());
        assert!(reject_root_overlaps(&pair, &profiles).is_ok());
    }

    #[test]
    fn media_source_paths_are_reserved_against_every_profile_root_and_pair() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("account-cloud");
        let pair = temp.path().join("account-pair");
        let source = root.join("photos");
        fs::create_dir_all(&source).expect("media source under cloud root");
        fs::create_dir(&pair).expect("folder pair");
        let profile = (
            "profile-a".into(),
            fs::canonicalize(&root).unwrap(),
            vec![fs::canonicalize(&pair).unwrap()],
            vec![("other-job".into(), fs::canonicalize(&pair).unwrap())],
            temp.path().join("profile-state"),
        );
        assert!(
            reject_media_source_overlaps(
                &fs::canonicalize(&source).unwrap(),
                "profile-b",
                "backup",
                std::slice::from_ref(&profile),
            )
            .is_err()
        );
        assert!(reject_root_overlaps(&source, std::slice::from_ref(&profile)).is_err());
        assert!(
            reject_profile_paths_against_media(
                std::slice::from_ref(&fs::canonicalize(&root).unwrap()),
                &[("backup".into(), fs::canonicalize(&source).unwrap())],
            )
            .is_err()
        );
        assert!(
            reject_pair_overlaps(
                &pair.join("new-child"),
                "profile-b",
                std::slice::from_ref(&profile)
            )
            .is_err()
        );
        assert!(
            reject_profile_paths_against_media(
                std::slice::from_ref(&fs::canonicalize(&source).unwrap()),
                &[("backup".into(), fs::canonicalize(&source).unwrap())],
            )
            .is_err()
        );

        let external = temp.path().join("photos");
        fs::create_dir(&external).expect("external source");
        assert!(
            reject_media_source_overlaps(
                &fs::canonicalize(&external).unwrap(),
                "profile-b",
                "backup",
                std::slice::from_ref(&profile),
            )
            .is_ok()
        );
    }

    #[test]
    fn disabled_new_job_is_rejected_on_overlap_but_saved_pause_is_not_a_startup_reservation() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("cloud");
        let source = root.join("photos");
        fs::create_dir_all(&source).expect("source below cloud root");
        let saved = MediaImportJob {
            id: "backup".into(),
            revision: 2,
            account_id: "account-a".into(),
            source_root: source.clone(),
            space_id: "space-a".into(),
            destination_root: "/Photos".into(),
            destination_root_resource_id: "folder-a".into(),
            filter: raiun_core::MediaFilter::Photos,
            organization: raiun_core::MediaOrganization::PreserveRelativePath,
            filesystem_mtime_utc: false,
            interval_seconds: 3_600,
            enabled: true,
        };
        let mut pause = saved.clone();
        pause.enabled = false;
        let profile = (
            "profile-a".into(),
            fs::canonicalize(&root).unwrap(),
            vec![],
            active_media_sources(std::slice::from_ref(&pause)).unwrap(),
            temp.path().join("profile-state"),
        );

        assert!(
            active_media_sources(std::slice::from_ref(&pause))
                .unwrap()
                .is_empty()
        );
        assert!(validate_profile_separation(std::slice::from_ref(&profile)).is_ok());
        assert!(!is_exact_media_pause(
            &[],
            &pause,
            Some(2),
            Some("account-a")
        ));
        assert!(
            reject_media_source_overlaps(
                &fs::canonicalize(&source).unwrap(),
                "profile-b",
                "new-disabled-job",
                std::slice::from_ref(&profile),
            )
            .is_err()
        );
    }

    #[test]
    fn manager_rejects_disabled_new_media_job_under_its_cloud_root() {
        let temp = tempdir().expect("test root");
        let state_dir = temp.path().join("agent-state");
        fs::create_dir(&state_dir).expect("state directory");
        let cloud_root = temp.path().join("cloud");
        let source = cloud_root.join("photos");
        fs::create_dir_all(&source).expect("source below cloud root");
        let manager = ProfileManager::open(state_dir).expect("profile manager");
        {
            let state = manager.state.lock().expect("profile state");
            let runtime = state.runtimes.get("default").unwrap().clone();
            runtime.settings.lock().unwrap().config.cloud_root = cloud_root;
        }
        let request = json!({
            "job": {
                "id":"paused-new",
                "revision":0,
                "account_id":"account-a",
                "source_root":source,
                "space_id":"space-a",
                "destination_root":"/Photos",
                "destination_root_resource_id":"folder-a",
                "filter":"photos",
                "organization":"preserve_relative_path",
                "filesystem_mtime_utc":false,
                "interval_seconds":3600,
                "enabled":false
            }
        });

        assert!(
            manager
                .check_media_source_overlap("default", &request)
                .is_err()
        );
        manager.request_shutdown().expect("shutdown runtimes");
    }

    #[test]
    fn only_exact_existing_pause_may_bypass_media_source_overlap_admission() {
        let saved = MediaImportJob {
            id: "backup".into(),
            revision: 4,
            account_id: "account-a".into(),
            source_root: PathBuf::from("/home/user/Pictures"),
            space_id: "space-a".into(),
            destination_root: "/Photos".into(),
            destination_root_resource_id: "folder-a".into(),
            filter: raiun_core::MediaFilter::Photos,
            organization: raiun_core::MediaOrganization::PreserveRelativePath,
            filesystem_mtime_utc: false,
            interval_seconds: 3_600,
            enabled: true,
        };
        let mut pause = saved.clone();
        pause.enabled = false;
        assert!(is_exact_media_pause(
            std::slice::from_ref(&saved),
            &pause,
            Some(4),
            Some("account-a"),
        ));

        assert!(!is_exact_media_pause(
            &[],
            &pause,
            Some(4),
            Some("account-a"),
        ));
        let mut changed = pause.clone();
        changed.source_root = PathBuf::from("/home/user");
        assert!(!is_exact_media_pause(
            std::slice::from_ref(&saved),
            &changed,
            Some(4),
            Some("account-a"),
        ));
        assert!(!is_exact_media_pause(
            std::slice::from_ref(&saved),
            &pause,
            Some(3),
            Some("account-a"),
        ));
    }

    #[cfg(unix)]
    #[test]
    fn media_source_alias_of_another_profiles_root_is_rejected() {
        let temp = tempdir().expect("tempdir");
        let real = temp.path().join("real-root");
        let alias = temp.path().join("media-alias");
        fs::create_dir(&real).expect("root");
        std::os::unix::fs::symlink(&real, &alias).expect("alias");
        let normalized_alias = resolve_directory(&alias, true).unwrap();
        let profile = (
            "profile-a".into(),
            fs::canonicalize(&real).unwrap(),
            vec![],
            vec![],
            temp.path().join("profile-state"),
        );
        assert!(
            reject_media_source_overlaps(&normalized_alias, "profile-b", "backup", &[profile],)
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn path_comparisons_detect_symlink_aliases_for_missing_roots() {
        use std::os::unix::fs::symlink;

        let temp = tempdir().expect("tempdir");
        let real = temp.path().join("real-cloud");
        let alias = temp.path().join("alias");
        fs::create_dir(&real).expect("cloud dir");
        symlink(&real, &alias).expect("alias");
        let profiles = vec![(
            "other".into(),
            canonical_existing_directory(&real).expect("canonical cloud"),
            vec![],
            vec![],
            temp.path().join("other-state"),
        )];

        assert!(reject_root_overlaps(&alias.join("account"), &profiles).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn profile_state_directories_reject_symlinks() {
        use std::os::unix::fs::symlink;

        let temp = tempdir().expect("tempdir");
        let state_dir = temp.path().join("state");
        fs::create_dir(&state_dir).expect("state dir");
        let actual = temp.path().join("actual");
        fs::create_dir(&actual).expect("actual dir");
        symlink(&actual, state_dir.join(PROFILES_DIR)).expect("symlink");
        assert!(ensure_profiles_root(&state_dir).is_err());
    }
}
