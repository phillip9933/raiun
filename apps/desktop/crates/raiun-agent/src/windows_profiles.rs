//! Account routing and durable exclusion reservations. Production activation
//! is enabled in non-test candidates after focused native broker acceptance.
use super::windows_profile_registry::{Registry, RootReservation, SourceKind, SourceReservation};
use super::*;
use std::collections::BTreeMap;

struct BrokerState {
    registry: Registry,
    runtimes: BTreeMap<String, Arc<WindowsAgent>>,
}
pub(super) struct WindowsProfiles {
    source_admissions: SharedSourceAdmissions,
    vault_sessions: Arc<raiun_vault::session::VaultSessionCoordinator>,
    storage: DpapiSessionStore,
    state: Mutex<BrokerState>,
    mutation_gate: Mutex<()>,
}

impl WindowsProfiles {
    fn open(storage: DpapiSessionStore) -> Result<Self, String> {
        let bytes = storage
            .load_profile_registry()
            .map_err(|_| "Could not read the account registry")?;
        let mut registry = Registry::decode_or_default(bytes.as_deref())?;
        // Active-session pointers are deliberately insufficient here: logout
        // preserves registered roots while revoking startup credentials.
        let ids = registry.profiles().keys().cloned().collect::<Vec<_>>();
        for id in &ids {
            let profile = storage
                .for_profile(id)
                .map_err(|_| "Account storage is unavailable")?;
            for bytes in profile
                .load_root_config_inventory(id)
                .map_err(|_| "Could not inventory saved account roots")?
            {
                let metadata = decode_root_metadata(&bytes, id)?;
                registry = registry.with_reserved_root(
                    id,
                    RootReservation::new(
                        metadata.path,
                        metadata.volume_serial,
                        metadata.file_index,
                        true,
                    )?,
                )?;
            }
        }
        registry = inventory_saved_source_exclusions(&storage, registry)?;
        validate_separation(&registry)?;
        let encoded = registry.encode()?;
        if bytes.as_deref() != Some(encoded.as_slice()) {
            storage
                .save_profile_registry(&encoded)
                .map_err(|_| "Could not save the account registry")?;
        }
        // No runtime/auth refresh starts until every profile's metadata and
        // exclusions have been admitted and the migration is durable.
        let source_admissions = Arc::new(Mutex::new(Arc::new(registry.clone())));
        // One application-wide owner enforces the global unlocked-session cap
        // and KDF permit across every account, including newly added profiles.
        let vault_sessions = Arc::new(raiun_vault::session::VaultSessionCoordinator::new());
        let mut runtimes = BTreeMap::new();
        for id in ids {
            let store = DpapiStore::for_profile(&id)?;
            let runtime = Arc::new(WindowsAgent::new_for_profile_with_services(
                &id,
                store,
                Some(source_admissions.clone()),
                vault_sessions.clone(),
            )?);
            runtime.attach_existing_file_save_owner()?;
            runtimes.insert(id.clone(), runtime);
        }
        Ok(Self {
            source_admissions,
            vault_sessions,
            storage,
            state: Mutex::new(BrokerState { registry, runtimes }),
            mutation_gate: Mutex::new(()),
        })
    }

    #[cfg(test)]
    pub(super) fn for_isolated_lifecycle_fixture(
        storage: DpapiSessionStore,
        registry: Registry,
        runtime: Arc<WindowsAgent>,
    ) -> Result<Self, String> {
        if registry.selected() != runtime.profile_scope {
            return Err("Fixture profile mismatch".into());
        }
        let source_admissions = runtime
            .source_admissions
            .clone()
            .ok_or("Fixture admissions missing")?;
        storage
            .save_profile_registry(&registry.encode()?)
            .map_err(|_| "Fixture registry persistence failed")?;
        let mut runtimes = BTreeMap::new();
        runtimes.insert(runtime.profile_scope.clone(), runtime.clone());
        Ok(Self {
            source_admissions,
            vault_sessions: runtime.vault_sessions.clone(),
            storage,
            state: Mutex::new(BrokerState { registry, runtimes }),
            mutation_gate: Mutex::new(()),
        })
    }

    #[cfg(test)]
    pub(super) fn handle_isolated_lifecycle_session(
        &self,
        request: Value,
    ) -> Result<(Value, bool), String> {
        // Private component seam; public handle_owned keeps its false gate.
        self.dispatch_vault_session(
            windows_vault_requests::OwnedControlRequest::new(request).decode_session()?,
        )
    }

    fn resolve(&self, request: &Value) -> Result<(String, Arc<WindowsAgent>), String> {
        let state = self
            .state
            .lock()
            .map_err(|_| "Account state is unavailable")?;
        let id = match request.get("profile_id") {
            None => state.registry.selected(),
            Some(Value::String(id)) => id,
            Some(_) => return Err("Invalid profile_id".into()),
        };
        let runtime = state
            .runtimes
            .get(id)
            .cloned()
            .ok_or("Unknown profile_id")?;
        Ok((id.into(), runtime))
    }

    fn persist(&self, registry: &Registry) -> Result<(), String> {
        // Independent snapshot lock only. Workers clone and release it before
        // any I/O and never acquire broker state/mutation/lifecycle locks.
        let mut published = self
            .source_admissions
            .lock()
            .map_err(|_| "Source admission is unavailable")?;
        self.storage
            .save_profile_registry(&registry.encode()?)
            .map_err(|_| "Could not save the account registry".to_owned())?;
        *published = Arc::new(registry.clone());
        Ok(())
    }

    pub(super) fn refresh_all(&self) -> Result<(), String> {
        let runtimes = self
            .state
            .lock()
            .map_err(|_| "Account state is unavailable")?
            .runtimes
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for runtime in runtimes {
            runtime.maybe_start_refresh()?;
        }
        Ok(())
    }

    pub(super) fn stop_all(&self) -> Result<(), String> {
        let runtimes = self
            .state
            .lock()
            .map_err(|_| "Account state is unavailable")?
            .runtimes
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let mut error = None;
        for runtime in runtimes {
            if let Err(next) = runtime.stop_and_join() {
                error.get_or_insert(next);
            }
        }
        error.map_or(Ok(()), Err)
    }

    fn handle_owned(
        &self,
        request: windows_vault_requests::OwnedControlRequest,
    ) -> Result<(Value, bool), String> {
        let session_action = request
            .value()
            .get("action")
            .and_then(Value::as_str)
            .is_some_and(|action| matches!(action, "vault_unlock" | "vault_lock" | "vault_forget"));
        if !session_action {
            return self.handle(request.value());
        }
        let request = request.decode_session()?;
        if !WINDOWS_VAULT_SESSIONS_ENABLED {
            return Err("Windows vault sessions are not available yet".into());
        }
        self.dispatch_vault_session(request)
    }

    // The public action gate is deliberately outside this shared implementation.
    // Isolated component fixtures can call this private seam without enabling
    // production RPC acceptance or replacing any authority checks below.
    fn dispatch_vault_session(
        &self,
        request: windows_vault_requests::session_requests::VaultSessionRequest,
    ) -> Result<(Value, bool), String> {
        let _gate = self
            .mutation_gate
            .lock()
            .map_err(|_| "Vault changes are unavailable")?;
        match request {
            windows_vault_requests::session_requests::VaultSessionRequest::Unlock {
                target,
                mut credential,
            } => {
                let (profile, runtime) = {
                    let state = self
                        .state
                        .lock()
                        .map_err(|_| "Account state is unavailable")?;
                    let profile = target
                        .profile_id
                        .as_deref()
                        .unwrap_or(state.registry.selected())
                        .to_owned();
                    let runtime = state
                        .runtimes
                        .get(&profile)
                        .cloned()
                        .ok_or("Unknown profile_id")?;
                    (profile, runtime)
                };
                let _credential_operation = runtime
                    .vault_credential_operation
                    .lock()
                    .map_err(|_| "Vault credential changes are unavailable")?;
                let prepared = runtime.prepare_windows_vault_unlock(&target, &mut credential)?;
                {
                    let mut state = self
                        .state
                        .lock()
                        .map_err(|_| "Account state is unavailable")?;
                    if state
                        .runtimes
                        .get(&profile)
                        .is_none_or(|active| !Arc::ptr_eq(active, &runtime))
                    {
                        return Err("The vault account runtime changed".into());
                    }
                    runtime.check_vault_preparation(&prepared)?;
                    // Write the historical encrypted-location exclusion BEFORE
                    // any live route can expose a native decrypted identity.
                    let next = state
                        .registry
                        .with_reserved_vault(&profile, prepared.reservation.clone())?;
                    self.persist(&next)?;
                    state.registry = next;
                }
                Ok((runtime.publish_windows_vault_unlock(prepared)?, false))
            }
            windows_vault_requests::session_requests::VaultSessionRequest::ForgetSaved {
                target,
            } => {
                let runtime = {
                    let state = self
                        .state
                        .lock()
                        .map_err(|_| "Account state is unavailable")?;
                    let profile = target
                        .profile_id
                        .as_deref()
                        .unwrap_or(state.registry.selected());
                    state
                        .runtimes
                        .get(profile)
                        .cloned()
                        .ok_or("Unknown profile_id")?
                };
                let _credential_operation = runtime
                    .vault_credential_operation
                    .lock()
                    .map_err(|_| "Vault credential changes are unavailable")?;
                Ok((runtime.forget_windows_vault_password(&target)?, false))
            }
            windows_vault_requests::session_requests::VaultSessionRequest::Lock { target } => {
                let runtime = {
                    let state = self
                        .state
                        .lock()
                        .map_err(|_| "Account state is unavailable")?;
                    let profile = target
                        .profile_id
                        .as_deref()
                        .unwrap_or(state.registry.selected());
                    state
                        .runtimes
                        .get(profile)
                        .cloned()
                        .ok_or("Unknown profile_id")?
                };
                let _credential_operation = runtime
                    .vault_credential_operation
                    .lock()
                    .map_err(|_| "Vault credential changes are unavailable")?;
                Ok((runtime.lock_windows_vault(&target)?, false))
            }
        }
    }

    pub(super) fn handle(&self, request: &Value) -> Result<(Value, bool), String> {
        reject_secret_request(request)?;
        let action = request
            .get("action")
            .and_then(Value::as_str)
            .ok_or("Missing action")?;
        match action {
            "shutdown" => Ok((json!({"stopping":true}), true)),
            "accounts" => {
                let (selected, profiles) = {
                    let state = self
                        .state
                        .lock()
                        .map_err(|_| "Account state is unavailable")?;
                    (
                        state.registry.selected().to_owned(),
                        state
                            .registry
                            .profiles()
                            .iter()
                            .map(|(id, record)| {
                                (
                                    id.clone(),
                                    record.label().to_owned(),
                                    state.runtimes[id].clone(),
                                )
                            })
                            .collect::<Vec<_>>(),
                    )
                };
                let mut items = Vec::new();
                for (id, label, runtime) in profiles {
                    let mut status = runtime.status()?;
                    status["profile_label"] = json!(label);
                    status["account_setup_requires_sign_in"] = json!(true);
                    status["account_switch_supported"] = json!(WINDOWS_ACCOUNTS_ENABLED);
                    items.push(json!({"id":id,"label":label,"status":status}));
                }
                Ok((json!({"selected":selected,"items":items}), false))
            }
            "account_select" => {
                let _gate = self
                    .mutation_gate
                    .lock()
                    .map_err(|_| "Account changes are unavailable")?;
                let id = request
                    .get("profile_id")
                    .and_then(Value::as_str)
                    .ok_or("Missing profile_id")?;
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| "Account state is unavailable")?;
                let next = state.registry.with_selected(id)?;
                self.persist(&next)?;
                state.registry = next;
                // Selection neither revokes credentials nor drains any runtime.
                Ok((json!({}), false))
            }
            "account_add" => {
                let _gate = self
                    .mutation_gate
                    .lock()
                    .map_err(|_| "Account changes are unavailable")?;
                if request.get("cloud_root").is_some() {
                    return Err(
                        "Add the Windows account first, then sign in and choose its drive folder"
                            .into(),
                    );
                }
                let label = request
                    .get("label")
                    .and_then(Value::as_str)
                    .ok_or("Missing label")?;
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| "Account state is unavailable")?;
                let mut allocated = None;
                for _ in 0..8 {
                    let mut bytes = [0_u8; 16];
                    getrandom::fill(&mut bytes).map_err(|_| "Could not allocate an account ID")?;
                    let id = format!(
                        "profile-{}",
                        bytes
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect::<String>()
                    );
                    if !state.registry.profiles().contains_key(&id) {
                        allocated = Some(id);
                        break;
                    }
                }
                let id = allocated.ok_or("Could not allocate an account ID")?;
                let next = state.registry.with_added(&id, label)?;
                let runtime = Arc::new(WindowsAgent::new_for_profile_with_services(
                    &id,
                    DpapiStore::for_profile(&id)?,
                    Some(self.source_admissions.clone()),
                    self.vault_sessions.clone(),
                )?);
                runtime.attach_existing_file_save_owner()?;
                self.persist(&next)?;
                state.registry = next;
                state.runtimes.insert(id.clone(), runtime);
                Ok((json!({"id":id}), false))
            }
            "configure" | "configure_root" => {
                let _gate = self
                    .mutation_gate
                    .lock()
                    .map_err(|_| "Account changes are unavailable")?;
                let (id, runtime) = self.resolve(request)?;
                let path = request
                    .get("cloud_root")
                    .and_then(Value::as_str)
                    .ok_or("Choose a Windows drive folder")?;
                let previous = {
                    let state = runtime
                        .state
                        .lock()
                        .map_err(|_| "Account state is unavailable")?;
                    if state.session.is_none()
                        || !state.online_authenticated
                        || state.authenticating
                        || state.refreshing
                        || state.logout_pending
                        || state.session_cleanup_uncertain
                    {
                        return Err("Connect this account before choosing a drive folder".into());
                    }
                    state.root_configuration.clone()
                };
                // Keep the same root pinned across reservation publication and
                // the existing authenticated configure operation's revalidation.
                let lease = match previous.as_ref().filter(|root| {
                    root.registration_ownership
                        .as_ref()
                        .is_some_and(|owner| owner.state != "prepared_not_registered")
                }) {
                    Some(root) => pin_registered_configured_root(
                        Path::new(path),
                        raiun_cloudfiles_windows::ConfiguredRootIdentity {
                            volume_serial: root.volume_serial,
                            file_index: root.file_index,
                        },
                    ),
                    None => pin_configured_root(Path::new(path)),
                }
                .map_err(root_error_text)?;
                let identity = lease.identity();
                let reservation = RootReservation::new(
                    path.into(),
                    identity.volume_serial,
                    identity.file_index,
                    true,
                )?;
                {
                    let mut state = self
                        .state
                        .lock()
                        .map_err(|_| "Account state is unavailable")?;
                    let next = state.registry.with_reserved_root(&id, reservation)?;
                    validate_separation(&next)?;
                    // Write ahead even if configure later fails. Retaining an
                    // extra exclusion never grants registration/account access.
                    self.persist(&next)?;
                    state.registry = next;
                }
                runtime.handle_request(request)
            }
            "pair_add" | "media_job_set" => {
                if (action == "pair_add" && !WINDOWS_FOLDER_SYNC_ENABLED)
                    || (action == "media_job_set" && !WINDOWS_MEDIA_METADATA_ENABLED)
                {
                    return Err("Cross-account folder and media setup is not enabled yet".into());
                }
                let _gate = self
                    .mutation_gate
                    .lock()
                    .map_err(|_| "Account changes are unavailable")?;
                let (id, runtime) = self.resolve(request)?;
                if matches!(windows_folder_requests::decode(request)?,
                    windows_folder_requests::FolderRequest::Media(
                        windows_media_requests::MediaRequest::Set { job, .. }) if !job.enabled)
                {
                    // The worker alone proves an exact existing-job disable
                    // before skipping its source pin. New/changed disabled jobs
                    // still require a matching durable receipt and live pin.
                    return runtime.handle_request(request);
                }
                let (reservation, pin) = runtime.prepare_source_reservation(request)?;
                {
                    let mut state = self
                        .state
                        .lock()
                        .map_err(|_| "Account state is unavailable")?;
                    let next = state.registry.with_reserved_source(&id, reservation)?;
                    validate_separation(&next)?;
                    // Publish the exclusion/worker receipt durably before the
                    // existing authenticated worker's document CAS or policy.
                    self.persist(&next)?;
                    state.registry = next;
                }
                let result = runtime.handle_request(request);
                pin.verify_path()
                    .map_err(|_| "The source changed; settings and recovery were preserved")?;
                result
            }
            "pair_exclusions_set" => {
                if !WINDOWS_FOLDER_SYNC_ENABLED {
                    return Err("Cross-account folder setup is not enabled yet".into());
                }
                let (_, runtime) = self.resolve(request)?;
                runtime.handle_request(request)
            }
            _ => {
                let (id, runtime) = self.resolve(request)?;
                let (mut response, stop) = runtime.handle_request(request)?;
                if action == "status" {
                    let state = self
                        .state
                        .lock()
                        .map_err(|_| "Account state is unavailable")?;
                    response["profile_label"] = json!(state.registry.profiles()[&id].label());
                    response["account_setup_requires_sign_in"] = json!(true);
                    response["account_switch_supported"] = json!(WINDOWS_ACCOUNTS_ENABLED);
                }
                Ok((response, stop))
            }
        }
    }
}

// Saved engine documents reserve paths only; they cannot restore credentials or
// authorize worker execution. Run before any account runtime is constructed.
fn inventory_saved_source_exclusions(
    storage: &DpapiSessionStore,
    mut registry: Registry,
) -> Result<Registry, String> {
    use raiun_control_windows::{PinnedDirectory, PrivateDirectory};
    use raiun_engine::folder_pairs::SavedSourceExclusions;
    let parent = PinnedDirectory::open(storage.local_edit_state_directory())
        .map_err(|_| "Could not pin saved folder settings")?;
    let profiles = registry.profiles().keys().cloned().collect::<Vec<_>>();
    let known = profiles.iter().map(String::as_str).collect::<Vec<_>>();
    let entries = std::fs::read_dir(storage.local_edit_state_directory())
        .map_err(|_| "Could not inventory saved folder settings")?;
    let mut stores = 0;
    for (index, entry) in entries.enumerate() {
        if index >= 4096 {
            return Err("Saved folder inventory exceeds its entry limit".into());
        }
        let entry = entry.map_err(|_| "Saved folder inventory is unavailable")?;
        let name = entry.file_name();
        let Some(text) = name.to_str() else {
            return Err("Saved folder inventory has an invalid name".into());
        };
        if !text.to_ascii_lowercase().starts_with("folder-sync-") {
            continue;
        }
        let digest = text
            .strip_prefix("folder-sync-")
            .ok_or("Saved folder settings use a noncanonical name")?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("Saved folder settings use a noncanonical name".into());
        }
        stores += 1;
        if stores > 64 {
            return Err("Too many saved folder settings stores".into());
        }
        parent
            .verify_path()
            .map_err(|_| "Saved folder settings changed")?;
        let directory = PrivateDirectory::open_under(&parent, &name)
            .map_err(|_| "Saved folder settings are not private or changed")?;
        let Some((profile, exclusions)) =
            SavedSourceExclusions::read_windows_existing(directory, &known)
                .map_err(|_| "Saved folder settings could not be safely inventoried")?
        else {
            continue;
        };
        for source in exclusions.sources() {
            let pin = PinnedDirectory::open(source.path())
                .map_err(|_| "A saved source is unavailable; its settings were preserved")?;
            let identity = pin.identity();
            let path = source
                .path()
                .to_str()
                .ok_or("Saved source path is invalid")?;
            let kind = match source.kind() {
                raiun_engine::folder_pairs::SavedSourceKind::FolderPair => SourceKind::FolderPair,
                raiun_engine::folder_pairs::SavedSourceKind::MediaJob => SourceKind::MediaJob,
            };
            registry = registry.with_reserved_source(
                &profile,
                SourceReservation::new(
                    exclusions.scope_digest().into(),
                    kind,
                    source.id().into(),
                    RootReservation::new(
                        path.into(),
                        identity.volume_serial,
                        identity.file_index,
                        false,
                    )?,
                )?,
            )?;
            pin.verify_path()
                .map_err(|_| "A saved source changed during inventory")?;
        }
    }
    parent
        .verify_path()
        .map_err(|_| "Saved folder settings changed")?;
    Ok(registry)
}

// A reservation can be a plain directory (including an unpopulated registered
// root) or an exactly OS-registered Cloud Files root. Neither grants account
// authority. Missing/replaced/unreadable roots are never declared disjoint.
enum ReservedPin {
    Plain(raiun_control_windows::PinnedDirectory),
    Registered(raiun_cloudfiles_windows::ConfiguredRootLease),
}
fn pin_reservation(root: &RootReservation) -> Result<ReservedPin, String> {
    if let Ok(pin) = raiun_control_windows::PinnedDirectory::open(Path::new(root.path())) {
        let identity = pin.identity();
        if identity.volume_serial != root.volume_serial()
            || identity.file_index != root.file_index()
        {
            return Err("A reserved account folder changed identity".into());
        }
        return Ok(ReservedPin::Plain(pin));
    }
    if !root.may_be_registered() {
        return Err("A reserved account folder is unavailable".into());
    }
    pin_registered_configured_root(
        Path::new(root.path()),
        raiun_cloudfiles_windows::ConfiguredRootIdentity {
            volume_serial: root.volume_serial(),
            file_index: root.file_index(),
        },
    )
    .map(ReservedPin::Registered)
    .map_err(root_error_text)
}
fn validate_separation(registry: &Registry) -> Result<(), String> {
    let mut roots = Vec::new();
    for (id, profile) in registry.profiles() {
        for (root, source) in profile
            .root_reservations()
            .iter()
            .map(|root| (root, false))
            .chain(
                profile
                    .source_reservations()
                    .iter()
                    .map(|row| (row.root(), true)),
            )
        {
            let pin = pin_reservation(root)?;
            let registered = match &pin {
                ReservedPin::Plain(_) => None,
                ReservedPin::Registered(held) => Some(held.identity()),
            };
            if overlaps_private_state(Path::new(root.path()), registered)? {
                return Err("A reserved account folder overlaps private application data".into());
            }
            roots.push((id, root, pin, source));
        }
    }
    for (index, (left_id, left, left_pin, left_source)) in roots.iter().enumerate() {
        for (right_id, right, right_pin, right_source) in roots.iter().skip(index + 1) {
            // Same-account cloud/source overlap is also forbidden: choosing a
            // drive folder must never register over an existing sync source.
            if left_id == right_id && left_source == right_source {
                continue;
            }
            let left_path = Path::new(left.path());
            let right_path = Path::new(right.path());
            let identity =
                |root: &RootReservation| raiun_cloudfiles_windows::ConfiguredRootIdentity {
                    volume_serial: root.volume_serial(),
                    file_index: root.file_index(),
                };
            let overlap = match (left_pin, right_pin) {
                (ReservedPin::Plain(left_held), ReservedPin::Plain(right_held)) => {
                    left_held
                        .verify_path()
                        .map_err(|_| "Reserved folder changed")?;
                    right_held
                        .verify_path()
                        .map_err(|_| "Reserved folder changed")?;
                    configured_roots_overlap(left_path, right_path)
                }
                (ReservedPin::Registered(left_held), ReservedPin::Plain(right_held)) => {
                    let _ = left_held.identity();
                    right_held
                        .verify_path()
                        .map_err(|_| "Reserved folder changed")?;
                    raiun_cloudfiles_windows::registered_configured_root_overlaps(
                        left_path,
                        identity(left),
                        right_path,
                    )
                }
                (ReservedPin::Plain(left_held), ReservedPin::Registered(right_held)) => {
                    left_held
                        .verify_path()
                        .map_err(|_| "Reserved folder changed")?;
                    let _ = right_held.identity();
                    raiun_cloudfiles_windows::registered_configured_root_overlaps(
                        right_path,
                        identity(right),
                        left_path,
                    )
                }
                (ReservedPin::Registered(left_held), ReservedPin::Registered(right_held)) => {
                    let _ = (left_held.identity(), right_held.identity());
                    raiun_cloudfiles_windows::registered_configured_roots_overlap(
                        left_path,
                        identity(left),
                        right_path,
                        identity(right),
                    )
                }
            }
            .map_err(root_error_text)?;
            if overlap {
                return Err(
                    "Account drive folders overlap; each account needs a separate folder".into(),
                );
            }
        }
    }
    Ok(())
}

/// Claim the pipe and a persistent exact-file ownership lease before registry
/// access. The lease spans pipe gaps and outlives every account shutdown join.
pub(super) fn serve_profiles() -> Result<(), String> {
    let storage =
        DpapiSessionStore::current_user().map_err(|_| "Account storage is unavailable")?;
    let owner = storage.lock_profile_registry().map_err(
        |_| "Another account broker owns this Windows profile, or its lock is unavailable",
    )?;
    // A competing broker must lose the lifetime lock before it can briefly
    // claim a pipe gap and disrupt the current owner's next listener bind.
    let first = NamedPipeListener::bind(Duration::from_millis(500))
        .map_err(|_| "Could not claim the current-user control pipe")?;
    let broker = WindowsProfiles::open(storage)?;
    let result = (|| {
        let mut listener = Some(first);
        loop {
            let owned = match listener.take() {
                Some(owned) => owned,
                None => NamedPipeListener::bind(Duration::from_millis(500))
                    .map_err(|_| "Could not claim the current-user control pipe")?,
            };
            broker.refresh_all()?;
            let mut stream = match owned.accept() {
                Ok(stream) => stream,
                Err(error)
                    if error.kind() == std::io::ErrorKind::TimedOut
                        || disconnected_pipe_client(&error) =>
                {
                    continue;
                }
                Err(_) => return Err("Could not accept an account control request".into()),
            };
            let response = read_json_value(&mut stream).and_then(|request| {
                let request = windows_vault_requests::OwnedControlRequest::new(request);
                broker.handle_owned(request)
            });
            let (body, stop) = match response {
                Ok((body, stop)) => (json!({"ok":true,"data":body}), stop),
                Err(error) => (json!({"ok":false,"error":error}), false),
            };
            let _ = write_json_line(&mut stream, &body);
            if stop {
                break;
            }
        }
        Ok(())
    })();
    let stopped = broker.stop_all();
    if stopped.is_err() {
        // Fail closed until process exit if any runtime could remain alive.
        // Do not hand its registry to another broker after a failed drain.
        std::mem::forget(owner);
    }
    result.and(stopped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_separation_refuses_cross_profile_and_same_account_drive_overlap() {
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).unwrap();
        let nonce = nonce.iter().map(|v| format!("{v:02x}")).collect::<String>();
        let root = std::env::temp_dir().join(format!("raiun-source-separation-{nonce}"));
        std::fs::create_dir(&root).unwrap();
        eprintln!("synthetic_source_separation_fixture={}", root.display());
        let cloud = root.join("drive");
        let source = root.join("photos");
        let child = source.join("child");
        std::fs::create_dir(&cloud).unwrap();
        std::fs::create_dir_all(&child).unwrap();
        let reservation = |path: &Path| {
            let pin = raiun_control_windows::PinnedDirectory::open(path).unwrap();
            let identity = pin.identity();
            RootReservation::new(
                path.to_str().unwrap().into(),
                identity.volume_serial,
                identity.file_index,
                false,
            )
            .unwrap()
        };
        let digest = "a".repeat(64);
        let registry = Registry::decode_or_default(None)
            .unwrap()
            .with_reserved_root("default", reservation(&cloud))
            .unwrap()
            .with_reserved_source(
                "default",
                SourceReservation::new(
                    digest.clone(),
                    SourceKind::MediaJob,
                    "photos".into(),
                    reservation(&source),
                )
                .unwrap(),
            )
            .unwrap();
        assert!(validate_separation(&registry).is_ok());
        let same_account_overlap = registry
            .with_reserved_source(
                "default",
                SourceReservation::new(
                    digest.clone(),
                    SourceKind::FolderPair,
                    "drive-as-source".into(),
                    reservation(&cloud),
                )
                .unwrap(),
            )
            .unwrap();
        assert!(validate_separation(&same_account_overlap).is_err());
        let other = "profile-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let cross_account_overlap = registry
            .with_added(other, "Other")
            .unwrap()
            .with_reserved_source(
                other,
                SourceReservation::new(
                    digest,
                    SourceKind::FolderPair,
                    "nested".into(),
                    reservation(&child),
                )
                .unwrap(),
            )
            .unwrap();
        assert!(validate_separation(&cross_account_overlap).is_err());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    #[ignore = "one-shot NIC-less lab VM; task-qualified ordinary RaiunLabUser; leaves registry evidence"]
    fn fresh_lab_broker_persists_profiles_without_stopping_other_runtimes() {
        assert_eq!(
            std::env::var("USERNAME").as_deref(),
            Ok("RaiunLabUser"),
            "requires dedicated synthetic user"
        );
        // Ordinary-user admission is also required by the operator task. This
        // fixed read-only child checks inherited token membership, no auth/data.
        let token = std::process::Command::new("powershell.exe")
            .env_remove("PSModulePath")
            .args(["-NoProfile", "-NonInteractive", "-Command",
                "$p=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()); if($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){exit 7}; exit 0"])
            .output().expect("qualify ordinary inherited Windows token");
        assert!(
            token.status.success(),
            "requires qualified ordinary-user token"
        );
        let storage = DpapiSessionStore::current_user().expect("open synthetic user's storage");
        let owner = storage
            .lock_profile_registry()
            .expect("own registry before first read");
        assert!(
            storage
                .load_profile_registry()
                .expect("read fresh registry")
                .is_none(),
            "existing registry forbids replay: preserve it, never reset"
        );
        assert!(
            storage
                .active_identity()
                .expect("read fresh active pointer")
                .is_none(),
            "existing active identity forbids this acceptance case"
        );
        let mut default_before = storage
            .load_root_config_inventory("default")
            .expect("capture only root metadata");
        default_before.sort();
        let broker =
            WindowsProfiles::open(storage.clone()).expect("open fresh broker while lease held");
        let a = broker
            .handle(&json!({"action":"account_add","label":"Synthetic A"}))
            .unwrap()
            .0["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let b = broker
            .handle(&json!({"action":"account_add","label":"Synthetic B"}))
            .unwrap()
            .0["id"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_ne!(a, b);
        let runtime_a = broker.resolve(&json!({"profile_id":a})).unwrap().1;
        let runtime_b = broker.resolve(&json!({"profile_id":b})).unwrap().1;
        assert!(!Arc::ptr_eq(&runtime_a, &runtime_b));
        let generation_a = runtime_a
            .generation
            .load(std::sync::atomic::Ordering::Acquire);
        let generation_b = runtime_b
            .generation
            .load(std::sync::atomic::Ordering::Acquire);
        for selected in [&a, &b] {
            broker
                .handle(&json!({"action":"account_select","profile_id":selected}))
                .unwrap();
            assert_eq!(
                runtime_a
                    .generation
                    .load(std::sync::atomic::Ordering::Acquire),
                generation_a
            );
            assert_eq!(
                runtime_b
                    .generation
                    .load(std::sync::atomic::Ordering::Acquire),
                generation_b
            );
            let persisted = Registry::decode_or_default(Some(
                &storage.load_profile_registry().unwrap().unwrap(),
            ))
            .unwrap();
            assert_eq!(persisted.selected(), selected);
            let (resolved, selected_runtime) = broker.resolve(&json!({"action":"status"})).unwrap();
            assert_eq!(&resolved, selected);
            assert!(Arc::ptr_eq(
                &selected_runtime,
                if selected == &a {
                    &runtime_a
                } else {
                    &runtime_b
                }
            ));
            assert!(Arc::ptr_eq(
                &broker.resolve(&json!({"profile_id":a})).unwrap().1,
                &runtime_a
            ));
            assert!(Arc::ptr_eq(
                &broker.resolve(&json!({"profile_id":b})).unwrap().1,
                &runtime_b
            ));
        }
        assert!(broker.handle(&json!({"action":"status","profile_id":"profile-ffffffffffffffffffffffffffffffff"})).is_err());
        assert!(
            runtime_a
                .handle_request(&json!({"action":"status","profile_id":b}))
                .is_err()
        );
        assert!(
            broker
                .handle(&json!({"action":"status","profile_id":17}))
                .is_err()
        );
        broker.stop_all().expect("stop/join every runtime");
        drop(runtime_a);
        drop(runtime_b);
        drop(broker);
        // Keep the SAME owner lease through restart; never release a live
        // broker to another process between durable selection and reopen.
        let reopened = WindowsProfiles::open(storage.clone()).expect("reopen durable broker");
        {
            let state = reopened.state.lock().unwrap();
            assert_eq!(state.registry.selected(), b);
            assert_eq!(state.registry.profiles().len(), 3);
            assert_eq!(state.registry.profiles()[&a].label(), "Synthetic A");
            assert_eq!(state.registry.profiles()[&b].label(), "Synthetic B");
            assert!(state.runtimes.contains_key("default"));
            assert!(state.runtimes.contains_key(&a));
            assert!(state.runtimes.contains_key(&b));
        }
        let mut default_after = storage.load_root_config_inventory("default").unwrap();
        default_after.sort();
        assert!(
            default_before == default_after,
            "default root metadata bytes must remain unchanged"
        );
        assert!(storage.active_identity().unwrap().is_none());
        reopened.stop_all().expect("stop/join reopened runtimes");
        drop(reopened);
        drop(owner);
        // Deliberately no cleanup/reset: new registry and synthetic profiles
        // remain as evidence on success/failure; the absence gate prevents replay.
    }
}
