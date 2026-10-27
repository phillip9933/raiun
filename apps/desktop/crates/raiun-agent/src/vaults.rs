//! Account-scoped vault control. Passwords are never saved in settings or history;
//! optional remembered passwords are kept only in the OS credential store.
use super::*;
use crate::vault_edit_jobs::{CopyVerifyReviewReason, VaultEditFailureClass};
use crate::vault_secrets::{
    RememberedStatus, SecretServiceVaultCredentialStore, VaultCredentialStore,
    begin_credential_operation, record_status, remembered_status,
};
use raiun_cache::{CacheScope, CiphertextPinState, ScopeProtection};
use raiun_opencloud::{
    OpenCloudClient,
    vault::VaultMetadataClient,
    vault_backend::VaultBackend,
    vault_cache::{VaultOfflineCache, VaultPendingOperationKind},
};
use raiun_vault::session::{VaultSessionCoordinator, VaultSessionScope};
use zeroize::{Zeroize, Zeroizing};

fn trace_vault_create_stage(stage: &'static str) {
    #[cfg(debug_assertions)]
    if std::env::var_os("RAIUN_TRACE_VAULT_CREATE").is_some() {
        eprintln!("raiun_vault_create_stage={stage}");
    }
    #[cfg(not(debug_assertions))]
    let _ = stage;
}

impl Runtime {
    fn active_vault_route(
        &self,
        space_id: &str,
        root_resource_id: &str,
    ) -> Result<raiun_fuse::VaultMountRoute, RouteError> {
        let routes = self
            .vault_mounts
            .routes()
            .map_err(|_| RouteError::Unavailable)?;
        let mut matches = routes.into_iter().filter(|route| {
            route.space_id() == space_id
                && route.root_resource_id() == root_resource_id
                && route.control().is_active().unwrap_or(false)
        });
        let route = matches.next().ok_or(RouteError::Unavailable)?;
        if matches.next().is_some() {
            return Err(RouteError::Ambiguous);
        }
        Ok(route)
    }

    fn offline_vault_context(&self) -> Result<(OpenCloudClient, String, u64), String> {
        let generation = self.operation_generation()?;
        if self.auth_transition.load(Ordering::Acquire)
            || self.shutdown.load(Ordering::Acquire)
            || self.retiring.load(Ordering::Acquire)
        {
            return Err("An account transition is in progress".into());
        }
        let settings = self.settings.lock().map_err(|_| "Settings poisoned")?;
        let server = settings
            .server
            .as_deref()
            .ok_or("Sign in to this server at least once before offline vault access")?;
        if settings.account_id.is_none() {
            return Err("The saved server account is unavailable for offline vault access".into());
        }
        let origin = url::Url::parse(server)
            .map_err(|_| "Saved server URL is invalid")?
            .origin()
            .ascii_serialization();
        let client = OpenCloudClient::new(server, "raiun-offline-only".to_owned())
            .map_err(|_| "Saved server URL is invalid")?;
        drop(settings);
        if self.auth_transition.load(Ordering::Acquire)
            || self.shutdown.load(Ordering::Acquire)
            || self.retiring.load(Ordering::Acquire)
            || self.auth_generation.load(Ordering::Acquire) != generation
        {
            return Err("An account transition is in progress".into());
        }
        Ok((client, origin, generation))
    }

    fn vault_context(&self) -> Result<(OpenCloudClient, String, u64), String> {
        let generation = self.operation_generation()?;
        if self.auth_transition.load(Ordering::Acquire)
            || self.shutdown.load(Ordering::Acquire)
            || self.retiring.load(Ordering::Acquire)
        {
            return Err("An account transition is in progress".into());
        }
        let auth = self
            .auth_state
            .lock()
            .map_err(|_| "Authentication state poisoned")?;
        if self.auth_transition.load(Ordering::Acquire)
            || self.shutdown.load(Ordering::Acquire)
            || self.retiring.load(Ordering::Acquire)
            || self.auth_generation.load(Ordering::Acquire) != generation
        {
            return Err("An account transition is in progress".into());
        }
        let session = auth.session.as_ref().ok_or("Sign in first")?;
        let origin = url::Url::parse(&session.server)
            .map_err(|_| "Invalid server")?
            .origin()
            .ascii_serialization();
        Ok((
            auth.client.clone().ok_or("Sign in first")?,
            origin,
            generation,
        ))
    }

    fn vault_scope(
        &self,
        origin: &str,
        space: &str,
        resource: &str,
    ) -> Result<VaultSessionScope, String> {
        VaultSessionScope::new(&self.vault_account_id, origin, space, resource)
            .map_err(|e| e.to_string())
    }

    pub(super) fn configure_vault_mount_routes(
        &self,
        settings: &Settings,
        _account_id: &str,
    ) -> Result<(), String> {
        let (client, origin) = {
            let auth = self
                .auth_state
                .lock()
                .map_err(|_| "Authentication state poisoned")?;
            let session = auth.session.as_ref().ok_or("Sign in first")?;
            let origin = url::Url::parse(&session.server)
                .map_err(|_| "Invalid server")?
                .origin()
                .ascii_serialization();
            (auth.client.clone().ok_or("Sign in first")?, origin)
        };

        for pair in &settings.config.pairs {
            let Some(binding) = pair.vault.as_ref() else {
                continue;
            };
            vault_mount::validate_root_identity(
                &client,
                &pair.space_id,
                &binding.root_path,
                &binding.root_resource_id,
            )
            .map_err(|error| format!("Could not validate configured encrypted folder: {error}"))?;
            let scope = self.vault_scope(&origin, &pair.space_id, &binding.root_resource_id)?;

            let route = match self
                .vault_mounts
                .get(
                    &pair.space_id,
                    &binding.root_path,
                    &binding.root_resource_id,
                )
                .map_err(|error| error.to_string())?
            {
                Some(route) => route,
                None => {
                    let control = raiun_fuse::vault_routes::VaultRouteControl::new();
                    let route = raiun_fuse::VaultMountRoute::new(
                        pair.space_id.clone(),
                        binding.root_path.clone(),
                        binding.root_resource_id.clone(),
                        control,
                    )
                    .map_err(|error| error.to_string())?;
                    match self.vault_mounts.register(route.clone()) {
                        Ok(()) => route,
                        Err(_) => self
                            .vault_mounts
                            .get(
                                &pair.space_id,
                                &binding.root_path,
                                &binding.root_resource_id,
                            )
                            .map_err(|error| error.to_string())?
                            .ok_or("Could not register encrypted folder mount route")?,
                    }
                }
            };

            if self
                .vaults
                .is_unlocked(&scope)
                .map_err(|error| error.to_string())?
                && (!route
                    .control()
                    .is_active()
                    .map_err(|error| error.to_string())?
                    || !route
                        .control()
                        .supports_writes()
                        .map_err(|error| error.to_string())?)
            {
                self.publish_unlocked_mount_route(
                    &client,
                    &origin,
                    &self.vault_account_id,
                    &pair.space_id,
                    &binding.root_path,
                    &binding.root_resource_id,
                )?;
            }
        }
        Ok(())
    }

    fn publish_unlocked_mount_route(
        &self,
        client: &OpenCloudClient,
        origin: &str,
        account_id: &str,
        space_id: &str,
        root_path: &str,
        resource_id: &str,
    ) -> Result<(bool, Option<&'static str>), String> {
        trace_vault_create_stage("route_ensure_start");
        let route = self.ensure_vault_mount_route(space_id, root_path, resource_id)?;
        trace_vault_create_stage("route_ensure_complete");
        let active = route
            .control()
            .is_active()
            .map_err(|error| error.to_string())?;
        if active
            && route
                .control()
                .supports_writes()
                .map_err(|error| error.to_string())?
        {
            return Ok((true, None));
        }
        if active {
            route
                .control()
                .revoke(|| Ok(()))
                .map_err(|error| error.to_string())?;
        }
        let scope = self.vault_scope(origin, space_id, resource_id)?;
        trace_vault_create_stage("writable_backend_start");
        let cache = self.open_vault_cache().ok();
        let writer = match cache {
            Some(cache) => vault_mount::new_cached_writable_backend(
                client.clone(),
                self.vaults.clone(),
                cache,
                scope.clone(),
                root_path,
            ),
            None => vault_mount::new_writable_backend(
                client.clone(),
                self.vaults.clone(),
                account_id,
                origin,
                space_id,
                root_path,
                resource_id,
            ),
        };
        trace_vault_create_stage("writable_backend_complete");
        match writer {
            Ok(backend) => {
                trace_vault_create_stage("writable_route_install_start");
                route
                    .control()
                    .install_writable_backend(backend)
                    .map_err(|error| error.to_string())?;
                trace_vault_create_stage("writable_route_install_complete");
                return Ok((true, None));
            }
            Err(_writer_error) => {
                // Keep verified read-only access when an authenticated route
                // cannot offer writes (for example, a server-side limitation).
            }
        }
        let backend = match self.open_vault_cache() {
            Ok(cache) => vault_mount::new_cached_read_backend(
                client.clone(),
                self.vaults.clone(),
                cache,
                scope,
                root_path,
            ),
            Err(_) => vault_mount::new_read_backend(
                client.clone(),
                self.vaults.clone(),
                account_id,
                origin,
                space_id,
                root_path,
                resource_id,
            ),
        }
        .map_err(|error| error.to_string())?;
        route
            .control()
            .install_backend(backend)
            .map_err(|error| error.to_string())?;
        Ok((false, Some("write_backend_unavailable")))
    }

    /// A successful explicit unlock is sufficient to expose a folder vault in
    /// the mounted drive. Local sync pairs are an independent feature and are
    /// not required for read-only browsing.
    fn ensure_vault_mount_route(
        &self,
        space_id: &str,
        root_path: &str,
        resource_id: &str,
    ) -> Result<raiun_fuse::VaultMountRoute, String> {
        if let Some(route) = self
            .vault_mounts
            .get(space_id, root_path, resource_id)
            .map_err(|error| error.to_string())?
        {
            return Ok(route);
        }

        let route = raiun_fuse::VaultMountRoute::new(
            space_id.to_owned(),
            root_path.to_owned(),
            resource_id.to_owned(),
            raiun_fuse::vault_routes::VaultRouteControl::new(),
        )
        .map_err(|error| error.to_string())?;
        match self.vault_mounts.register(route.clone()) {
            Ok(()) => Ok(route),
            Err(register_error) => self
                .vault_mounts
                .get(space_id, root_path, resource_id)
                .map_err(|error| error.to_string())?
                .ok_or_else(|| register_error.to_string()),
        }
    }

    fn vault_mount_ready(
        &self,
        space_id: &str,
        root_path: &str,
        resource_id: &str,
    ) -> Result<bool, String> {
        let Some(route) = self
            .vault_mounts
            .get(space_id, root_path, resource_id)
            .map_err(|error| error.to_string())?
        else {
            return Ok(false);
        };
        route
            .control()
            .is_active()
            .map_err(|error| error.to_string())
    }

    fn vault_mount_writable(
        &self,
        space_id: &str,
        root_path: &str,
        resource_id: &str,
    ) -> Result<(bool, Option<&'static str>), String> {
        let Some(route) = self
            .vault_mounts
            .get(space_id, root_path, resource_id)
            .map_err(|error| error.to_string())?
        else {
            return Ok((false, Some("route_not_installed")));
        };
        if !route
            .control()
            .supports_writes()
            .map_err(|error| error.to_string())?
        {
            return Ok((false, Some("route_read_only")));
        }
        // The spool follows the authenticated server account (the engine
        // account identity), while `vault_account_id` is the local profile
        // scope used for key isolation. They are intentionally different.
        let spool_dir = self.vault_write_spool_dir()?;
        let mounted = self
            .mount
            .lock()
            .map_err(|_| "Mount state poisoned")?
            .as_ref()
            .is_some_and(|handle| handle.is_mounted());
        if !mounted {
            return Ok((false, Some("drive_not_mounted")));
        }
        let spool_ready = raiun_fuse::vault_write::VaultWriteSpool::open_existing(&spool_dir)
            .ok()
            .flatten()
            .is_some();
        if !spool_ready {
            return Ok((false, Some("private_spool_unavailable")));
        }
        Ok((true, None))
    }

    fn vault_mount_existing_file_overwrite_status(
        &self,
        space_id: &str,
        root_path: &str,
        resource_id: &str,
    ) -> Result<(bool, Option<&'static str>), String> {
        let Some(route) = self
            .vault_mounts
            .get(space_id, root_path, resource_id)
            .map_err(|error| error.to_string())?
        else {
            return Ok((false, Some("route_not_installed")));
        };
        if !route
            .control()
            .supports_existing_file_overwrites()
            .map_err(|error| error.to_string())?
        {
            return Ok((false, Some("route_read_only")));
        }
        let spool_dir = self.vault_write_spool_dir()?;
        let mounted = self
            .mount
            .lock()
            .map_err(|_| "Mount state poisoned")?
            .as_ref()
            .is_some_and(|handle| handle.is_mounted());
        if !mounted {
            return Ok((false, Some("drive_not_mounted")));
        }
        let spool_ready = raiun_fuse::vault_write::VaultWriteSpool::open_existing(&spool_dir)
            .ok()
            .flatten()
            .is_some();
        Ok(if spool_ready {
            (true, None)
        } else {
            (false, Some("private_spool_unavailable"))
        })
    }

    fn vault_write_spool_dir(&self) -> Result<std::path::PathBuf, String> {
        let account_id = self
            .settings
            .lock()
            .map_err(|_| "Settings poisoned")?
            .account_id
            .clone()
            .ok_or("Authenticated account identity is unavailable")?;
        Ok(account_spool_dir(&self.dir, &account_id))
    }

    fn open_vault_cache(&self) -> Result<raiun_cache::Cache, String> {
        let account_id = self
            .settings
            .lock()
            .map_err(|_| "Settings poisoned")?
            .account_id
            .clone()
            .ok_or("Authenticated account identity is unavailable")?;
        let engine_dir = account_engine_dir(&self.dir, &account_id);
        let cache_dir = super::offline_cache_state_dir(&engine_dir)
            .map_err(|_| "Encrypted offline cache is unavailable")?;
        raiun_cache::Cache::open(&cache_dir, offline_cache::DEFAULT_CACHE_QUOTA_BYTES)
            .map_err(|_| "Encrypted offline cache is unavailable".into())
    }

    /// Queue background refreshes for pins belonging to currently active,
    /// unlocked routes. This only constructs local adapters while holding the
    /// gate; the actual remote traversal runs in the bounded pin worker.
    pub(super) fn refresh_due_vault_pins(&self, generation: u64) {
        let Ok(_sync) = self.sync_gate.lock() else {
            return;
        };
        if self.check_vault_generation(generation).is_err() {
            return;
        }
        let (client, origin) = {
            let Ok(auth) = self.auth_state.lock() else {
                return;
            };
            let Some(session) = auth.session.as_ref() else {
                return;
            };
            let Ok(server) = url::Url::parse(&session.server) else {
                return;
            };
            let Some(client) = auth.client.clone() else {
                return;
            };
            (client, server.origin().ascii_serialization())
        };
        let Ok(cache) = self.open_vault_cache() else {
            return;
        };
        let Ok(routes) = self.vault_mounts.routes() else {
            return;
        };
        for route in routes {
            if self.check_vault_generation(generation).is_err()
                || !route.control().is_active().unwrap_or(false)
            {
                continue;
            }
            let Ok(scope) = self.vault_scope(&origin, route.space_id(), route.root_resource_id())
            else {
                continue;
            };
            if !self.vaults.is_unlocked(&scope).unwrap_or(false) {
                continue;
            }
            let Ok(offline_cache) =
                VaultOfflineCache::new(cache.clone(), scope.clone(), route.root_path())
            else {
                continue;
            };
            let Ok(pins) = offline_cache.pins(None, 100) else {
                continue;
            };
            for pin in pins.items {
                if !matches!(
                    pin.state,
                    CiphertextPinState::Ready | CiphertextPinState::Stale
                ) {
                    continue;
                }
                if self.check_vault_generation(generation).is_err()
                    || !self.vaults.is_unlocked(&scope).unwrap_or(false)
                {
                    break;
                }
                let Ok(offline_cache) =
                    VaultOfflineCache::new(cache.clone(), scope.clone(), route.root_path())
                else {
                    continue;
                };
                let Ok(backend) = VaultBackend::new_with_offline_cache(
                    client.clone(),
                    self.vaults.clone(),
                    scope.clone(),
                    route.root_path().to_owned(),
                    offline_cache,
                ) else {
                    continue;
                };
                let _ = crate::vault_pin_jobs::VaultPinJobs::start_auto_refresh(
                    &self.vault_pin_jobs,
                    &scope,
                    backend,
                    pin.id,
                    Arc::clone(&self.auth_generation),
                    generation,
                );
            }
        }
    }

    /// Retry a bounded page of durable encrypted edits after an authenticated
    /// scheduler cycle. This only considers routes that are already unlocked
    /// in memory; it never restores credentials or unlocks a vault.
    pub(super) fn retry_due_vault_edits(&self, generation: u64) {
        if self.check_vault_generation(generation).is_err() {
            return;
        }
        let settings = match self.settings.lock().map(|settings| settings.clone()) {
            Ok(settings) if !settings.paused => settings,
            _ => return,
        };
        let (client, origin) = {
            let Ok(auth) = self.auth_state.lock() else {
                return;
            };
            let Some(session) = auth.session.as_ref() else {
                return;
            };
            let Ok(server) = url::Url::parse(&session.server) else {
                return;
            };
            let Some(client) = auth.client.clone() else {
                return;
            };
            (client, server.origin().ascii_serialization())
        };
        let Ok(cache) = self.open_vault_cache() else {
            return;
        };
        let Ok(routes) = self.vault_mounts.routes() else {
            return;
        };
        for route in routes {
            if self.check_vault_generation(generation).is_err()
                || settings
                    .paused_space_ids
                    .iter()
                    .any(|space| space == route.space_id())
                || !route.control().is_active().unwrap_or(false)
            {
                continue;
            }
            let Ok(scope) = self.vault_scope(&origin, route.space_id(), route.root_resource_id())
            else {
                continue;
            };
            if !self
                .vault_edit_reconcile_jobs
                .automatic_due(&scope)
                .unwrap_or(false)
            {
                continue;
            }
            if !self.vaults.is_unlocked(&scope).unwrap_or(false) {
                continue;
            }
            let Ok(journal) =
                VaultOfflineCache::new(cache.clone(), scope.clone(), route.root_path())
            else {
                continue;
            };
            if !journal.has_retryable_pending_edits().unwrap_or(false) {
                continue;
            }
            // The bounded worker revalidates the exact root/token before any
            // conditional mutation. Avoid a scheduler-thread network request.
            if self.check_vault_generation(generation).is_err()
                || !self.vaults.is_unlocked(&scope).unwrap_or(false)
            {
                continue;
            }
            let Ok(offline_cache) =
                VaultOfflineCache::new(cache.clone(), scope.clone(), route.root_path())
            else {
                continue;
            };
            let Ok(backend) = VaultBackend::new_with_offline_cache(
                client.clone(),
                self.vaults.clone(),
                scope.clone(),
                route.root_path().to_owned(),
                offline_cache,
            ) else {
                continue;
            };
            let Ok(_sync) = self.sync_gate.lock() else {
                return;
            };
            if self.check_vault_generation(generation).is_err()
                || !route.control().is_active().unwrap_or(false)
                || !self.vaults.is_unlocked(&scope).unwrap_or(false)
                || self
                    .settings
                    .lock()
                    .map(|settings| {
                        settings.paused
                            || settings
                                .paused_space_ids
                                .iter()
                                .any(|space| space == route.space_id())
                    })
                    .unwrap_or(true)
            {
                continue;
            }
            let _ = self.start_vault_edit_reconcile_job(scope, generation, true, journal, backend);
            drop(_sync);
        }
    }

    fn start_vault_edit_reconcile_job(
        &self,
        scope: VaultSessionScope,
        generation: u64,
        automatic: bool,
        journal: VaultOfflineCache,
        backend: VaultBackend,
    ) -> Result<crate::vault_edit_jobs::VaultEditReconcileStatus, String> {
        let sessions = Arc::clone(&self.vaults);
        let pin_jobs = Arc::clone(&self.vault_pin_jobs);
        let auth_generation = Arc::clone(&self.auth_generation);
        let worker_auth_generation = Arc::clone(&auth_generation);
        crate::vault_edit_jobs::VaultEditReconcileJobs::start_with_failure_class(
            &self.vault_edit_reconcile_jobs,
            &scope,
            auth_generation,
            generation,
            pin_jobs,
            automatic,
            move |cancelled, progress| {
                let report = crate::vault_edit_jobs::reconcile_dependency_batches(
                    cancelled,
                    &worker_auth_generation,
                    generation,
                    crate::vault_edit_jobs::maximum_batch(),
                    |limit| {
                        let (retryable, _truncated) = journal
                            .retryable_pending_edits(&sessions, limit)
                            .map_err(|_| {
                                "Saved encrypted edits could not be read safely".to_owned()
                            })?;
                        Ok(retryable)
                    },
                    |edit| {
                        let result = match edit.operation {
                            raiun_opencloud::vault_cache::VaultPendingOperationKind::DeleteFile => {
                                backend.reconcile_pending_delete(&edit.id, edit.revision)
                            }
                            raiun_opencloud::vault_cache::VaultPendingOperationKind::CreateDirectory => {
                                backend
                                    .reconcile_pending_directory_create(&edit.id, edit.revision)
                                    .map(|_| ())
                            }
                            _ => backend
                                .reconcile_pending_operation(&edit.id, edit.revision)
                                .map(|_| ()),
                        };
                        result.map(|_| ()).map_err(|error| {
                            if error.kind == raiun_core::backend::ErrorKind::Conflict {
                                crate::vault_edit_jobs::ReconcileFailure::Conflict
                            } else {
                                let failure_class =
                                    crate::vault_edit_jobs::reconcile_failure_class(error.kind);
                                crate::vault_edit_jobs::ReconcileFailure::Stop(failure_class)
                            }
                        })
                    },
                    || {
                        let (rows, more) = journal
                            .pending_edits(&sessions, None, crate::vault_edit_jobs::maximum_batch())
                            .map_err(|_| {
                                "Saved encrypted edits remain, but their status is unavailable"
                                    .to_owned()
                            })?;
                        Ok(rows.len() as u64 + u64::from(more))
                    },
                    progress,
                )?;
                Self::retire_completed_directory_receipts(&journal, &sessions)
                    .map_err(crate::vault_edit_jobs::VaultEditJobFailure::unclassified)?;
                Ok(report)
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn start_interrupted_file_create_retry_job(
        &self,
        scope: VaultSessionScope,
        generation: u64,
        write_id: String,
        revision: u64,
        retry_generation: u64,
        expected_retry_state: raiun_cache::CiphertextWriteState,
        backend: VaultBackend,
    ) -> Result<crate::vault_edit_jobs::VaultEditReconcileStatus, String> {
        let pin_jobs = Arc::clone(&self.vault_pin_jobs);
        let auth_generation = Arc::clone(&self.auth_generation);
        let worker_auth_generation = Arc::clone(&auth_generation);
        crate::vault_edit_jobs::VaultEditReconcileJobs::start_operation_with_failure_class(
            &self.vault_edit_reconcile_jobs,
            &scope,
            auth_generation,
            generation,
            pin_jobs,
            crate::vault_edit_jobs::VaultEditOperationBinding {
                operation: "create_file".into(),
                write_id: write_id.clone(),
                revision,
                retry_generation: Some(retry_generation),
            },
            move |cancelled, progress| {
                if cancelled.load(Ordering::Acquire)
                    || worker_auth_generation.load(Ordering::Acquire) != generation
                {
                    return Err(crate::vault_edit_jobs::VaultEditJobFailure::unclassified(
                        "Interrupted file retry was canceled by an account change",
                    ));
                }
                progress(0, 0, 0, 1);
                let result = backend.retry_interrupted_file_create(
                    &write_id,
                    revision,
                    expected_retry_state,
                    retry_generation,
                );
                match result {
                    Ok(_verified_entry) => {
                        progress(1, 1, 0, 0);
                        Ok(crate::vault_edit_jobs::VaultEditReconcileReport {
                            processed: 1,
                            uploaded: 1,
                            conflicts: 0,
                            remaining: 0,
                        })
                    }
                    Err(error) if error.kind == raiun_core::backend::ErrorKind::Conflict => {
                        progress(1, 0, 1, 1);
                        Ok(crate::vault_edit_jobs::VaultEditReconcileReport {
                            processed: 1,
                            uploaded: 0,
                            conflicts: 1,
                            remaining: 1,
                        })
                    }
                    Err(error) => {
                        match crate::vault_edit_jobs::interrupted_create_failure_class(error.kind) {
                            Some(failure_class) => {
                                Err(crate::vault_edit_jobs::VaultEditJobFailure::classified(
                                    "The connection was lost before the server could confirm this create. Its local copy remains saved.",
                                    failure_class,
                                ))
                            }
                            None => Err(crate::vault_edit_jobs::VaultEditJobFailure::unclassified(
                                "The interrupted file creation could not be confirmed. Its local copy remains saved.",
                            )),
                        }
                    }
                }
            },
        )
    }

    /// Retire verified parent receipts only after their direct dependents have
    /// disappeared from the encrypted journal. The cache performs the dependent
    /// check and deletion atomically; repeated passes release completed ancestors
    /// after their child-directory receipts become unreferenced.
    fn retire_completed_directory_receipts(
        journal: &VaultOfflineCache,
        sessions: &VaultSessionCoordinator,
    ) -> Result<(), String> {
        const MAX_PASSES: usize = 32;
        const MAX_ROWS: usize = 1_024;
        for _ in 0..MAX_PASSES {
            let mut after: Option<String> = None;
            let mut scanned = 0_usize;
            let mut retired_any = false;
            loop {
                if scanned >= MAX_ROWS {
                    break;
                }
                let (rows, more) = journal
                    .pending_edits(sessions, after.as_deref(), 100)
                    .map_err(|_| {
                        "Saved encrypted edit receipts could not be read safely".to_owned()
                    })?;
                if rows.is_empty() {
                    break;
                }
                scanned += rows.len();
                after = rows.last().map(|row| row.id.clone());
                for row in rows {
                    if row.operation != VaultPendingOperationKind::CreateDirectory
                        || row.state != raiun_cache::CiphertextWriteState::CommittedReceipt
                    {
                        continue;
                    }
                    match journal.retire_directory_receipt_if_unreferenced(
                        sessions,
                        &row.id,
                        row.receipt_for_revision,
                    ) {
                        Ok(()) => retired_any = true,
                        Err(error) if error.kind == raiun_core::backend::ErrorKind::Conflict => {}
                        Err(_) => {
                            return Err(
                                "A verified encrypted directory receipt could not be retained safely"
                                    .to_owned(),
                            );
                        }
                    }
                }
                if !more {
                    break;
                }
            }
            if !retired_any {
                break;
            }
        }
        Ok(())
    }

    fn revoke_vault_route_and_lock(&self, scope: &VaultSessionScope) -> Result<(), String> {
        self.vault_edit_reconcile_jobs
            .cancel_scope_and_wait(scope)?;
        self.vault_pin_jobs.cancel_scope_and_wait(scope)?;
        let routes = match self.routes_for_scope(scope) {
            Ok(routes) => routes,
            Err(error) => {
                let _ = self.vaults.lock(scope);
                return Err(error);
            }
        };
        if routes.is_empty() {
            self.vaults.lock(scope).map_err(|error| error.to_string())?;
            return Ok(());
        }

        let mut first_error = None;
        for route in routes {
            if let Err(error) = route.control().revoke(|| {
                self.vaults.lock(scope).map_err(|error| {
                    raiun_core::backend::CloudError::new(
                        raiun_core::backend::ErrorKind::Io,
                        error.to_string(),
                    )
                })
            }) {
                first_error.get_or_insert_with(|| error.to_string());
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    fn routes_for_scope(
        &self,
        scope: &VaultSessionScope,
    ) -> Result<Vec<raiun_fuse::VaultMountRoute>, String> {
        self.vault_mounts
            .routes()
            .map_err(|error| error.to_string())
            .map(|routes| {
                routes
                    .into_iter()
                    .filter(|route| {
                        route.space_id() == scope.space_id()
                            && route.root_resource_id() == scope.resource_id()
                    })
                    .collect()
            })
    }

    pub(super) fn revoke_all_vault_mount_routes(&self) -> Result<(), String> {
        let routes = self
            .vault_mounts
            .routes()
            .map_err(|error| error.to_string())?;
        let mut first_error = None;
        for route in routes {
            if let Err(error) = route.control().revoke(|| Ok(())) {
                first_error.get_or_insert_with(|| error.to_string());
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    pub(super) fn engine_for_pair(&self, pair: &FolderPair) -> Result<Engine, String> {
        let generation = self.operation_generation()?;
        let Some(binding) = &pair.vault else {
            return self.engine();
        };
        let (engine, client, origin) = {
            let auth = self
                .auth_state
                .lock()
                .map_err(|_| "Authentication state poisoned")?;
            if self.auth_transition.load(Ordering::Acquire)
                || self.shutdown.load(Ordering::Acquire)
                || self.retiring.load(Ordering::Acquire)
            {
                return Err("An account transition is in progress".into());
            }
            let session = auth.session.as_ref().ok_or("Sign in first")?;
            let origin = url::Url::parse(&session.server)
                .map_err(|_| "Invalid server")?
                .origin()
                .ascii_serialization();
            (
                auth.engine.clone().ok_or("Sign in first")?,
                auth.client.clone().ok_or("Sign in first")?,
                origin,
            )
        };
        let scope = self.vault_scope(&origin, &pair.space_id, &binding.root_resource_id)?;
        if !self.vaults.is_unlocked(&scope).map_err(|e| e.to_string())? {
            return Err(
                "Encrypted folder is locked. Unlock it in Sync folders to resume syncing.".into(),
            );
        }
        let backend = VaultBackend::new(
            client,
            self.vaults.clone(),
            scope,
            binding.root_path.clone(),
        )
        .map_err(|e| e.to_string())?;
        self.check_vault_generation(generation)?;
        Ok(engine.with_vault_backend(pair.space_id.clone(), binding.clone(), Arc::new(backend)))
    }

    pub(super) fn handle_vault(
        &self,
        request: Value,
        password: Option<Zeroizing<String>>,
    ) -> Result<Value, String> {
        if self.retiring.load(Ordering::Acquire) {
            return Err("This account is being removed or has been removed".into());
        }
        self.handle_vault_with_store(
            request,
            password,
            &SecretServiceVaultCredentialStore::for_state_dir(&self.dir),
        )
    }

    fn handle_vault_with_store(
        &self,
        request: Value,
        mut password: Option<Zeroizing<String>>,
        credential_store: &dyn VaultCredentialStore,
    ) -> Result<Value, String> {
        let text = |key: &str| {
            request
                .get(key)
                .and_then(Value::as_str)
                .ok_or_else(|| format!("Missing {key}"))
        };
        let action = text("action")?;
        let unlocked_roots_action = action == "vault_unlocked_roots";
        let space = if action == "vault_cached_roots" || unlocked_roots_action {
            ""
        } else {
            text("space_id")?
        };

        let offline_list =
            action == "vault_list" && request.get("offline").and_then(Value::as_bool) == Some(true);
        let offline_action = matches!(
            action,
            "vault_cached_roots"
                | "vault_unlocked_roots"
                | "vault_unlock_offline"
                | "vault_lock"
                | "vault_pin_status"
                | "vault_pin_cancel"
                | "vault_reconcile_edits_status"
                | "vault_reconcile_edits_cancel"
                | "vault_reconcile_edits_latest"
                | "vault_operations"
                | "vault_copy_verify_status"
                | "vault_copy_verify_cancel"
                | "vault_copy_status"
                | "vault_copy_cancel"
                | "vault_pins"
                | "vault_pin_remove"
        ) || offline_list;
        let (client, origin, generation) = if offline_action {
            self.offline_vault_context()?
        } else {
            self.vault_context()?
        };
        // Release auth before taking the sync gate, which logout acquires before
        // settings/auth. Holding this gate makes lock wait for an active pair's
        // conditional transfer.
        let _sync = self.sync_gate.lock().map_err(|_| "Sync state poisoned")?;
        self.check_vault_generation(generation)?;
        if unlocked_roots_action {
            const MAX_UNLOCKED_ROOTS: usize = 100;
            let mut roots = std::collections::BTreeSet::new();
            for route in self
                .vault_mounts
                .routes()
                .map_err(|_| "Encrypted vault routes are unavailable")?
            {
                if !route.control().is_active().unwrap_or(false) {
                    continue;
                }
                let Ok(scope) =
                    self.vault_scope(&origin, route.space_id(), route.root_resource_id())
                else {
                    continue;
                };
                if self.vaults.is_unlocked(&scope).unwrap_or(false) {
                    roots.insert((
                        route.space_id().to_owned(),
                        route.root_resource_id().to_owned(),
                    ));
                }
            }
            self.check_vault_generation(generation)?;
            let truncated = roots.len() > MAX_UNLOCKED_ROOTS;
            let roots = roots
                .into_iter()
                .take(MAX_UNLOCKED_ROOTS)
                .map(|(space_id, root_resource_id)| {
                    json!({"space_id":space_id,"root_resource_id":root_resource_id})
                })
                .collect::<Vec<_>>();
            return Ok(json!({"roots":roots,"truncated":truncated}));
        }
        if action == "vault_operations" {
            const DEFAULT_LIMIT: usize = 50;
            const MAX_LIMIT: usize = 100;
            let root_resource_id = text("root_resource_id")?;
            let after = request
                .get("after")
                .map(|value| value.as_str().ok_or("after must be a string"))
                .transpose()?;
            if after.is_some_and(|cursor| {
                cursor.len() != 32
                    || !cursor
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            }) {
                return Err("Encrypted operation cursor is invalid".into());
            }
            let requested_limit = request
                .get("limit")
                .map(|value| value.as_u64().ok_or("limit must be a positive integer"))
                .transpose()?
                .unwrap_or(DEFAULT_LIMIT as u64);
            let limit = usize::try_from(requested_limit)
                .ok()
                .filter(|value| (1..=MAX_LIMIT).contains(value))
                .ok_or("limit must be between 1 and 100")?;

            let mut matching_routes = self
                .vault_mounts
                .routes()
                .map_err(|_| "Encrypted vault routes are unavailable")?
                .into_iter()
                .filter(|route| {
                    route.space_id() == space
                        && route.root_resource_id() == root_resource_id
                        && route.control().is_active().unwrap_or(false)
                });
            let route = matching_routes
                .next()
                .ok_or("Encrypted vault route is unavailable")?;
            if matching_routes.next().is_some() {
                return Err("Encrypted vault route is ambiguous".into());
            }
            let scope = self.vault_scope(&origin, space, root_resource_id)?;
            if !self
                .vaults
                .is_unlocked(&scope)
                .map_err(|_| "Encrypted vault is locked")?
            {
                return Err("Unlock this encrypted vault before viewing saved operations".into());
            }

            let cache = self.open_vault_cache()?;
            let journal = VaultOfflineCache::new(cache, scope.clone(), route.root_path())
                .map_err(|_| "Encrypted operation journal is unavailable")?;
            // Directory receipts are internal dependency records. Skip them
            // without making users page through them, but bound how many
            // authenticated metadata headers one IPC request can inspect.
            const MAX_SCAN_ROWS: usize = 500;
            let mut operations = Vec::with_capacity(limit);
            let mut cursor = after.map(str::to_owned);
            let mut scanned = 0usize;
            let mut has_more = false;
            while scanned < MAX_SCAN_ROWS && operations.len() < limit {
                let page_limit = (MAX_SCAN_ROWS - scanned).min(100);
                let (page, page_has_more) = journal
                    .pending_edits(&self.vaults, cursor.as_deref(), page_limit)
                    .map_err(|_| "Encrypted operation metadata could not be authenticated")?;
                if page.is_empty() {
                    has_more = false;
                    break;
                }
                let page_len = page.len();
                let mut reached_item_limit = false;
                for (index, operation) in page.into_iter().enumerate() {
                    scanned += 1;
                    cursor = Some(operation.id.clone());
                    if is_internal_vault_receipt(operation.operation, operation.state) {
                        continue;
                    }
                    operations.push(operation);
                    if operations.len() == limit {
                        has_more = index + 1 < page_len || page_has_more;
                        reached_item_limit = true;
                        break;
                    }
                }
                if reached_item_limit {
                    break;
                }
                if !page_has_more {
                    has_more = false;
                    break;
                }
                has_more = true;
            }
            if scanned >= MAX_SCAN_ROWS && operations.len() < limit {
                has_more = true;
            }

            // Lock/account transitions are serialized by the sync gate above;
            // recheck the exact route/session before publishing decoded names.
            self.check_vault_generation(generation)?;
            if !route.control().is_active().unwrap_or(false)
                || !self.vaults.is_unlocked(&scope).unwrap_or(false)
            {
                return Err("Encrypted vault was locked while reading operation status".into());
            }
            // The cursor follows the last authenticated row scanned, not just
            // the last visible operation. Otherwise a run of internal
            // CommittedReceipt rows after a visible item would be rescanned on
            // every page and could starve later user operations.
            let next_after = has_more.then_some(cursor).flatten();
            let latest_edit_job = crate::vault_edit_jobs::VaultEditReconcileJobs::latest(
                &self.vault_edit_reconcile_jobs,
                &scope,
                generation,
            )
            .map_err(|_| "Encrypted edit job status is unavailable")?;
            let items = operations
                .into_iter()
                .map(|operation| {
                    let retry_job_active = latest_edit_job
                        .as_ref()
                        .is_some_and(|job| {
                            vault_retry_job_matches_operation(
                                &job.state,
                                job.operation.as_deref(),
                                job.write_id.as_deref(),
                                job.operation_revision,
                                job.retry_generation,
                                &operation.id,
                                operation.revision,
                                operation.retry_generation,
                            )
                        });
                    let (
                        needs_attention,
                        attention_reason,
                        retry_state,
                        can_retry_interrupted_create,
                    ) = vault_pending_operation_status_fields(
                        operation.operation,
                        operation.state,
                        retry_job_active,
                    );
                    json!({
                        "write_id":operation.id,
                        "revision":operation.revision,
                        "retry_generation":operation.retry_generation,
                        "operation":vault_pending_operation_name(operation.operation),
                        "state":vault_pending_operation_state_name(operation.state),
                        "needs_attention":needs_attention,
                        "attention_reason":attention_reason,
                        "retry_state":retry_state,
                        "can_retry_interrupted_create":can_retry_interrupted_create,
                        "path":operation.path,
                        "destination_path":if operation.destination_path.is_empty() { None } else { Some(operation.destination_path) },
                        "bytes":operation.plaintext_len,
                    })
                })
                .collect::<Vec<_>>();
            return Ok(json!({
                "space_id":space,
                "root_resource_id":root_resource_id,
                "auth_generation":generation,
                "items":items,
                "next_after":next_after,
                "truncated":has_more,
            }));
        }
        if action == "vault_copy_start" {
            let expected_generation = request
                .get("expected_generation")
                .and_then(Value::as_u64)
                .ok_or("expected_generation must be a nonnegative integer")?;
            let reject = |error| json!({"accepted":false,"error":error});
            if expected_generation != generation
                || self.auth_transition.load(Ordering::Acquire)
                || self.shutdown.load(Ordering::Acquire)
                || self.retiring.load(Ordering::Acquire)
            {
                return Ok(reject("stale_generation"));
            }
            if self.offline_namespace.load(Ordering::Acquire) {
                return Ok(reject("offline"));
            }
            let destination_scope = self.vault_scope(&origin, space, text("root_resource_id")?)?;
            let source_space = text("source_space_id")?;
            let source_scope =
                self.vault_scope(&origin, source_space, text("source_root_resource_id")?)?;
            if source_scope == destination_scope {
                return Ok(reject("scope_changed"));
            }
            if !self.vaults.is_unlocked(&source_scope).unwrap_or(false)
                || !self.vaults.is_unlocked(&destination_scope).unwrap_or(false)
            {
                return Ok(reject("locked"));
            }
            let source_route =
                match self.active_vault_route(source_space, source_scope.resource_id()) {
                    Ok(route) => route,
                    Err(_) => return Ok(reject("scope_changed")),
                };
            let destination_route =
                match self.active_vault_route(space, destination_scope.resource_id()) {
                    Ok(route) => route,
                    Err(_) => return Ok(reject("scope_changed")),
                };
            // Resource identities and versions are expectations, never inferred
            // from a caller's path. The backend verifies them before copying.
            let copy_request = raiun_opencloud::vault_backend::VaultCopyRequest {
                source_scope: source_scope.clone(),
                destination_scope: destination_scope.clone(),
                source_path: text("source_path")?.to_owned(),
                source_resource_id: text("source_resource_id")?.to_owned(),
                source_etag: text("source_etag")?.to_owned(),
                destination_path: text("destination_path")?.to_owned(),
                destination_parent_resource_id: text("destination_parent_resource_id")?.to_owned(),
                destination_parent_etag: text("destination_parent_etag")?.to_owned(),
                source_auth_generation: client.token_generation(),
                destination_auth_generation: client.token_generation(),
            };
            let cache = self.open_vault_cache()?;
            let sessions = Arc::clone(&self.vaults);
            let source_path = source_route.root_path().to_owned();
            let destination_path = destination_route.root_path().to_owned();
            let worker_generation = Arc::clone(&self.auth_generation);
            let worker_transition = Arc::clone(&self.auth_transition);
            let worker_shutdown = Arc::clone(&self.shutdown);
            let worker_source = source_scope.clone();
            let worker_destination = destination_scope.clone();
            let (release, start_gate) = std::sync::mpsc::channel();
            self.check_vault_generation(generation)?;
            // Admit under the runtime gate so a lock/logout cannot miss this
            // job. Its worker waits before serialization or backend work until
            // the gate is dropped; releasing it never needs the runtime gate.
            let job = crate::vault_edit_jobs::VaultEditReconcileJobs::start_copy_producer(
                &self.vault_edit_reconcile_jobs,
                crate::vault_edit_jobs::CopyProducerJobSpec {
                    destination: &destination_scope,
                    source: &source_scope,
                    auth_generation: Arc::clone(&self.auth_generation),
                    expected_generation: generation,
                    pin_jobs: Arc::clone(&self.vault_pin_jobs),
                    start_gate,
                },
                move |cancelled, progress, publish_binding| {
                    let invalidated = || {
                        cancelled.load(Ordering::Acquire)
                            || worker_generation.load(Ordering::Acquire) != generation
                            || worker_transition.load(Ordering::Acquire)
                            || worker_shutdown.load(Ordering::Acquire)
                    };
                    let unavailable = || {
                        crate::vault_edit_jobs::VaultEditJobFailure::unclassified(
                            "copy did not complete",
                        )
                    };
                    if invalidated() {
                        return Err(unavailable());
                    }
                    let backend = |scope: VaultSessionScope, path: String| {
                        let journal = VaultOfflineCache::new(cache.clone(), scope.clone(), &path)
                            .map_err(|_| unavailable())?;
                        VaultBackend::new_for_copy_verification(
                            client.clone(),
                            Arc::clone(&sessions),
                            scope,
                            path,
                            journal,
                        )
                        .map_err(|_| unavailable())
                    };
                    let source = backend(worker_source, source_path)?;
                    let destination = backend(worker_destination, destination_path)?;
                    progress(0, 0, 0, 1);
                    let mut publication_error = None;
                    let outcome = source.copy_file_to_cancellable_with_binding(
                        &destination,
                        &copy_request,
                        &invalidated,
                        |id, revision| {
                            if let Err(error) = publish_binding(id, revision) {
                                publication_error = Some(error);
                                // A durable row already exists. Stop before
                                // attempt admission if status publication fails.
                                cancelled.store(true, Ordering::Release);
                            }
                        },
                    );
                    if let Some(error) = publication_error {
                        return Err(error);
                    }
                    match outcome {
                        Ok(raiun_opencloud::vault_backend::VaultCopyOutcome::Copied { .. }) => {
                            progress(1, 1, 0, 0);
                            Ok(crate::vault_edit_jobs::VaultEditReconcileReport {
                                processed: 1,
                                uploaded: 1,
                                conflicts: 0,
                                remaining: 0,
                            })
                        }
                        Ok(
                            raiun_opencloud::vault_backend::VaultCopyOutcome::NeedsReconciliation {
                                ..
                            },
                        ) => {
                            progress(1, 0, 0, 1);
                            Err(crate::vault_edit_jobs::VaultEditJobFailure::classified(
                                "copy requires review",
                                VaultEditFailureClass::CopyNeedsReview(
                                    CopyVerifyReviewReason::VerificationUnavailable,
                                ),
                            ))
                        }
                        Err(_) => Err(unavailable()),
                    }
                },
            );
            drop(_sync);
            // Dropping this sender on admission failure also releases a failed
            // worker without allowing any backend operation to run.
            if job.is_ok() {
                let _ = release.send(());
            }
            return match job {
                Ok(job) => Ok(json!({"accepted":true,"job_id":job.job_id})),
                Err(error) if error.contains("already running") => Ok(reject("busy")),
                Err(_) => Ok(reject("unavailable")),
            };
        }
        if matches!(action, "vault_copy_status" | "vault_copy_cancel") {
            let expected_generation = request
                .get("expected_generation")
                .and_then(Value::as_u64)
                .ok_or("expected_generation must be a nonnegative integer")?;
            if expected_generation != generation {
                return Err("Copy job was not found".into());
            }
            let scope = self.vault_scope(&origin, space, text("root_resource_id")?)?;
            let job_id = text("job_id")?;
            let current = self
                .vault_edit_reconcile_jobs
                .status(&scope, job_id, generation)?;
            if current.operation.as_deref() != Some("copy_file") {
                return Err("Copy job was not found".into());
            }
            let status = if action == "vault_copy_cancel" {
                self.vault_edit_reconcile_jobs
                    .cancel(&scope, job_id, generation)
                    .or_else(|_| {
                        self.vault_edit_reconcile_jobs
                            .status(&scope, job_id, generation)
                    })?
            } else {
                current
            };
            return Ok(copy_producer_job_status(&status, generation));
        }
        if action == "vault_copy_verify_start" {
            let root_resource_id = text("root_resource_id")?;
            let write_id = text("write_id")?.to_owned();
            let revision = request
                .get("revision")
                .and_then(Value::as_u64)
                .ok_or("revision must be a positive integer")?;
            let expected_generation = request
                .get("expected_generation")
                .and_then(Value::as_u64)
                .ok_or("expected_generation must be a nonnegative integer")?;
            let reject = |error| json!({"accepted":false,"error":error});
            if !copy_verify_generation_is_current(expected_generation, generation) {
                return Ok(reject("stale_generation"));
            }
            if !valid_copy_write_id(&write_id) || revision == 0 {
                return Ok(reject("scope_changed"));
            }
            if self.auth_transition.load(Ordering::Acquire)
                || self.shutdown.load(Ordering::Acquire)
                || self.retiring.load(Ordering::Acquire)
            {
                return Ok(reject("stale_generation"));
            }
            if self.offline_namespace.load(Ordering::Acquire) {
                return Ok(reject("offline"));
            }
            let destination_scope = self.vault_scope(&origin, space, root_resource_id)?;
            if !self.vaults.is_unlocked(&destination_scope).unwrap_or(false) {
                return Ok(reject("locked"));
            }
            let destination_route = match self.active_vault_route(space, root_resource_id) {
                Ok(route) => route,
                Err(RouteError::Unavailable) => return Ok(reject("scope_changed")),
                Err(RouteError::Ambiguous) => return Ok(reject("scope_changed")),
            };
            let cache = self.open_vault_cache()?;
            let destination_journal = match VaultOfflineCache::new(
                cache.clone(),
                destination_scope.clone(),
                destination_route.root_path(),
            ) {
                Ok(journal) => journal,
                Err(_) => return Ok(reject("unavailable")),
            };
            let source_target = match destination_journal.pending_copy_source_target(
                &self.vaults,
                &write_id,
                revision,
            ) {
                Ok(target) => target,
                Err(error) if error.kind == raiun_core::backend::ErrorKind::NotFound => {
                    return Ok(reject("scope_changed"));
                }
                Err(_) => return Ok(reject("unavailable")),
            };

            let source_route = if let Some(target) = source_target.as_ref() {
                let route = match self
                    .active_vault_route(target.scope.space_id(), target.scope.resource_id())
                {
                    Ok(route) if route.root_path() == target.root_path => route,
                    Ok(_) | Err(RouteError::Ambiguous) => return Ok(reject("scope_changed")),
                    Err(RouteError::Unavailable) => return Ok(reject("missing_source")),
                };
                if let Some(error) = copy_verify_source_route_error(
                    &destination_scope,
                    target,
                    Some(route.root_path()),
                    self.vaults.is_unlocked(&target.scope).unwrap_or(false),
                ) {
                    return Ok(reject(error));
                }
                Some((target.scope.clone(), route.root_path().to_owned()))
            } else {
                // Legacy rows have no sealed source binding. The backend
                // resolver recognizes this before scope comparison and
                // returns the fixed review-only outcome without network I/O.
                None
            };
            self.check_vault_generation(generation)?;
            if self.auth_transition.load(Ordering::Acquire) {
                return Ok(reject("stale_generation"));
            }
            let source_scope = source_route.as_ref().map(|(scope, _)| scope.clone());
            let worker_source_scope = source_scope
                .clone()
                .unwrap_or_else(|| destination_scope.clone());
            let client_for_job = client.clone();
            let sessions = Arc::clone(&self.vaults);
            let cache_for_job = cache.clone();
            let destination_path = destination_route.root_path().to_owned();
            let source_path = source_route.as_ref().map(|(_, path)| path.clone());
            let worker_destination_scope = destination_scope.clone();
            let auth_generation = Arc::clone(&self.auth_generation);
            let worker_auth_generation = Arc::clone(&auth_generation);
            let worker_auth_transition = Arc::clone(&self.auth_transition);
            let worker_shutdown = Arc::clone(&self.shutdown);
            // This job performs network requests. Its generation/transition
            // fences below make it safe to start after releasing the runtime
            // sync gate, avoiding network I/O under a global runtime lock.
            drop(_sync);
            let job = crate::vault_edit_jobs::VaultEditReconcileJobs::start_copy_verification(
                &self.vault_edit_reconcile_jobs,
                crate::vault_edit_jobs::CopyVerificationJobSpec {
                    destination: &destination_scope,
                    source: source_scope.as_ref(),
                    auth_generation,
                    expected_generation: generation,
                    pin_jobs: Arc::clone(&self.vault_pin_jobs),
                    binding: crate::vault_edit_jobs::VaultEditOperationBinding {
                        operation: "copy_verify".into(),
                        write_id: write_id.clone(),
                        revision,
                        retry_generation: None,
                    },
                },
                move |cancelled, progress| {
                    if cancelled.load(Ordering::Acquire)
                        || worker_auth_generation.load(Ordering::Acquire) != generation
                        || worker_auth_transition.load(Ordering::Acquire)
                        || worker_shutdown.load(Ordering::Acquire)
                    {
                        return Err(crate::vault_edit_jobs::VaultEditJobFailure::unclassified(
                            "copy verification was invalidated",
                        ));
                    }
                    let Some(source_path) = source_path else {
                        // Old journal rows do not contain an authenticated
                        // source binding. Surface review without constructing
                        // an online backend or issuing any network probe.
                        return Err(crate::vault_edit_jobs::VaultEditJobFailure::classified(
                            "copy requires review",
                            VaultEditFailureClass::CopyNeedsReview(
                                CopyVerifyReviewReason::LegacyBindingUnavailable,
                            ),
                        ));
                    };
                    let destination_cache = VaultOfflineCache::new(
                        cache_for_job.clone(),
                        worker_destination_scope.clone(),
                        destination_path.clone(),
                    )
                    .map_err(|_| {
                        crate::vault_edit_jobs::VaultEditJobFailure::unclassified(
                            "copy verification is unavailable",
                        )
                    })?;
                    let destination = VaultBackend::new_for_copy_verification(
                        client_for_job.clone(),
                        Arc::clone(&sessions),
                        worker_destination_scope.clone(),
                        destination_path,
                        destination_cache,
                    )
                    .map_err(|_| {
                        crate::vault_edit_jobs::VaultEditJobFailure::unclassified(
                            "copy verification is unavailable",
                        )
                    })?;
                    let source_cache = VaultOfflineCache::new(
                        cache_for_job,
                        worker_source_scope.clone(),
                        source_path.clone(),
                    )
                    .map_err(|_| {
                        crate::vault_edit_jobs::VaultEditJobFailure::unclassified(
                            "copy verification is unavailable",
                        )
                    })?;
                    let source = VaultBackend::new_for_copy_verification(
                        client_for_job,
                        sessions,
                        worker_source_scope,
                        source_path,
                        source_cache,
                    )
                    .map_err(|_| {
                        crate::vault_edit_jobs::VaultEditJobFailure::unclassified(
                            "copy verification is unavailable",
                        )
                    })?;
                    if cancelled.load(Ordering::Acquire)
                        || worker_auth_generation.load(Ordering::Acquire) != generation
                        || worker_auth_transition.load(Ordering::Acquire)
                        || worker_shutdown.load(Ordering::Acquire)
                    {
                        return Err(crate::vault_edit_jobs::VaultEditJobFailure::unclassified(
                            "copy verification was invalidated",
                        ));
                    }
                    progress(0, 0, 0, 1);
                    match source.resolve_pending_copy_to_cancellable(
                        &destination,
                        &write_id,
                        revision,
                        || {
                            cancelled.load(Ordering::Acquire)
                                || worker_auth_generation.load(Ordering::Acquire) != generation
                                || worker_auth_transition.load(Ordering::Acquire)
                                || worker_shutdown.load(Ordering::Acquire)
                        },
                    ) {
                        Ok(raiun_opencloud::vault_backend::VaultCopyResolutionOutcome::Verified { .. }) => {
                            // The resolver checks these fences under the
                            // token/session leases at its completion-admission
                            // point, immediately before retiring the row. A
                            // later transition must not turn that committed
                            // local result into a cancelled job.
                            progress(1, 0, 0, 0);
                            Ok(crate::vault_edit_jobs::VaultEditReconcileReport {
                                processed: 1,
                                uploaded: 0,
                                conflicts: 0,
                                remaining: 0,
                            })
                        }
                        Ok(raiun_opencloud::vault_backend::VaultCopyResolutionOutcome::NeedsReview { reason, .. }) => {
                            Err(crate::vault_edit_jobs::VaultEditJobFailure::classified(
                                "copy requires review",
                                VaultEditFailureClass::CopyNeedsReview(copy_verify_reason(reason)),
                            ))
                        }
                        Err(_) => Err(crate::vault_edit_jobs::VaultEditJobFailure::unclassified(
                            "copy verification is unavailable",
                        )),
                    }
                },
            );
            return match job {
                Ok(job) => Ok(json!({"accepted":true,"job_id":job.job_id})),
                Err(error) if error.contains("already running") => Ok(reject("busy")),
                Err(_) => Ok(reject("unavailable")),
            };
        }
        if matches!(
            action,
            "vault_copy_verify_status" | "vault_copy_verify_cancel"
        ) {
            let root_resource_id = text("root_resource_id")?;
            let expected_generation = request
                .get("expected_generation")
                .and_then(Value::as_u64)
                .ok_or("expected_generation must be a nonnegative integer")?;
            if expected_generation != generation {
                return Err("Copy verification job was not found".into());
            }
            let scope = self.vault_scope(&origin, space, root_resource_id)?;
            let job_id = text("job_id")?;
            // Verify the action's job class before requesting cancellation.
            // The shared registry also contains other encrypted edit jobs.
            let current = self
                .vault_edit_reconcile_jobs
                .status(&scope, job_id, generation)?;
            if current.operation.as_deref() != Some("copy_verify") {
                return Err("Copy verification job was not found".into());
            }
            let status = if action == "vault_copy_verify_cancel" {
                match self
                    .vault_edit_reconcile_jobs
                    .cancel(&scope, job_id, generation)
                {
                    Ok(status) => status,
                    Err(_) => self
                        .vault_edit_reconcile_jobs
                        .status(&scope, job_id, generation)?,
                }
            } else {
                self.vault_edit_reconcile_jobs
                    .status(&scope, job_id, generation)?
            };
            if status.operation.as_deref() != Some("copy_verify") {
                return Err("Copy verification job was not found".into());
            }
            return Ok(copy_verify_job_status(&status, generation));
        }
        if action == "vault_retry_interrupted_file_create" {
            let root_resource_id = text("root_resource_id")?;
            let write_id = text("write_id")?;
            if write_id.len() != 32
                || !write_id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err("Interrupted file operation ID is invalid".into());
            }
            let revision = request
                .get("revision")
                .and_then(Value::as_u64)
                .filter(|revision| *revision > 0)
                .ok_or("Interrupted file operation revision is invalid")?;
            let retry_generation = request
                .get("retry_generation")
                .and_then(Value::as_u64)
                .ok_or("Interrupted file retry generation is invalid")?;
            let retry_state = vault_retry_state_from_name(text("retry_state")?)
                .ok_or("This file operation is no longer eligible for explicit retry")?;
            {
                let settings = self.settings.lock().map_err(|_| "Settings poisoned")?;
                if settings.paused || settings.paused_space_ids.iter().any(|id| id == space) {
                    return Err(
                        "Resume this account and Space before retrying the file creation".into(),
                    );
                }
            }
            let scope = self.vault_scope(&origin, space, root_resource_id)?;
            self.check_vault_generation(generation)?;
            if !self
                .vaults
                .is_unlocked(&scope)
                .map_err(|_| "Encrypted vault is locked")?
            {
                return Err("Unlock this encrypted vault before retrying the file creation".into());
            }
            let mut matching_routes = self
                .vault_mounts
                .routes()
                .map_err(|_| "Encrypted vault routes are unavailable")?
                .into_iter()
                .filter(|route| {
                    route.space_id() == space
                        && route.root_resource_id() == root_resource_id
                        && route.control().is_active().unwrap_or(false)
                });
            let route = matching_routes
                .next()
                .ok_or("Encrypted vault route is unavailable")?;
            if matching_routes.next().is_some() {
                return Err("Encrypted vault route is ambiguous".into());
            }
            let root_path = route.root_path().to_owned();
            let verified = VaultMetadataClient::new(&client)
                .inspect_vault(space, &root_path)
                .map_err(|_| "Encrypted vault could not be verified online")?;
            if verified.space_id != space || verified.root.id != root_resource_id {
                return Err("Encrypted vault identity changed; inspect it before retrying".into());
            }
            self.check_vault_generation(generation)?;
            if !route.control().is_active().unwrap_or(false)
                || !self.vaults.is_unlocked(&scope).unwrap_or(false)
            {
                return Err("Encrypted vault was locked while preparing the retry".into());
            }

            let cache = self.open_vault_cache()?;
            let journal = VaultOfflineCache::new(cache.clone(), scope.clone(), &root_path)
                .map_err(|_| "Encrypted operation journal is unavailable")?;
            let operation = journal
                .pending_operation(&self.vaults, write_id, revision)
                .map_err(|_| "The exact saved file operation is no longer available")?;
            if operation.operation != VaultPendingOperationKind::CreateFile
                || operation.base != raiun_core::backend::WriteCondition::Absent
                || operation.retry_generation != retry_generation
                || vault_pending_operation_retry_state(operation.operation, operation.state)
                    != Some(vault_retry_state_name(retry_state))
            {
                return Err(
                    "The file operation changed; refresh its status before retrying".into(),
                );
            }
            let offline_cache = VaultOfflineCache::new(cache, scope.clone(), &root_path)
                .map_err(|_| "Encrypted operation journal is unavailable")?;
            let backend = VaultBackend::new_with_offline_cache(
                client,
                self.vaults.clone(),
                scope.clone(),
                root_path,
                offline_cache,
            )
            .map_err(|_| "Encrypted vault could not be prepared for explicit retry")?;
            self.check_vault_generation(generation)?;
            let job = self.start_interrupted_file_create_retry_job(
                scope,
                generation,
                write_id.to_owned(),
                revision,
                retry_generation,
                retry_state,
                backend,
            )?;
            return Ok(json!({"accepted":true,"job_id":job.job_id}));
        }
        let _credential_operation = if matches!(
            action,
            "vault_unlock" | "vault_unlock_offline" | "vault_forget"
        ) {
            Some(begin_credential_operation(
                &self.dir,
                &self.vault_account_id,
            )?)
        } else {
            None
        };
        if action == "vault_create" {
            let secret = password.as_mut().ok_or("Missing password")?;
            if secret.is_empty() || secret.len() > 4096 {
                return Err("Password must contain 1–4096 UTF-8 bytes".into());
            }
            let mut bytes = Zeroizing::new(secret.as_bytes().to_vec());
            secret.zeroize();
            trace_vault_create_stage("remote_create_start");
            let remote = raiun_opencloud::vault_create::create_folder_vault(&client, space, text("parent_path")?, text("name")?)
                .map_err(|e| format!("Vault creation could not be confirmed; inspect the destination before retrying: {e}"))?;
            trace_vault_create_stage("remote_create_complete");
            let root_path = remote.root().root_path.clone();
            let resource = remote.root().root.id.clone();
            let scope = self.vault_scope(&origin, space, &resource)?;
            let result = (|| {
                self.check_vault_generation(generation)?;
                trace_vault_create_stage("local_kdf_start");
                let pending = self
                    .vaults
                    .begin_create(&scope, &mut bytes)
                    .map_err(|e| e.to_string())?;
                trace_vault_create_stage("local_kdf_complete");
                trace_vault_create_stage("remote_initialize_start");
                let listing = remote
                    .initialize(pending.integrity_token())
                    .map_err(|e| e.to_string())?;
                trace_vault_create_stage("remote_initialize_complete");
                self.check_vault_generation(generation)?;
                self.vaults
                    .finish_create(
                        pending,
                        listing
                            .integrity_token
                            .as_deref()
                            .ok_or("Vault proof was not saved")?,
                    )
                    .map_err(|e| e.to_string())?;
                trace_vault_create_stage("session_publish_complete");
                trace_vault_create_stage("route_publish_start");
                let publish_status = match self.publish_unlocked_mount_route(
                    &client,
                    &origin,
                    &self.vault_account_id,
                    space,
                    &root_path,
                    &resource,
                ) {
                    Ok(mounted) => {
                        trace_vault_create_stage("route_publish_complete");
                        mounted
                    }
                    Err(error) => {
                        trace_vault_create_stage("route_publish_failed");
                        self.revoke_vault_route_and_lock(&scope)?;
                        return Err(error);
                    }
                };
                if let Err(error) = self.check_vault_generation(generation) {
                    self.revoke_vault_route_and_lock(&scope)?;
                    return Err(error);
                }
                let (mounted_writable, status_reason) =
                    self.vault_mount_writable(space, &root_path, &resource)?;
                let write_unavailable_reason = match status_reason {
                    Some(reason @ ("drive_not_mounted" | "private_spool_unavailable")) => {
                        Some(reason)
                    }
                    _ => publish_status.1.or(status_reason),
                };
                trace_vault_create_stage("response_ready");
                Ok(json!({
                    "root_path":root_path,
                    "root_resource_id":resource,
                    "unlocked":true,
                    "vault_mount_ready":true,
                    "vault_mount_writable":mounted_writable,
                    "vault_mount_write_unavailable_reason": if mounted_writable { None } else { write_unavailable_reason },
                }))
            })();
            return result.map_err(|error: String| format!("The folder {root_path} was created and retained, but vault setup did not finish: {error}. If its password was saved, unlock it; otherwise use a new folder name."));
        }
        if action == "vault_lock" {
            let scope = self.vault_scope(&origin, space, text("root_resource_id")?)?;
            self.vault_edit_reconcile_jobs
                .cancel_scope_and_wait(&scope)?;
            self.revoke_vault_route_and_lock(&scope)?;
            self.wake.store(true, Ordering::Release);
            return Ok(json!({
                "unlocked":false,
                "vault_mount_ready":false,
                "vault_mount_writable":false,
                "vault_mount_existing_file_overwrite":false,
                "vault_mount_existing_file_overwrite_reason":"vault_locked",
                "vault_mount_write_unavailable_reason":"vault_locked",
            }));
        }
        if action == "vault_pin_start" {
            let root_path = text("root_path")?;
            let listing = VaultMetadataClient::new(&client)
                .inspect_vault(space, root_path)
                .map_err(|_| "Encrypted vault could not be verified online")?;
            let resource_id = text("root_resource_id")?;
            if listing.root.id != resource_id {
                return Err("Encrypted vault identity changed; inspect it before pinning".into());
            }
            let scope = self.vault_scope(&origin, space, resource_id)?;
            self.check_vault_generation(generation)?;
            if !self
                .vaults
                .is_unlocked(&scope)
                .map_err(|_| "Encrypted vault is locked")?
            {
                return Err("Unlock this encrypted vault before saving it offline".into());
            }
            let cache = self.open_vault_cache()?;
            let offline_cache = VaultOfflineCache::new(cache, scope.clone(), root_path)
                .map_err(|_| "Encrypted offline cache is unavailable")?;
            let backend = VaultBackend::new_with_offline_cache(
                client,
                self.vaults.clone(),
                scope.clone(),
                root_path.to_owned(),
                offline_cache,
            )
            .map_err(|_| "Encrypted vault could not be prepared for offline saving")?;
            let existing_pin_id = request
                .get("pin_id")
                .map(|value| value.as_str().ok_or("pin_id must be a string"))
                .transpose()?
                .map(str::to_owned);
            self.check_vault_generation(generation)?;
            let job_id = crate::vault_pin_jobs::VaultPinJobs::start(
                &self.vault_pin_jobs,
                &scope,
                backend,
                existing_pin_id,
                Arc::clone(&self.auth_generation),
                generation,
            )?;
            return Ok(json!({"accepted":true,"job_id":job_id}));
        }
        if action == "vault_reconcile_edits_start" {
            let resource_id = text("root_resource_id")?;
            {
                let settings = self.settings.lock().map_err(|_| "Settings poisoned")?;
                if settings.paused || settings.paused_space_ids.iter().any(|id| id == space) {
                    return Err("Resume this account and Space before retrying saved edits".into());
                }
            }
            let scope = self.vault_scope(&origin, space, resource_id)?;
            self.check_vault_generation(generation)?;
            if !self
                .vaults
                .is_unlocked(&scope)
                .map_err(|_| "Encrypted vault is locked")?
            {
                return Err("Unlock this encrypted vault before retrying saved edits".into());
            }

            // Resolve the root path only from a registered mount route, then
            // verify its stable root identity against the authenticated server.
            let mut matching = self
                .vault_mounts
                .routes()
                .map_err(|_| "Encrypted vault route is unavailable")?
                .into_iter()
                .filter(|route| {
                    route.space_id() == space
                        && route.root_resource_id() == resource_id
                        && route.control().is_active().unwrap_or(false)
                });
            let route = matching
                .next()
                .ok_or("Encrypted vault route is unavailable")?;
            if matching.next().is_some() {
                return Err("Encrypted vault route is ambiguous".into());
            }
            let root_path = route.root_path().to_owned();
            let verified = VaultMetadataClient::new(&client)
                .inspect_vault(space, &root_path)
                .map_err(|_| "Encrypted vault could not be verified online")?;
            if verified.space_id != space || verified.root.id != resource_id {
                return Err(
                    "Encrypted vault identity changed; inspect it before retrying edits".into(),
                );
            }
            self.check_vault_generation(generation)?;

            let cache = self.open_vault_cache()?;
            let offline_cache = VaultOfflineCache::new(cache.clone(), scope.clone(), &root_path)
                .map_err(|_| "Encrypted edit journal is unavailable")?;
            let journal = VaultOfflineCache::new(cache, scope.clone(), &root_path)
                .map_err(|_| "Encrypted edit journal is unavailable")?;
            let backend = VaultBackend::new_with_offline_cache(
                client,
                self.vaults.clone(),
                scope.clone(),
                root_path,
                offline_cache,
            )
            .map_err(|_| "Encrypted vault could not be prepared for saved edits")?;
            self.check_vault_generation(generation)?;

            let job =
                self.start_vault_edit_reconcile_job(scope, generation, false, journal, backend)?;
            return Ok(json!({"accepted":true,"job_id":job.job_id}));
        }
        if matches!(
            action,
            "vault_reconcile_edits_status" | "vault_reconcile_edits_cancel"
        ) {
            let scope = self.vault_scope(&origin, space, text("root_resource_id")?)?;
            let job_id = text("job_id")?;
            let current = self
                .vault_edit_reconcile_jobs
                .status(&scope, job_id, generation)?;
            if matches!(
                current.operation.as_deref(),
                Some("copy_verify" | "copy_file")
            ) {
                return Err("Encrypted edit job was not found".into());
            }
            let status = if action == "vault_reconcile_edits_cancel" {
                self.vault_edit_reconcile_jobs
                    .cancel(&scope, job_id, generation)?
            } else {
                self.vault_edit_reconcile_jobs
                    .status(&scope, job_id, generation)?
            };
            if matches!(
                status.operation.as_deref(),
                Some("copy_verify" | "copy_file")
            ) {
                return Err("Encrypted edit job was not found".into());
            }
            return serde_json::to_value(status)
                .map_err(|_| "Encrypted edit job status could not be encoded".into());
        }
        if action == "vault_reconcile_edits_latest" {
            let scope = self.vault_scope(&origin, space, text("root_resource_id")?)?;
            let latest = self.vault_edit_reconcile_jobs.latest(&scope, generation)?;
            let latest = latest.filter(|status| {
                !matches!(
                    status.operation.as_deref(),
                    Some("copy_verify" | "copy_file")
                )
            });
            return Ok(json!({"available":latest.is_some(),"status":latest}));
        }
        if matches!(action, "vault_pin_status" | "vault_pin_cancel") {
            let scope = self.vault_scope(&origin, space, text("root_resource_id")?)?;
            let job_id = text("job_id")?;
            if action == "vault_pin_cancel" {
                let cancelled = self.vault_pin_jobs.cancel(&scope, job_id)?;
                return Ok(json!({"cancelled":cancelled}));
            }
            let Some(snapshot) = self.vault_pin_jobs.status(&scope, job_id)? else {
                return Err("Encrypted snapshot job was not found".into());
            };
            let pin = snapshot.pin.map(|pin| {
                json!({
                    "id":pin.id,
                    "generation":pin.generation,
                    "state":ciphertext_pin_state_name(pin.state),
                    "item_count":pin.item_count,
                    "byte_len":pin.byte_len,
                })
            });
            return Ok(json!({
                "job_id":job_id,
                "state":snapshot.state,
                "error":snapshot.error,
                "items_done":snapshot.items_done,
                "bytes_done":snapshot.bytes_done,
                "pin":pin,
            }));
        }
        if action == "vault_pins" {
            let scope = self.vault_scope(&origin, space, text("root_resource_id")?)?;
            let after = request
                .get("after")
                .map(|value| value.as_str().ok_or("after must be a string"))
                .transpose()?;
            let limit = request
                .get("limit")
                .map(|value| value.as_u64().ok_or("limit must be a positive integer"))
                .transpose()?
                .unwrap_or(100);
            let limit = usize::try_from(limit).map_err(|_| "limit must be a positive integer")?;
            let cache = self.open_vault_cache()?;
            let offline_cache = VaultOfflineCache::new(cache, scope.clone(), "/")
                .map_err(|_| "Encrypted offline cache is unavailable")?;
            let page = offline_cache
                .pins(after, limit)
                .map_err(|_| "Encrypted snapshot list is unavailable")?;
            let active_job_id = self.vault_pin_jobs.active_job_id(&scope)?;
            return Ok(json!({
                "items":page.items.into_iter().map(|pin| json!({
                    "id":pin.id,
                    "generation":pin.generation,
                    "state":ciphertext_pin_state_name(pin.state),
                    "item_count":pin.item_count,
                    "byte_len":pin.byte_len,
                })).collect::<Vec<_>>(),
                "next_after":page.next_after,
                "truncated":page.truncated,
                "active_job_id":active_job_id,
            }));
        }
        if action == "vault_pin_remove" {
            let scope = self.vault_scope(&origin, space, text("root_resource_id")?)?;
            self.vault_pin_jobs.cancel_scope_and_wait(&scope)?;
            let pin_id = text("pin_id")?;
            let cache = self.open_vault_cache()?;
            let offline_cache = VaultOfflineCache::new(cache, scope, "/")
                .map_err(|_| "Encrypted offline cache is unavailable")?;
            offline_cache
                .remove_pin(pin_id)
                .map_err(|_| "Encrypted snapshot could not be removed")?;
            return Ok(json!({"removed":true}));
        }
        if action == "vault_forget" {
            let scope = self.vault_scope(&origin, space, text("root_resource_id")?)?;
            let cleanup = credential_store.remove(&scope)?;
            record_status(&scope, RememberedStatus::NotSaved);
            return Ok(json!({
                "remembered":false,
                "remembered_status":"not_saved",
                "cleanup":cleanup.as_str(),
            }));
        }
        if action == "vault_cached_roots" {
            let after = request
                .get("after")
                .map(|value| {
                    let space = value
                        .get("space_id")
                        .and_then(Value::as_str)
                        .ok_or("after.space_id must be a string")?;
                    let root = value
                        .get("root_resource_id")
                        .and_then(Value::as_str)
                        .ok_or("after.root_resource_id must be a string")?;
                    Ok::<_, String>((space.to_owned(), root.to_owned()))
                })
                .transpose()?;
            let limit = request
                .get("limit")
                .map(|value| value.as_u64().ok_or("limit must be a positive integer"))
                .transpose()?
                .unwrap_or(100);
            let limit = usize::try_from(limit).map_err(|_| "limit must be a positive integer")?;
            let cache = self.open_vault_cache()?;
            let page = VaultOfflineCache::discover_cached_roots(
                &cache,
                &origin,
                &self.vault_account_id,
                after
                    .as_ref()
                    .map(|(space, root)| (space.as_str(), root.as_str())),
                limit,
            )
            .map_err(|_| "Encrypted offline snapshots are unavailable")?;
            let next_after = page.next_after.map(|(space_id, root_resource_id)| {
                json!({"space_id":space_id,"root_resource_id":root_resource_id})
            });
            return Ok(json!({
                "roots":page.roots.iter().map(|root| json!({
                    "space_id":root.space_id,
                    "root_resource_id":root.root_resource_id,
                    "pin_id":root.pin_id,
                    "generation":root.generation,
                    "snapshot_available":true,
                })).collect::<Vec<_>>(),
                "next_after":next_after,
                "truncated":page.truncated,
            }));
        }
        if action == "vault_resolve_unlock_target" {
            let root_resource_id = text("root_resource_id")?;
            let routes = self
                .vault_mounts
                .routes()
                .map_err(|_| "Encrypted location is not a known Raiun mount target")?;
            let mut matching = routes.into_iter().filter(|route| {
                route.space_id() == space && route.root_resource_id() == root_resource_id
            });
            let route = matching
                .next()
                .ok_or("Encrypted location is not a known Raiun mount target")?;
            if matching.next().is_some() {
                return Err("Encrypted location target is ambiguous; reopen it from Raiun".into());
            }

            // The URI carries identifiers only. The path comes from Raiun's
            // own registered route and is freshly verified against the
            // authenticated server before the unlock UI may proceed.
            let root_path = route.root_path();
            let listing = VaultMetadataClient::new(&client)
                .inspect_vault(space, root_path)
                .map_err(|_| "Encrypted location could not be verified online")?;
            self.check_vault_generation(generation)?;
            if listing.space_id != space || listing.root.id != root_resource_id {
                return Err("Encrypted location identity changed; reopen it from Raiun".into());
            }

            let pin_id = request
                .get("pin_id")
                .map(|value| value.as_str().ok_or("pin_id must be a string"))
                .transpose()?;
            let pin_generation = if let Some(pin_id) = pin_id {
                if pin_id.is_empty() || pin_id.len() > 128 {
                    return Err("pin_id is invalid".into());
                }
                let scope = self.vault_scope(&origin, space, root_resource_id)?;
                let cache = self.open_vault_cache()?;
                let cache_scope = CacheScope::new(
                    scope.server_origin(),
                    scope.account_id(),
                    scope.space_id(),
                    scope.resource_id(),
                    ScopeProtection::CiphertextOnly,
                )
                .map_err(|_| "The encrypted snapshot is not ready for this location")?;
                let pin = cache
                    .active_ciphertext_pin_info(&cache_scope, pin_id)
                    .map_err(|_| "The encrypted snapshot is not ready for this location")?;
                if pin.state != CiphertextPinState::Ready {
                    return Err("The encrypted snapshot is not ready for this location".into());
                }
                Some(pin.generation)
            } else {
                None
            };
            self.check_vault_generation(generation)?;
            return Ok(json!({
                "resolved": true,
                "space_id": space,
                "root_resource_id": root_resource_id,
                "root_path": listing.root_path,
                "display_name": listing.root.raw_name,
                "pin_id": pin_id,
                "pin_generation": pin_generation,
            }));
        }
        if action == "vault_unlock_offline" {
            let resource_id = text("root_resource_id")?;
            let scope = self.vault_scope(&origin, space, resource_id)?;
            let use_saved = request
                .get("use_saved")
                .map(|value| value.as_bool().ok_or("use_saved must be a boolean"))
                .transpose()?
                .unwrap_or(false);
            let remember = request
                .get("remember")
                .map(|value| value.as_bool().ok_or("remember must be a boolean"))
                .transpose()?
                .unwrap_or(false);
            if remember && use_saved {
                return Err("Choose either a new password or the saved password".into());
            }
            if use_saved && password.is_some() {
                return Err("A password cannot be combined with use_saved".into());
            }
            let mut bytes = if use_saved {
                match credential_store.load(&scope) {
                    Ok(Some(password)) => {
                        record_status(&scope, RememberedStatus::KnownSaved);
                        password
                    }
                    Ok(None) => {
                        record_status(&scope, RememberedStatus::NotSaved);
                        return Err("No remembered password is available for this vault".into());
                    }
                    Err(error) => {
                        record_status(&scope, RememberedStatus::Unavailable);
                        return Err(error);
                    }
                }
            } else {
                let secret = password.as_mut().ok_or("Missing password")?;
                let bytes = Zeroizing::new(secret.as_bytes().to_vec());
                secret.zeroize();
                bytes
            };
            if bytes.is_empty() || bytes.len() > 4096 {
                bytes.zeroize();
                return Err("Password must contain 1–4096 UTF-8 bytes".into());
            }
            // Unlock consumes and zeroizes `bytes` during key derivation. Keep
            // a separate zeroizing copy only for an explicit remember request;
            // it is persisted only after the cached root and route are verified.
            let remember_bytes = remember.then(|| Zeroizing::new(bytes.to_vec()));

            let cache = self.open_vault_cache()?;
            let pin_id = request
                .get("pin_id")
                .map(|value| value.as_str().ok_or("pin_id must be a string"))
                .transpose()?
                .map(str::to_owned);
            let expected_generation = request
                .get("expected_generation")
                .map(|value| {
                    value
                        .as_u64()
                        .ok_or("expected_generation must be a non-negative integer")
                })
                .transpose()?;
            let pin_info = if let Some(pin_id) = pin_id.as_deref() {
                let pin_cache =
                    VaultOfflineCache::new_for_pin(cache.clone(), scope.clone(), "/", pin_id)
                        .map_err(
                            |_| "No current complete encrypted snapshot is available offline",
                        )?;
                let pin = pin_cache
                    .pin_info(pin_id)
                    .map_err(|_| "No current complete encrypted snapshot is available offline")?;
                if pin.state != CiphertextPinState::Ready {
                    return Err("The encrypted snapshot is not ready for this location".into());
                }
                let expected = expected_generation.ok_or(
                    "Reopen the encrypted snapshot before unlocking; its generation was not confirmed",
                )?;
                if pin.generation != expected {
                    return Err(
                        "The encrypted snapshot changed. Refresh saved locations and reopen the current copy before unlocking."
                            .into(),
                    );
                }
                Some(pin)
            } else {
                // The opportunistic online cache remains supported for existing users.
                if expected_generation.is_some() {
                    return Err("expected_generation requires pin_id".into());
                }
                if !VaultOfflineCache::cached_root_available(&cache, &scope)
                    .map_err(|_| "Encrypted offline cache is unavailable")?
                {
                    return Err("No current encrypted vault snapshot is available offline".into());
                }
                None
            };
            self.revoke_vault_route_and_lock(&scope)?;
            let unlocked = (|| {
                let snapshot = if let Some(pin_id) = pin_id.as_deref() {
                    VaultOfflineCache::unlock_cached_pin_root_expected(
                        &cache,
                        &self.vaults,
                        &scope,
                        pin_id,
                        expected_generation.expect("pin ID requires expected generation"),
                        &mut bytes,
                    )
                    .map_err(|error| {
                        if error.message == "encrypted snapshot generation changed" {
                            "The encrypted snapshot changed. Refresh saved locations and reopen the current copy before unlocking."
                        } else {
                            "Saved encrypted vault snapshot could not be unlocked"
                        }
                    })?
                } else {
                    VaultOfflineCache::unlock_cached_root(&cache, &self.vaults, &scope, &mut bytes)
                        .map_err(|_| "Saved encrypted vault snapshot could not be unlocked")?
                        .0
                };
                self.check_vault_generation(generation)?;
                let root_path = snapshot.root_path.clone();
                let space_name = snapshot.space_name.clone();
                let backend = vault_mount::new_offline_overwrite_backend_expected(
                    client.clone(),
                    self.vaults.clone(),
                    cache.clone(),
                    scope.clone(),
                    &root_path,
                    pin_id.as_deref().zip(expected_generation),
                    snapshot,
                )
                .map_err(|_| "Saved encrypted vault snapshot could not be opened")?;
                let route = self.ensure_vault_mount_route(space, &root_path, resource_id)?;
                let publish_route = || {
                    route
                        .control()
                        .install_existing_file_overwrite_backend(backend)
                        .map_err(|_| "Could not expose the offline encrypted vault")
                };
                // Hold a short cache manifest lease through route publication.
                // This closes the final check/install gap: a refresh cannot
                // replace the selected pin generation between validation and
                // exposing the backend built from that generation.
                if let (Some(pin_id), Some(expected_generation)) =
                    (pin_id.as_deref(), expected_generation)
                {
                    let pin_cache = VaultOfflineCache::new(
                        cache.clone(),
                        scope.clone(),
                        "/",
                    )
                    .map_err(|_| {
                        "The encrypted snapshot changed. Refresh saved locations and reopen the current copy before unlocking."
                    })?;
                    pin_cache
                        .with_active_pin_generation(pin_id, expected_generation, publish_route)
                        .map_err(|_| {
                            "The encrypted snapshot changed. Refresh saved locations and reopen the current copy before unlocking."
                        })?
                        .map_err(|_| "Could not expose the offline encrypted vault")?;
                } else {
                    publish_route()?;
                }
                self.check_vault_generation(generation)?;
                Ok::<_, String>((route, root_path, space_name))
            })();
            let (route, root_path, space_name) = match unlocked {
                Ok(result) => result,
                Err(error) => {
                    bytes.zeroize();
                    let _ = self.revoke_vault_route_and_lock(&scope);
                    return Err(error);
                }
            };
            let mut remembered = use_saved;
            let remember_error = if let Some(password) = remember_bytes.as_deref() {
                match credential_store.store(&scope, password) {
                    Ok(()) => {
                        remembered = true;
                        record_status(&scope, RememberedStatus::KnownSaved);
                        None
                    }
                    Err(_) => {
                        record_status(&scope, RememberedStatus::Unavailable);
                        Some("secure_store_unavailable")
                    }
                }
            } else {
                None
            };
            bytes.zeroize();
            let remembered_status = remembered_status(&scope);
            let ready = route
                .control()
                .is_active()
                .map_err(|_| "Vault route is inactive")?;
            let (overwrite_ready, overwrite_reason) =
                self.vault_mount_existing_file_overwrite_status(space, &root_path, resource_id)?;
            return Ok(json!({
                "unlocked":true,
                "offline":true,
                "root_path":root_path,
                "root_resource_id":resource_id,
                "pin_id":pin_id,
                "generation":pin_info.map(|pin|pin.generation),
                "space_name":space_name,
                "vault_mount_ready":ready,
                "vault_mount_writable":false,
                "vault_mount_existing_file_overwrite":overwrite_ready,
                "vault_mount_existing_file_overwrite_reason":overwrite_reason,
                "vault_mount_write_unavailable_reason":if overwrite_ready { Some("offline_existing_file_overwrite_only") } else { overwrite_reason },
                "remembered":remembered,
                "remembered_status":remembered_status,
                "remember_error":remember_error,
            }));
        }
        if offline_list {
            let resource_id = text("root_resource_id")?;
            let scope = self.vault_scope(&origin, space, resource_id)?;
            if !self
                .vaults
                .is_unlocked(&scope)
                .map_err(|_| "Encrypted vault is locked")?
            {
                return Err("Encrypted vault is locked".into());
            }
            let cache = self.open_vault_cache()?;
            let pin_id = request
                .get("pin_id")
                .map(|value| value.as_str().ok_or("pin_id must be a string"))
                .transpose()?;
            let offline_cache = match pin_id {
                Some(pin_id) => {
                    VaultOfflineCache::new_for_pin(cache.clone(), scope.clone(), "/", pin_id)
                }
                None => VaultOfflineCache::new(cache.clone(), scope.clone(), "/"),
            }
            .map_err(|_| "Encrypted offline snapshots are unavailable")?;
            let mut envelope = offline_cache
                .open_root_envelope()
                .map_err(|_| "Encrypted offline snapshots are unavailable")?;
            let (snapshot, _) = raiun_vault::sealed_cache::open_snapshot(
                &self.vaults,
                &scope,
                &mut envelope,
                raiun_vault::sealed_cache::MAX_CIPHERTEXT_BYTES,
            )
            .map_err(|_| "Encrypted offline root metadata could not be verified")?;
            let root_path = snapshot.root_path.clone();
            let backend = if let Some(pin_id) = pin_id {
                VaultBackend::new_from_cached_root(
                    client,
                    self.vaults.clone(),
                    scope.clone(),
                    root_path,
                    VaultOfflineCache::new_for_pin(
                        cache,
                        scope,
                        snapshot.root_path.clone(),
                        pin_id,
                    )
                    .map_err(|_| "Encrypted offline snapshots are unavailable")?,
                    snapshot,
                )
            } else {
                VaultBackend::new_from_cached_root(
                    client,
                    self.vaults.clone(),
                    scope.clone(),
                    root_path,
                    VaultOfflineCache::new(cache, scope, snapshot.root_path.clone())
                        .map_err(|_| "Encrypted offline snapshots are unavailable")?,
                    snapshot,
                )
            }
            .map_err(|_| "Encrypted offline root metadata could not be verified")?;
            let mut entries = Vec::new();
            backend
                .list(space, text("path")?, &mut |entry| {
                    entries.push(entry);
                    Ok(())
                })
                .map_err(|_| "Encrypted offline directory is not cached")?;
            self.check_vault_generation(generation)?;
            return Ok(json!(entries));
        }
        let root_path = text("root_path")?;
        let listing = VaultMetadataClient::new(&client)
            .inspect_vault(space, root_path)
            .map_err(|e| e.to_string())?;
        self.check_vault_generation(generation)?;
        if let Some(expected) = request.get("root_resource_id").and_then(Value::as_str) {
            if expected != listing.root.id {
                return Err("Vault root changed; select it again before unlocking".into());
            }
        } else if action != "vault_inspect" {
            return Err("Missing root_resource_id".into());
        }
        let scope = self.vault_scope(&origin, space, &listing.root.id)?;
        match action {
            "vault_inspect" => {
                let (mount_writable, write_unavailable_reason) =
                    self.vault_mount_writable(space, root_path, &listing.root.id)?;
                Ok(json!({
                    "root_path":listing.root_path, "root_resource_id":listing.root.id,
                    // A current server revision hint for conditional copy admission.
                    // The copy backend revalidates it before writing; this is not
                    // cryptographic proof or a promise that the root stays unchanged.
                    "root_etag":listing.root.strong_etag,
                    "unlocked":self.vaults.is_unlocked(&scope).map_err(|e| e.to_string())?,
                    "vault_mount_ready":self.vault_mount_ready(space, root_path, &listing.root.id)?,
                    "vault_mount_writable":mount_writable,
                    "vault_mount_write_unavailable_reason":write_unavailable_reason,
                    "remembered_status":remembered_status(&scope),
                    "initialized":listing.integrity_token.is_some(),
                    "writable":listing.root.writable,
                }))
            }
            "vault_unlock" => {
                let remember = request
                    .get("remember")
                    .map(|value| value.as_bool().ok_or("remember must be a boolean"))
                    .transpose()?
                    .unwrap_or(false);
                let use_saved = request
                    .get("use_saved")
                    .map(|value| value.as_bool().ok_or("use_saved must be a boolean"))
                    .transpose()?
                    .unwrap_or(false);
                if remember && use_saved {
                    return Err("Choose either a new password or the saved password".into());
                }
                if use_saved && password.is_some() {
                    return Err("A password cannot be combined with use_saved".into());
                }
                let mut bytes = if use_saved {
                    match credential_store.load(&scope) {
                        Ok(Some(password)) => {
                            record_status(&scope, RememberedStatus::KnownSaved);
                            password
                        }
                        Ok(None) => {
                            record_status(&scope, RememberedStatus::NotSaved);
                            return Err("No remembered password is available for this vault".into());
                        }
                        Err(error) => {
                            record_status(&scope, RememberedStatus::Unavailable);
                            return Err(error);
                        }
                    }
                } else {
                    let secret = password.as_mut().ok_or("Missing password")?;
                    let bytes = Zeroizing::new(secret.as_bytes().to_vec());
                    secret.zeroize();
                    bytes
                };
                if bytes.is_empty() || bytes.len() > 4096 {
                    bytes.zeroize();
                    return Err("Password must contain 1–4096 UTF-8 bytes".into());
                }
                // `VaultSessionCoordinator::unlock` wipes its input buffer on
                // every path. Preserve an isolated, zeroizing copy only when
                // the user explicitly opted in, and save it after the exact
                // remote token and unlocked route have both been verified.
                let remember_bytes = remember.then(|| Zeroizing::new(bytes.to_vec()));
                let token = listing
                    .integrity_token
                    .as_deref()
                    .ok_or("This vault has no integrity token; it cannot be unlocked")?;
                self.vaults
                    .unlock(&scope, &mut bytes, token)
                    .map_err(|e| e.to_string())?;
                let publish_status = match self.publish_unlocked_mount_route(
                    &client,
                    &origin,
                    &self.vault_account_id,
                    space,
                    root_path,
                    &listing.root.id,
                ) {
                    Ok(mounted) => mounted,
                    Err(error) => {
                        self.revoke_vault_route_and_lock(&scope)?;
                        return Err(error);
                    }
                };
                if let Err(error) = self.check_vault_generation(generation) {
                    self.revoke_vault_route_and_lock(&scope)?;
                    return Err(error);
                }
                self.wake.store(true, Ordering::Release);
                let (mounted_writable, status_reason) =
                    self.vault_mount_writable(space, root_path, &listing.root.id)?;
                let write_unavailable_reason = match status_reason {
                    Some(reason @ ("drive_not_mounted" | "private_spool_unavailable")) => {
                        Some(reason)
                    }
                    _ => publish_status.1.or(status_reason),
                };
                let mut remembered = use_saved;
                let remember_error = if let Some(password) = remember_bytes.as_deref() {
                    match credential_store.store(&scope, password) {
                        Ok(()) => {
                            remembered = true;
                            record_status(&scope, RememberedStatus::KnownSaved);
                            None
                        }
                        Err(_) => {
                            record_status(&scope, RememberedStatus::Unavailable);
                            Some("secure_store_unavailable")
                        }
                    }
                } else {
                    None
                };
                bytes.zeroize();
                let remembered_status = remembered_status(&scope);
                Ok(json!({
                    "unlocked":true,
                    "vault_mount_ready":true,
                    "vault_mount_writable":mounted_writable,
                    "vault_mount_write_unavailable_reason": if mounted_writable { None } else { write_unavailable_reason },
                    "remembered":remembered,
                    "remembered_status":remembered_status,
                    "remember_error":remember_error,
                }))
            }
            "vault_list" => {
                // Listing through the dialog must populate the same sealed
                // ciphertext cache used by the mounted route. The cache is
                // optional for online use: a local cache setup failure must
                // not prevent a successful remote listing.
                let cached_backend = self.open_vault_cache().ok().and_then(|cache| {
                    VaultOfflineCache::new(cache, scope.clone(), root_path.to_owned())
                        .ok()
                        .and_then(|offline_cache| {
                            VaultBackend::new_with_offline_cache(
                                client.clone(),
                                self.vaults.clone(),
                                scope.clone(),
                                root_path.to_owned(),
                                offline_cache,
                            )
                            .ok()
                        })
                });
                let backend = match cached_backend {
                    Some(backend) => backend,
                    None => {
                        VaultBackend::new(client, self.vaults.clone(), scope, root_path.to_owned())
                            .map_err(|e| e.to_string())?
                    }
                };
                let mut entries = Vec::new();
                backend
                    .list(space, text("path")?, &mut |entry| {
                        entries.push(entry);
                        Ok(())
                    })
                    .map_err(|e| e.to_string())?;
                self.check_vault_generation(generation)?;
                Ok(json!(entries))
            }
            _ => Err("Unknown vault action".into()),
        }
    }

    fn check_vault_generation(&self, generation: u64) -> Result<(), String> {
        if self.shutdown.load(Ordering::Acquire)
            || self.auth_transition.load(Ordering::Acquire)
            || self.auth_generation.load(Ordering::Acquire) != generation
        {
            Err("Vault operation was canceled by an account or shutdown change".into())
        } else {
            Ok(())
        }
    }
}

fn ciphertext_pin_state_name(state: CiphertextPinState) -> &'static str {
    match state {
        CiphertextPinState::Building => "building",
        CiphertextPinState::Ready => "ready",
        CiphertextPinState::Stale => "stale",
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RouteError {
    Unavailable,
    Ambiguous,
}

fn copy_verify_generation_is_current(expected: u64, current: u64) -> bool {
    expected == current
}

fn valid_copy_write_id(write_id: &str) -> bool {
    write_id.len() == 32
        && write_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn copy_verify_source_route_error(
    destination: &VaultSessionScope,
    source: &raiun_opencloud::vault_cache::VaultCopySourceTarget,
    registered_root_path: Option<&str>,
    source_unlocked: bool,
) -> Option<&'static str> {
    if source.scope.account_id() != destination.account_id()
        || source.scope.server_origin() != destination.server_origin()
    {
        return Some("scope_changed");
    }
    let Some(registered_root_path) = registered_root_path else {
        return Some("missing_source");
    };
    if registered_root_path != source.root_path {
        return Some("scope_changed");
    }
    if !source_unlocked {
        return Some("locked");
    }
    None
}

fn copy_verify_reason(
    reason: raiun_opencloud::vault_backend::VaultCopyResolutionReason,
) -> CopyVerifyReviewReason {
    use raiun_opencloud::vault_backend::VaultCopyResolutionReason as R;
    match reason {
        R::LegacySourceBindingUnavailable => CopyVerifyReviewReason::LegacyBindingUnavailable,
        R::CopyWasNeverAttempted => CopyVerifyReviewReason::NeverAttempted,
        R::SourceScopeMismatch => CopyVerifyReviewReason::SourceScopeMismatch,
        R::SourceChanged => CopyVerifyReviewReason::SourceChanged,
        R::DestinationChanged => CopyVerifyReviewReason::DestinationChanged,
        R::ContentMismatch => CopyVerifyReviewReason::ContentMismatch,
        R::AuthenticationGenerationChanged => {
            CopyVerifyReviewReason::AuthenticationGenerationChanged
        }
        R::VerificationUnavailable => CopyVerifyReviewReason::VerificationUnavailable,
    }
}

fn copy_producer_job_status(
    status: &crate::vault_edit_jobs::VaultEditReconcileStatus,
    auth_generation: u64,
) -> Value {
    let binding_valid = status.write_id.as_deref().is_some_and(valid_copy_write_id)
        && status
            .operation_revision
            .is_some_and(|revision| revision > 0);
    let state = match status.state.as_str() {
        "queued" => "queued",
        "running" => "running",
        "complete" if binding_valid => "copied",
        "cancelled" => "cancelled",
        "failed"
            if matches!(
                status.failure_class,
                Some(VaultEditFailureClass::CopyNeedsReview(_))
            ) =>
        {
            "needs_review"
        }
        _ => "failed",
    };
    let mut value = json!({
        "job_id":status.job_id,
        "auth_generation":auth_generation,
        "state":state,
        "cancel_requested":status.cancel_requested,
    });
    // This is the historical durable binding published by the backend. A
    // successful copy may already have retired its journal row.
    if binding_valid
        && let (Some(id), Some(revision)) = (&status.write_id, status.operation_revision)
    {
        value["write_id"] = json!(id);
        value["revision"] = json!(revision);
    }
    value
}

fn copy_verify_job_status(
    status: &crate::vault_edit_jobs::VaultEditReconcileStatus,
    auth_generation: u64,
) -> Value {
    let (state, reason) = match status.state.as_str() {
        "queued" => ("queued", None),
        "running" => ("running", None),
        "complete" => ("verified", None),
        "cancelled" => ("cancelled", None),
        "failed" => match status.failure_class {
            Some(VaultEditFailureClass::CopyNeedsReview(reason)) => ("needs_review", Some(reason)),
            _ => ("failed", None),
        },
        _ => ("failed", None),
    };
    let mut value = json!({
        "job_id":status.job_id,
        "auth_generation":auth_generation,
        "state":state,
        "cancel_requested":status.cancel_requested,
    });
    if let Some(reason) = reason {
        value["reason"] = serde_json::to_value(reason).unwrap_or(Value::Null);
    }
    value
}

fn vault_pending_operation_name(operation: VaultPendingOperationKind) -> &'static str {
    match operation {
        VaultPendingOperationKind::Overwrite => "overwrite",
        VaultPendingOperationKind::CreateFile => "create_file",
        VaultPendingOperationKind::RenameFile => "rename_file",
        VaultPendingOperationKind::DeleteFile => "delete_file",
        VaultPendingOperationKind::CreateDirectory => "create_directory",
        VaultPendingOperationKind::CopyFile => "copy_file",
    }
}

fn vault_pending_operation_state_name(state: raiun_cache::CiphertextWriteState) -> &'static str {
    match state {
        raiun_cache::CiphertextWriteState::Building => "building",
        raiun_cache::CiphertextWriteState::Pending => "pending",
        raiun_cache::CiphertextWriteState::NeverAttempted => "queued",
        raiun_cache::CiphertextWriteState::Attempting => "uncertain",
        raiun_cache::CiphertextWriteState::RecoveryAttempting
        | raiun_cache::CiphertextWriteState::RecoveryRetrying => "uncertain",
        raiun_cache::CiphertextWriteState::Uncertain => "uncertain",
        raiun_cache::CiphertextWriteState::Conflict => "conflict",
        raiun_cache::CiphertextWriteState::CommittedReceipt
        | raiun_cache::CiphertextWriteState::CancelledReceipt
        | raiun_cache::CiphertextWriteState::AcknowledgedReceipt => "internal",
    }
}

fn vault_retry_state_from_name(value: &str) -> Option<raiun_cache::CiphertextWriteState> {
    match value {
        "attempting" => Some(raiun_cache::CiphertextWriteState::Attempting),
        "recovery_attempting" => Some(raiun_cache::CiphertextWriteState::RecoveryAttempting),
        "recovery_retrying" => Some(raiun_cache::CiphertextWriteState::RecoveryRetrying),
        _ => None,
    }
}

fn vault_retry_state_name(state: raiun_cache::CiphertextWriteState) -> &'static str {
    match state {
        raiun_cache::CiphertextWriteState::Attempting => "attempting",
        raiun_cache::CiphertextWriteState::RecoveryAttempting => "recovery_attempting",
        raiun_cache::CiphertextWriteState::RecoveryRetrying => "recovery_retrying",
        _ => "",
    }
}

fn vault_pending_operation_attention_reason(
    operation: VaultPendingOperationKind,
    state: raiun_cache::CiphertextWriteState,
) -> Option<&'static str> {
    match (operation, state) {
        (
            VaultPendingOperationKind::CopyFile,
            raiun_cache::CiphertextWriteState::Building
            | raiun_cache::CiphertextWriteState::Pending
            | raiun_cache::CiphertextWriteState::NeverAttempted
            | raiun_cache::CiphertextWriteState::Attempting
            | raiun_cache::CiphertextWriteState::RecoveryAttempting
            | raiun_cache::CiphertextWriteState::RecoveryRetrying
            | raiun_cache::CiphertextWriteState::Uncertain
            | raiun_cache::CiphertextWriteState::Conflict,
        ) => Some("copy_file_requires_review"),
        (
            VaultPendingOperationKind::CreateDirectory,
            raiun_cache::CiphertextWriteState::Attempting,
        ) => Some("directory_create_attempt_interrupted"),
        (VaultPendingOperationKind::CreateFile, raiun_cache::CiphertextWriteState::Attempting) => {
            Some("file_create_attempt_interrupted")
        }
        (
            VaultPendingOperationKind::CreateFile,
            raiun_cache::CiphertextWriteState::RecoveryAttempting
            | raiun_cache::CiphertextWriteState::RecoveryRetrying,
        ) => Some("file_create_recovery_interrupted"),
        _ => None,
    }
}

fn vault_pending_operation_retry_state(
    operation: VaultPendingOperationKind,
    state: raiun_cache::CiphertextWriteState,
) -> Option<&'static str> {
    if operation != VaultPendingOperationKind::CreateFile {
        return None;
    }
    match state {
        raiun_cache::CiphertextWriteState::Attempting => Some("attempting"),
        raiun_cache::CiphertextWriteState::RecoveryAttempting => Some("recovery_attempting"),
        raiun_cache::CiphertextWriteState::RecoveryRetrying => Some("recovery_retrying"),
        _ => None,
    }
}

fn vault_pending_operation_can_retry_interrupted_create(
    operation: VaultPendingOperationKind,
    state: raiun_cache::CiphertextWriteState,
) -> bool {
    vault_pending_operation_retry_state(operation, state).is_some()
}

fn vault_pending_operation_status_fields(
    operation: VaultPendingOperationKind,
    state: raiun_cache::CiphertextWriteState,
    retry_job_active: bool,
) -> (bool, Option<&'static str>, Option<&'static str>, bool) {
    let attention_reason = vault_pending_operation_attention_reason(operation, state);
    let retry_state = vault_pending_operation_retry_state(operation, state);
    let can_retry_interrupted_create =
        vault_pending_operation_can_retry_interrupted_create(operation, state) && !retry_job_active;
    (
        attention_reason.is_some(),
        attention_reason,
        retry_state,
        can_retry_interrupted_create,
    )
}

#[allow(clippy::too_many_arguments)]
fn vault_retry_job_matches_operation(
    state: &str,
    operation: Option<&str>,
    job_write_id: Option<&str>,
    job_revision: Option<u64>,
    job_retry_generation: Option<u64>,
    write_id: &str,
    revision: u64,
    current_retry_generation: u64,
) -> bool {
    matches!(state, "queued" | "running")
        && operation == Some("create_file")
        && job_write_id == Some(write_id)
        && job_revision == Some(revision)
        && job_retry_generation.is_some_and(|generation| {
            generation == current_retry_generation
                || generation.checked_add(1) == Some(current_retry_generation)
        })
}

fn is_internal_vault_receipt(
    operation: VaultPendingOperationKind,
    state: raiun_cache::CiphertextWriteState,
) -> bool {
    (operation == VaultPendingOperationKind::CreateDirectory
        && state == raiun_cache::CiphertextWriteState::CommittedReceipt)
        || (operation == VaultPendingOperationKind::CreateFile
            && state == raiun_cache::CiphertextWriteState::CancelledReceipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::{
        io::{Cursor, Read, Write},
        net::{TcpListener, TcpStream},
        sync::atomic::{AtomicUsize, Ordering as AtomicOrdering},
        thread::{self, JoinHandle},
        time::Duration,
    };

    struct LoopbackRequestMonitor {
        count: Arc<AtomicUsize>,
        stop: Arc<AtomicBool>,
        worker: Option<JoinHandle<()>>,
    }

    impl LoopbackRequestMonitor {
        fn start(listener: &TcpListener) -> Self {
            let listener = listener.try_clone().unwrap();
            let count = Arc::new(AtomicUsize::new(0));
            let stop = Arc::new(AtomicBool::new(false));
            let worker_count = Arc::clone(&count);
            let worker_stop = Arc::clone(&stop);
            let worker = thread::spawn(move || {
                while !worker_stop.load(AtomicOrdering::Acquire) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            worker_count.fetch_add(1, AtomicOrdering::AcqRel);
                            let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
                            let mut request = [0_u8; 2048];
                            let _ = stream.read(&mut request);
                            let response = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                            let _ = stream.write_all(response);
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(2));
                        }
                        Err(_) => break,
                    }
                }
            });
            Self {
                count,
                stop,
                worker: Some(worker),
            }
        }

        fn count(&self) -> usize {
            self.count.load(AtomicOrdering::Acquire)
        }
    }

    impl Drop for LoopbackRequestMonitor {
        fn drop(&mut self) {
            self.stop.store(true, AtomicOrdering::Release);
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }

    #[test]
    fn copy_verify_ipc_fences_generation_scope_route_and_unlock_state() {
        let destination =
            VaultSessionScope::new("account", "https://cloud.example", "dest", "root-d").unwrap();
        let source = raiun_opencloud::vault_cache::VaultCopySourceTarget {
            scope: VaultSessionScope::new("account", "https://cloud.example", "source", "root-s")
                .unwrap(),
            root_path: "/Source.vault".into(),
        };
        assert!(copy_verify_generation_is_current(42, 42));
        assert!(!copy_verify_generation_is_current(41, 42));
        assert!(valid_copy_write_id(&"a1".repeat(16)));
        assert!(!valid_copy_write_id("../not-a-write-id"));
        assert_eq!(
            copy_verify_source_route_error(&destination, &source, Some("/Source.vault"), true,),
            None
        );
        assert_eq!(
            copy_verify_source_route_error(&destination, &source, Some("/Other.vault"), true),
            Some("scope_changed")
        );
        assert_eq!(
            copy_verify_source_route_error(&destination, &source, None, true),
            Some("missing_source")
        );
        assert_eq!(
            copy_verify_source_route_error(&destination, &source, Some("/Source.vault"), false,),
            Some("locked")
        );
        let wrong_account = raiun_opencloud::vault_cache::VaultCopySourceTarget {
            scope: VaultSessionScope::new(
                "other-account",
                "https://cloud.example",
                "source",
                "root-s",
            )
            .unwrap(),
            root_path: "/Source.vault".into(),
        };
        assert_eq!(
            copy_verify_source_route_error(
                &destination,
                &wrong_account,
                Some("/Source.vault"),
                true,
            ),
            Some("scope_changed")
        );
    }

    #[test]
    fn copy_verify_start_ipc_returns_fixed_rejections_before_admission() {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let runtime = runtime(dir.path().to_path_buf());
        let scope = seed_offline_vault(&runtime);
        let credentials = MockVaultCredentials::default();
        let request = |expected_generation| {
            json!({
                "action":"vault_copy_verify_start",
                "space_id":"space-a",
                "root_resource_id":"root-a",
                "write_id":"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "revision":3,
                "expected_generation":expected_generation
            })
        };

        let stale = runtime
            .handle_vault_with_store(request(8), None, &credentials)
            .unwrap();
        assert_eq!(stale, json!({"accepted":false,"error":"stale_generation"}));

        let locked = runtime
            .handle_vault_with_store(request(7), None, &credentials)
            .unwrap();
        assert_eq!(locked, json!({"accepted":false,"error":"locked"}));

        let token = include_str!("../../raiun-vault/tests/fixtures/web-integrity-token.b64").trim();
        let mut password = b"potato".to_vec();
        runtime.vaults.unlock(&scope, &mut password, token).unwrap();
        let missing_route = runtime
            .handle_vault_with_store(request(7), None, &credentials)
            .unwrap();
        assert_eq!(
            missing_route,
            json!({"accepted":false,"error":"scope_changed"})
        );
        assert!(
            runtime
                .vault_edit_reconcile_jobs
                .latest(&scope, 7)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn copy_verify_status_is_a_minimal_allowlisted_projection() {
        let mut status = crate::vault_edit_jobs::VaultEditReconcileStatus {
            generation: 4,
            job_id: "opaque-job".into(),
            space_id: "private-space".into(),
            root_resource_id: "private-root".into(),
            operation: Some("copy_verify".into()),
            write_id: Some("private-write".into()),
            operation_revision: Some(3),
            retry_generation: None,
            automatic: false,
            state: "failed".into(),
            processed: 0,
            uploaded: 0,
            conflicts: 0,
            remaining: 0,
            error: Some("must never reach IPC".into()),
            failure_class: Some(VaultEditFailureClass::CopyNeedsReview(
                CopyVerifyReviewReason::SourceChanged,
            )),
            cancel_requested: false,
        };
        let response = copy_verify_job_status(&status, 4);
        assert_eq!(response["state"], "needs_review");
        assert_eq!(response["reason"], "source_changed");
        assert_eq!(response["auth_generation"], 4);
        assert_eq!(response.as_object().unwrap().len(), 5);
        assert!(response.get("error").is_none());
        assert!(response.get("write_id").is_none());
        assert!(response.get("root_resource_id").is_none());

        status.failure_class = None;
        status.state = "complete".into();
        let verified = copy_verify_job_status(&status, 4);
        assert_eq!(verified["state"], "verified");
        assert!(verified.get("reason").is_none());
        assert_eq!(verified.as_object().unwrap().len(), 4);
    }

    #[test]
    fn copy_start_rejects_stale_locked_and_missing_routes_before_network_or_admission() {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let runtime = runtime(dir.path().to_path_buf());
        // Retain the normal synthetic offline fixture setup, then point only
        // the authenticated test client at a local listener that can prove
        // rejection did not issue a remote request.
        let _seeded = seed_offline_vault(&runtime);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let request_monitor = LoopbackRequestMonitor::start(&listener);
        let server = format!("http://{}", listener.local_addr().unwrap());
        let client = OpenCloudClient::new(&server, "synthetic-token".into()).unwrap();
        let origin = client.server_origin().unwrap();
        {
            runtime.settings.lock().unwrap().server = Some(server.clone());
            let mut auth = runtime.auth_state.lock().unwrap();
            auth.session.as_mut().unwrap().server = server;
            auth.client = Some(client);
        }

        let destination = VaultSessionScope::new(
            &runtime.vault_account_id,
            &origin,
            "destination-space",
            "destination-root",
        )
        .unwrap();
        let source = VaultSessionScope::new(
            &runtime.vault_account_id,
            &origin,
            "source-space",
            "source-root",
        )
        .unwrap();
        let request = |expected_generation| {
            json!({
                "action":"vault_copy_start",
                "space_id":destination.space_id(),
                "root_resource_id":destination.resource_id(),
                "source_space_id":source.space_id(),
                "source_root_resource_id":source.resource_id(),
                "source_path":"folder/file.bin",
                "source_resource_id":"source-file-id",
                "source_etag":"\"source-etag\"",
                "destination_path":"folder/copy.bin",
                "destination_parent_resource_id":"destination-folder-id",
                "destination_parent_etag":"\"destination-etag\"",
                "expected_generation":expected_generation
            })
        };
        let credentials = MockVaultCredentials::default();

        let stale = runtime
            .handle_vault_with_store(request(6), None, &credentials)
            .unwrap();
        assert_eq!(stale, json!({"accepted":false,"error":"stale_generation"}));
        assert!(
            runtime
                .vault_edit_reconcile_jobs
                .latest(&destination, 7)
                .unwrap()
                .is_none()
        );

        let locked = runtime
            .handle_vault_with_store(request(7), None, &credentials)
            .unwrap();
        assert_eq!(locked, json!({"accepted":false,"error":"locked"}));
        assert!(
            runtime
                .vault_edit_reconcile_jobs
                .latest(&destination, 7)
                .unwrap()
                .is_none()
        );

        let token = include_str!("../../raiun-vault/tests/fixtures/web-integrity-token.b64").trim();
        for scope in [&source, &destination] {
            let mut password = b"potato".to_vec();
            runtime.vaults.unlock(scope, &mut password, token).unwrap();
        }
        let missing_route = runtime
            .handle_vault_with_store(request(7), None, &credentials)
            .unwrap();
        assert_eq!(
            missing_route,
            json!({"accepted":false,"error":"scope_changed"})
        );
        assert!(
            runtime
                .vault_edit_reconcile_jobs
                .latest(&destination, 7)
                .unwrap()
                .is_none()
        );
        assert!(
            runtime
                .vault_edit_reconcile_jobs
                .latest(&source, 7)
                .unwrap()
                .is_none()
        );

        // Allow a short bounded settling interval to catch accidental client
        // use even if it were scheduled asynchronously after the IPC response.
        thread::sleep(Duration::from_millis(25));
        assert_eq!(request_monitor.count(), 0);
    }

    #[test]
    fn copy_status_publishes_only_real_binding_and_wrong_class_cancel_is_inert() {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let runtime = runtime(dir.path().to_path_buf());
        let destination = seed_offline_vault(&runtime);
        let source = VaultSessionScope::new(
            &runtime.vault_account_id,
            destination.server_origin(),
            "source-space",
            "source-root",
        )
        .unwrap();
        let (release, start_gate) = std::sync::mpsc::channel();
        let (published_tx, published_rx) = std::sync::mpsc::channel();
        let queued = crate::vault_edit_jobs::VaultEditReconcileJobs::start_copy_producer(
            &runtime.vault_edit_reconcile_jobs,
            crate::vault_edit_jobs::CopyProducerJobSpec {
                destination: &destination,
                source: &source,
                auth_generation: Arc::clone(&runtime.auth_generation),
                expected_generation: 7,
                pin_jobs: Arc::clone(&runtime.vault_pin_jobs),
                start_gate,
            },
            move |cancelled, _progress, publish_binding| {
                publish_binding("ab0123456789abcdef0123456789abcd", 12)?;
                published_tx.send(()).unwrap();
                while !cancelled.load(AtomicOrdering::Acquire) {
                    thread::yield_now();
                }
                Err(crate::vault_edit_jobs::VaultEditJobFailure::unclassified(
                    "synthetic copy cancelled after durable queue",
                ))
            },
        )
        .unwrap();
        let credentials = MockVaultCredentials::default();
        let status_request = |action: &str| {
            json!({
                "action":action,
                "space_id":destination.space_id(),
                "root_resource_id":destination.resource_id(),
                "job_id":queued.job_id,
                "expected_generation":7
            })
        };

        let before = runtime
            .handle_vault_with_store(status_request("vault_copy_status"), None, &credentials)
            .unwrap();
        assert_eq!(before["state"], "queued");
        assert!(before.get("write_id").is_none());
        assert!(before.get("revision").is_none());
        assert!(before.get("error").is_none());
        assert_eq!(before.as_object().unwrap().len(), 4);

        release.send(()).unwrap();
        published_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let after = runtime
            .handle_vault_with_store(status_request("vault_copy_status"), None, &credentials)
            .unwrap();
        assert_eq!(after["state"], "running");
        assert_eq!(after["write_id"], "ab0123456789abcdef0123456789abcd");
        assert_eq!(after["revision"], 12);
        assert!(after.get("error").is_none());
        assert_eq!(after.as_object().unwrap().len(), 6);

        assert!(
            runtime
                .handle_vault_with_store(
                    json!({
                        "action":"vault_reconcile_edits_cancel",
                        "space_id":destination.space_id(),
                        "root_resource_id":destination.resource_id(),
                        "job_id":queued.job_id
                    }),
                    None,
                    &credentials,
                )
                .is_err()
        );
        let still_running = runtime
            .handle_vault_with_store(status_request("vault_copy_status"), None, &credentials)
            .unwrap();
        assert_eq!(still_running["cancel_requested"], false);

        let cancel = runtime
            .handle_vault_with_store(status_request("vault_copy_cancel"), None, &credentials)
            .unwrap();
        assert_eq!(cancel["cancel_requested"], true);
        runtime
            .vault_edit_reconcile_jobs
            .cancel_scope_and_wait(&destination)
            .unwrap();
        let terminal = runtime
            .handle_vault_with_store(status_request("vault_copy_status"), None, &credentials)
            .unwrap();
        assert_eq!(terminal["state"], "cancelled");
        assert_eq!(terminal["write_id"], "ab0123456789abcdef0123456789abcd");
        assert_eq!(terminal["revision"], 12);
    }

    #[test]
    fn copy_status_maps_unbound_success_to_failed_without_synthetic_binding() {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let runtime = runtime(dir.path().to_path_buf());
        let destination = seed_offline_vault(&runtime);
        let source = VaultSessionScope::new(
            &runtime.vault_account_id,
            destination.server_origin(),
            "source-space",
            "source-root",
        )
        .unwrap();
        let (release, start_gate) = std::sync::mpsc::channel();
        let queued = crate::vault_edit_jobs::VaultEditReconcileJobs::start_copy_producer(
            &runtime.vault_edit_reconcile_jobs,
            crate::vault_edit_jobs::CopyProducerJobSpec {
                destination: &destination,
                source: &source,
                auth_generation: Arc::clone(&runtime.auth_generation),
                expected_generation: 7,
                pin_jobs: Arc::clone(&runtime.vault_pin_jobs),
                start_gate,
            },
            |_cancelled, _progress, _publish_binding| {
                Ok(crate::vault_edit_jobs::VaultEditReconcileReport {
                    processed: 1,
                    uploaded: 1,
                    conflicts: 0,
                    remaining: 0,
                })
            },
        )
        .unwrap();
        release.send(()).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let status = runtime
                .vault_edit_reconcile_jobs
                .status(&destination, &queued.job_id, 7)
                .unwrap();
            if status.state == "failed" {
                break;
            }
            assert!(std::time::Instant::now() < deadline);
            thread::yield_now();
        }
        let response = runtime
            .handle_vault_with_store(
                json!({
                    "action":"vault_copy_status",
                    "space_id":destination.space_id(),
                    "root_resource_id":destination.resource_id(),
                    "job_id":queued.job_id,
                    "expected_generation":7
                }),
                None,
                &MockVaultCredentials::default(),
            )
            .unwrap();
        assert_eq!(response["state"], "failed");
        assert!(response.get("write_id").is_none());
        assert!(response.get("revision").is_none());
        assert_eq!(response.as_object().unwrap().len(), 4);
    }

    #[test]
    fn wrong_edit_cancel_class_does_not_cancel_copy_verification_job() {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let runtime = runtime(dir.path().to_path_buf());
        let destination = seed_offline_vault(&runtime);
        let source = VaultSessionScope::new(
            "test-account",
            "https://cloud.example.test",
            "source-space",
            "source-root",
        )
        .unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let job = crate::vault_edit_jobs::VaultEditReconcileJobs::start_copy_verification(
            &runtime.vault_edit_reconcile_jobs,
            crate::vault_edit_jobs::CopyVerificationJobSpec {
                destination: &destination,
                source: Some(&source),
                auth_generation: Arc::clone(&runtime.auth_generation),
                expected_generation: 7,
                pin_jobs: Arc::clone(&runtime.vault_pin_jobs),
                binding: crate::vault_edit_jobs::VaultEditOperationBinding {
                    operation: "copy_verify".into(),
                    write_id: "ab".repeat(16),
                    revision: 5,
                    retry_generation: None,
                },
            },
            move |cancelled, _progress| {
                started_tx.send(()).unwrap();
                while !cancelled.load(AtomicOrdering::Acquire) {
                    thread::yield_now();
                }
                Err(crate::vault_edit_jobs::VaultEditJobFailure::unclassified(
                    "synthetic verification cancellation",
                ))
            },
        )
        .unwrap();
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();

        let credentials = MockVaultCredentials::default();
        let wrong_class = runtime.handle_vault_with_store(
            json!({
                "action":"vault_reconcile_edits_cancel",
                "space_id":destination.space_id(),
                "root_resource_id":destination.resource_id(),
                "job_id":job.job_id
            }),
            None,
            &credentials,
        );
        assert!(wrong_class.is_err());
        let still_running = runtime
            .vault_edit_reconcile_jobs
            .status(&destination, &job.job_id, 7)
            .unwrap();
        assert_eq!(still_running.state, "running");
        assert!(!still_running.cancel_requested);

        let right_class = runtime
            .handle_vault_with_store(
                json!({
                    "action":"vault_copy_verify_cancel",
                    "space_id":destination.space_id(),
                    "root_resource_id":destination.resource_id(),
                    "job_id":job.job_id,
                    "expected_generation":7
                }),
                None,
                &credentials,
            )
            .unwrap();
        assert!(matches!(
            right_class["state"].as_str(),
            Some("running" | "cancelled")
        ));
        assert_eq!(right_class["cancel_requested"], true);
        runtime
            .vault_edit_reconcile_jobs
            .cancel_scope_and_wait(&destination)
            .unwrap();
        let joined = runtime
            .vault_edit_reconcile_jobs
            .status(&destination, &job.job_id, 7)
            .unwrap();
        assert_eq!(joined.state, "cancelled");
        assert!(joined.cancel_requested);

        let (edit_started_tx, edit_started_rx) = std::sync::mpsc::channel();
        let edit_job =
            crate::vault_edit_jobs::VaultEditReconcileJobs::start_operation_with_failure_class(
                &runtime.vault_edit_reconcile_jobs,
                &destination,
                Arc::clone(&runtime.auth_generation),
                7,
                Arc::clone(&runtime.vault_pin_jobs),
                crate::vault_edit_jobs::VaultEditOperationBinding {
                    operation: "create_file".into(),
                    write_id: "cd".repeat(16),
                    revision: 2,
                    retry_generation: None,
                },
                move |cancelled, _progress| {
                    edit_started_tx.send(()).unwrap();
                    while !cancelled.load(AtomicOrdering::Acquire) {
                        thread::yield_now();
                    }
                    Err(crate::vault_edit_jobs::VaultEditJobFailure::unclassified(
                        "synthetic ordinary edit cancellation",
                    ))
                },
            )
            .unwrap();
        edit_started_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        let wrong_copy_class = runtime.handle_vault_with_store(
            json!({
                "action":"vault_copy_verify_cancel",
                "space_id":destination.space_id(),
                "root_resource_id":destination.resource_id(),
                "job_id":edit_job.job_id,
                "expected_generation":7
            }),
            None,
            &credentials,
        );
        assert!(wrong_copy_class.is_err());
        let ordinary_still_running = runtime
            .vault_edit_reconcile_jobs
            .status(&destination, &edit_job.job_id, 7)
            .unwrap();
        assert_eq!(ordinary_still_running.state, "running");
        assert!(!ordinary_still_running.cancel_requested);

        let ordinary_cancel = runtime
            .handle_vault_with_store(
                json!({
                    "action":"vault_reconcile_edits_cancel",
                    "space_id":destination.space_id(),
                    "root_resource_id":destination.resource_id(),
                    "job_id":edit_job.job_id
                }),
                None,
                &credentials,
            )
            .unwrap();
        assert_eq!(ordinary_cancel["cancel_requested"], true);
        runtime
            .vault_edit_reconcile_jobs
            .cancel_scope_and_wait(&destination)
            .unwrap();
        let ordinary_joined = runtime
            .vault_edit_reconcile_jobs
            .status(&destination, &edit_job.job_id, 7)
            .unwrap();
        assert_eq!(ordinary_joined.state, "cancelled");
        assert!(ordinary_joined.cancel_requested);
    }

    #[test]
    fn committed_directory_receipts_are_internal_not_user_operations() {
        assert!(is_internal_vault_receipt(
            VaultPendingOperationKind::CreateDirectory,
            raiun_cache::CiphertextWriteState::CommittedReceipt,
        ));
        assert!(!is_internal_vault_receipt(
            VaultPendingOperationKind::CreateDirectory,
            raiun_cache::CiphertextWriteState::Pending,
        ));
        assert!(!is_internal_vault_receipt(
            VaultPendingOperationKind::CreateFile,
            raiun_cache::CiphertextWriteState::CommittedReceipt,
        ));
        assert!(is_internal_vault_receipt(
            VaultPendingOperationKind::CreateFile,
            raiun_cache::CiphertextWriteState::CancelledReceipt,
        ));
        assert_eq!(
            vault_pending_operation_state_name(raiun_cache::CiphertextWriteState::CancelledReceipt),
            "internal"
        );
    }

    #[test]
    fn attempting_create_operations_have_distinct_attention_reasons() {
        assert_eq!(
            vault_pending_operation_name(VaultPendingOperationKind::CopyFile),
            "copy_file"
        );
        assert_eq!(
            vault_pending_operation_state_name(raiun_cache::CiphertextWriteState::NeverAttempted),
            "queued"
        );
        assert_eq!(
            vault_pending_operation_state_name(raiun_cache::CiphertextWriteState::Attempting),
            "uncertain"
        );
        assert_eq!(
            vault_pending_operation_attention_reason(
                VaultPendingOperationKind::CreateDirectory,
                raiun_cache::CiphertextWriteState::Attempting,
            ),
            Some("directory_create_attempt_interrupted")
        );
        assert_eq!(
            vault_pending_operation_attention_reason(
                VaultPendingOperationKind::CreateFile,
                raiun_cache::CiphertextWriteState::Attempting,
            ),
            Some("file_create_attempt_interrupted")
        );
        assert_eq!(
            vault_pending_operation_attention_reason(
                VaultPendingOperationKind::Overwrite,
                raiun_cache::CiphertextWriteState::Attempting,
            ),
            None,
            "only CreateFile and CreateDirectory Attempting rows are non-retryable attention states"
        );
        assert_eq!(
            vault_pending_operation_attention_reason(
                VaultPendingOperationKind::CreateDirectory,
                raiun_cache::CiphertextWriteState::Uncertain,
            ),
            None,
            "transport uncertainty remains distinct from a crash-left attempt"
        );
        assert!(!is_internal_vault_receipt(
            VaultPendingOperationKind::CreateDirectory,
            raiun_cache::CiphertextWriteState::NeverAttempted,
        ));
        assert!(!is_internal_vault_receipt(
            VaultPendingOperationKind::CreateDirectory,
            raiun_cache::CiphertextWriteState::Attempting,
        ));
    }

    #[test]
    fn explicit_interrupted_file_create_retry_is_offered_only_for_exact_retryable_states() {
        use raiun_cache::CiphertextWriteState as State;
        assert_eq!(
            vault_pending_operation_retry_state(
                VaultPendingOperationKind::CreateFile,
                State::Attempting
            ),
            Some("attempting")
        );
        assert_eq!(
            vault_pending_operation_retry_state(
                VaultPendingOperationKind::CreateFile,
                State::RecoveryAttempting
            ),
            Some("recovery_attempting")
        );
        assert_eq!(
            vault_pending_operation_retry_state(
                VaultPendingOperationKind::CreateFile,
                State::RecoveryRetrying
            ),
            Some("recovery_retrying"),
            "a retrying row can be offered again only after its bound job is inactive"
        );
        assert_eq!(
            vault_pending_operation_retry_state(
                VaultPendingOperationKind::CreateFile,
                State::Uncertain
            ),
            None,
            "transport uncertainty is not the crash-left create state"
        );
        assert_eq!(
            vault_pending_operation_retry_state(
                VaultPendingOperationKind::Overwrite,
                State::Attempting
            ),
            None,
            "the action is never offered for overwrite rows"
        );
        assert!(vault_pending_operation_can_retry_interrupted_create(
            VaultPendingOperationKind::CreateFile,
            State::Attempting
        ));
        assert!(!vault_pending_operation_can_retry_interrupted_create(
            VaultPendingOperationKind::CreateDirectory,
            State::Attempting
        ));
        assert_eq!(
            vault_pending_operation_attention_reason(
                VaultPendingOperationKind::CreateFile,
                State::RecoveryRetrying
            ),
            Some("file_create_recovery_interrupted")
        );
    }

    #[test]
    fn claimed_copy_crash_and_other_unresolved_states_are_review_only() {
        use raiun_cache::CiphertextWriteState as State;

        for state in [
            State::NeverAttempted,
            State::Attempting,
            State::Uncertain,
            State::Conflict,
        ] {
            let (needs_attention, attention_reason, retry_state, can_retry) =
                vault_pending_operation_status_fields(
                    VaultPendingOperationKind::CopyFile,
                    state,
                    false,
                );
            assert!(needs_attention, "{state:?} copy rows set needs_attention");
            assert_eq!(
                attention_reason,
                Some("copy_file_requires_review"),
                "{state:?} copy rows must be surfaced for review"
            );
            assert_eq!(retry_state, None, "{state:?} copy rows have no retry state");
            assert!(!can_retry, "{state:?} copy rows are never retryable");
        }
    }

    #[test]
    fn explicit_retry_is_hidden_only_for_the_exact_active_create_job() {
        let id = "a1".repeat(16);
        assert!(vault_retry_job_matches_operation(
            "running",
            Some("create_file"),
            Some(&id),
            Some(7),
            Some(3),
            &id,
            7,
            3
        ));
        assert!(!vault_retry_job_matches_operation(
            "running",
            Some("create_file"),
            Some(&id),
            Some(7),
            Some(3),
            &id,
            8,
            3
        ));
        assert!(!vault_retry_job_matches_operation(
            "running",
            Some("overwrite"),
            Some(&id),
            Some(7),
            Some(3),
            &id,
            7,
            3
        ));
        assert!(!vault_retry_job_matches_operation(
            "complete",
            Some("create_file"),
            Some(&id),
            Some(7),
            Some(3),
            &id,
            7,
            3
        ));
        assert!(vault_retry_job_matches_operation(
            "running",
            Some("create_file"),
            Some(&id),
            Some(7),
            Some(3),
            &id,
            7,
            4
        ));
        assert!(!vault_retry_job_matches_operation(
            "running",
            Some("create_file"),
            Some(&id),
            Some(7),
            Some(3),
            &id,
            7,
            5
        ));
    }

    struct InertVaultReadBackend;
    impl raiun_fuse::vault_routes::VaultReadBackend for InertVaultReadBackend {
        fn authorize(&self) -> Result<(), raiun_core::backend::CloudError> {
            Ok(())
        }

        fn list(
            &self,
            _: &str,
        ) -> Result<Vec<raiun_core::backend::RemoteEntry>, raiun_core::backend::CloudError>
        {
            Ok(Vec::new())
        }

        fn stat(
            &self,
            _: &str,
        ) -> Result<raiun_core::backend::RemoteEntry, raiun_core::backend::CloudError> {
            Err(raiun_core::backend::CloudError::new(
                raiun_core::backend::ErrorKind::NotFound,
                "fixture",
            ))
        }

        fn open(
            &self,
            _: &str,
        ) -> Result<
            Box<dyn raiun_fuse::vault_routes::VaultReadStream>,
            raiun_core::backend::CloudError,
        > {
            Ok(Box::new(Cursor::new(Vec::<u8>::new())))
        }
    }

    struct NoopSessionStore;
    impl SessionStore for NoopSessionStore {
        fn save(&self, _: &auth::Session) -> Result<(), String> {
            Ok(())
        }
        fn load(&self, _: &str, _: &str) -> Result<Option<auth::Session>, String> {
            Ok(None)
        }
        fn remove(&self, _: &str, _: &str) -> Result<(), String> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct MockVaultCredentials(Mutex<HashMap<VaultSessionScope, Zeroizing<Vec<u8>>>>);

    impl VaultCredentialStore for MockVaultCredentials {
        fn store(&self, scope: &VaultSessionScope, password: &[u8]) -> Result<(), String> {
            self.0
                .lock()
                .map_err(|_| "mock credential store poisoned")?
                .insert(scope.clone(), Zeroizing::new(password.to_vec()));
            Ok(())
        }

        fn load(&self, scope: &VaultSessionScope) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
            Ok(self
                .0
                .lock()
                .map_err(|_| "mock credential store poisoned")?
                .get(scope)
                .map(|password| Zeroizing::new(password.to_vec())))
        }

        fn remove(
            &self,
            scope: &VaultSessionScope,
        ) -> Result<crate::vault_secrets::CredentialCleanup, String> {
            self.0
                .lock()
                .map_err(|_| "mock credential store poisoned")?
                .remove(scope);
            Ok(crate::vault_secrets::CredentialCleanup::Uncertain)
        }
    }

    struct SyntheticVaultServer {
        origin: String,
        stop: Arc<AtomicBool>,
        worker: Option<JoinHandle<()>>,
    }

    impl SyntheticVaultServer {
        fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let origin = format!("http://{address}");
            let stop = Arc::new(AtomicBool::new(false));
            let worker_stop = Arc::clone(&stop);
            let worker_origin = origin.clone();
            let worker = thread::spawn(move || {
                while !worker_stop.load(AtomicOrdering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => serve_vault_request(stream, &worker_origin),
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(2));
                        }
                        Err(error) => panic!("synthetic vault listener failed: {error}"),
                    }
                }
            });
            Self {
                origin,
                stop,
                worker: Some(worker),
            }
        }
    }

    impl Drop for SyntheticVaultServer {
        fn drop(&mut self) {
            self.stop.store(true, AtomicOrdering::Release);
            if let Some(worker) = self.worker.take() {
                worker.join().unwrap();
            }
        }
    }

    fn serve_vault_request(mut stream: TcpStream, origin: &str) {
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut headers = Vec::new();
        let mut byte = [0];
        while !headers.ends_with(b"\r\n\r\n") {
            if stream.read_exact(&mut byte).is_err() {
                return;
            }
            headers.push(byte[0]);
            assert!(
                headers.len() <= 32 * 1024,
                "synthetic request headers bounded"
            );
        }
        let request = String::from_utf8(headers).unwrap();
        let mut lines = request.lines();
        let mut first_line = lines.next().unwrap_or_default().split_ascii_whitespace();
        let method = first_line.next().unwrap_or_default();
        let target = first_line.next().unwrap_or_default();
        let request_headers: HashMap<_, _> = lines
            .filter_map(|line| {
                let (name, value) = line.split_once(':')?;
                Some((name.to_ascii_lowercase(), value.trim().to_owned()))
            })
            .collect();
        let content_length = request_headers
            .get("content-length")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        assert!(
            content_length <= 64 * 1024,
            "synthetic request body bounded"
        );
        let mut request_body = vec![0; content_length];
        if content_length > 0 {
            stream
                .read_exact(&mut request_body)
                .expect("synthetic fixture must consume the complete HTTP request body");
        }
        if request_headers.get("authorization").map(String::as_str)
            != Some("Bearer synthetic-token")
        {
            write!(
                stream,
                "HTTP/1.1 401 Unauthorized\r\nContent-Length: 12\r\nConnection: close\r\n\r\nunauthorized"
            )
            .unwrap();
            stream.flush().unwrap();
            return;
        }
        let response = if method == "GET" && target == "/graph/v1.0/me/drives" {
            (
                200,
                "application/json",
                format!(
                    r#"{{"value":[{{"id":"space-a","name":"Personal","driveType":"personal","root":{{"id":"space-root","webDavUrl":"{origin}/dav/personal/","permissions":"RDNVW"}}}}]}}"#
                ),
            )
        } else if method == "PROPFIND"
            && target == "/dav/personal/Travel.vault/"
            && request_headers.get("depth").map(String::as_str) == Some("1")
        {
            let token =
                include_str!("../../raiun-vault/tests/fixtures/web-integrity-token.b64").trim();
            (
                207,
                "application/xml",
                format!(
                    r#"<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:ocrclone="ocrclone"><d:response><d:href>{origin}/dav/personal/Travel.vault/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getcontentlength>0</d:getcontentlength><d:getetag>"root-etag"</d:getetag><d:getcontenttype>application/vnd.opencloud.vault</d:getcontenttype><oc:fileid>root-a</oc:fileid><oc:name>Travel.vault</oc:name><oc:size>0</oc:size><oc:permissions>RDNVW</oc:permissions><ocrclone:integrity-id>{token}</ocrclone:integrity-id></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#
                ),
            )
        } else {
            (404, "text/plain", "not found".to_owned())
        };
        write!(
            stream,
            "HTTP/1.1 {} Synthetic\r\nContent-Length: {}\r\nContent-Type: {}\r\nConnection: close\r\n\r\n",
            response.0,
            response.2.len(),
            response.1
        )
        .unwrap();
        stream.write_all(response.2.as_bytes()).unwrap();
        stream.flush().unwrap();
    }

    fn runtime(dir: PathBuf) -> Runtime {
        let server = "https://cloud.example.test".to_owned();
        let client = OpenCloudClient::new(&server, "synthetic-token".into()).unwrap();
        Runtime {
            dir: dir.clone(),
            transfer_budget: Mutex::new(None),
            settings: Mutex::new(Settings {
                config: raiun_core::Config {
                    schema_version: raiun_core::CONFIG_SCHEMA_VERSION,
                    cloud_root: dir.join("cloud"),
                    pairs: Vec::new(),
                },
                server: Some(server.clone()),
                client_id: "test-client".into(),
                account_id: Some("test-account".into()),
                retired_pair_ids: Vec::new(),
                paused: false,
                paused_space_ids: Vec::new(),
                mount_enabled: false,
                media_jobs: Vec::new(),
                network_proxy: raiun_opencloud::ProxyConfig::System,
                network_proxy_account_id: Some("test-account".into()),
                network_proxy_revision: 1,
                bandwidth_limits: raiun_opencloud::transfer_budget::TransferLimits::default(),
                bandwidth_account_id: None,
                bandwidth_revision: 1,
            }),
            auth_state: Mutex::new(AuthState {
                engine: None,
                session: Some(auth::Session {
                    server: server.clone(),
                    client_id: "test-client".into(),
                    access_token: "synthetic-token".into(),
                    refresh_token: None,
                    expires_at: u64::MAX,
                    token_endpoint: format!("{server}/token"),
                    expected_issuer: None,
                    last_refresh_at: None,
                    proxy: raiun_opencloud::ProxyConfig::System,
                }),
                client: Some(client),
                account_id: Some("test-account".into()),
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
            auth_generation: Arc::new(AtomicU64::new(7)),
            restoring: AtomicBool::new(false),
            shutdown: Arc::new(AtomicBool::new(false)),
            auth_transition: Arc::new(AtomicBool::new(false)),
            retiring: AtomicBool::new(false),
            offline_namespace: AtomicBool::new(false),
            offline_namespace_probe_unix: AtomicU64::new(0),
            session_store: Arc::new(NoopSessionStore),
            vaults: Arc::new(raiun_vault::session::VaultSessionCoordinator::new()),
            vault_mounts: raiun_fuse::VaultMountRegistry::new(),
            vault_account_id: "test-account".into(),
            local_profile_id: "test-profile".into(),
            cache_jobs: Arc::new(offline_cache::CacheJobs::default()),
            write_reconcile_jobs: Arc::new(offline_cache::WriteReconcileJobs::default()),
            vault_pin_jobs: Arc::new(vault_pin_jobs::VaultPinJobs::default()),
            vault_edit_reconcile_jobs: Arc::new(
                crate::vault_edit_jobs::VaultEditReconcileJobs::default(),
            ),
            cache_error: Mutex::new(None),
            vault_cleanup_uncertain: AtomicBool::new(false),
        }
    }

    fn seed_offline_vault(runtime: &Runtime) -> VaultSessionScope {
        use raiun_cache::{ContentProtection, ContentVersion, Retention, ScopeProtection};
        use raiun_vault::sealed_cache::{SealedVaultEntry, SealedVaultSnapshot, seal_snapshot};

        let origin = "https://cloud.example.test";
        let scope =
            VaultSessionScope::new(&runtime.vault_account_id, origin, "space-a", "root-a").unwrap();
        let initial_sessions = raiun_vault::session::VaultSessionCoordinator::new();
        let mut password = b"potato".to_vec();
        let token = include_str!("../../raiun-vault/tests/fixtures/web-integrity-token.b64").trim();
        initial_sessions
            .unlock(&scope, &mut password, token)
            .unwrap();
        let encrypted_name = initial_sessions.encrypt_name(&scope, "Memo.txt").unwrap();
        let snapshot = SealedVaultSnapshot {
            integrity_token: token.to_owned(),
            root_etag: Some("\"root-etag\"".into()),
            root_path: "/Travel.vault".into(),
            space_dav_root: format!("{origin}/dav/"),
            space_name: "Personal".into(),
            space_dav_url: format!("{origin}/dav/"),
            space_personal: true,
            space_writable: true,
            space_encrypted: false,
            directory_resource_id: "root-a".into(),
            encrypted_directory_path: String::new(),
            directory_etag: "\"root-etag\"".into(),
            directory_modified_unix: 1,
            directory_writable: true,
            entries: vec![SealedVaultEntry {
                resource_id: "memo-a".into(),
                parent_resource_id: "root-a".into(),
                encrypted_name,
                etag: Some("\"memo-etag\"".into()),
                ciphertext_len: 48,
                directory: false,
                modified_unix: 1,
                writable: true,
            }],
        };

        let settings_account = runtime.settings.lock().unwrap().account_id.clone().unwrap();
        let account_dir = account_engine_dir(&runtime.dir, &settings_account);
        std::fs::create_dir_all(&account_dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&account_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let cache = runtime.open_vault_cache().unwrap();
        let cache_scope = raiun_cache::CacheScope::new(
            origin,
            &runtime.vault_account_id,
            "space-a",
            "root-a",
            ScopeProtection::CiphertextOnly,
        )
        .unwrap();
        let epoch = cache.ciphertext_epoch(&cache_scope).unwrap();
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("sealed-root.bin");
        let info = seal_snapshot(&initial_sessions, &scope, &snapshot, &path).unwrap();
        let mut ciphertext = std::fs::File::open(path).unwrap();
        cache
            .publish_ciphertext_if_epoch(
                &cache_scope,
                &ContentVersion {
                    resource_id: "raiun-vault-listing-v1:root-a".into(),
                    etag: format!("raiun-vault-sealed-metadata-v2:{epoch}"),
                    protection: ContentProtection::Ciphertext,
                },
                &mut ciphertext,
                info.ciphertext_bytes,
                Retention::Recent,
                epoch,
            )
            .unwrap();
        initial_sessions.lock(&scope).unwrap();
        scope
    }

    fn seed_offline_pin(runtime: &Runtime, scope: &VaultSessionScope) -> (String, u64) {
        use raiun_cache::{
            CiphertextPinItemKind, ContentProtection, ContentVersion, ScopeProtection,
        };
        let cache = runtime.open_vault_cache().unwrap();
        let cache_scope = raiun_cache::CacheScope::new(
            scope.server_origin(),
            scope.account_id(),
            scope.space_id(),
            scope.resource_id(),
            ScopeProtection::CiphertextOnly,
        )
        .unwrap();
        let epoch = cache.ciphertext_epoch(&cache_scope).unwrap();
        let source_version = ContentVersion {
            resource_id: format!("raiun-vault-listing-v1:{}", scope.resource_id()),
            etag: format!("raiun-vault-sealed-metadata-v2:{epoch}"),
            protection: ContentProtection::Ciphertext,
        };
        let mut source = cache.open_content(&cache_scope, &source_version).unwrap();
        let byte_len = source.metadata().unwrap().len();
        let build = cache
            .begin_ciphertext_pin(&cache_scope, epoch, None)
            .unwrap();
        let pin_version = ContentVersion {
            resource_id: source_version.resource_id.clone(),
            etag: format!(
                "raiun-vault-sealed-metadata-v2:pin:{}:{}:{epoch}",
                build.id(),
                build.generation()
            ),
            protection: ContentProtection::Ciphertext,
        };
        cache
            .publish_ciphertext_for_pin_if_epoch(
                &cache_scope,
                &pin_version,
                &mut source,
                byte_len,
                &build,
                CiphertextPinItemKind::RootListing,
            )
            .unwrap();
        let ready = cache.finish_ciphertext_pin(&cache_scope, &build).unwrap();
        (ready.id, ready.generation)
    }

    #[test]
    fn transition_rejects_new_vault_context_after_generation_bump_and_resets_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = Arc::new(runtime(dir.path().to_path_buf()));
        assert!(runtime.vault_context().is_ok());
        let stale_generation = runtime.operation_generation().unwrap();

        let transition = AuthTransition::begin(&runtime.auth_transition).unwrap();
        runtime.auth_generation.fetch_add(1, Ordering::AcqRel);
        let (sent, received) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            let runtime = runtime.clone();
            scope.spawn(move || sent.send(runtime.vault_context().is_err()).unwrap());
            assert!(received.recv().unwrap());
        });
        assert!(AuthTransition::begin(&runtime.auth_transition).is_err());

        drop(transition);
        assert!(runtime.vault_context().is_ok());
        assert_ne!(runtime.operation_generation().unwrap(), stale_generation);
    }

    #[test]
    fn explicit_unlock_can_register_a_browsing_route_without_a_sync_pair() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = runtime(dir.path().to_path_buf());
        assert!(runtime.settings.lock().unwrap().config.pairs.is_empty());
        assert!(
            !runtime
                .vault_mount_ready("space-a", "/Travel.vault", "resource-a")
                .unwrap()
        );
        assert!(
            !runtime
                .vault_mount_ready("space-a", "/", "resource-a")
                .unwrap()
        );

        let route = runtime
            .ensure_vault_mount_route("space-a", "/Travel.vault", "resource-a")
            .unwrap();
        let control = route.control().clone();
        assert!(
            !runtime
                .vault_mount_ready("space-a", "/Travel.vault", "resource-a")
                .unwrap()
        );

        control
            .install_backend(Arc::new(InertVaultReadBackend))
            .unwrap();
        assert!(
            runtime
                .vault_mount_ready("space-a", "/Travel.vault", "resource-a")
                .unwrap()
        );
        assert!(
            !runtime
                .vault_mount_ready("space-a", "/Travel.vault", "other-resource")
                .unwrap()
        );
    }

    #[test]
    fn unlocked_roots_ipc_lists_only_active_exact_unlocked_scopes() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = runtime(dir.path().to_path_buf());
        let scope = runtime
            .vault_scope("https://cloud.example.test", "space-a", "root-a")
            .unwrap();
        let token = include_str!("../../raiun-vault/tests/fixtures/web-integrity-token.b64").trim();
        let mut password = b"potato".to_vec();
        runtime.vaults.unlock(&scope, &mut password, token).unwrap();

        let route = runtime
            .ensure_vault_mount_route("space-a", "/Travel.vault", "root-a")
            .unwrap();
        route
            .control()
            .install_backend(Arc::new(InertVaultReadBackend))
            .unwrap();
        runtime
            .ensure_vault_mount_route("space-b", "/Other.vault", "root-b")
            .unwrap();

        let response = runtime
            .handle_vault_with_store(
                json!({"action":"vault_unlocked_roots"}),
                None,
                &MockVaultCredentials::default(),
            )
            .unwrap();
        assert_eq!(
            response,
            json!({
                "roots":[{"space_id":"space-a","root_resource_id":"root-a"}],
                "truncated":false
            })
        );

        runtime.vaults.lock(&scope).unwrap();
        let locked = runtime
            .handle_vault_with_store(
                json!({"action":"vault_unlocked_roots"}),
                None,
                &MockVaultCredentials::default(),
            )
            .unwrap();
        assert_eq!(locked, json!({"roots":[],"truncated":false}));
    }

    #[test]
    fn explicit_route_creation_respects_the_registry_bound() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = runtime(dir.path().to_path_buf());
        let mut accepted = 0;
        let mut rejected_at = None;
        for index in 0..64 {
            match runtime.ensure_vault_mount_route(
                &format!("space-{index}"),
                "/Travel.vault",
                &format!("resource-{index}"),
            ) {
                Ok(_) => accepted += 1,
                Err(_) => {
                    rejected_at = Some(index);
                    break;
                }
            }
        }
        assert!(
            rejected_at.is_some(),
            "route registry must have a fixed bound"
        );
        assert_eq!(runtime.vault_mounts.routes().unwrap().len(), accepted);
    }

    #[test]
    fn write_spool_readiness_uses_authenticated_account_not_local_profile_scope() {
        let dir = tempfile::tempdir().unwrap();
        let mut runtime = runtime(dir.path().to_path_buf());
        runtime.vault_account_id = "local-profile-id".into();
        let server_account_id = "4f70656e436c6f7564";
        runtime.settings.lock().unwrap().account_id = Some(server_account_id.into());

        let expected = account_spool_dir(&runtime.dir, server_account_id);
        let wrong = account_spool_dir(&runtime.dir, &runtime.vault_account_id);
        std::fs::create_dir_all(&expected).unwrap();
        std::fs::create_dir_all(&wrong).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&expected, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::set_permissions(&wrong, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        raiun_fuse::vault_write::VaultWriteSpool::open(&expected).unwrap();
        assert!(
            raiun_fuse::vault_write::VaultWriteSpool::open_existing(&wrong)
                .unwrap()
                .is_none()
        );

        assert_eq!(runtime.vault_write_spool_dir().unwrap(), expected);
        assert_ne!(expected, wrong);
    }

    #[test]
    fn whole_space_vault_mount_route_reports_ready_after_unlock() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = runtime(dir.path().to_path_buf());
        assert!(
            !runtime
                .vault_mount_ready("encrypted-space", "/", "space-root-id")
                .unwrap()
        );
        let route = runtime
            .ensure_vault_mount_route("encrypted-space", "/", "space-root-id")
            .unwrap();
        assert_eq!(route.root_path(), "/");
        route
            .control()
            .install_backend(Arc::new(InertVaultReadBackend))
            .unwrap();
        assert!(
            runtime
                .vault_mount_ready("encrypted-space", "/", "space-root-id")
                .unwrap()
        );
        assert!(
            !runtime
                .vault_mount_ready("encrypted-space", "/", "other-resource")
                .unwrap()
        );
    }

    #[test]
    fn offline_vault_ipc_discovers_unlocks_lists_and_locks_without_auth_session() {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let runtime = runtime(dir.path().to_path_buf());
        let scope = seed_offline_vault(&runtime);
        {
            let mut auth = runtime.auth_state.lock().unwrap();
            auth.session = None;
            auth.client = None;
            auth.account_id = None;
        }
        let credentials = MockVaultCredentials::default();
        credentials.store(&scope, b"potato").unwrap();

        let roots = runtime
            .handle_vault_with_store(json!({"action":"vault_cached_roots"}), None, &credentials)
            .unwrap();
        assert_eq!(roots["roots"][0]["space_id"], "space-a");
        assert_eq!(roots["roots"][0]["root_resource_id"], "root-a");
        assert_eq!(roots["roots"][0]["snapshot_available"], true);
        assert!(roots["roots"][0].get("root_path").is_none());
        assert!(roots["roots"][0].get("integrity_token").is_none());

        let wrong_password = runtime.handle_vault_with_store(
            json!({
                "action":"vault_unlock_offline",
                "space_id":"space-a",
                "root_resource_id":"root-a"
            }),
            Some(Zeroizing::new("incorrect".to_owned())),
            &credentials,
        );
        assert!(wrong_password.is_err());
        assert!(!runtime.vaults.is_unlocked(&scope).unwrap());

        let unlocked = runtime
            .handle_vault_with_store(
                json!({
                    "action":"vault_unlock_offline",
                    "space_id":"space-a",
                    "root_resource_id":"root-a",
                    "use_saved":true
                }),
                None,
                &credentials,
            )
            .unwrap();
        assert_eq!(unlocked["unlocked"], true);
        assert_eq!(unlocked["offline"], true);
        assert_eq!(unlocked["root_path"], "/Travel.vault");
        assert_eq!(unlocked["vault_mount_writable"], false);
        assert_eq!(unlocked["vault_mount_existing_file_overwrite"], false);
        assert_eq!(
            unlocked["vault_mount_existing_file_overwrite_reason"],
            "drive_not_mounted"
        );
        let route = runtime
            .vault_mounts
            .get("space-a", "/Travel.vault", "root-a")
            .unwrap()
            .unwrap();
        assert!(!route.control().supports_writes().unwrap());
        assert!(route.control().supports_existing_file_overwrites().unwrap());

        let listed = runtime
            .handle_vault_with_store(
                json!({
                    "action":"vault_list",
                    "offline":true,
                    "space_id":"space-a",
                    "root_resource_id":"root-a",
                    "path":"/"
                }),
                None,
                &credentials,
            )
            .unwrap();
        assert_eq!(listed[0]["path"], "/Memo.txt");
        assert_eq!(listed[0]["id"], "memo-a");
        assert_eq!(listed[0]["writable"], true);

        let operations = runtime
            .handle_vault_with_store(
                json!({
                    "action":"vault_operations",
                    "space_id":"space-a",
                    "root_resource_id":"root-a",
                    "limit":50
                }),
                None,
                &credentials,
            )
            .unwrap();
        assert_eq!(operations["space_id"], "space-a");
        assert_eq!(operations["root_resource_id"], "root-a");
        assert_eq!(operations["items"], json!([]));
        assert_eq!(operations["next_after"], Value::Null);
        assert_eq!(operations["truncated"], false);
        assert!(
            runtime
                .handle_vault_with_store(
                    json!({
                        "action":"vault_operations",
                        "space_id":"space-a",
                        "root_resource_id":"another-root"
                    }),
                    None,
                    &credentials,
                )
                .is_err()
        );

        let locked = runtime
            .handle_vault_with_store(
                json!({
                    "action":"vault_lock",
                    "space_id":"space-a",
                    "root_resource_id":"root-a"
                }),
                None,
                &credentials,
            )
            .unwrap();
        assert_eq!(locked["unlocked"], false);
        assert!(!runtime.vaults.is_unlocked(&scope).unwrap());
        assert!(
            runtime
                .handle_vault_with_store(
                    json!({
                        "action":"vault_operations",
                        "space_id":"space-a",
                        "root_resource_id":"root-a"
                    }),
                    None,
                    &credentials,
                )
                .is_err()
        );
        assert!(
            runtime
                .handle_vault_with_store(
                    json!({
                        "action":"vault_list",
                        "offline":true,
                        "space_id":"space-a",
                        "root_resource_id":"root-a",
                        "path":"/"
                    }),
                    None,
                    &credentials,
                )
                .is_err()
        );

        let cache = runtime.open_vault_cache().unwrap();
        let cache_scope = raiun_cache::CacheScope::new(
            scope.server_origin(),
            scope.account_id(),
            scope.space_id(),
            scope.resource_id(),
            raiun_cache::ScopeProtection::CiphertextOnly,
        )
        .unwrap();
        cache.invalidate_ciphertext_scope(&cache_scope).unwrap();
        let after_invalidation = runtime
            .handle_vault_with_store(json!({"action":"vault_cached_roots"}), None, &credentials)
            .unwrap();
        assert!(after_invalidation["roots"].as_array().unwrap().is_empty());
    }

    #[test]
    fn offline_pin_unlock_rejects_stale_generation_before_route_publication() {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let runtime = runtime(dir.path().to_path_buf());
        let scope = seed_offline_vault(&runtime);
        let (pin_id, current_generation) = seed_offline_pin(&runtime, &scope);
        {
            let mut auth = runtime.auth_state.lock().unwrap();
            auth.session = None;
            auth.client = None;
            auth.account_id = None;
        }
        let credentials = MockVaultCredentials::default();

        let stale = runtime.handle_vault_with_store(
            json!({
                "action":"vault_unlock_offline",
                "space_id":"space-a",
                "root_resource_id":"root-a",
                "pin_id":pin_id,
                "expected_generation":current_generation + 1,
                "remember":true
            }),
            Some(Zeroizing::new("potato".to_owned())),
            &credentials,
        );
        assert_eq!(
            stale.unwrap_err(),
            "The encrypted snapshot changed. Refresh saved locations and reopen the current copy before unlocking."
        );
        assert!(!runtime.vaults.is_unlocked(&scope).unwrap());
        assert!(
            runtime
                .vault_mounts
                .get("space-a", "/Travel.vault", "root-a")
                .unwrap()
                .is_none()
        );
        assert!(credentials.load(&scope).unwrap().is_none());

        let current = runtime
            .handle_vault_with_store(
                json!({
                    "action":"vault_unlock_offline",
                    "space_id":"space-a",
                    "root_resource_id":"root-a",
                    "pin_id":pin_id,
                    "expected_generation":current_generation
                }),
                Some(Zeroizing::new("potato".to_owned())),
                &credentials,
            )
            .unwrap();
        assert_eq!(current["unlocked"], true);
        assert_eq!(current["pin_id"], pin_id);
        assert_eq!(current["generation"], current_generation);
        assert!(runtime.vaults.is_unlocked(&scope).unwrap());
    }

    #[test]
    fn queued_create_status_is_visible_without_a_sync_pair() {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let runtime = runtime(dir.path().to_path_buf());
        let scope = seed_offline_vault(&runtime);
        {
            let mut auth = runtime.auth_state.lock().unwrap();
            auth.session = None;
            auth.client = None;
            auth.account_id = None;
        }
        let credentials = MockVaultCredentials::default();
        let password = b"potato";
        credentials.store(&scope, password).unwrap();
        runtime
            .handle_vault_with_store(
                json!({
                    "action":"vault_unlock_offline",
                    "space_id":"space-a",
                    "root_resource_id":"root-a"
                }),
                Some(Zeroizing::new("potato".to_owned())),
                &credentials,
            )
            .unwrap();

        assert!(runtime.settings.lock().unwrap().config.pairs.is_empty());
        let cache = runtime.open_vault_cache().unwrap();
        let offline =
            VaultOfflineCache::new(cache.clone(), scope.clone(), "/Travel.vault").unwrap();
        let operation_sessions = Arc::new(VaultSessionCoordinator::new());
        let mut operation_password = password.to_vec();
        let (root_snapshot, _) = offline
            .unlock_root(&operation_sessions, &mut operation_password)
            .unwrap();
        let client =
            OpenCloudClient::new(scope.server_origin(), "offline-only".to_owned()).unwrap();
        let backend = VaultBackend::new_from_cached_root(
            client,
            operation_sessions,
            scope.clone(),
            "/Travel.vault".to_owned(),
            offline,
            root_snapshot,
        )
        .unwrap();
        let parent_ref = raiun_opencloud::vault_cache::VaultPendingParentRef::Stable {
            resource_id: "root-a".to_owned(),
        };
        let target = backend
            .prepare_file_create_target_for_parent("/Retry.txt", &parent_ref, None)
            .unwrap();
        let mut body = Cursor::new(b"retained local draft".to_vec());
        let outcome = backend
            .create_prepared_reader_with_queue_for_parent(
                &target,
                &mut body,
                b"retained local draft".len() as u64,
                None,
                &parent_ref,
            )
            .unwrap();
        let (write_id, revision) = match outcome {
            raiun_opencloud::vault_backend::VaultUploadOutcome::QueuedCreate {
                write_id,
                revision,
                ..
            } => (write_id, revision),
            other => panic!("expected durable queued create, got {other:?}"),
        };
        let page = runtime
            .handle_vault_with_store(
                json!({
                    "action":"vault_operations",
                    "space_id":"space-a",
                    "root_resource_id":"root-a"
                }),
                None,
                &credentials,
            )
            .unwrap();
        assert_eq!(page["auth_generation"], 7);
        assert_eq!(page["items"].as_array().unwrap().len(), 1);
        let item = &page["items"][0];
        assert_eq!(item["write_id"], write_id);
        assert_eq!(item["revision"], revision);
        assert_eq!(item["operation"], "create_file");
        assert_eq!(item["path"], "/Retry.txt");
        assert_eq!(item["state"], "queued");
        assert_eq!(item["attention_reason"], Value::Null);
        assert_eq!(item["retry_state"], Value::Null);
        assert_eq!(item["can_retry_interrupted_create"], false);
    }

    #[test]
    fn remembered_v8_password_survives_kdf_zeroization_lock_and_saved_unlock() {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let runtime = runtime(dir.path().to_path_buf());
        let scope = seed_offline_vault(&runtime);
        {
            let mut auth = runtime.auth_state.lock().unwrap();
            auth.session = None;
            auth.client = None;
            auth.account_id = None;
        }
        let credentials = MockVaultCredentials::default();
        let password = b"potato";

        let first_unlock = runtime
            .handle_vault_with_store(
                json!({
                    "action":"vault_unlock_offline",
                    "space_id":"space-a",
                    "root_resource_id":"root-a",
                    "remember":true
                }),
                Some(Zeroizing::new(
                    std::str::from_utf8(password).unwrap().to_owned(),
                )),
                &credentials,
            )
            .unwrap();
        assert_eq!(first_unlock["unlocked"], true);
        assert_eq!(first_unlock["remembered"], true);
        assert_eq!(
            credentials.load(&scope).unwrap().unwrap().as_slice(),
            password
        );

        // Exercise both name and content key portions of the complete Web v8
        // rclone-crypt key bundle before locking the session.
        let encrypted_name = runtime
            .vaults
            .encrypt_name(&scope, "roundtrip.txt")
            .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let encrypted_path = temp.path().join("ciphertext.bin");
        let plaintext = b"saved key uses every v8 content-key field";
        runtime
            .vaults
            .encrypt_file_transactional(
                &scope,
                &mut Cursor::new(plaintext),
                &encrypted_path,
                plaintext.len() as u64,
                4096,
            )
            .unwrap();
        let ciphertext = std::fs::read(&encrypted_path).unwrap();

        runtime
            .handle_vault_with_store(
                json!({
                    "action":"vault_lock",
                    "space_id":"space-a",
                    "root_resource_id":"root-a"
                }),
                None,
                &credentials,
            )
            .unwrap();
        assert!(!runtime.vaults.is_unlocked(&scope).unwrap());

        let saved_unlock = runtime
            .handle_vault_with_store(
                json!({
                    "action":"vault_unlock_offline",
                    "space_id":"space-a",
                    "root_resource_id":"root-a",
                    "use_saved":true
                }),
                None,
                &credentials,
            )
            .unwrap();
        assert_eq!(saved_unlock["unlocked"], true);
        assert_eq!(
            runtime
                .vaults
                .decrypt_name(&scope, &encrypted_name)
                .unwrap(),
            "roundtrip.txt"
        );
        let decrypted_path = temp.path().join("plaintext.bin");
        runtime
            .vaults
            .decrypt_file_transactional(
                &scope,
                &mut Cursor::new(ciphertext),
                &decrypted_path,
                plaintext.len() as u64,
                Some(plaintext.len() as u64),
            )
            .unwrap();
        assert_eq!(std::fs::read(decrypted_path).unwrap(), plaintext);
    }

    #[test]
    fn online_unlock_remembers_password_before_kdf_wipes_its_input() {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let server = SyntheticVaultServer::start();
        let runtime = runtime(dir.path().to_path_buf());
        let account_id = "74657374";
        let client = OpenCloudClient::new(&server.origin, "synthetic-token".into()).unwrap();
        {
            let mut settings = runtime.settings.lock().unwrap();
            settings.server = Some(server.origin.clone());
            settings.account_id = Some(account_id.into());
        }
        let account_dir = account_engine_dir(&runtime.dir, account_id);
        std::fs::create_dir_all(&account_dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&account_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        {
            let mut auth = runtime.auth_state.lock().unwrap();
            auth.client = Some(client);
            auth.session = Some(auth::Session {
                server: server.origin.clone(),
                client_id: "test-client".into(),
                access_token: "synthetic-token".into(),
                refresh_token: None,
                expires_at: u64::MAX,
                token_endpoint: format!("{}/token", server.origin),
                expected_issuer: None,
                last_refresh_at: None,
                proxy: raiun_opencloud::ProxyConfig::System,
            });
        }
        let credentials = MockVaultCredentials::default();
        let first_unlock = runtime
            .handle_vault_with_store(
                json!({
                    "action":"vault_unlock",
                    "space_id":"space-a",
                    "root_path":"/Travel.vault",
                    "root_resource_id":"root-a",
                    "remember":true
                }),
                Some(Zeroizing::new("potato".to_owned())),
                &credentials,
            )
            .unwrap();
        assert_eq!(first_unlock["unlocked"], true);
        assert_eq!(first_unlock["remembered"], true);
        let scope = runtime
            .vault_scope(&server.origin, "space-a", "root-a")
            .unwrap();
        assert_eq!(
            credentials.load(&scope).unwrap().unwrap().as_slice(),
            b"potato"
        );

        runtime
            .handle_vault_with_store(
                json!({
                    "action":"vault_lock",
                    "space_id":"space-a",
                    "root_resource_id":"root-a"
                }),
                None,
                &credentials,
            )
            .unwrap();
        assert!(!runtime.vaults.is_unlocked(&scope).unwrap());
        let saved_unlock = runtime
            .handle_vault_with_store(
                json!({
                    "action":"vault_unlock",
                    "space_id":"space-a",
                    "root_path":"/Travel.vault",
                    "root_resource_id":"root-a",
                    "use_saved":true
                }),
                None,
                &credentials,
            )
            .unwrap();
        assert_eq!(saved_unlock["unlocked"], true);
        assert!(runtime.vaults.is_unlocked(&scope).unwrap());
    }

    #[test]
    fn online_dialog_listing_seals_root_for_offline_discovery_without_fuse_mount() {
        let dir = tempfile::tempdir().unwrap();
        let server = SyntheticVaultServer::start();
        let runtime = runtime(dir.path().to_path_buf());
        let account_id = "74657374";
        let client = OpenCloudClient::new(&server.origin, "synthetic-token".into()).unwrap();
        {
            let mut settings = runtime.settings.lock().unwrap();
            settings.server = Some(server.origin.clone());
            settings.account_id = Some(account_id.into());
        }
        {
            let account_dir = account_engine_dir(&runtime.dir, account_id);
            std::fs::create_dir_all(&account_dir).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&account_dir, std::fs::Permissions::from_mode(0o700))
                    .unwrap();
            }
            let mut auth = runtime.auth_state.lock().unwrap();
            auth.client = Some(client);
            auth.session = Some(auth::Session {
                server: server.origin.clone(),
                client_id: "test-client".into(),
                access_token: "synthetic-token".into(),
                refresh_token: None,
                expires_at: u64::MAX,
                token_endpoint: format!("{}/token", server.origin),
                expected_issuer: None,
                last_refresh_at: None,
                proxy: raiun_opencloud::ProxyConfig::System,
            });
        }
        let scope = VaultSessionScope::new(
            &runtime.vault_account_id,
            &server.origin,
            "space-a",
            "root-a",
        )
        .unwrap();
        let token = include_str!("../../raiun-vault/tests/fixtures/web-integrity-token.b64").trim();
        let mut password = b"potato".to_vec();
        runtime.vaults.unlock(&scope, &mut password, token).unwrap();

        let entries = runtime
            .handle_vault_with_store(
                json!({
                    "action":"vault_list",
                    "space_id":"space-a",
                    "root_path":"/Travel.vault",
                    "root_resource_id":"root-a",
                    "path":"/"
                }),
                None,
                &MockVaultCredentials::default(),
            )
            .unwrap();
        assert_eq!(entries.as_array().unwrap().len(), 0);
        assert!(runtime.vault_mounts.routes().unwrap().is_empty());

        let roots = runtime
            .handle_vault_with_store(
                json!({"action":"vault_cached_roots"}),
                None,
                &MockVaultCredentials::default(),
            )
            .unwrap();
        assert_eq!(roots["roots"].as_array().unwrap().len(), 1);
        assert_eq!(roots["roots"][0]["space_id"], "space-a");
        assert_eq!(roots["roots"][0]["root_resource_id"], "root-a");
        assert!(roots["roots"][0].get("root_path").is_none());

        // Deep-link hints cannot select arbitrary cloud paths. The resolver
        // only works after Raiun has a route with this exact stable identity,
        // and it rechecks the remote root before returning the trusted path.
        let resolver_request = json!({
            "action":"vault_resolve_unlock_target",
            "space_id":"space-a",
            "root_resource_id":"root-a"
        });
        assert!(
            runtime
                .handle_vault_with_store(
                    resolver_request.clone(),
                    None,
                    &MockVaultCredentials::default(),
                )
                .is_err()
        );
        let route = raiun_fuse::VaultMountRoute::new(
            "space-a".into(),
            "/Travel.vault".into(),
            "root-a".into(),
            raiun_fuse::vault_routes::VaultRouteControl::new(),
        )
        .unwrap();
        route
            .control()
            .install_backend(Arc::new(InertVaultReadBackend))
            .unwrap();
        runtime.vault_mounts.register(route).unwrap();
        let resolved = runtime
            .handle_vault_with_store(resolver_request, None, &MockVaultCredentials::default())
            .unwrap();
        assert_eq!(resolved["resolved"], true);
        assert_eq!(resolved["space_id"], "space-a");
        assert_eq!(resolved["root_resource_id"], "root-a");
        assert_eq!(resolved["root_path"], "/Travel.vault");
        assert_eq!(resolved["display_name"], "Travel.vault");
        assert!(resolved.get("pin_id").unwrap().is_null());
        assert!(
            runtime
                .handle_vault_with_store(
                    json!({
                        "action":"vault_resolve_unlock_target",
                        "space_id":"space-a",
                        "root_resource_id":"another-root"
                    }),
                    None,
                    &MockVaultCredentials::default(),
                )
                .is_err()
        );

        let started = runtime
            .handle_vault_with_store(
                json!({
                    "action":"vault_reconcile_edits_start",
                    "space_id":"space-a",
                    "root_resource_id":"root-a"
                }),
                None,
                &MockVaultCredentials::default(),
            )
            .unwrap();
        assert_eq!(started["accepted"], true);
        let job_id = started["job_id"].as_str().unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        let status = loop {
            let status = runtime
                .handle_vault_with_store(
                    json!({
                        "action":"vault_reconcile_edits_status",
                        "space_id":"space-a",
                        "root_resource_id":"root-a",
                        "job_id":job_id
                    }),
                    None,
                    &MockVaultCredentials::default(),
                )
                .unwrap();
            if status["state"] == "complete" {
                break status;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "empty encrypted reconciliation job did not complete"
            );
            thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(status["root_resource_id"], "root-a");
        assert_eq!(status["processed"], 0);
        assert_eq!(status["uploaded"], 0);
        assert_eq!(status["remaining"], 0);
        let latest = runtime
            .handle_vault_with_store(
                json!({
                    "action":"vault_reconcile_edits_latest",
                    "space_id":"space-a",
                    "root_resource_id":"root-a"
                }),
                None,
                &MockVaultCredentials::default(),
            )
            .unwrap();
        assert_eq!(latest["available"], true);
        assert_eq!(latest["status"]["job_id"], job_id);
        assert_eq!(latest["status"]["automatic"], false);

        runtime.settings.lock().unwrap().paused_space_ids = vec!["space-a".into()];
        assert!(
            runtime
                .handle_vault_with_store(
                    json!({
                        "action":"vault_reconcile_edits_start",
                        "space_id":"space-a",
                        "root_resource_id":"root-a"
                    }),
                    None,
                    &MockVaultCredentials::default(),
                )
                .is_err()
        );
        runtime.settings.lock().unwrap().paused_space_ids.clear();

        let locked = runtime
            .handle_vault_with_store(
                json!({
                    "action":"vault_lock",
                    "space_id":"space-a",
                    "root_resource_id":"root-a"
                }),
                None,
                &MockVaultCredentials::default(),
            )
            .unwrap();
        assert_eq!(locked["unlocked"], false);
        assert!(
            runtime
                .handle_vault_with_store(
                    json!({
                        "action":"vault_reconcile_edits_start",
                        "space_id":"space-a",
                        "root_resource_id":"root-a"
                    }),
                    None,
                    &MockVaultCredentials::default(),
                )
                .is_err()
        );
    }
}
