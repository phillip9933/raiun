// Explicit cached-only provider. Saved ownership locates protected state;
// only a password-authenticated sealed envelope grants a live read route.
impl WindowsAgent {
    fn connect_windows_cached_provider(
        &self,
        context: &WindowsVaultOfflineAccount,
    ) -> Result<VerifiedVaultBackend, String> {
        self.check_windows_vault_offline_account(context)?;
        let owner = context
            .configuration
            .registration_ownership
            .as_ref()
            .ok_or("Missing saved root owner")?;
        let active = ActiveProviderBinding {
            generation: context.generation,
            path: PathBuf::from(&context.configuration.path),
            identity: context._root.identity(),
            personal_space_id: owner.personal_drive_id.clone(),
            personal_root_resource_id: owner
                .personal_root_resource_id
                .clone()
                .ok_or("Missing saved Personal root")?,
        };
        if self.provider.connection_matches(active.clone())? {
            let current = self.provider.verified_vault_backend(active)?;
            if !current.backend.is_cached_only() {
                return Err("An online provider is still active".into());
            }
            return Ok(current);
        }
        let client = Arc::new(
            OpenCloudClient::new_offline(&context.configuration.server)
                .map_err(|_| "Could not prepare offline client")?,
        );
        let scope = raiun_cloudfiles_windows::ProviderScope::new(
            &client,
            self.profile_scope.clone(),
            owner.account_id.clone(),
            context.origin.clone(),
        )
        .map_err(|_| "Could not bind offline account")?;
        let recovery =
            windows_gui_recovery::current_user(scope.clone(), context._root.identity(), None)
                .map_err(|_| "Protected Windows recovery state is unavailable")?;
        let recovery: Arc<dyn raiun_cloudfiles_windows::EditRecoveryProvider> = Arc::new(recovery);
        let catalog = recovery
            .identity_catalog()
            .ok_or("Protected Windows catalogue is unavailable")?;
        let admissions = self
            .source_admissions
            .as_ref()
            .ok_or("Saved encrypted locations are unavailable")?
            .lock()
            .map_err(|_| "Saved encrypted locations are unavailable")?
            .clone();
        let profile = admissions
            .profiles()
            .get(&self.profile_scope)
            .ok_or("Saved account is unavailable")?;
        let locations = profile
            .vault_reservations()
            .iter()
            .map(|r| (r.space_id().to_owned(), r.root_path().to_owned()))
            .collect::<Vec<_>>();
        let backend = Arc::new(
            raiun_cloudfiles_windows::OpenCloudPlaceholderBackend::new_cached_only(
                client,
                scope,
                context._root.identity(),
                catalog.clone(),
                &active.personal_space_id,
                &active.personal_root_resource_id,
                &locations,
            )
            .map_err(|_| "Protected cached namespace is unavailable")?,
        );
        self.check_windows_vault_offline_account(context)?;
        let mut save_admission = if WINDOWS_VAULT_OFFLINE_WRITES_ENABLED {
            self.provider.prepare_existing_file_save_worker(
                &active,
                &self.state,
                &self.session_store,
                false,
            )?
        } else {
            None
        };
        self.provider.connect_with_file_rename(
            active.path.clone(),
            context.generation,
            context._root.identity(),
            true,
            active.personal_space_id.clone(),
            active.personal_root_resource_id.clone(),
            backend.clone(),
            recovery,
            WINDOWS_VAULT_OFFLINE_WRITES_ENABLED.then_some(catalog),
            context.account.clone(),
            self.session_store.clone(),
        )?;
        self.check_windows_vault_offline_account(context)?;
        if let Some(admission) = save_admission.as_mut() {
            admission.owner.check_cached_save_worker_account(&active)?;
            admission.committed = true;
        }
        self.provider.verified_vault_backend(active)
    }
    fn inspect_windows_cached_vault(&self, request: &Value) -> Result<Value, String> {
        let _operation = self
            .vault_credential_operation
            .lock()
            .map_err(|_| "Vault changes are unavailable")?;
        let request = windows_vault_requests::decode(request)?;
        let resource = request
            .root_resource_id
            .ok_or("Refresh the saved vault identity")?;
        let context =
            self.windows_vault_offline_account(self.generation.load(Ordering::Acquire))?;
        let owner = context
            .configuration
            .registration_ownership
            .as_ref()
            .ok_or("Offline owner changed")?;
        let active = ActiveProviderBinding {
            generation: context.generation,
            path: PathBuf::from(&context.configuration.path),
            identity: context._root.identity(),
            personal_space_id: owner.personal_drive_id.clone(),
            personal_root_resource_id: owner
                .personal_root_resource_id
                .clone()
                .ok_or("Missing saved root")?,
        };
        let verified = self.provider.verified_vault_backend(active.clone())?;
        let scope = raiun_vault::session::VaultSessionScope::new(
            &self.profile_scope,
            &context.origin,
            &request.space_id,
            &resource,
        )
        .map_err(|_| "Invalid saved scope")?;
        let unlocked = self
            .vault_sessions
            .is_unlocked(&scope)
            .map_err(|_| "Vault session is unavailable")?;
        let ready = unlocked
            && verified
                .backend
                .list_cached_vault(&request.space_id, &request.root_path, &resource, "/")
                .is_ok();
        let incomplete = self
            .provider
            .vault_lock_cleanup_status(
                active,
                request.space_id,
                resource.clone(),
                request.root_path.clone(),
            )
            .ok();
        self.check_windows_vault_offline_account(&context)?;
        Ok(
            json!({"initialized":true,"unlocked":unlocked,"root_path":request.root_path,"root_resource_id":resource,"vault_mount_ready":ready,"vault_mount_writable":false,"vault_mount_existing_file_in_place":false,"vault_mount_existing_file_overwrite":false,"vault_native_operations":[],"vault_mount_write_unavailable_reason":"offline_read_only","vault_lock_cleanup_status":if incomplete==Some(true){"incomplete"}else if incomplete==Some(false){"complete"}else{"unknown"}}),
        )
    }
    fn reconnect_windows_cached_provider(&self, request: &Value) -> Result<Value, String> {
        let _operation = self
            .vault_credential_operation
            .lock()
            .map_err(|_| "Vault changes are unavailable")?;
        if request.as_object().is_none_or(|o| {
            o.keys()
                .any(|k| !matches!(k.as_str(), "action" | "profile_id" | "expected_generation"))
        }) || request.get("profile_id").and_then(Value::as_str)
            != Some(self.profile_scope.as_str())
        {
            return Err("Invalid offline reconnect request".into());
        }
        let expected = request
            .get("expected_generation")
            .and_then(Value::as_u64)
            .ok_or("Refresh the account")?;
        let context = self.windows_vault_offline_account(expected)?;
        if !self
            .state
            .lock()
            .map_err(|_| "Account state is unavailable")?
            .offline_cached
        {
            return Err("Cached mode is not active".into());
        }
        self.vault_copy_jobs.cancel_all_and_wait()?;
        self.vault_copy_serialization.cancel_all_and_wait()?;
        let owner = context
            .configuration
            .registration_ownership
            .as_ref()
            .ok_or("The cached drive owner is unavailable")?;
        let binding = ActiveProviderBinding {
            generation: expected,
            path: PathBuf::from(&context.configuration.path),
            identity: context._root.identity(),
            personal_space_id: owner.personal_drive_id.clone(),
            personal_root_resource_id: owner
                .personal_root_resource_id
                .clone()
                .ok_or("The cached Personal root is unavailable")?,
        };
        if self.provider.connection_matches(binding.clone())? {
            self.provider.disconnect_cached_for_reconnect(binding)?;
        } else {
            self.provider.disconnect()?;
        }
        self.vault_sessions
            .lock_all()
            .map_err(|_| "Could not clear cached vault sessions")?;
        self.check_windows_vault_offline_account(&context)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| "Account state is unavailable")?;
        if state.active_generation != expected
            || self.generation.load(Ordering::Acquire) != expected
            || state.root_configuration.as_ref() != Some(&context.configuration)
        {
            return Err("The offline account changed".into());
        }
        let generation = self.next_generation()?;
        state.active_generation = generation;
        state.offline_cached = false;
        state.online_authenticated = false;
        state.needs_refresh = state.session.is_some();
        state.refresh_retry_at = 0;
        drop(state);
        self.provider.authorize_generation(generation);
        Ok(json!({"offline":false,"reconnect_requested":true,"auth_generation":generation}))
    }
    fn unlock_windows_cached_vault(
        &self,
        target: &windows_vault_requests::session_requests::VaultTarget,
        password: &mut windows_vault_requests::session_requests::VaultPassword,
        pin: Option<&(String, u64)>,
    ) -> Result<Value, String> {
        use raiun_opencloud::vault_cache::VaultOfflineCache;
        use sha2::Digest;
        if mount_only() {
            return Err("Headless vault access is disabled".into());
        }
        if target
            .profile_id
            .as_deref()
            .is_some_and(|p| p != self.profile_scope)
        {
            return Err("The offline account changed".into());
        }
        // Stop/join all original jobs and native plaintext custody before a new
        // credential-free generation is admitted. A failed cleanup stops here.
        let expected = self.generation.load(Ordering::Acquire);
        let original = self.windows_vault_offline_account(expected)?;
        self.vault_copy_jobs.cancel_all_and_wait()?;
        self.vault_copy_serialization.cancel_all_and_wait()?;
        self.provider.disconnect()?;
        self.vault_sessions
            .lock_all()
            .map_err(|_| "Could not clear original vault sessions")?;
        self.check_windows_vault_offline_account(&original)?;
        let generation = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| "Account state is unavailable")?;
            if state.active_generation != original.generation
                || self.generation.load(Ordering::Acquire) != original.generation
                || state.root_configuration.as_ref() != Some(&original.configuration)
                || state.authenticating
                || state.refreshing
                || state.retiring
                || state.logout_pending
            {
                return Err("The offline account changed".into());
            }
            let generation = self.next_generation()?;
            state.active_generation = generation;
            state.online_authenticated = false;
            state.offline_cached = true;
            state.needs_refresh = false;
            generation
        };
        self.provider.authorize_generation(generation);
        let context = self.windows_vault_offline_account(generation)?;
        let cache = self.open_windows_vault_cache(&context)?;
        let cache_pin = self.windows_vault_cache_pin(&context)?;
        let scope = raiun_vault::session::VaultSessionScope::new(
            &self.profile_scope,
            &context.origin,
            &target.space_id,
            &target.root_resource_id,
        )
        .map_err(|_| "Invalid cached vault scope")?;
        let snapshot = match pin {
            Some((id, generation)) => VaultOfflineCache::unlock_cached_pin_root_expected(
                &cache,
                &self.vault_sessions,
                &scope,
                id,
                *generation,
                password.as_mut_bytes(),
            ),
            None => VaultOfflineCache::unlock_cached_root(
                &cache,
                &self.vault_sessions,
                &scope,
                password.as_mut_bytes(),
            )
            .map(|(s, _)| s),
        }
        .map_err(|_| "Could not verify the cached vault password or snapshot")?;
        let result = (|| {
            let root_path = snapshot.root_path.clone();
            let verified = self.connect_windows_cached_provider(&context)?;
            let trusted = verified.backend.scope().clone();
            let client = verified
                .backend
                .offline_client()
                .map_err(|_| "Cached client changed")?;
            let offline = match pin {
                Some((id, generation)) => VaultOfflineCache::new_for_pin_generation(
                    cache,
                    scope.clone(),
                    root_path.clone(),
                    id,
                    *generation,
                ),
                None => VaultOfflineCache::new(cache, scope.clone(), root_path.clone()),
            }
            .map_err(|_| "Could not bind cached vault")?;
            let binding = Arc::new(
                raiun_cloudfiles_windows::vault_read::WindowsVaultReadBinding::new_offline(
                    trusted.clone(),
                    client,
                    self.vault_sessions.clone(),
                    scope.clone(),
                    offline,
                    snapshot,
                    cache_pin,
                )
                .map_err(|_| "Could not bind verified cached read route")?,
            );
            let custody = verified.custody.view(&trusted, &scope, &root_path)?;
            let storage =
                DpapiSessionStore::current_user().map_err(|_| "Private staging is unavailable")?;
            let parent =
                raiun_control_windows::PinnedDirectory::open(storage.local_edit_state_directory())
                    .map_err(|_| "Private staging changed")?;
            let key =
                serde_json::to_vec(&(&context.account, scope.space_id(), scope.resource_id()))
                    .map_err(|_| "Could not bind private staging")?;
            let name = format!("vault-stage-{:x}", sha2::Sha256::digest(key));
            let private = Arc::new(
                raiun_control_windows::PrivateDirectory::create_or_open_under(
                    &parent,
                    std::ffi::OsStr::new(&name),
                )
                .map_err(|_| "Private staging changed")?,
            );
            let saved_owner = context
                .configuration
                .registration_ownership
                .as_ref()
                .ok_or("Offline owner changed")?;
            let worker_binding = ActiveProviderBinding {
                generation,
                path: PathBuf::from(&context.configuration.path),
                identity: context._root.identity(),
                personal_space_id: saved_owner.personal_drive_id.clone(),
                personal_root_resource_id: saved_owner
                    .personal_root_resource_id
                    .clone()
                    .ok_or("Missing saved root")?,
            };
            let marker = if WINDOWS_VAULT_OFFLINE_WRITES_ENABLED {
                self.provider
                    .existing_vault_save_worker_marker(&worker_binding)?
            } else {
                None
            };
            let adapter = Arc::new(match marker {
                Some(marker) => raiun_cloudfiles_windows::vault_placeholder::WindowsVaultPlaceholderBackend::new_with_existing_file_saves(
                    binding, private, raiun_cloudfiles_windows::MAX_REQUEST_BYTES, custody,
                    marker, self.provider.authorized_generation.clone(), generation,
                ),
                None => raiun_cloudfiles_windows::vault_placeholder::WindowsVaultPlaceholderBackend::new(
                    binding, private, raiun_cloudfiles_windows::MAX_REQUEST_BYTES, custody,
                ),
            }.map_err(|_| "Could not prepare cached adapter")?);
            self.check_windows_vault_offline_account(&context)?;
            verified
                .backend
                .install_vault_route(adapter, context._root.identity())
                .map_err(|_| "Could not install cached route")?;
            let owner = context
                .configuration
                .registration_ownership
                .as_ref()
                .ok_or("Offline owner changed")?;
            let active = ActiveProviderBinding {
                generation,
                path: PathBuf::from(&context.configuration.path),
                identity: context._root.identity(),
                personal_space_id: owner.personal_drive_id.clone(),
                personal_root_resource_id: owner
                    .personal_root_resource_id
                    .clone()
                    .ok_or("Missing saved root")?,
            };
            self.provider.refresh_vault_parent(
                active,
                scope.space_id().into(),
                scope.resource_id().into(),
                root_path.clone(),
            )?;
            self.check_windows_vault_offline_account(&context)?;
            Ok(
                json!({"unlocked":true,"offline":true,"root_path":root_path,"root_resource_id":scope.resource_id(),"auth_generation":generation,"vault_mount_ready":true,"vault_mount_writable":false,"vault_mount_existing_file_in_place":false,"vault_mount_existing_file_overwrite":false,"vault_mount_write_unavailable_reason":"offline_read_only","vault_native_operations":[],"pin_id":pin.map(|p|p.0.as_str()),"generation":pin.map(|p|p.1)}),
            )
        })();
        if result.is_err() {
            let _ = self.provider.disconnect();
            let _ = self.vault_sessions.lock(&scope);
        }
        result
    }
}
