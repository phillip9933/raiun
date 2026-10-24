// Trusted broker preparation for Windows vault sessions. The production action
// gate stays disabled until native projection and complete lock are accepted.
struct PreparedWindowsVaultUnlock {
    backend: Arc<raiun_cloudfiles_windows::OpenCloudPlaceholderBackend>,
    adapter: Arc<raiun_cloudfiles_windows::vault_placeholder::WindowsVaultPlaceholderBackend>,
    sessions: Arc<raiun_vault::session::VaultSessionCoordinator>,
    scope: raiun_vault::session::VaultSessionScope,
    reservation: windows_profile_registry::VaultReservation,
    generation: u64,
    configuration: RootConfiguration,
    session: auth::Session,
    root_path: String,
    _root_lease: raiun_cloudfiles_windows::ConfiguredRootLease,
    published: bool,
}
impl Drop for PreparedWindowsVaultUnlock {
    fn drop(&mut self) {
        if !self.published {
            let _ = self.sessions.lock(&self.scope);
        }
    }
}
impl WindowsAgent {
    fn lock_windows_vault(
        &self,
        target: &windows_vault_requests::session_requests::VaultTarget,
    ) -> Result<Value, String> {
        if target
            .profile_id
            .as_ref()
            .is_some_and(|profile| profile != &self.profile_scope)
        {
            return Err("Select the current Windows account".into());
        }
        let (generation, configuration) = {
            let state = self
                .state
                .lock()
                .map_err(|_| "Account state is unavailable")?;
            (
                state.active_generation,
                state
                    .root_configuration
                    .clone()
                    .ok_or("The Windows drive is unavailable")?,
            )
        };
        if generation == 0
            || generation != self.generation.load(Ordering::Acquire)
            || configuration.profile_scope != self.profile_scope
        {
            return Err("The vault account changed".into());
        }
        let owner = configuration
            .registration_ownership
            .as_ref()
            .ok_or("The Windows drive is unverified")?;
        let origin = url::Url::parse(&configuration.server)
            .map_err(|_| "The vault origin is invalid")?
            .origin()
            .ascii_serialization();
        let scope = raiun_vault::session::VaultSessionScope::new(
            &self.profile_scope,
            &origin,
            &target.space_id,
            &target.root_resource_id,
        )
        .map_err(|_| "The vault scope is invalid")?;
        let binding = ActiveProviderBinding {
            generation,
            path: PathBuf::from(&configuration.path),
            identity: raiun_cloudfiles_windows::ConfiguredRootIdentity {
                volume_serial: configuration.volume_serial,
                file_index: configuration.file_index,
            },
            personal_space_id: owner.personal_drive_id.clone(),
            personal_root_resource_id: owner
                .personal_root_resource_id
                .clone()
                .ok_or("The drive root is unverified")?,
        };
        let root_path = if target.root_path == "/" {
            "/"
        } else {
            target.root_path.trim_end_matches('/')
        }
        .to_owned();
        let cleanup = self.provider.lock_vault_route(
            binding,
            target.space_id.clone(),
            target.root_resource_id.clone(),
            root_path,
        );
        // Even a cleanup refusal must stop further scoped crypto. Never turn
        // retained local plaintext/dirty state into a successful lock response.
        let keys = self
            .vault_sessions
            .lock(&scope)
            .map_err(|_| "Could not clear the vault session");
        cleanup?;
        keys?;
        Ok(
            json!({"unlocked":false,"vault_mount_ready":false,"vault_mount_writable":false,
            "vault_mount_existing_file_overwrite":false,"vault_mount_write_unavailable_reason":"route_not_installed"}),
        )
    }
    fn check_vault_preparation(&self, prepared: &PreparedWindowsVaultUnlock) -> Result<(), String> {
        let state = self
            .state
            .lock()
            .map_err(|_| "Account state is unavailable")?;
        if self.generation.load(Ordering::Acquire) != prepared.generation
            || state.active_generation != prepared.generation
            || !state.online_authenticated
            || state.logout_pending
            || state.authenticating
            || state.refreshing
            || state.needs_refresh
            || state.session_cleanup_uncertain
            || state.root_configuration.as_ref() != Some(&prepared.configuration)
            || state.session.as_ref().is_none_or(|session| {
                session.server != prepared.session.server
                    || session.client_id != prepared.session.client_id
                    || session.expected_issuer != prepared.session.expected_issuer
                    || session.access_token != prepared.session.access_token
            })
            || prepared.backend.is_revoked()
        {
            return Err("The account changed during vault preparation".into());
        }
        Ok(())
    }
    fn prepare_windows_vault_unlock(
        &self,
        target: &windows_vault_requests::session_requests::VaultTarget,
        password: &mut windows_vault_requests::session_requests::VaultPassword,
    ) -> Result<PreparedWindowsVaultUnlock, String> {
        use raiun_opencloud::vault::VaultMetadataClient;
        use sha2::Digest;
        if target
            .profile_id
            .as_ref()
            .is_some_and(|id| id != &self.profile_scope)
        {
            return Err("Select the current Windows account".into());
        }
        let (session, generation, configuration) = {
            let state = self
                .state
                .lock()
                .map_err(|_| "Account state is unavailable")?;
            if !state.online_authenticated
                || state.logout_pending
                || state.authenticating
                || state.refreshing
                || state.needs_refresh
                || state.session_cleanup_uncertain
            {
                return Err("Connect this account before unlocking a vault".into());
            }
            (
                state.session.clone().ok_or("Connect this account")?,
                state.active_generation,
                state
                    .root_configuration
                    .clone()
                    .ok_or("Connect the Windows drive first")?,
            )
        };
        let owner = configuration
            .registration_ownership
            .as_ref()
            .ok_or("The drive has no verified owner")?;
        if generation == 0
            || generation != self.generation.load(Ordering::Acquire)
            || !configuration.valid
            || configuration.profile_scope != self.profile_scope
            || configuration.server != session.server
            || configuration.client_id != session.client_id
            || owner.state != "registered"
        {
            return Err("The Windows drive is not ready for vault access".into());
        }
        let identity = raiun_cloudfiles_windows::ConfiguredRootIdentity {
            volume_serial: configuration.volume_serial,
            file_index: configuration.file_index,
        };
        let root_lease = pin_registered_configured_root(Path::new(&configuration.path), identity)
            .map_err(root_error_text)?;
        let active = ActiveProviderBinding {
            generation,
            path: PathBuf::from(&configuration.path),
            identity,
            personal_space_id: owner.personal_drive_id.clone(),
            personal_root_resource_id: owner
                .personal_root_resource_id
                .clone()
                .ok_or("The drive root is unverified")?,
        };
        let backend = self.provider.verified_vault_backend(active)?;
        let (client, trusted) = backend
            .vault_read_context(identity)
            .map_err(|_| "The connected drive changed")?;
        if trusted.profile_id() != self.profile_scope || trusted.account_id() != owner.account_id {
            return Err("The connected drive belongs to another account".into());
        }
        if backend
            .has_vault_root(&target.space_id, &target.root_resource_id)
            .map_err(|_| "Could not inspect the current vault routes")?
        {
            return Err("This vault already has an active route".into());
        }
        let listing = VaultMetadataClient::new(client.as_ref())
            .inspect_vault(&target.space_id, &target.root_path)
            .map_err(|_| "Could not inspect the selected vault")?;
        let root_path = if listing.root_path == "/" {
            "/"
        } else {
            listing.root_path.trim_end_matches('/')
        }
        .to_owned();
        let requested = if target.root_path == "/" {
            "/"
        } else {
            target.root_path.trim_end_matches('/')
        };
        if listing.space_id != target.space_id
            || listing.root.id != target.root_resource_id
            || !listing.root.directory
            || root_path != requested
        {
            return Err("The selected vault root changed; select it again".into());
        }
        let scope = raiun_vault::session::VaultSessionScope::new(
            &self.profile_scope,
            trusted.server_origin(),
            &listing.space_id,
            &listing.root.id,
        )
        .map_err(|_| "Could not bind the vault session")?;
        let issuer = session
            .expected_issuer
            .as_ref()
            .map(|issuer| url::Url::parse(issuer).map(|value| value.to_string()))
            .transpose()
            .map_err(|_| "The account issuer is invalid")?;
        let account_scope = raiun_engine::folder_pairs::AccountScope::new(
            self.profile_scope.clone(),
            url::Url::parse(&session.server)
                .map_err(|_| "The account server is invalid")?
                .to_string(),
            session.client_id.clone(),
            issuer,
            trusted.account_id().to_owned(),
        )
        .map_err(|_| "Could not bind the account scope")?;
        let digest = format!(
            "{:x}",
            sha2::Sha256::digest(
                serde_json::to_vec(&account_scope)
                    .map_err(|_| "Could not bind the account scope")?
            )
        );
        let reservation = windows_profile_registry::VaultReservation::new(
            digest.clone(),
            listing.space_id.clone(),
            listing.root.id.clone(),
            root_path.clone(),
        )?;
        let token = listing
            .integrity_token
            .as_deref()
            .ok_or("The selected vault is not initialized")?;
        self.vault_sessions
            .unlock(&scope, password.as_mut_bytes(), token)
            .map_err(|_| "Could not verify the vault password")?;
        // Every failure after verified insertion must clear this new session.
        let result = (|| {
            let binding = Arc::new(
                raiun_cloudfiles_windows::vault_read::WindowsVaultReadBinding::new_online(
                    trusted,
                    client,
                    self.vault_sessions.clone(),
                    scope.clone(),
                    root_path.clone(),
                )
                .map_err(|_| "Could not bind the verified vault read route")?,
            );
            let storage = DpapiSessionStore::current_user()
                .map_err(|_| "Private Windows storage is unavailable")?;
            let parent =
                raiun_control_windows::PinnedDirectory::open(storage.local_edit_state_directory())
                    .map_err(|_| "Private Windows storage could not be admitted")?;
            let staging_scope =
                serde_json::to_vec(&(digest.as_str(), scope.space_id(), scope.resource_id()))
                    .map_err(|_| "Could not bind private vault staging")?;
            let name = format!("vault-stage-{:x}", sha2::Sha256::digest(staging_scope));
            let private = Arc::new(
                raiun_control_windows::PrivateDirectory::create_or_open_under(
                    &parent,
                    std::ffi::OsStr::new(&name),
                )
                .map_err(|_| "Private vault staging could not be admitted")?,
            );
            let adapter = Arc::new(
                raiun_cloudfiles_windows::vault_placeholder::WindowsVaultPlaceholderBackend::new(
                    binding,
                    private,
                    raiun_cloudfiles_windows::MAX_REQUEST_BYTES,
                )
                .map_err(|_| "Could not prepare the verified vault adapter")?,
            );
            Ok(adapter)
        })();
        let adapter = match result {
            Ok(adapter) => adapter,
            Err(error) => {
                let _ = self.vault_sessions.lock(&scope);
                return Err(error);
            }
        };
        let prepared = PreparedWindowsVaultUnlock {
            backend,
            adapter,
            sessions: self.vault_sessions.clone(),
            scope,
            reservation,
            generation,
            configuration,
            session,
            root_path,
            _root_lease: root_lease,
            published: false,
        };
        self.check_vault_preparation(&prepared)?;
        Ok(prepared)
    }
    fn publish_windows_vault_unlock(
        &self,
        mut prepared: PreparedWindowsVaultUnlock,
    ) -> Result<Value, String> {
        // The broker has already committed the historical reservation. Make
        // the same exclusion live BEFORE any later revalidation can fail.
        if prepared
            .backend
            .reserve_live_vault_exclusion(
                prepared._root_lease.identity(),
                prepared.scope.space_id(),
                &prepared.root_path,
            )
            .is_err()
        {
            let _ = self.provider.disconnect();
            return Err("Could not exclude the verified vault from ordinary access".into());
        }
        self.check_vault_preparation(&prepared)?;
        prepared
            .backend
            .install_vault_route(prepared.adapter.clone(), prepared._root_lease.identity())
            .map_err(|_| "Could not install the verified vault route")?;
        if let Err(error) = self.check_vault_preparation(&prepared) {
            // Disconnect owns all retired routes and preserves failed cleanup.
            let _ = self.provider.disconnect();
            return Err(error);
        }
        let owner = prepared
            .configuration
            .registration_ownership
            .as_ref()
            .ok_or("The drive owner changed")?;
        let active = ActiveProviderBinding {
            generation: prepared.generation,
            path: PathBuf::from(&prepared.configuration.path),
            identity: prepared._root_lease.identity(),
            personal_space_id: owner.personal_drive_id.clone(),
            personal_root_resource_id: owner
                .personal_root_resource_id
                .clone()
                .ok_or("The drive root is unverified")?,
        };
        if let Err(error) = self
            .provider
            .refresh_vault_parent(
                active,
                prepared.scope.space_id().to_owned(),
                prepared.scope.resource_id().to_owned(),
                prepared.root_path.clone(),
            )
            .and_then(|()| self.check_vault_preparation(&prepared))
        {
            // A route without confirmed enumeration is not a successful unlock.
            // Disconnect retains its cleanup ownership and historical exclusion.
            let _ = self.provider.disconnect();
            return Err(error);
        }
        prepared.published = true;
        Ok(json!({"unlocked":true,"root_path":prepared.root_path,
            "root_resource_id":prepared.scope.resource_id(),"vault_mount_ready":false,
            "vault_mount_writable":false,"vault_mount_existing_file_overwrite":false,
            "vault_mount_write_unavailable_reason":"route_not_installed",
            "remembered":false,"remembered_status":"not_saved"}))
    }
}
