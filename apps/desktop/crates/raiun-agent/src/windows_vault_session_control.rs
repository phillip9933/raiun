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
    remembered_scope: windows_vault_credentials::Scope,
    remember_password: Option<zeroize::Zeroizing<Vec<u8>>>,
    used_saved_password: bool,
}
impl Drop for PreparedWindowsVaultUnlock {
    fn drop(&mut self) {
        if !self.published {
            let _ = self.sessions.lock(&self.scope);
        }
    }
}
impl WindowsAgent {
    fn inspect_windows_vault(&self, request: &Value) -> Result<Value, String> {
        // Disabled preparation adds no credential I/O or session observation.
        if !WINDOWS_VAULT_SESSIONS_ENABLED {
            return self.folder_request(request);
        }
        let _operation = self
            .vault_credential_operation
            .lock()
            .map_err(|_| "Vault credential operation is unavailable")?;
        let (session, generation) = {
            let state = self
                .state
                .lock()
                .map_err(|_| "Account state is unavailable")?;
            if !state.online_authenticated
                || state.authenticating
                || state.refreshing
                || state.logout_pending
                || state.needs_refresh
                || state.session_cleanup_uncertain
            {
                return Err("Connect this account before inspecting a remembered password".into());
            }
            (
                state
                    .session
                    .clone()
                    .ok_or("A verified account is required")?,
                state.active_generation,
            )
        };
        if generation == 0 || generation != self.generation.load(Ordering::Acquire) {
            return Err("The vault account changed".into());
        }
        // Existing same-worker path performs fresh metadata inspection and exact
        // selected root/Space joins. No AccountState or secret-file lock is held.
        let mut inspected = self.folder_request(request)?;
        let space_id = request
            .get("space_id")
            .and_then(Value::as_str)
            .ok_or("The selected vault is invalid")?;
        let root_id = inspected
            .get("root_resource_id")
            .and_then(Value::as_str)
            .ok_or("The inspected vault has no stable identity")?;
        let account = self
            .provider
            .bandwidth
            .scope()?
            .filter(|scope| {
                scope.matches(
                    &self.profile_scope,
                    &session.server,
                    &session.client_id,
                    session.expected_issuer.as_deref(),
                )
            })
            .ok_or("A verified account is required")?;
        let origin = url::Url::parse(&session.server)
            .map_err(|_| "The vault account is invalid")?
            .origin()
            .ascii_serialization();
        let vault = raiun_vault::session::VaultSessionScope::new(
            &self.profile_scope,
            &origin,
            space_id,
            root_id,
        )
        .map_err(|_| "The inspected vault scope is invalid")?;
        let scope = windows_vault_credentials::Scope::from_trusted_account(
            &self.profile_scope,
            account.bytes(),
            &vault,
        )?;
        let remembered_status = match windows_vault_credentials::contains_saved(
            &VaultCredentialStore {
                store: self.session_store.as_ref(),
                profile: &self.profile_scope,
            },
            &scope,
        ) {
            Ok(true) => "known_saved",
            Ok(false) => "not_saved",
            Err(_) => "unavailable",
        };
        // Presence never establishes unlock authority. Read actual coordinator
        // state for the exact inspected vault, under the same operation gate.
        let unlocked = self
            .vault_sessions
            .is_unlocked(&vault)
            .map_err(|_| "Vault session state is unavailable")?;
        if self
            .provider
            .bandwidth
            .scope()?
            .is_none_or(|current| current.bytes() != account.bytes())
        {
            return Err("The vault account changed during inspection".into());
        }
        {
            let state = self
                .state
                .lock()
                .map_err(|_| "Account state is unavailable")?;
            if generation != self.generation.load(Ordering::Acquire)
                || state.active_generation != generation
                || !state.online_authenticated
                || state.authenticating
                || state.refreshing
                || state.logout_pending
                || state.needs_refresh
                || state.session_cleanup_uncertain
                || state.session.as_ref().is_none_or(|current| {
                    current.server != session.server
                        || current.client_id != session.client_id
                        || current.expected_issuer != session.expected_issuer
                        || current.access_token != session.access_token
                        || current.expires_at != session.expires_at
                })
            {
                return Err(
                    "The account changed during vault inspection; refresh before continuing".into(),
                );
            }
        }
        inspected["remembered_status"] = json!(remembered_status);
        inspected["unlocked"] = json!(unlocked);
        // Coordinator state does not prove native projection or lock acceptance.
        inspected["vault_mount_ready"] = json!(false);
        inspected["vault_mount_writable"] = json!(false);
        Ok(inspected)
    }

    fn forget_windows_vault_password(
        &self,
        target: &windows_vault_requests::session_requests::VaultTarget,
    ) -> Result<Value, String> {
        if target
            .profile_id
            .as_ref()
            .is_some_and(|p| p != &self.profile_scope)
        {
            return Err("Select the current Windows account".into());
        }
        let (session, generation) = {
            let state = self
                .state
                .lock()
                .map_err(|_| "Account state is unavailable")?;
            if state.authenticating
                || state.refreshing
                || state.logout_pending
                || state.session_cleanup_uncertain
            {
                return Err("Wait for the account transition before forgetting a password".into());
            }
            (
                state
                    .session
                    .clone()
                    .ok_or("A verified account is required")?,
                state.active_generation,
            )
        };
        let account = self
            .provider
            .bandwidth
            .scope()?
            .filter(|scope| {
                scope.matches(
                    &self.profile_scope,
                    &session.server,
                    &session.client_id,
                    session.expected_issuer.as_deref(),
                )
            })
            .ok_or("A verified account is required")?;
        if generation == 0 || generation != self.generation.load(Ordering::Acquire) {
            return Err("The vault account changed".into());
        }
        let origin = url::Url::parse(&session.server)
            .map_err(|_| "The vault account is invalid")?
            .origin()
            .ascii_serialization();
        let vault = raiun_vault::session::VaultSessionScope::new(
            &self.profile_scope,
            &origin,
            &target.space_id,
            &target.root_resource_id,
        )
        .map_err(|_| "The vault scope is invalid")?;
        let scope = windows_vault_credentials::Scope::from_trusted_account(
            &self.profile_scope,
            account.bytes(),
            &vault,
        )?;
        windows_vault_credentials::forget(
            &VaultCredentialStore {
                store: self.session_store.as_ref(),
                profile: &self.profile_scope,
            },
            &scope,
        )?;
        let state = self
            .state
            .lock()
            .map_err(|_| "The password may have been forgotten; account state is unavailable")?;
        if generation != self.generation.load(Ordering::Acquire)
            || state.active_generation != generation
            || state.authenticating
            || state.refreshing
            || state.logout_pending
            || state.session_cleanup_uncertain
            || state.session.as_ref().is_none_or(|current| {
                current.server != session.server
                    || current.client_id != session.client_id
                    || current.expected_issuer != session.expected_issuer
                    || current.access_token != session.access_token
            })
        {
            return Err("The account changed; the password may have been forgotten, so refresh before continuing".into());
        }
        Ok(json!({"remembered":false,"remembered_status":"not_saved","forgotten":true}))
    }
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
        credential: &mut windows_vault_requests::session_requests::VaultUnlockCredential,
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
        let verified = self.provider.verified_vault_backend(active)?;
        let backend = verified.backend;
        let custody = verified.custody;
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
        let account_bytes =
            serde_json::to_vec(&account_scope).map_err(|_| "Could not bind the account scope")?;
        let digest = format!("{:x}", sha2::Sha256::digest(&account_bytes));
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
        // Reuse the exact canonical account identity used for the reservation.
        // Reconstructing from raw session URLs can disagree on an origin's
        // optional slash, even though the authenticated identity is unchanged.
        let remembered_scope = windows_vault_credentials::Scope::from_trusted_account(
            &self.profile_scope,
            &account_bytes,
            &scope,
        )?;
        let store = VaultCredentialStore {
            store: self.session_store.as_ref(),
            profile: &self.profile_scope,
        };
        let mut saved_password = if matches!(
            credential,
            windows_vault_requests::session_requests::VaultUnlockCredential::Saved
        ) {
            Some(
                windows_vault_credentials::load(&store, &remembered_scope)?
                    .ok_or("No remembered password is available for this exact vault")?,
            )
        } else {
            None
        };
        let used_saved_password = saved_password.is_some();
        let mut remember_password = None;
        let material = match credential {
            windows_vault_requests::session_requests::VaultUnlockCredential::Manual {
                password,
                remember,
            } => {
                if *remember {
                    // The owned input is bounded by the decoder. Allocate once;
                    // this extra zeroized copy survives the KDF's input wipe.
                    let bytes = password.as_mut_bytes();
                    let mut copy = zeroize::Zeroizing::new(Vec::with_capacity(bytes.len()));
                    copy.extend_from_slice(bytes);
                    remember_password = Some(copy);
                }
                password.as_mut_bytes()
            }
            windows_vault_requests::session_requests::VaultUnlockCredential::Saved => {
                saved_password
                    .as_mut()
                    .ok_or("The remembered password changed")?
                    .as_mut_slice()
            }
        };
        self.vault_sessions
            .unlock(&scope, material, token)
            .map_err(|_| "Could not verify the vault password")?;
        // Every failure after verified insertion must clear this new session.
        let result = (|| {
            let custody_view = custody.view(&trusted, &scope, &root_path)?;
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
                    custody_view,
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
            remembered_scope,
            remember_password,
            used_saved_password,
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
        // The per-runtime operation fence spans load/proof/publication and
        // serializes forget/logout. Stored bytes never authorize a route.
        let (remembered, remembered_status) =
            if let Some(password) = prepared.remember_password.as_ref() {
                let store = VaultCredentialStore {
                    store: self.session_store.as_ref(),
                    profile: &self.profile_scope,
                };
                let saved = windows_vault_credentials::begin_remember(
                    &store,
                    prepared.remembered_scope.clone(),
                )
                .and_then(|ticket| {
                    windows_vault_credentials::commit_remember(&store, ticket, password)
                });
                if saved.is_ok() {
                    (true, "known_saved")
                } else {
                    (false, "unavailable")
                }
            } else if prepared.used_saved_password {
                (true, "known_saved")
            } else {
                (false, "unknown")
            };
        if let Err(error) = self.check_vault_preparation(&prepared) {
            let _ = self.provider.disconnect();
            return Err(error);
        }
        prepared.published = true;
        Ok(json!({"unlocked":true,"root_path":prepared.root_path,
            "root_resource_id":prepared.scope.resource_id(),"vault_mount_ready":false,
            "vault_mount_writable":false,"vault_mount_existing_file_overwrite":false,
            "vault_mount_write_unavailable_reason":"route_not_installed",
            "remembered":remembered,"remembered_status":remembered_status}))
    }
}
