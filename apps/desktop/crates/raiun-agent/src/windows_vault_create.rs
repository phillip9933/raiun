// Explicit NEW folder creation. Every remote failure retains the created folder;
// the existing broker owns exclusion reservation and native publication.
struct WindowsVaultContext {
    session: auth::Session,
    generation: u64,
    configuration: RootConfiguration,
    identity: raiun_cloudfiles_windows::ConfiguredRootIdentity,
    root_lease: raiun_cloudfiles_windows::ConfiguredRootLease,
    active: ActiveProviderBinding,
    verified: VerifiedVaultBackend,
}
impl WindowsAgent {
    fn capture_windows_vault_context(
        &self,
        profile_id: Option<&str>,
        expected_generation: Option<u64>,
    ) -> Result<WindowsVaultContext, String> {
        if profile_id.is_some_and(|id| id != self.profile_scope) {
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
        if expected_generation.is_some_and(|expected| expected != generation) {
            return Err("The account changed before vault creation".into());
        }
        let verified = self.provider.verified_vault_backend(active.clone())?;
        let (_, trusted) = verified
            .backend
            .vault_read_context(identity)
            .map_err(|_| "The connected drive changed")?;
        if trusted.profile_id() != self.profile_scope || trusted.account_id() != owner.account_id {
            return Err("The connected drive belongs to another account".into());
        }
        self.check_windows_vault_authority(
            &session,
            generation,
            &configuration,
            &verified.backend,
        )?;
        Ok(WindowsVaultContext {
            session,
            generation,
            configuration,
            identity,
            root_lease,
            active,
            verified,
        })
    }
    fn check_windows_vault_authority(
        &self,
        session: &auth::Session,
        generation: u64,
        configuration: &RootConfiguration,
        backend: &raiun_cloudfiles_windows::OpenCloudPlaceholderBackend,
    ) -> Result<(), String> {
        let state = self
            .state
            .lock()
            .map_err(|_| "Account state is unavailable")?;
        if self.generation.load(Ordering::Acquire) != generation
            || state.active_generation != generation
            || !state.online_authenticated
            || state.logout_pending
            || state.authenticating
            || state.refreshing
            || state.needs_refresh
            || state.session_cleanup_uncertain
            || state.root_configuration.as_ref() != Some(configuration)
            || state.session.as_ref().is_none_or(|current| {
                current.server != session.server
                    || current.client_id != session.client_id
                    || current.expected_issuer != session.expected_issuer
                    || !Self::same_session_authority(Some(current), Some(session))
                    || current.expires_at <= unix_time_now().saturating_add(30)
            })
            || backend.is_revoked()
        {
            return Err("The account changed during vault preparation".into());
        }
        Ok(())
    }

    fn inspect_windows_vault_create_parent(&self, request: &Value) -> Result<Value, String> {
        use raiun_core::backend::CloudBackend;
        let fields = request.as_object().ok_or("Invalid vault parent request")?;
        if fields.keys().any(|key| {
            !matches!(
                key.as_str(),
                "action" | "profile_id" | "space_id" | "parent_path" | "expected_auth_generation"
            )
        }) {
            return Err("Invalid vault parent request".into());
        }
        let text = |key: &str, max: usize| {
            fields
                .get(key)
                .and_then(Value::as_str)
                .filter(|s| {
                    !s.is_empty()
                        && s.len() <= max
                        && s.trim() == *s
                        && !s.chars().any(char::is_control)
                })
                .ok_or("Invalid vault parent request")
        };
        let profile = text("profile_id", 128)?;
        let space = text("space_id", 512)?;
        let path = text("parent_path", 4096)?;
        raiun_core::validate_remote_path(path).map_err(|_| "Invalid vault parent path")?;
        let expected = fields
            .get("expected_auth_generation")
            .and_then(Value::as_u64)
            .filter(|g| *g != 0)
            .ok_or("Invalid account generation")?;
        let context = self.capture_windows_vault_context(Some(profile), Some(expected))?;
        let (client, _) = context
            .verified
            .backend
            .vault_read_context(context.identity)
            .map_err(|_| "The connected drive changed")?;
        let spaces = client
            .spaces()
            .map_err(|_| "Could not inspect the selected Space")?;
        if !spaces
            .iter()
            .any(|selected| selected.id == space && selected.writable && !selected.encrypted)
        {
            return Err("Choose an ordinary writable Space".into());
        }
        let parent = client
            .stat(space, path)
            .map_err(|_| "Could not inspect the selected parent")?;
        if !parent.directory || !parent.writable || parent.encrypted {
            return Err("Choose an ordinary writable parent folder".into());
        }
        self.check_windows_vault_authority(
            &context.session,
            context.generation,
            &context.configuration,
            &context.verified.backend,
        )?;
        Ok(
            json!({"parent_path":path,"parent_resource_id":parent.id,"auth_generation":context.generation}),
        )
    }
    fn prepare_windows_vault_create(
        &self,
        request: windows_vault_requests::create_requests::VaultCreateRequest,
    ) -> Result<PreparedWindowsVaultUnlock, String> {
        let windows_vault_requests::create_requests::VaultCreateRequest {
            target,
            name,
            expected_auth_generation,
            password,
        } = request;
        let mut credential =
            windows_vault_requests::session_requests::VaultUnlockCredential::Manual {
                password: windows_vault_requests::session_requests::VaultPassword::from_owned(
                    password,
                ),
                remember: false,
            };
        self.prepare_windows_vault_session(
            &target,
            &mut credential,
            Some((&name, expected_auth_generation)),
        )
    }
}
