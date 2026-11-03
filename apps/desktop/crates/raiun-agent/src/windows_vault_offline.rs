// Encrypted offline snapshot controls. Cache membership is scoped by the exact
// authenticated saved AccountScope; it grants neither bearer nor native write.
struct WindowsVaultOfflineAccount {
    configuration: RootConfiguration,
    generation: u64,
    account: Vec<u8>,
    origin: String,
    _root: raiun_cloudfiles_windows::ConfiguredRootLease,
}
impl WindowsAgent {
    fn windows_vault_offline_account(
        &self,
        expected: u64,
    ) -> Result<WindowsVaultOfflineAccount, String> {
        let (configuration, generation) = {
            let state = self
                .state
                .lock()
                .map_err(|_| "Account state is unavailable")?;
            if state.retiring
                || state.logout_pending
                || state.authenticating
                || state.refreshing
                || state.session_cleanup_uncertain
                || state.active_generation == 0
                || state.active_generation != expected
                || self.generation.load(Ordering::Acquire) != expected
            {
                return Err("The encrypted offline account changed".into());
            }
            let c = state
                .root_configuration
                .clone()
                .ok_or("Connect this account once before offline access")?;
            if state.session.as_ref().is_some_and(|s| {
                s.server != c.server || s.client_id != c.client_id || s.expected_issuer != c.issuer
            }) {
                return Err("The saved offline account does not match this sign-in".into());
            }
            (c, state.active_generation)
        };
        let owner = configuration
            .registration_ownership
            .as_ref()
            .ok_or("The saved Windows root has no authenticated owner")?;
        if !configuration.valid
            || configuration.profile_scope != self.profile_scope
            || owner.state != "registered"
            || owner.volume_serial != configuration.volume_serial
            || owner.file_index != configuration.file_index
        {
            return Err("The saved Windows root ownership changed".into());
        }
        let issuer = configuration
            .issuer
            .as_deref()
            .map(|v| url::Url::parse(v).map(|v| v.to_string()))
            .transpose()
            .map_err(|_| "The saved issuer is invalid")?;
        let account = raiun_engine::folder_pairs::AccountScope::new(
            self.profile_scope.clone(),
            url::Url::parse(&configuration.server)
                .map_err(|_| "The saved server is invalid")?
                .to_string(),
            configuration.client_id.clone(),
            issuer,
            owner.account_id.clone(),
        )
        .map_err(|_| "The saved offline account is invalid")?;
        let account = serde_json::to_vec(&account)
            .map_err(|_| "Could not bind the encrypted offline account")?;
        let origin = url::Url::parse(&configuration.server)
            .map_err(|_| "The saved server is invalid")?
            .origin()
            .ascii_serialization();
        let root = pin_registered_configured_root(
            Path::new(&configuration.path),
            raiun_cloudfiles_windows::ConfiguredRootIdentity {
                volume_serial: configuration.volume_serial,
                file_index: configuration.file_index,
            },
        )
        .map_err(|_| "The saved Windows root registration changed")?;
        let result = WindowsVaultOfflineAccount {
            configuration,
            generation,
            account,
            origin,
            _root: root,
        };
        self.check_windows_vault_offline_account(&result)?;
        Ok(result)
    }
    fn check_windows_vault_offline_account(
        &self,
        context: &WindowsVaultOfflineAccount,
    ) -> Result<(), String> {
        let state = self
            .state
            .lock()
            .map_err(|_| "Account state is unavailable")?;
        if state.retiring
            || state.logout_pending
            || state.authenticating
            || state.refreshing
            || state.session_cleanup_uncertain
            || state.active_generation != context.generation
            || self.generation.load(Ordering::Acquire) != context.generation
            || state.root_configuration.as_ref() != Some(&context.configuration)
        {
            return Err("The encrypted offline account changed".into());
        }
        Ok(())
    }
    fn open_windows_vault_cache(
        &self,
        context: &WindowsVaultOfflineAccount,
    ) -> Result<raiun_cache::Cache, String> {
        use sha2::Digest;
        self.check_windows_vault_offline_account(context)?;
        let storage = DpapiSessionStore::current_user()
            .map_err(|_| "Private Windows storage is unavailable")?;
        let parent =
            raiun_control_windows::PinnedDirectory::open(storage.local_edit_state_directory())
                .map_err(|_| "Private Windows storage changed")?;
        let name = format!("vault-offline-{:x}", sha2::Sha256::digest(&context.account));
        let directory = raiun_control_windows::PrivateDirectory::create_or_open_under(
            &parent,
            std::ffi::OsStr::new(&name),
        )
        .map_err(|_| "Private encrypted cache is unavailable")?;
        let cache = raiun_cache::Cache::open(directory.path(), 1 << 30)
            .map_err(|_| "Could not open the encrypted offline cache")?;
        self.check_windows_vault_offline_account(context)?;
        Ok(cache)
    }
    fn windows_vault_offline_request(&self, request: &Value) -> Result<Value, String> {
        use raiun_opencloud::{vault_backend::VaultBackend, vault_cache::VaultOfflineCache};
        let fields = request
            .as_object()
            .ok_or("Invalid encrypted offline request")?;
        let action = fields
            .get("action")
            .and_then(Value::as_str)
            .ok_or("Invalid encrypted offline action")?;
        let extra: &[&str] = match action {
            "vault_pin_start" => &["space_id", "root_resource_id", "root_path", "pin_id"],
            "vault_pins" => &["space_id", "root_resource_id", "after", "limit"],
            "vault_pin_status" | "vault_pin_cancel" => &["space_id", "root_resource_id", "job_id"],
            "vault_pin_remove" => &["space_id", "root_resource_id", "pin_id"],
            "vault_cache_usage" => &[],
            "vault_cache_quota_set" => &["quota_bytes"],
            _ => return Err("Unsupported encrypted offline action".into()),
        };
        if fields.keys().any(|k| {
            !matches!(k.as_str(), "action" | "profile_id" | "expected_generation")
                && !extra.contains(&k.as_str())
        }) {
            return Err("Invalid encrypted offline fields".into());
        }
        if fields.get("profile_id").and_then(Value::as_str) != Some(self.profile_scope.as_str()) {
            return Err("Select the current encrypted offline account".into());
        }
        let expected = fields
            .get("expected_generation")
            .and_then(Value::as_u64)
            .filter(|g| *g != 0)
            .ok_or("Refresh the current account")?;
        let text = |key: &str, max: usize| -> Result<&str, String> {
            fields
                .get(key)
                .and_then(Value::as_str)
                .filter(|s| {
                    !s.is_empty()
                        && s.len() <= max
                        && s.trim() == *s
                        && !s.chars().any(char::is_control)
                })
                .ok_or_else(|| "Invalid encrypted offline selection".into())
        };
        let _operation = self
            .vault_credential_operation
            .lock()
            .map_err(|_| "Vault operations are unavailable")?;
        let context = self.windows_vault_offline_account(expected)?;
        let cache = self.open_windows_vault_cache(&context)?;
        if action == "vault_cache_usage" || action == "vault_cache_quota_set" {
            if action == "vault_cache_quota_set" {
                let quota = fields
                    .get("quota_bytes")
                    .and_then(Value::as_u64)
                    .ok_or("Invalid encrypted cache allowance")?;
                cache
                    .set_quota_bytes(quota)
                    .map_err(|_| "Encrypted cache allowance was not changed")?;
            }
            let usage = cache
                .usage()
                .map_err(|_| "Encrypted cache usage is unavailable")?;
            self.check_windows_vault_offline_account(&context)?;
            return Ok(
                json!({"quota_bytes":usage.quota_bytes,"used_bytes":usage.used_bytes,"pinned_bytes":usage.pinned_bytes,"protected_bytes":usage.protected_bytes,"over_quota":usage.over_quota}),
            );
        }
        let scope = raiun_vault::session::VaultSessionScope::new(
            &self.profile_scope,
            &context.origin,
            text("space_id", 512)?,
            text("root_resource_id", 4096)?,
        )
        .map_err(|_| "Invalid encrypted offline scope")?;
        let offline = VaultOfflineCache::new(cache, scope.clone(), "/")
            .map_err(|_| "Encrypted offline cache is unavailable")?;
        let result = match action {
            "vault_pin_start" => {
                let root = text("root_path", 4096)?;
                raiun_core::validate_remote_path(root).map_err(|_| "Invalid encrypted root")?;
                let online =
                    self.capture_windows_vault_context(Some(&self.profile_scope), Some(expected))?;
                let (client, trusted) = online
                    .verified
                    .backend
                    .vault_read_context(online.identity)
                    .map_err(|_| "The connected vault account changed")?;
                let owner = context
                    .configuration
                    .registration_ownership
                    .as_ref()
                    .ok_or("The offline root changed")?;
                if trusted.account_id() != owner.account_id
                    || trusted.profile_id() != self.profile_scope
                    || trusted.server_origin() != context.origin
                {
                    return Err("The connected and offline accounts differ".into());
                }
                if !self
                    .vault_sessions
                    .is_unlocked(&scope)
                    .map_err(|_| "Vault state is unavailable")?
                {
                    return Err("Unlock this encrypted vault before saving it offline".into());
                }
                let offline = VaultOfflineCache::new(
                    self.open_windows_vault_cache(&context)?,
                    scope.clone(),
                    root,
                )
                .map_err(|_| "Encrypted offline cache is unavailable")?;
                let backend = VaultBackend::new_with_offline_cache(
                    (*client).clone(),
                    self.vault_sessions.clone(),
                    scope.clone(),
                    root.into(),
                    offline,
                )
                .map_err(|_| "Could not prepare the encrypted offline snapshot")?;
                self.check_windows_vault_offline_account(&context)?;
                let pin = fields
                    .get("pin_id")
                    .map(|_| text("pin_id", 256).map(str::to_owned))
                    .transpose()?;
                let job = crate::vault_pin_jobs::VaultPinJobs::start(
                    &self.vault_copy_serialization,
                    &scope,
                    backend,
                    pin,
                    self.generation.clone(),
                    expected,
                )?;
                json!({"accepted":true,"job_id":job})
            }
            "vault_pins" => {
                let after = fields
                    .get("after")
                    .map(|_| text("after", 256))
                    .transpose()?;
                let limit = fields
                    .get("limit")
                    .map(|v| v.as_u64().ok_or("Invalid snapshot page size"))
                    .transpose()?
                    .unwrap_or(50);
                let page = offline
                    .pins(
                        after,
                        usize::try_from(limit).map_err(|_| "Invalid snapshot page size")?,
                    )
                    .map_err(|_| "Encrypted snapshot list is unavailable")?;
                json!({"items":page.items.into_iter().map(windows_ciphertext_pin).collect::<Vec<_>>(),"next_after":page.next_after,"truncated":page.truncated,"active_job_id":self.vault_copy_serialization.active_job_id(&scope)?})
            }
            "vault_pin_status" => {
                let job = text("job_id", 256)?;
                let s = self
                    .vault_copy_serialization
                    .status(&scope, job)?
                    .ok_or("Encrypted snapshot job was not found")?;
                json!({"job_id":job,"state":s.state,"error":s.error,"items_done":s.items_done,"bytes_done":s.bytes_done,"pin":s.pin.map(windows_ciphertext_pin)})
            }
            "vault_pin_cancel" => {
                json!({"cancelled":self.vault_copy_serialization.cancel(&scope,text("job_id",256)?)?})
            }
            "vault_pin_remove" => {
                self.vault_copy_serialization
                    .cancel_scope_and_wait(&scope)?;
                offline
                    .remove_pin(text("pin_id", 256)?)
                    .map_err(|_| "Encrypted snapshot could not be removed")?;
                json!({"removed":true})
            }
            _ => return Err("Unsupported encrypted offline action".into()),
        };
        self.check_windows_vault_offline_account(&context)?;
        Ok(result)
    }
}
fn windows_ciphertext_pin(pin: raiun_cache::CiphertextPinInfo) -> Value {
    let state = match pin.state {
        raiun_cache::CiphertextPinState::Building => "building",
        raiun_cache::CiphertextPinState::Ready => "ready",
        raiun_cache::CiphertextPinState::Stale => "stale",
    };
    json!({"id":pin.id,"generation":pin.generation,"state":state,"item_count":pin.item_count,"byte_len":pin.byte_len})
}
