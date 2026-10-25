// Explicit hot-route capture upload. No scheduler, native acknowledgement,
// cleanup, history retirement or writable publication is enabled here.

const WINDOWS_VAULT_EDIT_UPLOAD_ENABLED: bool = false;

impl WindowsAgent {
    fn upload_windows_vault_capture_request(&self, request: &Value) -> Result<Value, String> {
        let field = |name: &str| {
            request
                .get(name)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty() && value.len() <= 4096)
                .ok_or_else(|| "Select an existing retained vault edit".to_owned())
        };
        let origin = {
            let state = self
                .state
                .lock()
                .map_err(|_| "Account state is unavailable")?;
            url::Url::parse(&state.session.as_ref().ok_or("Connect this account")?.server)
                .map_err(|_| "The account origin is invalid")?
                .origin()
                .ascii_serialization()
        };
        let vault = raiun_vault::session::VaultSessionScope::new(
            &self.profile_scope,
            &origin,
            field("space_id")?,
            field("root_resource_id")?,
        )
        .map_err(|_| "The vault scope is invalid")?;
        self.upload_windows_vault_capture(&vault, field("root_path")?, field("capture_id")?)
    }

    /// One explicitly selected, never-attempted retained edit on an already-live
    /// route. This runs on the control/native-test caller, never on the provider
    /// command owner thread. All state/custody/publication locks end before HTTP.
    /// Post-lock/restart recovery and replay require separate reconciliation.
    fn upload_windows_vault_capture(
        &self,
        vault: &raiun_vault::session::VaultSessionScope,
        remote_root: &str,
        capture_id: &str,
    ) -> Result<Value, String> {
        use raiun_cloudfiles_windows::{CancellationToken, ExistingVaultUploadTarget};
        use raiun_core::backend::{ErrorKind, RemoteEntry};
        use raiun_opencloud::vault_backend::VaultExistingOverwriteOutcome;
        use sha2::{Digest, Sha256};
        use std::time::Instant;

        vault_edit_capture::CaptureId::new(capture_id)
            .map_err(|_| "Select an existing retained vault edit")?;
        if remote_root.len() > 4096 || !remote_root.starts_with('/') {
            return Err("The retained vault root is invalid".into());
        }
        let (session, generation, configuration) = {
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
                return Err("Connect the original account before uploading a retained edit".into());
            }
            (
                state.session.clone().ok_or("Connect this account")?,
                state.active_generation,
                state
                    .root_configuration
                    .clone()
                    .ok_or("Connect the original Windows drive")?,
            )
        };
        let owner = configuration
            .registration_ownership
            .as_ref()
            .ok_or("The original Windows drive has no verified owner")?;
        let origin = url::Url::parse(&session.server)
            .map_err(|_| "The account origin is invalid")?
            .origin()
            .ascii_serialization();
        if generation == 0
            || generation != self.generation.load(Ordering::Acquire)
            || generation != self.provider.authorized_generation.load(Ordering::Acquire)
            || !configuration.valid
            || configuration.profile_scope != self.profile_scope
            || configuration.server != session.server
            || configuration.client_id != session.client_id
            || owner.state != "registered"
            || vault.account_id() != self.profile_scope
            || vault.server_origin() != origin
            || session.expires_at <= unix_time_now().saturating_add(30)
        {
            return Err("The retained edit does not match the current account and drive".into());
        }
        validate_registration_ownership(
            owner,
            &session.server,
            configuration.volume_serial,
            configuration.file_index,
        )?;
        let identity = raiun_cloudfiles_windows::ConfiguredRootIdentity {
            volume_serial: configuration.volume_serial,
            file_index: configuration.file_index,
        };
        let _root_pin = pin_registered_configured_root(Path::new(&configuration.path), identity)
            .map_err(root_error_text)?;
        let active = ActiveProviderBinding {
            generation,
            path: PathBuf::from(&configuration.path),
            identity,
            personal_space_id: owner.personal_drive_id.clone(),
            personal_root_resource_id: owner
                .personal_root_resource_id
                .clone()
                .ok_or("The original drive root is unverified")?,
        };
        let verified = self.provider.verified_vault_backend(active.clone())?;
        let (_, trusted) = verified
            .backend
            .vault_read_context(identity)
            .map_err(|_| "The connected Windows drive changed")?;
        if trusted.profile_id() != self.profile_scope || trusted.account_id() != owner.account_id {
            return Err("The connected Windows drive belongs to another account".into());
        }
        // Do not call confirm_windows_vault_readiness/refresh_vault_parent:
        // pending capture history must keep publication readiness incomplete.
        let current = || -> Result<(), String> {
            if generation != self.generation.load(Ordering::Acquire)
                || generation != self.provider.authorized_generation.load(Ordering::Acquire)
                || verified.backend.is_revoked()
            {
                return Err("The account or Windows drive changed".into());
            }
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
                || state.active_generation != generation
                || state.root_configuration.as_ref() != Some(&configuration)
                || state.session.as_ref().is_none_or(|now| {
                    now.server != session.server
                        || now.client_id != session.client_id
                        || now.expected_issuer != session.expected_issuer
                        || now.access_token != session.access_token
                        || now.expires_at != session.expires_at
                })
            {
                return Err("The account changed during the retained edit upload".into());
            }
            drop(state);
            pin_registered_configured_root(Path::new(&configuration.path), identity)
                .map_err(root_error_text)?;
            Ok(())
        };
        current()?;
        if !self
            .vault_sessions
            .is_unlocked(vault)
            .map_err(|_| "Vault state is unavailable")?
        {
            return Err("Unlock the original vault before uploading a retained edit".into());
        }
        let ledger = verified
            .custody
            .upload_ledger(&trusted, vault, remote_root, capture_id)?;
        // ProviderScope alone omits OAuth client and issuer. Compare the complete
        // fresh authenticated account to the protected frame's canonical scope.
        let issuer = session
            .expected_issuer
            .as_ref()
            .map(|issuer| url::Url::parse(issuer).map(|url| url.to_string()))
            .transpose()
            .map_err(|_| "The account issuer is invalid")?;
        let account = raiun_engine::folder_pairs::AccountScope::new(
            self.profile_scope.clone(),
            url::Url::parse(&session.server)
                .map_err(|_| "The account server is invalid")?
                .to_string(),
            session.client_id.clone(),
            issuer,
            trusted.account_id().to_owned(),
        )
        .map_err(|_| "The authenticated account scope is invalid")?;
        let account = zeroize::Zeroizing::new(
            serde_json::to_vec(&account)
                .map_err(|_| "The authenticated account scope is unavailable")?,
        );
        if !ledger.scope().matches_canonical_account(&account) {
            return Err(
                "The retained edit belongs to a different authenticated account scope".into(),
            );
        }
        let retained = ledger
            .read_body()
            .map_err(|_| "The protected retained edit is unavailable")?;
        let original = ledger.reference().entry();
        let target = ExistingVaultUploadTarget::new(
            trusted.clone(),
            vault.clone(),
            remote_root.to_owned(),
            identity,
            original.opaque(),
            RemoteEntry {
                id: original.remote_id().into(),
                path: original.root_relative_path().into(),
                directory: original.is_directory(),
                size: original.length(),
                etag: original.etag().into(),
                modified_unix: 0,
                writable: false,
                encrypted: false,
            },
        )
        .map_err(|_| "The retained edit has an invalid original target")?;
        let mut attempt = match ledger.reopen_attempt() {
            Ok(attempt) => attempt,
            Err(vault_edit_upload::Error::Missing) => ledger
                .initialize_attempt()
                .map_err(|_| "The upload attempt could not be durably initialized")?,
            Err(_) => return Err("The protected upload attempt is unavailable".into()),
        };
        current()?;
        ledger
            .verify_current()
            .map_err(|_| "The retained edit context changed")?;
        let ticket = attempt.begin_attempt(&ledger).map_err(
            |_| "This retained edit already has an attempt; inspect recovery before continuing",
        )?;
        let cancellation = CancellationToken::for_offline_job();
        let deadline = Instant::now() + Duration::from_secs(300);
        let cancelled = || {
            cancellation.is_cancelled()
                || cancellation.is_expired()
                || Instant::now() >= deadline
                || self.generation.load(Ordering::Acquire) != generation
                || self.provider.authorized_generation.load(Ordering::Acquire) != generation
                || verified.backend.is_revoked()
        };
        let mut source = std::io::Cursor::new(retained.bytes_for_recovery());
        let outcome = verified.backend.upload_existing_vault_capture(
            &target,
            &mut source,
            retained.bytes_for_recovery().len() as u64,
            Arc::clone(&self.provider.authorized_generation),
            generation,
            &cancelled,
        );
        let uncertain = || {
            json!({"state":"uncertain", "capture_id":capture_id,
            "retained":true, "local_cleanup":"incomplete", "automatic_retry":false})
        };
        // A failed postcheck may leave Attempting if even an uncertainty CAS
        // cannot be authenticated. Reopening that record becomes Uncertain;
        // never claim rollback, replay, cleanup or a current remote version.
        if current().is_err() || ledger.verify_current().is_err() || cancelled() {
            let _ = attempt.record_uncertain(&ledger, ticket);
            return Ok(uncertain());
        }
        match outcome {
            Ok(VaultExistingOverwriteOutcome::Verified(receipt)) => {
                let digest: [u8; 32] = Sha256::digest(retained.bytes_for_recovery()).into();
                if receipt.plaintext_sha256() != digest {
                    let _ = attempt.record_uncertain(&ledger, ticket);
                    return Ok(uncertain());
                }
                let entry = receipt.entry();
                if attempt
                    .record_readback_evidence(
                        &ledger,
                        ticket,
                        &entry.id,
                        &entry.etag,
                        &entry.etag,
                        retained.bytes_for_recovery(),
                    )
                    .is_err()
                {
                    return Ok(uncertain());
                }
                Ok(
                    json!({"state":"remote_verified_pending_local", "capture_id":capture_id,
                    "retained":true, "local_cleanup":"incomplete", "automatic_retry":false}),
                )
            }
            Ok(VaultExistingOverwriteOutcome::NeedsReconciliation { .. }) => {
                let _ = attempt.record_uncertain(&ledger, ticket);
                Ok(uncertain())
            }
            Err(error) => {
                // The primitive guarantees Err means no PUT was dispatched.
                // Conflict is still retained and never automatically retried.
                if error.kind == ErrorKind::Conflict {
                    let _ = attempt.record_conflict(&ledger, ticket);
                } else {
                    let _ = attempt.record_uncertain(&ledger, ticket);
                }
                Ok(uncertain())
            }
        }
    }
}
