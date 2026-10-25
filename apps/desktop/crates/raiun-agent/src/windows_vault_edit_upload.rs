// Guarded hot-route capture upload, shared with private fresh-close dispatch.
// Normal activation, cleanup, history retirement and writable publication
// remain disabled. Explicit native byte-completion candidates are private.

const WINDOWS_VAULT_EDIT_UPLOAD_ENABLED: bool = false;

struct FreshVaultUploadExpectation {
    origin: windows_vault_custody::FreshCaptureOrigin,
    expected_generation: u64,
    dispatch: raiun_cloudfiles_windows::FreshVaultCaptureDispatch,
    active: Arc<std::sync::atomic::AtomicBool>,
}

impl WindowsAgent {
    /// Private one-use queue admission; a locator from history cannot call this
    /// without its original process-local custody and vault-binding identities.
    fn upload_from_fresh_close(
        &self,
        job: windows_vault_close_worker::FreshVaultCloseJob,
    ) -> Result<Value, String> {
        // Snapshot this worker's cancellation identity once. No worker mutex
        // may be reacquired by the network cancellation predicate or join path.
        let active = self.fresh_close_active_marker(job.expected_generation)?;
        let windows_vault_close_worker::FreshVaultCloseJob {
            origin,
            vault,
            remote_root,
            capture_id,
            dispatch,
            expected_generation,
        } = job;
        let mut result = self.upload_windows_vault_capture_inner(
            &vault,
            &remote_root,
            &capture_id,
            false,
            false,
            Some(FreshVaultUploadExpectation {
                origin,
                expected_generation,
                dispatch,
                active,
            }),
        )?;
        // Remote verification never authorizes native acknowledgement, dirty
        // history removal or Lock cleanup. Keep that boundary explicit.
        result
            .as_object_mut()
            .ok_or("The fresh upload result is unavailable")?
            .insert("native_confirmation".into(), Value::Bool(false));
        Ok(result)
    }

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
        self.upload_windows_vault_capture_with_completion(vault, remote_root, capture_id, false)
    }

    /// Private readonly-completion compatibility seam. Historical readback alone
    /// never supplies the owned native continuation.
    fn upload_windows_vault_capture_with_completion(
        &self,
        vault: &raiun_vault::session::VaultSessionScope,
        remote_root: &str,
        capture_id: &str,
        complete_local: bool,
    ) -> Result<Value, String> {
        self.upload_windows_vault_capture_inner(
            vault,
            remote_root,
            capture_id,
            complete_local,
            false,
            None,
        )
    }

    /// Explicit writable byte-completion candidate only. This chooses the native
    /// operation before upload; it never retries a failed readonly metadata write.
    /// The current readonly Lock cleanup guard remains authoritative and may refuse.
    #[cfg(all(test, debug_assertions))]
    fn upload_windows_vault_capture_with_writable_completion(
        &self,
        vault: &raiun_vault::session::VaultSessionScope,
        remote_root: &str,
        capture_id: &str,
    ) -> Result<Value, String> {
        let mut result = self.upload_windows_vault_capture_inner(
            vault,
            remote_root,
            capture_id,
            true,
            true,
            None,
        )?;
        let native_completed = result["state"] == "local_completed";
        let value = result
            .as_object_mut()
            .ok_or("Native byte-completion result unavailable")?;
        value.insert("native_confirmation".into(), Value::Bool(native_completed));
        value.insert("read_only_restored".into(), Value::Bool(false));
        Ok(result)
    }

    fn upload_windows_vault_capture_inner(
        &self,
        vault: &raiun_vault::session::VaultSessionScope,
        remote_root: &str,
        capture_id: &str,
        complete_local: bool,
        writable_bytes: bool,
        fresh: Option<FreshVaultUploadExpectation>,
    ) -> Result<Value, String> {
        use raiun_cloudfiles_windows::{
            CancellationToken, ExistingVaultUploadTarget, FreshVaultUpload, VaultLiveUploadOutcome,
            VaultUploadControl,
        };
        use raiun_core::backend::{ErrorKind, RemoteEntry};
        use raiun_opencloud::vault_backend::VaultExistingOverwriteOutcome;
        use sha2::{Digest, Sha256};
        use std::time::Instant;

        // Fresh automatic notifications remain remote-only. Their worker cancel
        // identity is borrowed for HTTP and is not an owned native continuation.
        if (fresh.is_some() && complete_local) || (writable_bytes && !complete_local) {
            return Err("The requested vault completion mode is unavailable".into());
        }
        let (fresh_origin, fresh_generation, dispatch, fresh_active) = match fresh {
            Some(fresh) => (
                Some(fresh.origin),
                Some(fresh.expected_generation),
                Some(fresh.dispatch),
                Some(fresh.active),
            ),
            None => (None, None, None, None),
        };
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
            || fresh_generation.is_some_and(|expected| expected == 0 || expected != generation)
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
        if fresh_origin
            .as_ref()
            .is_some_and(|origin| !verified.custody.matches_fresh_origin(origin))
        {
            return Err("The fresh edit belongs to an earlier Windows connection".into());
        }
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
                || fresh_active
                    .as_ref()
                    .is_some_and(|active| !active.load(Ordering::Acquire))
                || fresh_origin
                    .as_ref()
                    .is_some_and(|origin| !verified.custody.matches_fresh_origin(origin))
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
        let target = match dispatch {
            Some(dispatch) => target.with_fresh_dispatch(dispatch),
            None => target,
        };
        let verify_fresh_dispatch = || -> Result<(), String> {
            if fresh_generation.is_some() {
                verified
                    .backend
                    .validate_fresh_vault_capture_dispatch(&target)
                    .map_err(|_| "The fresh edit's original unlock or route changed")?;
            }
            Ok(())
        };
        // A stale queue event must not initialize or consume a durable attempt
        // by silently selecting a replacement login, connection or unlock.
        current()?;
        verify_fresh_dispatch()?;
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
        verify_fresh_dispatch()?;
        let ticket = attempt.begin_attempt(&ledger).map_err(
            |_| "This retained edit already has an attempt; inspect recovery before continuing",
        )?;
        let cancellation = CancellationToken::for_offline_job();
        let deadline = Instant::now()
            + Duration::from_secs(session.expires_at.saturating_sub(unix_time_now()).min(300));
        let cancelled = || {
            cancellation.is_cancelled()
                || cancellation.is_expired()
                || Instant::now() >= deadline
                || self.generation.load(Ordering::Acquire) != generation
                || self.provider.authorized_generation.load(Ordering::Acquire) != generation
                || verified.backend.is_revoked()
                || fresh_active
                    .as_ref()
                    .is_some_and(|active| !active.load(Ordering::Acquire))
        };
        let mut source = std::io::Cursor::new(retained.bytes_for_recovery());
        // Normalize remote evidence without cloning or reconstructing the live
        // completion capability. The remote-only path deliberately never mints it.
        struct VerifiedResult {
            entry: RemoteEntry,
            digest: [u8; 32],
            completion: Option<FreshVaultUpload>,
        }
        enum UploadResult {
            Verified(VerifiedResult),
            NeedsReconciliation,
        }
        let outcome = if complete_local {
            // CancellationToken owns its fixed deadline; the cap carries it
            // through local completion, independently of this borrowed closure.
            let control = VaultUploadControl::new(
                Arc::clone(&self.provider.authorized_generation),
                generation,
                cancellation.clone(),
                deadline,
            )
            .map_err(|_| "The retained edit upload context changed")?;
            verified
                .backend
                .upload_existing_vault_capture_live(
                    target,
                    &mut source,
                    retained.bytes_for_recovery().len() as u64,
                    control,
                    &cancelled,
                )
                .map(|result| match result {
                    VaultLiveUploadOutcome::Verified(capability) => {
                        let receipt = capability.remote_evidence();
                        UploadResult::Verified(VerifiedResult {
                            entry: receipt.entry().clone(),
                            digest: receipt.plaintext_sha256(),
                            completion: Some(capability),
                        })
                    }
                    VaultLiveUploadOutcome::NeedsReconciliation { .. } => {
                        UploadResult::NeedsReconciliation
                    }
                })
        } else {
            verified
                .backend
                .upload_existing_vault_capture(
                    &target,
                    &mut source,
                    retained.bytes_for_recovery().len() as u64,
                    Arc::clone(&self.provider.authorized_generation),
                    generation,
                    &cancelled,
                )
                .map(|result| match result {
                    VaultExistingOverwriteOutcome::Verified(receipt) => {
                        UploadResult::Verified(VerifiedResult {
                            entry: receipt.entry().clone(),
                            digest: receipt.plaintext_sha256(),
                            completion: None,
                        })
                    }
                    VaultExistingOverwriteOutcome::NeedsReconciliation { .. } => {
                        UploadResult::NeedsReconciliation
                    }
                })
        };
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
            Ok(UploadResult::Verified(receipt)) => {
                let digest: [u8; 32] = Sha256::digest(retained.bytes_for_recovery()).into();
                if receipt.digest != digest {
                    let _ = attempt.record_uncertain(&ledger, ticket);
                    return Ok(uncertain());
                }
                let entry = &receipt.entry;
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
                if let Some(capability) = receipt.completion {
                    // A recorded readback is still historical evidence. Only the
                    // fresh route capability and the actual native exclusive
                    // body proof can authorize the local disposition callbacks.
                    if current().is_err() || cancelled() {
                        return Ok(
                            json!({"state":"remote_verified_pending_local", "capture_id":capture_id,
                            "retained":true, "local_cleanup":"incomplete", "automatic_retry":false}),
                        );
                    }
                    let store = match ledger.local_completion_store() {
                        Ok(store) => store,
                        Err(_) => {
                            return Ok(
                                json!({"state":"remote_verified_pending_local", "capture_id":capture_id,
                            "retained":true, "local_cleanup":"incomplete", "automatic_retry":false}),
                            );
                        }
                    };
                    let store: Box<dyn raiun_cloudfiles_windows::VaultLocalCompletionStore> =
                        Box::new(store);
                    #[cfg(all(test, debug_assertions))]
                    let (store, writer_probe) = if self.synthetic_vault_completion_writer_probe {
                        let (store, probe) = tests::instrument_vault_completion_store(
                            store,
                            PathBuf::from(&configuration.path),
                        );
                        (store, Some(probe))
                    } else {
                        (store, None)
                    };
                    let completion_result = if writable_bytes {
                        self.provider.complete_writable_vault_upload(
                            active,
                            Arc::clone(&verified.backend),
                            capability,
                            store,
                        )
                    } else {
                        self.provider.complete_vault_upload(
                            active,
                            Arc::clone(&verified.backend),
                            capability,
                            store,
                        )
                    };
                    #[cfg(all(test, debug_assertions))]
                    let probe_result = writer_probe
                        .map(tests::finalize_vault_completion_probe)
                        .transpose();
                    #[cfg(all(test, debug_assertions))]
                    if let Err(error) = &probe_result {
                        eprintln!("C06_VAULT_WRITER_PROBE_FINAL_RESULT_REFUSED={error}");
                    }
                    if completion_result.is_err() {
                        return Ok(
                            json!({"state":"remote_verified_pending_local", "capture_id":capture_id,
                            "retained":true, "local_cleanup":"incomplete", "automatic_retry":false}),
                        );
                    }
                    let completed = json!({"state":"local_completed", "capture_id":capture_id,
                        "retained":true, "local_cleanup":"requires_current_native_check", "automatic_retry":false});
                    #[cfg(all(test, debug_assertions))]
                    let completed = {
                        let mut value = completed;
                        if let Some(probe) = probe_result? {
                            value["native_writer_exclusion"] =
                                probe["native_writer_exclusion"].clone();
                            value["native_writer_error"] = probe["native_writer_error"].clone();
                        }
                        value
                    };
                    return Ok(completed);
                }
                Ok(
                    json!({"state":"remote_verified_pending_local", "capture_id":capture_id,
                    "retained":true, "local_cleanup":"incomplete", "automatic_retry":false}),
                )
            }
            Ok(UploadResult::NeedsReconciliation) => {
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
