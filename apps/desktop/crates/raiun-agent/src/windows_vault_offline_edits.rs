// Cached close notifications retain their original protected capture. A local
// journal receipt never grants remote or native clean-completion authority.
// Activation waits for the native queued namespace and reconciliation adapters.
const WINDOWS_VAULT_OFFLINE_WRITES_ENABLED: bool = false;
impl WindowsAgent {
    fn check_cached_save_worker_account(
        &self,
        binding: &ActiveProviderBinding,
    ) -> Result<(), String> {
        let context = self.windows_vault_offline_account(binding.generation)?;
        let owner = context
            .configuration
            .registration_ownership
            .as_ref()
            .ok_or("The cached drive owner is unavailable")?;
        if !WINDOWS_VAULT_OFFLINE_WRITES_ENABLED
            || !self
                .state
                .lock()
                .map_err(|_| "Account state is unavailable")?
                .offline_cached
            || self.provider.authorized_generation.load(Ordering::Acquire) != binding.generation
            || Path::new(&context.configuration.path) != binding.path
            || context._root.identity() != binding.identity
            || owner.personal_drive_id != binding.personal_space_id
            || owner.personal_root_resource_id.as_deref()
                != Some(binding.personal_root_resource_id.as_str())
        {
            return Err("The cached save worker account or root changed".into());
        }
        self.check_windows_vault_offline_account(&context)
    }
    fn windows_vault_pending_request(&self, request: &Value) -> Result<Value, String> {
        use raiun_opencloud::vault_cache::{VaultOfflineCache, VaultPendingOperationKind};
        let _operation = self
            .vault_credential_operation
            .lock()
            .map_err(|_| "Vault changes are unavailable")?;
        let fields = request.as_object().ok_or("Invalid saved-edit request")?;
        if fields.keys().any(|k| {
            !matches!(
                k.as_str(),
                "action"
                    | "profile_id"
                    | "expected_generation"
                    | "space_id"
                    | "root_resource_id"
                    | "root_path"
                    | "after"
                    | "limit"
                    | "job_id"
            )
        }) {
            return Err("Invalid saved-edit request".into());
        }
        let text = |key: &str, max: usize| {
            fields
                .get(key)
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control))
                .ok_or("Invalid saved-edit request")
        };
        if text("profile_id", 128)? != self.profile_scope {
            return Err("Select the current account".into());
        }
        let action = text("action", 64)?;
        let expected = fields
            .get("expected_generation")
            .and_then(Value::as_u64)
            .filter(|g| *g != 0)
            .ok_or("Refresh the current account")?;
        let context = self.windows_vault_offline_account(expected)?;
        let owner = context
            .configuration
            .registration_ownership
            .as_ref()
            .ok_or("The saved root owner is unavailable")?;
        let active = ActiveProviderBinding {
            generation: expected,
            path: PathBuf::from(&context.configuration.path),
            identity: context._root.identity(),
            personal_space_id: owner.personal_drive_id.clone(),
            personal_root_resource_id: owner
                .personal_root_resource_id
                .clone()
                .ok_or("The Personal root is unavailable")?,
        };
        let verified = self.provider.verified_vault_backend(active)?;
        let space = text("space_id", 512)?;
        let resource = text("root_resource_id", 512)?;
        let root = text("root_path", 4096)?;
        let scope = raiun_vault::session::VaultSessionScope::new(
            &self.profile_scope,
            &context.origin,
            space,
            resource,
        )
        .map_err(|_| "Invalid encrypted location")?;
        let route = verified
            .backend
            .verified_vault_copy_route(context._root.identity(), space, resource, root)
            .map_err(|_| "Unlock the original encrypted location first")?;
        let epoch = self
            .vault_sessions
            .capture_session_epoch(&scope)
            .map_err(|_| "Unlock the encrypted location first")?;
        let cache_pin = self.windows_vault_cache_pin(&context)?;
        let cache = self.open_windows_vault_cache(&context)?;
        let journal = VaultOfflineCache::new(cache.clone(), scope.clone(), root)
            .map_err(|_| "The encrypted edit journal is unavailable")?;
        let result = match action {
            "vault_operations" => {
                let after = fields.get("after").map(|_| text("after", 32)).transpose()?;
                if after.is_some_and(|s| s.len() != 32 || !s.bytes().all(|b| b.is_ascii_hexdigit()))
                {
                    return Err("Invalid saved-edit cursor".into());
                }
                let limit = fields
                    .get("limit")
                    .map(|v| v.as_u64().ok_or("Invalid page size"))
                    .transpose()?
                    .unwrap_or(50);
                if !(1..=100).contains(&limit) {
                    return Err("Invalid page size".into());
                }
                let mut cursor = after.map(str::to_owned);
                let mut scanned = 0;
                let mut items = Vec::new();
                let mut more = false;
                while scanned < 500 && items.len() < limit as usize {
                    let (rows, page_more) = journal
                        .pending_edits(
                            &self.vault_sessions,
                            cursor.as_deref(),
                            100usize.min(500 - scanned),
                        )
                        .map_err(|_| "Saved edit metadata could not be authenticated")?;
                    if rows.is_empty() {
                        more = false;
                        break;
                    }
                    let total = rows.len();
                    for (index, row) in rows.into_iter().enumerate() {
                        scanned += 1;
                        cursor = Some(row.id.clone());
                        if matches!(
                            row.state,
                            raiun_cache::CiphertextWriteState::CommittedReceipt
                                | raiun_cache::CiphertextWriteState::CancelledReceipt
                                | raiun_cache::CiphertextWriteState::AcknowledgedReceipt
                        ) {
                            continue;
                        }
                        let operation = crate::vault_operation_wire::vault_pending_operation_name(
                            row.operation,
                        );
                        let state = crate::vault_operation_wire::vault_pending_operation_state_name(
                            row.state,
                        );
                        let attention =
                            crate::vault_operation_wire::vault_pending_operation_attention_reason(
                                row.operation,
                                row.state,
                            );
                        items.push(json!({"write_id":row.id,"revision":row.revision,
                            "retry_generation":row.retry_generation,"operation":operation,"state":state,
                            "needs_attention":attention.is_some(),"attention_reason":attention,
                            "retry_state":null,"can_retry_interrupted_create":false,
                            "path":row.path,"destination_path":if row.destination_path.is_empty(){None}else{Some(row.destination_path)},
                            "bytes":row.plaintext_len}));
                        if items.len() == limit as usize {
                            more = index + 1 < total || page_more;
                            break;
                        }
                    }
                    if items.len() == limit as usize {
                        break;
                    }
                    if !page_more {
                        more = false;
                        break;
                    }
                    more = true;
                }
                if scanned == 500 && items.len() < limit as usize {
                    more = true;
                }
                json!({"space_id":space,"root_resource_id":resource,"auth_generation":expected,"items":items,"next_after":if more{cursor}else{None},"truncated":more})
            }
            "vault_reconcile_edits_status" | "vault_reconcile_edits_cancel" => {
                let job = text("job_id", 256)?;
                let status = self.vault_copy_jobs.status(&scope, job, expected)?;
                if status.operation.is_some() {
                    return Err("Saved-edit job was not found".into());
                }
                let status = if action == "vault_reconcile_edits_cancel" {
                    self.vault_copy_jobs.cancel(&scope, job, expected)?
                } else {
                    status
                };
                serde_json::to_value(status).map_err(|_| "Could not encode saved-edit status")?
            }
            "vault_reconcile_edits_latest" => {
                let latest = self
                    .vault_copy_jobs
                    .latest(&scope, expected)?
                    .filter(|s| s.operation.is_none());
                json!({"available":latest.is_some(),"status":latest})
            }
            "vault_reconcile_edits_start" => {
                // Fresh online account and installed route are mandatory. Cached
                // ownership and journal metadata alone cannot authorize HTTP.
                let online =
                    self.capture_windows_vault_context(Some(&self.profile_scope), Some(expected))?;
                if online.verified.backend.is_cached_only()
                    || online.identity != context._root.identity()
                {
                    return Err("Reconnect the original account before retrying saved edits".into());
                }
                let (client, trusted) = online
                    .verified
                    .backend
                    .vault_read_context(online.identity)
                    .map_err(|_| "The online drive changed")?;
                if trusted.account_id() != owner.account_id
                    || trusted.server_origin() != context.origin
                {
                    return Err("The online account differs from the saved edit account".into());
                }
                let offline = VaultOfflineCache::new(cache, scope.clone(), root)
                    .map_err(|_| "The encrypted journal is unavailable")?;
                let backend = raiun_opencloud::vault_backend::VaultBackend::new_with_offline_cache(
                    (*client).clone(),
                    self.vault_sessions.clone(),
                    scope.clone(),
                    root.into(),
                    offline,
                )
                .map_err(|_| "The online vault could not be verified")?;
                self.check_windows_vault_authority(
                    &online.session,
                    expected,
                    &online.configuration,
                    &online.verified.backend,
                )?;
                let sessions = self.vault_sessions.clone();
                let generation = self.generation.clone();
                let worker_generation = generation.clone();
                let provider = online.verified.backend.clone();
                let path = PathBuf::from(&context.configuration.path);
                let root_identity = context._root.identity();
                let route = route.clone();
                let scope = scope.clone();
                let job = crate::vault_edit_jobs::VaultEditReconcileJobs::start_with_failure_class(
                    &self.vault_copy_jobs,
                    &scope,
                    generation,
                    expected,
                    self.vault_copy_serialization.clone(),
                    false,
                    move |cancelled, progress| {
                        let current = || {
                            !cancelled.load(Ordering::Acquire)
                                && worker_generation.load(Ordering::Acquire) == expected
                                && !provider.is_revoked()
                                && cache_pin.verify_path().is_ok()
                                && pin_registered_configured_root(&path, root_identity).is_ok()
                                && provider
                                    .verified_vault_copy_route(
                                        root_identity,
                                        route.space_id(),
                                        route.root_resource_id(),
                                        route.root_path(),
                                    )
                                    .is_ok_and(|current| Arc::ptr_eq(&current, &route))
                        };
                        if !current() {
                            return Err(crate::vault_edit_jobs::VaultEditJobFailure::unclassified(
                                "The original edit connection changed",
                            ));
                        }
                        crate::vault_edit_jobs::reconcile_dependency_batches(
                            cancelled,
                            &worker_generation,
                            expected,
                            crate::vault_edit_jobs::maximum_batch(),
                            |limit| {
                                if !current() {
                                    return Err("The edit connection changed".into());
                                }
                                journal
                                    .retryable_pending_edits(&sessions, limit)
                                    .map(|(rows, _)| rows)
                                    .map_err(|_| "Saved edit metadata is unavailable".into())
                            },
                            |edit| {
                                if !current() {
                                    return Err(crate::vault_edit_jobs::ReconcileFailure::Stop(
                                        None,
                                    ));
                                }
                                let result = match edit.operation {
                                    VaultPendingOperationKind::DeleteFile => {
                                        backend.reconcile_pending_delete(&edit.id, edit.revision)
                                    }
                                    VaultPendingOperationKind::CreateDirectory => backend
                                        .reconcile_pending_directory_create(&edit.id, edit.revision)
                                        .map(|_| ()),
                                    _ => backend
                                        .reconcile_pending_operation(&edit.id, edit.revision)
                                        .map(|_| ()),
                                };
                                result.map_err(|e| {
                                    if e.kind == raiun_core::backend::ErrorKind::Conflict {
                                        crate::vault_edit_jobs::ReconcileFailure::Conflict
                                    } else {
                                        crate::vault_edit_jobs::ReconcileFailure::Stop(
                                            crate::vault_edit_jobs::reconcile_failure_class(e.kind),
                                        )
                                    }
                                })
                            },
                            || {
                                journal
                                    .pending_edits(
                                        &sessions,
                                        None,
                                        crate::vault_edit_jobs::maximum_batch(),
                                    )
                                    .map(|(rows, more)| rows.len() as u64 + u64::from(more))
                                    .map_err(|_| "Saved edit status is unavailable".into())
                            },
                            progress,
                        )
                    },
                )?;
                json!({"accepted":true,"job_id":job.job_id})
            }
            _ => return Err("Saved-edit action is unavailable".into()),
        };
        self.vault_sessions
            .with_session_epoch(&scope, &epoch, || ())
            .map_err(|_| "The original vault unlock changed")?;
        let current = verified
            .backend
            .verified_vault_copy_route(
                context._root.identity(),
                route.space_id(),
                route.root_resource_id(),
                route.root_path(),
            )
            .map_err(|_| "The original encrypted route changed")?;
        if !Arc::ptr_eq(&current, &route) {
            return Err("The original encrypted route changed".into());
        }
        self.check_windows_vault_offline_account(&context)?;
        Ok(result)
    }

    fn queue_windows_vault_fresh_capture(
        &self,
        job: windows_vault_close_worker::FreshVaultCloseJob,
        active: Arc<AtomicBool>,
        policy: windows_vault_close_worker::FreshCloseCompletionPolicy,
    ) -> Result<Value, String> {
        use raiun_cloudfiles_windows::{CancellationToken, ExistingVaultUploadTarget};
        use raiun_core::backend::RemoteEntry;
        if !policy.writable_bytes() || !active.load(Ordering::Acquire) {
            return Err("The original cached edit worker is unavailable".into());
        }
        let windows_vault_close_worker::FreshVaultCloseJob {
            origin,
            vault,
            remote_root,
            capture_id,
            dispatch,
            expected_generation,
        } = job;
        let context = self.windows_vault_offline_account(expected_generation)?;
        let owner = context
            .configuration
            .registration_ownership
            .as_ref()
            .ok_or("The cached drive owner is unavailable")?;
        let binding = ActiveProviderBinding {
            generation: context.generation,
            path: PathBuf::from(&context.configuration.path),
            identity: context._root.identity(),
            personal_space_id: owner.personal_drive_id.clone(),
            personal_root_resource_id: owner
                .personal_root_resource_id
                .clone()
                .ok_or("The cached Personal root is unavailable")?,
        };
        let verified = self.provider.verified_vault_backend(binding.clone())?;
        if !verified.backend.is_cached_only()
            || !verified.custody.matches_fresh_origin(&origin)
            || vault.account_id() != self.profile_scope
            || vault.server_origin() != context.origin
        {
            return Err("The cached edit belongs to a different drive connection".into());
        }
        let (_, trusted) = verified
            .backend
            .vault_read_context(context._root.identity())
            .map_err(|_| "The cached drive changed")?;
        let ledger = verified
            .custody
            .upload_ledger(&trusted, &vault, &remote_root, &capture_id)?;
        if !ledger.scope().matches_canonical_account(&context.account) {
            return Err("The cached edit belongs to another account".into());
        }
        let original = ledger.reference().entry();
        let target = ExistingVaultUploadTarget::new(
            trusted,
            vault,
            remote_root,
            context._root.identity(),
            original.opaque(),
            RemoteEntry {
                id: original.remote_id().into(),
                path: original.root_relative_path().into(),
                directory: false,
                size: original.length(),
                etag: original.etag().into(),
                modified_unix: 0,
                writable: false,
                encrypted: false,
            },
        )
        .map_err(|_| "The original cached target is unavailable")?
        .with_fresh_dispatch(dispatch);
        verified
            .backend
            .validate_fresh_vault_capture_dispatch(&target)
            .map_err(|_| "The original cached unlock changed")?;
        let cancelled: Arc<dyn Fn() -> bool + Send + Sync> = {
            let generation = self.generation.clone();
            let provider_generation = self.provider.authorized_generation.clone();
            let backend = verified.backend.clone();
            let active = active.clone();
            let token = CancellationToken::for_recovery_job(
                raiun_cloudfiles_windows::StreamedRecoveryPolicy::default(),
            )
            .cancellation()
            .clone();
            Arc::new(move || {
                token.is_cancelled()
                    || token.is_expired()
                    || !active.load(Ordering::Acquire)
                    || generation.load(Ordering::Acquire) != expected_generation
                    || provider_generation.load(Ordering::Acquire) != expected_generation
                    || backend.is_revoked()
            })
        };
        self.check_windows_vault_offline_account(&context)?;
        let mut retained = ledger
            .read_body_cancelled(&*cancelled)
            .map_err(|_| "The protected cached edit is unavailable")?;
        let length = retained.len();
        let digest = retained.sha256();
        let receipt = if retained.is_streamed() {
            let mut source = retained
                .streamed_reader(cancelled.clone())
                .map_err(|_| "The protected cached edit could not be opened")?;
            verified.backend.queue_cached_vault_existing_capture(
                &target,
                &mut source,
                length,
                digest,
                self.provider.authorized_generation.clone(),
                expected_generation,
                cancelled.clone(),
            )
        } else {
            let mut source = std::io::Cursor::new(
                retained
                    .legacy()
                    .ok_or("The protected edit format is unavailable")?
                    .bytes_for_recovery(),
            );
            verified.backend.queue_cached_vault_existing_capture(
                &target,
                &mut source,
                length,
                digest,
                self.provider.authorized_generation.clone(),
                expected_generation,
                cancelled.clone(),
            )
        }
        .map_err(|_| "The edit remains protected, but offline queueing did not finish")?;
        if cancelled() || !verified.custody.matches_fresh_origin(&origin) {
            return Err("The cached edit changed; retained copies were preserved".into());
        }
        self.check_windows_vault_offline_account(&context)?;
        ledger.record_cached_queue(&receipt, length, digest)?;
        verified
            .backend
            .validate_fresh_vault_capture_dispatch(&target)
            .map_err(|_| "The cached unlock changed after queueing; copies were preserved")?;
        self.check_windows_vault_offline_account(&context)?;
        Ok(json!({"state":"local_queued","write_id":receipt.write_id(),
            "revision":receipt.revision(),"native_confirmation":false,
            "read_only_restored":false}))
    }
}
