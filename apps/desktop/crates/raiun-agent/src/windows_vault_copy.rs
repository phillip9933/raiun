// Explicit one-file online copy. The portable copy journal remains ciphertext
// only; this adapter grants no generic Windows vault write or replay authority.
struct WindowsVaultCopyRequest {
    generation: u64,
    source_space: String,
    source_root: String,
    source_id: String,
    destination_space: String,
    destination_root: String,
    destination_id: String,
    source_path: String,
    source_resource_id: String,
    source_etag: String,
    destination_path: String,
    destination_parent_resource_id: String,
    destination_parent_etag: String,
}
impl WindowsVaultCopyRequest {
    fn decode(value: &Value, profile: &str) -> Result<Self, String> {
        let invalid = || "Invalid encrypted copy request".to_owned();
        let fields = value.as_object().ok_or_else(invalid)?;
        if fields.keys().any(|key| {
            !matches!(
                key.as_str(),
                "action"
                    | "profile_id"
                    | "expected_generation"
                    | "space_id"
                    | "root_path"
                    | "root_resource_id"
                    | "source_space_id"
                    | "source_root_path"
                    | "source_root_resource_id"
                    | "source_path"
                    | "source_resource_id"
                    | "source_etag"
                    | "destination_path"
                    | "destination_parent_resource_id"
                    | "destination_parent_etag"
            )
        }) {
            return Err(invalid());
        }
        let text = |key: &str, max: usize| -> Result<String, String> {
            fields
                .get(key)
                .and_then(Value::as_str)
                .filter(|value| {
                    !value.is_empty()
                        && value.len() <= max
                        && value.trim() == *value
                        && !value.chars().any(char::is_control)
                })
                .map(str::to_owned)
                .ok_or_else(invalid)
        };
        if text("action", 64)? != "vault_copy_start" || text("profile_id", 128)? != profile {
            return Err(invalid());
        }
        let request = Self {
            generation: fields
                .get("expected_generation")
                .and_then(Value::as_u64)
                .filter(|g| *g != 0)
                .ok_or_else(invalid)?,
            source_space: text("source_space_id", 512)?,
            source_root: text("source_root_path", 4096)?,
            source_id: text("source_root_resource_id", 512)?,
            destination_space: text("space_id", 512)?,
            destination_root: text("root_path", 4096)?,
            destination_id: text("root_resource_id", 512)?,
            source_path: text("source_path", 4096)?,
            source_resource_id: text("source_resource_id", 512)?,
            source_etag: text("source_etag", 4096)?,
            destination_path: text("destination_path", 4096)?,
            destination_parent_resource_id: text("destination_parent_resource_id", 512)?,
            destination_parent_etag: text("destination_parent_etag", 4096)?,
        };
        for path in [
            &request.source_root,
            &request.destination_root,
            &request.source_path,
            &request.destination_path,
        ] {
            raiun_core::validate_remote_path(path).map_err(|_| invalid())?;
            if path.contains('\\') {
                return Err(invalid());
            }
        }
        if request.source_path == "/" || request.destination_path == "/" {
            return Err(invalid());
        }
        Ok(request)
    }
}
impl WindowsAgent {
    fn prepare_windows_vault_copy(
        self: &Arc<Self>,
        value: &Value,
    ) -> Result<(Value, Option<std::sync::mpsc::Sender<()>>), String> {
        use crate::vault_edit_jobs::{
            CopyProducerJobSpec, CopyVerifyReviewReason, VaultEditFailureClass,
            VaultEditJobFailure, VaultEditReconcileJobs, VaultEditReconcileReport,
        };
        use raiun_opencloud::vault_backend::{VaultBackend, VaultCopyOutcome, VaultCopyRequest};
        use sha2::Digest;
        let request = WindowsVaultCopyRequest::decode(value, &self.profile_scope)?;
        let reject = |error| (json!({"accepted":false,"error":error}), None);
        let _operation = self
            .vault_credential_operation
            .lock()
            .map_err(|_| "Vault changes are unavailable")?;
        let context = self
            .capture_windows_vault_context(Some(&self.profile_scope), Some(request.generation))?;
        let (client, trusted) = context
            .verified
            .backend
            .vault_read_context(context.identity)
            .map_err(|_| "The connected drive changed")?;
        let scope = |space: &str, id: &str| {
            raiun_vault::session::VaultSessionScope::new(
                &self.profile_scope,
                trusted.server_origin(),
                space,
                id,
            )
            .map_err(|_| "Invalid vault scope")
        };
        let source_scope = scope(&request.source_space, &request.source_id)?;
        let destination_scope = scope(&request.destination_space, &request.destination_id)?;
        if source_scope == destination_scope {
            return Ok(reject("scope_changed"));
        }
        if !self
            .vault_sessions
            .is_unlocked(&source_scope)
            .unwrap_or(false)
            || !self
                .vault_sessions
                .is_unlocked(&destination_scope)
                .unwrap_or(false)
        {
            return Ok(reject("locked"));
        }
        // Retain the exact installed route Arcs and their original opaque epochs.
        // A caller's path or a remembered exclusion cannot substitute for these.
        let source_route = context
            .verified
            .backend
            .verified_vault_copy_route(
                context.identity,
                &request.source_space,
                &request.source_id,
                &request.source_root,
            )
            .map_err(|_| "The source vault route changed")?;
        let destination_route = context
            .verified
            .backend
            .verified_vault_copy_route(
                context.identity,
                &request.destination_space,
                &request.destination_id,
                &request.destination_root,
            )
            .map_err(|_| "The destination vault route changed")?;
        let issuer = context
            .session
            .expected_issuer
            .as_ref()
            .map(|issuer| url::Url::parse(issuer).map(|u| u.to_string()))
            .transpose()
            .map_err(|_| "The account issuer is invalid")?;
        let account = raiun_engine::folder_pairs::AccountScope::new(
            self.profile_scope.clone(),
            url::Url::parse(&context.session.server)
                .map_err(|_| "The account server is invalid")?
                .to_string(),
            context.session.client_id.clone(),
            issuer,
            trusted.account_id().to_owned(),
        )
        .map_err(|_| "The account scope is invalid")?;
        let bytes = serde_json::to_vec(&account).map_err(|_| "The account scope is invalid")?;
        let storage = DpapiSessionStore::current_user()
            .map_err(|_| "Private Windows storage is unavailable")?;
        let parent =
            raiun_control_windows::PinnedDirectory::open(storage.local_edit_state_directory())
                .map_err(|_| "Private Windows storage is unavailable")?;
        let name = format!("vault-copy-journal-{:x}", sha2::Sha256::digest(bytes));
        let private = raiun_control_windows::PrivateDirectory::create_or_open_under(
            &parent,
            std::ffi::OsStr::new(&name),
        )
        .map_err(|_| "Private encrypted copy storage is unavailable")?;
        // Native Cache::open uses pinned private directories, Windows SQLite VFS,
        // and private ciphertext blobs. Never use the ordinary FileCache here.
        let copy = VaultCopyRequest {
            source_scope: source_scope.clone(),
            destination_scope: destination_scope.clone(),
            source_path: request.source_path,
            source_resource_id: request.source_resource_id,
            source_etag: request.source_etag,
            destination_path: request.destination_path,
            destination_parent_resource_id: request.destination_parent_resource_id,
            destination_parent_etag: request.destination_parent_etag,
            source_auth_generation: client.token_generation(),
            destination_auth_generation: client.token_generation(),
        };
        self.check_windows_vault_authority(
            &context.session,
            context.generation,
            &context.configuration,
            &context.verified.backend,
        )?;
        let (release, gate) = std::sync::mpsc::channel();
        let sessions = self.vault_sessions.clone();
        let generation = self.generation.clone();
        let expected = request.generation;
        let backend = context.verified.backend.clone();
        let worker_root_path = PathBuf::from(&context.configuration.path);
        let worker_root_identity = context.identity;
        let worker_source = source_scope.clone();
        let worker_destination = destination_scope.clone();
        let job = VaultEditReconcileJobs::start_copy_producer(
            &self.vault_copy_jobs,
            CopyProducerJobSpec {
                destination: &destination_scope,
                source: &source_scope,
                auth_generation: generation.clone(),
                expected_generation: expected,
                pin_jobs: self.vault_copy_serialization.clone(),
                start_gate: gate,
            },
            move |cancelled, progress, publish| {
                // Keep physical/private directory pins through the complete job.
                let _root_pin =
                    pin_registered_configured_root(&worker_root_path, worker_root_identity)
                        .map_err(|_| {
                            VaultEditJobFailure::unclassified("The original Windows drive changed")
                        })?;
                let _private_pin = private;
                // Called under shared token/session fences: atomics ONLY.
                let stop = || {
                    cancelled.load(Ordering::Acquire)
                        || generation.load(Ordering::Acquire) != expected
                        || backend.vault_copy_route_cancelled(&source_route)
                        || backend.vault_copy_route_cancelled(&destination_route)
                };
                let unavailable =
                    || VaultEditJobFailure::unclassified("Encrypted copy did not complete");
                let review = || {
                    VaultEditJobFailure::classified(
                        "Encrypted copy requires review",
                        VaultEditFailureClass::CopyNeedsReview(
                            CopyVerifyReviewReason::VerificationUnavailable,
                        ),
                    )
                };
                if stop() {
                    return Err(unavailable());
                }
                // Open only after the shared per-profile serialization gate:
                // cache startup must never sweep another live job's stages.
                let cache = raiun_cache::Cache::open(_private_pin.path(), 1 << 30)
                    .map_err(|_| unavailable())?;
                let source = VaultBackend::new(
                    (*client).clone(),
                    sessions.clone(),
                    worker_source,
                    request.source_root,
                )
                .map_err(|_| unavailable())?;
                let journal = raiun_opencloud::vault_cache::VaultOfflineCache::new(
                    cache,
                    worker_destination.clone(),
                    &request.destination_root,
                )
                .map_err(|_| unavailable())?;
                let destination = VaultBackend::new_with_offline_cache(
                    (*client).clone(),
                    sessions,
                    worker_destination,
                    request.destination_root,
                    journal,
                )
                .map_err(|_| unavailable())?;
                if stop() {
                    return Err(unavailable());
                }
                progress(0, 0, 0, 1);
                let mut binding_published = false;
                let mut publication_error = None;
                let result = source.copy_file_to_cancellable_with_binding(
                    &destination,
                    &copy,
                    &stop,
                    |id, revision| {
                        binding_published = true;
                        if let Err(error) = publish(id, revision) {
                            publication_error = Some(error);
                            cancelled.store(true, Ordering::Release);
                        }
                    },
                );
                if let Some(error) = publication_error {
                    return Err(error);
                }
                match result {
                    Ok(VaultCopyOutcome::Copied { .. }) => {
                        progress(1, 1, 0, 0);
                        Ok(VaultEditReconcileReport {
                            processed: 1,
                            uploaded: 1,
                            conflicts: 0,
                            remaining: 0,
                        })
                    }
                    Ok(VaultCopyOutcome::NeedsReconciliation { .. }) => {
                        progress(1, 0, 0, 1);
                        Err(review())
                    }
                    Err(_) if binding_published => Err(review()),
                    Err(_) => Err(unavailable()),
                }
            },
        );
        match job {
            Ok(job) => Ok((json!({"accepted":true,"job_id":job.job_id}), Some(release))),
            Err(_) => Ok(reject("busy")),
        }
    }

    // Copy-only metadata, not a writable native listing or offline capability.
    fn windows_vault_copy_parent(&self, value: &Value) -> Result<Value, String> {
        use raiun_core::backend::CloudBackend;
        let fields = value.as_object().ok_or("Invalid copy parent request")?;
        if fields.keys().any(|key| {
            !matches!(
                key.as_str(),
                "action"
                    | "profile_id"
                    | "space_id"
                    | "root_path"
                    | "root_resource_id"
                    | "path"
                    | "expected_generation"
            )
        }) {
            return Err("Invalid copy parent request".into());
        }
        let text = |key: &str, max: usize| {
            fields
                .get(key)
                .and_then(Value::as_str)
                .filter(|v| {
                    !v.is_empty()
                        && v.len() <= max
                        && v.trim() == *v
                        && !v.chars().any(char::is_control)
                })
                .ok_or("Invalid copy parent request")
        };
        if text("profile_id", 128)? != self.profile_scope {
            return Err("Select the current account".into());
        }
        let space = text("space_id", 512)?;
        let root = text("root_path", 4096)?;
        let id = text("root_resource_id", 512)?;
        let path = text("path", 4096)?;
        for path in [root, path] {
            raiun_core::validate_remote_path(path).map_err(|_| "Invalid copy parent path")?;
            if path.contains('\\') {
                return Err("Invalid copy parent path".into());
            }
        }
        let expected = fields
            .get("expected_generation")
            .and_then(Value::as_u64)
            .filter(|g| *g != 0)
            .ok_or("Invalid copy generation")?;
        let _operation = self
            .vault_credential_operation
            .lock()
            .map_err(|_| "Vault changes are unavailable")?;
        let context =
            self.capture_windows_vault_context(Some(&self.profile_scope), Some(expected))?;
        let route = context
            .verified
            .backend
            .verified_vault_copy_route(context.identity, space, id, root)
            .map_err(|_| "The destination vault route changed")?;
        let (client, trusted) = context
            .verified
            .backend
            .vault_read_context(context.identity)
            .map_err(|_| "The connected drive changed")?;
        let scope = raiun_vault::session::VaultSessionScope::new(
            &self.profile_scope,
            trusted.server_origin(),
            space,
            id,
        )
        .map_err(|_| "Invalid copy scope")?;
        let backend = raiun_opencloud::vault_backend::VaultBackend::new(
            (*client).clone(),
            self.vault_sessions.clone(),
            scope,
            root.to_owned(),
        )
        .map_err(|_| "Could not inspect the destination vault")?;
        let parent = backend
            .stat(space, path)
            .map_err(|_| "Could not inspect the destination parent")?;
        if !parent.directory || parent.path != path {
            return Err("The destination parent changed".into());
        }
        self.check_windows_vault_authority(
            &context.session,
            expected,
            &context.configuration,
            &context.verified.backend,
        )?;
        let current = context
            .verified
            .backend
            .verified_vault_copy_route(context.identity, space, id, root)
            .map_err(|_| "The destination vault route changed")?;
        if !Arc::ptr_eq(&current, &route) {
            return Err("The destination vault route changed".into());
        }
        // Historical read-only expectations, never copy authority. Start and
        // the shared copy operation recheck this exact parent ID/strong ETag.
        Ok(json!({"path":path,"parent_resource_id":parent.id,
            "parent_etag":parent.etag,"writable":parent.writable,"auth_generation":expected}))
    }

    fn windows_vault_copy_status(&self, value: &Value) -> Result<Value, String> {
        use crate::vault_edit_jobs::VaultEditFailureClass;
        let fields = value.as_object().ok_or("Invalid copy status request")?;
        if fields.keys().any(|key| {
            !matches!(
                key.as_str(),
                "action"
                    | "profile_id"
                    | "space_id"
                    | "root_resource_id"
                    | "job_id"
                    | "expected_generation"
            )
        }) {
            return Err("Invalid copy status request".into());
        }
        let text = |key: &str| {
            fields
                .get(key)
                .and_then(Value::as_str)
                .filter(|v| {
                    !v.is_empty()
                        && v.len() <= 512
                        && v.trim() == *v
                        && !v.chars().any(char::is_control)
                })
                .ok_or("Invalid copy status request")
        };
        if text("profile_id")? != self.profile_scope {
            return Err("Copy job was not found".into());
        }
        let expected = fields
            .get("expected_generation")
            .and_then(Value::as_u64)
            .filter(|g| *g != 0)
            .ok_or("Invalid copy generation")?;
        let origin = {
            let state = self
                .state
                .lock()
                .map_err(|_| "Account state is unavailable")?;
            if state.active_generation != expected
                || self.generation.load(Ordering::Acquire) != expected
            {
                return Err("Copy job was not found".into());
            }
            url::Url::parse(&state.session.as_ref().ok_or("Connect this account")?.server)
                .map_err(|_| "The account server is invalid")?
                .origin()
                .ascii_serialization()
        };
        let scope = raiun_vault::session::VaultSessionScope::new(
            &self.profile_scope,
            &origin,
            text("space_id")?,
            text("root_resource_id")?,
        )
        .map_err(|_| "Invalid copy scope")?;
        let id = text("job_id")?;
        let mut status = self.vault_copy_jobs.status(&scope, id, expected)?;
        if status.operation.as_deref() != Some("copy_file") {
            return Err("Copy job was not found".into());
        }
        if text("action")? == "vault_copy_cancel" {
            status = self
                .vault_copy_jobs
                .cancel(&scope, id, expected)
                .or_else(|_| self.vault_copy_jobs.status(&scope, id, expected))?;
        }
        let bound = status.write_id.as_ref().is_some_and(|id| {
            id.len() == 32
                && id
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        }) && status
            .operation_revision
            .is_some_and(|revision| revision > 0);
        let state = match status.state.as_str() {
            "queued" => "queued",
            "running" => "running",
            "complete" if bound => "copied",
            "cancelled" if bound => "needs_review",
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
        let mut result = json!({"job_id":status.job_id,"auth_generation":expected,"state":state,"cancel_requested":status.cancel_requested});
        if bound {
            result["write_id"] = json!(status.write_id);
            result["revision"] = json!(status.operation_revision);
        }
        Ok(result)
    }
}
