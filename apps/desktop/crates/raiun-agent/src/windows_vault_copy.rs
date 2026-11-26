// Explicit one-file online copy. The portable copy journal remains ciphertext
// only; this adapter grants no generic Windows vault write or replay authority.
struct WindowsVaultCopyRequest {
    moving: bool,
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
        if !matches!(
            text("action", 64)?.as_str(),
            "vault_copy_start" | "vault_move_start"
        ) || text("profile_id", 128)? != profile
        {
            return Err(invalid());
        }
        let request = Self {
            moving: text("action", 64)? == "vault_move_start",
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
            source_auth_generation: client.provider_context_generation(),
            destination_auth_generation: client.provider_context_generation(),
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
        let job = VaultEditReconcileJobs::start_file_transfer_producer(
            &self.vault_copy_jobs,
            CopyProducerJobSpec {
                destination: &destination_scope,
                source: &source_scope,
                auth_generation: generation.clone(),
                expected_generation: expected,
                pin_jobs: self.vault_copy_serialization.clone(),
                start_gate: gate,
            },
            request.moving,
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
                let source_journal = raiun_opencloud::vault_cache::VaultOfflineCache::new(
                    cache.clone(),
                    worker_source.clone(),
                    &request.source_root,
                )
                .map_err(|_| unavailable())?;
                let source = VaultBackend::new_with_offline_cache(
                    (*client).clone(),
                    sessions.clone(),
                    worker_source,
                    request.source_root,
                    source_journal,
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
                let mut on_binding = |id: &str, revision: u64| {
                    binding_published = true;
                    if let Err(error) = publish(id, revision) {
                        publication_error = Some(error);
                        cancelled.store(true, Ordering::Release);
                    }
                };
                let transfer = if request.moving {
                    source
                        .move_file_to_cancellable_with_binding(
                            &destination,
                            &copy,
                            &stop,
                            &mut on_binding,
                        )
                        .map(|outcome| match outcome {
                            raiun_opencloud::vault_backend::VaultMoveOutcome::Moved { copy } => {
                                Some(copy)
                            }
                            _ => None,
                        })
                } else {
                    source
                        .copy_file_to_cancellable_with_binding(
                            &destination,
                            &copy,
                            &stop,
                            &mut on_binding,
                        )
                        .map(Some)
                };
                drop(on_binding);
                let outcome = transfer;
                if let Some(error) = publication_error {
                    return Err(error);
                }
                match outcome {
                    Ok(Some(VaultCopyOutcome::Copied { .. })) => {
                        progress(1, 1, 0, 0);
                        Ok(VaultEditReconcileReport {
                            processed: 1,
                            uploaded: 1,
                            conflicts: 0,
                            remaining: 0,
                        })
                    }
                    Ok(None) | Ok(Some(VaultCopyOutcome::NeedsReconciliation { .. })) => {
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
        if !matches!(status.operation.as_deref(), Some("copy_file" | "move_file")) {
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
            "complete" if bound && status.operation.as_deref() == Some("move_file") => "moved",
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

    /// Merge the separately protected copy journal into the normal saved
    /// operations view. Native vault operations remain the first page stream;
    /// copy-journal pagination starts only after that stream is exhausted.
    fn windows_vault_operations_with_copy(&self, request: &Value) -> Result<Value, String> {
        let fields = request
            .as_object()
            .ok_or("Invalid saved-operation request")?;
        let after = fields
            .get("after")
            .map(|value| value.as_str().ok_or("Invalid saved-operation cursor"))
            .transpose()?;
        let copy_cursor = match after {
            Some(value) if value == "copy:" => Some(None),
            Some(value) if value.starts_with("copy:") => {
                let id = &value[5..];
                if !windows_valid_copy_write_id(id) {
                    return Err("Invalid saved-operation cursor".into());
                }
                Some(Some(id.to_owned()))
            }
            _ => None,
        };

        let mut native_request = request.clone();
        if copy_cursor.is_some() {
            // The Windows native journal accepts only its existing 32-hex
            // cursor. Use it for the usual account/root/auth checks, then
            // replace its first-page items because this request is in the
            // independent copy-journal stream.
            if let Some(object) = native_request.as_object_mut() {
                object.remove("after");
            }
        }
        let mut result = self.windows_vault_pending_request(&native_request)?;
        let result_object = result
            .as_object_mut()
            .ok_or("Saved operations are unavailable")?;
        let expected_generation = fields
            .get("expected_generation")
            .and_then(Value::as_u64)
            .filter(|generation| *generation != 0)
            .ok_or("Refresh the current account")?;
        let space = fields
            .get("space_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 512)
            .ok_or("Invalid saved-operation scope")?;
        let root_resource_id = fields
            .get("root_resource_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 512)
            .ok_or("Invalid saved-operation scope")?;
        let root_path = fields
            .get("root_path")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 4096)
            .ok_or("Invalid saved-operation root")?;
        let limit = fields
            .get("limit")
            .map(|value| value.as_u64().ok_or("Invalid page size"))
            .transpose()?
            .unwrap_or(50);
        let limit = usize::try_from(limit)
            .ok()
            .filter(|limit| (1..=100).contains(limit))
            .ok_or("Invalid page size")?;

        // Do not mix records from a stale or differently routed native page.
        if result_object.get("space_id").and_then(Value::as_str) != Some(space)
            || result_object
                .get("root_resource_id")
                .and_then(Value::as_str)
                != Some(root_resource_id)
            || result_object.get("auth_generation").and_then(Value::as_u64)
                != Some(expected_generation)
        {
            return Err("The encrypted account changed while reading saved operations".into());
        }

        let native_items = result_object
            .get_mut("items")
            .and_then(Value::as_array_mut)
            .ok_or("Saved operations are unavailable")?;
        if copy_cursor.is_some() {
            native_items.clear();
            result_object.insert("next_after".into(), Value::Null);
            result_object.insert("truncated".into(), Value::Bool(false));
        } else if result_object
            .get("truncated")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            // Keep the existing native continuation intact. Copy rows start
            // only once this first stream is complete.
            return Ok(result);
        }

        let is_copy_stream = copy_cursor.is_some();
        let current_items = result_object
            .get("items")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0);
        let remaining = limit.saturating_sub(current_items);
        let after_copy = copy_cursor.as_ref().and_then(Clone::clone);
        let copy_page = self.read_windows_copy_operations_page(
            space,
            root_resource_id,
            root_path,
            expected_generation,
            after_copy.as_deref(),
            if remaining == 0 { 1 } else { remaining },
        )?;

        if remaining == 0 {
            // Probe only to determine whether a second stream exists. Keep its
            // first row unconsumed; the next request starts at the sentinel.
            let next = if copy_page.has_items || copy_page.more {
                Some(if copy_page.has_items {
                    copy_page
                        .cursor_before_first
                        .clone()
                        .flatten()
                        .unwrap_or_default()
                } else {
                    copy_page
                        .scanned_cursor
                        .clone()
                        .or_else(|| after_copy.clone())
                        .unwrap_or_default()
                })
            } else {
                None
            };
            if let Some(cursor) = next {
                result_object.insert(
                    "next_after".into(),
                    Value::String(copy_cursor_wire(&cursor)),
                );
                result_object.insert("truncated".into(), Value::Bool(true));
            }
            return Ok(result);
        }

        let items = result_object
            .get_mut("items")
            .and_then(Value::as_array_mut)
            .ok_or("Saved operations are unavailable")?;
        items.extend(copy_page.items);
        if copy_page.more {
            let cursor = copy_page
                .next_after
                .or(copy_page.scanned_cursor)
                .unwrap_or_default();
            result_object.insert(
                "next_after".into(),
                Value::String(copy_cursor_wire(&cursor)),
            );
            result_object.insert("truncated".into(), Value::Bool(true));
        } else if is_copy_stream {
            result_object.insert("next_after".into(), Value::Null);
            result_object.insert("truncated".into(), Value::Bool(false));
        }
        Ok(result)
    }

    fn read_windows_copy_operations_page(
        &self,
        space: &str,
        root_resource_id: &str,
        root_path: &str,
        expected_generation: u64,
        after: Option<&str>,
        limit: usize,
    ) -> Result<WindowsCopyOperationsPage, String> {
        use raiun_opencloud::vault_cache::{
            VaultOfflineCache, VaultPendingOperationKind as Operation,
        };
        use std::sync::atomic::AtomicBool;

        let account = self.windows_vault_offline_account(expected_generation)?;
        self.check_windows_vault_offline_account(&account)?;
        if self.generation.load(Ordering::Acquire) != expected_generation {
            return Err("The encrypted account changed while reading saved operations".into());
        }
        let owner = account
            .configuration
            .registration_ownership
            .as_ref()
            .ok_or("The saved root owner is unavailable")?;
        let active = ActiveProviderBinding {
            generation: expected_generation,
            path: PathBuf::from(&account.configuration.path),
            identity: account._root.identity(),
            personal_space_id: owner.personal_drive_id.clone(),
            personal_root_resource_id: owner
                .personal_root_resource_id
                .clone()
                .ok_or("The Personal root is unavailable")?,
        };
        let verified = self.provider.verified_vault_backend(active)?;
        let route = verified
            .backend
            .verified_vault_copy_route(account._root.identity(), space, root_resource_id, root_path)
            .map_err(|_| "Encrypted vault route is unavailable")?;
        let scope = raiun_vault::session::VaultSessionScope::new(
            &self.profile_scope,
            &account.origin,
            space,
            root_resource_id,
        )
        .map_err(|_| "Invalid saved-operation scope")?;
        if !self.vault_sessions.is_unlocked(&scope).unwrap_or(false) {
            return Err("Unlock this encrypted vault before viewing saved operations".into());
        }

        let cancelled = AtomicBool::new(false);
        let result = self.vault_copy_serialization.try_run_serialized(&cancelled, || {
            let (private, cache) = windows_copy_cache_for_account(&account.account)?;
            let _private_pin = private;
            let journal = VaultOfflineCache::new(cache, scope.clone(), route.root_path())
                .map_err(|_| "Encrypted copy journal is unavailable")?;
            let mut cursor = after.map(str::to_owned);
            let mut items = Vec::with_capacity(limit);
            let mut scanned = 0usize;
            let mut more = false;
            let mut cursor_before_first: Option<Option<String>> = None;
            const MAX_SCAN_ROWS: usize = 500;
            while scanned < MAX_SCAN_ROWS && items.len() < limit {
                let page_limit = (MAX_SCAN_ROWS - scanned).min(100);
                let (rows, page_more) = journal
                    .pending_edits(&self.vault_sessions, cursor.as_deref(), page_limit)
                    .map_err(|_| "Encrypted copy metadata could not be authenticated")?;
                if rows.is_empty() {
                    more = false;
                    break;
                }
                let rows_len = rows.len();
                let mut reached_limit = false;
                for (index, row) in rows.into_iter().enumerate() {
                    let previous_cursor = cursor.clone();
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
                    let is_copy = row.operation == Operation::CopyFile;
                    let is_fenced_source_removal = row.operation == Operation::DeleteFile
                        && row.state == raiun_cache::CiphertextWriteState::Conflict;
                    if !is_copy && !is_fenced_source_removal {
                        continue;
                    }
                    if is_copy {
                        if let Some(source) = journal
                            .pending_copy_source_target(&self.vault_sessions, &row.id, row.revision)
                            .map_err(|_| "Encrypted copy metadata could not be authenticated")?
                        {
                            if source.scope.account_id() != scope.account_id()
                                || source.scope.server_origin() != scope.server_origin()
                            {
                                return Err("Encrypted copy source scope is invalid".into());
                            }
                        }
                    }
                    cursor_before_first.get_or_insert(previous_cursor);
                    let operation = crate::vault_operation_wire::vault_pending_operation_name(
                        row.operation,
                    );
                    let state = crate::vault_operation_wire::vault_pending_operation_state_name(
                        row.state,
                    );
                    let attention = if is_fenced_source_removal {
                        Some("source_removal_requires_review")
                    } else {
                        crate::vault_operation_wire::vault_pending_operation_attention_reason(
                            row.operation,
                            row.state,
                        )
                    };
                    items.push(json!({
                        "write_id":row.id,
                        "revision":row.revision,
                        "retry_generation":row.retry_generation,
                        "operation":operation,
                        "state":state,
                        "needs_attention":attention.is_some(),
                        "attention_reason":attention,
                        "retry_state":null,
                        "can_retry_interrupted_create":false,
                        "path":row.path,
                        "destination_path":if row.destination_path.is_empty() { None } else { Some(row.destination_path) },
                        "bytes":row.plaintext_len,
                    }));
                    if items.len() == limit {
                        more = index + 1 < rows_len || page_more;
                        reached_limit = true;
                        break;
                    }
                }
                if reached_limit {
                    break;
                }
                if !page_more {
                    more = false;
                    break;
                }
                more = true;
            }
            if scanned >= MAX_SCAN_ROWS && items.len() < limit {
                more = true;
            }
            let has_items = !items.is_empty();
            Ok(WindowsCopyOperationsPage {
                items,
                more,
                next_after: more.then(|| cursor.clone()).flatten(),
                scanned_cursor: cursor,
                cursor_before_first,
                has_items,
            })
        });
        let page = result?;

        self.check_windows_vault_offline_account(&account)?;
        if self.generation.load(Ordering::Acquire) != expected_generation
            || !self.vault_sessions.is_unlocked(&scope).unwrap_or(false)
            || verified.backend.vault_copy_route_cancelled(&route)
        {
            return Err(
                "The encrypted account or vault changed while reading saved operations".into(),
            );
        }
        Ok(page)
    }

    fn prepare_windows_vault_copy_verification(
        self: &Arc<Self>,
        request: &Value,
    ) -> Result<(Value, Option<std::sync::mpsc::Sender<()>>), String> {
        use crate::vault_edit_jobs::{
            CopyVerifyReviewReason, VaultEditFailureClass, VaultEditJobFailure,
            VaultEditReconcileJobs, VaultEditReconcileReport,
        };
        use raiun_opencloud::vault_backend::VaultBackend;
        use raiun_opencloud::vault_cache::VaultOfflineCache;

        let fields = request
            .as_object()
            .ok_or("Invalid Copy verification request")?;
        let reject = |error| (json!({"accepted":false,"error":error}), None);
        if fields.keys().any(|key| {
            !matches!(
                key.as_str(),
                "action"
                    | "profile_id"
                    | "expected_generation"
                    | "space_id"
                    | "root_resource_id"
                    | "root_path"
                    | "write_id"
                    | "revision"
            )
        }) {
            return Err("Invalid Copy verification request".into());
        }
        let text = |key: &str, max: usize| {
            fields
                .get(key)
                .and_then(Value::as_str)
                .filter(|value| {
                    !value.is_empty()
                        && value.len() <= max
                        && value.trim() == *value
                        && !value.chars().any(char::is_control)
                })
                .ok_or("Invalid Copy verification request")
        };
        if text("action", 64)? != "vault_copy_verify_start"
            || text("profile_id", 128)? != self.profile_scope
        {
            return Err("Invalid Copy verification request".into());
        }
        let expected = fields
            .get("expected_generation")
            .and_then(Value::as_u64)
            .filter(|generation| *generation != 0)
            .ok_or("Refresh the current account")?;
        let write_id = text("write_id", 32)?.to_owned();
        if !windows_valid_copy_write_id(&write_id) {
            return Ok(reject("scope_changed"));
        }
        let revision = fields
            .get("revision")
            .and_then(Value::as_u64)
            .filter(|revision| *revision > 0)
            .ok_or("Invalid Copy revision")?;
        if self.generation.load(Ordering::Acquire) != expected {
            return Ok(reject("stale_generation"));
        }

        let _operation = self
            .vault_credential_operation
            .lock()
            .map_err(|_| "Vault changes are unavailable")?;
        let context =
            self.capture_windows_vault_context(Some(&self.profile_scope), Some(expected))?;
        if context.verified.backend.is_cached_only() {
            return Ok(reject("offline"));
        }
        let (client, trusted) = context
            .verified
            .backend
            .vault_read_context(context.identity)
            .map_err(|_| "The connected drive changed")?;
        let space = text("space_id", 512)?;
        let root_id = text("root_resource_id", 512)?;
        let destination_root_path = text("root_path", 4096)?;
        raiun_core::validate_remote_path(destination_root_path)
            .map_err(|_| "Invalid Copy verification root")?;
        if destination_root_path.contains('\\') {
            return Err("Invalid Copy verification root".into());
        }
        let destination_scope = raiun_vault::session::VaultSessionScope::new(
            &self.profile_scope,
            trusted.server_origin(),
            space,
            root_id,
        )
        .map_err(|_| "Invalid Copy scope")?;
        if !self
            .vault_sessions
            .is_unlocked(&destination_scope)
            .unwrap_or(false)
        {
            return Ok(reject("locked"));
        }
        let destination_route = context
            .verified
            .backend
            .verified_vault_copy_route(context.identity, space, root_id, destination_root_path)
            .map_err(|_| "The destination vault route changed")?;
        let account = windows_copy_account_scope(
            &self.profile_scope,
            &context.session,
            trusted.account_id(),
        )?;
        let account_bytes =
            serde_json::to_vec(&account).map_err(|_| "The account scope is invalid")?;
        let private = windows_copy_private_directory_for_account(&account_bytes)?;
        let cancelled_preflight = std::sync::atomic::AtomicBool::new(false);
        let source_target =
            self.vault_copy_serialization
                .try_run_serialized(&cancelled_preflight, || {
                    let cache = raiun_cache::Cache::open(private.path(), 1 << 30)
                        .map_err(|_| "Copy journal entry is unavailable".to_owned())?;
                    let destination_journal = VaultOfflineCache::new(
                        cache,
                        destination_scope.clone(),
                        destination_route.root_path(),
                    )
                    .map_err(|_| "Copy journal entry is unavailable".to_owned())?;
                    destination_journal
                        .pending_copy_source_target(&self.vault_sessions, &write_id, revision)
                        .map_err(|_| "Copy journal entry is unavailable".to_owned())
                });
        let source_target = match source_target {
            Ok(Some(target)) => Some(target),
            Ok(None) => None,
            Err(error) if error == "Encrypted remote operation is busy" => {
                return Ok(reject("busy"));
            }
            Err(_) => return Ok(reject("scope_changed")),
        };
        if let Some(target) = source_target.as_ref()
            && (target.scope.account_id() != destination_scope.account_id()
                || target.scope.server_origin() != destination_scope.server_origin())
        {
            return Ok(reject("scope_changed"));
        }
        if source_target
            .as_ref()
            .is_some_and(|target| target.scope == destination_scope)
        {
            return Ok(reject("scope_changed"));
        }
        let source_route = if let Some(target) = source_target.as_ref() {
            if !self
                .vault_sessions
                .is_unlocked(&target.scope)
                .unwrap_or(false)
            {
                return Ok(reject("locked"));
            }
            let route = context
                .verified
                .backend
                .verified_vault_copy_route(
                    context.identity,
                    target.scope.space_id(),
                    target.scope.resource_id(),
                    &target.root_path,
                )
                .map_err(|_| "The source vault route changed")?;
            Some((target.scope.clone(), route))
        } else {
            // Legacy Copy records do not have an authenticated source binding;
            // admit a review-only job which performs no remote request.
            None
        };
        self.check_windows_vault_authority(
            &context.session,
            expected,
            &context.configuration,
            &context.verified.backend,
        )?;
        drop(_operation);

        let source_scope = source_route.as_ref().map(|(scope, _)| scope.clone());
        let worker_source = source_scope
            .clone()
            .unwrap_or_else(|| destination_scope.clone());
        let worker_destination = destination_scope.clone();
        let destination_path = destination_route.root_path().to_owned();
        let source_path = source_route
            .as_ref()
            .map(|(_, route)| route.root_path().to_owned());
        let client = (*client).clone();
        let sessions = self.vault_sessions.clone();
        let generation = self.generation.clone();
        let backend = context.verified.backend.clone();
        let source_route_for_worker = source_route.as_ref().map(|(_, route)| Arc::clone(route));
        let root_path = PathBuf::from(&context.configuration.path);
        let root_identity = context.identity;
        let auth_generation = self.generation.clone();
        let job = VaultEditReconcileJobs::start_copy_verification(
            &self.vault_copy_jobs,
            crate::vault_edit_jobs::CopyVerificationJobSpec {
                destination: &destination_scope,
                source: source_scope.as_ref(),
                auth_generation,
                expected_generation: expected,
                pin_jobs: self.vault_copy_serialization.clone(),
                binding: crate::vault_edit_jobs::VaultEditOperationBinding {
                    operation: "copy_verify".into(),
                    write_id: write_id.clone(),
                    revision,
                    retry_generation: None,
                },
            },
            move |cancelled, progress| {
                let _root_pin = pin_registered_configured_root(&root_path, root_identity)
                    .map_err(|_| VaultEditJobFailure::unclassified("The Windows drive changed"))?;
                let _private_pin = private;
                let stop = || {
                    cancelled.load(Ordering::Acquire)
                        || generation.load(Ordering::Acquire) != expected
                        || backend.vault_copy_route_cancelled(&destination_route)
                        || source_route_for_worker
                            .as_ref()
                            .is_some_and(|route| backend.vault_copy_route_cancelled(route))
                };
                if stop() {
                    return Err(VaultEditJobFailure::unclassified(
                        "Copy verification was invalidated",
                    ));
                }
                if source_path.is_none() {
                    return Err(VaultEditJobFailure::classified(
                        "Copy requires review",
                        VaultEditFailureClass::CopyNeedsReview(
                            CopyVerifyReviewReason::LegacyBindingUnavailable,
                        ),
                    ));
                }
                let cache =
                    raiun_cache::Cache::open(_private_pin.path(), 1 << 30).map_err(|_| {
                        VaultEditJobFailure::unclassified("Copy verification is unavailable")
                    })?;
                let source_path = source_path.expect("checked above");
                let source_cache =
                    VaultOfflineCache::new(cache.clone(), worker_source.clone(), &source_path)
                        .map_err(|_| {
                            VaultEditJobFailure::unclassified("Copy verification is unavailable")
                        })?;
                let destination_cache =
                    VaultOfflineCache::new(cache, worker_destination.clone(), &destination_path)
                        .map_err(|_| {
                            VaultEditJobFailure::unclassified("Copy verification is unavailable")
                        })?;
                let source = VaultBackend::new_with_offline_cache(
                    client.clone(),
                    sessions.clone(),
                    worker_source.clone(),
                    source_path,
                    source_cache,
                )
                .map_err(|_| {
                    VaultEditJobFailure::unclassified("Copy verification is unavailable")
                })?;
                let destination = VaultBackend::new_with_offline_cache(
                    client,
                    sessions,
                    worker_destination,
                    destination_path,
                    destination_cache,
                )
                .map_err(|_| {
                    VaultEditJobFailure::unclassified("Copy verification is unavailable")
                })?;
                if stop() {
                    return Err(VaultEditJobFailure::unclassified(
                        "Copy verification was invalidated",
                    ));
                }
                progress(0, 0, 0, 1);
                match source.resolve_pending_copy_to_cancellable(
                    &destination,
                    &write_id,
                    revision,
                    stop,
                ) {
                    Ok(raiun_opencloud::vault_backend::VaultCopyResolutionOutcome::Verified {
                        ..
                    }) => {
                        progress(1, 0, 0, 0);
                        Ok(VaultEditReconcileReport {
                            processed: 1,
                            uploaded: 0,
                            conflicts: 0,
                            remaining: 0,
                        })
                    }
                    Ok(
                        raiun_opencloud::vault_backend::VaultCopyResolutionOutcome::NeedsReview {
                            reason,
                            ..
                        },
                    ) => Err(VaultEditJobFailure::classified(
                        "Copy requires review",
                        VaultEditFailureClass::CopyNeedsReview(windows_copy_verify_reason(reason)),
                    )),
                    Err(_) => Err(VaultEditJobFailure::unclassified(
                        "Copy verification is unavailable",
                    )),
                }
            },
        );
        match job {
            Ok(job) => Ok((json!({"accepted":true,"job_id":job.job_id}), None)),
            Err(error) if error.contains("already running") => Ok(reject("busy")),
            Err(_) => Ok(reject("unavailable")),
        }
    }

    fn windows_vault_copy_verification_status(&self, request: &Value) -> Result<Value, String> {
        let fields = request
            .as_object()
            .ok_or("Invalid Copy verification status request")?;
        if fields.keys().any(|key| {
            !matches!(
                key.as_str(),
                "action"
                    | "profile_id"
                    | "expected_generation"
                    | "space_id"
                    | "root_resource_id"
                    | "job_id"
            )
        }) {
            return Err("Invalid Copy verification status request".into());
        }
        let text = |key: &str, max: usize| {
            fields
                .get(key)
                .and_then(Value::as_str)
                .filter(|value| {
                    !value.is_empty()
                        && value.len() <= max
                        && value.trim() == *value
                        && !value.chars().any(char::is_control)
                })
                .ok_or("Invalid Copy verification status request")
        };
        if text("profile_id", 128)? != self.profile_scope {
            return Err("Copy verification job was not found".into());
        }
        let expected = fields
            .get("expected_generation")
            .and_then(Value::as_u64)
            .filter(|generation| *generation != 0)
            .ok_or("Invalid Copy verification generation")?;
        let account = self.windows_vault_offline_account(expected)?;
        let scope = raiun_vault::session::VaultSessionScope::new(
            &self.profile_scope,
            &account.origin,
            text("space_id", 512)?,
            text("root_resource_id", 512)?,
        )
        .map_err(|_| "Copy verification job was not found")?;
        let job_id = text("job_id", 256)?;
        let action = text("action", 64)?;
        if !matches!(
            action,
            "vault_copy_verify_status" | "vault_copy_verify_cancel"
        ) {
            return Err("Invalid Copy verification status request".into());
        }
        let mut status = self.vault_copy_jobs.status(&scope, job_id, expected)?;
        if status.operation.as_deref() != Some("copy_verify") {
            return Err("Copy verification job was not found".into());
        }
        if action == "vault_copy_verify_cancel" {
            status = self
                .vault_copy_jobs
                .cancel(&scope, job_id, expected)
                .or_else(|_| self.vault_copy_jobs.status(&scope, job_id, expected))?;
        }
        if status.operation.as_deref() != Some("copy_verify") {
            return Err("Copy verification job was not found".into());
        }
        Ok(windows_copy_verification_job_status(&status, expected))
    }
}

fn windows_copy_verification_job_status(
    status: &crate::vault_edit_jobs::VaultEditReconcileStatus,
    auth_generation: u64,
) -> Value {
    use crate::vault_edit_jobs::VaultEditFailureClass;
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

struct WindowsCopyOperationsPage {
    items: Vec<Value>,
    more: bool,
    next_after: Option<String>,
    scanned_cursor: Option<String>,
    cursor_before_first: Option<Option<String>>,
    has_items: bool,
}

fn copy_cursor_wire(cursor: &str) -> String {
    if cursor.is_empty() {
        "copy:".to_owned()
    } else {
        format!("copy:{cursor}")
    }
}

fn windows_valid_copy_write_id(write_id: &str) -> bool {
    write_id.len() == 32
        && write_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn windows_copy_verify_reason(
    reason: raiun_opencloud::vault_backend::VaultCopyResolutionReason,
) -> crate::vault_edit_jobs::CopyVerifyReviewReason {
    use crate::vault_edit_jobs::CopyVerifyReviewReason as Review;
    use raiun_opencloud::vault_backend::VaultCopyResolutionReason as Reason;
    match reason {
        Reason::LegacySourceBindingUnavailable => Review::LegacyBindingUnavailable,
        Reason::CopyWasNeverAttempted => Review::NeverAttempted,
        Reason::SourceScopeMismatch => Review::SourceScopeMismatch,
        Reason::SourceChanged => Review::SourceChanged,
        Reason::DestinationChanged => Review::DestinationChanged,
        Reason::ContentMismatch => Review::ContentMismatch,
        Reason::AuthenticationGenerationChanged => Review::AuthenticationGenerationChanged,
        Reason::VerificationUnavailable => Review::VerificationUnavailable,
    }
}

fn windows_copy_account_scope(
    profile: &str,
    session: &auth::Session,
    account_id: &str,
) -> Result<raiun_engine::folder_pairs::AccountScope, String> {
    let issuer = session
        .expected_issuer
        .as_deref()
        .map(|issuer| url::Url::parse(issuer).map(|issuer| issuer.to_string()))
        .transpose()
        .map_err(|_| "The account issuer is invalid")?;
    raiun_engine::folder_pairs::AccountScope::new(
        profile.to_owned(),
        url::Url::parse(&session.server)
            .map_err(|_| "The account server is invalid")?
            .to_string(),
        session.client_id.clone(),
        issuer,
        account_id.to_owned(),
    )
    .map_err(|_| "The account scope is invalid".into())
}

fn windows_copy_cache_for_account(
    account: &[u8],
) -> Result<(raiun_control_windows::PrivateDirectory, raiun_cache::Cache), String> {
    let private = windows_copy_private_directory_for_account(account)?;
    let cache = raiun_cache::Cache::open(private.path(), 1 << 30)
        .map_err(|_| "Private encrypted copy storage is unavailable")?;
    Ok((private, cache))
}

fn windows_copy_private_directory_for_account(
    account: &[u8],
) -> Result<raiun_control_windows::PrivateDirectory, String> {
    use sha2::Digest;
    let storage =
        DpapiSessionStore::current_user().map_err(|_| "Private Windows storage is unavailable")?;
    let parent = raiun_control_windows::PinnedDirectory::open(storage.local_edit_state_directory())
        .map_err(|_| "Private Windows storage is unavailable")?;
    let directory_name = format!("vault-copy-journal-{:x}", sha2::Sha256::digest(account));
    let private = raiun_control_windows::PrivateDirectory::create_or_open_under(
        &parent,
        std::ffi::OsStr::new(&directory_name),
    )
    .map_err(|_| "Private encrypted copy storage is unavailable")?;
    Ok(private)
}
