//! Durable ordinary-create admission and explicitly owned background delivery.
use super::*;
use raiun_cache::{OrdinaryCreateReceipt, OrdinaryCreateRequest, OrdinaryCreateState};
#[cfg(unix)]
use raiun_core::backend::OperationCancellation;
use raiun_core::backend::OrdinaryCreateMetadata;

#[derive(Debug, Clone)]
pub struct VerifiedCreateParent {
    scope: CacheScope,
    path: String,
    parent_resource_id: String,
}
impl VerifiedCreateParent {
    pub fn scope(&self) -> &CacheScope {
        &self.scope
    }
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn parent_resource_id(&self) -> &str {
        &self.parent_resource_id
    }
}
#[derive(Debug, Clone, Serialize)]
pub struct SavedCreateCheck {
    pub outcome: &'static str,
    pub checked_at_unix: i64,
    pub bytes: u64,
    pub resolved: bool,
}

fn checked_digest(
    reader: &mut impl Read,
    check: &dyn Fn() -> bool,
) -> Result<(u64, String), CloudError> {
    let mut hash = Sha256::new();
    let mut len = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        current(check)?;
        let count = reader.read(&mut buffer).map_err(io_error)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
        len = len.checked_add(count as u64).ok_or_else(refused)?;
    }
    current(check)?;
    Ok((len, format!("{:x}", hash.finalize())))
}

pub struct CreateHandoffRequest<'a> {
    pub parent: &'a VerifiedCreateParent,
    pub source: &'a File,
    pub expected_len: u64,
    pub expected_sha256: &'a str,
    pub handoff_id: &'a str,
    pub max_pending_bytes: u64,
}
#[derive(Debug, Clone)]
pub struct DurableCreateReceipt {
    scope: CacheScope,
    receipt: OrdinaryCreateReceipt,
}
impl DurableCreateReceipt {
    pub fn scope(&self) -> &CacheScope {
        &self.scope
    }
    pub fn storage_receipt(&self) -> &OrdinaryCreateReceipt {
        &self.receipt
    }
}
#[derive(Debug, Clone)]
pub struct PendingCreateView {
    pub receipt: OrdinaryCreateReceipt,
    pub entry: RemoteEntry,
}
fn refused() -> CloudError {
    CloudError::new(
        ErrorKind::Conflict,
        "ordinary create binding or authority changed; local bytes retained",
    )
}
fn current(check: &dyn Fn() -> bool) -> Result<(), CloudError> {
    if check() { Ok(()) } else { Err(refused()) }
}
fn admitted(state: OrdinaryCreateState) -> bool {
    state != OrdinaryCreateState::Staged
}
fn active(state: OrdinaryCreateState) -> bool {
    admitted(state) && state != OrdinaryCreateState::Verified
}

impl Engine {
    pub(super) fn create_cache(&self, scope: &CacheScope) -> Result<&Cache, CloudError> {
        let identity = self.account_scope.as_ref().ok_or_else(refused)?;
        if self.vault_binding.is_some()
            || scope.protection() != ScopeProtection::PlaintextAllowed
            || scope.account_id() != identity.account_id
            || scope.origin() != identity.origin
            || self.backend.server_origin().as_deref() != Some(scope.origin())
        {
            return Err(refused());
        }
        Ok(&self.offline_cache.as_ref().ok_or_else(refused)?.cache)
    }
    /// Record local custody failure visibility only; this does not attempt an upload.
    pub fn record_pending_create_delete_refusal(
        &self,
        scope: &CacheScope,
        path: &str,
    ) -> Result<(), CloudError> {
        // A local refusal is normally before Engine::delete creates a transfer
        // row. Surface it without granting network authority or changing custody.
        self.create_cache(scope)?;
        validate_remote_path(path).map_err(|_| refused())?;
        if self.pending_create(scope, path)?.is_none() {
            return Err(refused());
        }
        let transfer = self.begin_transfer(None, scope.space_id(), path, "delete")?;
        self.finish_transfer(
            transfer,
            "failed",
            0,
            Some("Saved upload cannot be deleted while its remote outcome is unresolved. Review it in Transfers; the local copy is preserved."),
        )
    }

    /// Record local custody failure visibility only; this does not attempt an upload.
    pub fn record_create_handoff_failure(
        &self,
        scope: &CacheScope,
        path: &str,
    ) -> Result<(), CloudError> {
        self.create_cache(scope)?;
        validate_remote_path(path).map_err(|_| refused())?;
        if !path.starts_with('/') || path == "/" || path.ends_with('/') {
            return Err(refused());
        }
        let context = self.offline_cache.as_ref().ok_or_else(refused)?;
        // Match retained original scope metadata, never obtain fresh network authority.
        if self
            .cached_scope(scope.space_id(), context)
            .map_err(cache_cloud_error)?
            != *scope
        {
            return Err(refused());
        }
        let transfer = self.begin_transfer(None, scope.space_id(), path, "upload")?;
        self.finish_transfer(
            transfer,
            "failed",
            0,
            Some("File saved locally but upload could not be queued. Open Saved upload copies in Transfers to recover it."),
        )
    }
    /// Locate retained create recovery without obtaining new remote authority.
    /// Mount startup must not probe every Space's DAV root just to watch its
    /// existing journal. New creates and delivery still require fresh proofs.
    pub fn cached_create_recovery_scope(
        &self,
        space: &str,
    ) -> Result<Option<CacheScope>, CloudError> {
        let Some(context) = &self.offline_cache else {
            return Ok(None);
        };
        let scope = context
            .cache
            .find_plaintext_scope(&context.origin, &context.account_id, space)
            .map_err(cache_cloud_error)?;
        if let Some(scope) = &scope {
            self.create_cache(scope)?;
        }
        Ok(scope)
    }

    pub fn ordinary_create_scope(&self, space: &str) -> Result<Option<CacheScope>, CloudError> {
        if self.offline_cache.is_none() {
            return Ok(None);
        }
        match self.ordinary_write_scope(space) {
            Ok(scope) => Ok(Some(scope)),
            Err(error) if error.kind == ErrorKind::Offline => {
                let context = self.offline_cache.as_ref().ok_or_else(refused)?;
                self.cached_scope(space, context)
                    .map(Some)
                    .map_err(cache_cloud_error)
            }
            Err(error) => Err(error),
        }
    }
    pub fn capture_new_plaintext_create_parent(
        &self,
        expected_scope: &CacheScope,
        path: &str,
        expected_parent_id: Option<&str>,
        check: &dyn Fn() -> bool,
    ) -> Result<VerifiedCreateParent, CloudError> {
        self.prove_create_parent(expected_scope, path, expected_parent_id, check, true)
    }
    /// Capture initial create authority and its exact scope from the same fresh
    /// root/parent/absence observation. This proof is not reused at release or
    /// pre-claim, which remain pinned to the captured scope.
    pub fn capture_new_plaintext_create_parent_for_space(
        &self,
        space: &str,
        path: &str,
        expected_parent_id: Option<&str>,
        check: &dyn Fn() -> bool,
    ) -> Result<VerifiedCreateParent, CloudError> {
        self.observe_create_parent(space, None, path, expected_parent_id, check, true)
    }
    fn prove_create_parent(
        &self,
        expected_scope: &CacheScope,
        path: &str,
        expected_parent_id: Option<&str>,
        check: &dyn Fn() -> bool,
        require_absence: bool,
    ) -> Result<VerifiedCreateParent, CloudError> {
        self.create_cache(expected_scope)?;
        self.observe_create_parent(
            expected_scope.space_id(),
            Some(expected_scope),
            path,
            expected_parent_id,
            check,
            require_absence,
        )
    }
    fn observe_create_parent(
        &self,
        space: &str,
        expected_scope: Option<&CacheScope>,
        path: &str,
        expected_parent_id: Option<&str>,
        check: &dyn Fn() -> bool,
        require_absence: bool,
    ) -> Result<VerifiedCreateParent, CloudError> {
        let identity = self.account_scope.as_ref().ok_or_else(refused)?;
        let context = self.offline_cache.as_ref().ok_or_else(refused)?;
        if self.vault_binding.is_some()
            || context.account_id != identity.account_id
            || context.origin != identity.origin
            || self.backend.server_origin().as_deref() != Some(identity.origin.as_str())
        {
            return Err(refused());
        }
        current(check)?;
        validate_remote_path(path).map_err(|_| refused())?;
        if !path.starts_with('/') || path == "/" || path.ends_with('/') {
            return Err(refused());
        }
        let parent_path = parent_path(path)?;
        if parent_path != "/" && expected_parent_id.is_none() {
            return Err(refused());
        }
        // One observation reuses only this proof's freshly resolved routing.
        // Admission, pre-claim and completion still make separate fresh proofs.
        let observation = self.backend.ordinary_create_metadata(
            space,
            path,
            expected_scope.map(CacheScope::root_resource_id),
            expected_parent_id,
            require_absence,
            check,
        )?;
        self.validate_create_observation(
            space,
            expected_scope,
            path,
            expected_parent_id,
            check,
            require_absence,
            &observation,
        )
    }
    // Shared by ordinary proof calls and the upload preflight callback. Facts
    // remain borrowed for this operation; no reusable authority is cached.
    #[allow(clippy::too_many_arguments)]
    fn validate_create_observation(
        &self,
        space: &str,
        expected_scope: Option<&CacheScope>,
        path: &str,
        expected_parent_id: Option<&str>,
        check: &dyn Fn() -> bool,
        require_absence: bool,
        observation: &OrdinaryCreateMetadata,
    ) -> Result<VerifiedCreateParent, CloudError> {
        let identity = self.account_scope.as_ref().ok_or_else(refused)?;
        let context = self.offline_cache.as_ref().ok_or_else(refused)?;
        if self.vault_binding.is_some()
            || context.account_id != identity.account_id
            || context.origin != identity.origin
            || self.backend.server_origin().as_deref() != Some(identity.origin.as_str())
        {
            return Err(refused());
        }
        current(check)?;
        validate_remote_path(path).map_err(|_| refused())?;
        if !path.starts_with('/') || path == "/" || path.ends_with('/') {
            return Err(refused());
        }
        let parent_path = parent_path(path)?;
        if parent_path != "/" && expected_parent_id.is_none() {
            return Err(refused());
        }
        let scope = CacheScope::new(
            &context.origin,
            &context.account_id,
            &observation.space.id,
            &observation.root.id,
            ScopeProtection::PlaintextAllowed,
        )
        .map_err(cache_cloud_error)?;
        self.create_cache(&scope)?;
        if expected_scope.is_some_and(|expected| scope != *expected)
            || observation.space.id != space
            || observation.space.encrypted
            || !observation.space.writable
            || observation.root.path != "/"
            || !observation.root.directory
            || observation.root.encrypted
            || !observation.root.writable
            || observation.root.id.is_empty()
            || observation.root.id.chars().any(char::is_control)
        {
            return Err(refused());
        }
        let mut parent = &observation.root;
        let mut entries = observation.ancestors.iter();
        let mut ancestor = String::new();
        for component in parent_path.split('/').filter(|part| !part.is_empty()) {
            current(check)?;
            ancestor.push('/');
            ancestor.push_str(component);
            parent = entries.next().ok_or_else(refused)?;
            if !parent.directory
                || parent.encrypted
                || !parent.writable
                || parent.path != ancestor
                || parent.id.is_empty()
                || parent.id.chars().any(char::is_control)
            {
                return Err(refused());
            }
        }
        if entries.next().is_some() || expected_parent_id.is_some_and(|id| id != parent.id) {
            return Err(refused());
        }
        if require_absence && observation.target.is_some() {
            return Err(refused());
        }
        current(check)?;
        Ok(VerifiedCreateParent {
            scope,
            path: path.into(),
            parent_resource_id: parent.id.clone(),
        })
    }
    /// Inspect a stopped saved upload without sending or deleting cloud data.
    /// Only an exact conditional readback can complete its local journal row.
    pub fn check_saved_create(
        &self,
        scope: &CacheScope,
        write_id: i64,
        check: &dyn Fn() -> bool,
    ) -> Result<SavedCreateCheck, CloudError> {
        current(check)?;
        let cache = self.create_cache(scope)?;
        let receipt = cache
            .ordinary_create_for_write(scope, write_id)
            .map_err(cache_cloud_error)?
            .ok_or_else(refused)?;
        if !matches!(
            receipt.state,
            OrdinaryCreateState::Uncertain | OrdinaryCreateState::Conflict
        ) || receipt.body_evicted
        {
            return Err(refused());
        }
        let mut local = cache
            .open_content_cancellable(scope, &receipt.write.content, || !check())
            .map_err(cache_cloud_error)?;
        let (len, digest) = checked_digest(&mut local, check)?;
        if len != receipt.byte_len || digest != receipt.sha256 {
            return Err(CloudError::new(
                ErrorKind::InvalidResponse,
                "Saved file failed local integrity verification; no cloud request was sent",
            ));
        }
        drop(local);
        let transfer = self.begin_transfer(
            None,
            scope.space_id(),
            &receipt.write.logical_path,
            "verify_upload",
        )?;
        let outcome = (|| {
            let (observed_scope, _) = self.online_plaintext_scope(scope.space_id())?;
            if observed_scope != *scope {
                return Err(refused());
            }
            current(check)?;
            let entry = match self
                .backend
                .stat(scope.space_id(), &receipt.write.logical_path)
            {
                Ok(entry) => Some(entry),
                Err(error) if error.kind == ErrorKind::NotFound => None,
                Err(error) => return Err(error),
            };
            current(check)?;
            let result = |outcome, resolved| SavedCreateCheck {
                outcome,
                resolved,
                bytes: receipt.byte_len,
                checked_at_unix: now_unix(),
            };
            let Some(entry) = entry else {
                // A negative observation is information only, never retry or
                // deletion authority. Recheck root identity before reporting it.
                if self.online_plaintext_scope(scope.space_id())?.0 != *scope {
                    return Err(refused());
                }
                current(check)?;
                return Ok(result("missing", false));
            };
            if entry.path != receipt.write.logical_path
                || entry.directory
                || entry.encrypted
                || !entry.writable
                || entry.id.is_empty()
                || !entry.etag.starts_with('"')
                || !entry.etag.ends_with('"')
                || entry.etag.len() <= 2
                || entry.etag.chars().any(char::is_control)
            {
                return Ok(result("unavailable", false));
            }
            if entry.size != receipt.byte_len {
                return Ok(result("different", false));
            }
            let token = raiun_core::backend::OperationCancellation::new();
            let downloaded = NamedTempFile::new_in(self.cache_dir()).map_err(io_error)?;
            let verified = self.backend.download_in_root_with_cancellation(
                scope.space_id(),
                &receipt.write.logical_path,
                Some(&entry.etag),
                downloaded.path(),
                scope.root_resource_id(),
                &token,
            )?;
            current(check)?;
            let (remote_len, remote_digest) =
                checked_digest(&mut File::open(downloaded.path()).map_err(io_error)?, check)?;
            if verified.id != entry.id
                || verified.path != entry.path
                || verified.etag != entry.etag
                || verified.directory
                || verified.encrypted
                || !verified.writable
            {
                return Ok(result("unavailable", false));
            }
            if verified.size != receipt.byte_len
                || remote_len != receipt.byte_len
                || remote_digest != receipt.sha256
            {
                return Ok(result("different", false));
            }
            let _execution = self.execution()?;
            self.prove_create_parent(
                scope,
                &receipt.write.logical_path,
                Some(&receipt.write.parent_resource_id),
                check,
                false,
            )?;
            current(check)?;
            let _metadata = self.metadata_publication()?;
            cache
                .invalidate_paths(scope, &[&receipt.write.logical_path])
                .map_err(cache_cloud_error)?;
            current(check)?;
            cache
                .confirm_ordinary_create_readback(scope, &receipt, &verified, &remote_digest)
                .map_err(cache_cloud_error)?;
            Ok(result("verified", true))
        })();
        let (state, message) = match &outcome {
            Ok(result) if result.resolved => (
                "completed",
                "Cloud copy matches saved bytes; no upload was sent.".to_owned(),
            ),
            Ok(result) if result.outcome == "missing" => (
                "attention",
                "Cloud copy was not found. Saved bytes are preserved; no retry was sent."
                    .to_owned(),
            ),
            Ok(result) if result.outcome == "unavailable" => (
                "attention", "Cloud copy could not be compared reliably. Saved bytes are preserved; no upload was sent.".to_owned(),
            ),
            Ok(_) => (
                "attention",
                "Cloud copy does not match the saved upload. Both copies were left unchanged."
                    .to_owned(),
            ),
            Err(error) => (
                "failed",
                format!("Checking saved upload: {}", error.message),
            ),
        };
        self.finish_transfer(transfer, state, 0, Some(&message))?;
        outcome
    }

    pub fn queue_new_plaintext_create_scoped(
        &self,
        request: CreateHandoffRequest<'_>,
        check: &dyn Fn() -> bool,
    ) -> Result<DurableCreateReceipt, CloudError> {
        let _total_admission = CreateAdmissionStageTimer::start(
            &self.inner.create_admission_diagnostics.total_admission,
        );
        let parent = request.parent;
        let cache = self.create_cache(&parent.scope)?;
        current(check)?;
        let staged = {
            let _body_staging = CreateAdmissionStageTimer::start(
                &self.inner.create_admission_diagnostics.body_staging,
            );
            let metadata = request.source.metadata().map_err(io_error)?;
            if !metadata.is_file() || metadata.len() != request.expected_len {
                return Err(refused());
            }
            self.clean_create_headroom(&parent.scope, request.expected_len);
            let mut source = request.source.try_clone().map_err(io_error)?;
            source.seek(SeekFrom::Start(0)).map_err(io_error)?;
            cache
                .stage_ordinary_create(
                    &parent.scope,
                    OrdinaryCreateRequest {
                        max_pending_bytes: request.max_pending_bytes,
                        handoff_id: request.handoff_id.into(),
                        parent_resource_id: parent.parent_resource_id.clone(),
                        name: parent.path.rsplit('/').next().ok_or_else(refused)?.into(),
                        logical_path: parent.path.clone(),
                        expected_len: request.expected_len,
                        expected_sha256: request.expected_sha256.into(),
                    },
                    &mut source,
                )
                .map_err(cache_cloud_error)?
        };
        // Serialize only final bounded namespace proof/admission with existing
        // mutators. No body copy or background transfer holds this gate.
        let _execution_wait = CreateAdmissionStageTimer::start(
            &self.inner.create_admission_diagnostics.execution_wait,
        );
        let _execution = self.execution()?;
        drop(_execution_wait);
        let _execution_hold = CreateAdmissionStageTimer::start(
            &self.inner.create_admission_diagnostics.execution_hold,
        );
        let proof = {
            let _fresh_namespace_proof = CreateAdmissionStageTimer::start(
                &self
                    .inner
                    .create_admission_diagnostics
                    .fresh_namespace_proof,
            );
            self.capture_new_plaintext_create_parent(
                &parent.scope,
                &parent.path,
                Some(&parent.parent_resource_id),
                check,
            )?
        };
        if proof.parent_resource_id != parent.parent_resource_id {
            return Err(refused());
        }
        // The namespace proof above may perform bounded metadata HTTP; none
        // occurs while this publication guard is held. Serialize invalidation
        // and Ready CAS with cached_list's check-and-publish transaction.
        let metadata_publication_wait = CreateAdmissionStageTimer::start(
            &self
                .inner
                .create_admission_diagnostics
                .metadata_publication_wait,
        );
        let _metadata = self.metadata_publication()?;
        drop(metadata_publication_wait);
        let _local_ready_publish = CreateAdmissionStageTimer::start(
            &self.inner.create_admission_diagnostics.local_ready_publish,
        );
        current(check)?;
        cache
            .invalidate_paths(&parent.scope, &[&parent.path])
            .map_err(cache_cloud_error)?;
        let receipt = if staged.state == OrdinaryCreateState::Staged {
            cache
                .admit_ordinary_create(&parent.scope, &staged)
                .map_err(cache_cloud_error)?
        } else {
            staged
        };
        current(check)?;
        if receipt.state != OrdinaryCreateState::Ready {
            return Err(refused());
        }
        Ok(DurableCreateReceipt {
            scope: parent.scope.clone(),
            receipt,
        })
    }
    /// Look up exact admitted metadata for preparing a durable provider marker.
    /// This does not verify the body or grant permission to discard a spool,
    /// serve bytes or dispatch a write. Custody must be acknowledged separately.
    pub fn create_handoff_receipt_metadata(
        &self,
        scope: &CacheScope,
        path: &str,
        handoff_id: &str,
    ) -> Result<Option<OrdinaryCreateReceipt>, CloudError> {
        let cache = self.create_cache(scope)?;
        let Some(receipt) = cache
            .ordinary_create_for_handoff(scope, handoff_id)
            .map_err(cache_cloud_error)?
        else {
            return Ok(None);
        };
        if receipt.write.logical_path != path {
            return Err(refused());
        }
        if receipt.state == OrdinaryCreateState::Staged {
            return Ok(None);
        }
        Ok(Some(receipt))
    }
    pub fn create_receipt_for_handoff(
        &self,
        scope: &CacheScope,
        path: &str,
        handoff_id: &str,
    ) -> Result<Option<DurableCreateReceipt>, CloudError> {
        let Some(receipt) = self.create_handoff_receipt_metadata(scope, path, handoff_id)? else {
            return Ok(None);
        };
        Ok(Some(self.validate_create_receipt(
            scope, path, handoff_id, &receipt,
        )?))
    }
    pub fn validate_create_receipt(
        &self,
        scope: &CacheScope,
        path: &str,
        handoff_id: &str,
        expected: &OrdinaryCreateReceipt,
    ) -> Result<DurableCreateReceipt, CloudError> {
        let cache = self.create_cache(scope)?;
        let actual = cache
            .ordinary_create_for_handoff(scope, handoff_id)
            .map_err(cache_cloud_error)?
            .ok_or_else(refused)?;
        // Cache normalizes only lifecycle/write-state/remote/ACK/disposition.
        // Every immutable write and body binding must match the durable intent.
        if !admitted(actual.state)
            || !actual.has_same_immutable_binding(expected)
            || actual.write.logical_path != path
        {
            return Err(refused());
        }
        if actual.body_evicted {
            // Only Cache's committed clean tombstone can replace opening the
            // body for cleanup. Missing unresolved/unqualified bodies fail.
            if actual.state != OrdinaryCreateState::Verified
                || actual.write.state != WriteState::Verified
                || !actual.local_handoff_acknowledged
                || actual.remote.is_none()
            {
                return Err(refused());
            }
        } else {
            let _body = cache
                .open_content(scope, &actual.write.content)
                .map_err(cache_cloud_error)?;
        }
        Ok(DurableCreateReceipt {
            scope: scope.clone(),
            receipt: actual,
        })
    }
    /// FUSE calls only after its exact V3 receipt and directory are fsynced.
    /// This records local acceptance, never remote delivery or replay authority.
    pub fn acknowledge_create_handoff(
        &self,
        scope: &CacheScope,
        path: &str,
        handoff_id: &str,
        expected: &OrdinaryCreateReceipt,
        check: &dyn Fn() -> bool,
    ) -> Result<DurableCreateReceipt, CloudError> {
        current(check)?;
        let actual = self
            .create_handoff_receipt_metadata(scope, path, handoff_id)?
            .ok_or_else(refused)?;
        if !actual.has_same_immutable_binding(expected) {
            return Err(refused());
        }
        let cache = self.create_cache(scope)?;
        // Cache verifies the complete durable body and retains its reader
        // through the ACK CAS. Do not duplicate that full read here.
        let receipt = cache
            .acknowledge_ordinary_create_handoff(scope, &actual)
            .map_err(cache_cloud_error)?;
        current(check)?;
        // Optional cleanup runs before later admission under quota pressure,
        // outside this custody acknowledgement path.
        Ok(DurableCreateReceipt {
            scope: scope.clone(),
            receipt,
        })
    }
    fn clean_create_headroom(&self, scope: &CacheScope, incoming_len: u64) {
        let Ok(cache) = self.create_cache(scope) else {
            return;
        };
        let Ok(quota) = cache.try_quota_bytes() else {
            return;
        };
        let target = quota.saturating_sub(incoming_len.saturating_mul(2));
        let _ = cache.evict_acknowledged_ordinary_create_bodies(scope, target, 64);
    }
    pub fn fetch_create_snapshot(
        &self,
        scope: &CacheScope,
        path: &str,
        handoff_id: &str,
    ) -> Result<FetchSnapshot, CloudError> {
        let receipt = self
            .create_receipt_for_handoff(scope, path, handoff_id)?
            .ok_or_else(refused)?;
        let file = self
            .create_cache(scope)?
            .open_content(scope, &receipt.receipt.write.content)
            .map_err(cache_cloud_error)?;
        Ok(FetchSnapshot {
            _temp: None,
            file: SnapshotReader::Cached(file),
        })
    }
    pub(super) fn create_view(
        &self,
        scope: &CacheScope,
        receipt: OrdinaryCreateReceipt,
    ) -> Result<PendingCreateView, CloudError> {
        let mut entry = self.remote_entry_for_pending_in_scope(scope, &receipt.write)?;
        entry.id = format!("raiun-pending-create:{}", receipt.handoff_id);
        entry.etag = format!("\"raiun-local-create:{}\"", receipt.handoff_id);
        entry.writable = false;
        Ok(PendingCreateView { receipt, entry })
    }
    pub fn pending_create(
        &self,
        scope: &CacheScope,
        path: &str,
    ) -> Result<Option<PendingCreateView>, CloudError> {
        if self.offline_cache.is_none() {
            return Ok(None);
        }
        let cache = self.create_cache(scope)?;
        let Some(write) = cache
            .pending_write_for_path(scope, path)
            .map_err(cache_cloud_error)?
        else {
            return Ok(None);
        };
        let Some(receipt) = cache
            .ordinary_create_for_write(scope, write.id)
            .map_err(cache_cloud_error)?
        else {
            return Ok(None);
        };
        if !active(receipt.state) {
            return Ok(None);
        }
        self.create_view(scope, receipt).map(Some)
    }
    pub fn pending_create_children(
        &self,
        scope: &CacheScope,
        parent_id: &str,
    ) -> Result<Vec<PendingCreateView>, CloudError> {
        if self.offline_cache.is_none() {
            return Ok(Vec::new());
        }
        let cache = self.create_cache(scope)?;
        let mut result = Vec::new();
        for write in cache
            .pending_writes_for_parent(scope, parent_id)
            .map_err(cache_cloud_error)?
        {
            if let Some(receipt) = cache
                .ordinary_create_for_write(scope, write.id)
                .map_err(cache_cloud_error)?
                && active(receipt.state)
            {
                if result.len() >= MAX_LIST_ENTRIES {
                    return Err(refused());
                }
                result.push(self.create_view(scope, receipt)?);
            }
        }
        Ok(result)
    }
    pub fn has_pending_create_overlap(
        &self,
        scope: &CacheScope,
        path: &str,
    ) -> Result<bool, CloudError> {
        if self.offline_cache.is_none() {
            return Ok(false);
        }
        self.create_cache(scope)?
            .ordinary_create_path_blocked(scope, path)
            .map_err(cache_cloud_error)
    }
    pub fn ordinary_create_page(
        &self,
        scope: &CacheScope,
        after: Option<i64>,
        limit: usize,
    ) -> Result<raiun_cache::OrdinaryCreatePage, CloudError> {
        self.create_cache(scope)?
            .ordinary_creates(scope, after, limit)
            .map_err(cache_cloud_error)
    }
    // Trusted live scope registration is needed for first mutations/listings.
    // Cache NotFound denotes an absent scope row, never a silent clean answer.
    // Normal legacy Match paths retain their original behavior. The public
    // overlap query protects all unresolved writes; this guard additionally
    // isolates only new-ledger custody. The complete scan never returns a
    // truncated clean answer and retains only one bounded page at a time.
    fn ledger_overlap(&self, scope: &CacheScope, path: &str) -> Result<bool, CloudError> {
        let cache = self.create_cache(scope)?;
        if !cache
            .ordinary_create_path_blocked(scope, path)
            .map_err(cache_cloud_error)?
        {
            return Ok(false);
        }
        let mut after = None;
        loop {
            let page = cache
                .ordinary_creates(scope, after, 256)
                .map_err(cache_cloud_error)?;
            for receipt in page.items {
                let other = receipt.write.logical_path.as_str();
                if receipt.state != OrdinaryCreateState::Verified
                    && (path == other
                        || path == "/"
                        || other == "/"
                        || path
                            .strip_prefix(other)
                            .is_some_and(|tail| tail.starts_with('/'))
                        || other
                            .strip_prefix(path)
                            .is_some_and(|tail| tail.starts_with('/')))
                {
                    return Ok(true);
                }
            }
            match page.next_after {
                Some(next) if after.is_none_or(|old| next > old) => after = Some(next),
                Some(_) => return Err(refused()),
                None => return Ok(false),
            }
        }
    }
    pub(super) fn create_overlap_live(
        &self,
        scope: &CacheScope,
        path: &str,
    ) -> Result<bool, CloudError> {
        let cache = self.create_cache(scope)?;
        match self.ledger_overlap(scope, path) {
            Err(error) if error.kind == ErrorKind::NotFound => {
                cache
                    .invalidate_paths(scope, &[path])
                    .map_err(cache_cloud_error)?;
                self.ledger_overlap(scope, path)
            }
            result => result,
        }
    }
    pub(super) fn guard_create_mutation(
        &self,
        space: &str,
        paths: &[&str],
    ) -> Result<(), CloudError> {
        if self.offline_cache.is_none() || self.vault_binding.is_some() {
            return Ok(());
        }
        let (scope, _) = self.online_plaintext_scope(space)?;
        self.guard_create_mutation_in_scope(&scope, paths)
    }

    pub(super) fn guard_create_mutation_in_scope(
        &self,
        scope: &CacheScope,
        paths: &[&str],
    ) -> Result<(), CloudError> {
        for path in paths {
            if self.create_overlap_live(scope, path)? {
                return Err(refused());
            }
        }
        Ok(())
    }
}

pub struct CreateUploadHooks {
    pub is_current: Arc<dyn Fn() -> bool + Send + Sync>,
    pub dispatch_allowed: Arc<dyn Fn(&CacheScope) -> bool + Send + Sync>,
}
#[cfg(unix)]
mod owner {
    use super::*;
    use std::{
        sync::Condvar,
        thread::{self, JoinHandle},
        time::{Duration, Instant},
    };
    const CREATE_WORKERS: usize = 4;
    const READY_DISCOVERY_LIMIT: usize = CREATE_WORKERS;
    const MAX_WATCHED_SCOPES: usize = 256;

    struct Shared {
        engine: Engine,
        stopping: AtomicBool,
        token: OperationCancellation,
        scopes: Mutex<Vec<CacheScope>>,
        preparing: Mutex<Vec<(CacheScope, i64)>>,
        wake: Condvar,
        signal: Mutex<WakeSignal>,
        hooks: CreateUploadHooks,
    }
    #[derive(Default)]
    struct WakeSignal {
        generation: u64,
        admission_generation: u64,
    }
    impl Shared {
        fn notify(&self, admission: bool) -> Result<(), CloudError> {
            let mut signal = self.signal.lock().map_err(|_| refused())?;
            signal.generation = signal.generation.wrapping_add(1);
            if admission {
                signal.admission_generation = signal.admission_generation.wrapping_add(1);
            }
            self.wake.notify_all();
            Ok(())
        }
    }
    // This is only in-process preparation ownership. The durable one-use
    // cache claim is still required before any send; dropping this lease never
    // resets a durable claim or grants retry authority.
    struct PreparationLease {
        shared: Arc<Shared>,
        scope: CacheScope,
        write_id: i64,
    }
    impl PreparationLease {
        fn acquire(
            shared: &Arc<Shared>,
            scope: &CacheScope,
            write_id: i64,
        ) -> Result<Option<Self>, CloudError> {
            let mut active = shared.preparing.lock().map_err(|_| refused())?;
            if active.iter().any(|(s, id)| s == scope && *id == write_id) {
                return Ok(None);
            }
            active.push((scope.clone(), write_id));
            Ok(Some(Self {
                shared: shared.clone(),
                scope: scope.clone(),
                write_id,
            }))
        }
    }
    impl Drop for PreparationLease {
        fn drop(&mut self) {
            if let Ok(mut active) = self.shared.preparing.lock() {
                active.retain(|(scope, id)| *scope != self.scope || *id != self.write_id);
            }
            let _ = self.shared.notify(false);
        }
    }
    pub struct CreateUploadOwner {
        shared: Arc<Shared>,
        workers: Vec<JoinHandle<()>>,
        _lock: File,
        _directory: File,
    }
    #[derive(Clone)]
    pub struct CreateUploadHandle {
        shared: Arc<Shared>,
    }
    impl CreateUploadHandle {
        pub fn is_accepting(&self) -> bool {
            !self.shared.stopping.load(Ordering::Acquire) && (self.shared.hooks.is_current)()
        }
        pub fn wake_scope(&self, scope: &CacheScope) -> Result<(), CloudError> {
            if !self.is_accepting() {
                return Err(refused());
            }
            let mut scopes = self.shared.scopes.lock().map_err(|_| refused())?;
            if !scopes.contains(scope) {
                if scopes.len() >= MAX_WATCHED_SCOPES {
                    return Err(refused());
                }
                self.shared
                    .engine
                    .create_cache(scope)?
                    .recover_interrupted_ordinary_creates(scope)
                    .map_err(cache_cloud_error)?;
                scopes.push(scope.clone());
            }
            drop(scopes);
            self.shared.notify(true)
        }
        pub fn stop_admission(&self) {
            self.shared.stopping.store(true, Ordering::Release);
            self.shared.token.cancel();
            let _ = self.shared.notify(false);
        }
    }
    impl CreateUploadOwner {
        pub fn handle(&self) -> CreateUploadHandle {
            CreateUploadHandle {
                shared: self.shared.clone(),
            }
        }
        pub fn stop_and_join(&mut self) -> Result<(), CloudError> {
            self.handle().stop_admission();
            let mut panicked = false;
            for worker in self.workers.drain(..) {
                panicked |= worker.join().is_err();
            }
            if panicked { Err(refused()) } else { Ok(()) }
        }
    }
    impl Drop for CreateUploadOwner {
        fn drop(&mut self) {
            let _ = self.stop_and_join();
        }
    }
    impl Engine {
        pub fn start_create_upload_owner(
            &self,
            hooks: CreateUploadHooks,
        ) -> Result<CreateUploadOwner, CloudError> {
            if self.offline_cache.is_none()
                || self.vault_binding.is_some()
                || self.account_scope.is_none()
            {
                return Err(refused());
            }
            let directory = File::from(
                rustix::fs::open(
                    &self.inner.state_dir,
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::DIRECTORY
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .map_err(io_error)?,
            );
            let lock = File::from(
                rustix::fs::openat(
                    &directory,
                    ".ordinary-create-uploader.lock",
                    rustix::fs::OFlags::CREATE
                        | rustix::fs::OFlags::RDWR
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
                )
                .map_err(io_error)?,
            );
            use std::os::unix::fs::MetadataExt;
            let metadata = lock.metadata().map_err(io_error)?;
            if !metadata.is_file()
                || metadata.nlink() != 1
                || metadata.uid() != directory.metadata().map_err(io_error)?.uid()
                || metadata.mode() & 0o077 != 0
            {
                return Err(refused());
            }
            rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
                .map_err(io_error)?;
            // Recovery is scoped lazily on first watch, after this sole-owner lock.
            let shared = Arc::new(Shared {
                engine: self.clone(),
                stopping: AtomicBool::new(false),
                token: OperationCancellation::new(),
                scopes: Mutex::new(Vec::new()),
                preparing: Mutex::new(Vec::new()),
                wake: Condvar::new(),
                signal: Mutex::new(WakeSignal::default()),
                hooks,
            });
            let mut owner = CreateUploadOwner {
                shared: shared.clone(),
                workers: Vec::new(),
                _lock: lock,
                _directory: directory,
            };
            // One coordinator-free receiver per worker; a bounded four-row
            // SQL window lets each see past other workers' preparation leases.
            // The durable one-use claim still follows full preparation/proof.
            for index in 0..CREATE_WORKERS {
                let engine = self.clone();
                let shared = shared.clone();
                owner.workers.push(
                    thread::Builder::new()
                        .name(format!("raiun-create-{index}"))
                        .spawn(move || run(engine, shared))
                        .map_err(io_error)?,
                );
            }
            Ok(owner)
        }
    }
    fn run(engine: Engine, shared: Arc<Shared>) {
        // Lease-release wakes may make other receipts available, but must not
        // repeatedly retry an unchanged Ready refusal (e.g. offline/pause).
        // Only a real scope wake or bounded fallback starts a new retry epoch.
        let mut deferred = Vec::new();
        let mut admission_generation = 0;
        let mut retry_at = Instant::now() + Duration::from_secs(1);
        loop {
            if shared.stopping.load(Ordering::Acquire) {
                return;
            }
            if Instant::now() >= retry_at {
                deferred.clear();
                retry_at = Instant::now() + Duration::from_secs(1);
            }
            // Capture before discovery: a notification between SQL discovery
            // and waiting is a stored event, even if nobody was asleep yet.
            let generation = match shared.signal.lock() {
                Ok(signal) => {
                    if signal.admission_generation != admission_generation {
                        deferred.clear();
                        admission_generation = signal.admission_generation;
                    }
                    signal.generation
                }
                Err(_) => return,
            };
            let scopes = match shared.scopes.lock() {
                Ok(scopes) => scopes.clone(),
                Err(_) => return,
            };
            let mut did_work = false;
            for scope in scopes {
                if shared.stopping.load(Ordering::Acquire)
                    || engine.inner.sync_paused.load(Ordering::Acquire)
                    || !(shared.hooks.is_current)()
                {
                    break;
                }
                let Ok(cache) = engine.create_cache(&scope) else {
                    continue;
                };
                if !(shared.hooks.dispatch_allowed)(&scope) {
                    continue;
                }
                // Snapshot only selector hints; release the preparation mutex
                // before cache SQL. A released lease's stored generation wake
                // still makes its Ready row available to the next discovery.
                let preparing = match shared.preparing.lock() {
                    Ok(active) => {
                        if active.len() > CREATE_WORKERS {
                            return;
                        }
                        active
                            .iter()
                            .filter(|(active_scope, _)| active_scope == &scope)
                            .map(|(_, id)| *id)
                            .collect::<Vec<_>>()
                    }
                    Err(_) => return,
                };
                let Ok((observed_ids, ready)) = cache.ready_ordinary_create_discovery(
                    &scope,
                    READY_DISCOVERY_LIMIT,
                    &preparing,
                ) else {
                    continue;
                };
                // Each worker retains at most four discovered IDs per watched
                // scope (4 * 256 = 1024); completed/blocked rows cannot accumulate.
                deferred.retain(|(deferred_scope, id)| {
                    deferred_scope != &scope || observed_ids.contains(id)
                });
                for receipt in ready {
                    if shared.stopping.load(Ordering::Acquire) {
                        return;
                    }
                    if deferred.iter().any(|(deferred_scope, id)| {
                        deferred_scope == &scope && *id == receipt.write.id
                    }) {
                        continue;
                    }
                    let _preparation =
                        match PreparationLease::acquire(&shared, &scope, receipt.write.id) {
                            Ok(Some(lease)) => lease,
                            Ok(None) => continue,
                            Err(_) => return,
                        };
                    // Discovery can have raced with another worker completing
                    // this row. Recheck before copying/hashing the whole body.
                    let receipt = match cache.ordinary_create_for_write(&scope, receipt.write.id) {
                        Ok(Some(current))
                            if current.state == OrdinaryCreateState::Ready
                                && current.has_same_immutable_binding(&receipt) =>
                        {
                            current
                        }
                        _ => {
                            deferred.push((scope.clone(), receipt.write.id));
                            continue;
                        }
                    };
                    match engine.deliver_create(&scope, &receipt, &shared.token, &|| {
                        !shared.stopping.load(Ordering::Acquire)
                            && (shared.hooks.is_current)()
                            && (shared.hooks.dispatch_allowed)(&scope)
                    }) {
                        Ok(true) => did_work = true,
                        Ok(false) => deferred.push((scope.clone(), receipt.write.id)),
                        Err(error)
                            if !shared.stopping.load(Ordering::Acquire)
                                && (shared.hooks.is_current)()
                                && !engine.inner.sync_paused.load(Ordering::Acquire)
                                && error.kind != ErrorKind::Offline =>
                        {
                            // Definitely pre-claim validation/storage failures
                            // require attention. A stale claim cannot be reset
                            // by this Ready-only CAS.
                            deferred.push((scope.clone(), receipt.write.id));
                            let _ = cache.block_ordinary_create(&scope, &receipt);
                        }
                        Err(_) => deferred.push((scope.clone(), receipt.write.id)),
                    }
                }
            }
            if did_work {
                // Drain Ready work without the previous fixed 10ms gap.
                continue;
            }
            let Ok(signal) = shared.signal.lock() else {
                return;
            };
            let Ok((signal, timeout)) = shared.wake.wait_timeout_while(
                signal,
                retry_at.saturating_duration_since(Instant::now()),
                |signal| {
                    signal.generation == generation && !shared.stopping.load(Ordering::Acquire)
                },
            ) else {
                return;
            };
            drop(signal);
            if timeout.timed_out() {
                deferred.clear();
                retry_at = Instant::now() + Duration::from_secs(1);
            }
        }
    }
    impl Engine {
        fn deliver_create(
            &self,
            scope: &CacheScope,
            receipt: &OrdinaryCreateReceipt,
            token: &OperationCancellation,
            check: &dyn Fn() -> bool,
        ) -> Result<bool, CloudError> {
            if self.inner.sync_paused.load(Ordering::Acquire) {
                return Ok(false);
            }
            let cache = self.create_cache(scope)?;
            current(check)?;
            let mut source = NamedTempFile::new_in(self.cache_dir()).map_err(io_error)?;
            cache
                .copy_ready_ordinary_create_snapshot_cancellable(
                    scope,
                    receipt,
                    source.as_file_mut(),
                    || token.is_cancelled() || !check(),
                )
                .map_err(cache_cloud_error)?;
            // Fully validated disposable snapshot only. The synced immutable
            // cache body and journal retain crash custody until completion;
            // no receipt/recovery state ever depends on this temp surviving.
            // Remember pause refusal independently of its present value: a
            // fast resume must not turn an unclaimed paused job into Conflict.
            let paused_seen = std::cell::Cell::new(false);
            let preclaim_check = || {
                if self.inner.sync_paused.load(Ordering::Acquire) {
                    paused_seen.set(true);
                    false
                } else {
                    check()
                }
            };
            // The backend's fresh upload proof is independently validated here
            // before the one-use Ready CAS. This avoids a second HTTP proof,
            // without lending an admission proof to a later body operation.
            let callback_called = std::cell::Cell::new(false);
            let callback_repeated = std::cell::Cell::new(false);
            let claimed = std::cell::RefCell::new(None);
            let transfer = std::cell::Cell::new(None);
            let stage = std::cell::Cell::new("Preparing upload");
            let upload = self.backend.upload_new_in_root_with_preflight(
                scope.space_id(),
                &receipt.write.logical_path,
                source.path(),
                scope.root_resource_id(),
                &receipt.write.parent_resource_id,
                token,
                &preclaim_check,
                &|observation| {
                    if callback_called.replace(true) {
                        callback_repeated.set(true);
                        return Err(refused());
                    }
                    if token.is_cancelled() {
                        return Err(refused());
                    }
                    let proof = self.validate_create_observation(
                        scope.space_id(),
                        Some(scope),
                        &receipt.write.logical_path,
                        Some(&receipt.write.parent_resource_id),
                        &preclaim_check,
                        true,
                        observation,
                    );
                    if paused_seen.get() || self.inner.sync_paused.load(Ordering::Acquire) {
                        return Ok(false);
                    }
                    proof?;
                    current(&preclaim_check)?;
                    if token.is_cancelled() {
                        return Err(refused());
                    }
                    let Some(claim) = cache
                        .claim_ordinary_create(scope, receipt)
                        .map_err(cache_cloud_error)?
                    else {
                        return Ok(false);
                    };
                    // Save ownership before any fallible post-claim work. All
                    // subsequent errors become Uncertain, never Ready/replay.
                    *claimed.borrow_mut() = Some(claim);
                    current(&|| {
                        !token.is_cancelled()
                            && check()
                            && !self.inner.sync_paused.load(Ordering::Acquire)
                    })?;
                    {
                        let _metadata = self.metadata_publication()?;
                        cache
                            .invalidate_paths(scope, &[&receipt.write.logical_path])
                            .map_err(cache_cloud_error)?;
                    }
                    transfer.set(Some(self.begin_transfer(
                        None,
                        scope.space_id(),
                        &receipt.write.logical_path,
                        "upload",
                    )?));
                    stage.set("Sending file");
                    Ok(true)
                },
            );
            // Even a backend that swallowed a repeated callback refusal cannot
            // turn that contract violation into successful local completion.
            let upload = if callback_repeated.get() {
                Err(refused())
            } else {
                upload
            };
            let Some(claim) = claimed.into_inner() else {
                if !callback_repeated.get()
                    && (paused_seen.get() || self.inner.sync_paused.load(Ordering::Acquire))
                {
                    return Ok(false);
                }
                return match upload {
                    Ok(None) if callback_called.get() => Ok(false),
                    Ok(_) => Err(refused()),
                    Err(error) => Err(error),
                };
            };
            let mut completed = false;
            let outcome = (|| {
                let uploaded = upload?.ok_or_else(refused)?;
                if uploaded.id.is_empty()
                    || uploaded.directory
                    || uploaded.encrypted
                    || !uploaded.writable
                    || uploaded.path != receipt.write.logical_path
                    || uploaded.size != receipt.byte_len
                    || !strong(&uploaded.etag)
                {
                    return Err(refused());
                }
                current(&|| check() && !self.inner.sync_paused.load(Ordering::Acquire))?;
                let server_confirmed = self.backend.server_confirms_new_upload();
                let verified = if server_confirmed {
                    // Only this invocation's successful owned upload can use
                    // server confirmation. Saved uncertain/conflict checks
                    // retain independent conditional full-body verification.
                    uploaded.clone()
                } else {
                    stage.set("Verifying uploaded file");
                    match self.backend.verify_download_in_root_with_cancellation(
                        scope.space_id(),
                        &receipt.write.logical_path,
                        &uploaded,
                        &receipt.sha256,
                        scope.root_resource_id(),
                        token,
                    ) {
                        Ok(Some(verified)) => verified,
                        Ok(None) => {
                            // Backends without full streaming verification retain
                            // exact conditional readback into a disposable snapshot.
                            let download =
                                NamedTempFile::new_in(self.cache_dir()).map_err(io_error)?;
                            let verified = self.backend.download_in_root_with_cancellation(
                                scope.space_id(),
                                &receipt.write.logical_path,
                                Some(&uploaded.etag),
                                download.path(),
                                scope.root_resource_id(),
                                token,
                            )?;
                            if hash_cancelled(download.path(), token)? != receipt.sha256
                                || fs::metadata(download.path()).map_err(io_error)?.len()
                                    != receipt.byte_len
                            {
                                return Err(refused());
                            }
                            verified
                        }
                        Err(error) => return Err(error),
                    }
                };
                if verified.id != uploaded.id
                    || verified.etag != uploaded.etag
                    || verified.path != uploaded.path
                    || verified.size != receipt.byte_len
                    || verified.directory
                    || verified.encrypted
                    || !verified.writable
                {
                    return Err(refused());
                }
                current(&|| check() && !self.inner.sync_paused.load(Ordering::Acquire))?;
                if token.is_cancelled() {
                    return Err(refused());
                }
                stage.set("Confirming upload destination");
                self.prove_create_parent(
                    scope,
                    &receipt.write.logical_path,
                    Some(&receipt.write.parent_resource_id),
                    &|| {
                        !token.is_cancelled()
                            && check()
                            && !self.inner.sync_paused.load(Ordering::Acquire)
                    },
                    false,
                )?;
                current(&|| {
                    !token.is_cancelled()
                        && check()
                        && !self.inner.sync_paused.load(Ordering::Acquire)
                })?;
                if server_confirmed {
                    cache.complete_server_confirmed_ordinary_create(scope, &claim, &verified)
                } else {
                    cache.complete_ordinary_create(scope, &claim, &verified, &receipt.sha256)
                }
                .map_err(cache_cloud_error)?;
                completed = true;
                Ok(())
            })();
            let failure_message = outcome
                .as_ref()
                .err()
                .map(|error: &CloudError| format!("{}: {}", stage.get(), error.message));
            let progress = if let Some(id) = transfer.get() {
                self.finish_transfer(
                    id,
                    if completed { "completed" } else { "failed" },
                    if completed { receipt.byte_len } else { 0 },
                    failure_message.as_deref(),
                )
            } else {
                Ok(())
            };
            if outcome.is_err() && !completed {
                cache
                    .mark_ordinary_create_uncertain(scope, claim)
                    .map_err(cache_cloud_error)?;
            }
            progress?;
            Ok(true)
        }
    }
    fn hash_cancelled(path: &Path, token: &OperationCancellation) -> Result<String, CloudError> {
        let mut file = File::open(path).map_err(io_error)?;
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        loop {
            if token.is_cancelled() {
                return Err(refused());
            }
            let count = file.read(&mut buffer).map_err(io_error)?;
            if count == 0 {
                break;
            }
            hash.update(&buffer[..count]);
        }
        Ok(format!("{:x}", hash.finalize()))
    }
    fn strong(etag: &str) -> bool {
        etag.len() >= 2
            && etag.starts_with('"')
            && etag.ends_with('"')
            && !etag.contains(['\r', '\n'])
    }
}
#[cfg(unix)]
pub use owner::{CreateUploadHandle, CreateUploadOwner};
