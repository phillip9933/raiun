//! Explicit continuation of a verified create as a new conditional edit.
//! The historical create is never replayed and never grants native authority.
use super::*;
use crate::streamed_store::namespace_file_store::StoredFileJoin;
use crate::{InitialEditReceipt, PreparedEditRecovery, VerifiedEditReadback};

pub(crate) struct ContinuationAdmission {
    admission: Admission,
    original: StoredFileJoin,
    report: NamespaceDestinationReport,
    binding: PlaceholderEditBinding,
}

pub(crate) fn admit_continuation(
    backend: &Arc<OpenCloudPlaceholderBackend>,
    admission: Admission,
    join: &StoredFileJoin,
    report: &NamespaceDestinationReport,
) -> Result<ContinuationAdmission, BackendError> {
    admission.check(backend)?;
    join.intent()
        .validate()
        .map_err(|_| BackendError::Unavailable)?;
    let NamespaceOperation::CreateFile {
        destination,
        content,
    } = &join.intent().operation
    else {
        return Err(BackendError::Unavailable);
    };
    let progress = join.progress();
    if progress.remote != crate::namespace_intent::NamespacePhase::Verified
        || progress.attention.is_some()
        || progress.recorded_complete
        || report.destination != *destination
        || report.content.as_ref() != Some(content)
        || report.remote.byte_len != content.byte_len
        || destination.parent.scope != admission.parent.scope
        || destination.parent.local_components != admission.parent_components
        || destination.parent.remote.resource_id != admission.parent.remote.resource_id
        || !namespace::strong(&report.remote.etag)
        || !valid_remote_id(&report.remote.resource_id)
        || report.remote.resource_id == admission.parent.remote.resource_id
        || report.remote.resource_id == admission.parent.scope.root_resource_id
    {
        return Err(BackendError::Unavailable);
    }
    let scope = &admission.parent.scope;
    let binding = PlaceholderEditBinding {
        profile_id: scope.profile_id.clone(),
        server_origin: scope.server_origin.clone(),
        account_subject: scope.account_subject.clone(),
        account_generation: admission.auth.token_generation,
        space_id: scope.space_id.clone(),
        root_resource_id: scope.root_resource_id.clone(),
        remote_resource_id: report.remote.resource_id.clone(),
        virtual_path: admission.child_path(&destination.name)?,
        base_etag: report.remote.etag.clone(),
        base_size: report.remote.byte_len,
    };
    let result = ContinuationAdmission {
        admission,
        original: join.clone(),
        report: report.clone(),
        binding,
    };
    Ok(result)
}

impl ContinuationAdmission {
    pub(crate) fn binding(&self) -> &PlaceholderEditBinding {
        &self.binding
    }
    pub(crate) fn identity(&self) -> [u8; 16] {
        *binding_identity(
            &self.admission.catalog_scope,
            "file",
            &[
                &self.binding.space_id,
                &self.binding.root_resource_id,
                &self.binding.virtual_path,
                &self.binding.remote_resource_id,
            ],
        )
        .as_bytes()
    }
    pub(crate) fn check(
        &self,
        backend: &Arc<OpenCloudPlaceholderBackend>,
    ) -> Result<(), BackendError> {
        self.admission.check(backend)
    }
    fn refresh_baseline(
        &self,
        backend: &Arc<OpenCloudPlaceholderBackend>,
    ) -> Result<(), BackendError> {
        self.admission.qualify_target(backend)?;
        let request = self.admission.job.cancellation().bounded_request();
        let entry = backend
            .client
            .stat_with_context(
                &self.binding.space_id,
                &self.binding.virtual_path,
                RangeReadContext {
                    deadline: request.deadline(),
                    token_generation: self.admission.auth.token_generation,
                },
            )
            .map_err(|error| backend.reject_cached_cloud_error(error))?;
        self.check(backend)?;
        if entry.path != self.binding.virtual_path
            || entry.id != self.report.remote.resource_id
            || entry.etag != self.report.remote.etag
            || entry.size != self.report.remote.byte_len
            || entry.directory
            || entry.encrypted
            || !entry.writable
            || !namespace::strong(&entry.etag)
        {
            return Err(BackendError::Unavailable);
        }
        self.admission.qualify_target(backend)
    }
    pub(crate) fn dispatch(
        &self,
        backend: &Arc<OpenCloudPlaceholderBackend>,
        receipt: InitialEditReceipt,
        recovery: &dyn PreparedEditRecovery,
    ) -> Result<VerifiedEditReadback, BackendError> {
        self.refresh_baseline(backend)?;
        let metadata = receipt.metadata();
        if metadata.scope != self.admission.parent.scope
            || metadata.local_file != self.report.destination.local_file
            || metadata.relative_path != self.binding.virtual_path.trim_start_matches('/')
            || metadata.generation != self.admission.auth.token_generation
            || metadata.remote.as_ref() != Some(&self.report.remote)
            || recovery.provider_scope() != backend.scope()
            || recovery.root_identity() != self.admission.catalog_scope.local_root()
        {
            return Err(BackendError::Unavailable);
        }
        let key = (metadata.record_id.clone(), metadata.generation);
        let proof = backend.with_initial_edit_session_for_job(
            &self.admission.parent.scope,
            Some(&self.admission.job),
            |session| {
                recovery
                    .dispatch_initial_receipt_verified(receipt, session.remote())
                    .map_err(|_| BackendError::Unavailable)
                    .and_then(|(outcome, proof)| {
                        if !matches!(
                            outcome,
                            crate::ReconciliationOutcome::VerifiedApplied { .. }
                        ) {
                            return Err(BackendError::Unavailable);
                        }
                        proof.ok_or(BackendError::Unavailable)
                    })
            },
        )??;
        self.check_proof(backend, &proof)?;
        if proof.metadata().record_id != key.0 || proof.metadata().generation != key.1 {
            return Err(BackendError::Unavailable);
        }
        Ok(proof)
    }
    /// Explicitly reverify a selected protected successor. Existing recovery
    /// retains its conditional-write and already-applied verification rules;
    /// acknowledged records take a strictly read-only full remote hash path.
    pub(crate) fn resume(
        &self,
        backend: &Arc<OpenCloudPlaceholderBackend>,
        recovery: &dyn PreparedEditRecovery,
        store: &Arc<crate::streamed_store::SnapshotStore>,
        key: &crate::streamed_store::StreamedRecordKey,
        state: crate::streamed_store::StreamedAttemptState,
    ) -> Result<VerifiedEditReadback, BackendError> {
        self.admission.qualify_target(backend)?;
        let pin = store
            .open_verified_key(key, &mut || self.admission.job.is_stopped())
            .map_err(|_| BackendError::Unavailable)?;
        let binding = pin.manifest().binding();
        if binding.scope != self.admission.parent.scope
            || binding.local_file != self.report.destination.local_file
            || binding.remote.as_ref() != Some(&self.report.remote)
            || binding.relative_path != self.binding.virtual_path.trim_start_matches('/')
            || key.generation() != self.admission.auth.token_generation
            || recovery.provider_scope() != backend.scope()
            || recovery.root_identity() != self.admission.catalog_scope.local_root()
        {
            return Err(BackendError::Unavailable);
        }
        drop(pin);
        let proof = backend.with_initial_edit_session_for_job(
            &self.admission.parent.scope,
            Some(&self.admission.job),
            |session| {
                if matches!(
                    state,
                    crate::streamed_store::StreamedAttemptState::LocallyAcknowledged { .. }
                ) {
                    let remote = session
                        .remote()
                        .streamed_remote_for_job(&self.admission.job)
                        .ok_or(BackendError::Unavailable)?;
                    let job = self.admission.job.clone();
                    let proof = crate::streamed_reconcile::verify_acknowledged_streamed_edit(
                        store,
                        key,
                        remote.as_ref(),
                        Arc::new(move || job.is_stopped()),
                    )
                    .map_err(|_| BackendError::Unavailable)?;
                    crate::VerifiedEditReadback::from_streamed(proof)
                        .map(|proof| proof.with_recovery_job(self.admission.job.clone()))
                        .map_err(|_| BackendError::Unavailable)
                } else {
                    let (outcome, proof) = recovery
                        .dispatch_recovered_edit_verified(
                            key.record_id(),
                            key.generation(),
                            session.remote(),
                            crate::ExplicitRecoveryApproval::user_reviewed(),
                        )
                        .map_err(|_| BackendError::Unavailable)?;
                    if !matches!(
                        outcome,
                        crate::ReconciliationOutcome::VerifiedApplied { .. }
                    ) {
                        return Err(BackendError::Unavailable);
                    }
                    proof.ok_or(BackendError::Unavailable)
                }
            },
        )??;
        self.check_proof(backend, &proof)?;
        if proof.metadata().record_id != key.record_id()
            || proof.metadata().generation != key.generation()
        {
            return Err(BackendError::Unavailable);
        }
        Ok(proof)
    }
    fn check_proof(
        &self,
        backend: &Arc<OpenCloudPlaceholderBackend>,
        proof: &VerifiedEditReadback,
    ) -> Result<(), BackendError> {
        self.check(backend)?;
        let metadata = proof.metadata();
        let version = proof.remote_version();
        if !proof.is_streamed()
            || metadata.scope != self.admission.parent.scope
            || metadata.local_file != self.report.destination.local_file
            || metadata.relative_path != self.binding.virtual_path.trim_start_matches('/')
            || metadata.remote.as_ref() != Some(&self.report.remote)
            || metadata.generation != self.admission.auth.token_generation
            || metadata.record_id == self.original.snapshot_id()
            || metadata.content_len != version.size
            || version.resource_id != self.report.remote.resource_id
            || !namespace::strong(&version.etag)
            || version.is_directory
            || version.encrypted
            || !version.writable
            || proof.recovery_job().is_none_or(|job| job.is_stopped())
        {
            return Err(BackendError::Unavailable);
        }
        Ok(())
    }
    /// All HTTP and protected-body dispatch have finished. Publish only the
    /// verified successor baseline under the original account/token fence.
    pub(crate) fn publish_and_complete<T>(
        &self,
        backend: &Arc<OpenCloudPlaceholderBackend>,
        proof: &VerifiedEditReadback,
        complete: impl FnOnce(&[u8; 16]) -> Result<T, crate::Error>,
    ) -> Result<T, crate::Error> {
        let unavailable = || crate::Error::EditRecoveryUnavailable;
        self.check_proof(backend, proof)
            .map_err(|_| unavailable())?;
        let scope = &self.admission.parent.scope;
        let identity = binding_identity(
            &self.admission.catalog_scope,
            "file",
            &[
                &scope.space_id,
                &scope.root_resource_id,
                &self.binding.virtual_path,
                &self.report.remote.resource_id,
            ],
        );
        let version = proof.remote_version();
        let binding = FileBinding {
            space_id: scope.space_id.clone(),
            root_resource_id: scope.root_resource_id.clone(),
            path: self.binding.virtual_path.clone(),
            remote_id: version.resource_id.clone(),
            etag: version.etag.clone(),
            size: version.size,
        };
        let _permit = backend
            .begin_scoped_publish(self.admission.job.cancellation())
            .map_err(|_| unavailable())?;
        self.check_proof(backend, proof)
            .map_err(|_| unavailable())?;
        let mut state = backend.state.try_lock().map_err(|_| unavailable())?;
        let composite = composite_root_identity(
            &backend.scope,
            self.admission.catalog_scope.personal_space_id(),
            self.admission.catalog_scope.personal_root_resource_id(),
        );
        let root_current = matches!(state.namespace_directories.get(&composite),
            Some(NamespaceDirectory::Root {account_id,personal_space_id,personal_root_id})
            if account_id == backend.scope.account_id()
                && personal_space_id == self.admission.catalog_scope.personal_space_id()
                && personal_root_id == self.admission.catalog_scope.personal_root_resource_id());
        let parent_current = state
            .directories
            .get(&self.admission.parent.identity)
            .is_some_and(|parent| {
                parent.space_id == scope.space_id
                    && parent.root_resource_id == scope.root_resource_id
                    && parent.path == self.admission.parent.path
                    && parent.remote_id == self.admission.parent.remote.resource_id
            });
        if !root_current
            || !parent_current
            || binding_count(&state) >= MAX_IDENTITY_CATALOG_ENTRIES
            || state.directories.contains_key(&identity)
            || state.namespace_directories.contains_key(&identity)
            || state.files.iter().any(|(key, prior)| {
                (*key == identity
                    || (prior.space_id == binding.space_id
                        && prior.root_resource_id == binding.root_resource_id
                        && prior.path == binding.path))
                    && (*key != identity
                        || prior.remote_id != binding.remote_id
                        || prior.path != binding.path
                        || prior.space_id != binding.space_id
                        || prior.root_resource_id != binding.root_resource_id
                        || !((prior.etag == self.report.remote.etag
                            && prior.size == self.report.remote.byte_len)
                            || prior == &binding))
            })
        {
            return Err(unavailable());
        }
        backend
            .upsert_identity_binding(
                &self.admission.catalog_scope,
                &ProviderIdentityBinding::File {
                    identity: *identity.as_bytes(),
                    space_id: binding.space_id.clone(),
                    root_resource_id: binding.root_resource_id.clone(),
                    path: binding.path.clone(),
                    remote_id: binding.remote_id.clone(),
                    etag: binding.etag.clone(),
                    size: binding.size,
                },
            )
            .map_err(|_| unavailable())?;
        state.files.insert(identity, binding);
        let result = complete(identity.as_bytes())?;
        self.check_proof(backend, proof)
            .map_err(|_| unavailable())?;
        Ok(result)
    }
}
