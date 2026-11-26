//! One live native completion seal for an already remote-verified ordinary
//! create followed by a conditional edit. Never deserialized or reopened.
use super::*;

pub(crate) struct NativeFileCreateContinuation<'a> {
    _reference: &'a SourceReference<'a>,
    store: Arc<SnapshotStore>,
    original_join: StoredFileJoin,
    original_report: crate::namespace_intent::NamespaceDestinationReport,
    new_edit_key: StreamedRecordKey,
    new_binding: SnapshotBinding,
    local_file: LocalFileIdentity,
    native_usn: i64,
    body_sha256: [u8; 32],
}
impl NativeFileCreateContinuation<'_> {
    pub(crate) fn matches(
        &self,
        store: &Arc<SnapshotStore>,
        original: &StoredFileJoin,
        report: &crate::namespace_intent::NamespaceDestinationReport,
        new_edit_key: &StreamedRecordKey,
    ) -> bool {
        Arc::ptr_eq(&self.store, store)
            && original.key() == self.original_join.key()
            && original.intent() == self.original_join.intent()
            && original.snapshot_id() == self.original_join.snapshot_id()
            && original.manifest_commitment_sha256()
                == self.original_join.manifest_commitment_sha256()
            && report == &self.original_report
            && new_edit_key == &self.new_edit_key
            && self.new_binding.record_id == new_edit_key.record_id()
            && self.new_binding.generation == new_edit_key.generation()
            && self.new_binding.scope == *new_edit_key.scope()
            && self.new_binding.scope == *original.key().scope()
            && self.new_binding.local_file == self.local_file
            && self.local_file == report.destination.local_file
            && self.new_binding.remote.as_ref() == Some(&report.remote)
            && self.native_usn > 0
    }

    pub(crate) fn new_edit_key(&self) -> &StreamedRecordKey {
        &self.new_edit_key
    }

    pub(crate) fn body_sha256(&self) -> [u8; 32] {
        self.body_sha256
    }

    pub(super) fn seal<'a>(
        reference: &'a SourceReference<'a>,
        body: &ReplacementBody,
        identity: &[u8; 16],
        job: &crate::StreamedRecoveryJob,
        store: Arc<SnapshotStore>,
        original_join: StoredFileJoin,
        original_report: crate::namespace_intent::NamespaceDestinationReport,
        new_edit_key: StreamedRecordKey,
        new_binding: SnapshotBinding,
    ) -> Result<NativeFileCreateContinuation<'a>, Error> {
        validate_converted(reference, body.snapshot, &body.path, identity, true)?;
        hash_source(reference, body.snapshot.file_size, job, &body.digest)?;
        let snapshot = root_snapshot(reference.raw)?;
        let native_usn = completion_usn(reference.raw, snapshot.identity.file_index)?;
        if native_usn <= 0 || job.is_stopped() {
            return Err(Error::EditRecoveryUnavailable);
        }
        let local_file = LocalFileIdentity {
            volume_serial: snapshot.identity.volume_serial,
            file_index: snapshot.identity.file_index,
        };
        let proof = NativeFileCreateContinuation {
            _reference: reference,
            store,
            original_join,
            original_report,
            new_edit_key,
            new_binding,
            local_file,
            native_usn,
            body_sha256: body.digest,
        };
        if !proof.matches(
            &proof.store,
            &proof.original_join,
            &proof.original_report,
            &proof.new_edit_key,
        ) {
            return Err(Error::EditRecoveryUnavailable);
        }
        Ok(proof)
    }
}

impl ConfiguredRootConnection {
    /// The selected historical create carries its own protected body and
    /// exact live file checks below. A dirty-close observation is expected
    /// while that file is held; it cannot waive any of those selected checks.
    fn selected_create_recovery_context(
        &self,
        backend: &Arc<crate::OpenCloudPlaceholderBackend>,
        authorization: CapturedAuthorization,
        job: &crate::StreamedRecoveryJob,
        current: &crate::opencloud::file_create::Current,
    ) -> Result<Arc<dyn PreparedEditRecovery>, Error> {
        let unavailable = || Error::EditRecoveryUnavailable;
        let erased: Arc<dyn PlaceholderBackend> = backend.clone();
        if !self.connected
            || self.state.readiness.load(Ordering::Acquire) != CALLBACK_READY
            || backend.is_revoked()
            || !Arc::ptr_eq(&erased, &self.state.backend)
            || !backend.owns_composite_root_identity(self.composite_root_identity)
            || authorization.agent_generation == 0
            || authorization.token_generation == 0
            || authorization.token_generation != backend.scope().token_generation()
            || job.is_stopped()
            || !current(authorization)
        {
            return Err(unavailable());
        }
        let root = self.root.as_ref().ok_or_else(unavailable)?;
        root.verify_identity(true)?;
        root.verify_registered()?;
        let physical = crate::ConfiguredRootIdentity {
            volume_serial: root.identity.volume_serial,
            file_index: root.identity.file_index,
        };
        let recovery = self.state.recovery.as_ref().ok_or_else(unavailable)?;
        if recovery.provider_scope() != backend.scope() || recovery.root_identity() != physical {
            return Err(unavailable());
        }
        Ok(Arc::clone(recovery))
    }

    /// Explicit owner action for one historical RemoteVerified create. The
    /// create request is never dispatched again: current bytes become a new
    /// conditional edit against its verified remote resource and strong tag.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn continue_personal_file_create(
        &self,
        backend: &Arc<crate::OpenCloudPlaceholderBackend>,
        parent_components: &[&str],
        name: &str,
        record_id: &str,
        record_generation: u64,
        authorization: CapturedAuthorization,
        job: &crate::StreamedRecoveryJob,
        current: crate::opencloud::file_create::Current,
    ) -> Result<crate::FileCreateContinuationOutcome, Error> {
        let phase = std::cell::Cell::new(crate::FileCreateContinuationStage::Context);
        let result = (|| {
            let no = || Error::EditRecoveryUnavailable;
            if !self.connected
                || self.state.readiness.load(Ordering::Acquire) != CALLBACK_READY
                || record_generation == 0
                || record_id.is_empty()
                || job.is_stopped()
                || !current(authorization)
                || crate::personal_create_relative(parent_components, name).is_none()
            {
                return Err(no());
            }
            let root = self.root.as_ref().ok_or_else(no)?;
            root.verify_identity(true)?;
            root.verify_registered()?;
            let physical = crate::ConfiguredRootIdentity {
                volume_serial: root.identity.volume_serial,
                file_index: root.identity.file_index,
            };
            let recovery =
                self.selected_create_recovery_context(backend, authorization, job, &current)?;
            let admission = backend
                .admit_file_create(
                    parent_components,
                    physical,
                    authorization,
                    job,
                    current.clone(),
                )
                .map_err(|_| no())?;
            phase.set(crate::FileCreateContinuationStage::History);
            let rename = self
                .file_rename_store(backend, &admission.parent.scope, authorization)?
                .ok_or_else(no)?;
            let store = FileCreateStore::new(rename.snapshot_store().clone()).map_err(|_| no())?;
            let mut selected = store
                .discover()
                .map_err(|_| no())?
                .into_iter()
                .filter(|row| {
                    row.snapshot_id() == record_id && row.key().generation() == record_generation
                });
            let original = selected.next().ok_or_else(no)?;
            if selected.next().is_some() || original.key().scope() != &admission.parent.scope {
                return Err(no());
            }
            let mut initial_lease = store.acquire_dispatch(original.key()).map_err(|_| no())?;
            let report = initial_lease
                .remote_verified_report()
                .ok_or_else(no)?
                .clone();
            if initial_lease.record().key() != original.key()
                || initial_lease.record().intent() != original.intent()
                || initial_lease.record().manifest_commitment_sha256()
                    != original.manifest_commitment_sha256()
            {
                return Err(no());
            }
            if report.destination.name != name
                || report.destination.parent.local_components.len() != parent_components.len()
                || !report
                    .destination
                    .parent
                    .local_components
                    .iter()
                    .zip(parent_components)
                    .all(|(stored, supplied)| stored == supplied)
            {
                return Err(no());
            }
            let parent_route = admission.parent.route.clone();
            let parent_identity = admission.parent.identity;
            let local = report.destination.local_file;
            if local.volume_serial != physical.volume_serial || local.file_index == 0 {
                return Err(no());
            }
            // An original zero-PUT native acknowledgement cannot be superseded
            // by this conditional-successor path. Refuse before any capture,
            // staging or PUT; retain the historical join for explicit review.
            if initial_lease
                .has_acknowledged_original()
                .map_err(|_| no())?
            {
                return Ok(crate::FileCreateContinuationOutcome::HistoricalReviewRequired);
            }
            let (parent, parent_snapshot, ancestors) =
                native_namespace_directory::pin_namespace_parent(
                    root,
                    &parent_route,
                    parent_identity,
                    parent_components,
                    FILE_READ_ATTRIBUTES,
                )?;
            if parent_snapshot.identity.volume_serial
                != report.destination.parent.local_file.volume_serial
                || parent_snapshot.identity.file_index
                    != report.destination.parent.local_file.file_index
            {
                return Err(no());
            }
            let path = final_path_for_handle(parent.0)
                .map_err(|_| Error::ConfiguredRootChanged)?
                .join(name);
            if initial_lease.has_superseded_original().map_err(|_| no())? {
                phase.set(crate::FileCreateContinuationStage::Custody);
                root.verify_identity(true)?;
                root.verify_registered()?;
                if job.is_stopped() || !current(authorization) {
                    return Err(no());
                }
                initial_lease
                    .finish_superseded_existing()
                    .map_err(|_| no())?;
                return Ok(crate::FileCreateContinuationOutcome::HistoricalLinkCompleted);
            }
            let candidate = initial_lease.continuation_candidate().map_err(|_| no())?;
            drop(initial_lease); // No record/state lock spans HTTP.
            if candidate.is_none() {
                let verified = store
                    .open_joined(original.key(), &mut || job.is_stopped())
                    .map_err(|_| no())?;
                verified.verify_pin().map_err(|_| no())?;
                if verified.record().key() != original.key() {
                    return Err(no());
                }
            }
            let continuation = crate::opencloud::file_create::continuation::admit_continuation(
                backend, admission, &original, &report,
            )
            .map_err(|_| no())?;
            let stopped = || job.is_stopped() || !current(authorization) || backend.is_revoked();
            phase.set(crate::FileCreateContinuationStage::Capture);
            let (body, new_key, new_binding, proof, already_acknowledged) =
                if let Some((key, state)) = candidate {
                    let pin = store
                        .snapshot_store()
                        .open_verified_key(&key, &mut || stopped())
                        .map_err(|_| no())?;
                    let binding = pin.manifest().binding().clone();
                    let expected_sha = *pin.manifest().content_sha256();
                    if binding.local_file != local
                        || binding.remote.as_ref() != Some(&report.remote)
                        || key.scope() != original.key().scope()
                    {
                        return Err(no());
                    }
                    let (body, ()) = ReplacementBody::capture_continuation_with_usn(
                        &path,
                        physical.volume_serial,
                        local.file_index,
                        continuation.identity(),
                        job,
                        &stopped,
                        |reader, snapshot, _usn| {
                            if snapshot.file_size != binding.content_len {
                                return Err(no());
                            }
                            io::copy(reader, &mut io::sink()).map_err(|_| no())?;
                            Ok(())
                        },
                    )?;
                    if body.sha256() != expected_sha {
                        return Err(no());
                    }
                    pin.verify_pin().map_err(|_| no())?;
                    drop(pin);
                    body.check(job, &stopped)?;
                    phase.set(crate::FileCreateContinuationStage::Remote);
                    let proof = continuation
                        .resume(
                            backend,
                            recovery.as_ref(),
                            store.snapshot_store(),
                            &key,
                            state,
                        )
                        .map_err(|_| no())?;
                    (
                        body,
                        key,
                        binding,
                        proof,
                        matches!(
                            state,
                            crate::streamed_store::StreamedAttemptState::LocallyAcknowledged { .. }
                        ),
                    )
                } else {
                    let binding = continuation.binding().clone();
                    let relative = binding.virtual_path.trim_start_matches('/').to_owned();
                    let (body, stage) = ReplacementBody::capture_same_file_with_usn(
                        &path,
                        physical.volume_serial,
                        local.file_index,
                        job,
                        &stopped,
                        |reader, snapshot, _usn| {
                            recovery
                                .stage_streamed_edit(
                                    &binding,
                                    physical,
                                    local,
                                    &relative,
                                    snapshot.file_size,
                                    job,
                                    reader,
                                    &mut || stopped(),
                                )
                                .map_err(|_| no())
                        },
                    )?;
                    body.check(job, &stopped)?;
                    let mut receipt = recovery
                        .commit_streamed_edit(stage, &mut || stopped())
                        .map_err(|_| no())?
                        .ok_or_else(no)?;
                    body.check(job, &stopped)?;
                    let (new_id, _) = receipt.record_key();
                    let key = store
                        .snapshot_store()
                        .record_key(new_id)
                        .map_err(|_| no())?;
                    let pin = store
                        .snapshot_store()
                        .open_verified_key(&key, &mut || stopped())
                        .map_err(|_| no())?;
                    let new_binding = pin.manifest().binding().clone();
                    if new_binding.local_file != local
                        || new_binding.content_len != body.len()
                        || pin.manifest().content_sha256() != &body.sha256()
                        || new_binding.remote.as_ref() != Some(&report.remote)
                    {
                        return Err(no());
                    }
                    drop(pin);
                    let bound = job.clone();
                    receipt.link_recovery_revocation(Arc::new(move || bound.is_stopped()));
                    phase.set(crate::FileCreateContinuationStage::Remote);
                    let proof = continuation
                        .dispatch(backend, receipt, recovery.as_ref())
                        .map_err(|_| no())?;
                    (body, key, new_binding, proof, false)
                };
            phase.set(crate::FileCreateContinuationStage::NativePreflight);
            body.check(job, &stopped)?;
            root.verify_identity(true)?;
            root.verify_registered()?;
            let (parent_again, current_parent, _pins) =
                native_namespace_directory::pin_namespace_parent(
                    root,
                    &parent_route,
                    parent_identity,
                    parent_components,
                    FILE_READ_ATTRIBUTES,
                )?;
            if current_parent.identity != parent_snapshot.identity
                || !windows_paths_equal(
                    &final_path_for_handle(parent_again.0)
                        .map_err(|_| no())?
                        .join(name),
                    &path,
                )
            {
                return Err(no());
            }
            let final_reference = body.source.reference()?;
            phase.set(crate::FileCreateContinuationStage::NativePublication);
            let (published_identity, completed) =
                continuation.publish_and_complete(backend, &proof, |identity| {
                    phase.set(crate::FileCreateContinuationStage::NativeCompletion);
                    body.convert_with_phase(
                        identity,
                        job,
                        &stopped,
                        || !stopped(),
                        || {
                            phase.set(crate::FileCreateContinuationStage::NativeVerify);
                        },
                    )?;
                    phase.set(crate::FileCreateContinuationStage::NativePublication);
                    let completed =
                        crate::CompletedLocalEdit::from_verified_native_completion_for_generation(
                            &proof,
                            authorization.token_generation,
                        )
                        .map_err(|_| no())?;
                    Ok((*identity, completed))
                })?;
            phase.set(crate::FileCreateContinuationStage::NativePostPublish);
            continuation.check(backend).map_err(|_| no())?;
            root.verify_identity(true)?;
            root.verify_registered()?;
            if stopped() {
                return Err(no());
            }
            validate_converted(
                &final_reference,
                body.snapshot,
                &body.path,
                &published_identity,
                true,
            )?;
            hash_source(&final_reference, body.len(), job, &body.sha256())?;
            phase.set(crate::FileCreateContinuationStage::Custody);
            if !already_acknowledged {
                recovery
                    .record_local_completion(completed)
                    .map_err(|_| no())?;
            }
            let old_lease = store.acquire_dispatch(original.key()).map_err(|_| no())?;
            phase.set(crate::FileCreateContinuationStage::NativeSeal);
            let seal = NativeFileCreateContinuation::seal(
                &final_reference,
                &body,
                &published_identity,
                job,
                store.snapshot_store().clone(),
                original.clone(),
                report.clone(),
                new_key,
                new_binding,
            )?;
            let mut old_lease = old_lease;
            phase.set(crate::FileCreateContinuationStage::Custody);
            old_lease.record_continued(&seal).map_err(|_| no())?;
            drop(ancestors);
            drop(parent);
            Ok(crate::FileCreateContinuationOutcome::LocallyCompleted)
        })();
        result.map_err(|error| match error {
            Error::EditRecoveryUnavailable => Error::FileCreateContinuation { stage: phase.get() },
            other => other,
        })
    }
}
