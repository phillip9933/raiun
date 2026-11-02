//! Original-delete-owner local-first file disposition. No restored slot, path
//! hint, or elapsed interval can authorize a replacement or remote deletion.
use super::super::native_file_create::ReplacementBody;
use super::*;

pub(super) struct CompletedReplacement {
    pub(super) path: PathBuf,
    pub(super) file: LocalFileIdentity,
    pub(super) identity: [u8; 16],
}

// Same original native body owner survives unresolved post-capture work.
// Deliberately retained like the original unresolved delete Owner; never
// reconstructed, transferred to another worker or used for automatic replay.
struct BodyCustody(Option<ReplacementBody>);
impl std::ops::Deref for BodyCustody {
    type Target = ReplacementBody;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref().expect("live replacement body")
    }
}
impl BodyCustody {
    fn release(mut self) {
        drop(self.0.take());
    }
}
impl Drop for BodyCustody {
    fn drop(&mut self) {
        if let Some(body) = self.0.take() {
            std::mem::forget(body);
        }
    }
}

fn receipt(local: &Local<'_, '_>) -> Result<(), Error> {
    let inner = local
        .shared
        .inner
        .lock()
        .map_err(|_| Error::EditRecoveryUnavailable)?;
    let slot = inner
        .slot
        .as_ref()
        .filter(|slot| slot.ticket.key == local.ticket.key)
        .ok_or(Error::EditRecoveryUnavailable)?;
    if !slot.ack_success || !slot.completed {
        return Err(Error::EditRecoveryUnavailable);
    }
    Ok(())
}

fn context(local: &Local<'_, '_>) -> Result<(), Error> {
    if !local.shared.live(local.ticket)
        || !local.locally_removed
        || !local.admission.borrow().is_current()
    {
        return Err(Error::EditRecoveryUnavailable);
    }
    receipt(local)?;
    local.root.verify_identity(true)?;
    local.root.verify_registered()?;
    let parent = root_snapshot(local.parent.0)?;
    if parent.identity.volume_serial != local.source.local.parent.local_file.volume_serial
        || parent.identity.file_index != local.source.local.parent.local_file.file_index
    {
        return Err(Error::ConfiguredRootChanged);
    }
    for (handle, old) in &local._ancestors {
        let now = root_snapshot(handle.0)?;
        if now.identity != old.identity
            || now.reparse_tag != old.reparse_tag
            || now.file_attributes != old.file_attributes
        {
            return Err(Error::ConfiguredRootChanged);
        }
    }
    if local
        .state
        .unverifiable_placeholder_closes
        .load(Ordering::Acquire)
        != 0
    {
        return Err(Error::EditRecoveryUnavailable);
    }
    Ok(())
}

/// None is fresh actual absence under retained root/parent custody; Some is
/// only the newly observed plain FileID, never a mutation capability.
pub(super) fn classify(local: &Local<'_, '_>) -> Result<Option<LocalFileIdentity>, Error> {
    context(local)?;
    let wide = wide_path(&local.ticket.path)?;
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return if unsafe { GetLastError() } == 2 {
            Ok(None)
        } else {
            Err(win32_io_error("classify owned post-delete entry"))
        };
    }
    let leaf = RawOwnedHandle(raw);
    let now = root_snapshot(leaf.0)?;
    let mut info: ByHandleFileInformation = unsafe { zeroed() };
    if unsafe { GetFileInformationByHandle(leaf.0, &mut info) } == 0
        || info.number_of_links != 1
        || now.identity.volume_serial != local.ticket.key.volume
        || now.identity.file_index == local.ticket.key.file
        || now.identity.file_index == 0
        || now.file_attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || now.placeholder_state != 0
        || now.reparse_tag != 0
        || !windows_paths_equal(
            &final_path_for_handle(leaf.0).map_err(|_| Error::ConfiguredRootChanged)?,
            &local.ticket.path,
        )
    {
        return Err(Error::ConfiguredRootChanged);
    }
    context(local)?;
    Ok(Some(LocalFileIdentity {
        volume_serial: now.identity.volume_serial,
        file_index: now.identity.file_index,
    }))
}

pub(super) fn check_removed(local: &Local<'_, '_>, absent: bool) -> Result<(), Error> {
    context(local)?;
    if absent && classify(local)?.is_some() {
        return Err(Error::ConfiguredRootChanged);
    }
    Ok(())
}

pub(super) fn allow_local_and_wait(
    local: &mut Local<'_, '_>,
    recovery: &Arc<dyn PreparedEditRecovery>,
) -> Result<(), Error> {
    local.check().map_err(|_| Error::EditRecoveryUnavailable)?;
    let leaf = local.leaf.as_ref().ok_or(Error::EditRecoveryUnavailable)?;
    let mut info: ByHandleFileInformation = unsafe { zeroed() };
    if unsafe { GetFileInformationByHandle(leaf.0, &mut info) } == 0 || info.number_of_links != 1 {
        return Err(Error::EditRecoveryUnavailable);
    }
    // Keep the configured body policy's original job/deadline after ACK; the
    // callback's 45s admission budget never becomes a large-body transfer cap.
    let weak = Arc::downgrade(&local.shared.backend);
    let closed = local.shared.closed.clone();
    let original = local.shared.config.current.clone();
    let auth = local.shared.config.authorization;
    let job = recovery
        .begin_streamed_job()
        .ok_or(Error::EditRecoveryUnavailable)?
        .with_revocation_check(Arc::new(move || {
            !original(auth)
                || weak.upgrade().is_none_or(|backend| backend.is_revoked())
                || closed.load(Ordering::Acquire)
        }));
    if !ack_once(local.shared, local.ticket, true) {
        return Err(Error::EditRecoveryUnavailable);
    }
    local.acknowledged = true;
    local
        .ticket
        .post_ack_job
        .set(job)
        .map_err(|_| Error::EditRecoveryUnavailable)?;
    local.leaf.take();
    loop {
        if !local.shared.live(local.ticket) {
            return Err(Error::EditRecoveryUnavailable);
        }
        let mut inner = local
            .shared
            .inner
            .lock()
            .map_err(|_| Error::EditRecoveryUnavailable)?;
        let slot = inner
            .slot
            .as_mut()
            .filter(|slot| slot.ticket.key == local.ticket.key)
            .ok_or(Error::EditRecoveryUnavailable)?;
        if slot.ack_success && slot.completed {
            let closes = std::mem::take(&mut slot.deferred);
            drop(inner);
            if closes
                .into_iter()
                .any(|close| !close.finish_after_owned_completion())
            {
                return Err(Error::EditRecoveryUnavailable);
            }
            local.locally_removed = true;
            return context(local);
        }
        let (guard, _) = local
            .shared
            .changed
            .wait_timeout(inner, Duration::from_millis(20))
            .map_err(|_| Error::EditRecoveryUnavailable)?;
        drop(guard);
    }
}

pub(super) fn replace(
    local: &mut Local<'_, '_>,
    recovery: &Arc<dyn PreparedEditRecovery>,
    expected_new: LocalFileIdentity,
) -> Result<FileDeleteOutcome, Error> {
    context(local)?;
    let scope = local.source.local.parent.scope.clone();
    let (probe, lifetime) = local
        .admission
        .borrow()
        .dispatch_probe(local.state.close_capture_admission.clone())
        .ok_or(Error::EditRecoveryUnavailable)?;
    let observation = lifetime.observation_probe();
    let job = local
        .ticket
        .post_ack_job
        .get()
        .ok_or(Error::EditRecoveryUnavailable)?
        .with_revocation_check(Arc::new(move || !observation()));
    let stopped = || job.is_stopped() || !local.shared.live(local.ticket);
    let binding = crate::PlaceholderEditBinding {
        profile_id: scope.profile_id.clone(),
        server_origin: scope.server_origin.clone(),
        account_subject: scope.account_subject.clone(),
        account_generation: local.shared.config.authorization.token_generation,
        space_id: scope.space_id.clone(),
        root_resource_id: scope.root_resource_id.clone(),
        remote_resource_id: local.source.remote.resource_id.clone(),
        virtual_path: format!(
            "{}/{}",
            local
                .source
                .local
                .parent
                .local_components
                .iter()
                .skip(
                    if local.source.local.parent.local_components[0] == "Spaces" {
                        2
                    } else {
                        1
                    }
                )
                .cloned()
                .collect::<Vec<_>>()
                .join("/"),
            local.source.local.name
        ),
        base_etag: local.source.remote.etag.clone(),
        base_size: local.source.remote.byte_len,
    };
    let relative = binding.virtual_path.trim_start_matches('/').to_owned();
    let (body, stage) = ReplacementBody::capture(
        &local.ticket.path,
        local.ticket.key.volume,
        local.ticket.key.file,
        &job,
        &stopped,
        |reader, snapshot| {
            if snapshot.identity.volume_serial != expected_new.volume_serial
                || snapshot.identity.file_index != expected_new.file_index
            {
                return Err(Error::ConfiguredRootChanged);
            }
            recovery
                .stage_streamed_edit(
                    &binding,
                    local.shared.root,
                    expected_new,
                    &relative,
                    snapshot.file_size,
                    &job,
                    reader,
                    &mut || stopped(),
                )
                .map_err(|_| Error::EditRecoveryUnavailable)
        },
    )?;
    let body = BodyCustody(Some(body));
    context(local)?;
    body.check(&job, &stopped)?;
    let receipt = recovery
        .commit_streamed_edit(stage, &mut || stopped())
        .map_err(|_| Error::EditRecoveryUnavailable)?
        .ok_or(Error::EditRecoveryUnavailable)?;
    body.check(&job, &stopped)?;
    // This is the one owned fresh body, not a recovered record. Other pending
    // content already fenced admission before ACK; no general health bypass.
    if !local.admission.borrow_mut().claim_dispatch() || !lifetime.arm_after_dispatch() {
        return Err(Error::EditRecoveryUnavailable);
    }
    let job = job.with_revocation_check(Arc::new(move || !probe()));
    let mut receipt = receipt;
    let bound = job.clone();
    receipt.link_recovery_revocation(Arc::new(move || bound.is_stopped()));
    let stopped = || job.is_stopped() || !local.shared.live(local.ticket);
    let result = local
        .shared
        .backend
        .with_initial_edit_session_for_job(&scope, Some(&job), |session| {
            context(local)?;
            body.check(&job, &stopped)?;
            let (outcome, proof) = recovery
                .dispatch_initial_receipt_verified(receipt, session.remote())
                .map_err(|_| Error::EditRecoveryUnavailable)?;
            if !matches!(
                outcome,
                crate::ReconciliationOutcome::VerifiedApplied { .. }
            ) {
                return Err(Error::EditRecoveryUnavailable);
            }
            let proof = proof.ok_or(Error::EditRecoveryUnavailable)?;
            if proof.metadata().local_file != body.local_file() {
                return Err(Error::ConfiguredRootChanged);
            }
            let publication = session
                .prepare_verified_edit(&local.ticket.key.identity, &proof)
                .map_err(|_| Error::EditRecoveryUnavailable)?;
            body.check(&job, &stopped)?;
            context(local)?;
            publication.publish_and_complete(|| {
                context(local)?;
                body.convert(&local.ticket.key.identity, &job, &stopped, || {
                    local.admission.borrow_mut().claim_completion()
                })?;
                context(local)?;
                let completed = crate::CompletedLocalEdit::from_verified_native_completion(&proof)
                    .map_err(|_| Error::EditRecoveryUnavailable)?;
                recovery
                    .record_local_completion(completed)
                    .map_err(|_| Error::EditRecoveryUnavailable)
            })
        })
        .map_err(|_| Error::ProviderUnavailable)?;
    result?;
    let mut inner = local
        .shared
        .inner
        .lock()
        .map_err(|_| Error::EditRecoveryUnavailable)?;
    if inner.replacements.len() >= 64 {
        // Bounded advisory hint metadata only; never evict pending custody,
        // protected bodies or durable recovery history.
        inner.replacements.remove(0);
    }
    inner.replacements.push(CompletedReplacement {
        path: local.ticket.path.clone(),
        file: body.local_file(),
        identity: local.ticket.key.identity,
    });
    // Close the protected file only after releasing the callback-needed mutex.
    drop(inner);
    body.release();
    Ok(FileDeleteOutcome::Completed)
}
