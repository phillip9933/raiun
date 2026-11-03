//! One EMPTY encrypted directory deletion in the original native callback owner.
//! Qualify both native and remote emptiness BEFORE ACK; never recurse or replay.
use super::vault_replacement::{Custody, Local, Original, VaultDeleteChoice, metadata_usn};
use super::*;
use crate::opencloud::vault_child_create::VaultChildCreateParent;
use crate::vault_file_delete::{VaultFileDeleteNativeProof, VaultFileDeleteRemoteProof};
#[allow(clippy::too_many_arguments)]
pub(super) fn execute<'a, 'b>(
    shared: &'a Arc<Shared>,
    ticket: &'a Ticket,
    state: &'a Arc<CallbackState>,
    admission: &'a RefCell<SaveRenameTicket<'b>>,
    parents: &[String],
    name: &str,
    parent: Arc<VaultChildCreateParent>,
    job: crate::StreamedRecoveryJob,
) -> Result<FileDeleteOutcome, Error> {
    let no = || Error::EditRecoveryUnavailable;
    if ticket.kind != NamespaceObjectKind::Directory
        || ticket.size != 0
        || !parent.vault().backend().existing_file_saves_active()
    {
        return Err(no());
    }
    let route = parent.vault().backend().clone();
    let (id, saved) = route
        .file_rename_source(*parent.opaque().as_bytes(), name, true)
        .map_err(|_| no())?;
    if id != ticket.key.identity {
        return Err(no());
    }
    let queued_directory =
        route.binding().is_cached_only() && saved.id.starts_with("raiun-pending-directory:");
    let original = if queued_directory {
        saved
    } else {
        let metadata = job.cancellation().bounded_request();
        route
            .fresh_directory_rename_source(&saved, &metadata)
            .map_err(|_| no())?
    };
    let path = state
        .root_path
        .as_ref()
        .ok_or(Error::ConfiguredRootChanged)?;
    let root = pin_registered_configured_root(path, shared.root)?;
    let refs = parents.iter().map(String::as_str).collect::<Vec<_>>();
    let (parent_pin, parent_snapshot, ancestors) =
        native_namespace_directory::pin_reinspected_namespace_parent(
            &root,
            path,
            parent.route(),
            parent.opaque(),
            &refs,
        )?;
    let wide = wide_path(&ticket.path)?;
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_READ_ATTRIBUTES | 1,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS | 0x0010_0000,
            null_mut(),
        )
    };
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(win32_io_error("pin original empty encrypted directory"));
    }
    let leaf = RawOwnedHandle(raw);
    let snapshot = root_snapshot(leaf.0)?;
    let usn = metadata_usn(leaf.0, ticket.key.file)?;
    let parent_file = LocalFileIdentity {
        volume_serial: parent_snapshot.identity.volume_serial,
        file_index: parent_snapshot.identity.file_index,
    };
    let mut components = parents.to_vec();
    components.push(name.to_owned());
    let descriptor = if queued_directory {
        None
    } else {
        Some(
            route
                .binding()
                .directory_delete_descriptor(
                    shared.root,
                    ticket.key.identity,
                    original.clone(),
                    *parent.opaque().as_bytes(),
                    parent.metadata().clone(),
                    LocalFileIdentity {
                        volume_serial: ticket.key.volume,
                        file_index: ticket.key.file,
                    },
                    usn,
                    parent_file,
                    metadata_usn(parent_pin.0, parent_file.file_index)?,
                    components.clone(),
                )
                .map_err(|_| no())?,
        )
    };
    let original_context = if let Some(descriptor) = &descriptor {
        Original {
            owner: descriptor.owner.clone(),
            vault: descriptor.vault.clone(),
            remote_root: descriptor.remote_root.clone(),
            metadata: descriptor.original.clone(),
            epoch: descriptor.historical_unlock_epoch,
        }
    } else {
        Original {
            owner: route.binding().cached_provider_scope(),
            vault: route.binding().cached_vault_scope(),
            remote_root: route.binding().cached_remote_root(),
            metadata: original.clone(),
            epoch: route.binding().historical_unlock_epoch(),
        }
    };
    let mut local = Custody(Some(Local {
        shared,
        ticket,
        state,
        admission,
        parent,
        root,
        parent_pin,
        parent_snapshot,
        ancestors,
        leaf: Some(leaf),
        original_snapshot: snapshot,
        original_usn: usn,
        original: original_context,
        queued_directory,
        components,
        job,
        acknowledged: false,
        removed: false,
        terminal: false,
        published: false,
    }));
    local.original_current()?;
    if queued_directory {
        let stop = || local.stopped();
        let receipt = route
            .binding()
            .cancel_cached_directory_create(&original, &stop)
            .map_err(|_| no())?;
        // The SDK receipt is a durable cancellation intent from this point.
        // Every later failure retains the original native owner and pins.
        local.published = true;
        route
            .record_cached_directory_cancel_queued(
                &receipt,
                ticket.key.identity,
                ticket.key.file,
                usn,
            )
            .map_err(|_| no())?;
        local.allow_and_wait()?;
        let choice = VaultDeleteChoice::from_local(local.0.take().ok_or_else(no)?);
        choice.confirm_absence()?;
        let (probe, lifetime) = admission
            .borrow()
            .dispatch_probe(state.close_capture_admission.clone())
            .ok_or_else(no)?;
        if !admission.borrow_mut().claim_dispatch() || !lifetime.arm_after_dispatch() || !probe() {
            return Err(no());
        }
        route.publish_cached_directory_cancel(
            &receipt,
            ticket.key.identity,
            ticket.key.file,
            usn,
            || {
                choice.confirm_absence()?;
                if !admission.borrow_mut().claim_completion() {
                    return Err(no());
                }
                choice.confirm_absence()
            },
        )?;
        choice.confirm_absence()?;
        route
            .binding()
            .acknowledge_cancelled_cached_directory(&receipt, &|| choice.stopped())
            .map_err(|_| no())?;
        choice.release_completed()?;
        return Ok(FileDeleteOutcome::Completed);
    }
    let descriptor = descriptor.ok_or_else(no)?;
    let generation = shared.config.generation.as_ref().ok_or_else(no)?.clone();
    let context = raiun_opencloud::RangeReadContext {
        deadline: local.job.cancellation().bounded_request().deadline(),
        token_generation: descriptor.owner.token_generation(),
    };
    let target = {
        let stop = || local.stopped();
        let cancel = crate::vault_custody::VaultUploadCancellation {
            generation: generation.clone(),
            expected: shared.config.authorization.agent_generation,
            cancelled: &stop,
        };
        route
            .binding()
            .prepare_empty_directory_delete(
                &descriptor.original,
                &descriptor.parent,
                &cancel,
                context,
            )
            .map_err(|_| no())?
    };
    local.original_current()?;
    // Failure can follow durable publication, including BEFORE ACK. Keep the
    // original pins/owner for every uncertain state from this point onward.
    local.published = true;
    let record = route.begin_file_delete(&descriptor).map_err(|_| no())?;
    local.original_current()?;
    local.allow_and_wait()?;
    let choice = VaultDeleteChoice::from_local(local.0.take().ok_or_else(no)?);
    choice.confirm_absence()?;
    let (probe, lifetime) = admission
        .borrow()
        .dispatch_probe(state.close_capture_admission.clone())
        .ok_or_else(no)?;
    let observation = lifetime.observation_probe();
    let job = choice
        .job
        .with_revocation_check(Arc::new(move || !observation()));
    if !admission.borrow_mut().claim_dispatch() || !lifetime.arm_after_dispatch() {
        return Err(no());
    }
    let job = job.with_revocation_check(Arc::new(move || !probe()));
    let stop = || job.is_stopped() || choice.stopped();
    let cancel = crate::vault_custody::VaultUploadCancellation {
        generation,
        expected: shared.config.authorization.agent_generation,
        cancelled: &stop,
    };
    let result = route
        .binding()
        .send_empty_directory_delete(
            &descriptor.original,
            &descriptor.parent,
            target,
            &cancel,
            context,
            &mut || {
                let fail = || {
                    CloudError::new(
                        ErrorKind::Conflict,
                        "original empty directory delete owner changed",
                    )
                };
                choice.confirm_absence().map_err(|_| fail())?;
                record.claim_send().map_err(|_| fail())
            },
        )
        .map_err(|_| no())?;
    let raiun_opencloud::vault_backend::VaultFileDeleteOutcome::Verified(verified) = result else {
        return Err(no());
    };
    let proof = VaultFileDeleteRemoteProof {
        descriptor: descriptor.clone(),
        target: None,
        directory_dispatch: Some(route.binding().capture_dispatch_stamp()),
        verified,
    };
    record.record_remote(&proof).map_err(|_| no())?;
    choice.confirm_absence()?;
    route.publish_file_delete(&proof, &cancel, || {
        choice.confirm_absence()?;
        if !admission.borrow_mut().claim_completion() {
            return Err(no());
        }
        let native = VaultFileDeleteNativeProof {
            descriptor: descriptor.clone(),
            parent_usn_after: choice.parent_current_usn()?,
        };
        record.record_native_completed(&native).map_err(|_| no())?;
        choice.confirm_absence()
    })?;
    choice.release_completed()?;
    Ok(FileDeleteOutcome::Completed)
}
