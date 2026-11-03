//! Clean encrypted FILE deletion after the ORIGINAL owner's local completion
//! and exact fresh absence. No restored row, timer or name initiates DELETE.
use super::vault_replacement::VaultDeleteChoice;
use super::*;
use crate::vault_file_delete::{
    VaultFileDeleteDescriptor, VaultFileDeleteNativeProof, VaultFileDeleteRemoteProof,
};

pub(super) fn execute(choice: VaultDeleteChoice<'_, '_>) -> Result<FileDeleteOutcome, Error> {
    choice.confirm_absence()?;
    choice
        .parent
        .check()
        .map_err(|_| Error::ProviderUnavailable)?;
    let generation = choice
        .shared
        .config
        .generation
        .as_ref()
        .ok_or(Error::EditRecoveryUnavailable)?
        .clone();
    let parent_file = choice.parent_native_file()?;
    let descriptor = VaultFileDeleteDescriptor {
        owner: choice.original_owner().clone(),
        vault: choice.original_vault().clone(),
        remote_root: choice.original_remote_root().to_owned(),
        root: choice.shared.root,
        original_identity: choice.ticket.key.identity,
        original: choice.original_metadata().clone(),
        empty_directory: false,
        parent_identity: *choice.parent.opaque().as_bytes(),
        parent: choice.parent.metadata().clone(),
        historical_unlock_epoch: choice.original_epoch(),
        original_file: LocalFileIdentity {
            volume_serial: choice.ticket.key.volume,
            file_index: choice.ticket.key.file,
        },
        original_usn: choice.original_usn,
        parent_file,
        parent_usn: choice.parent_current_usn()?,
        components: choice.components.clone(),
    };
    descriptor
        .validate()
        .map_err(|_| Error::EditRecoveryUnavailable)?;
    let (probe, lifetime) = choice
        .admission
        .borrow()
        .dispatch_probe(choice.state.close_capture_admission.clone())
        .ok_or(Error::EditRecoveryUnavailable)?;
    let observation = lifetime.observation_probe();
    let job = choice
        .job
        .with_revocation_check(Arc::new(move || !observation()));
    let stop = || job.is_stopped() || choice.stopped();
    let context = raiun_opencloud::RangeReadContext {
        deadline: job.cancellation().bounded_request().deadline(),
        token_generation: descriptor.owner.token_generation(),
    };
    let prepare_cancel = crate::vault_custody::VaultUploadCancellation {
        generation: generation.clone(),
        expected: choice.shared.config.authorization.agent_generation,
        cancelled: &stop,
    };
    let record = choice
        .parent
        .vault()
        .backend()
        .begin_file_delete(&descriptor)
        .map_err(|_| Error::EditRecoveryUnavailable)?;
    if record.descriptor().facts() != descriptor.facts() {
        return Err(Error::EditRecoveryUnavailable);
    }
    let target = choice
        .parent
        .vault()
        .backend()
        .binding()
        .prepare_file_delete(
            &descriptor.original,
            &descriptor.parent,
            &prepare_cancel,
            context,
        )
        .map_err(|_| Error::EditRecoveryUnavailable)?;
    choice.confirm_absence()?;
    if !choice.admission.borrow_mut().claim_dispatch() || !lifetime.arm_after_dispatch() {
        return Err(Error::EditRecoveryUnavailable);
    }
    let job = job.with_revocation_check(Arc::new(move || !probe()));
    // All supplied cancellation probes are atomics; native/record checks run
    // only in the explicit SDK before-send guard, outside crypto/session locks.
    let stop = || job.is_stopped() || choice.stopped();
    let cancel = crate::vault_custody::VaultUploadCancellation {
        generation,
        expected: choice.shared.config.authorization.agent_generation,
        cancelled: &stop,
    };
    let result = choice
        .parent
        .vault()
        .backend()
        .binding()
        .send_file_delete(
            &descriptor.original,
            &descriptor.parent,
            target,
            &cancel,
            context,
            &mut || {
                let refused = || {
                    CloudError::new(
                        ErrorKind::Forbidden,
                        "original vault file delete owner changed",
                    )
                };
                choice.confirm_absence().map_err(|_| refused())?;
                record.claim_send().map_err(|_| refused())
            },
        )
        .map_err(|_| Error::EditRecoveryUnavailable)?;
    let verified = match result {
        raiun_opencloud::vault_backend::VaultFileDeleteOutcome::Verified(p) => p,
        raiun_opencloud::vault_backend::VaultFileDeleteOutcome::NeedsReconciliation => {
            return Err(Error::EditRecoveryUnavailable);
        }
    };
    let locator = crate::ExistingVaultUploadTarget::new(
        descriptor.owner.clone(),
        descriptor.vault.clone(),
        descriptor.remote_root.clone(),
        descriptor.root,
        descriptor.original_identity,
        descriptor.original.clone(),
    )
    .map_err(|_| Error::EditRecoveryUnavailable)?
    .with_fresh_dispatch(
        choice
            .parent
            .vault()
            .backend()
            .binding()
            .capture_dispatch_stamp(),
    );
    let proof = VaultFileDeleteRemoteProof {
        descriptor,
        target: Some(locator),
        directory_dispatch: None,
        verified,
    };
    record
        .record_remote(&proof)
        .map_err(|_| Error::EditRecoveryUnavailable)?;
    choice.confirm_absence()?;
    choice
        .parent
        .vault()
        .backend()
        .publish_file_delete(&proof, &cancel, || {
            choice.confirm_absence()?;
            if !choice.admission.borrow_mut().claim_completion() {
                return Err(Error::EditRecoveryUnavailable);
            }
            let d = proof.descriptor();
            let native = VaultFileDeleteNativeProof {
                descriptor: d.clone(),
                parent_usn_after: choice.parent_current_usn()?,
            };
            record
                .record_native_completed(&native)
                .map_err(|_| Error::EditRecoveryUnavailable)?;
            choice.confirm_absence()?;
            choice
                .state
                .hydrated_files
                .lock()
                .map_err(|_| Error::EditRecoveryUnavailable)?
                .retire_deleted(
                    d.original_identity,
                    d.original_file.file_index,
                    d.original.size,
                    &d.components,
                )
                .map_err(|_| Error::EditRecoveryUnavailable)?;
            choice
                .state
                .writable_cleanup
                .lock()
                .map_err(|_| Error::EditRecoveryUnavailable)?
                .retire_deleted(&d.original_identity, |r| {
                    r.root == d.root
                        && r.identity == d.original_identity
                        && r.file == d.original_file
                        && r.length == d.original.size
                        && r.components == d.components
                })
                .map_err(|_| Error::EditRecoveryUnavailable)?;
            Ok(())
        })?;
    choice.release_completed()?;
    Ok(FileDeleteOutcome::Completed)
}
