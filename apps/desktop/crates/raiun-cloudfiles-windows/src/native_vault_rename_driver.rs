//! Same-parent encrypted FILE rename. SDK phases are scoped/joined; native pins
//! never cross threads. Any publication uncertainty retains original custody.
use super::*;
use crate::namespace_intent::CapturedAuthorization;
use crate::native::native_vault_file_rename::VaultFileRenamePins;
use std::cell::RefCell;
fn joined<T: Send>(f: impl FnOnce() -> Result<T, Error> + Send) -> Result<T, Error> {
    std::thread::scope(|s| {
        s.spawn(f)
            .join()
            .map_err(|_| Error::EditRecoveryUnavailable)?
    })
}
impl ConfiguredRootConnection {
    pub(crate) fn try_vault_file_rename(
        &self,
        backend: &Arc<crate::OpenCloudPlaceholderBackend>,
        old: &[String],
        new: &[String],
        file: LocalFileIdentity,
        auth: CapturedAuthorization,
        generation: Arc<AtomicU64>,
        current: crate::opencloud::file_create::Current,
    ) -> Result<bool, Error> {
        let no = || Error::EditRecoveryUnavailable;
        if old.len() < 2
            || old.len() != new.len()
            || old[..old.len() - 1] != new[..new.len() - 1]
            || old
                .last()
                .unwrap()
                .eq_ignore_ascii_case(new.last().unwrap())
        {
            return Err(no());
        }
        let root = self.root.as_ref().ok_or_else(no)?;
        root.verify_identity(true)?;
        root.verify_registered()?;
        let root_id = crate::ConfiguredRootIdentity {
            volume_serial: root.identity.volume_serial,
            file_index: root.identity.file_index,
        };
        let job =
            crate::CancellationToken::for_recovery_job(crate::StreamedRecoveryPolicy::default());
        let parents = old[..old.len() - 1].to_vec();
        let parent = joined(|| {
            backend
                .capture_vault_child_create_parent(
                    &parents,
                    root_id,
                    auth,
                    &job,
                    current.clone(),
                    generation.clone(),
                )
                .map_err(|_| no())
        })?;
        let Some(parent) = parent else {
            return Ok(false);
        };
        let (tracker, recovery) = self.file_rename_guard_context(backend)?;
        if recovery.has_unresolved().map_err(|_| no())?
            || recovery
                .has_unresolved_content_authenticated_legacy()
                .map_err(|_| no())?
        {
            return Err(no());
        }
        let mut admission = tracker.try_begin_create().ok_or_else(no)?;
        let observation = admission.observation_probe();
        let stop = || parent.is_stopped() || !observation();
        parent.check().map_err(|_| no())?;
        let route = parent.vault().backend();
        let (identity, original) = route
            .file_rename_source(*parent.opaque().as_bytes(), old.last().unwrap())
            .map_err(|_| no())?;
        let opaque = crate::OpaqueIdentity::from_bytes(identity);
        let mut pins = std::mem::ManuallyDrop::new(VaultFileRenamePins::pin(
            self,
            backend,
            parent.components(),
            parent.route(),
            parent.opaque(),
            old.last().unwrap(),
            new.last().unwrap(),
            opaque,
            file,
            original.size,
        )?);
        let mut published = false;
        let result = (|| {
            if pins.original_identity() != opaque {
                return Err(no());
            }
            if stop() || !admission.is_current() {
                return Err(no());
            }
            let destination = format!(
                "{}/{}",
                parent.metadata().path.trim_end_matches('/'),
                new.last().unwrap()
            );
            let budget = job.cancellation().bounded_request();
            let context = raiun_opencloud::RangeReadContext {
                deadline: budget.deadline(),
                token_generation: auth.token_generation,
            };
            let cancel = crate::vault_custody::VaultUploadCancellation {
                generation: generation.clone(),
                expected: auth.agent_generation,
                cancelled: &stop,
            };
            let target = joined(|| {
                let cancel = crate::vault_custody::VaultUploadCancellation {
                    generation: generation.clone(),
                    expected: auth.agent_generation,
                    cancelled: &stop,
                };
                route
                    .binding()
                    .prepare_file_rename(
                        &original,
                        &destination,
                        parent.metadata(),
                        &cancel,
                        context,
                    )
                    .map_err(|_| no())
            })?;
            pins.verify(self, false)?;
            parent.check().map_err(|_| no())?;
            let facts = crate::VaultFileRenameFacts {
                volume: pins.file().volume_serial,
                file: pins.file().file_index,
                usn: pins.usn(),
                parent_file: pins.parent_file().file_index,
                parent_usn: pins.parent_usn(),
                identity,
                parent_identity: *parent.opaque().as_bytes(),
                old_components: pins.old_components().to_vec(),
                new_components: pins.components().to_vec(),
                original: original.clone(),
                parent: parent.metadata().clone(),
                destination: destination.clone(),
                encoded_source: target.encoded_source().into(),
                encoded_destination: target.encoded_destination().into(),
                integrity: target.integrity_token().into(),
                historical_epoch: 0,
                token_generation: auth.token_generation,
            };
            let descriptor = route
                .binding()
                .rename_descriptor(root_id, facts)
                .map_err(|_| no())?;
            // Err may follow a durable publication. Retain from BEFORE this call.
            published = true;
            let record = route
                .prepare_file_rename_record(&descriptor)
                .map_err(|_| no())?;
            pins.verify(self, false)?;
            parent.check().map_err(|_| no())?;
            if stop() || !admission.claim_dispatch() {
                return Err(no());
            }
            let dispatch = admission.dispatch_probe();
            let proof = pins.send_proof()?;
            let outcome = joined(|| {
                let cancel = crate::vault_custody::VaultUploadCancellation {
                    generation: generation.clone(),
                    expected: auth.agent_generation,
                    cancelled: &stop,
                };
                let mut before = || {
                    if stop() || !dispatch() {
                        return Err(raiun_core::backend::CloudError::new(
                            raiun_core::backend::ErrorKind::Conflict,
                            "vault rename admission changed",
                        ));
                    }
                    proof.check()?;
                    record.claim_send().map_err(|_| {
                        raiun_core::backend::CloudError::new(
                            raiun_core::backend::ErrorKind::Io,
                            "vault rename intent unavailable",
                        )
                    })
                };
                route
                    .binding()
                    .send_file_rename(
                        &original,
                        &destination,
                        parent.metadata(),
                        target,
                        &cancel,
                        context,
                        &mut before,
                    )
                    .map_err(|_| no())
            })?;
            let raiun_opencloud::vault_backend::VaultFileRenameOutcome::Verified(verified) =
                outcome
            else {
                return Err(no());
            };
            if !route.binding().file_rename_proof_matches(&verified) {
                return Err(no());
            }
            record.record_remote(&verified).map_err(|_| no())?;
            pins.verify(self, false)?;
            parent.check().map_err(|_| no())?;
            let admission = RefCell::new(admission);
            route.publish_file_rename(&verified, identity, &cancel, || {
                pins.complete(self, opaque, &|| {
                    !stop()
                        && admission
                            .try_borrow_mut()
                            .is_ok_and(|mut a| a.claim_completion())
                })?;
                pins.verify(self, true)?;
                if stop() {
                    return Err(no());
                }
                self.state
                    .hydrated_files
                    .lock()
                    .map_err(|_| no())?
                    .rebase_vault_rename(identity, file.file_index, original.size, old, new)
                    .map_err(|_| no())?;
                // Preserve an existing factual body receipt; never invent a digest.
                let existing = self
                    .state
                    .writable_cleanup
                    .lock()
                    .map_err(|_| no())?
                    .admitted(&identity, |r| {
                        r.identity == identity
                            && r.file == file
                            && r.components == old
                            && r.length == original.size
                            && route.binding().matches_cleanup_dispatch(&r.dispatch)
                    })
                    .ok();
                if let Some((_, receipt, uncertain)) = existing {
                    if uncertain {
                        return Err(no());
                    }
                    let mut original_receipt = receipt.original.clone();
                    if let Some(e) = original_receipt.as_mut() {
                        if e.id != original.id || e.etag != original.etag || e.path != original.path
                        {
                            return Err(no());
                        }
                        e.path = destination.clone();
                    }
                    let mut book = self.state.writable_cleanup.lock().map_err(|_| no())?;
                    let ticket = book.reserve(identity).map_err(|_| no())?;
                    book.publish(
                        ticket,
                        WritableCleanupReceipt {
                            dispatch: route.binding().capture_dispatch_stamp(),
                            root: root_id,
                            identity,
                            file,
                            components: new.to_vec(),
                            length: receipt.length,
                            sha256: receipt.sha256,
                            clean_hydration: receipt.clean_hydration,
                            original: original_receipt,
                        },
                    )
                    .map_err(|_| no())?;
                }
                record
                    .record_native(file.file_index, pins.usn())
                    .map_err(|_| no())
            })?;
            Ok(true)
        })();
        if !published || matches!(&result, Ok(true)) {
            unsafe { std::mem::ManuallyDrop::drop(&mut pins) }
        } else {
            tracker.mark_unknown();
        }
        result
    }
}
