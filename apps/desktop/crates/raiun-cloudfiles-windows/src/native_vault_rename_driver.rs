//! One original live vault namespace MOVE. SDK phases are scoped/joined;
//! native pins never cross threads and publication uncertainty retains custody.
use super::native_vault_directory_rename::VaultDirectoryRenamePins;
use super::native_vault_file_rename::VaultFileRenamePins;
use super::*;
use crate::namespace_intent::CapturedAuthorization;
use std::cell::RefCell;
fn joined<T: Send>(f: impl FnOnce() -> Result<T, Error> + Send) -> Result<T, Error> {
    std::thread::scope(|s| {
        s.spawn(f)
            .join()
            .map_err(|_| Error::EditRecoveryUnavailable)?
    })
}
enum Pins {
    File(VaultFileRenamePins),
    Directory(VaultDirectoryRenamePins),
}
enum Target {
    File(raiun_opencloud::vault_backend::VaultFileRenameTarget),
    Directory(raiun_opencloud::vault_backend::VaultDirectoryRenameTarget),
}
enum Verified {
    File(raiun_opencloud::vault_backend::VaultVerifiedFileRename),
    Directory(raiun_opencloud::vault_backend::VaultVerifiedDirectoryRename),
}
enum Proof {
    File(native_vault_file_rename::VaultFileRenameSendProof),
    Directory(native_vault_directory_rename::VaultDirectoryRenameSendProof),
}
impl Proof {
    fn check(&self) -> Result<(), raiun_core::backend::CloudError> {
        match self {
            Self::File(p) => p.check(),
            Self::Directory(p) => p.check(),
        }
    }
}
impl Target {
    fn encoded_source(&self) -> &str {
        match self {
            Self::File(t) => t.encoded_source(),
            Self::Directory(t) => t.encoded_source(),
        }
    }
    fn encoded_destination(&self) -> &str {
        match self {
            Self::File(t) => t.encoded_destination(),
            Self::Directory(t) => t.encoded_destination(),
        }
    }
    fn integrity(&self) -> &str {
        match self {
            Self::File(t) => t.integrity_token(),
            Self::Directory(t) => t.integrity_token(),
        }
    }
}
impl Verified {
    fn root(&self) -> &raiun_opencloud::vault_backend::VaultVerifiedFileRename {
        match self {
            Self::File(p) => p,
            Self::Directory(p) => p.root_proof(),
        }
    }
}
impl Pins {
    fn verify(&self, c: &ConfiguredRootConnection, complete: bool) -> Result<(), Error> {
        match self {
            Self::File(p) => p.verify(c, complete),
            Self::Directory(p) => p.check(c, complete),
        }
    }
    fn proof(&self) -> Result<Proof, Error> {
        match self {
            Self::File(p) => p.send_proof().map(Proof::File),
            Self::Directory(p) => p.send_proof().map(Proof::Directory),
        }
    }
    fn facts(
        &self,
    ) -> Result<
        (
            u64,
            i64,
            u64,
            i64,
            Option<Vec<crate::VaultDirectoryRenameNode>>,
            u64,
            i64,
        ),
        Error,
    > {
        match self {
            Self::File(p) => Ok((
                p.file().file_index,
                p.usn(),
                p.parent_file().file_index,
                p.parent_usn(),
                None,
                p.destination_parent_file().file_index,
                p.destination_parent_usn(),
            )),
            Self::Directory(p) => {
                let (f, u, pf, pu, n) = p.facts()?;
                Ok((
                    f,
                    u,
                    pf,
                    pu,
                    Some(n),
                    p.destination_parent_file(),
                    p.destination_parent_usn(),
                ))
            }
        }
    }
    fn complete(
        &mut self,
        c: &ConfiguredRootConnection,
        id: crate::OpaqueIdentity,
        claim: &dyn Fn() -> bool,
    ) -> Result<Vec<(u64, i64)>, Error> {
        match self {
            Self::File(p) => {
                if p.original_identity() != id {
                    return Err(Error::EditRecoveryUnavailable);
                }
                p.complete(c, id, claim)?;
                p.verify(c, true)?;
                Ok(vec![(p.file().file_index, p.usn())])
            }
            Self::Directory(p) => p.complete(c, claim),
        }
    }
}
impl ConfiguredRootConnection {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn try_vault_file_rename(
        &self,
        backend: &Arc<crate::OpenCloudPlaceholderBackend>,
        old: &[String],
        new: &[String],
        file: LocalFileIdentity,
        auth: CapturedAuthorization,
        generation: Arc<AtomicU64>,
        current: crate::opencloud::file_create::Current,
        directory: bool,
    ) -> Result<bool, Error> {
        let no = || Error::EditRecoveryUnavailable;
        if old.len() < 2
            || new.len() < 2
            || old
                .iter()
                .map(|s| s.to_lowercase())
                .eq(new.iter().map(|s| s.to_lowercase()))
            || (directory && new.starts_with(old))
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
        let parent = joined(|| {
            backend
                .capture_vault_child_create_parent(
                    &old[..old.len() - 1],
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
        let destination_parent = if old[..old.len() - 1] == new[..new.len() - 1] {
            parent.clone()
        } else {
            joined(|| {
                backend
                    .capture_vault_child_create_parent(
                        &new[..new.len() - 1],
                        root_id,
                        auth,
                        &job,
                        current.clone(),
                        generation.clone(),
                    )
                    .map_err(|_| no())
            })?
            .ok_or_else(no)?
        };
        if !Arc::ptr_eq(parent.vault(), destination_parent.vault()) {
            return Err(no());
        }
        parent.check().map_err(|_| no())?;
        destination_parent.check().map_err(|_| no())?;
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
        let stop = || parent.is_stopped() || destination_parent.is_stopped() || !observation();
        let route = parent.vault().backend();
        let (identity, original) = route
            .file_rename_source(*parent.opaque().as_bytes(), old.last().unwrap(), directory)
            .map_err(|_| no())?;
        let pending_create = route.binding().is_cached_only()
            && original.id.starts_with(if directory {
                "raiun-pending-directory:"
            } else {
                "raiun-pending-create:"
            });
        let original = if directory && !pending_create {
            let metadata = job.cancellation().bounded_request();
            joined(|| {
                route
                    .fresh_directory_rename_source(&original, &metadata)
                    .map_err(|_| no())
            })?
        } else {
            original
        };
        let opaque = crate::OpaqueIdentity::from_bytes(identity);
        let rows = if directory {
            route
                .directory_rename_catalogue(&original)
                .map_err(|_| no())?
        } else {
            Vec::new()
        };
        let pins = if directory {
            Pins::Directory(VaultDirectoryRenamePins::pin(
                self,
                backend,
                &parent,
                &destination_parent,
                old,
                new,
                file,
                &rows,
                pending_create,
            )?)
        } else {
            Pins::File(VaultFileRenamePins::pin(
                self,
                backend,
                destination_parent.components(),
                destination_parent.route(),
                destination_parent.opaque(),
                parent.components(),
                parent.route(),
                parent.opaque(),
                old.last().unwrap(),
                new.last().unwrap(),
                opaque,
                file,
                original.size,
                pending_create,
            )?)
        };
        let mut pins = std::mem::ManuallyDrop::new(pins);
        let mut published = false;
        let result = (|| {
            if stop() || !admission.is_current() {
                return Err(no());
            }
            pins.verify(self, false)?;
            let destination = format!(
                "{}/{}",
                destination_parent.metadata().path.trim_end_matches('/'),
                new.last().unwrap()
            );
            if pending_create {
                let binding = route.binding();
                let parent_ref = binding
                    .cached_parent_ref(destination_parent.metadata(), &stop)
                    .map_err(|_| no())?;
                let native_rows = match &*pins {
                    Pins::File(p) => {
                        let digest = p.pending_body_sha256()?;
                        vec![(
                            original.clone(),
                            identity,
                            file.file_index,
                            p.usn(),
                            Some(digest),
                        )]
                    }
                    Pins::Directory(p) => p.pending_native_bodies()?,
                };
                if native_rows.len() > 64 || native_rows.is_empty() {
                    return Err(no());
                }
                for (entry, _, _, _, digest) in &native_rows {
                    let prefix = if entry.directory {
                        "raiun-pending-directory:"
                    } else {
                        "raiun-pending-create:"
                    };
                    let id = entry.id.strip_prefix(prefix).ok_or_else(no)?;
                    let revision = entry
                        .etag
                        .strip_prefix(&format!("raiun-pending-v1:{id}:"))
                        .and_then(|v| v.parse::<u64>().ok())
                        .ok_or_else(no)?;
                    let sealed = binding
                        .cached_pending_operation(id, revision, &stop)
                        .map_err(|_| no())?;
                    if sealed.path != entry.path
                        || sealed.plaintext_len != entry.size
                        || digest
                            .as_ref()
                            .is_some_and(|hash| sealed.plaintext_sha256.as_str() != hash.as_str())
                        || sealed.state != raiun_cache::CiphertextWriteState::NeverAttempted
                    {
                        return Err(no());
                    }
                }
                let (native_file, usn, parent_file, parent_usn, _, dest_file, dest_usn) =
                    pins.facts()?;
                let descriptor = crate::opencloud::VaultCachedRetargetDescriptor {
                    owner: backend.scope().clone(),
                    vault: binding.cached_vault_scope(),
                    remote_root: parent.vault().root_path().to_owned(),
                    root: root_id,
                    identity,
                    original: original.clone(),
                    parent_identity: *parent.opaque().as_bytes(),
                    parent: parent.metadata().clone(),
                    destination_parent: destination_parent.metadata().clone(),
                    destination_parent_identity: *destination_parent.opaque().as_bytes(),
                    historical_unlock_epoch: binding.historical_unlock_epoch(),
                    original_file: LocalFileIdentity {
                        volume_serial: root_id.volume_serial,
                        file_index: native_file,
                    },
                    original_usn: usn,
                    parent_file: LocalFileIdentity {
                        volume_serial: root_id.volume_serial,
                        file_index: parent_file,
                    },
                    parent_usn,
                    destination_parent_file: LocalFileIdentity {
                        volume_serial: root_id.volume_serial,
                        file_index: dest_file,
                    },
                    destination_parent_usn: dest_usn,
                    old_components: old.to_vec(),
                    new_components: new.to_vec(),
                    destination_parent_ref: parent_ref.clone(),
                };
                descriptor.validate().map_err(|_| no())?;
                if !admission.claim_dispatch() || stop() {
                    return Err(no());
                }
                let receipt = if directory {
                    let result = joined(|| {
                        binding
                            .retarget_cached_directory_subtree(
                                &original,
                                &destination,
                                &parent_ref,
                                &stop,
                            )
                            .map_err(|_| no())
                    })?;
                    published = true;
                    crate::opencloud::VaultCachedNamespaceQueued::pending_directory_retarget(
                        &descriptor,
                        result,
                    )
                    .map_err(|_| no())?
                } else {
                    let result = joined(|| {
                        binding
                            .retarget_cached_file_create(
                                &original,
                                &destination,
                                &parent_ref,
                                &stop,
                            )
                            .map_err(|_| no())
                    })?;
                    published = true;
                    crate::opencloud::VaultCachedNamespaceQueued::pending_file_retarget(
                        &descriptor,
                        result,
                    )
                    .map_err(|_| no())?
                };
                route
                    .record_cached_retarget_queued(&receipt)
                    .map_err(|_| no())?;
                pins.verify(self, false)?;
                let cancel = crate::vault_custody::VaultUploadCancellation {
                    generation: generation.clone(),
                    expected: auth.agent_generation,
                    cancelled: &stop,
                };
                route.publish_cached_retarget(&receipt, &cancel, || {
                    if stop() || !admission.claim_completion() {
                        return Err(no());
                    }
                    let completed = match &mut *pins {
                        Pins::File(p) => {
                            let (file, usn) = p.complete_cached_queued(self, &|| !stop())?;
                            vec![(identity, file, usn)]
                        }
                        Pins::Directory(p) => p.complete_cached_queued(self, &|| !stop())?,
                    };
                    route
                        .record_cached_retarget_native(&receipt, &completed)
                        .map_err(|_| no())
                })?;
                return Ok(true);
            }
            if route.binding().is_cached_only() && !directory {
                if original.id.starts_with("raiun-pending-") {
                    return Err(no());
                }
                let (native_file, usn, parent_file, parent_usn, _, dest_file, dest_usn) =
                    pins.facts()?;
                if !admission.claim_dispatch() || stop() {
                    return Err(no());
                }
                let outcome = joined(|| {
                    route
                        .binding()
                        .queue_cached_file_rename(&original.path, &destination, &original, &stop)
                        .map_err(|_| no())
                })?;
                let (write_id, revision) = match &outcome {
                    raiun_opencloud::vault_backend::VaultRenameOutcome::Queued {
                        write_id,
                        revision,
                        uncertain: false,
                        ..
                    } => (write_id, *revision),
                    _ => return Err(no()),
                };
                published = true;
                let sealed = route
                    .binding()
                    .cached_pending_operation(write_id, revision, &stop)
                    .map_err(|_| no())?;
                if sealed.path != original.path
                    || sealed.destination_path != destination
                    || sealed.base_resource_id != original.id
                    || sealed.base_etag != original.etag
                {
                    return Err(no());
                }
                let facts = crate::VaultFileRenameFacts {
                    volume: root_id.volume_serial,
                    file: native_file,
                    usn,
                    parent_file,
                    parent_usn,
                    identity,
                    parent_identity: *parent.opaque().as_bytes(),
                    old_components: old.to_vec(),
                    new_components: new.to_vec(),
                    original: original.clone(),
                    children: None,
                    parent: parent.metadata().clone(),
                    destination_parent: if Arc::ptr_eq(&parent, &destination_parent) {
                        None
                    } else {
                        Some(crate::VaultFileRenameDestination {
                            identity: *destination_parent.opaque().as_bytes(),
                            parent: destination_parent.metadata().clone(),
                            file: dest_file,
                            usn: dest_usn,
                        })
                    },
                    destination: destination.clone(),
                    encoded_source: sealed.encoded_target,
                    encoded_destination: sealed.encoded_destination_target,
                    integrity: sealed.root_integrity_token,
                    historical_epoch: 0,
                    token_generation: auth.token_generation,
                };
                let descriptor = route
                    .binding()
                    .rename_descriptor(root_id, facts)
                    .map_err(|_| no())?;
                let receipt =
                    crate::opencloud::VaultCachedNamespaceQueued::file_rename(&descriptor, outcome)
                        .map_err(|_| no())?;
                let record = route
                    .prepare_file_rename_record(&descriptor)
                    .map_err(|_| no())?;
                record.record_local_queued(&receipt).map_err(|_| no())?;
                pins.verify(self, false)?;
                let cancel = crate::vault_custody::VaultUploadCancellation {
                    generation: generation.clone(),
                    expected: auth.agent_generation,
                    cancelled: &stop,
                };
                route.publish_cached_namespace(&receipt, &cancel, || {
                    if stop() || !admission.claim_completion() {
                        return Err(no());
                    }
                    let Pins::File(local) = &mut *pins else {
                        return Err(no());
                    };
                    let (file, usn) = local.complete_cached_queued(self, &|| !stop())?;
                    record
                        .record_local_queued_native(&receipt, identity, file, usn)
                        .map_err(|_| no())
                })?;
                return Ok(true);
            }
            let budget = job.cancellation().bounded_request();
            let context = raiun_opencloud::RangeReadContext {
                deadline: budget.deadline(),
                token_generation: auth.token_generation,
            };
            let target = joined(|| {
                let cancel = crate::vault_custody::VaultUploadCancellation {
                    generation: generation.clone(),
                    expected: auth.agent_generation,
                    cancelled: &stop,
                };
                if directory {
                    let expected = rows.iter().map(|e| e.metadata.clone()).collect::<Vec<_>>();
                    route
                        .binding()
                        .prepare_directory_rename(
                            &original,
                            &destination,
                            parent.metadata(),
                            destination_parent.metadata(),
                            &expected,
                            &cancel,
                            context,
                        )
                        .map(Target::Directory)
                        .map_err(|_| no())
                } else {
                    route
                        .binding()
                        .prepare_file_rename(
                            &original,
                            &destination,
                            parent.metadata(),
                            destination_parent.metadata(),
                            &cancel,
                            context,
                        )
                        .map(Target::File)
                        .map_err(|_| no())
                }
            })?;
            pins.verify(self, false)?;
            parent.check().map_err(|_| no())?;
            destination_parent.check().map_err(|_| no())?;
            let (native_file, usn, parent_file, parent_usn, children, dest_file, dest_usn) =
                pins.facts()?;
            let children = match (&target, children) {
                (Target::Directory(t), Some(mut nodes)) => {
                    for n in &mut nodes {
                        let fresh = t
                            .original_tree()
                            .iter()
                            .find(|e| e.id == n.original.id && e.path == n.original.path)
                            .ok_or_else(no)?;
                        n.original = fresh.clone();
                    }
                    Some(nodes)
                }
                (_, n) => n,
            };
            let facts = crate::VaultFileRenameFacts {
                volume: root_id.volume_serial,
                file: native_file,
                usn,
                parent_file,
                parent_usn,
                identity,
                parent_identity: *parent.opaque().as_bytes(),
                old_components: old.to_vec(),
                new_components: new.to_vec(),
                original: original.clone(),
                children,
                parent: parent.metadata().clone(),
                destination_parent: if Arc::ptr_eq(&parent, &destination_parent) {
                    None
                } else {
                    Some(crate::VaultFileRenameDestination {
                        identity: *destination_parent.opaque().as_bytes(),
                        parent: destination_parent.metadata().clone(),
                        file: dest_file,
                        usn: dest_usn,
                    })
                },
                destination: destination.clone(),
                encoded_source: target.encoded_source().into(),
                encoded_destination: target.encoded_destination().into(),
                integrity: target.integrity().into(),
                historical_epoch: 0,
                token_generation: auth.token_generation,
            };
            let descriptor = route
                .binding()
                .rename_descriptor(root_id, facts)
                .map_err(|_| no())?;
            published = true;
            let record = route
                .prepare_file_rename_record(&descriptor)
                .map_err(|_| no())?;
            pins.verify(self, false)?;
            parent.check().map_err(|_| no())?;
            destination_parent.check().map_err(|_| no())?;
            if stop() || !admission.claim_dispatch() {
                return Err(no());
            }
            let dispatch = admission.dispatch_probe();
            let proof = pins.proof()?;
            let verified = joined(|| {
                let cancel = crate::vault_custody::VaultUploadCancellation {
                    generation: generation.clone(),
                    expected: auth.agent_generation,
                    cancelled: &stop,
                };
                let mut before = || {
                    if stop() || !dispatch() {
                        return Err(raiun_core::backend::CloudError::new(
                            raiun_core::backend::ErrorKind::Conflict,
                            "vault MOVE admission changed",
                        ));
                    }
                    proof.check()?;
                    record.claim_send().map_err(|_| {
                        raiun_core::backend::CloudError::new(
                            raiun_core::backend::ErrorKind::Io,
                            "vault MOVE intent unavailable",
                        )
                    })
                };
                match target {
                    Target::File(t) => match route
                        .binding()
                        .send_file_rename(
                            &original,
                            &destination,
                            parent.metadata(),
                            destination_parent.metadata(),
                            t,
                            &cancel,
                            context,
                            &mut before,
                        )
                        .map_err(|_| no())?
                    {
                        raiun_opencloud::vault_backend::VaultFileRenameOutcome::Verified(p) => {
                            Ok(Verified::File(p))
                        }
                        _ => Err(no()),
                    },
                    Target::Directory(t) => match route
                        .binding()
                        .send_directory_rename(
                            &original,
                            &destination,
                            parent.metadata(),
                            destination_parent.metadata(),
                            t,
                            &cancel,
                            context,
                            &mut before,
                        )
                        .map_err(|_| no())?
                    {
                        raiun_opencloud::vault_backend::VaultDirectoryRenameOutcome::Verified(
                            p,
                        ) => Ok(Verified::Directory(p)),
                        _ => Err(no()),
                    },
                }
            })?;
            if !route.binding().file_rename_proof_matches(verified.root()) {
                return Err(no());
            }
            match &verified {
                Verified::File(p) => record.record_remote(p),
                Verified::Directory(p) => record.record_directory_remote(p),
            }
            .map_err(|_| no())?;
            pins.verify(self, false)?;
            parent.check().map_err(|_| no())?;
            destination_parent.check().map_err(|_| no())?;
            let admission = RefCell::new(admission);
            let cancel = crate::vault_custody::VaultUploadCancellation {
                generation: generation.clone(),
                expected: auth.agent_generation,
                cancelled: &stop,
            };
            let mut complete = || {
                let completed = pins.complete(self, opaque, &|| {
                    !stop()
                        && admission
                            .try_borrow_mut()
                            .is_ok_and(|mut a| a.claim_completion())
                })?;
                pins.verify(self, true)?;
                if stop() {
                    return Err(no());
                }
                if !directory {
                    self.rebase_vault_native_file(
                        route,
                        root_id,
                        identity,
                        file,
                        &original,
                        old,
                        new,
                        &destination,
                    )?;
                } else {
                    for n in descriptor
                        .facts
                        .children
                        .as_ref()
                        .ok_or_else(no)?
                        .iter()
                        .filter(|n| !n.original.directory)
                    {
                        let suffix = n
                            .original
                            .path
                            .strip_prefix(&format!("{}/", original.path))
                            .ok_or_else(no)?;
                        let mut old_parts = old.to_vec();
                        old_parts.extend(suffix.split('/').map(str::to_owned));
                        self.rebase_vault_native_file(
                            route,
                            root_id,
                            n.identity,
                            LocalFileIdentity {
                                volume_serial: root_id.volume_serial,
                                file_index: n.file,
                            },
                            &n.original,
                            &old_parts,
                            &n.new_components,
                            &format!("{}/{suffix}", destination),
                        )?;
                    }
                }
                if directory {
                    record.record_directory_native(&completed)
                } else {
                    let (f, u) = completed[0];
                    record.record_native(f, u)
                }
                .map_err(|_| no())
            };
            match &verified {
                Verified::File(p) => route.publish_file_rename(p, identity, &cancel, &mut complete),
                Verified::Directory(p) => {
                    route.publish_directory_rename(p, &rows, &cancel, &mut complete)
                }
            }?;
            Ok(true)
        })();
        if !published || matches!(&result, Ok(true)) {
            unsafe { std::mem::ManuallyDrop::drop(&mut pins) }
        } else {
            tracker.mark_unknown();
        }
        result
    }
    fn rebase_vault_native_file(
        &self,
        route: &crate::vault_placeholder::WindowsVaultPlaceholderBackend,
        root: crate::ConfiguredRootIdentity,
        identity: [u8; 16],
        file: LocalFileIdentity,
        original: &raiun_core::backend::RemoteEntry,
        old: &[String],
        new: &[String],
        destination: &str,
    ) -> Result<(), Error> {
        let no = || Error::EditRecoveryUnavailable;
        self.state
            .hydrated_files
            .lock()
            .map_err(|_| no())?
            .rebase_vault_rename(identity, file.file_index, original.size, old, new)
            .map_err(|_| no())?;
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
            let mut metadata = receipt.original.clone();
            if let Some(e) = metadata.as_mut() {
                if e.id != original.id || e.etag != original.etag || e.path != original.path {
                    return Err(no());
                }
                e.path = destination.to_owned();
            }
            let mut book = self.state.writable_cleanup.lock().map_err(|_| no())?;
            let ticket = book.reserve(identity).map_err(|_| no())?;
            book.publish(
                ticket,
                WritableCleanupReceipt {
                    dispatch: route.binding().capture_dispatch_stamp(),
                    root,
                    identity,
                    file,
                    components: new.to_vec(),
                    length: receipt.length,
                    sha256: receipt.sha256,
                    clean_hydration: receipt.clean_hydration,
                    original: metadata,
                },
            )
            .map_err(|_| no())?;
        }
        Ok(())
    }
}
