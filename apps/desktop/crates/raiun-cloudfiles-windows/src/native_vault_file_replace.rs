//! Encrypted replacement in the ORIGINAL delete callback owner. No restored
//! row, timer, pathname, or local completion can authorize a cloud DELETE.
use super::super::native_file_create::ReplacementBody;
use super::*;
use crate::opencloud::vault_child_create::VaultChildCreateParent;
use crate::vault_file_replace::{
    VaultFileReplaceDescriptor, VaultFileReplaceNativeProof, VaultFileReplaceRemoteProof,
};
use raiun_core::backend::RemoteEntry;
use raiun_vault::session::VaultSessionScope;

pub(super) struct Original {
    pub(super) owner: crate::ProviderScope,
    pub(super) vault: VaultSessionScope,
    pub(super) remote_root: String,
    pub(super) metadata: RemoteEntry,
    pub(super) epoch: u64,
}
/// Owner-thread only, with all original handles/admission still retained.
/// This is a decision locator, NOT a remote-delete/send capability.
pub(super) struct VaultDeleteChoice<'a, 'b> {
    local: Option<Local<'a, 'b>>,
}
impl<'a, 'b> std::ops::Deref for VaultDeleteChoice<'a, 'b> {
    type Target = Local<'a, 'b>;
    fn deref(&self) -> &Self::Target {
        self.local.as_ref().expect("original delete choice")
    }
}
impl std::ops::DerefMut for VaultDeleteChoice<'_, '_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.local.as_mut().expect("original delete choice")
    }
}
impl<'a, 'b> VaultDeleteChoice<'a, 'b> {
    pub(super) fn from_local(local: Local<'a, 'b>) -> Self {
        Self { local: Some(local) }
    }

    pub(super) fn confirm_absence(&self) -> Result<(), Error> {
        if self.classify()?.is_some() {
            return Err(Error::ConfiguredRootChanged);
        }
        self.native_current()
    }
    /// Called by the conditional cloud-delete owner only after its actual
    /// absence/readback/native completion proof; failure retains original pins.
    pub(super) fn release_completed(mut self) -> Result<(), Error> {
        self.confirm_absence()?;
        let local = self.local.as_mut().ok_or(Error::EditRecoveryUnavailable)?;
        local.terminal = true;
        drop(self.local.take());
        Ok(())
    }
}
impl Drop for VaultDeleteChoice<'_, '_> {
    fn drop(&mut self) {
        if let Some(local) = self.local.take() {
            if (local.acknowledged || local.published) && !local.terminal {
                std::mem::forget(local);
            }
        }
    }
}
pub(super) struct Local<'a, 'b> {
    pub(super) shared: &'a Arc<Shared>,
    pub(super) ticket: &'a Ticket,
    pub(super) state: &'a Arc<CallbackState>,
    pub(super) admission: &'a RefCell<SaveRenameTicket<'b>>,
    pub(super) parent: Arc<VaultChildCreateParent>,
    pub(super) root: RootInspectionLease,
    pub(super) parent_pin: RawOwnedHandle,
    pub(super) parent_snapshot: RootSnapshot,
    pub(super) ancestors: Vec<(RawOwnedHandle, RootSnapshot)>,
    pub(super) leaf: Option<RawOwnedHandle>,
    pub(super) original_snapshot: RootSnapshot,
    pub(super) original_usn: i64,
    pub(super) original: Original,
    pub(super) components: Vec<String>,
    pub(super) job: crate::StreamedRecoveryJob,
    pub(super) acknowledged: bool,
    pub(super) removed: bool,
    pub(super) terminal: bool,
    pub(super) published: bool,
}
pub(super) struct Custody<'a, 'b>(pub(super) Option<Local<'a, 'b>>);
impl<'a, 'b> std::ops::Deref for Custody<'a, 'b> {
    type Target = Local<'a, 'b>;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref().expect("owned original vault delete")
    }
}
impl std::ops::DerefMut for Custody<'_, '_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut().expect("owned original vault delete")
    }
}
impl Drop for Custody<'_, '_> {
    fn drop(&mut self) {
        if let Some(local) = self.0.take() {
            if (local.acknowledged || local.published) && !local.terminal {
                std::mem::forget(local);
            }
        }
    }
}
struct Body(Option<ReplacementBody>);
impl std::ops::Deref for Body {
    type Target = ReplacementBody;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref().expect("owned replacement body")
    }
}
impl Body {
    fn release(mut self) {
        drop(self.0.take());
    }
}
impl Drop for Body {
    fn drop(&mut self) {
        if let Some(body) = self.0.take() {
            std::mem::forget(body);
        }
    }
}

// These original metadata pins were opened WITHOUT OVERLAPPED. Use the same
// bounded synchronous USN query as native_plain_file_capture, with a real byte
// counter and NULL OVERLAPPED. Never apply async completion to a sync handle.
pub(super) fn metadata_usn(handle: Handle, file: u64) -> Result<i64, Error> {
    let mut storage = [0u64; 8192];
    let mut returned = 0u32;
    if unsafe {
        DeviceIoControl(
            handle,
            0x0009_00eb,
            null(),
            0,
            storage.as_mut_ptr().cast(),
            65536,
            &mut returned,
            null_mut(),
        )
    } == 0
    {
        return Err(win32_io_error("read replacement metadata USN"));
    }
    if !(60..=65536).contains(&returned) {
        return Err(Error::EditRecoveryUnavailable);
    }
    let bytes =
        unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), returned as usize) };
    decode_file_usn_record(bytes, file).ok_or(Error::EditRecoveryUnavailable)
}
impl Local<'_, '_> {
    pub(super) fn original_owner(&self) -> &crate::ProviderScope {
        &self.original.owner
    }
    pub(super) fn original_vault(&self) -> &VaultSessionScope {
        &self.original.vault
    }
    pub(super) fn original_remote_root(&self) -> &str {
        &self.original.remote_root
    }
    pub(super) fn original_metadata(&self) -> &RemoteEntry {
        &self.original.metadata
    }
    pub(super) fn original_epoch(&self) -> u64 {
        self.original.epoch
    }
    /// Pure original cancellation only. Safe inside SDK crypto epoch fences.
    pub(super) fn stopped(&self) -> bool {
        self.job.is_stopped() || !self.shared.live(self.ticket) || self.parent.is_stopped()
    }
    /// Native-only postproof: never acquire route/token/epoch/catalogue locks.
    pub(super) fn native_current(&self) -> Result<(), Error> {
        if self.stopped()
            || !self.admission.borrow().is_current()
            || self
                .state
                .unverifiable_placeholder_closes
                .load(Ordering::Acquire)
                != 0
        {
            return Err(Error::EditRecoveryUnavailable);
        }
        native_namespace_directory::verify_reinspected_namespace_root(
            &self.root,
            self.state
                .root_path
                .as_deref()
                .ok_or(Error::ConfiguredRootChanged)?,
        )?;
        let activity = self
            .state
            .activity
            .try_lock()
            .map_err(|_| Error::EditRecoveryUnavailable)?;
        if activity.active_fetches != 0 || activity.staged_fetches != 0 {
            return Err(Error::EditRecoveryUnavailable);
        }
        drop(activity);
        let now = root_snapshot(self.parent_pin.0)?;
        if now.identity != self.parent_snapshot.identity
            || now.reparse_tag != self.parent_snapshot.reparse_tag
            || now.file_attributes != self.parent_snapshot.file_attributes
        {
            return Err(Error::ConfiguredRootChanged);
        }
        for (handle, old) in &self.ancestors {
            let now = root_snapshot(handle.0)?;
            if now.identity != old.identity
                || now.reparse_tag != old.reparse_tag
                || now.file_attributes != old.file_attributes
            {
                return Err(Error::ConfiguredRootChanged);
            }
        }
        if self.removed {
            let inner = self
                .shared
                .inner
                .lock()
                .map_err(|_| Error::EditRecoveryUnavailable)?;
            let slot = inner
                .slot
                .as_ref()
                .filter(|s| s.ticket.key == self.ticket.key)
                .ok_or(Error::EditRecoveryUnavailable)?;
            if !slot.ack_success || !slot.completed {
                return Err(Error::EditRecoveryUnavailable);
            }
        }
        Ok(())
    }
    pub(super) fn parent_current_usn(&self) -> Result<i64, Error> {
        self.native_current()?;
        metadata_usn(self.parent_pin.0, self.parent_native_file()?.file_index)
    }
    pub(super) fn parent_native_file(&self) -> Result<LocalFileIdentity, Error> {
        Ok(LocalFileIdentity {
            volume_serial: self.parent_snapshot.identity.volume_serial,
            file_index: self.parent_snapshot.identity.file_index,
        })
    }
    pub(super) fn original_current(&self) -> Result<(), Error> {
        self.native_current()?;
        self.parent
            .check()
            .map_err(|_| Error::ProviderUnavailable)?;
        let leaf = self.leaf.as_ref().ok_or(Error::EditRecoveryUnavailable)?;
        let now = root_snapshot(leaf.0)?;
        let mut links: ByHandleFileInformation = unsafe { zeroed() };
        if unsafe { GetFileInformationByHandle(leaf.0, &mut links) } == 0
            || links.number_of_links != 1
            || !same_edit_snapshot(self.original_snapshot, now)
            || now.identity.file_index != self.ticket.key.file
            || now.identity.volume_serial != self.ticket.key.volume
            || now.file_size != self.ticket.size
            || (now.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0)
                != (self.ticket.kind == NamespaceObjectKind::Directory)
            || (self.ticket.kind == NamespaceObjectKind::File && now.file_attributes & 1 != 0)
            || now.placeholder_state & CF_PLACEHOLDER_STATE_PLACEHOLDER == 0
            || now.placeholder_state & CF_PLACEHOLDER_STATE_IN_SYNC == 0
            || native_namespace_directory::opaque_directory_identity(leaf.0)?
                != self.ticket.key.identity
            || (self.ticket.kind == NamespaceObjectKind::File
                && modified_ranges_for_handle(leaf.0)
                    .map_err(|_| Error::EditRecoveryUnavailable)?)
            || (self.ticket.kind == NamespaceObjectKind::Directory && !physically_empty(leaf.0)?)
            || metadata_usn(leaf.0, self.ticket.key.file)? != self.original_usn
            || !windows_paths_equal(
                &final_path_for_handle(leaf.0).map_err(|_| Error::ConfiguredRootChanged)?,
                &self.ticket.path,
            )
            || self
                .state
                .vault_dirty
                .lock()
                .map_err(|_| Error::EditRecoveryUnavailable)?
                .has_pending()
        {
            return Err(Error::EditRecoveryUnavailable);
        }
        Ok(())
    }
    pub(super) fn allow_and_wait(&mut self) -> Result<(), Error> {
        self.original_current()?;
        if !ack_once(self.shared, self.ticket, true) {
            return Err(Error::EditRecoveryUnavailable);
        }
        self.acknowledged = true;
        self.ticket
            .post_ack_job
            .set(self.job.clone())
            .map_err(|_| Error::EditRecoveryUnavailable)?;
        self.leaf.take();
        loop {
            if self.stopped() {
                return Err(Error::EditRecoveryUnavailable);
            }
            let mut inner = self
                .shared
                .inner
                .lock()
                .map_err(|_| Error::EditRecoveryUnavailable)?;
            let slot = inner
                .slot
                .as_mut()
                .filter(|s| s.ticket.key == self.ticket.key)
                .ok_or(Error::EditRecoveryUnavailable)?;
            if slot.ack_success && slot.completed {
                let deferred = std::mem::take(&mut slot.deferred);
                drop(inner);
                if deferred
                    .into_iter()
                    .any(|c| !c.finish_after_owned_completion())
                {
                    return Err(Error::EditRecoveryUnavailable);
                }
                self.removed = true;
                return self.native_current();
            }
            let (guard, _) = self
                .shared
                .changed
                .wait_timeout(inner, Duration::from_millis(20))
                .map_err(|_| Error::EditRecoveryUnavailable)?;
            drop(guard);
        }
    }
    /// Actual same-name absence or fresh distinct plain FileID, under retained
    /// original root/parent ownership. No timeout or cached name is a result.
    fn classify(&self) -> Result<Option<LocalFileIdentity>, Error> {
        self.native_current()?;
        let path = wide_path(&self.ticket.path)?;
        let raw = unsafe {
            CreateFileW(
                path.as_ptr(),
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
                Err(win32_io_error("classify original vault replacement"))
            };
        }
        let leaf = RawOwnedHandle(raw);
        let now = root_snapshot(leaf.0)?;
        let mut links: ByHandleFileInformation = unsafe { zeroed() };
        if unsafe { GetFileInformationByHandle(leaf.0, &mut links) } == 0
            || links.number_of_links != 1
            || now.identity.volume_serial != self.shared.root.volume_serial
            || now.identity.file_index == 0
            || now.identity.file_index == self.ticket.key.file
            || now.file_attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
            || now.placeholder_state != 0
            || now.reparse_tag != 0
            || !windows_paths_equal(
                &final_path_for_handle(leaf.0).map_err(|_| Error::ConfiguredRootChanged)?,
                &self.ticket.path,
            )
        {
            return Err(Error::ConfiguredRootChanged);
        }
        self.native_current()?;
        Ok(Some(LocalFileIdentity {
            volume_serial: now.identity.volume_serial,
            file_index: now.identity.file_index,
        }))
    }
}

/// Called BEFORE the ordinary classifier. None is proven ordinary ancestry;
/// a locked/unknown encrypted location must never fall through to plain writes.
pub(super) fn try_execute<'a, 'b>(
    shared: &'a Arc<Shared>,
    ticket: &'a Ticket,
    state: &'a Arc<CallbackState>,
    admission: &'a RefCell<SaveRenameTicket<'b>>,
    parents: &[String],
    name: &str,
) -> Result<Option<FileDeleteOutcome>, Error> {
    let refs = parents.iter().map(String::as_str).collect::<Vec<_>>();
    let Some(generation) = shared.config.generation.as_ref() else {
        shared
            .backend
            .capture_namespace_parent(&refs, shared.root, shared.config.authorization)
            .map_err(|_| Error::ProviderUnavailable)?;
        return Ok(None);
    };
    let weak = Arc::downgrade(&shared.backend);
    let closed = shared.closed.clone();
    let current = shared.config.current.clone();
    let auth = shared.config.authorization;
    let job = CancellationToken::for_recovery_job(crate::StreamedRecoveryPolicy::default())
        .with_revocation_check(Arc::new(move || {
            closed.load(Ordering::Acquire)
                || !current(auth)
                || weak.upgrade().is_none_or(|b| b.is_revoked())
        }));
    let parent = shared
        .backend
        .capture_vault_child_create_parent(
            parents,
            shared.root,
            auth,
            &job,
            shared.config.current.clone(),
            generation.clone(),
        )
        .map_err(|_| Error::ProviderUnavailable)?;
    let Some(parent) = parent else {
        return Ok(None);
    };
    if ticket.kind == NamespaceObjectKind::Directory {
        return super::vault_directory_delete::execute(
            shared, ticket, state, admission, parents, name, parent, job,
        )
        .map(Some);
    }
    if ticket.kind != NamespaceObjectKind::File
        || !parent.vault().backend().existing_file_saves_active()
    {
        return Err(Error::EditRecoveryUnavailable);
    }
    let mut original = None;
    parent
        .vault()
        .backend()
        .with_vault_edit_capture(&ticket.key.identity, &mut |capture| {
            let b = capture.baseline();
            if b.root() != shared.root
                || b.identity() != ticket.key.identity
                || b.metadata().size != ticket.size
            {
                return Err(BackendError::Unavailable);
            }
            original = Some(Original {
                owner: b.owner().clone(),
                vault: b.vault().clone(),
                remote_root: b.remote_root().to_owned(),
                metadata: b.metadata().clone(),
                epoch: b.unlock_epoch(),
            });
            Ok(())
        })
        .map_err(|_| Error::ProviderUnavailable)?;
    let original = original.ok_or(Error::ProviderUnavailable)?;
    if original.metadata.path
        != format!("{}/{}", parent.metadata().path.trim_end_matches('/'), name)
    {
        return Err(Error::ConfiguredRootChanged);
    }
    let path = state
        .root_path
        .as_ref()
        .ok_or(Error::ConfiguredRootChanged)?;
    let root = pin_registered_configured_root(path, shared.root)?;
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
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(win32_io_error("pin original encrypted replacement"));
    }
    let leaf = RawOwnedHandle(raw);
    let original_snapshot = root_snapshot(leaf.0)?;
    let original_usn = metadata_usn(leaf.0, ticket.key.file)?;
    if parent_snapshot.identity.file_index == 0 {
        return Err(Error::ConfiguredRootChanged);
    }
    let mut components = parents.to_vec();
    components.push(name.to_owned());
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
        original_snapshot,
        original_usn,
        original,
        components,
        job,
        acknowledged: false,
        removed: false,
        terminal: false,
        published: false,
    }));
    local.allow_and_wait()?;
    let Some(new_file) = local.classify()? else {
        // Only this original owner may consume the fresh absence decision.
        let choice = VaultDeleteChoice {
            local: Some(local.0.take().ok_or(Error::EditRecoveryUnavailable)?),
        };
        return super::vault_delete::execute(choice).map(Some);
    };
    replace(&mut local, new_file)?;
    local.terminal = true;
    Ok(Some(FileDeleteOutcome::Completed))
}

fn replace(local: &mut Local<'_, '_>, new_file: LocalFileIdentity) -> Result<(), Error> {
    local.native_current()?;
    local
        .parent
        .check()
        .map_err(|_| Error::ProviderUnavailable)?;
    let generation = local
        .shared
        .config
        .generation
        .as_ref()
        .ok_or(Error::EditRecoveryUnavailable)?
        .clone();
    let (probe, lifetime) = local
        .admission
        .borrow()
        .dispatch_probe(local.state.close_capture_admission.clone())
        .ok_or(Error::EditRecoveryUnavailable)?;
    let observation = lifetime.observation_probe();
    let job = local
        .job
        .with_revocation_check(Arc::new(move || !observation()));
    let stopped = || job.is_stopped() || local.stopped();
    let parent_native = local.parent_native_file()?;
    let parent_usn = metadata_usn(local.parent_pin.0, parent_native.file_index)?;
    let (body, staged) = ReplacementBody::capture_with_usn(
        &local.ticket.path,
        local.ticket.key.volume,
        local.ticket.key.file,
        &job,
        &stopped,
        |reader, snapshot, usn| {
            if snapshot.identity.volume_serial != new_file.volume_serial
                || snapshot.identity.file_index != new_file.file_index
            {
                return Err(Error::ConfiguredRootChanged);
            }
            let d = VaultFileReplaceDescriptor {
                owner: local.original.owner.clone(),
                vault: local.original.vault.clone(),
                remote_root: local.original.remote_root.clone(),
                root: local.shared.root,
                original_identity: local.ticket.key.identity,
                original: local.original.metadata.clone(),
                parent_identity: *local.parent.opaque().as_bytes(),
                parent: local.parent.metadata().clone(),
                historical_unlock_epoch: local.original.epoch,
                original_file: LocalFileIdentity {
                    volume_serial: local.ticket.key.volume,
                    file_index: local.ticket.key.file,
                },
                original_usn: local.original_usn,
                parent_file: parent_native,
                parent_usn,
                replacement_file: new_file,
                replacement_usn: usn,
                components: local.components.clone(),
                plaintext_len: snapshot.file_size,
            };
            d.validate().map_err(|_| Error::EditRecoveryUnavailable)?;
            let capture = local
                .parent
                .vault()
                .backend()
                .begin_file_replace(&d)
                .map_err(|_| Error::EditRecoveryUnavailable)?;
            let staged = capture
                .stage(reader, &stopped)
                .map_err(|_| Error::EditRecoveryUnavailable)?;
            Ok((d, staged))
        },
    )?;
    let body = Body(Some(body));
    local.native_current()?;
    body.check(&job, &stopped)?;
    let (descriptor, staged) = staged;
    let record = staged
        .commit(
            body.sha256(),
            &mut || {
                local
                    .native_current()
                    .map_err(|_| BackendError::Unavailable)?;
                body.check(&job, &stopped)
                    .map_err(|_| BackendError::Unavailable)
            },
            &stopped,
        )
        .map_err(|_| Error::EditRecoveryUnavailable)?;
    if record.descriptor().facts() != descriptor.facts()
        || record.plaintext_sha256() != body.sha256()
        || body.len() != descriptor.plaintext_len
        || body.usn() != descriptor.replacement_usn
    {
        return Err(Error::EditRecoveryUnavailable);
    }
    let dirty = {
        let mut dirty = local
            .state
            .vault_dirty
            .lock()
            .map_err(|_| Error::EditRecoveryUnavailable)?;
        dirty
            .record(
                descriptor.original_identity,
                new_file,
                body.len(),
                body.sha256(),
                descriptor.components.clone(),
            )
            .map_err(|_| Error::EditRecoveryUnavailable)?;
        dirty
            .snapshot(&descriptor.original_identity)
            .map_err(|_| Error::EditRecoveryUnavailable)?
    };
    if !local.admission.borrow_mut().claim_dispatch() || !lifetime.arm_after_dispatch() {
        return Err(Error::EditRecoveryUnavailable);
    }
    let job = job.with_revocation_check(Arc::new(move || !probe()));
    let stopped = || job.is_stopped() || local.stopped();
    let reader_stop: Arc<dyn Fn() -> bool + Send + Sync> = {
        let job = job.clone();
        let owner = local.shared.clone();
        let original = local.ticket.clone();
        let route = local.parent.clone();
        Arc::new(move || job.is_stopped() || !owner.live(&original) || route.is_stopped())
    };
    let mut reader = record
        .open_reader(reader_stop)
        .map_err(|_| Error::EditRecoveryUnavailable)?;
    let target = crate::ExistingVaultUploadTarget::new(
        descriptor.owner.clone(),
        descriptor.vault.clone(),
        descriptor.remote_root.clone(),
        descriptor.root,
        descriptor.original_identity,
        descriptor.original.clone(),
    )
    .map_err(|_| Error::EditRecoveryUnavailable)?
    .with_fresh_dispatch(
        local
            .parent
            .vault()
            .backend()
            .binding()
            .capture_dispatch_stamp(),
    );
    local.native_current()?;
    body.check(&job, &stopped)?;
    record
        .claim_send()
        .map_err(|_| Error::EditRecoveryUnavailable)?;
    let verified = match local
        .shared
        .backend
        .upload_existing_vault_streamed_capture(
            &target,
            &mut reader,
            body.len(),
            body.sha256(),
            generation.clone(),
            local.shared.config.authorization.agent_generation,
            &stopped,
        )
        .map_err(|_| Error::EditRecoveryUnavailable)?
    {
        raiun_opencloud::vault_backend::VaultExistingOverwriteOutcome::Verified(proof) => proof,
        raiun_opencloud::vault_backend::VaultExistingOverwriteOutcome::NeedsReconciliation {
            ..
        } => return Err(Error::EditRecoveryUnavailable),
    };
    if verified.plaintext_sha256() != body.sha256()
        || verified.entry().id != descriptor.original.id
        || verified.entry().path != descriptor.original.path
        || verified.entry().size != body.len()
    {
        return Err(Error::EditRecoveryUnavailable);
    }
    let proof = VaultFileReplaceRemoteProof {
        descriptor,
        target,
        verified,
    };
    record
        .record_remote(&proof)
        .map_err(|_| Error::EditRecoveryUnavailable)?;
    local.native_current()?;
    body.check(&job, &stopped)?;
    let cancellation = crate::vault_custody::VaultUploadCancellation {
        generation,
        expected: local.shared.config.authorization.agent_generation,
        cancelled: &stopped,
    };
    local
        .parent
        .vault()
        .backend()
        .publish_file_replacement(&proof, &cancellation, || {
            local.native_current()?;
            body.check(&job, &stopped)?;
            let d = proof.descriptor();
            let cleanup = local
                .state
                .writable_cleanup
                .lock()
                .map_err(|_| Error::EditRecoveryUnavailable)?
                .reserve(d.original_identity)
                .map_err(|_| Error::EditRecoveryUnavailable)?;
            body.convert(&d.original_identity, &job, &stopped, || {
                local.admission.borrow_mut().claim_completion()
            })?;
            local.native_current()?;
            let completed = VaultFileReplaceNativeProof {
                descriptor: d.clone(),
                completed_usn: body.completed_usn(&d.original_identity)?,
                plaintext_sha256: body.sha256(),
            };
            record
                .record_native_completed(&completed)
                .map_err(|_| Error::EditRecoveryUnavailable)?;
            local
                .state
                .hydrated_files
                .lock()
                .map_err(|_| Error::EditRecoveryUnavailable)?
                .replace_verified(
                    d.original_identity,
                    d.original_file.file_index,
                    d.replacement_file.file_index,
                    d.original.size,
                    d.plaintext_len,
                    &d.components,
                )
                .map_err(|_| Error::EditRecoveryUnavailable)?;
            let mut original = proof.entry().clone();
            original.writable = false;
            local
                .state
                .writable_cleanup
                .lock()
                .map_err(|_| Error::EditRecoveryUnavailable)?
                .publish(
                    cleanup,
                    WritableCleanupReceipt {
                        dispatch: local
                            .parent
                            .vault()
                            .backend()
                            .binding()
                            .capture_dispatch_stamp(),
                        root: d.root,
                        identity: d.original_identity,
                        file: new_file,
                        components: d.components.clone(),
                        length: d.plaintext_len,
                        sha256: body.sha256(),
                        clean_hydration: false,
                        original: Some(original),
                    },
                )
                .map_err(|_| Error::EditRecoveryUnavailable)?;

            local
                .state
                .vault_dirty
                .lock()
                .map_err(|_| Error::EditRecoveryUnavailable)?
                .resolve(&dirty)
                .map_err(|_| Error::EditRecoveryUnavailable)?;
            Ok(())
        })?;
    let mut inner = local
        .shared
        .inner
        .lock()
        .map_err(|_| Error::EditRecoveryUnavailable)?;
    if inner.replacements.len() >= 64 {
        inner.replacements.remove(0);
    }
    inner.replacements.push(replacement::CompletedReplacement {
        path: local.ticket.path.clone(),
        file: body.local_file(),
        identity: local.ticket.key.identity,
    });
    drop(inner);
    body.release();
    Ok(())
}
