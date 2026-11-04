//! Exact clean-file cross-parent move in one managed Space/root.
//! Both parents, the moved original FileID and full content stay pinned through publication.
use super::*;
use crate::NativeFileRenameError as N;
use crate::namespace_file_rename::{
    FileRenameCompletionError, FileRenameLocal, FileRenameOutcome, FileRenameReadback,
    reconcile_file_rename,
};
use crate::namespace_intent::{
    CapturedAuthorization, ExistingNamespaceEntry, LocalNamespaceEntry, NamespaceIntent,
    NamespaceObjectKind, NamespaceOperation, NamespaceParent, StorageClassification,
};
use crate::opencloud::{FileMoveBinding, FileMoveSession};
use crate::save_rename_admission::{GuardedLocal, GuardedRemote, SaveRenameAdmission};
use crate::streamed_store::namespace_rename_store::FileRenamePublishResult;
use raiun_control_windows::directory_notifications::directory_rename_hints::RenameHintPair;
use std::cell::RefCell;

fn absent(path: &Path) -> Result<bool, Error> {
    let wide = wide_path(path)?;
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
    if !raw.is_null() && raw != INVALID_HANDLE_VALUE {
        drop(RawOwnedHandle(raw));
        return Ok(false);
    }
    if unsafe { GetLastError() } == 2 {
        Ok(true)
    } else {
        Err(win32_io_error("verify original move source absence"))
    }
}
struct Pins<'a> {
    connection: &'a ConfiguredRootConnection,
    parent: RawOwnedHandle,
    parent_snapshot: RootSnapshot,
    destination_parent: RawOwnedHandle,
    destination_parent_snapshot: RootSnapshot,
    destination_ancestors: Vec<(RawOwnedHandle, RootSnapshot)>,
    destination_parent_identity: crate::OpaqueIdentity,
    digest: Option<[u8; 32]>,
    cancellation: crate::CancellationToken,
    ancestors: Vec<(RawOwnedHandle, RootSnapshot)>,
    protected: ProtectedCompletionFile,
    snapshot: RootSnapshot,
    basic: FileBasicInfo,
    usn: i64,
    root: RootIdentity,
    root_path: PathBuf,
    old: PathBuf,
    new: PathBuf,
    source_identity: crate::OpaqueIdentity,
    current_identity: [u8; 16],
    parent_identity: crate::OpaqueIdentity,
    updated: bool,
}
impl Pins<'_> {
    fn check(&self, identity: &[u8; 16], enumerate: bool) -> Result<(), Error> {
        let root = self
            .connection
            .root
            .as_ref()
            .ok_or(Error::ConfiguredRootChanged)?;
        root.verify_identity(true)?;
        root.verify_registered()?;
        if !self.connection.connected
            || self.connection.state.readiness.load(Ordering::Acquire) != CALLBACK_READY
            || self
                .connection
                .state
                .unverifiable_placeholder_closes
                .load(Ordering::Acquire)
                != 0
            || !windows_paths_equal(&root.path, &self.root_path)
            || root.identity != self.root
            || !same_snapshot(root_snapshot(self.parent.0)?, self.parent_snapshot)
            || native_namespace_directory::opaque_directory_identity(self.parent.0)?
                != *self.parent_identity.as_bytes()
            || !same_snapshot(
                root_snapshot(self.destination_parent.0)?,
                self.destination_parent_snapshot,
            )
            || native_namespace_directory::opaque_directory_identity(self.destination_parent.0)?
                != *self.destination_parent_identity.as_bytes()
            || modified_ranges_for_handle(self.protected.raw)
                .map_err(|_| Error::EditRecoveryUnavailable)?
            || !file_links(self.protected.raw, self.snapshot.identity)?
            || !absent(&self.old)?
            || !windows_paths_equal(
                &final_path_for_handle(self.protected.raw)
                    .map_err(|_| Error::ConfiguredRootChanged)?,
                &self.new,
            )
            || native_namespace_directory::opaque_directory_identity(self.protected.raw)?
                != *identity
            || (self.digest.is_none()
                && !clean_cloud_only_entry(
                    root_snapshot(self.protected.raw)?,
                    self.root,
                    LocalFileIdentity {
                        volume_serial: self.snapshot.identity.volume_serial,
                        file_index: self.snapshot.identity.file_index,
                    },
                    self.snapshot.file_size,
                ))
            || !same_snapshot(root_snapshot(self.protected.raw)?, self.snapshot)
            || completion_usn(self.protected.raw, self.snapshot.identity.file_index)? != self.usn
            || completion_basic_info(self.protected.raw)? != self.basic
        {
            return Err(Error::ConfiguredRootChanged);
        }
        for (handle, snapshot) in self.ancestors.iter().chain(&self.destination_ancestors) {
            if !same_snapshot(root_snapshot(handle.0)?, *snapshot) {
                return Err(Error::ConfiguredRootChanged);
            }
        }
        let activity = self
            .connection
            .state
            .activity
            .try_lock()
            .map_err(|_| Error::EditRecoveryUnavailable)?;
        if activity.active_fetches != 0 || activity.staged_fetches != 0 {
            return Err(Error::EditRecoveryUnavailable);
        }
        drop(activity);
        if let Some(expected_digest) = self.digest.filter(|_| enumerate) {
            let digest = native_digest(
                &self
                    .protected
                    .digest_complete(self.snapshot.file_size, Some(&self.cancellation))?,
            )?;
            if digest != expected_digest
                || !same_snapshot(root_snapshot(self.protected.raw)?, self.snapshot)
                || completion_usn(self.protected.raw, self.snapshot.identity.file_index)?
                    != self.usn
                || completion_basic_info(self.protected.raw)? != self.basic
            {
                return Err(Error::ConfiguredRootChanged);
            }
        }

        Ok(())
    }
}
struct Local<'p, 's, 'b> {
    pins: &'p RefCell<Pins<'b>>,
    session: &'s FileMoveSession<'s>,
}
impl FileRenameLocal for Local<'_, '_, '_> {
    fn admit(&mut self, _: &NamespaceIntent) -> Result<(), CloudError> {
        let pins = self.pins.try_borrow().map_err(|_| conflict())?;
        pins.check(pins.source_identity.as_bytes(), false)
            .map_err(|_| conflict())
    }
    fn record_completion<F>(
        &mut self,
        _: &NamespaceIntent,
        readback: &FileRenameReadback,
        record: F,
    ) -> Result<(), FileRenameCompletionError>
    where
        F: FnOnce() -> Result<(), crate::streamed_store::StoreError>,
    {
        use FileRenameCompletionError as E;
        {
            let pins = self.pins.try_borrow().map_err(|_| E::Unavailable)?;
            if pins.updated {
                return Err(E::Uncertain);
            }
            pins.check(pins.source_identity.as_bytes(), true)
                .map_err(|_| E::Unavailable)?;
        } // No pin borrow spans session metadata/publication entry.

        self.session.publish_completion(
            readback,
            |identity| {
                let mut pins = self.pins.try_borrow_mut().map_err(|_| E::Unavailable)?;
                pins.check(pins.source_identity.as_bytes(), false)
                    .map_err(|_| E::Unavailable)?;
                let before = pins.snapshot;
                let basic = pins.basic;
                let mut usn = pins.usn;
                pins.updated = true;
                // Exact referenced file, positive original USN CAS; metadata and
                // ranges NULL. MARK_IN_SYNC only; full body/hash is independently retained.
                let hr = unsafe {
                    CfUpdatePlaceholder(
                        pins.protected.protected,
                        null(),
                        identity.as_ptr().cast(),
                        16,
                        null(),
                        0,
                        if pins.digest.is_some() { 2 } else { 0 },
                        &mut usn,
                        null_mut(),
                    )
                };
                if hr < 0 || usn <= 0 {
                    return Err(E::Uncertain);
                }
                let after = root_snapshot(pins.protected.raw).map_err(|_| E::Uncertain)?;
                let after_basic =
                    completion_basic_info(pins.protected.raw).map_err(|_| E::Uncertain)?;
                if after.identity != before.identity
                    || after.file_attributes != before.file_attributes
                    || after.reparse_tag != before.reparse_tag
                    || after.file_size != before.file_size
                    || after.last_write_time != before.last_write_time
                    || after.placeholder_state
                        != (before.placeholder_state | CF_PLACEHOLDER_STATE_IN_SYNC)
                    || after_basic.creation_time != basic.creation_time
                    || after_basic.last_access_time != basic.last_access_time
                    || after_basic.last_write_time != basic.last_write_time
                    || after_basic.file_attributes != basic.file_attributes
                    || after_basic.change_time < basic.change_time
                {
                    return Err(E::Uncertain);
                }
                pins.snapshot = after;
                pins.basic = after_basic;
                pins.usn = usn;
                pins.current_identity = *identity;
                pins.check(identity, true).map_err(|_| E::Uncertain)
            },
            record,
        )
    }
}
impl crate::ConfiguredRootConnection {
    /// One current already-observed clean-file move. Native facts and both
    /// fresh parents admit it; notification paths alone grant no authority.
    #[allow(clippy::too_many_arguments)]
    pub fn reconcile_fresh_file_move(
        &self,
        backend: &Arc<crate::OpenCloudPlaceholderBackend>,
        pair: RenameHintPair<'_>,
        file: LocalFileIdentity,
        auth: CapturedAuthorization,
        generation: u64,
        current: &dyn Fn(CapturedAuthorization) -> bool,
    ) -> Result<FileRenameOutcome, N> {
        let (tracker, recovery) = self
            .inner
            .file_rename_guard_context(backend)
            .map_err(N::Local)?;
        let admission = SaveRenameAdmission::new(
            tracker
                .try_begin_rename()
                .ok_or(N::DeferredBeforePublication)?,
        );
        let clean = |whole| {
            admission.probe_clean(|| {
                if whole && recovery.has_unresolved()? {
                    return Ok(true);
                }
                recovery.has_unresolved_content_authenticated_legacy()
            })
        };
        if !clean(true) || generation == 0 || !current(auth) {
            return Err(N::DeferredBeforePublication);
        }
        let guarded = |a| admission.check().is_ok() && current(a);
        let old = pair.old_components().to_vec();
        let new = pair.new_components().to_vec();
        if old.iter().chain(&new).any(|part| !valid_component(part)) {
            return Err(N::Local(Error::ConfiguredRootChanged));
        }
        let binding: FileMoveBinding = backend
            .prepare_file_move(
                pair,
                crate::ConfiguredRootIdentity {
                    volume_serial: self
                        .inner
                        .root
                        .as_ref()
                        .ok_or(N::Local(Error::ConfiguredRootChanged))?
                        .identity
                        .volume_serial,
                    file_index: self
                        .inner
                        .root
                        .as_ref()
                        .ok_or(N::Local(Error::ConfiguredRootChanged))?
                        .identity
                        .file_index,
                },
                auth,
                &guarded,
            )
            .map_err(N::Backend)?;
        let root = self
            .inner
            .root
            .as_ref()
            .ok_or(N::Local(Error::ConfiguredRootChanged))?;
        let refs = old[..old.len() - 1]
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let (parent, parent_snapshot, ancestors) =
            native_namespace_directory::pin_namespace_parent(
                root,
                &binding.parent.route,
                binding.parent.identity,
                &refs,
                FILE_READ_ATTRIBUTES,
            )
            .map_err(N::Local)?;
        let destination_refs = new[..new.len() - 1]
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let (destination_parent, destination_parent_snapshot, destination_ancestors) =
            native_namespace_directory::pin_namespace_parent(
                root,
                &binding.destination_parent.route,
                binding.destination_parent.identity,
                &destination_refs,
                FILE_READ_ATTRIBUTES,
            )
            .map_err(N::Local)?;
        let source_path = old.iter().fold(root.path.clone(), |p, c| p.join(c));
        let destination_path = new.iter().fold(root.path.clone(), |p, c| p.join(c));
        let protected =
            ProtectedCompletionFile::open(&wide_path(&destination_path).map_err(N::Local)?)
                .map_err(N::Local)?;
        let snapshot = root_snapshot(protected.raw).map_err(N::Local)?;
        if !admitted_file_entry(
            snapshot,
            root.identity,
            file,
            binding.source_remote.byte_len,
        ) || !file_links(protected.raw, snapshot.identity).map_err(N::Local)?
            || modified_ranges_for_handle(protected.raw)
                .map_err(|_| N::Local(Error::EditRecoveryUnavailable))?
        {
            return Err(N::Local(Error::ConfiguredRootChanged));
        }
        verify_completion_identity(protected.raw, binding.source_identity.as_bytes())
            .map_err(N::Local)?;
        let cancellation = crate::CancellationToken::with_timeout(
            binding
                .deadline()
                .checked_duration_since(std::time::Instant::now())
                .ok_or(N::Local(Error::EditRecoveryUnavailable))?,
        );
        let digest = if clean_cloud_only_entry(
            snapshot,
            root.identity,
            file,
            binding.source_remote.byte_len,
        ) {
            None
        } else {
            Some(
                native_digest(
                    &protected
                        .digest_complete(binding.source_remote.byte_len, Some(&cancellation))
                        .map_err(N::Local)?,
                )
                .map_err(N::Local)?,
            )
        };
        let basic = completion_basic_info(protected.raw).map_err(N::Local)?;
        let usn = completion_usn(protected.raw, file.file_index).map_err(N::Local)?;
        if usn <= 0 {
            return Err(N::Local(Error::EditRecoveryUnavailable));
        }
        let pins = RefCell::new(Pins {
            connection: &self.inner,
            parent,
            parent_snapshot,
            destination_parent,
            destination_parent_snapshot,
            destination_ancestors,
            destination_parent_identity: binding.destination_parent.identity,
            digest,
            cancellation,
            ancestors,
            protected,
            snapshot,
            basic,
            usn,
            root: root.identity,
            root_path: root.path.clone(),
            old: source_path,
            new: destination_path,
            source_identity: binding.source_identity,
            current_identity: *binding.source_identity.as_bytes(),
            parent_identity: binding.parent.identity,
            updated: false,
        });
        pins.borrow()
            .check(binding.source_identity.as_bytes(), true)
            .map_err(N::Local)?;
        let pinned_current = |a| {
            guarded(a)
                && pins
                    .try_borrow()
                    .is_ok_and(|pins| pins.check(&pins.current_identity, false).is_ok())
        };
        let parent = NamespaceParent {
            scope: binding.parent.scope.clone(),
            authorization: auth,
            classification: StorageClassification::Ordinary,
            local_file: LocalFileIdentity {
                volume_serial: parent_snapshot.identity.volume_serial,
                file_index: parent_snapshot.identity.file_index,
            },
            local_components: old[..old.len() - 1].to_vec(),
            remote: binding.parent.remote.clone(),
        };
        let destination_parent = NamespaceParent {
            scope: binding.destination_parent.scope.clone(),
            authorization: auth,
            classification: StorageClassification::Ordinary,
            local_file: LocalFileIdentity {
                volume_serial: destination_parent_snapshot.identity.volume_serial,
                file_index: destination_parent_snapshot.identity.file_index,
            },
            local_components: new[..new.len() - 1].to_vec(),
            remote: binding.destination_parent.remote.clone(),
        };
        let source = ExistingNamespaceEntry {
            local: LocalNamespaceEntry {
                parent: parent.clone(),
                name: old.last().unwrap().clone(),
                local_file: file,
                object_kind: NamespaceObjectKind::File,
            },
            remote: binding.source_remote.clone(),
        };
        let intent = NamespaceIntent {
            schema_version: 1,
            record_id: "0".repeat(32),
            record_generation: generation,
            operation: NamespaceOperation::MoveWithinScope {
                source,
                destination: LocalNamespaceEntry {
                    parent: destination_parent,
                    name: new.last().unwrap().clone(),
                    local_file: file,
                    object_kind: NamespaceObjectKind::File,
                },
            },
        };
        let store = self
            .file_rename_store(backend, &binding.parent.scope, auth)
            .map_err(N::Local)?
            .ok_or(N::Local(Error::EditRecoveryUnavailable))?;
        if !clean(true) {
            return Err(N::DeferredBeforePublication);
        }
        // Remote/local proofs are complete before fresh protected publication.
        backend
            .with_file_move(&binding, &intent, digest, &pinned_current, |session| {
                crate::namespace_file_rename::FileRenameRemote::preflight(session, &intent)
            })
            .map_err(N::Backend)?
            .map_err(|_| N::DeferredBeforePublication)?;
        pins.borrow()
            .check(binding.source_identity.as_bytes(), true)
            .map_err(N::Local)?;
        let fresh = match store.publish_intent(intent).map_err(N::Store)? {
            FileRenamePublishResult::Fresh(v) => v,
            FileRenamePublishResult::Retained => return Ok(FileRenameOutcome::Retained),
        };
        let mut lease = fresh.acquire_dispatch().map_err(N::Store)?;
        let intent = lease.intent().clone();
        if !clean(false) {
            return Err(N::AdmissionAfterPublication);
        }
        backend
            .with_file_move(&binding, &intent, digest, &pinned_current, |session| {
                let mut local = Local {
                    pins: &pins,
                    session,
                };
                let mut local = GuardedLocal {
                    local: &mut local,
                    admission: &admission,
                };
                let remote = GuardedRemote {
                    remote: session,
                    admission: &admission,
                };
                reconcile_file_rename(&mut lease, &remote, &mut local)
            })
            .map_err(N::Backend)?
            .map_err(N::Store)
    }
}
