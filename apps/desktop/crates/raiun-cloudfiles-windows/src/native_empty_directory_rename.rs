//! Metadata-only completion of an already observed same-parent EMPTY directory rename.
//! No file digest, subtree rebase, caller pathname authority or recovered replay.
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
use crate::opencloud::{EmptyDirectoryRenameBinding, EmptyDirectoryRenameSession};
use crate::save_rename_admission::{GuardedLocal, GuardedRemote, SaveRenameAdmission};
use crate::streamed_store::namespace_rename_store::FileRenamePublishResult;
use raiun_control_windows::directory_notifications::directory_rename_hints::RenameHintPair;
use std::cell::RefCell;

struct Pins<'a> {
    connection: &'a ConfiguredRootConnection,
    parent: RawOwnedHandle,
    parent_snapshot: RootSnapshot,
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
            || !absent(&self.old)?
            || !windows_paths_equal(
                &final_path_for_handle(self.protected.raw)
                    .map_err(|_| Error::ConfiguredRootChanged)?,
                &self.new,
            )
            || native_namespace_directory::opaque_directory_identity(self.protected.raw)?
                != *identity
            || !same_snapshot(root_snapshot(self.protected.raw)?, self.snapshot)
            || completion_usn(self.protected.raw, self.snapshot.identity.file_index)? != self.usn
            || completion_basic_info(self.protected.raw)? != self.basic
        {
            return Err(Error::ConfiguredRootChanged);
        }
        for (handle, snapshot) in &self.ancestors {
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
        if enumerate {
            if !super::super::native_file_delete::physically_empty(self.protected.raw)?
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
    session: &'s EmptyDirectoryRenameSession<'s>,
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
                // Exact referenced directory, positive original USN CAS; metadata and
                // ranges NULL. MARK_IN_SYNC only, no file size/hash or dehydration.
                let hr = unsafe {
                    CfUpdatePlaceholder(
                        pins.protected.protected,
                        null(),
                        identity.as_ptr().cast(),
                        16,
                        null(),
                        0,
                        2,
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
                    || after.file_size != 0
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
                pins.check(identity, false).map_err(|_| E::Uncertain)
            },
            record,
        )
    }
}
impl crate::ConfiguredRootConnection {
    /// One live same-batch empty-folder rename. This completes actual observed
    /// native metadata; it does not perform or infer an OS rename from a name.
    #[allow(clippy::too_many_arguments)]
    pub fn reconcile_fresh_empty_directory_rename(
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
        let binding: EmptyDirectoryRenameBinding = backend
            .prepare_empty_directory_rename(
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
        let source_path = old.iter().fold(root.path.clone(), |p, c| p.join(c));
        let destination_path = new.iter().fold(root.path.clone(), |p, c| p.join(c));
        let protected =
            ProtectedCompletionFile::open(&wide_path(&destination_path).map_err(N::Local)?)
                .map_err(N::Local)?;
        let snapshot = root_snapshot(protected.raw).map_err(N::Local)?;
        if snapshot.identity.volume_serial != file.volume_serial
            || snapshot.identity.file_index != file.file_index
            || snapshot.file_attributes & FILE_ATTRIBUTE_DIRECTORY == 0
            || snapshot.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
            || !cleanup_cloud_reparse_tag(snapshot.reparse_tag)
            || snapshot.placeholder_state & CF_PLACEHOLDER_STATE_PLACEHOLDER == 0
            || snapshot.placeholder_state & 2 != 0
            || snapshot.placeholder_state & !0x3f != 0
            || snapshot.file_size != 0
        {
            return Err(N::Local(Error::ConfiguredRootChanged));
        }
        let basic = completion_basic_info(protected.raw).map_err(N::Local)?;
        let usn = completion_usn(protected.raw, file.file_index).map_err(N::Local)?;
        if usn <= 0 {
            return Err(N::Local(Error::EditRecoveryUnavailable));
        }
        let pins = RefCell::new(Pins {
            connection: &self.inner,
            parent,
            parent_snapshot,
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
        let source = ExistingNamespaceEntry {
            local: LocalNamespaceEntry {
                parent: parent.clone(),
                name: old.last().unwrap().clone(),
                local_file: file,
                object_kind: NamespaceObjectKind::Directory,
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
                    parent,
                    name: new.last().unwrap().clone(),
                    local_file: file,
                    object_kind: NamespaceObjectKind::Directory,
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
            .with_empty_directory_rename(&binding, &intent, &pinned_current, |session| {
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
            .with_empty_directory_rename(&binding, &intent, &pinned_current, |session| {
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
