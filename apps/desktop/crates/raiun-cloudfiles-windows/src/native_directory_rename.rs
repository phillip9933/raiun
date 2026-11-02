//! Metadata-only completion of an already observed same-parent bounded nonempty directory rename.
//! Rebase only the exact pinned catalog/remote subtree; no file digest, caller
//! pathname authority, recovered replay or server subtree-CAS claim.
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
use crate::opencloud::{DirectoryRenameBinding, DirectoryRenameSession};
use crate::save_rename_admission::{GuardedLocal, GuardedRemote, SaveRenameAdmission};
use crate::streamed_store::namespace_rename_store::FileRenamePublishResult;
use raiun_control_windows::directory_notifications::directory_rename_hints::RenameHintPair;
use std::cell::RefCell;

// Every node owns a referenced exclusive Cloud Files handle. It denies existing
// data writers and retains its share exclusion until completion or uncertainty.
struct NodePin {
    protected: ProtectedCompletionFile,
    snapshot: RootSnapshot,
    basic: FileBasicInfo,
    usn: i64,
    path: PathBuf,
    source_identity: [u8; 16],
    current_identity: [u8; 16],
    directory: bool,
    updated: bool,
}
impl NodePin {
    fn check(&self) -> Result<(), Error> {
        if !same_snapshot(root_snapshot(self.protected.raw)?, self.snapshot)
            || completion_basic_info(self.protected.raw)? != self.basic
            || completion_usn(self.protected.raw, self.snapshot.identity.file_index)? != self.usn
            || native_namespace_directory::opaque_directory_identity(self.protected.raw)?
                != self.current_identity
            || !windows_paths_equal(
                &final_path_for_handle(self.protected.raw)
                    .map_err(|_| Error::ConfiguredRootChanged)?,
                &self.path,
            )
            || (!self.directory
                && (!file_links(self.protected.raw, self.snapshot.identity)?
                    || modified_ranges_for_handle(self.protected.raw)
                        .map_err(|_| Error::EditRecoveryUnavailable)?))
        {
            return Err(Error::ConfiguredRootChanged);
        }
        Ok(())
    }
    fn update(&mut self, identity: &[u8; 16]) -> Result<(), FileRenameCompletionError> {
        use FileRenameCompletionError as E;
        self.check().map_err(|_| E::Unavailable)?;
        if self.updated {
            return Err(E::Uncertain);
        }
        self.updated = true;
        let before = self.snapshot;
        let basic = self.basic;
        let mut usn = self.usn;
        // Positive original USN CAS; metadata/ranges NULL. No file body changes.
        let hr = unsafe {
            CfUpdatePlaceholder(
                self.protected.protected,
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
        let after = root_snapshot(self.protected.raw).map_err(|_| E::Uncertain)?;
        let after_basic = completion_basic_info(self.protected.raw).map_err(|_| E::Uncertain)?;
        if after.identity != before.identity
            || after.file_attributes != before.file_attributes
            || after.reparse_tag != before.reparse_tag
            || after.file_size != before.file_size
            || after.last_write_time != before.last_write_time
            || after.placeholder_state != (before.placeholder_state | CF_PLACEHOLDER_STATE_IN_SYNC)
            || after_basic.creation_time != basic.creation_time
            || after_basic.last_access_time != basic.last_access_time
            || after_basic.last_write_time != basic.last_write_time
            || after_basic.file_attributes != basic.file_attributes
            || after_basic.change_time < basic.change_time
        {
            return Err(E::Uncertain);
        }
        self.snapshot = after;
        self.basic = after_basic;
        self.usn = usn;
        self.current_identity = *identity;
        self.check().map_err(|_| E::Uncertain)
    }
}
struct Pins<'a> {
    connection: &'a ConfiguredRootConnection,
    parent: RawOwnedHandle,
    parent_snapshot: RootSnapshot,
    ancestors: Vec<(RawOwnedHandle, RootSnapshot)>,
    nodes: Vec<NodePin>,
    root: RootIdentity,
    root_path: PathBuf,
    old: PathBuf,
    parent_identity: crate::OpaqueIdentity,
}
impl Pins<'_> {
    fn check(&self, enumerate: bool) -> Result<(), Error> {
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
        for node in &self.nodes {
            node.check()?;
            if enumerate && node.directory {
                let actual = children(node.protected.raw)?;
                let expected = self
                    .nodes
                    .iter()
                    .filter(|n| n.path.parent() == Some(node.path.as_path()))
                    .collect::<Vec<_>>();
                if actual.len() != expected.len()
                    || actual.iter().any(|(name, id)| {
                        !expected.iter().any(|n| {
                            n.path.file_name().and_then(|s| s.to_str()) == Some(name.as_str())
                                && n.snapshot.identity.file_index == *id
                        })
                    })
                {
                    return Err(Error::ConfiguredRootChanged);
                }
                node.check()?;
            }
        }
        Ok(())
    }
}
#[repr(C)]
struct DirectoryInfo {
    next: u32,
    index: u32,
    times: [i64; 6],
    attributes: u32,
    name_bytes: u32,
    ea_size: u32,
    short_length: u8,
    short_name: [u16; 12],
    file_id: i64,
    name: [u16; 1],
}
const _: () = {
    assert!(std::mem::offset_of!(DirectoryInfo, name) == 104);
    assert!(std::mem::offset_of!(DirectoryInfo, name_bytes) == 60);
    assert!(size_of::<DirectoryInfo>() == 112);
    assert!(std::mem::align_of::<DirectoryInfo>() == 8);
};
fn children(handle: Handle) -> Result<Vec<(String, u64)>, Error> {
    let mut result = Vec::new();
    let mut class = 11;
    for _ in 0..1024 {
        let mut words = [0u64; 512];
        let ok = unsafe {
            GetFileInformationByHandleEx(
                handle,
                class,
                words.as_mut_ptr().cast(),
                std::mem::size_of_val(&words) as u32,
            )
        };
        if ok == 0 {
            return if unsafe { GetLastError() } == 18 {
                Ok(result)
            } else {
                Err(win32_io_error("enumerate pinned directory rename"))
            };
        }
        class = 10;
        let bytes = unsafe {
            std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), std::mem::size_of_val(&words))
        };
        let mut offset = 0usize;
        loop {
            if offset + size_of::<DirectoryInfo>() > bytes.len() {
                return Err(Error::ConfiguredRootChanged);
            }
            let entry = unsafe {
                std::ptr::read_unaligned(bytes.as_ptr().add(offset).cast::<DirectoryInfo>())
            };
            let start = offset + 104;
            let len = entry.name_bytes as usize;
            if len == 0 || len % 2 != 0 || start.checked_add(len).is_none_or(|e| e > bytes.len()) {
                return Err(Error::ConfiguredRootChanged);
            }
            let units = bytes[start..start + len]
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect::<Vec<_>>();
            let name = String::from_utf16(&units).map_err(|_| Error::ConfiguredRootChanged)?;
            if name != "." && name != ".." {
                if !valid_component(&name)
                    || entry.file_id == 0
                    || result.len() >= 1024
                    || result
                        .iter()
                        .any(|(n, _): &(String, u64)| n.eq_ignore_ascii_case(&name))
                {
                    return Err(Error::ConfiguredRootChanged);
                }
                result.push((name, entry.file_id as u64));
            }
            if entry.next == 0 {
                break;
            }
            let next = entry.next as usize;
            if next % 8 != 0
                || next < 104 + len
                || offset.checked_add(next).is_none_or(|e| e >= bytes.len())
            {
                return Err(Error::ConfiguredRootChanged);
            }
            offset += next;
        }
    }
    Err(Error::ConfiguredRootChanged)
}
struct Local<'p, 's, 'b> {
    pins: &'p RefCell<Pins<'b>>,
    session: &'s DirectoryRenameSession<'s>,
}
impl FileRenameLocal for Local<'_, '_, '_> {
    fn admit(&mut self, _: &NamespaceIntent) -> Result<(), CloudError> {
        self.pins
            .try_borrow()
            .map_err(|_| conflict())?
            .check(false)
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
            self.pins
                .try_borrow()
                .map_err(|_| E::Unavailable)?
                .check(true)
                .map_err(|_| E::Unavailable)?;
        }
        self.session.publish_completion(
            readback,
            |identities| {
                let mut pins = self.pins.try_borrow_mut().map_err(|_| E::Unavailable)?;
                pins.check(false).map_err(|_| E::Unavailable)?;
                if identities.len() != pins.nodes.len() {
                    return Err(E::Uncertain);
                }
                // Children first, root last; every original row remains protected.
                for index in (0..pins.nodes.len()).rev() {
                    let node = &mut pins.nodes[index];
                    let mut found = identities
                        .iter()
                        .filter(|(old, _)| *old == node.source_identity);
                    let (_, identity) = found.next().ok_or(E::Uncertain)?;
                    if found.next().is_some() {
                        return Err(E::Uncertain);
                    }
                    node.update(identity)?;
                }
                pins.check(true).map_err(|_| E::Uncertain)
            },
            record,
        )
    }
}
impl crate::ConfiguredRootConnection {
    /// One live same-batch bounded ordinary directory rename. This completes actual observed
    /// native metadata; it does not perform or infer an OS rename from a name.
    #[allow(clippy::too_many_arguments)]
    pub fn reconcile_fresh_directory_rename(
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
        let binding: DirectoryRenameBinding = backend
            .prepare_directory_rename(
                &pair,
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
        if binding.nodes.len() == 1 {
            drop(admission);
            return self.reconcile_fresh_empty_directory_rename(
                backend, pair, file, auth, generation, current,
            );
        }
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
        let source_remote_path = binding.source_remote_path();
        let mut nodes = Vec::new();
        let mut expected = binding.nodes.iter().collect::<Vec<_>>();
        expected.sort_by_key(|node| node.entry.path.len()); // pin every ancestor before its children
        for node in expected {
            let suffix = node
                .entry
                .path
                .strip_prefix(&source_remote_path)
                .ok_or(N::Local(Error::ConfiguredRootChanged))?;
            let mut path = destination_path.clone();
            for component in suffix.split('/').filter(|p| !p.is_empty()) {
                if !valid_component(component) {
                    return Err(N::Local(Error::ConfiguredRootChanged));
                }
                path.push(component);
            }
            let protected = ProtectedCompletionFile::open(&wide_path(&path).map_err(N::Local)?)
                .map_err(N::Local)?;
            let snapshot = root_snapshot(protected.raw).map_err(N::Local)?;
            if snapshot.identity.volume_serial != root.identity.volume_serial
                || snapshot.identity.file_index == 0
                || (snapshot.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0)
                    != node.entry.directory
                || snapshot.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
                || !cleanup_cloud_reparse_tag(snapshot.reparse_tag)
                || snapshot.placeholder_state & CF_PLACEHOLDER_STATE_PLACEHOLDER == 0
                || snapshot.placeholder_state & CF_PLACEHOLDER_STATE_IN_SYNC == 0
                || snapshot.placeholder_state & 2 != 0
                || snapshot.placeholder_state & !0x3f != 0
                || snapshot.file_size
                    != if node.entry.directory {
                        0
                    } else {
                        node.entry.size
                    }
                || (suffix.is_empty()
                    && (snapshot.identity.file_index != file.file_index
                        || snapshot.identity.volume_serial != file.volume_serial))
            {
                return Err(N::Local(Error::ConfiguredRootChanged));
            }
            let basic = completion_basic_info(protected.raw).map_err(N::Local)?;
            let usn =
                completion_usn(protected.raw, snapshot.identity.file_index).map_err(N::Local)?;
            if usn <= 0 {
                return Err(N::Local(Error::EditRecoveryUnavailable));
            }
            nodes.push(NodePin {
                protected,
                snapshot,
                basic,
                usn,
                path,
                source_identity: *node.identity().as_bytes(),
                current_identity: *node.identity().as_bytes(),
                directory: node.entry.directory,
                updated: false,
            });
        }
        let pins = RefCell::new(Pins {
            connection: &self.inner,
            parent,
            parent_snapshot,
            ancestors,
            nodes,
            root: root.identity,
            root_path: root.path.clone(),
            old: source_path,
            parent_identity: binding.parent.identity,
        });
        pins.borrow().check(true).map_err(N::Local)?;
        let pinned_current = |a| {
            guarded(a)
                && pins
                    .try_borrow()
                    .is_ok_and(|pins| pins.check(false).is_ok())
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
            .with_directory_rename(&binding, &intent, &pinned_current, |session| {
                crate::namespace_file_rename::FileRenameRemote::preflight(session, &intent)
            })
            .map_err(N::Backend)?
            .map_err(|_| N::DeferredBeforePublication)?;
        pins.borrow().check(true).map_err(N::Local)?;
        let fresh = match store.publish_intent(intent) {
            Ok(FileRenamePublishResult::Fresh(v)) => v,
            Ok(FileRenamePublishResult::Retained) => return Ok(FileRenameOutcome::Retained),
            Err(error) => {
                // Publication can fail after its protected intent is durable.
                // Keep original custody even when no fresh receipt was returned.
                std::mem::forget(pins);
                return Err(N::Store(error));
            }
        };
        // Every fallible step after fresh publication shares one custody exit.
        // Acquisition/admission/backend-entry failures cannot drop the subtree.
        let result = (|| {
            let mut lease = fresh.acquire_dispatch().map_err(N::Store)?;
            let intent = lease.intent().clone();
            if !clean(false) {
                return Err(N::AdmissionAfterPublication);
            }
            backend
                .with_directory_rename(&binding, &intent, &pinned_current, |session| {
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
        })();
        if !matches!(&result, Ok(FileRenameOutcome::Completed)) {
            // Keep the original native subtree pinned after published uncertainty.
            // No detached worker, callback pointer or replay is created.
            std::mem::forget(pins);
        }
        result
    }
}
