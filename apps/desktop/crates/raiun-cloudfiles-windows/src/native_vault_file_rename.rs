//! Original-owner, metadata-only encrypted clean FILE rename admission.
//! No hydration, body read, history adoption or in-sync repair is allowed.
use super::*;
use raiun_core::backend::{CloudError, ErrorKind};
use sha2::{Digest, Sha256};

pub(super) struct SourceParentPins {
    handle: RawOwnedHandle,
    ancestors: Vec<(RawOwnedHandle, RootSnapshot)>,
    proof: SourceParentProof,
}
#[derive(Clone)]
pub(super) struct SourceParentProof {
    components: Vec<String>,
    route: Vec<crate::PlaceholderChild>,
    identity: crate::OpaqueIdentity,
    snapshot: RootSnapshot,
    usn: i64,
}
impl SourceParentPins {
    pub(super) fn pin(
        root: &OwnedConfiguredRoot,
        components: &[String],
        route: &[crate::PlaceholderChild],
        identity: crate::OpaqueIdentity,
    ) -> Result<Self, Error> {
        let refs = components.iter().map(String::as_str).collect::<Vec<_>>();
        let (h, s, a) = native_namespace_directory::pin_namespace_parent(
            root,
            route,
            identity,
            &refs,
            FILE_READ_ATTRIBUTES,
        )?;
        let usn = completion_usn(h.0, s.identity.file_index)?;
        if usn <= 0 {
            return Err(Error::ConfiguredRootChanged);
        }
        Ok(Self {
            handle: h,
            ancestors: a,
            proof: SourceParentProof {
                components: components.to_vec(),
                route: route.to_vec(),
                identity,
                snapshot: s,
                usn,
            },
        })
    }
    pub(super) fn file(&self) -> LocalFileIdentity {
        LocalFileIdentity {
            volume_serial: self.proof.snapshot.identity.volume_serial,
            file_index: self.proof.snapshot.identity.file_index,
        }
    }
    pub(super) fn usn(&self) -> i64 {
        self.proof.usn
    }
    pub(super) fn send_proof(&self) -> SourceParentProof {
        self.proof.clone()
    }
    pub(super) fn check(&self, root: &Path) -> Result<(), Error> {
        let p = &self.proof;
        if !same_edit_snapshot(root_snapshot(self.handle.0)?, p.snapshot)
            || completion_usn(self.handle.0, p.snapshot.identity.file_index)? != p.usn
            || native_namespace_directory::opaque_directory_identity(self.handle.0)?
                != *p.identity.as_bytes()
            || !windows_paths_equal(
                &final_path_for_handle(self.handle.0).map_err(|_| Error::ConfiguredRootChanged)?,
                &path(root, &p.components),
            )
            || p.route.len() != self.ancestors.len() + 1
        {
            return Err(Error::ConfiguredRootChanged);
        }
        for ((h, s), e) in self.ancestors.iter().zip(&p.route) {
            if !same_edit_snapshot(root_snapshot(h.0)?, *s)
                || native_namespace_directory::opaque_directory_identity(h.0)?.as_slice()
                    != e.identity
            {
                return Err(Error::ConfiguredRootChanged);
            }
        }
        Ok(())
    }
}
impl SourceParentProof {
    pub(super) fn check(&self, lease: &RootInspectionLease, root: &Path) -> Result<(), Error> {
        let refs = self
            .components
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let (h, s, _) = native_namespace_directory::pin_reinspected_namespace_parent(
            lease,
            root,
            &self.route,
            self.identity,
            &refs,
        )?;
        if !same_edit_snapshot(s, self.snapshot)
            || completion_usn(h.0, s.identity.file_index)? != self.usn
        {
            return Err(Error::ConfiguredRootChanged);
        }
        Ok(())
    }
}
pub(super) struct VaultFileRenamePins {
    root_path: PathBuf,
    root: RootIdentity,
    source_parent: Option<SourceParentPins>,
    parent: RawOwnedHandle,
    parent_snapshot: RootSnapshot,
    parent_usn: i64,
    ancestors: Vec<(RawOwnedHandle, RootSnapshot)>,
    route: Vec<crate::PlaceholderChild>,
    parent_identity: crate::OpaqueIdentity,
    original_identity: crate::OpaqueIdentity,
    components: Vec<String>,
    old_components: Vec<String>,
    _destination: RawOwnedHandle,
    protected: ProtectedCompletionFile,
    snapshot: RootSnapshot,
    basic: FileBasicInfo,
    usn: i64,
    updated: Option<crate::OpaqueIdentity>,
    attempted: bool,
    pending: bool,
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}
#[derive(Clone)]
pub(super) struct VaultFileRenameSendProof {
    root_path: PathBuf,
    root: RootIdentity,
    source_parent: Option<SourceParentProof>,
    parent: RootSnapshot,
    parent_usn: i64,
    route: Vec<crate::PlaceholderChild>,
    parent_identity: crate::OpaqueIdentity,
    identity: crate::OpaqueIdentity,
    components: Vec<String>,
    old_components: Vec<String>,
    snapshot: RootSnapshot,
    basic: FileBasicInfo,
    usn: i64,
}
fn path(root: &Path, parts: &[String]) -> PathBuf {
    let mut p = root.to_owned();
    for s in parts {
        p.push(s);
    }
    p
}
pub(super) fn absent(path: &Path) -> Result<bool, Error> {
    let wide = wide_path(path)?;
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            null_mut(),
        )
    };
    if !raw.is_null() && raw != INVALID_HANDLE_VALUE {
        drop(RawOwnedHandle(raw));
        return Ok(false);
    }
    // The original managed parent is pinned. Missing ancestors, access or
    // sharing errors do not establish absence of the original source name.
    match unsafe { GetLastError() } {
        2 => Ok(true),
        _ => Err(win32_io_error("inspect original vault rename source")),
    }
}
pub(super) fn links_one(handle: Handle, expected: RootIdentity) -> Result<bool, Error> {
    let mut info: ByHandleFileInformation = unsafe { zeroed() };
    if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
        return Err(win32_io_error("inspect vault rename links"));
    }
    Ok(info.number_of_links == 1
        && info.volume_serial_number == expected.volume_serial
        && ((u64::from(info.file_index_high) << 32) | u64::from(info.file_index_low))
            == expected.file_index)
}
fn clean(snapshot: RootSnapshot, file: LocalFileIdentity, size: u64, pending: bool) -> bool {
    snapshot.identity.volume_serial == file.volume_serial
        && snapshot.identity.file_index == file.file_index
        && file.file_index != 0
        && snapshot.file_size == size
        && snapshot.file_attributes & FILE_ATTRIBUTE_DIRECTORY == 0
        && snapshot.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        && cleanup_cloud_reparse_tag(snapshot.reparse_tag)
        && snapshot.placeholder_state & CF_PLACEHOLDER_STATE_PLACEHOLDER != 0
        && (snapshot.placeholder_state & CF_PLACEHOLDER_STATE_IN_SYNC != 0) != pending
        && snapshot.placeholder_state & CF_PLACEHOLDER_STATE_SYNC_ROOT == 0
        && snapshot.placeholder_state
            & !(CF_PLACEHOLDER_STATE_PLACEHOLDER
                | 0x4
                | CF_PLACEHOLDER_STATE_IN_SYNC
                | CF_PLACEHOLDER_STATE_PARTIAL
                | CF_PLACEHOLDER_STATE_PARTIALLY_ON_DISK)
            == 0
}
fn inspect(
    handle: Handle,
    expected: RootSnapshot,
    basic: FileBasicInfo,
    usn: i64,
    identity: crate::OpaqueIdentity,
    destination: &Path,
    pending: bool,
) -> Result<(), Error> {
    let snapshot = root_snapshot(handle)?;
    let file = LocalFileIdentity {
        volume_serial: expected.identity.volume_serial,
        file_index: expected.identity.file_index,
    };
    if !clean(snapshot, file, expected.file_size, pending)
        || !same_edit_snapshot(snapshot, expected)
        || completion_basic_info(handle)? != basic
        || usn <= 0
        || completion_usn(handle, file.file_index)? != usn
        || !links_one(handle, expected.identity)?
        || native_namespace_directory::opaque_directory_identity(handle)? != *identity.as_bytes()
        || (!pending
            && modified_ranges_for_handle(handle).map_err(|_| Error::EditRecoveryUnavailable)?)
        || !windows_paths_equal(
            &final_path_for_handle(handle).map_err(|_| Error::ConfiguredRootChanged)?,
            destination,
        )
    {
        return Err(Error::ConfiguredRootChanged);
    }
    Ok(())
}
impl VaultFileRenamePins {
    pub(super) fn body_sha256(&self) -> Result<[u8; 32], Error> {
        self.verify_handles(self.original_identity)?;
        let mut hash = Sha256::new();
        let mut offset = 0u64;
        let mut buffer = Zeroizing::new(vec![0u8; 64 * 1024]);
        while offset < self.snapshot.file_size {
            let len = usize::try_from((self.snapshot.file_size - offset).min(buffer.len() as u64))
                .map_err(|_| Error::EditRecoveryUnavailable)?;
            self.protected
                .read_complete_at(offset, &mut buffer[..len])?;
            hash.update(&buffer[..len]);
            offset += len as u64;
        }
        self.verify_handles(self.original_identity)?;
        Ok(hash.finalize().into())
    }
    pub(super) fn pending_body_sha256(&self) -> Result<String, Error> {
        if !self.pending || self.snapshot.file_size > 64 * 1024 * 1024 {
            return Err(Error::EditRecoveryUnavailable);
        }
        self.verify_handles(self.original_identity)?;
        let len =
            usize::try_from(self.snapshot.file_size).map_err(|_| Error::EditRecoveryUnavailable)?;
        let mut bytes = Zeroizing::new(vec![0u8; len]);
        self.protected.read_complete(&mut bytes)?;
        self.verify_handles(self.original_identity)?;
        Ok(format!("{:x}", Sha256::digest(&*bytes)))
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn pin(
        connection: &ConfiguredRootConnection,
        backend: &Arc<crate::OpenCloudPlaceholderBackend>,
        parent_components: &[String],
        route: &[crate::PlaceholderChild],
        parent_identity: crate::OpaqueIdentity,
        source_parent_components: &[String],
        source_route: &[crate::PlaceholderChild],
        source_parent_identity: crate::OpaqueIdentity,
        old_name: &str,
        new_name: &str,
        original_identity: crate::OpaqueIdentity,
        expected_file: LocalFileIdentity,
        plaintext_len: u64,
        pending: bool,
    ) -> Result<Self, Error> {
        let erased: Arc<dyn PlaceholderBackend> = backend.clone();
        if !connection.connected
            || !Arc::ptr_eq(&erased, &connection.state.backend)
            || connection.state.readiness.load(Ordering::Acquire) != CALLBACK_READY
            || backend.is_revoked()
            || source_parent_components.is_empty()
            || source_parent_components.len() > 255
            || source_parent_components.iter().any(|s| !valid_component(s))
            || parent_components.is_empty()
            || parent_components.len() > 255
            || parent_components.iter().any(|s| !valid_component(s))
            || !valid_component(old_name)
            || !valid_component(new_name)
            || *original_identity.as_bytes() == [0; 16]
        {
            return Err(Error::ProviderUnavailable);
        }
        let root = connection
            .root
            .as_ref()
            .ok_or(Error::ConfiguredRootChanged)?;
        root.verify_identity(true)?;
        root.verify_registered()?;
        if expected_file.volume_serial != root.identity.volume_serial
            || expected_file.file_index == root.identity.file_index
        {
            return Err(Error::ConfiguredRootChanged);
        }
        let refs: Vec<_> = parent_components.iter().map(String::as_str).collect();
        let (parent, parent_snapshot, ancestors) =
            native_namespace_directory::pin_namespace_parent(
                root,
                route,
                parent_identity,
                &refs,
                FILE_READ_ATTRIBUTES,
            )?;
        let parent_usn = completion_usn(parent.0, parent_snapshot.identity.file_index)?;
        let components: Vec<_> = parent_components
            .iter()
            .cloned()
            .chain(std::iter::once(new_name.to_owned()))
            .collect();
        let old_components: Vec<_> = source_parent_components
            .iter()
            .cloned()
            .chain(std::iter::once(old_name.to_owned()))
            .collect();
        let source_parent = if source_parent_components == parent_components {
            if source_parent_identity != parent_identity {
                return Err(Error::ConfiguredRootChanged);
            }
            None
        } else {
            let refs = source_parent_components
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>();
            let (h, s, a) = native_namespace_directory::pin_namespace_parent(
                root,
                source_route,
                source_parent_identity,
                &refs,
                FILE_READ_ATTRIBUTES,
            )?;
            let usn = completion_usn(h.0, s.identity.file_index)?;
            if usn <= 0 {
                return Err(Error::ConfiguredRootChanged);
            }
            Some(SourceParentPins {
                handle: h,
                ancestors: a,
                proof: SourceParentProof {
                    components: source_parent_components.to_vec(),
                    route: source_route.to_vec(),
                    identity: source_parent_identity,
                    snapshot: s,
                    usn,
                },
            })
        };
        let destination = path(&root.path, &components);
        let old = path(&root.path, &old_components);
        if parent_usn <= 0 || windows_paths_equal(&old, &destination) || !absent(&old)? {
            return Err(Error::ConfiguredRootChanged);
        }
        // Same original destination CF object, no WRITE/DELETE sharing. Keep
        // the existing exclusive RH oplock/reference for readonly placeholders;
        // no WRITE_ACCESS/FOREGROUND fallback or attribute change is attempted.
        let marker = open_root(&destination, FILE_READ_ATTRIBUTES, FILE_SHARE_READ)?;
        let snapshot = root_snapshot(marker.0)?;
        if !clean(snapshot, expected_file, plaintext_len, pending)
            || !links_one(marker.0, snapshot.identity)?
        {
            return Err(Error::ConfiguredRootChanged);
        }
        let protected = ProtectedCompletionFile::open_for_cleanup(&wide_path(&destination)?)?;
        let basic = completion_basic_info(protected.raw)?;
        let usn = completion_usn(protected.raw, expected_file.file_index)?;
        inspect(
            protected.raw,
            snapshot,
            basic,
            usn,
            original_identity,
            &destination,
            pending,
        )?;
        if !same_edit_snapshot(root_snapshot(marker.0)?, snapshot) {
            return Err(Error::ConfiguredRootChanged);
        }
        let pins = Self {
            root_path: root.path.clone(),
            root: root.identity,
            source_parent,
            parent,
            parent_snapshot,
            parent_usn,
            ancestors,
            route: route.to_vec(),
            parent_identity,
            original_identity,
            components,
            old_components,
            _destination: marker,
            protected,
            snapshot,
            basic,
            usn,
            updated: None,
            attempted: false,
            pending,
            _thread: std::marker::PhantomData,
        };
        pins.verify(connection, false)?;
        Ok(pins)
    }
    pub(super) fn file(&self) -> LocalFileIdentity {
        LocalFileIdentity {
            volume_serial: self.snapshot.identity.volume_serial,
            file_index: self.snapshot.identity.file_index,
        }
    }
    pub(super) fn usn(&self) -> i64 {
        self.usn
    }
    pub(super) fn parent_file(&self) -> LocalFileIdentity {
        let s = self
            .source_parent
            .as_ref()
            .map(|p| p.proof.snapshot)
            .unwrap_or(self.parent_snapshot);
        LocalFileIdentity {
            volume_serial: s.identity.volume_serial,
            file_index: s.identity.file_index,
        }
    }
    pub(super) fn parent_usn(&self) -> i64 {
        self.source_parent
            .as_ref()
            .map(|p| p.proof.usn)
            .unwrap_or(self.parent_usn)
    }
    pub(super) fn destination_parent_file(&self) -> LocalFileIdentity {
        LocalFileIdentity {
            volume_serial: self.parent_snapshot.identity.volume_serial,
            file_index: self.parent_snapshot.identity.file_index,
        }
    }
    pub(super) fn destination_parent_usn(&self) -> i64 {
        self.parent_usn
    }
    pub(super) fn original_identity(&self) -> crate::OpaqueIdentity {
        self.original_identity
    }
    fn verify_handles(&self, identity: crate::OpaqueIdentity) -> Result<(), Error> {
        if let Some(p) = &self.source_parent {
            p.check(&self.root_path)?;
        }
        if !same_edit_snapshot(root_snapshot(self.parent.0)?, self.parent_snapshot)
            || completion_usn(self.parent.0, self.parent_snapshot.identity.file_index)?
                != self.parent_usn
            || native_namespace_directory::opaque_directory_identity(self.parent.0)?
                != *self.parent_identity.as_bytes()
            || self.route.len() != self.ancestors.len() + 1
            || !absent(&path(&self.root_path, &self.old_components))?
        {
            return Err(Error::ConfiguredRootChanged);
        }
        for ((handle, snapshot), expected) in self.ancestors.iter().zip(&self.route) {
            if !same_edit_snapshot(root_snapshot(handle.0)?, *snapshot)
                || native_namespace_directory::opaque_directory_identity(handle.0)?.as_slice()
                    != expected.identity
            {
                return Err(Error::ConfiguredRootChanged);
            }
        }
        inspect(
            self.protected.raw,
            self.snapshot,
            self.basic,
            self.usn,
            identity,
            &path(&self.root_path, &self.components),
            self.pending,
        )?;
        if !same_edit_snapshot(root_snapshot(self._destination.0)?, self.snapshot) {
            return Err(Error::ConfiguredRootChanged);
        }
        Ok(())
    }
    pub(super) fn verify(
        &self,
        connection: &ConfiguredRootConnection,
        updated: bool,
    ) -> Result<(), Error> {
        if !connection.connected
            || connection.state.readiness.load(Ordering::Acquire) != CALLBACK_READY
        {
            return Err(Error::ProviderUnavailable);
        }
        let root = connection
            .root
            .as_ref()
            .ok_or(Error::ConfiguredRootChanged)?;
        root.verify_identity(true)?;
        root.verify_registered()?;
        if root.identity != self.root || !windows_paths_equal(&root.path, &self.root_path) {
            return Err(Error::ConfiguredRootChanged);
        }
        let identity = if updated {
            self.updated.ok_or(Error::EditRecoveryUnavailable)?
        } else {
            if self.attempted {
                return Err(Error::EditRecoveryUnavailable);
            }
            self.original_identity
        };
        self.verify_handles(identity)
    }
    pub(super) fn send_proof(&self) -> Result<VaultFileRenameSendProof, Error> {
        if self.attempted {
            return Err(Error::EditRecoveryUnavailable);
        }
        if self.pending {
            return Err(Error::EditRecoveryUnavailable);
        }
        self.verify_handles(self.original_identity)?;
        Ok(VaultFileRenameSendProof {
            root_path: self.root_path.clone(),
            root: self.root,
            source_parent: self.source_parent.as_ref().map(|p| p.proof.clone()),
            parent: self.parent_snapshot,
            parent_usn: self.parent_usn,
            route: self.route.clone(),
            parent_identity: self.parent_identity,
            identity: self.original_identity,
            components: self.components.clone(),
            old_components: self.old_components.clone(),
            snapshot: self.snapshot,
            basic: self.basic,
            usn: self.usn,
        })
    }
    /// Keep the original renamed object locally dirty after a sealed cached
    /// journal revision. No identity replacement or MARK_IN_SYNC is allowed.
    pub(super) fn complete_cached_queued(
        &mut self,
        connection: &ConfiguredRootConnection,
        claim: &dyn Fn() -> bool,
    ) -> Result<(u64, i64), Error> {
        self.verify(connection, false)?;
        if self.pending {
            if !claim() {
                return Err(Error::EditRecoveryUnavailable);
            }
            self.verify_handles(self.original_identity)?;
            self.attempted = true;
            return Ok((self.file().file_index, self.usn));
        }
        if !claim() {
            return Err(Error::EditRecoveryUnavailable);
        }
        self.attempted = true;
        let mut usn = self.usn;
        let hr = unsafe { CfSetInSyncState(self.protected.protected, 0, 0, &mut usn) };
        if hr < 0 || usn < self.usn {
            return Err(Error::EditRecoveryUnavailable);
        }
        let after = root_snapshot(self.protected.raw)?;
        if after.identity != self.snapshot.identity
            || after.file_size != self.snapshot.file_size
            || after.file_attributes != self.snapshot.file_attributes
            || after.placeholder_state & CF_PLACEHOLDER_STATE_IN_SYNC != 0
            || completion_usn(self.protected.raw, self.file().file_index)? != usn
            || native_namespace_directory::opaque_directory_identity(self.protected.raw)?
                != *self.original_identity.as_bytes()
        {
            return Err(Error::ConfiguredRootChanged);
        }
        self.usn = usn;
        Ok((self.file().file_index, usn))
    }
    /// Only inside ORIGINAL live publication/epoch fences, after one guarded
    /// remote MOVE proved same resource/strong unchanged ETag. The caller's
    /// claim binds its durable intent; no record/name alone can call this.
    pub(super) fn complete(
        &mut self,
        connection: &ConfiguredRootConnection,
        identity: crate::OpaqueIdentity,
        claim: &dyn Fn() -> bool,
    ) -> Result<(), Error> {
        self.verify(connection, false)?;
        if *identity.as_bytes() == [0; 16] || !claim() {
            return Err(Error::EditRecoveryUnavailable);
        }
        self.attempted = true;
        let before = self.basic;
        let mut usn = self.usn;
        // Identity only: SAME protected original, positive input USN. No body,
        // metadata, ranges, dehydration or MARK_IN_SYNC flags; never repair an
        // IN_SYNC bit that Windows cleared during rename/update.
        let hr = unsafe {
            CfUpdatePlaceholder(
                self.protected.protected,
                null(),
                identity.as_bytes().as_ptr().cast(),
                16,
                null(),
                0,
                0,
                &mut usn,
                null_mut(),
            )
        };
        if hr < 0 || usn <= 0 {
            return Err(Error::EditRecoveryUnavailable);
        }
        let after = completion_basic_info(self.protected.raw)?;
        if after.creation_time != before.creation_time
            || after.last_access_time != before.last_access_time
            || after.last_write_time != before.last_write_time
            || after.file_attributes != before.file_attributes
            || after.change_time < before.change_time
            || usn < self.usn
        {
            return Err(Error::ConfiguredRootChanged);
        }
        self.basic = after;
        self.usn = usn;
        self.updated = Some(identity);
        self.verify(connection, true)?;
        if completion_basic_info(self.protected.raw)? != after
            || completion_usn(self.protected.raw, self.file().file_index)? != usn
        {
            return Err(Error::ConfiguredRootChanged);
        }
        Ok(())
    }
}
impl VaultFileRenameSendProof {
    pub(super) fn check(&self) -> Result<(), CloudError> {
        self.check_native().map_err(|_| {
            CloudError::new(ErrorKind::Conflict, "original native vault rename changed")
        })
    }
    fn check_native(&self) -> Result<(), Error> {
        let identity = crate::ConfiguredRootIdentity {
            volume_serial: self.root.volume_serial,
            file_index: self.root.file_index,
        };
        let lease = pin_registered_configured_root(&self.root_path, identity)?;
        if let Some(p) = &self.source_parent {
            p.check(&lease, &self.root_path)?;
        }
        let (_, parts) = self
            .components
            .split_last()
            .ok_or(Error::ConfiguredRootChanged)?;
        let refs: Vec<_> = parts.iter().map(String::as_str).collect();
        let (parent, snapshot, _ancestors) =
            native_namespace_directory::pin_reinspected_namespace_parent(
                &lease,
                &self.root_path,
                &self.route,
                self.parent_identity,
                &refs,
            )?;
        if !same_edit_snapshot(snapshot, self.parent)
            || completion_usn(parent.0, snapshot.identity.file_index)? != self.parent_usn
            || !absent(&path(&self.root_path, &self.old_components))?
        {
            return Err(Error::ConfiguredRootChanged);
        }
        let destination = path(&self.root_path, &self.components);
        // Metadata only and SHARE_WRITE so this cannot conflict with a
        // retained original provider owner; never reopen body/write authority.
        let file = open_root(
            &destination,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
        )?;
        inspect(
            file.0,
            self.snapshot,
            self.basic,
            self.usn,
            self.identity,
            &destination,
            false,
        )?;
        native_namespace_directory::verify_reinspected_namespace_root(&lease, &self.root_path)
    }
}
