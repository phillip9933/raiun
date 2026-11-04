//! Native custody for one new child directory of a retained live vault.
//! Nondestructive conversion preserves local children; each child needs its
//! own independent admission, never implicit upload or subtree adoption.
//! No path, journal row or remote result alone authorizes publication.
use super::*;

#[link(name = "CldApi")]
unsafe extern "system" {
    fn CfConvertToPlaceholder(
        file: Handle,
        identity: *const c_void,
        length: u32,
        flags: u32,
        usn: *mut i64,
        overlapped: *mut c_void,
    ) -> HResult;
}

pub(super) struct VaultDirectoryPins {
    root_path: PathBuf,
    root: RootIdentity,
    components: Vec<String>,
    route: Vec<crate::PlaceholderChild>,
    parent_identity: crate::OpaqueIdentity,
    parent: RawOwnedHandle,
    parent_snapshot: RootSnapshot,
    parent_usn: i64,
    ancestors: Vec<(RawOwnedHandle, RootSnapshot)>,
    child: RawOwnedHandle,
    original: RootSnapshot,
    usn: i64,
    converted: Option<[u8; 16]>,
    attempted: bool,
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}
/// Read-only exact-source facts transferred to a joined worker. Every handle
/// is opened and retained on that worker; original owner pins remain alive.
#[derive(Clone)]
pub(super) struct VaultDirectorySendProof {
    root_path: PathBuf,
    root: RootIdentity,
    components: Vec<String>,
    route: Vec<crate::PlaceholderChild>,
    parent_identity: crate::OpaqueIdentity,
    parent: RootSnapshot,
    parent_usn: i64,
    original: RootSnapshot,
    usn: i64,
}

impl VaultDirectoryPins {
    /// The caller must first capture the exact live vault parent capability.
    /// This native adapter independently proves physical ancestry/opaque IDs.
    pub(super) fn pin(
        connection: &ConfiguredRootConnection,
        backend: &Arc<crate::OpenCloudPlaceholderBackend>,
        parent_components: &[String],
        route: &[crate::PlaceholderChild],
        parent_identity: crate::OpaqueIdentity,
        name: &str,
    ) -> Result<Self, Error> {
        let erased: Arc<dyn PlaceholderBackend> = backend.clone();
        if !connection.connected
            || !Arc::ptr_eq(&erased, &connection.state.backend)
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
        let result = Self::pin_root(root, parent_components, route, parent_identity, name)?;
        result.verify(connection, false)?;
        Ok(result)
    }
    fn pin_root(
        root: &OwnedConfiguredRoot,
        parent_components: &[String],
        route: &[crate::PlaceholderChild],
        parent_identity: crate::OpaqueIdentity,
        name: &str,
    ) -> Result<Self, Error> {
        if parent_components.is_empty()
            || parent_components.len() > 255
            || parent_components.iter().any(|p| !valid_component(p))
            || !valid_component(name)
        {
            return Err(Error::InvalidConfiguredRoot);
        }
        let parts: Vec<_> = parent_components.iter().map(String::as_str).collect();
        let (parent, parent_snapshot, ancestors) =
            native_namespace_directory::pin_namespace_parent(
                root,
                route,
                parent_identity,
                &parts,
                FILE_READ_ATTRIBUTES,
            )?;
        let parent_usn = completion_usn(parent.0, parent_snapshot.identity.file_index)?;
        if parent_usn <= 0 {
            return Err(Error::ConfiguredRootChanged);
        }
        let mut path = root.path.clone();
        for part in parent_components {
            path.push(part);
        }
        path.push(name);
        let wide = wide_path(&path)?;
        // No delete sharing: the original directory and its managed parents
        // cannot be renamed/replaced while this owner is awaiting remote work.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_READ_ATTRIBUTES | 2 | 1, // WRITE_DATA for convert, LIST_DIRECTORY metadata access.
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            return Err(win32_io_error("pin encrypted child directory"));
        }
        let child = RawOwnedHandle(raw);
        let original = root_snapshot(child.0)?;
        let usn = completion_usn(child.0, original.identity.file_index)?;
        if original.file_attributes & FILE_ATTRIBUTE_DIRECTORY == 0
            || original.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || original.reparse_tag != 0
            || original.placeholder_state != 0
            || original.identity.volume_serial != root.identity.volume_serial
            || original.identity.file_index == 0
            || usn <= 0
            || original.identity == parent_snapshot.identity
            || original.identity == root.identity
            || !windows_paths_equal(
                &final_path_for_handle(child.0).map_err(|_| Error::ConfiguredRootChanged)?,
                &path,
            )
        {
            return Err(Error::ConfiguredRootChanged);
        }
        Ok(Self {
            root_path: root.path.clone(),
            root: root.identity,
            components: parent_components
                .iter()
                .cloned()
                .chain(std::iter::once(name.to_owned()))
                .collect(),
            route: route.to_vec(),
            parent_identity,
            parent,
            parent_snapshot,
            parent_usn,
            ancestors,
            child,
            original,
            usn,
            converted: None,
            attempted: false,
            _thread: std::marker::PhantomData,
        })
    }
    pub(super) fn file(&self) -> crate::LocalFileIdentity {
        crate::LocalFileIdentity {
            volume_serial: self.original.identity.volume_serial,
            file_index: self.original.identity.file_index,
        }
    }
    pub(super) fn parent_file(&self) -> crate::LocalFileIdentity {
        crate::LocalFileIdentity {
            volume_serial: self.parent_snapshot.identity.volume_serial,
            file_index: self.parent_snapshot.identity.file_index,
        }
    }
    pub(super) fn parent_usn(&self) -> i64 {
        self.parent_usn
    }
    pub(super) fn usn(&self) -> i64 {
        self.usn
    }
    pub(super) fn components(&self) -> &[String] {
        &self.components
    }
    pub(super) fn send_proof(&self) -> Result<VaultDirectorySendProof, Error> {
        if self.attempted || self.converted.is_some() {
            return Err(Error::EditRecoveryUnavailable);
        }
        Ok(VaultDirectorySendProof {
            root_path: self.root_path.clone(),
            root: self.root,
            components: self.components.clone(),
            route: self.route.clone(),
            parent_identity: self.parent_identity,
            parent: self.parent_snapshot,
            parent_usn: self.parent_usn,
            original: self.original,
            usn: self.usn,
        })
    }
    pub(super) fn verify(
        &self,
        connection: &ConfiguredRootConnection,
        converted: bool,
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
        self.verify_handles(converted)
    }
    fn verify_handles(&self, converted: bool) -> Result<(), Error> {
        if !same_edit_snapshot(root_snapshot(self.parent.0)?, self.parent_snapshot)
            || completion_usn(self.parent.0, self.parent_snapshot.identity.file_index)?
                != self.parent_usn
            || native_namespace_directory::opaque_directory_identity(self.parent.0)?
                != *self.parent_identity.as_bytes()
        {
            return Err(Error::ConfiguredRootChanged);
        }
        if self.route.len() != self.ancestors.len() + 1 {
            return Err(Error::ConfiguredRootChanged);
        }
        for ((handle, snapshot), expected) in self.ancestors.iter().zip(&self.route) {
            let actual = root_snapshot(handle.0)?;
            if actual.identity != snapshot.identity
                || !cleanup_cloud_reparse_tag(actual.reparse_tag)
                || native_namespace_directory::opaque_directory_identity(handle.0)?.as_slice()
                    != expected.identity
            {
                return Err(Error::ConfiguredRootChanged);
            }
        }
        let actual = root_snapshot(self.child.0)?;
        let mut path = self.root_path.clone();
        for part in &self.components {
            path.push(part);
        }
        if actual.identity != self.original.identity
            || actual.file_attributes & FILE_ATTRIBUTE_DIRECTORY == 0
            || !windows_paths_equal(
                &final_path_for_handle(self.child.0).map_err(|_| Error::ConfiguredRootChanged)?,
                &path,
            )
            || completion_usn(self.child.0, actual.identity.file_index)? != self.usn
        {
            return Err(Error::ConfiguredRootChanged);
        }
        if converted {
            if !cleanup_cloud_reparse_tag(actual.reparse_tag)
                || actual.placeholder_state & CF_PLACEHOLDER_STATE_PLACEHOLDER == 0
                || Some(native_namespace_directory::opaque_directory_identity(
                    self.child.0,
                )?) != self.converted
            {
                return Err(Error::ConfiguredRootChanged);
            }
        } else if !same_edit_snapshot(actual, self.original)
            || actual.reparse_tag != 0
            || actual.placeholder_state != 0
        {
            return Err(Error::ConfiguredRootChanged);
        }
        Ok(())
    }
    /// Invoke only inside the original live account/route/epoch publication
    /// fence, after verified MKCOL and protected catalogue readback. No flags
    /// mark body clean or dehydrate; a directory has no plaintext body.
    pub(super) fn convert(
        &mut self,
        connection: &ConfiguredRootConnection,
        identity: [u8; 16],
    ) -> Result<(), Error> {
        if self.attempted || identity == [0; 16] {
            return Err(Error::EditRecoveryUnavailable);
        }
        self.verify(connection, false)?;
        self.attempted = true;
        let mut usn = self.usn;
        let hr = unsafe {
            CfConvertToPlaceholder(
                self.child.0,
                identity.as_ptr().cast(),
                16,
                4,
                &mut usn,
                null_mut(),
            )
        };
        if hr < 0 {
            return Err(native_error("publish encrypted child directory", hr));
        }
        if usn <= 0 || completion_usn(self.child.0, self.original.identity.file_index)? != usn {
            return Err(Error::ConfiguredRootChanged);
        }
        self.usn = usn;
        self.converted = Some(identity);
        self.verify(connection, true)
    }
}
impl VaultDirectorySendProof {
    /// This is a read-only final native send check. No names alone admit a
    /// mutation: original physical identities and positive USN must match.
    pub(super) fn check(&self) -> Result<(), Error> {
        let identity = crate::ConfiguredRootIdentity {
            volume_serial: self.root.volume_serial,
            file_index: self.root.file_index,
        };
        let lease = pin_registered_configured_root(&self.root_path, identity)?;
        let (name, parts) = self
            .components
            .split_last()
            .ok_or(Error::ConfiguredRootChanged)?;
        let refs: Vec<_> = parts.iter().map(String::as_str).collect();
        let (parent, parent_snapshot, _ancestors) =
            native_namespace_directory::pin_reinspected_namespace_parent(
                &lease,
                &self.root_path,
                &self.route,
                self.parent_identity,
                &refs,
            )?;
        let parent_usn = completion_usn(parent.0, parent_snapshot.identity.file_index)?;
        let mut path = self.root_path.clone();
        for p in parts {
            path.push(p);
        }
        path.push(name);
        let child = open_root(
            &path,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
        )?;
        let original = root_snapshot(child.0)?;
        let usn = completion_usn(child.0, original.identity.file_index)?;
        if original.file_attributes & FILE_ATTRIBUTE_DIRECTORY == 0
            || original.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || original.reparse_tag != 0
            || original.placeholder_state != 0
            || !windows_paths_equal(
                &final_path_for_handle(child.0).map_err(|_| Error::ConfiguredRootChanged)?,
                &path,
            )
        {
            return Err(Error::ConfiguredRootChanged);
        }
        if original.identity != self.original.identity
            || parent_snapshot.identity != self.parent.identity
            || !same_edit_snapshot(original, self.original)
            || parent_usn != self.parent_usn
            || usn != self.usn
        {
            return Err(Error::ConfiguredRootChanged);
        }
        native_namespace_directory::verify_reinspected_namespace_root(&lease, &self.root_path)
    }
}
