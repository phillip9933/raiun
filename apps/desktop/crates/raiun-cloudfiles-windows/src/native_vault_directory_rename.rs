//! Exact owned clean vault subtree after an observed native directory MOVE.
//! No file SHA, hydration, replay or IN_SYNC repair. Opaque IDs retain identity.
use super::native_vault_file_rename::{SourceParentPins, SourceParentProof};
use super::*;
use crate::opencloud::vault_child_create::VaultChildCreateParent;
use raiun_core::backend::{CloudError, ErrorKind, RemoteEntry};
struct Node {
    marker: RawOwnedHandle,
    protected: ProtectedCompletionFile,
    proof: NodeProof,
}
#[derive(Clone)]
struct NodeProof {
    snapshot: RootSnapshot,
    basic: FileBasicInfo,
    usn: i64,
    identity: [u8; 16],
    components: Vec<String>,
    original: RemoteEntry,
}
fn path(root: &Path, parts: &[String]) -> PathBuf {
    parts.iter().fold(root.to_owned(), |p, s| p.join(s))
}
fn inspect(h: Handle, p: &NodeProof, root: &Path) -> Result<(), Error> {
    let s = root_snapshot(h)?;
    if !same_edit_snapshot(s, p.snapshot)
        || completion_basic_info(h)? != p.basic
        || completion_usn(h, s.identity.file_index)? != p.usn
        || native_namespace_directory::opaque_directory_identity(h)? != p.identity
        || !windows_paths_equal(
            &final_path_for_handle(h).map_err(|_| Error::ConfiguredRootChanged)?,
            &path(root, &p.components),
        )
        || (!p.original.directory
            && (!native_vault_file_rename::links_one(h, s.identity)?
                || modified_ranges_for_handle(h).map_err(|_| Error::EditRecoveryUnavailable)?))
    {
        return Err(Error::ConfiguredRootChanged);
    }
    Ok(())
}
fn marker(path: &Path, directory: bool, share: u32) -> Result<RawOwnedHandle, Error> {
    let wide = wide_path(path)?;
    let h = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_READ_ATTRIBUTES | if directory { 1 } else { 0 },
            share,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS | 0x0010_0000,
            null_mut(),
        )
    };
    if h.is_null() || h == INVALID_HANDLE_VALUE {
        return Err(win32_io_error("pin vault directory subtree metadata"));
    }
    Ok(RawOwnedHandle(h))
}
pub(super) struct VaultDirectoryRenamePins {
    root: RootIdentity,
    root_path: PathBuf,
    source_parent: SourceParentPins,
    destination_parent: SourceParentPins,
    old: Vec<String>,
    nodes: Vec<Node>,
    completed: bool,
}
#[derive(Clone)]
pub(super) struct VaultDirectoryRenameSendProof {
    root: RootIdentity,
    root_path: PathBuf,
    source_parent: SourceParentProof,
    destination_parent: SourceParentProof,
    old: Vec<String>,
    nodes: Vec<NodeProof>,
}
impl VaultDirectoryRenamePins {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn pin(
        connection: &ConfiguredRootConnection,
        backend: &Arc<crate::OpenCloudPlaceholderBackend>,
        parent: &VaultChildCreateParent,
        destination_parent: &VaultChildCreateParent,
        old: &[String],
        new: &[String],
        file: LocalFileIdentity,
        entries: &[crate::vault_custody::VaultCatalogueEntry],
    ) -> Result<Self, Error> {
        let erased: Arc<dyn PlaceholderBackend> = backend.clone();
        if !connection.connected
            || !Arc::ptr_eq(&erased, &connection.state.backend)
            || backend.is_revoked()
            || entries.is_empty()
            || entries.len() > 1024
            || old.len() < 2
            || new.len() < 2
            || new.starts_with(old)
        {
            return Err(Error::EditRecoveryUnavailable);
        }
        let root = connection
            .root
            .as_ref()
            .ok_or(Error::ConfiguredRootChanged)?;
        root.verify_identity(true)?;
        root.verify_registered()?;
        let source_parent =
            SourceParentPins::pin(root, parent.components(), parent.route(), parent.opaque())?;
        let destination_parent = SourceParentPins::pin(
            root,
            destination_parent.components(),
            destination_parent.route(),
            destination_parent.opaque(),
        )?;
        let original = entries
            .iter()
            .find(|e| {
                e.metadata.directory
                    && e.metadata.path
                        == format!(
                            "{}/{}",
                            parent.metadata().path.trim_end_matches('/'),
                            old.last().unwrap()
                        )
            })
            .ok_or(Error::EditRecoveryUnavailable)?;
        let mut expected = entries.iter().collect::<Vec<_>>();
        expected.sort_by_key(|e| e.metadata.path.len());
        let mut nodes = Vec::new();
        let mut ids = std::collections::BTreeSet::new();
        let mut files = std::collections::BTreeSet::new();
        for e in expected {
            let suffix = e
                .metadata
                .path
                .strip_prefix(&original.metadata.path)
                .ok_or(Error::ConfiguredRootChanged)?;
            if !suffix.is_empty() && !suffix.starts_with('/') {
                return Err(Error::ConfiguredRootChanged);
            }
            let mut components = new.to_vec();
            for part in suffix.split('/').filter(|p| !p.is_empty()) {
                if !valid_component(part) {
                    return Err(Error::ConfiguredRootChanged);
                }
                components.push(part.to_owned());
            }
            if components.len() > 256 || components.iter().map(String::len).sum::<usize>() > 32000 {
                return Err(Error::ConfiguredRootChanged);
            }
            let p = path(&root.path, &components);
            let marker = marker(&p, e.metadata.directory, FILE_SHARE_READ)?;
            let s = root_snapshot(marker.0)?;
            if s.identity.volume_serial != root.identity.volume_serial
                || s.identity.file_index == 0
                || s.identity == root.identity
                || !files.insert(s.identity.file_index)
                || !ids.insert(e.identity)
                || (s.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0) != e.metadata.directory
                || s.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
                || !cleanup_cloud_reparse_tag(s.reparse_tag)
                || s.placeholder_state & CF_PLACEHOLDER_STATE_PLACEHOLDER == 0
                || s.placeholder_state & CF_PLACEHOLDER_STATE_IN_SYNC == 0
                || s.placeholder_state & CF_PLACEHOLDER_STATE_SYNC_ROOT != 0
                || s.placeholder_state & !0x3f != 0
                || s.file_size != e.metadata.size
                || (suffix.is_empty()
                    && (s.identity.file_index != file.file_index
                        || s.identity.volume_serial != file.volume_serial))
            {
                return Err(Error::ConfiguredRootChanged);
            }
            let protected = ProtectedCompletionFile::open_for_cleanup(&wide_path(&p)?)?;
            let usn = completion_usn(protected.raw, s.identity.file_index)?;
            if usn <= 0 {
                return Err(Error::EditRecoveryUnavailable);
            }
            let proof = NodeProof {
                snapshot: s,
                basic: completion_basic_info(protected.raw)?,
                usn,
                identity: e.identity,
                components,
                original: e.metadata.clone(),
            };
            inspect(protected.raw, &proof, &root.path)?;
            nodes.push(Node {
                marker,
                protected,
                proof,
            });
        }
        let pins = Self {
            root: root.identity,
            root_path: root.path.clone(),
            source_parent,
            destination_parent,
            old: old.to_vec(),
            nodes,
            completed: false,
        };
        pins.check(connection, true)?;
        Ok(pins)
    }
    pub(super) fn check(
        &self,
        connection: &ConfiguredRootConnection,
        enumerate: bool,
    ) -> Result<(), Error> {
        let root = connection
            .root
            .as_ref()
            .ok_or(Error::ConfiguredRootChanged)?;
        root.verify_identity(true)?;
        root.verify_registered()?;
        if !connection.connected
            || connection.state.readiness.load(Ordering::Acquire) != CALLBACK_READY
            || root.identity != self.root
            || !windows_paths_equal(&root.path, &self.root_path)
            || connection
                .state
                .unverifiable_placeholder_closes
                .load(Ordering::Acquire)
                != 0
            || !native_vault_file_rename::absent(&path(&self.root_path, &self.old))?
        {
            return Err(Error::ConfiguredRootChanged);
        }
        self.source_parent.check(&self.root_path)?;
        self.destination_parent.check(&self.root_path)?;
        let activity = connection
            .state
            .activity
            .try_lock()
            .map_err(|_| Error::EditRecoveryUnavailable)?;
        if activity.active_fetches != 0 || activity.staged_fetches != 0 {
            return Err(Error::EditRecoveryUnavailable);
        }
        drop(activity);
        for node in &self.nodes {
            inspect(node.protected.raw, &node.proof, &self.root_path)?;
            inspect(node.marker.0, &node.proof, &self.root_path)?;
            if enumerate && node.proof.original.directory {
                // ON_DISK_ONLY avoids a provider enumeration callback/HTTP
                // reentry while the original publication fence is retained.
                let actual = native_vault_cleanup_inventory::local_names(&path(
                    &self.root_path,
                    &node.proof.components,
                ))?;
                let expected = self
                    .nodes
                    .iter()
                    .filter(|e| {
                        e.proof.components.len() == node.proof.components.len() + 1
                            && e.proof.components.starts_with(&node.proof.components)
                    })
                    .collect::<Vec<_>>();
                if actual.len() != expected.len()
                    || actual.iter().any(|name| {
                        !expected
                            .iter()
                            .any(|e| e.proof.components.last() == Some(name))
                    })
                {
                    return Err(Error::ConfiguredRootChanged);
                }
                inspect(node.protected.raw, &node.proof, &self.root_path)?;
            }
        }
        Ok(())
    }
    pub(super) fn facts(
        &self,
    ) -> Result<(u64, i64, u64, i64, Vec<crate::VaultDirectoryRenameNode>), Error> {
        let first = self.nodes.first().ok_or(Error::ConfiguredRootChanged)?;
        Ok((
            first.proof.snapshot.identity.file_index,
            first.proof.usn,
            self.source_parent.file().file_index,
            self.source_parent.usn(),
            self.nodes
                .iter()
                .skip(1)
                .map(|n| crate::VaultDirectoryRenameNode {
                    identity: n.proof.identity,
                    file: n.proof.snapshot.identity.file_index,
                    usn: n.proof.usn,
                    original: n.proof.original.clone(),
                    new_components: n.proof.components.clone(),
                })
                .collect(),
        ))
    }
    pub(super) fn destination_parent_file(&self) -> u64 {
        self.destination_parent.file().file_index
    }
    pub(super) fn destination_parent_usn(&self) -> i64 {
        self.destination_parent.usn()
    }
    pub(super) fn send_proof(&self) -> Result<VaultDirectoryRenameSendProof, Error> {
        if self.completed {
            return Err(Error::EditRecoveryUnavailable);
        }
        Ok(VaultDirectoryRenameSendProof {
            root: self.root,
            root_path: self.root_path.clone(),
            source_parent: self.source_parent.send_proof(),
            destination_parent: self.destination_parent.send_proof(),
            old: self.old.clone(),
            nodes: self.nodes.iter().map(|n| n.proof.clone()).collect(),
        })
    }
    /// Windows already performed the rename. Every opaque remains original, so
    /// completion is exact whole-tree readback, never a fabricated dirty-bit repair.
    pub(super) fn complete(
        &mut self,
        connection: &ConfiguredRootConnection,
        claim: &dyn Fn() -> bool,
    ) -> Result<Vec<(u64, i64)>, Error> {
        self.check(connection, true)?;
        if self.completed || !claim() {
            return Err(Error::EditRecoveryUnavailable);
        }
        self.completed = true;
        self.check(connection, true)?;
        Ok(self
            .nodes
            .iter()
            .map(|n| (n.proof.snapshot.identity.file_index, n.proof.usn))
            .collect())
    }
}
impl VaultDirectoryRenameSendProof {
    pub(super) fn check(&self) -> Result<(), CloudError> {
        self.check_native().map_err(|_| {
            CloudError::new(ErrorKind::Conflict, "original native vault subtree changed")
        })
    }
    fn check_native(&self) -> Result<(), Error> {
        let lease = pin_registered_configured_root(
            &self.root_path,
            crate::ConfiguredRootIdentity {
                volume_serial: self.root.volume_serial,
                file_index: self.root.file_index,
            },
        )?;
        self.source_parent.check(&lease, &self.root_path)?;
        self.destination_parent.check(&lease, &self.root_path)?;
        if !native_vault_file_rename::absent(&path(&self.root_path, &self.old))? {
            return Err(Error::ConfiguredRootChanged);
        }
        for node in &self.nodes {
            let h = marker(
                &path(&self.root_path, &node.components),
                false,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
            )?;
            inspect(h.0, node, &self.root_path)?;
        }
        native_namespace_directory::verify_reinspected_namespace_root(&lease, &self.root_path)
    }
}
