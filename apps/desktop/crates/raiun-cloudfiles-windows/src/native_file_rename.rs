//! Narrow native admission and identity-only completion for same-parent file rename.
#[path = "native_file_move.rs"]
mod file_move;
use super::*;
use crate::FileRenameBindingCandidate;
use crate::namespace_file_rename::{
    FileRenameCompletionError, FileRenameLocal, FileRenameReadback,
};
use crate::namespace_intent::{
    LocalNamespaceEntry, NamespaceIntent, NamespaceObjectKind, NamespaceOperation,
    StorageClassification,
};
use crate::opencloud::VerifiedRenameSourceContent;
use raiun_core::backend::{CloudError, ErrorKind};
use std::{cell::Cell, time::Instant};

fn conflict() -> CloudError {
    CloudError::new(ErrorKind::Conflict, "native file rename binding changed")
}

fn native_digest(value: &str) -> Result<[u8; 32], Error> {
    if value.len() != 64 {
        return Err(Error::EditRecoveryUnavailable);
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = (pair[0] as char)
            .to_digit(16)
            .ok_or(Error::EditRecoveryUnavailable)?;
        let low = (pair[1] as char)
            .to_digit(16)
            .ok_or(Error::EditRecoveryUnavailable)?;
        digest[index] = ((high << 4) | low) as u8;
    }
    Ok(digest)
}

fn move_parts(
    intent: &NamespaceIntent,
) -> Result<
    (
        &crate::namespace_intent::ExistingNamespaceEntry,
        &LocalNamespaceEntry,
    ),
    Error,
> {
    let NamespaceOperation::MoveWithinScope {
        source,
        destination,
    } = &intent.operation
    else {
        return Err(Error::EditRecoveryUnavailable);
    };
    if intent.record_generation == 0
        || source.local.object_kind != NamespaceObjectKind::File
        || destination.object_kind != NamespaceObjectKind::File
        || source.local.parent != destination.parent
        || source.local.local_file != destination.local_file
        || source.local.name.eq_ignore_ascii_case(&destination.name)
        || source.local.parent.classification != StorageClassification::Ordinary
        || !match source
            .local
            .parent
            .local_components
            .first()
            .map(String::as_str)
        {
            Some("Personal") => true,
            Some("Spaces") => source.local.parent.local_components.len() >= 2,
            _ => false,
        }
    {
        return Err(Error::EditRecoveryUnavailable);
    }
    Ok((source, destination))
}

fn same_root_entry(
    snapshot: RootSnapshot,
    expected_root: RootIdentity,
    file: LocalFileIdentity,
    size: u64,
) -> bool {
    snapshot.identity.volume_serial == expected_root.volume_serial
        && snapshot.identity.file_index == file.file_index
        && file.volume_serial == expected_root.volume_serial
        && snapshot.file_attributes & FILE_ATTRIBUTE_DIRECTORY == 0
        && snapshot.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        && cleanup_cloud_reparse_tag(snapshot.reparse_tag)
        && snapshot.placeholder_state == CF_PLACEHOLDER_STATE_PLACEHOLDER
        && snapshot.file_size == size
}
fn same_snapshot(left: RootSnapshot, right: RootSnapshot) -> bool {
    left.identity == right.identity
        && left.file_attributes == right.file_attributes
        && left.reparse_tag == right.reparse_tag
        && left.placeholder_state == right.placeholder_state
        && left.file_size == right.file_size
        && left.last_write_time == right.last_write_time
}

fn file_links(handle: Handle, expected: RootIdentity) -> Result<bool, Error> {
    let mut info: ByHandleFileInformation = unsafe { zeroed() };
    // SAFETY: live no-follow file handle pinned by this module.
    if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
        return Err(win32_io_error("inspect file rename link count"));
    }
    let actual = RootIdentity {
        volume_serial: info.volume_serial_number,
        file_index: (u64::from(info.file_index_high) << 32) | u64::from(info.file_index_low),
    };
    if actual != expected || actual.file_index == 0 {
        return Err(Error::ConfiguredRootChanged);
    }
    Ok(info.number_of_links == 1)
}

fn absent(path: &Path) -> Result<bool, Error> {
    let wide = wide_path(path)?;
    // Check the directory entry itself, including dangling reparse points.
    // Only not-found results mean absent; sharing/permission errors fail closed.
    let handle = unsafe {
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
    if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
        unsafe { CloseHandle(handle) };
        return Ok(false);
    }
    match unsafe { GetLastError() } {
        2 | 3 => Ok(true),
        _ => Err(win32_io_error("check rename source absence")),
    }
}

pub(crate) struct PinnedFileRename<'connection> {
    connection: &'connection ConfiguredRootConnection,
    backend: Arc<crate::OpenCloudPlaceholderBackend>,
    recovery: Arc<dyn PreparedEditRecovery>,
    operation: NamespaceOperation,
    generation: u64,
    root: RootIdentity,
    root_path: PathBuf,
    parent: RawOwnedHandle,
    parent_snapshot: RootSnapshot,
    parent_route: Vec<[u8; 16]>,
    _parent_ancestors: Vec<(RawOwnedHandle, RootSnapshot)>,
    _path_directories: Vec<RawOwnedHandle>,
    _destination: RawOwnedHandle,
    protected: ProtectedCompletionFile,
    destination_snapshot: RootSnapshot,
    destination_basic: FileBasicInfo,
    destination_usn: i64,
    parent_identity: crate::OpaqueIdentity,
    source_identity: crate::OpaqueIdentity,
    file: LocalFileIdentity,
    source_path: PathBuf,
    destination_path: PathBuf,
    digest: [u8; 32],
    size: u64,
    identity_update_attempted: bool,
}

impl ConfiguredRootConnection {
    /// Retain the callback owner's exact admission and recovery capabilities.
    /// Owner-thread only, before HTTP and outside a backend session lease.
    pub(crate) fn file_rename_guard_context(
        &self,
        backend: &Arc<crate::OpenCloudPlaceholderBackend>,
    ) -> Result<
        (
            Arc<crate::close_capture_admission::CloseCaptureAdmission>,
            Arc<dyn PreparedEditRecovery>,
        ),
        Error,
    > {
        let erased: Arc<dyn PlaceholderBackend> = backend.clone();
        if !self.connected
            || self.state.readiness.load(Ordering::Acquire) != CALLBACK_READY
            || backend.is_revoked()
            || !Arc::ptr_eq(&erased, &self.state.backend)
            || !backend.owns_composite_root_identity(self.composite_root_identity)
            || self
                .state
                .unverifiable_placeholder_closes
                .load(Ordering::Acquire)
                != 0
            || self
                .state
                .vault_dirty
                .try_lock()
                .map(|dirty| dirty.has_pending())
                .unwrap_or(true)
        {
            return Err(Error::EditRecoveryUnavailable);
        }
        let root = self.root.as_ref().ok_or(Error::ConfiguredRootChanged)?;
        root.verify_identity(true)?;
        root.verify_registered()?;
        let recovery = self
            .state
            .recovery
            .as_ref()
            .ok_or(Error::EditRecoveryUnavailable)?;
        let root_identity = crate::ConfiguredRootIdentity {
            volume_serial: root.identity.volume_serial,
            file_index: root.identity.file_index,
        };
        if recovery.provider_scope() != backend.scope() || recovery.root_identity() != root_identity
        {
            return Err(Error::EditRecoveryUnavailable);
        }
        Ok((
            Arc::clone(&self.state.close_capture_admission),
            Arc::clone(recovery),
        ))
    }

    fn validate_file_rename_candidate_connection(
        &self,
        backend: &Arc<crate::OpenCloudPlaceholderBackend>,
        candidate: &FileRenameBindingCandidate<'_>,
        generation: u64,
    ) -> Result<RootIdentity, Error> {
        if generation == 0
            || !self.connected
            || self.state.readiness.load(Ordering::Acquire) != CALLBACK_READY
        {
            return Err(Error::ProviderUnavailable);
        }
        let erased: Arc<dyn PlaceholderBackend> = backend.clone();
        if !Arc::ptr_eq(&erased, &self.state.backend) {
            return Err(Error::ProviderUnavailable);
        }
        let root = self.root.as_ref().ok_or(Error::ConfiguredRootChanged)?;
        root.verify_identity(true)?;
        root.verify_registered()?;
        let root_identity = crate::ConfiguredRootIdentity {
            volume_serial: root.identity.volume_serial,
            file_index: root.identity.file_index,
        };
        let recovery = self
            .state
            .recovery
            .as_ref()
            .ok_or(Error::EditRecoveryUnavailable)?;
        let provider_scope = recovery.provider_scope();
        let scope = candidate.catalog_scope();
        let authorization = candidate.authorization();
        if recovery.root_identity() != root_identity
            || scope.local_root() != root_identity
            || scope.profile_id() != provider_scope.profile_id()
            || scope.account_id() != provider_scope.account_id()
            || scope.server_origin() != provider_scope.server_origin()
            || authorization.token_generation != provider_scope.token_generation()
            || authorization.agent_generation == 0
            || candidate.local_file_hint().volume_serial != root_identity.volume_serial
            || candidate.local_file_hint().file_index == 0
        {
            return Err(Error::ProviderUnavailable);
        }
        Ok(root.identity)
    }

    /// Read-only connection/root/recovery admission before a candidate-parent
    /// session performs any HTTP metadata refresh.
    pub(crate) fn preflight_file_rename_candidate(
        &self,
        backend: &Arc<crate::OpenCloudPlaceholderBackend>,
        candidate: &FileRenameBindingCandidate<'_>,
        generation: u64,
        owner_current: &dyn Fn(crate::namespace_intent::CapturedAuthorization) -> bool,
    ) -> Result<(), Error> {
        self.validate_file_rename_candidate_connection(backend, candidate, generation)?;
        if !backend.file_rename_token_is_current()
            || !backend.owns_composite_root_identity(self.composite_root_identity)
            || !owner_current(candidate.authorization())
        {
            return Err(Error::ProviderUnavailable);
        }
        Ok(())
    }

    /// Assemble the full local/remote intent only after a fresh backend parent
    /// capture and native pin have been joined to this exact configured root.
    /// The resulting intent remains a proposal; the existing producer repeats
    /// all parent/file proofs under its fresh sessions before publication.
    pub(crate) fn intent_from_file_rename_candidate(
        &self,
        backend: &Arc<crate::OpenCloudPlaceholderBackend>,
        candidate: &FileRenameBindingCandidate<'_>,
        captured: &crate::CapturedDirectoryParent,
        generation: u64,
    ) -> Result<NamespaceIntent, Error> {
        self.validate_file_rename_candidate_connection(backend, candidate, generation)?;
        let root = self.root.as_ref().ok_or(Error::ConfiguredRootChanged)?;
        let root_identity = crate::ConfiguredRootIdentity {
            volume_serial: root.identity.volume_serial,
            file_index: root.identity.file_index,
        };
        let scope = candidate.catalog_scope();
        let authorization = candidate.authorization();
        if captured.identity != candidate.parent_identity()
            || captured.remote.resource_id != candidate.parent_remote_id()
            || captured.scope.profile_id != scope.profile_id
            || captured.scope.account_subject != scope.account_id
            || captured.scope.server_origin != scope.server_origin
            || captured.scope.space_id != candidate.space_id()
            || captured.scope.root_resource_id != candidate.root_resource_id()
            || captured.scope.root_volume_serial != root_identity.volume_serial
            || captured.scope.root_file_index != root_identity.file_index
        {
            return Err(Error::ProviderUnavailable);
        }

        let pair = candidate.rename_hint_pair();
        let old = pair.old_components();
        let new = pair.new_components();
        if old.len() < 2
            || old.len() != new.len()
            || !match old.first().map(String::as_str) {
                Some("Personal") => old.len() >= 2,
                Some("Spaces") => old.len() >= 3,
                _ => false,
            }
            || old[..old.len() - 1] != new[..new.len() - 1]
            || old
                .iter()
                .chain(new)
                .any(|component| !valid_component(component))
            || old[old.len() - 1].eq_ignore_ascii_case(&new[new.len() - 1])
            || captured.route.len() != old.len() - 1
        {
            return Err(Error::InvalidConfiguredRoot);
        }
        let parent_components = old[..old.len() - 1]
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let remote_parent_path = candidate
            .source_path()
            .rsplit_once('/')
            .map(|(parent, _)| if parent.is_empty() { "/" } else { parent })
            .ok_or(Error::ConfiguredRootChanged)?;
        if captured.path != remote_parent_path {
            return Err(Error::ConfiguredRootChanged);
        }

        let (parent_handle, parent_snapshot, _ancestors) =
            native_namespace_directory::pin_namespace_parent(
                root,
                &captured.route,
                captured.identity,
                &parent_components,
                FILE_READ_ATTRIBUTES,
            )?;
        if parent_snapshot.identity.volume_serial != root.identity.volume_serial
            || parent_snapshot.identity.file_index == 0
        {
            return Err(Error::ConfiguredRootChanged);
        }

        let mut source_path = root.path.clone();
        for part in old {
            source_path.push(part);
        }
        let mut destination_path = root.path.clone();
        for part in new {
            destination_path.push(part);
        }
        if !absent(&source_path)? {
            return Err(Error::ConfiguredRootChanged);
        }
        let (root_final, _path_directories, entry, snapshot) = pin_callback_path_chain(
            &destination_path,
            root.identity,
            candidate.local_file_hint().file_index,
            CallbackSizePolicy::Exact(candidate.source_size()),
        )
        .map_err(|_| Error::ConfiguredRootChanged)?;
        if !windows_paths_equal(&root_final, &root.path)
            || !same_root_entry(
                snapshot,
                root.identity,
                candidate.local_file_hint(),
                candidate.source_size(),
            )
            || !windows_paths_equal(
                &final_path_for_handle(entry.0).map_err(|_| Error::ConfiguredRootChanged)?,
                &destination_path,
            )
            || !windows_paths_equal(
                &final_path_for_handle(parent_handle.0)
                    .map_err(|_| Error::ConfiguredRootChanged)?,
                destination_path
                    .parent()
                    .ok_or(Error::ConfiguredRootChanged)?,
            )
            || !file_links(entry.0, snapshot.identity)?
            || modified_ranges_for_handle(entry.0).map_err(|_| Error::EditRecoveryUnavailable)?
        {
            return Err(Error::ConfiguredRootChanged);
        }
        verify_completion_identity(entry.0, candidate.source_identity().as_bytes())?;
        if !absent(&source_path)? {
            return Err(Error::ConfiguredRootChanged);
        }
        root.verify_identity(true)?;
        root.verify_registered()?;

        let parent = crate::namespace_intent::NamespaceParent {
            scope: captured.scope.clone(),
            authorization,
            classification: StorageClassification::Ordinary,
            local_file: crate::LocalFileIdentity {
                volume_serial: parent_snapshot.identity.volume_serial,
                file_index: parent_snapshot.identity.file_index,
            },
            local_components: parent_components
                .iter()
                .map(|part| (*part).to_owned())
                .collect(),
            remote: captured.remote.clone(),
        };
        let local_file = crate::LocalFileIdentity {
            volume_serial: snapshot.identity.volume_serial,
            file_index: snapshot.identity.file_index,
        };
        let source = crate::namespace_intent::ExistingNamespaceEntry {
            local: LocalNamespaceEntry {
                parent: parent.clone(),
                name: old.last().cloned().ok_or(Error::InvalidConfiguredRoot)?,
                local_file,
                object_kind: NamespaceObjectKind::File,
            },
            remote: crate::RemoteEditBaseline {
                resource_id: candidate.source_remote_id().to_owned(),
                etag: candidate.source_etag().to_owned(),
                byte_len: candidate.source_size(),
            },
        };
        let destination = LocalNamespaceEntry {
            parent,
            name: new.last().cloned().ok_or(Error::InvalidConfiguredRoot)?,
            local_file,
            object_kind: NamespaceObjectKind::File,
        };
        let intent = NamespaceIntent {
            schema_version: 1,
            // FileRenameStore replaces this validation placeholder with its
            // own random record ID before durable publication.
            record_id: "0".repeat(32),
            record_generation: generation,
            operation: NamespaceOperation::MoveWithinScope {
                source,
                destination,
            },
        };
        intent
            .validate()
            .map_err(|_| Error::EditRecoveryUnavailable)?;
        Ok(intent)
    }

    pub(crate) fn prepare_pinned_file_rename<'connection>(
        &'connection self,
        backend: &Arc<crate::OpenCloudPlaceholderBackend>,
        session: &crate::FileRenameSession<'_>,
        intent: &NamespaceIntent,
    ) -> Result<PinnedFileRename<'connection>, Error> {
        let (source, destination) = move_parts(intent)?;
        let erased: Arc<dyn PlaceholderBackend> = backend.clone();
        if !Arc::ptr_eq(&erased, &self.state.backend)
            || !std::ptr::eq(backend.as_ref(), session.backend())
            || !self.connected
            || self.state.readiness.load(Ordering::Acquire) != CALLBACK_READY
            || intent.operation != session.intent().operation
            || intent.record_generation != session.intent().record_generation
        {
            return Err(Error::ProviderUnavailable);
        }
        let root = self.root.as_ref().ok_or(Error::ConfiguredRootChanged)?;
        root.verify_identity(true)?;
        root.verify_registered()?;
        let root_identity = root.identity;
        let root_public = crate::ConfiguredRootIdentity {
            volume_serial: root_identity.volume_serial,
            file_index: root_identity.file_index,
        };
        let recovery = self
            .state
            .recovery
            .as_ref()
            .ok_or(Error::EditRecoveryUnavailable)?;
        if recovery.provider_scope() != backend.scope()
            || recovery.root_identity() != root_public
            || source.local.parent.scope.root_volume_serial != root_identity.volume_serial
            || source.local.parent.scope.root_file_index != root_identity.file_index
        {
            return Err(Error::ProviderUnavailable);
        }
        let captured = session
            .capture_native_parent()
            .map_err(|_| Error::ProviderUnavailable)?;
        let components = source
            .local
            .parent
            .local_components
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let (parent, parent_snapshot, parent_ancestors) =
            native_namespace_directory::pin_namespace_parent(
                root,
                &captured.route,
                captured.identity,
                &components,
                FILE_READ_ATTRIBUTES,
            )?;
        if parent_snapshot.identity.file_index != source.local.parent.local_file.file_index
            || parent_snapshot.identity.volume_serial
                != source.local.parent.local_file.volume_serial
            || captured.identity != session.parent_identity()
            || captured.remote != source.local.parent.remote
        {
            return Err(Error::ConfiguredRootChanged);
        }
        let mut source_path = root.path.clone();
        for part in &source.local.parent.local_components {
            source_path.push(part);
        }
        source_path.push(&source.local.name);
        let mut destination_path = root.path.clone();
        for part in &destination.parent.local_components {
            destination_path.push(part);
        }
        destination_path.push(&destination.name);
        if !absent(&source_path)? || !valid_component(&destination.name) {
            return Err(Error::ConfiguredRootChanged);
        }
        let (root_final, path_directories, entry, snapshot) = pin_callback_path_chain(
            &destination_path,
            root_identity,
            source.local.local_file.file_index,
            CallbackSizePolicy::Exact(source.remote.byte_len),
        )
        .map_err(|_| Error::ConfiguredRootChanged)?;
        if !windows_paths_equal(&root_final, &root.path)
            || !same_root_entry(
                snapshot,
                root_identity,
                source.local.local_file,
                source.remote.byte_len,
            )
        {
            return Err(Error::ConfiguredRootChanged);
        }
        let leaf_final =
            final_path_for_handle(entry.0).map_err(|_| Error::ConfiguredRootChanged)?;
        let expected_parent = destination_path
            .parent()
            .ok_or(Error::ConfiguredRootChanged)?;
        let route_ids = captured
            .route
            .iter()
            .map(|child| {
                child
                    .identity
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::ConfiguredRootChanged)
            })
            .collect::<Result<Vec<[u8; 16]>, Error>>()?;
        if !windows_paths_equal(&leaf_final, &destination_path)
            || !windows_paths_equal(
                &final_path_for_handle(parent.0).map_err(|_| Error::ConfiguredRootChanged)?,
                expected_parent,
            )
        {
            return Err(Error::ConfiguredRootChanged);
        }
        let entry_path = wide_path(&destination_path)?;
        let protected = ProtectedCompletionFile::open(&entry_path)?;
        let protected_snapshot = root_snapshot(protected.raw)?;
        let basic = completion_basic_info(protected.raw)?;
        if !same_snapshot(protected_snapshot, snapshot)
            || !same_root_entry(
                protected_snapshot,
                root_identity,
                source.local.local_file,
                source.remote.byte_len,
            )
            || basic.file_attributes != snapshot.file_attributes
            || !file_links(protected.raw, protected_snapshot.identity)?
            || modified_ranges_for_handle(protected.raw)
                .map_err(|_| Error::EditRecoveryUnavailable)?
            || basic.creation_time <= 0
            || basic.last_access_time <= 0
            || basic.last_write_time <= 0
            || basic.change_time <= 0
        {
            return Err(Error::ConfiguredRootChanged);
        }
        verify_completion_identity(protected.raw, session.source_identity().as_bytes())?;
        let usn = completion_usn(protected.raw, source.local.local_file.file_index)?;
        if usn <= 0 || !absent(&source_path)? {
            return Err(Error::ConfiguredRootChanged);
        }
        let remaining = session
            .deadline()
            .checked_duration_since(Instant::now())
            .ok_or(Error::EditRecoveryUnavailable)?;
        let cancellation = crate::CancellationToken::with_timeout(remaining);
        let digest = native_digest(
            &protected.digest_complete(source.remote.byte_len, Some(&cancellation))?,
        )?;
        let after_hash = root_snapshot(protected.raw)?;
        let after_basic = completion_basic_info(protected.raw)?;
        let after_usn = completion_usn(protected.raw, source.local.local_file.file_index)?;
        if !same_snapshot(after_hash, protected_snapshot)
            || after_basic != basic
            || after_usn != usn
            || !absent(&source_path)?
        {
            return Err(Error::ConfiguredRootChanged);
        }
        root.verify_identity(true)?;
        root.verify_registered()?;
        Ok(PinnedFileRename {
            connection: self,
            backend: backend.clone(),
            recovery: Arc::clone(recovery),
            operation: intent.operation.clone(),
            generation: intent.record_generation,
            root: root_identity,
            root_path: root.path.clone(),
            parent,
            parent_snapshot,
            parent_route: route_ids,
            _parent_ancestors: parent_ancestors,
            _path_directories: path_directories,
            _destination: entry,
            protected,
            destination_snapshot: protected_snapshot,
            destination_basic: basic,
            destination_usn: usn,
            parent_identity: captured.identity,
            source_identity: session.source_identity(),
            file: source.local.local_file,
            source_path,
            destination_path,
            digest,
            size: source.remote.byte_len,
            identity_update_attempted: false,
        })
    }
}

impl<'connection> PinnedFileRename<'connection> {
    pub(crate) fn local<'pin, 'session, 'backend>(
        &'pin mut self,
        session: &'session crate::FileRenameSession<'backend>,
    ) -> NativeFileRenameLocal<'pin, 'connection, 'session, 'backend> {
        NativeFileRenameLocal {
            pins: self,
            session,
            source_proof: None,
        }
    }
    fn matches(&self, intent: &NamespaceIntent) -> bool {
        intent.record_generation == self.generation && intent.operation == self.operation
    }
    fn verify_native(
        &self,
        identity: &[u8; 16],
    ) -> Result<(RootSnapshot, FileBasicInfo, i64), Error> {
        let root = self
            .connection
            .root
            .as_ref()
            .ok_or(Error::ConfiguredRootChanged)?;
        root.verify_identity(true)?;
        root.verify_registered()?;
        let recovery = self
            .connection
            .state
            .recovery
            .as_ref()
            .ok_or(Error::EditRecoveryUnavailable)?;
        if !self.connection.connected
            || self.connection.state.readiness.load(Ordering::Acquire) != CALLBACK_READY
            || !Arc::ptr_eq(recovery, &self.recovery)
            || !same_snapshot(root_snapshot(self.parent.0)?, self.parent_snapshot)
            || native_namespace_directory::opaque_directory_identity(self.parent.0)?
                != *self.parent_identity.as_bytes()
            || !windows_paths_equal(&root.path, &self.root_path)
            || !absent(&self.source_path)?
            || !windows_paths_equal(
                &final_path_for_handle(self.protected.raw)
                    .map_err(|_| Error::ConfiguredRootChanged)?,
                &self.destination_path,
            )
        {
            return Err(Error::ConfiguredRootChanged);
        }
        for ((handle, expected_snapshot), identity) in
            self._parent_ancestors.iter().zip(&self.parent_route)
        {
            if native_namespace_directory::opaque_directory_identity(handle.0)? != *identity
                || !same_snapshot(root_snapshot(handle.0)?, *expected_snapshot)
            {
                return Err(Error::ConfiguredRootChanged);
            }
        }
        let parent_final =
            final_path_for_handle(self.parent.0).map_err(|_| Error::ConfiguredRootChanged)?;
        let destination_parent = self
            .destination_path
            .parent()
            .ok_or(Error::ConfiguredRootChanged)?;
        if !windows_paths_equal(&parent_final, destination_parent) {
            return Err(Error::ConfiguredRootChanged);
        }
        let snapshot = root_snapshot(self.protected.raw)?;
        if !same_root_entry(snapshot, self.root, self.file, self.size)
            || !same_snapshot(snapshot, self.destination_snapshot)
            || !same_snapshot(root_snapshot(self._destination.0)?, snapshot)
        {
            return Err(Error::ConfiguredRootChanged);
        }
        verify_completion_identity(self.protected.raw, identity)?;
        let basic = completion_basic_info(self.protected.raw)?;
        if basic.creation_time != self.destination_basic.creation_time
            || basic.last_access_time != self.destination_basic.last_access_time
            || basic.last_write_time != self.destination_basic.last_write_time
            || basic.file_attributes != self.destination_basic.file_attributes
            || if identity == self.source_identity.as_bytes() {
                basic.change_time != self.destination_basic.change_time
            } else {
                basic.change_time < self.destination_basic.change_time
            }
            || !file_links(self.protected.raw, snapshot.identity)?
            || modified_ranges_for_handle(self.protected.raw)
                .map_err(|_| Error::EditRecoveryUnavailable)?
        {
            return Err(Error::ConfiguredRootChanged);
        }
        let usn = completion_usn(self.protected.raw, self.file.file_index)?;
        if if identity == self.source_identity.as_bytes() {
            usn != self.destination_usn
        } else {
            usn < self.destination_usn
        } {
            return Err(Error::ConfiguredRootChanged);
        }
        root.verify_identity(true)?;
        root.verify_registered()?;
        Ok((snapshot, basic, usn))
    }
}

pub(crate) struct NativeFileRenameLocal<'pin, 'connection, 'session, 'backend> {
    pins: &'pin mut PinnedFileRename<'connection>,
    session: &'session crate::FileRenameSession<'backend>,
    source_proof: Option<VerifiedRenameSourceContent<'session, 'backend>>,
}

impl FileRenameLocal for NativeFileRenameLocal<'_, '_, '_, '_> {
    fn admit(&mut self, intent: &NamespaceIntent) -> Result<(), CloudError> {
        if !self.pins.matches(intent)
            || self.pins.identity_update_attempted
            || !std::ptr::eq(self.pins.backend.as_ref(), self.session.backend())
            || self.session.intent().operation != intent.operation
            || self.session.intent().record_generation != intent.record_generation
        {
            return Err(conflict());
        }
        self.session.remote().ensure_authorized(intent)?;
        self.pins
            .verify_native(self.pins.source_identity.as_bytes())
            .map_err(|_| conflict())?;
        let remaining = self
            .session
            .deadline()
            .checked_duration_since(Instant::now())
            .ok_or_else(conflict)?;
        let cancellation = crate::CancellationToken::with_timeout(remaining);
        let digest = native_digest(
            &self
                .pins
                .protected
                .digest_complete(self.pins.size, Some(&cancellation))
                .map_err(|_| conflict())?,
        )
        .map_err(|_| conflict())?;
        if digest != self.pins.digest {
            return Err(conflict());
        }
        let (after_hash, after_hash_basic, after_hash_usn) = self
            .pins
            .verify_native(self.pins.source_identity.as_bytes())
            .map_err(|_| conflict())?;
        if !same_snapshot(after_hash, self.pins.destination_snapshot)
            || after_hash_basic != self.pins.destination_basic
            || after_hash_usn != self.pins.destination_usn
        {
            return Err(conflict());
        }
        if self.source_proof.is_none() {
            let proof = self.session.verify_source_content(digest)?;
            let (after, after_basic, after_usn) = self
                .pins
                .verify_native(self.pins.source_identity.as_bytes())
                .map_err(|_| conflict())?;
            if !same_snapshot(after, self.pins.destination_snapshot)
                || after_basic != self.pins.destination_basic
                || after_usn != self.pins.destination_usn
            {
                return Err(conflict());
            }
            self.source_proof = Some(proof);
        }
        self.session.remote().ensure_authorized(intent)
    }

    fn record_completion<F>(
        &mut self,
        intent: &NamespaceIntent,
        readback: &FileRenameReadback,
        record: F,
    ) -> Result<(), FileRenameCompletionError>
    where
        F: FnOnce() -> Result<(), crate::streamed_store::StoreError>,
    {
        if !self.pins.matches(intent) || self.source_proof.is_none() {
            return Err(FileRenameCompletionError::Unavailable);
        }
        self.admit(intent)
            .map_err(|_| FileRenameCompletionError::Unavailable)?;
        let proof = self
            .source_proof
            .as_ref()
            .ok_or(FileRenameCompletionError::Unavailable)?;
        let publication = self
            .session
            .prepare_content_verified_file_rename(readback, proof)
            .map_err(|_| FileRenameCompletionError::Unavailable)?;
        if proof.byte_len() != self.pins.size
            || publication.digest() != &self.pins.digest
            || publication.byte_len() != self.pins.size
            || publication.source_identity() != self.pins.source_identity
        {
            return Err(FileRenameCompletionError::Unavailable);
        }
        let new_identity = *publication.identity().as_bytes();
        let cancellation = crate::CancellationToken::with_timeout(
            self.session
                .deadline()
                .checked_duration_since(Instant::now())
                .ok_or(FileRenameCompletionError::Unavailable)?,
        );
        let called = Cell::new(false);
        publication
            .publish_file_rename_completion(|| {
                let (before, before_basic, before_usn) = self
                    .pins
                    .verify_native(self.pins.source_identity.as_bytes())
                    .map_err(|_| FileRenameCompletionError::Unavailable)?;
                let body = self
                    .pins
                    .protected
                    .digest_complete(self.pins.size, Some(&cancellation))
                    .map_err(|_| FileRenameCompletionError::Unavailable)?;
                if native_digest(&body).map_err(|_| FileRenameCompletionError::Unavailable)?
                    != self.pins.digest
                    || before_usn <= 0
                {
                    return Err(FileRenameCompletionError::Unavailable);
                }
                let (before_after_hash, before_after_basic, before_after_usn) = self
                    .pins
                    .verify_native(self.pins.source_identity.as_bytes())
                    .map_err(|_| FileRenameCompletionError::Unavailable)?;
                if !same_snapshot(before_after_hash, before)
                    || before_after_basic != before_basic
                    || before_after_usn != before_usn
                {
                    return Err(FileRenameCompletionError::Unavailable);
                }
                self.pins.identity_update_attempted = true;
                called.set(true);
                // SAFETY: exclusive referenced protected handle and exact destination identity remain pinned. Optional metadata, ranges, USN and flags are null/zero.
                let hr = unsafe {
                    CfUpdatePlaceholder(
                        self.pins.protected.protected,
                        null(),
                        new_identity.as_ptr().cast(),
                        new_identity.len() as u32,
                        null(),
                        0,
                        0,
                        null_mut(),
                        null_mut(),
                    )
                };
                if hr < 0 {
                    return Err(FileRenameCompletionError::Uncertain);
                }
                let (after, after_basic, after_usn) = self
                    .pins
                    .verify_native(&new_identity)
                    .map_err(|_| FileRenameCompletionError::Uncertain)?;
                let after_body = self
                    .pins
                    .protected
                    .digest_complete(self.pins.size, Some(&cancellation))
                    .map_err(|_| FileRenameCompletionError::Uncertain)?;
                let (after_hash, after_hash_basic, after_hash_usn) = self
                    .pins
                    .verify_native(&new_identity)
                    .map_err(|_| FileRenameCompletionError::Uncertain)?;
                if after.identity != before.identity
                    || after.file_size != before.file_size
                    || after.file_attributes != before.file_attributes
                    || after.reparse_tag != before.reparse_tag
                    || after.placeholder_state != before.placeholder_state
                    || after.last_write_time != before.last_write_time
                    || after_basic.creation_time != before_basic.creation_time
                    || after_basic.last_access_time != before_basic.last_access_time
                    || after_basic.last_write_time != before_basic.last_write_time
                    || after_basic.file_attributes != before_basic.file_attributes
                    || after_basic.change_time < before_basic.change_time
                    || after_basic.change_time <= 0
                    || after_usn < before_usn
                    || after_usn <= 0
                    || !same_snapshot(after_hash, after)
                    || after_hash_basic != after_basic
                    || after_hash_usn != after_usn
                    || native_digest(&after_body)
                        .map_err(|_| FileRenameCompletionError::Uncertain)?
                        != self.pins.digest
                {
                    return Err(FileRenameCompletionError::Uncertain);
                }
                record().map_err(FileRenameCompletionError::Store)?;
                let (final_snapshot, final_basic, final_usn) = self
                    .pins
                    .verify_native(&new_identity)
                    .map_err(|_| FileRenameCompletionError::Uncertain)?;
                let final_body = self
                    .pins
                    .protected
                    .digest_complete(self.pins.size, Some(&cancellation))
                    .map_err(|_| FileRenameCompletionError::Uncertain)?;
                let (final_after_hash, final_after_basic, final_after_usn) = self
                    .pins
                    .verify_native(&new_identity)
                    .map_err(|_| FileRenameCompletionError::Uncertain)?;
                if !same_snapshot(final_snapshot, after)
                    || final_basic.creation_time != after_basic.creation_time
                    || final_basic.last_access_time != after_basic.last_access_time
                    || final_basic.last_write_time != after_basic.last_write_time
                    || final_basic.file_attributes != after_basic.file_attributes
                    || final_basic.change_time < after_basic.change_time
                    || final_usn < after_usn
                    || !same_snapshot(final_after_hash, final_snapshot)
                    || final_after_basic != final_basic
                    || final_after_usn != final_usn
                    || native_digest(&final_body)
                        .map_err(|_| FileRenameCompletionError::Uncertain)?
                        != self.pins.digest
                {
                    return Err(FileRenameCompletionError::Uncertain);
                }
                Ok(())
            })
            .map_err(|error| {
                if called.get() && error == FileRenameCompletionError::Unavailable {
                    FileRenameCompletionError::Uncertain
                } else {
                    error
                }
            })
    }
}

#[path = "native_empty_directory_rename.rs"]
mod empty_directory;

#[path = "native_directory_rename.rs"]
mod directory_rename;
