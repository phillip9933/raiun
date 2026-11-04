//! Local-only, synchronous capture. No upload/conversion/in-sync capability.
use super::*;
use crate::PlainFileCaptureParent;
use crate::namespace_intent::{
    LocalNamespaceEntry, NamespaceFileContent, NamespaceIntent, NamespaceObjectKind,
    NamespaceOperation, NamespaceParent, StorageClassification,
};
use crate::streamed_snapshot::SnapshotBinding;
use crate::streamed_store::namespace_file_store::{
    CapturedCreatePath, FileCreateStore, PublishedFileJoin,
};
use std::fs::File;
#[path = "native_plain_file_capture_checks.rs"]
mod checks;
use checks::CaptureReader;

pub(crate) struct NativePlainFileCapture<'connection, 'parent, 'lease> {
    connection: &'connection ConfiguredRootConnection,
    context: &'parent PlainFileCaptureParent<'lease>,
    backend: Arc<crate::OpenCloudPlaceholderBackend>,
    parent: RawOwnedHandle,
    parent_snapshot: RootSnapshot,
    _ancestors: Vec<(RawOwnedHandle, RootSnapshot)>,
    file: File,
    snapshot: RootSnapshot,
    usn: i64,
    entry: LocalNamespaceEntry,
    local_components: Vec<String>,
    relative_path: String,
    generation: u64,
}
fn plain_snapshot(file: &File) -> Result<(RootSnapshot, i64), Error> {
    let handle = file.as_raw_handle();
    let snapshot = root_snapshot(handle)?;
    let mut info: ByHandleFileInformation = unsafe { zeroed() };
    // SAFETY: live owned synchronous disk handle and exact writable Win32 layout.
    if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
        return Err(win32_io_error("inspect plain capture links"));
    }
    let identity = RootIdentity {
        volume_serial: info.volume_serial_number,
        file_index: (u64::from(info.file_index_high) << 32) | u64::from(info.file_index_low),
    };
    if snapshot.identity != identity
        || identity.file_index == 0
        || info.number_of_links != 1
        || snapshot.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0
        || snapshot.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || snapshot.reparse_tag != 0
        || snapshot.placeholder_state != 0
    {
        return Err(Error::ConfiguredRootChanged);
    }
    const READ_USN: u32 = 0x0009_00eb;
    let mut storage = [0u64; 8192];
    let mut returned = 0;
    // SAFETY: file was opened WITHOUT OVERLAPPED. This synchronous query uses
    // a bounded aligned buffer, real byte counter and NULL OVERLAPPED; no
    // pointer survives this call. No USN write/enable or asynchronous fallback.
    if unsafe {
        DeviceIoControl(
            handle,
            READ_USN,
            null(),
            0,
            storage.as_mut_ptr().cast(),
            65536,
            &mut returned,
            null_mut(),
        )
    } == 0
    {
        return Err(win32_io_error("read plain capture USN"));
    }
    if !(60..=65536).contains(&returned) {
        return Err(Error::EditRecoveryUnavailable);
    }
    // SAFETY: synchronous I/O has returned; the initialized storage is 65536
    // bytes and the validated byte count stays within that live allocation.
    let bytes =
        unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), returned as usize) };
    let usn =
        decode_file_usn_record(bytes, identity.file_index).ok_or(Error::EditRecoveryUnavailable)?;
    Ok((snapshot, usn))
}
impl ConfiguredRootConnection {
    pub(crate) fn prepare_plain_file_capture<'connection, 'parent, 'lease>(
        &'connection self,
        backend: &Arc<crate::OpenCloudPlaceholderBackend>,
        context: &'parent PlainFileCaptureParent<'lease>,
        name: &str,
        generation: u64,
    ) -> Result<NativePlainFileCapture<'connection, 'parent, 'lease>, Error> {
        context
            .check_current()
            .map_err(|_| Error::ProviderUnavailable)?;
        if generation == 0
            || !valid_component(name)
            || !std::ptr::eq(backend.as_ref(), context.backend())
            || context.components().is_empty()
            || context.components().len() > 255
        {
            return Err(Error::EditRecoveryUnavailable);
        }
        let erased: Arc<dyn PlaceholderBackend> = backend.clone();
        if !self.connected
            || self.state.readiness.load(Ordering::Acquire) != CALLBACK_READY
            || !Arc::ptr_eq(&erased, &self.state.backend)
        {
            return Err(Error::ProviderUnavailable);
        }
        let root = self.root.as_ref().ok_or(Error::ConfiguredRootChanged)?;
        root.verify_identity(true)?;
        root.verify_registered()?;
        let captured = context.captured();
        let scope = &captured.scope;
        let physical = crate::ConfiguredRootIdentity {
            volume_serial: root.identity.volume_serial,
            file_index: root.identity.file_index,
        };
        let recovery = self
            .state
            .recovery
            .as_ref()
            .ok_or(Error::EditRecoveryUnavailable)?;
        if scope.root_volume_serial != physical.volume_serial
            || scope.root_file_index != physical.file_index
            || recovery.root_identity() != physical
            || recovery.provider_scope() != backend.scope()
        {
            return Err(Error::ProviderUnavailable);
        }
        let components = context
            .components()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let (parent, parent_snapshot, ancestors) =
            native_namespace_directory::pin_namespace_parent(
                root,
                &captured.route,
                captured.identity,
                &components,
                FILE_READ_ATTRIBUTES,
            )?;
        let mut path = root.path.clone();
        for part in &components {
            path.push(part);
        }
        path.push(name);
        if path.as_os_str().encode_wide().count() > 32767 {
            return Err(Error::InvalidConfiguredRoot);
        }
        let wide = wide_path(&path)?;
        // SAFETY: actual admitted managed ancestor handles are retained without
        // DELETE sharing. Open leaf itself, synchronously, and SHARE_READ ONLY:
        // a current writer/delete holder refuses this capture before reservation.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            return Err(win32_io_error("open closed plain capture source"));
        }
        // SAFETY: exclusively owned new synchronous read handle, transferred
        // exactly once into File. No borrowed protected/Cf handle is adopted.
        let file = unsafe { File::from_raw_handle(raw) };
        let (snapshot, usn) = plain_snapshot(&file)?;
        if snapshot.identity.volume_serial != root.identity.volume_serial
            || snapshot.identity == root.identity
            || snapshot.identity == parent_snapshot.identity
        {
            return Err(Error::ConfiguredRootChanged);
        }
        let final_path = final_path_for_handle(file.as_raw_handle())
            .map_err(|_| Error::ConfiguredRootChanged)?;
        let parent_final =
            final_path_for_handle(parent.0).map_err(|_| Error::ConfiguredRootChanged)?;
        if final_path.file_name().and_then(|n| n.to_str()) != Some(name)
            || final_path
                .parent()
                .is_none_or(|p| !windows_paths_equal(p, &parent_final))
        {
            return Err(Error::ConfiguredRootChanged);
        }
        let relative_parent = captured
            .path
            .strip_prefix('/')
            .ok_or(Error::ConfiguredRootChanged)?
            .trim_end_matches('/');
        let relative_path = if relative_parent.is_empty() {
            name.to_owned()
        } else {
            format!("{relative_parent}/{name}")
        };
        let local_components = context
            .components()
            .iter()
            .cloned()
            .chain(std::iter::once(name.to_owned()))
            .collect::<Vec<_>>();
        CapturedCreatePath::new(local_components.clone(), relative_path.clone())
            .map_err(|_| Error::EditRecoveryUnavailable)?;
        let entry = LocalNamespaceEntry {
            parent: NamespaceParent {
                scope: scope.clone(),
                authorization: context.authorization(),
                classification: StorageClassification::Ordinary,
                local_file: LocalFileIdentity {
                    volume_serial: parent_snapshot.identity.volume_serial,
                    file_index: parent_snapshot.identity.file_index,
                },
                local_components: context.components().to_vec(),
                remote: captured.remote.clone(),
            },
            name: name.into(),
            local_file: LocalFileIdentity {
                volume_serial: snapshot.identity.volume_serial,
                file_index: snapshot.identity.file_index,
            },
            object_kind: NamespaceObjectKind::File,
        };
        let capture = NativePlainFileCapture {
            connection: self,
            context,
            backend: backend.clone(),
            parent,
            parent_snapshot,
            _ancestors: ancestors,
            file,
            snapshot,
            usn,
            entry,
            local_components,
            relative_path,
            generation,
        };
        capture.verify()?;
        Ok(capture)
    }
}
impl NativePlainFileCapture<'_, '_, '_> {
    fn current(&self) -> Result<(), Error> {
        self.context
            .check_current()
            .map_err(|_| Error::ProviderUnavailable)?;
        if !self.connection.connected
            || self.connection.state.readiness.load(Ordering::Acquire) != CALLBACK_READY
            || !std::ptr::eq(self.backend.as_ref(), self.context.backend())
        {
            return Err(Error::ProviderUnavailable);
        }
        Ok(())
    }
    fn verify(&self) -> Result<(), Error> {
        self.current()?;
        let root = self
            .connection
            .root
            .as_ref()
            .ok_or(Error::ConfiguredRootChanged)?;
        root.verify_identity(true)?;
        root.verify_registered()?;
        let captured = self.context.captured();
        let parts = self
            .context
            .components()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let (fresh, parent, _pins) = native_namespace_directory::pin_namespace_parent(
            root,
            &captured.route,
            captured.identity,
            &parts,
            FILE_READ_ATTRIBUTES,
        )?;
        if parent.identity != self.parent_snapshot.identity
            || root_snapshot(self.parent.0)?.identity != parent.identity
            || native_namespace_directory::opaque_directory_identity(fresh.0)?
                != native_namespace_directory::opaque_directory_identity(self.parent.0)?
        {
            return Err(Error::ConfiguredRootChanged);
        }
        let (snapshot, usn) = plain_snapshot(&self.file)?;
        if !same_edit_snapshot(snapshot, self.snapshot) || usn != self.usn {
            return Err(Error::EditRecoveryUnavailable);
        }
        let final_path = final_path_for_handle(self.file.as_raw_handle())
            .map_err(|_| Error::ConfiguredRootChanged)?;
        let parent_final =
            final_path_for_handle(self.parent.0).map_err(|_| Error::ConfiguredRootChanged)?;
        if final_path.file_name().and_then(|s| s.to_str()) != Some(self.entry.name.as_str())
            || final_path
                .parent()
                .is_none_or(|p| !windows_paths_equal(p, &parent_final))
        {
            return Err(Error::ConfiguredRootChanged);
        }
        self.current()
    }
    pub(crate) fn capture_and_join(
        mut self,
        store: &Arc<FileCreateStore>,
    ) -> Result<PublishedFileJoin, Error> {
        self.verify()?;
        if store.scope() != &self.entry.parent.scope {
            return Err(Error::EditRecoveryUnavailable);
        }
        let reservation = store
            .snapshot_store()
            .try_begin_capture(SnapshotBinding {
                record_id: String::new(),
                scope: self.entry.parent.scope.clone(),
                generation: self.generation,
                local_file: self.entry.local_file,
                relative_path: self.relative_path.clone(),
                remote: None,
                content_len: self.snapshot.file_size,
            })
            .map_err(|_| Error::EditRecoveryUnavailable)?;
        let context = self.context;
        let readiness = &self.connection.state.readiness;
        let mut cancelled = || {
            context.check_current().is_err() || readiness.load(Ordering::Acquire) != CALLBACK_READY
        };
        let (stage, digest) = {
            let mut reader =
                CaptureReader::new(&mut self.file, self.snapshot.file_size, &mut cancelled);
            let stage = reservation
                .capture(&mut reader, &mut || context.check_current().is_err())
                .map_err(|_| Error::EditRecoveryUnavailable)?;
            let digest = reader.finish().ok_or(Error::EditRecoveryUnavailable)?;
            (stage, digest)
        };
        self.verify()?;
        let committed = stage
            .verify_and_commit(&mut cancelled)
            .map_err(|_| Error::EditRecoveryUnavailable)?;
        if committed.manifest().binding().remote.is_some()
            || committed.manifest().binding().content_len != self.snapshot.file_size
            || committed.manifest().content_sha256() != &digest
        {
            return Err(Error::EditRecoveryUnavailable);
        }
        self.verify()?;
        let draft = NamespaceIntent {
            schema_version: 1,
            record_id: "0".repeat(32),
            record_generation: self.generation,
            operation: NamespaceOperation::CreateFile {
                destination: self.entry.clone(),
                content: NamespaceFileContent {
                    byte_len: self.snapshot.file_size,
                    sha256: digest.iter().map(|b| format!("{b:02x}")).collect(),
                },
            },
        };
        let mapping =
            CapturedCreatePath::new(self.local_components.clone(), self.relative_path.clone())
                .map_err(|_| Error::EditRecoveryUnavailable)?;
        let joined = store
            .publish_fresh(draft, committed, mapping, &mut cancelled)
            .map_err(|_| Error::EditRecoveryUnavailable)?;
        // The join may already be durable: failure preserves facts, returns no
        // successful fresh capture, and never authorizes network/native actions.
        self.verify()?;
        Ok(joined)
    }
}
#[cfg(test)]
#[path = "native_plain_file_capture_tests.rs"]
mod tests;
