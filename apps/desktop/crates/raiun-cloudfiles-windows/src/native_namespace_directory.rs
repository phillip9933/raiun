//! Exact native directory admission and no-dehydration publication. Local
//! components are hints until joined to current authenticated opaque routing.
use super::*;
use crate::namespace_intent::{
    CapturedAuthorization, LocalNamespaceEntry, NamespaceIntent, NamespaceObjectKind,
    NamespaceOperation, NamespaceParent, StorageClassification,
};
use crate::namespace_reconcile::{
    DirectoryCompletionError, DirectoryCreateLocal, DirectoryCreateReadback,
};
use crate::{DirectoryCreateSession, VerifiedDirectoryPublication};
use raiun_core::backend::{CloudError, ErrorKind};

#[link(name = "CldApi")]
unsafe extern "system" {
    fn CfConvertToPlaceholder(
        file: Handle,
        identity: *const c_void,
        identity_length: u32,
        flags: u32,
        usn: *mut i64,
        overlapped: *mut c_void,
    ) -> HResult;
}
const ENABLE_ON_DEMAND_POPULATION: u32 = 4;
const FILE_WRITE_DATA_ACCESS: u32 = 2;

#[cfg(all(debug_assertions, feature = "synthetic-agent-integration"))]
fn fixture_diagnostic(stage: &'static str, error: Option<&Error>) {
    static EMITTED: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let mut count = EMITTED.load(Ordering::Relaxed);
    loop {
        if count >= 32 {
            return;
        }
        match EMITTED.compare_exchange_weak(count, count + 1, Ordering::Relaxed, Ordering::Relaxed)
        {
            Ok(_) => break,
            Err(current) => count = current,
        }
    }
    match error {
        Some(Error::Native { hresult, .. }) => eprintln!(
            "namespace_fixture stage={stage} category=Native hresult=0x{:08x}",
            *hresult as u32
        ),
        Some(Error::Io { kind, .. }) => {
            eprintln!("namespace_fixture stage={stage} category=Io kind={kind:?}");
        }
        Some(error) => eprintln!("namespace_fixture stage={stage} category={error:?}"),
        None => eprintln!("namespace_fixture stage={stage}"),
    }
}

pub(crate) struct PinnedNamespaceDirectory<'connection> {
    connection: &'connection ConfiguredRootConnection,
    backend: Arc<crate::OpenCloudPlaceholderBackend>,
    parent: RawOwnedHandle,
    parent_snapshot: RootSnapshot,
    ancestors: Vec<(RawOwnedHandle, RootSnapshot)>,
    child: RawOwnedHandle,
    snapshot: RootSnapshot,
    components: Vec<String>,
    entry: LocalNamespaceEntry,
    parent_identity: crate::OpaqueIdentity,
    generation: u64,
    attempted: bool,
    converted_identity: Option<[u8; 16]>,
}
pub(super) fn opaque_directory_identity(handle: Handle) -> Result<[u8; 16], Error> {
    // Same CF_PLACEHOLDER_BASIC_INFO layout as the existing population helper.
    // DWORD-aligned storage bounds both header and exactly16 opaque bytes.
    let mut storage = [0u64; 6];
    let mut returned = 0;
    let hr = unsafe {
        CfGetPlaceholderInfo(
            handle,
            CF_PLACEHOLDER_INFO_BASIC,
            storage.as_mut_ptr().cast(),
            size_of_val(&storage) as u32,
            &mut returned,
        )
    };
    if hr < 0 {
        return Err(native_error("inspect namespace parent identity", hr));
    }
    if returned < 44 || returned as usize > size_of_val(&storage) {
        return Err(Error::ConfiguredRootChanged);
    }
    let bytes =
        unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), returned as usize) };
    if u32::from_ne_bytes(
        bytes[24..28]
            .try_into()
            .map_err(|_| Error::ConfiguredRootChanged)?,
    ) != 16
    {
        return Err(Error::ConfiguredRootChanged);
    }
    bytes[28..44]
        .try_into()
        .map_err(|_| Error::ConfiguredRootChanged)
}
pub(super) fn pin_namespace_parent(
    root: &OwnedConfiguredRoot,
    route: &[crate::PlaceholderChild],
    identity: crate::OpaqueIdentity,
    components: &[&str],
    access: u32,
) -> Result<PinnedPopulationDirectory, Error> {
    let expected = route.last().ok_or(Error::ConfiguredRootChanged)?;
    let (parent, snapshot, ancestors) =
        pin_configured_directory_path(root, expected, components, access)?;
    if ancestors.len() + 1 != route.len() || !cleanup_cloud_reparse_tag(snapshot.reparse_tag) {
        return Err(Error::ConfiguredRootChanged);
    }
    for ((handle, state), expected) in ancestors.iter().zip(route) {
        if !cleanup_cloud_reparse_tag(state.reparse_tag)
            || opaque_directory_identity(handle.0)?.as_slice() != expected.identity
        {
            return Err(Error::ConfiguredRootChanged);
        }
    }
    if opaque_directory_identity(parent.0)? != *identity.as_bytes() {
        return Err(Error::ConfiguredRootChanged);
    }
    Ok((parent, snapshot, ancestors))
}
impl ConfiguredRootConnection {
    pub(crate) fn prepare_namespace_directory<'a>(
        &'a self,
        backend: &Arc<crate::OpenCloudPlaceholderBackend>,
        parent_components: &[&str],
        name: &str,
        authorization: CapturedAuthorization,
        generation: u64,
    ) -> Result<PinnedNamespaceDirectory<'a>, Error> {
        if generation == 0
            || !valid_component(name)
            || parent_components.is_empty()
            || parent_components.len() > 255
            || parent_components.iter().any(|part| !valid_component(part))
        {
            return Err(Error::InvalidConfiguredRoot);
        }
        let erased: Arc<dyn PlaceholderBackend> = backend.clone();
        if !Arc::ptr_eq(&erased, &self.state.backend)
            || !self.connected
            || self.state.readiness.load(Ordering::Acquire) != CALLBACK_READY
        {
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
        if recovery.provider_scope() != backend.scope() || recovery.root_identity() != root_identity
        {
            return Err(Error::ProviderUnavailable);
        }
        let captured = backend
            .capture_namespace_parent(parent_components, root_identity, authorization)
            .map_err(|_| Error::ProviderUnavailable)?;
        let (parent, parent_snapshot, ancestors) = pin_namespace_parent(
            root,
            &captured.route,
            captured.identity,
            parent_components,
            FILE_READ_ATTRIBUTES,
        )?;
        let mut path = root.path.clone();
        for part in parent_components {
            path.push(part);
        }
        path.push(name);
        let wide = wide_path(&path)?;
        // SAFETY: exact connected root and every actual managed parent are
        // retained without delete sharing. OPEN_REPARSE_POINT rejects leaf
        // traversal; WRITE_DATA is required by synchronous conversion. No DELETE.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_READ_ATTRIBUTES | FILE_WRITE_DATA_ACCESS,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            return Err(win32_io_error("pin new namespace directory"));
        }
        let child = RawOwnedHandle(raw);
        let snapshot = root_snapshot(child.0)?;
        if snapshot.file_attributes & FILE_ATTRIBUTE_DIRECTORY == 0
            || snapshot.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || snapshot.placeholder_state != 0
            || snapshot.identity.volume_serial != root.identity.volume_serial
            || snapshot.identity.file_index == 0
            || snapshot.identity == parent_snapshot.identity
            || snapshot.identity == root.identity
        {
            return Err(Error::ConfiguredRootChanged);
        }
        let final_path =
            final_path_for_handle(child.0).map_err(|_| Error::ConfiguredRootChanged)?;
        if final_path.file_name().and_then(|name| name.to_str()) != Some(name) {
            return Err(Error::ConfiguredRootChanged);
        }
        let entry = LocalNamespaceEntry {
            parent: NamespaceParent {
                scope: captured.scope,
                authorization,
                classification: StorageClassification::Ordinary,
                local_file: LocalFileIdentity {
                    volume_serial: parent_snapshot.identity.volume_serial,
                    file_index: parent_snapshot.identity.file_index,
                },
                local_components: parent_components.iter().map(|s| (*s).to_owned()).collect(),
                remote: captured.remote,
            },
            name: name.into(),
            local_file: LocalFileIdentity {
                volume_serial: snapshot.identity.volume_serial,
                file_index: snapshot.identity.file_index,
            },
            object_kind: NamespaceObjectKind::Directory,
        };
        let prepared = PinnedNamespaceDirectory {
            connection: self,
            backend: backend.clone(),
            parent,
            parent_snapshot,
            ancestors,
            child,
            snapshot,
            components: parent_components
                .iter()
                .copied()
                .chain(std::iter::once(name))
                .map(str::to_owned)
                .collect(),
            entry,
            parent_identity: captured.identity,
            generation,
            attempted: false,
            converted_identity: None,
        };
        prepared.verify(false)?;
        Ok(prepared)
    }
}
impl<'connection> PinnedNamespaceDirectory<'connection> {
    pub(crate) fn observation(&self) -> Result<crate::NamespaceDirectoryObservation, Error> {
        let root = self
            .connection
            .root
            .as_ref()
            .ok_or(Error::ConfiguredRootChanged)?;
        root.verify_identity(true)?;
        root.verify_registered()?;
        let result = observed(self.child.0)?;
        if result.local_file != self.entry.local_file {
            return Err(Error::ConfiguredRootChanged);
        }
        root.verify_identity(true)?;
        Ok(result)
    }
    pub(crate) fn entry(&self) -> &LocalNamespaceEntry {
        &self.entry
    }
    pub(crate) fn parent_identity(&self) -> crate::OpaqueIdentity {
        self.parent_identity
    }
    pub(crate) fn intent(&self) -> NamespaceIntent {
        NamespaceIntent {
            schema_version: 1,
            record_id: "0".repeat(32),
            record_generation: self.generation,
            operation: NamespaceOperation::CreateDirectory {
                destination: self.entry.clone(),
            },
        }
    }
    pub(crate) fn validate_presend(&self, intent: &NamespaceIntent) -> Result<(), Error> {
        if self.attempted || intent.validate().is_err() || !self.matches(intent) {
            return Err(Error::EditRecoveryUnavailable);
        }
        self.verify(false)
    }
    fn matches(&self, intent: &NamespaceIntent) -> bool {
        intent.record_generation == self.generation
            && matches!(&intent.operation,NamespaceOperation::CreateDirectory{destination}if destination==&self.entry)
    }
    fn verify(&self, converted: bool) -> Result<(), Error> {
        if !self.connection.connected
            || self.connection.state.readiness.load(Ordering::Acquire) != CALLBACK_READY
            || self.backend.is_revoked()
        {
            return Err(Error::ProviderUnavailable);
        }
        let root = self
            .connection
            .root
            .as_ref()
            .ok_or(Error::ConfiguredRootChanged)?;
        root.verify_identity(true)?;
        root.verify_registered()?;
        let parent = root_snapshot(self.parent.0)?;
        if parent.identity != self.parent_snapshot.identity
            || !valid_callback_directory_snapshot(parent)
            || opaque_directory_identity(self.parent.0)? != *self.parent_identity.as_bytes()
        {
            return Err(Error::ConfiguredRootChanged);
        }
        let refs = self
            .components
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        verify_population_path(root, self.child.0, &self.ancestors, &refs)?;
        let current = root_snapshot(self.child.0)?;
        if current.identity != self.snapshot.identity
            || current.file_attributes & FILE_ATTRIBUTE_DIRECTORY == 0
            || (converted
                && (current.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
                    || !cleanup_cloud_reparse_tag(current.reparse_tag)
                    || current.placeholder_state & CF_PLACEHOLDER_STATE_PLACEHOLDER == 0
                    || current.placeholder_state & 8 != 0))
            || (!converted
                && (current.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
                    || current.placeholder_state != 0))
        {
            return Err(Error::ConfiguredRootChanged);
        }
        Ok(())
    }
    fn convert(&mut self, publication: &VerifiedDirectoryPublication<'_, '_>) -> Result<(), Error> {
        if self.attempted
            || !self.matches(publication.intent())
            || !std::ptr::eq(self.backend.as_ref(), publication.backend())
        {
            return Err(Error::EditRecoveryUnavailable);
        }
        publication.publish_and_complete(|| {
            self.verify(false).inspect_err(|_error| {
                #[cfg(all(debug_assertions, feature = "synthetic-agent-integration"))]
                fixture_diagnostic("convert_pre_verify", Some(_error));
            })?;
            self.attempted = true;
            let mut usn = 0;
            // SAFETY: SAME pinned plain directory, WRITE_DATA+attributes, no
            // delete sharing. Identity16 remains borrowed through this documented
            // synchronous call (null OVERLAPPED); flags4 only, no dehydration,
            // FORCE or MARK_IN_SYNC. All pins/connection/session stay alive.
            let hr = unsafe {
                CfConvertToPlaceholder(
                    self.child.0,
                    publication.identity().as_ptr().cast(),
                    16,
                    ENABLE_ON_DEMAND_POPULATION,
                    &mut usn,
                    null_mut(),
                )
            };
            if hr < 0 {
                return Err(native_error("convert verified namespace directory", hr));
            }
            self.verify(true).inspect_err(|_error| {
                #[cfg(all(debug_assertions, feature = "synthetic-agent-integration"))]
                fixture_diagnostic("convert_post_verify", Some(_error));
            })?;
            if opaque_directory_identity(self.child.0)? != *publication.identity() {
                return Err(Error::ConfiguredRootChanged);
            }
            self.converted_identity = Some(*publication.identity());
            Ok(())
        })
    }
    pub(crate) fn local<'a, 'session, 'backend>(
        &'a mut self,
        session: &'session DirectoryCreateSession<'backend>,
    ) -> NativeDirectoryLocal<'a, 'connection, 'session, 'backend> {
        NativeDirectoryLocal {
            prepared: self,
            session,
        }
    }
}
pub(crate) struct NativeDirectoryLocal<'pin, 'connection, 'session, 'backend> {
    prepared: &'pin mut PinnedNamespaceDirectory<'connection>,
    session: &'session DirectoryCreateSession<'backend>,
}
impl DirectoryCreateLocal for NativeDirectoryLocal<'_, '_, '_, '_> {
    fn admit(&mut self, intent: &NamespaceIntent) -> Result<(), CloudError> {
        if !self.prepared.matches(intent) || self.prepared.attempted {
            #[cfg(all(debug_assertions, feature = "synthetic-agent-integration"))]
            fixture_diagnostic("admit_matches", None);
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "native directory changed",
            ));
        }
        self.session
            .remote()
            .ensure_authorized(intent)
            .inspect_err(|_error| {
                #[cfg(all(debug_assertions, feature = "synthetic-agent-integration"))]
                fixture_diagnostic("admit_authorization", None);
            })?;
        self.prepared.verify(false).map_err(|_error| {
            #[cfg(all(debug_assertions, feature = "synthetic-agent-integration"))]
            fixture_diagnostic("admit_verify", Some(&_error));
            CloudError::new(ErrorKind::Conflict, "native directory changed")
        })
    }
    fn publish(
        &mut self,
        intent: &NamespaceIntent,
        readback: &DirectoryCreateReadback,
    ) -> Result<(), CloudError> {
        self.admit(intent)?;
        let publication = self
            .session
            .prepare_verified_directory(readback)
            .map_err(|_error| {
                #[cfg(all(debug_assertions, feature = "synthetic-agent-integration"))]
                fixture_diagnostic("prepare_verified_directory", None);
                CloudError::new(ErrorKind::Conflict, "directory publication unavailable")
            })?;
        self.prepared.convert(&publication).map_err(|_error| {
            #[cfg(all(debug_assertions, feature = "synthetic-agent-integration"))]
            fixture_diagnostic("publish_convert", Some(&_error));
            CloudError::new(ErrorKind::Conflict, "native directory publication pending")
        })
    }
    fn record_completion<F>(
        &mut self,
        intent: &NamespaceIntent,
        readback: &DirectoryCreateReadback,
        record: F,
    ) -> Result<(), DirectoryCompletionError>
    where
        F: FnOnce() -> Result<(), crate::streamed_store::StoreError>,
    {
        if !self.prepared.matches(intent)
            || !std::ptr::eq(self.prepared.backend.as_ref(), self.session.backend())
        {
            #[cfg(all(debug_assertions, feature = "synthetic-agent-integration"))]
            fixture_diagnostic("completion_binding", None);
            return Err(DirectoryCompletionError::Unavailable);
        }
        let identity = self.prepared.converted_identity.ok_or_else(|| {
            #[cfg(all(debug_assertions, feature = "synthetic-agent-integration"))]
            fixture_diagnostic("completion_identity", None);
            DirectoryCompletionError::Unavailable
        })?;
        self.session
            .record_directory_completion(readback, &identity, || {
                self.prepared
                    .verify(true)
                    .map_err(|_| DirectoryCompletionError::Unavailable)?;
                if opaque_directory_identity(self.prepared.child.0)
                    .map_err(|_| DirectoryCompletionError::Unavailable)?
                    != identity
                {
                    return Err(DirectoryCompletionError::Unavailable);
                }
                record().map_err(DirectoryCompletionError::Store)?;
                self.prepared
                    .verify(true)
                    .map_err(|_| DirectoryCompletionError::Uncertain)?;
                if opaque_directory_identity(self.prepared.child.0)
                    .map_err(|_| DirectoryCompletionError::Uncertain)?
                    != identity
                {
                    return Err(DirectoryCompletionError::Uncertain);
                }
                Ok(())
            })
            .inspect_err(|_error| {
                #[cfg(all(debug_assertions, feature = "synthetic-agent-integration"))]
                fixture_diagnostic("record_directory_completion", None);
            })
    }
}

fn observed(handle: Handle) -> Result<crate::NamespaceDirectoryObservation, Error> {
    let snapshot = root_snapshot(handle)?;
    let identity = if snapshot.placeholder_state & CF_PLACEHOLDER_STATE_PLACEHOLDER != 0 {
        Some(opaque_directory_identity(handle)?)
    } else {
        None
    };
    Ok(crate::NamespaceDirectoryObservation {
        local_file: LocalFileIdentity {
            volume_serial: snapshot.identity.volume_serial,
            file_index: snapshot.identity.file_index,
        },
        attributes: snapshot.file_attributes,
        reparse_tag: snapshot.reparse_tag,
        placeholder_state: snapshot.placeholder_state,
        opaque_identity: identity,
    })
}
impl ConfiguredRootConnection {
    #[cfg(all(debug_assertions, feature = "synthetic-agent-integration"))]
    pub(crate) fn namespace_directory_fixture_observation(
        &self,
        components: &[&str],
    ) -> Result<crate::NamespaceDirectoryObservation, Error> {
        if components.is_empty()
            || components.len() > 256
            || components.iter().any(|s| !valid_component(s))
        {
            return Err(Error::ConfiguredRootChanged);
        }
        let root = self.root.as_ref().ok_or(Error::ConfiguredRootChanged)?;
        root.verify_identity(true)?;
        root.verify_registered()?;
        let mut path = root.path.clone();
        let mut pins = Vec::with_capacity(components.len());
        for component in components {
            path.push(component);
            let handle = open_root(
                &path,
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
            )?;
            let snapshot = root_snapshot(handle.0)?;
            if snapshot.file_attributes & FILE_ATTRIBUTE_DIRECTORY == 0
                || (snapshot.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
                    && !cleanup_cloud_reparse_tag(snapshot.reparse_tag))
            {
                return Err(Error::ConfiguredRootChanged);
            }
            pins.push(handle);
        }
        let value = observed(pins.last().ok_or(Error::ConfiguredRootChanged)?.0)?;
        root.verify_identity(true)?;
        root.verify_registered()?;
        Ok(value)
    }
}
