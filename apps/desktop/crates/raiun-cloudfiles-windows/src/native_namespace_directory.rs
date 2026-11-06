//! Exact native directory admission and no-dehydration publication. Local
//! components are hints until joined to current authenticated opaque routing.
use super::*;
use crate::creation_preparation::{
    Failure, Stage as PreparationStage, Trace, wait_for_recovery_health,
};
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
    pins: DirectoryPins,
}
pub(crate) struct DirectoryPins {
    _owner_thread: std::marker::PhantomData<std::rc::Rc<()>>,
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
impl std::ops::Deref for PinnedNamespaceDirectory<'_> {
    type Target = DirectoryPins;
    fn deref(&self) -> &DirectoryPins {
        &self.pins
    }
}
impl std::ops::DerefMut for PinnedNamespaceDirectory<'_> {
    fn deref_mut(&mut self) -> &mut DirectoryPins {
        &mut self.pins
    }
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
        self.pin_admitted_directory(
            backend,
            parent_components,
            name,
            authorization,
            generation,
            &captured,
        )
    }
    fn pin_admitted_directory<'a>(
        &'a self,
        backend: &Arc<crate::OpenCloudPlaceholderBackend>,
        parent_components: &[&str],
        name: &str,
        authorization: CapturedAuthorization,
        generation: u64,
        captured: &crate::opencloud::CapturedDirectoryParent,
    ) -> Result<PinnedNamespaceDirectory<'a>, Error> {
        let root = self.root.as_ref().ok_or(Error::ConfiguredRootChanged)?;
        root.verify_identity(true)?;
        root.verify_registered()?;
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
                scope: captured.scope.clone(),
                authorization,
                classification: StorageClassification::Ordinary,
                local_file: LocalFileIdentity {
                    volume_serial: parent_snapshot.identity.volume_serial,
                    file_index: parent_snapshot.identity.file_index,
                },
                local_components: parent_components.iter().map(|s| (*s).to_owned()).collect(),
                remote: captured.remote.clone(),
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
            pins: DirectoryPins {
                _owner_thread: std::marker::PhantomData,
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
            },
        };
        prepared.verify(false)?;
        Ok(prepared)
    }
}
impl DirectoryPins {
    // Only called under an original typed directory publication fence.
    fn convert_under_publication(
        &mut self,
        connection: &ConfiguredRootConnection,
        identity: &[u8; 16],
    ) -> Result<(), Error> {
        if self.attempted {
            return Err(Error::EditRecoveryUnavailable);
        }
        self.verify(connection, false).inspect_err(|_error| {
            #[cfg(all(debug_assertions, feature = "synthetic-agent-integration"))]
            fixture_diagnostic("convert_pre_verify", Some(_error));
        })?;
        self.attempted = true;
        let mut usn = 0;
        // SAFETY: SAME pinned plain directory, WRITE_DATA+attributes, no
        // delete sharing. Identity16 remains live; synchronous flags4 only,
        // no dehydration, FORCE or MARK_IN_SYNC. Pins and connection stay live.
        let hr = unsafe {
            CfConvertToPlaceholder(
                self.child.0,
                identity.as_ptr().cast(),
                16,
                ENABLE_ON_DEMAND_POPULATION,
                &mut usn,
                null_mut(),
            )
        };
        if hr < 0 {
            return Err(native_error("convert verified namespace directory", hr));
        }
        self.verify(connection, true).inspect_err(|_error| {
            #[cfg(all(debug_assertions, feature = "synthetic-agent-integration"))]
            fixture_diagnostic("convert_post_verify", Some(_error));
        })?;
        if opaque_directory_identity(self.child.0)? != *identity {
            return Err(Error::ConfiguredRootChanged);
        }
        self.converted_identity = Some(*identity);
        Ok(())
    }
    fn verify(&self, connection: &ConfiguredRootConnection, converted: bool) -> Result<(), Error> {
        if !connection.connected
            || connection.state.readiness.load(Ordering::Acquire) != CALLBACK_READY
            || self.backend.is_revoked()
        {
            return Err(Error::ProviderUnavailable);
        }
        let root = connection
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
        self.pins.verify(self.connection, converted)
    }
    fn convert(&mut self, publication: &VerifiedDirectoryPublication<'_, '_>) -> Result<(), Error> {
        if self.attempted
            || !self.matches(publication.intent())
            || !std::ptr::eq(self.backend.as_ref(), publication.backend())
        {
            return Err(Error::EditRecoveryUnavailable);
        }
        let connection = self.connection;
        publication.publish_and_complete(|| {
            self.pins
                .convert_under_publication(connection, publication.identity())
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
        let Some(identity) = self.prepared.converted_identity else {
            #[cfg(all(debug_assertions, feature = "synthetic-agent-integration"))]
            fixture_diagnostic("completion_identity", None);
            return Err(DirectoryCompletionError::Unavailable);
        };
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

use crate::close_capture_admission::{CloseCaptureAdmission, OwnedDirectoryAdmission};
use crate::directory_create_phase::{Phase, ReplyDisposition, ReplyKey, TaskFlight};
use crate::namespace_intent::{NamespaceEventKind, NamespaceProgressSnapshot};
use crate::namespace_reconcile::DirectoryCreateOutcome;
use crate::opencloud::{OwnedDirectorySend, OwnedDirectorySession, RefreshedDirectory};
use crate::streamed_store::namespace_store::{DirectoryIntentLease, DirectoryIntentStore};
type DirectoryCurrent = Arc<dyn Fn(CapturedAuthorization) -> bool + Send + Sync>;
#[derive(Default)]
pub(super) struct DirectoryOwner {
    closed: bool,
    nonce: u64,
    attempt: Option<DirectoryAttempt>,
}
struct DirectoryAttempt {
    key: Arc<ReplyKey>,
    phase: Phase,
    done: Arc<std::sync::atomic::AtomicBool>,
    backend: Arc<crate::OpenCloudPlaceholderBackend>,
    recovery: Arc<dyn crate::PreparedEditRecovery>,
    tracker: Arc<CloseCaptureAdmission>,
    admission: OwnedDirectoryAdmission,
    components: Vec<String>,
    name: String,
    job: crate::StreamedRecoveryJob,
    current: DirectoryCurrent,
    ready: Arc<std::sync::atomic::AtomicBool>,
    pins: Option<DirectoryPins>,
    lease: Option<DirectoryIntentLease>,
    submitted: bool,
    verified: bool,
    trace: Arc<Trace>,
}
/// Move-only SDK task; no native handle, owner ticket or record lease.
pub struct DirectoryCreateTask {
    key: Arc<ReplyKey>,
    kind: Option<Box<DirectoryTaskKind>>,
    _flight: TaskFlight,
    trace: Arc<Trace>,
}
/// Original invocation reply. No public constructor or serializable proof.
pub struct DirectoryCreateReply {
    key: Arc<ReplyKey>,
    phase: Phase,
    kind: DirectoryReplyKind,
}
impl DirectoryCreateReply {
    /// A fixed diagnostic boundary, not authorization to retry a retained intent.
    pub fn failure_context(&self) -> &'static str {
        match &self.kind {
            DirectoryReplyKind::Prepared(Err(failure)) => failure.message("Folder"),
            DirectoryReplyKind::Prepared(Ok(_)) => {
                "Folder creation paused: native directory admission or protected intent publication failed. Recovery files have been kept."
            }
            DirectoryReplyKind::Preflight(_, _) => {
                "Folder creation paused: conditional cloud preflight or dispatch admission failed. Recovery files have been kept."
            }
            DirectoryReplyKind::Sent(_, _) => {
                "Folder creation paused: cloud result verification or protected result persistence failed. Recovery files have been kept."
            }
            DirectoryReplyKind::Refreshed(_, _) => {
                "Folder creation paused: verified directory publication or native completion failed. Recovery files have been kept."
            }
        }
    }
}
pub enum DirectoryCreateStep {
    Task(DirectoryCreateTask),
    /// No new ticket, native capture or durable intent was created.
    BusyBeforeCapture,
    Finished(DirectoryCreateOutcome),
}
enum DirectoryTaskKind {
    Prepare {
        backend: Arc<crate::OpenCloudPlaceholderBackend>,
        components: Vec<String>,
        name: String,
        job: crate::StreamedRecoveryJob,
        current: DirectoryCurrent,
        recovery: Arc<dyn crate::PreparedEditRecovery>,
    },
    Preflight(OwnedDirectorySession, NamespaceIntent),
    Send(
        OwnedDirectorySession,
        NamespaceIntent,
        NamespaceProgressSnapshot,
    ),
    Refresh(
        Box<(
            OwnedDirectorySession,
            NamespaceIntent,
            crate::namespace_intent::NamespaceDestinationReport,
        )>,
    ),
}
enum DirectoryReplyKind {
    Prepared(Result<(OwnedDirectorySession, Arc<DirectoryIntentStore>), Failure>),
    Preflight(
        OwnedDirectorySession,
        Result<(), raiun_core::backend::CloudError>,
    ),
    Sent(OwnedDirectorySession, OwnedDirectorySend),
    Refreshed(
        OwnedDirectorySession,
        Result<RefreshedDirectory, BackendError>,
    ),
}
impl DirectoryCreateTask {
    /// Fixed progress observation only. The caller must independently observe
    /// its ORIGINAL job expiry; this grants no dispatch or completion authority.
    pub fn deadline_context(&self) -> Arc<dyn Fn() -> &'static str + Send + Sync> {
        let trace = Arc::clone(&self.trace);
        Arc::new(move || trace.deadline_message("Folder"))
    }
    /// Run on a joined SDK worker. The original deadline/epoch is never renewed.
    pub fn execute(mut self) -> DirectoryCreateReply {
        let trace = Arc::clone(&self.trace);
        let (phase, kind) = match *self
            .kind
            .take()
            .expect("private directory task consumed once")
        {
            DirectoryTaskKind::Prepare {
                backend,
                components,
                name,
                job,
                current,
                recovery,
            } => {
                let result = (|| {
                    let mut health_wait = None;
                    trace.enter(PreparationStage::Job);
                    job.check()?;
                    let refs: Vec<_> = components.iter().map(String::as_str).collect();
                    let session = OwnedDirectorySession::prepare_traced(
                        backend,
                        &refs,
                        self.key.root,
                        self.key.authorization,
                        job.clone(),
                        current.clone(),
                        &trace,
                    )?;
                    trace.enter(PreparationStage::Current);
                    session.check()?;
                    let space = session
                        .fresh_create_space_for_child(&components, &name)?
                        .with_preparation_trace(Arc::clone(&trace));
                    if wait_for_recovery_health(&job, &trace, &mut health_wait, || {
                        trace.enter(PreparationStage::Job);
                        job.check()?;
                        trace.enter(PreparationStage::Current);
                        if !current(self.key.authorization) {
                            return Err(BackendError::Unavailable);
                        }
                        session.check()?;
                        trace.enter(PreparationStage::RecoveryBefore);
                        recovery.has_unresolved_for_fresh_create_in_space(&space)
                    })? {
                        return Err(BackendError::Unavailable);
                    }
                    trace.enter(PreparationStage::Current);
                    session.check()?;
                    trace.enter(PreparationStage::RecoveryStore);
                    let store = recovery
                        .directory_intent_store(&session.captured.scope, self.key.authorization)?
                        .ok_or(BackendError::Unavailable)?;
                    trace.enter(PreparationStage::Current);
                    session.check()?;
                    if wait_for_recovery_health(&job, &trace, &mut health_wait, || {
                        trace.enter(PreparationStage::Job);
                        job.check()?;
                        trace.enter(PreparationStage::Current);
                        if !current(self.key.authorization) {
                            return Err(BackendError::Unavailable);
                        }
                        session.check()?;
                        trace.enter(PreparationStage::RecoveryAfter);
                        recovery.has_unresolved_for_fresh_create_in_space(&space)
                    })? {
                        return Err(BackendError::Unavailable);
                    }
                    trace.enter(PreparationStage::Current);
                    session.check()?;
                    Ok((session, store))
                })()
                .map_err(|error| {
                    trace.backend(error);
                    trace.failure()
                });
                (Phase::Prepare, DirectoryReplyKind::Prepared(result))
            }
            DirectoryTaskKind::Preflight(session, intent) => {
                trace.enter(PreparationStage::DirectoryPreflight);
                let result = session.preflight(&intent);
                (
                    Phase::Preflight,
                    DirectoryReplyKind::Preflight(session, result),
                )
            }
            DirectoryTaskKind::Send(session, intent, progress) => {
                trace.enter(PreparationStage::DirectorySend);
                let result = match crate::namespace_reconcile::submitted_directory_dispatch(
                    &intent, progress,
                ) {
                    Ok(dispatch) => session.send(&dispatch),
                    Err(_) => OwnedDirectorySend::Uncertain,
                };
                (Phase::Send, DirectoryReplyKind::Sent(session, result))
            }
            DirectoryTaskKind::Refresh(pair) => {
                trace.enter(PreparationStage::DirectoryRefresh);
                let (session, intent, report) = *pair;
                let result = session.refresh(&intent, &report);
                (
                    Phase::Refresh,
                    DirectoryReplyKind::Refreshed(session, result),
                )
            }
        };
        DirectoryCreateReply {
            key: self.key.clone(),
            phase,
            kind,
        }
    }
}
impl DirectoryAttempt {
    fn task(&mut self, phase: Phase, kind: DirectoryTaskKind) -> DirectoryCreateStep {
        let (done, flight) = TaskFlight::new();
        self.done = done;
        self.phase = phase;
        self.trace.enter(match phase {
            Phase::Prepare => PreparationStage::QueuedPrepare,
            Phase::Preflight => PreparationStage::QueuedPreflight,
            Phase::Send => PreparationStage::QueuedSend,
            Phase::Refresh => PreparationStage::QueuedRefresh,
        });
        DirectoryCreateStep::Task(DirectoryCreateTask {
            key: self.key.clone(),
            kind: Some(Box::new(kind)),
            _flight: flight,
            trace: Arc::clone(&self.trace),
        })
    }
    fn incomplete(&self) -> DirectoryCreateOutcome {
        if self.verified {
            DirectoryCreateOutcome::RemoteVerifiedLocalPending
        } else if self.submitted {
            DirectoryCreateOutcome::Uncertain
        } else {
            DirectoryCreateOutcome::Deferred
        }
    }
}
impl ConfiguredRootConnection {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn begin_fresh_personal_directory_create(
        &self,
        backend: &Arc<crate::OpenCloudPlaceholderBackend>,
        components: &[&str],
        name: &str,
        authorization: CapturedAuthorization,
        generation: u64,
        original_job: &crate::StreamedRecoveryJob,
        original_current: DirectoryCurrent,
    ) -> Result<DirectoryCreateStep, Error> {
        if generation == 0
            || crate::personal_create_relative(components, name).is_none()
            || components.len() > 255
            || components.iter().any(|part| !valid_component(part))
            || !valid_component(name)
            || components.iter().map(|part| part.len() + 1).sum::<usize>() + name.len() > 32768
            || !original_current(authorization)
            || original_job.is_stopped()
        {
            return Err(Error::InvalidConfiguredRoot);
        }
        let mut slot = self
            .directory_owner
            .try_borrow_mut()
            .map_err(|_| Error::ConnectionStateInvalid)?;
        if slot.closed {
            return Err(Error::ProviderUnavailable);
        }
        if slot.attempt.is_some() {
            return Ok(DirectoryCreateStep::BusyBeforeCapture);
        }
        let (tracker, recovery) = self.file_create_guard_context(backend)?;
        let Some(admission) = tracker.try_begin_directory() else {
            if tracker.known_busy_for_create() {
                return Ok(DirectoryCreateStep::BusyBeforeCapture);
            }
            return Ok(DirectoryCreateStep::Finished(
                DirectoryCreateOutcome::Deferred,
            ));
        };
        let observation = admission.observation_probe();
        let dispatch = admission.dispatch_probe();
        let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let started = ready.clone();
        let current: DirectoryCurrent = Arc::new(move |auth| {
            original_current(auth)
                && observation()
                && (!started.load(Ordering::Acquire) || dispatch())
        });
        let check = current.clone();
        let original = Arc::downgrade(backend);
        let job = original_job.with_revocation_check(Arc::new(move || {
            !check(authorization)
                || original.upgrade().is_none_or(|b| {
                    b.is_revoked() || b.scope().token_generation() != authorization.token_generation
                })
        }));
        let root = self.root.as_ref().ok_or(Error::ConfiguredRootChanged)?;
        slot.nonce = slot
            .nonce
            .checked_add(1)
            .ok_or(Error::ConnectionStateInvalid)?;
        let key = Arc::new(ReplyKey {
            nonce: slot.nonce,
            context: self.context_key,
            root: crate::ConfiguredRootIdentity {
                volume_serial: root.identity.volume_serial,
                file_index: root.identity.file_index,
            },
            generation,
            authorization,
        });
        let mut attempt = DirectoryAttempt {
            key,
            phase: Phase::Prepare,
            done: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            backend: backend.clone(),
            recovery: recovery.clone(),
            tracker,
            admission,
            components: components.iter().map(|part| (*part).to_owned()).collect(),
            name: name.into(),
            job: job.clone(),
            current: current.clone(),
            ready,
            pins: None,
            lease: None,
            submitted: false,
            verified: false,
            trace: Arc::new(Trace::new()),
        };
        self.check_directory_attempt(&attempt)?;
        // Store the dispatch-ready bit only in owner/SDK currentness; the ticket
        // probe is armed by the actual successful one-use owner claim.
        let kind = DirectoryTaskKind::Prepare {
            backend: backend.clone(),
            components: attempt.components.clone(),
            name: attempt.name.clone(),
            job,
            current,
            recovery,
        };
        let step = attempt.task(Phase::Prepare, kind);
        // ready stays false until dispatch; observation still invalidates every close.
        slot.attempt = Some(attempt);
        Ok(step)
    }
    fn check_directory_attempt(&self, attempt: &DirectoryAttempt) -> Result<(), Error> {
        if attempt.job.is_stopped()
            || !(attempt.current)(attempt.key.authorization)
            || !attempt.admission.is_current()
            || attempt.key.context != self.context_key
            || !self.connected
            || self.namespace_observation_closed
        {
            return Err(Error::ProviderUnavailable);
        }
        let root = self.root.as_ref().ok_or(Error::ConfiguredRootChanged)?;
        if root.identity.volume_serial != attempt.key.root.volume_serial
            || root.identity.file_index != attempt.key.root.file_index
        {
            return Err(Error::ConfiguredRootChanged);
        }
        root.verify_identity(true)?;
        root.verify_registered()?;
        let (tracker, recovery) = self.file_create_guard_context(&attempt.backend)?;
        if !Arc::ptr_eq(&tracker, &attempt.tracker) || !Arc::ptr_eq(&recovery, &attempt.recovery) {
            return Err(Error::ProviderUnavailable);
        }
        Ok(())
    }
    pub(crate) fn close_fresh_personal_directory_create(&self) -> bool {
        let Ok(mut slot) = self.directory_owner.try_borrow_mut() else {
            return false;
        };
        slot.closed = true;
        if let Some(attempt) = &slot.attempt {
            attempt.job.cancel();
            if !attempt.done.load(Ordering::Acquire) {
                return false;
            }
        }
        slot.attempt.take();
        true
    }
}
impl ConfiguredRootConnection {
    pub(crate) fn advance_fresh_personal_directory_create(
        &self,
        reply: DirectoryCreateReply,
    ) -> Result<DirectoryCreateStep, Error> {
        let mut slot = self
            .directory_owner
            .try_borrow_mut()
            .map_err(|_| Error::ConnectionStateInvalid)?;
        let original = slot.attempt.as_ref().ok_or(Error::ConnectionStateInvalid)?;
        let disposition = ReplyKey::disposition(
            &original.key,
            &reply.key,
            original.phase,
            reply.phase,
            original.done.load(Ordering::Acquire),
            original.job.is_stopped(),
            slot.closed,
        );
        if disposition == ReplyDisposition::Wrong || original.key.nonce != slot.nonce {
            return Err(Error::ConnectionStateInvalid);
        }
        let mut attempt = slot.attempt.take().ok_or(Error::ConnectionStateInvalid)?;
        attempt.trace.enter(PreparationStage::NativeContext);
        if disposition == ReplyDisposition::Retire
            || self.check_directory_attempt(&attempt).is_err()
        {
            return Ok(DirectoryCreateStep::Finished(attempt.incomplete()));
        }
        let step = match reply.kind {
            DirectoryReplyKind::Prepared(result) => {
                let (session, store) = result.map_err(|_| Error::EditRecoveryUnavailable)?;
                if !session.original_backend(&attempt.backend) {
                    return Err(Error::ProviderUnavailable);
                }
                let refs: Vec<_> = attempt.components.iter().map(String::as_str).collect();
                attempt.trace.enter(PreparationStage::NativeParentPin);
                let prepared = self.pin_admitted_directory(
                    &attempt.backend,
                    &refs,
                    &attempt.name,
                    attempt.key.authorization,
                    attempt.key.generation,
                    &session.captured,
                )?;
                let pins = prepared.pins;
                self.check_directory_attempt(&attempt)?;
                attempt
                    .trace
                    .enter(PreparationStage::DirectoryIntentAdmission);
                let (published, lease) = store
                    .publish_intent_for_dispatch(NamespaceIntent {
                        schema_version: 1,
                        record_id: "0".repeat(32),
                        record_generation: attempt.key.generation,
                        operation: NamespaceOperation::CreateDirectory {
                            destination: pins.entry.clone(),
                        },
                    })
                    .map_err(|_| Error::EditRecoveryUnavailable)?;
                if !published.created || published.record.progress.sequence != 0 {
                    return Ok(DirectoryCreateStep::Finished(
                        DirectoryCreateOutcome::Retained,
                    ));
                }
                let lease = lease.ok_or(Error::EditRecoveryUnavailable)?;
                self.check_directory_attempt(&attempt)?;
                let intent = lease.intent().clone();
                attempt.pins = Some(pins);
                attempt.lease = Some(lease);
                attempt.task(
                    Phase::Preflight,
                    DirectoryTaskKind::Preflight(session, intent),
                )
            }
            DirectoryReplyKind::Preflight(session, result) => {
                attempt
                    .trace
                    .enter(PreparationStage::DirectoryResultPersistence);
                if !session.original_backend(&attempt.backend) {
                    return Err(Error::ProviderUnavailable);
                }
                if let Err(error) = result {
                    let event = if error.kind == raiun_core::backend::ErrorKind::Conflict {
                        NamespaceEventKind::Conflict
                    } else {
                        NamespaceEventKind::Deferred
                    };
                    attempt
                        .lease
                        .as_mut()
                        .ok_or(Error::EditRecoveryUnavailable)?
                        .append_event(event)
                        .map_err(|_| Error::EditRecoveryUnavailable)?;
                    return Ok(DirectoryCreateStep::Finished(
                        if error.kind == raiun_core::backend::ErrorKind::Conflict {
                            DirectoryCreateOutcome::Conflict
                        } else {
                            DirectoryCreateOutcome::Deferred
                        },
                    ));
                }
                session.check().map_err(|_| Error::ProviderUnavailable)?;
                attempt
                    .pins
                    .as_ref()
                    .ok_or(Error::EditRecoveryUnavailable)?
                    .verify(self, false)?;
                if !attempt.admission.claim_dispatch() {
                    return Err(Error::EditRecoveryUnavailable);
                }
                let lease = attempt
                    .lease
                    .as_mut()
                    .ok_or(Error::EditRecoveryUnavailable)?;
                crate::namespace_reconcile::submit_directory_create(lease)
                    .map_err(|_| Error::EditRecoveryUnavailable)?;
                attempt.submitted = true;
                attempt.ready.store(true, Ordering::Release);
                let intent = lease.intent().clone();
                let progress = lease.progress();
                attempt.task(
                    Phase::Send,
                    DirectoryTaskKind::Send(session, intent, progress),
                )
            }
            DirectoryReplyKind::Sent(session, result) => {
                attempt
                    .trace
                    .enter(PreparationStage::DirectoryResultPersistence);
                if !session.original_backend(&attempt.backend) {
                    return Err(Error::ProviderUnavailable);
                }
                let lease = attempt
                    .lease
                    .as_mut()
                    .ok_or(Error::EditRecoveryUnavailable)?;
                match result {
                    OwnedDirectorySend::Rejected(error) => {
                        let event = if error.kind == raiun_core::backend::ErrorKind::Conflict {
                            NamespaceEventKind::Conflict
                        } else {
                            NamespaceEventKind::Deferred
                        };
                        lease
                            .append_event(event)
                            .map_err(|_| Error::EditRecoveryUnavailable)?;
                        return Ok(DirectoryCreateStep::Finished(
                            if error.kind == raiun_core::backend::ErrorKind::Conflict {
                                DirectoryCreateOutcome::Conflict
                            } else {
                                DirectoryCreateOutcome::Deferred
                            },
                        ));
                    }
                    OwnedDirectorySend::Uncertain => {
                        lease
                            .append_event(NamespaceEventKind::Uncertain)
                            .map_err(|_| Error::EditRecoveryUnavailable)?;
                        return Ok(DirectoryCreateStep::Finished(
                            DirectoryCreateOutcome::Uncertain,
                        ));
                    }
                    OwnedDirectorySend::Verified(report) => {
                        let readback =
                            crate::namespace_reconcile::record_directory_verified(lease, *report)
                                .map_err(|_| Error::EditRecoveryUnavailable)?;
                        attempt.verified = true;
                        let intent = lease.intent().clone();
                        let report = readback.report().clone();
                        attempt.task(
                            Phase::Refresh,
                            DirectoryTaskKind::Refresh(Box::new((session, intent, report))),
                        )
                    }
                }
            }
            DirectoryReplyKind::Refreshed(session, result) => {
                attempt
                    .trace
                    .enter(PreparationStage::NativeDirectoryPublication);
                if !session.original_backend(&attempt.backend) {
                    return Err(Error::ProviderUnavailable);
                }
                let proof = match result {
                    Ok(proof) => proof,
                    Err(_) => {
                        return Ok(DirectoryCreateStep::Finished(
                            DirectoryCreateOutcome::RemoteVerifiedLocalPending,
                        ));
                    }
                };
                let pins = attempt
                    .pins
                    .as_mut()
                    .ok_or(Error::EditRecoveryUnavailable)?;
                // Full context checks above precede backend.state. Only native
                // pins/currentness checks run inside the original local fence.
                let current = attempt.current.clone();
                let auth = attempt.key.authorization;
                session.publish(&proof, |identity| {
                    if !current(auth) {
                        return Err(Error::ProviderUnavailable);
                    }
                    pins.convert_under_publication(self, identity)?;
                    if !current(auth) {
                        return Err(Error::ProviderUnavailable);
                    }
                    Ok(())
                })?;
                // publish has dropped backend.state and provider/token fences.
                // No global quota/journal I/O may occur while those locks live.
                self.check_directory_attempt(&attempt)?;
                if !attempt.admission.claim_completion() {
                    return Ok(DirectoryCreateStep::Finished(
                        DirectoryCreateOutcome::RemoteVerifiedLocalPending,
                    ));
                }
                let pins = attempt
                    .pins
                    .as_ref()
                    .ok_or(Error::EditRecoveryUnavailable)?;
                pins.verify(self, true)?;
                if pins.converted_identity.is_none() {
                    return Err(Error::EditRecoveryUnavailable);
                }
                attempt
                    .trace
                    .enter(PreparationStage::LocalCompletionPersistence);
                attempt
                    .lease
                    .as_mut()
                    .ok_or(Error::EditRecoveryUnavailable)?
                    .append_event(NamespaceEventKind::LocalCompleted {
                        destination: pins.entry.clone(),
                    })
                    .map_err(|_| Error::EditRecoveryUnavailable)?;
                if !current(auth) {
                    return Ok(DirectoryCreateStep::Finished(
                        DirectoryCreateOutcome::RemoteVerifiedLocalPending,
                    ));
                }
                return Ok(DirectoryCreateStep::Finished(
                    DirectoryCreateOutcome::LocalCompleted,
                ));
            }
        };
        slot.attempt = Some(attempt);
        Ok(step)
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn reconcile_fresh_personal_directory_create(
        &self,
        backend: &Arc<crate::OpenCloudPlaceholderBackend>,
        components: &[&str],
        name: &str,
        authorization: CapturedAuthorization,
        generation: u64,
        job: &crate::StreamedRecoveryJob,
        current: DirectoryCurrent,
    ) -> Result<DirectoryCreateOutcome, Error> {
        let mut step = self.begin_fresh_personal_directory_create(
            backend,
            components,
            name,
            authorization,
            generation,
            job,
            current,
        )?;
        loop {
            step = match step {
                DirectoryCreateStep::BusyBeforeCapture => {
                    return Ok(DirectoryCreateOutcome::Deferred);
                }
                DirectoryCreateStep::Finished(outcome) => return Ok(outcome),
                DirectoryCreateStep::Task(task) => {
                    self.advance_fresh_personal_directory_create(task.execute())?
                }
            };
        }
    }
}

const _: fn() = || {
    fn send<T: Send>() {}
    send::<DirectoryCreateTask>();
    send::<DirectoryCreateReply>();
};

/// Read-only worker proof of the original OS registration and actual cloud
/// root state. This creates no connection owner and sets no ownership flags.
pub(super) fn verify_reinspected_namespace_root(
    lease: &RootInspectionLease,
    path: &Path,
) -> Result<(), Error> {
    let identity = RootIdentity {
        volume_serial: lease.identity.volume_serial,
        file_index: lease.identity.file_index,
    };
    let root = lease._pinned.last().ok_or(Error::ConfiguredRootChanged)?;
    if !valid_root_snapshot(
        root_snapshot(root.0)?,
        identity,
        RootSnapshotState::Connected,
    ) || !windows_paths_equal(
        &final_path_for_handle(root.0).map_err(|_| Error::ConfiguredRootChanged)?,
        path,
    ) {
        return Err(Error::ConfiguredRootChanged);
    }
    verify_sync_root_registration(path, identity)
}

/// Actual metadata pins for a joined worker, not an OwnedConfiguredRoot or a
/// fabricated connected flag. The original connection/cap stays with caller.
pub(super) fn pin_reinspected_namespace_parent(
    lease: &RootInspectionLease,
    root_path: &Path,
    route: &[crate::PlaceholderChild],
    identity: crate::OpaqueIdentity,
    components: &[&str],
) -> Result<PinnedPopulationDirectory, Error> {
    verify_reinspected_namespace_root(lease, root_path)?;
    if components.is_empty()
        || components.len() > 256
        || route.len() != components.len()
        || route
            .last()
            .is_none_or(|r| r.identity.as_slice() != identity.as_bytes())
    {
        return Err(Error::ConfiguredRootChanged);
    }
    let mut path = root_path.to_owned();
    let mut pins = Vec::with_capacity(components.len());
    for (part, expected) in components.iter().zip(route) {
        if !valid_component(part) || expected.name != *part || !expected.metadata.is_directory {
            return Err(Error::ConfiguredRootChanged);
        }
        path.push(part);
        let handle = open_root(
            &path,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
        )?;
        let snapshot = root_snapshot(handle.0)?;
        if snapshot.identity.volume_serial != lease.identity.volume_serial
            || snapshot.identity.file_index == 0
            || snapshot.file_attributes & FILE_ATTRIBUTE_DIRECTORY == 0
            || !cleanup_cloud_reparse_tag(snapshot.reparse_tag)
            || !valid_callback_directory_snapshot(snapshot)
            || opaque_directory_identity(handle.0)?.as_slice() != expected.identity
            || !windows_paths_equal(
                &final_path_for_handle(handle.0).map_err(|_| Error::ConfiguredRootChanged)?,
                &path,
            )
        {
            return Err(Error::ConfiguredRootChanged);
        }
        pins.push((handle, snapshot));
    }
    verify_reinspected_namespace_root(lease, root_path)?;
    let (parent, snapshot) = pins.pop().ok_or(Error::ConfiguredRootChanged)?;
    Ok((parent, snapshot, pins))
}
