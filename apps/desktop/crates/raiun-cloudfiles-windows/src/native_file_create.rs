//! Explicit same-owner ordinary Personal file create; never recovered replay.
use super::*;
use crate::close_capture_admission::OwnedCreateAdmission;
use crate::file_create_phase::{Phase, ReplyDisposition, ReplyKey, TaskFlight};
use crate::namespace_intent::{
    CapturedAuthorization, LocalNamespaceEntry, NamespaceFileContent, NamespaceIntent,
    NamespaceObjectKind, NamespaceOperation, NamespaceParent, StorageClassification,
};
use crate::opencloud::file_create::{Admission, RefreshedCreateReadback, VerifiedCreateReadback};
use crate::streamed_snapshot::SnapshotBinding;
use crate::streamed_store::namespace_file_store::{CapturedCreatePath, FileCreateStore};
use crate::streamed_store::namespace_file_store::{
    FileCreateLease, StoredFileJoin, VerifiedFileJoin,
};
use crate::streamed_store::namespace_rename_store::FileRenameStore;
use crate::streamed_store::{SnapshotStore, StreamedRecordKey};
use std::io::{self, Read};

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
/// Live same-owner native custody, never serializable or reconstructible.
pub(crate) struct NativeFileCreateCompletion<'a> {
    _reference: &'a SourceReference<'a>,
    store: Arc<crate::streamed_store::SnapshotStore>,
    join: crate::streamed_store::namespace_file_store::StoredFileJoin,
    key: crate::streamed_store::StreamedRecordKey,
    report: crate::namespace_intent::NamespaceDestinationReport,
}
impl NativeFileCreateCompletion<'_> {
    pub(crate) fn binding_valid(&self) -> bool {
        self.matches(&self.store, &self.join, &self.report)
    }
    pub(crate) fn snapshot(
        &self,
    ) -> (
        &Arc<crate::streamed_store::SnapshotStore>,
        &crate::streamed_store::StreamedRecordKey,
    ) {
        (&self.store, &self.key)
    }
    pub(crate) fn matches(
        &self,
        store: &Arc<crate::streamed_store::SnapshotStore>,
        join: &crate::streamed_store::namespace_file_store::StoredFileJoin,
        report: &crate::namespace_intent::NamespaceDestinationReport,
    ) -> bool {
        Arc::ptr_eq(store, &self.store)
            && join.key() == self.join.key()
            && join.intent() == self.join.intent()
            && join.snapshot_id() == self.key.record_id()
            && join.manifest_commitment_sha256() == self.key.commitment_sha256()
            && report == &self.report
    }
}
struct SourceOwner(Handle);
impl SourceOwner {
    fn open(path: &[u16]) -> Result<Self, Error> {
        let mut handle = null_mut();
        // SAFETY: bounded pinned path and owned output; normal files supported.
        let hr = unsafe { CfOpenFileWithOplock(path.as_ptr(), 1 | 2, &mut handle) };
        if hr < 0 {
            return Err(native_error("open fresh file-create source", hr));
        }
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(Error::EditRecoveryUnavailable);
        }
        Ok(Self(handle))
    }
    fn reference(&self) -> Result<SourceReference<'_>, Error> {
        // SAFETY: live opaque owner; every successful reference has one release.
        if unsafe { CfReferenceProtectedHandle(self.0) } == 0 {
            return Err(Error::EditRecoveryUnavailable);
        }
        let result = SourceReference {
            owner: self,
            raw: unsafe { CfGetWin32HandleFromProtectedHandle(self.0) },
        };
        if result.raw.is_null() || result.raw == INVALID_HANDLE_VALUE {
            return Err(Error::EditRecoveryUnavailable);
        }
        Ok(result)
    }
}
impl Drop for SourceOwner {
    fn drop(&mut self) {
        unsafe { CfCloseHandle(self.0) };
    }
}
pub(super) struct SourceReference<'a> {
    owner: &'a SourceOwner,
    pub(super) raw: Handle,
}
impl Drop for SourceReference<'_> {
    fn drop(&mut self) {
        unsafe { CfReleaseProtectedHandle(self.owner.0) };
    }
}

fn plain(reference: &SourceReference<'_>) -> Result<(RootSnapshot, i64), Error> {
    let snapshot = root_snapshot(reference.raw)?;
    let mut info: ByHandleFileInformation = unsafe { zeroed() };
    // SAFETY: referenced Win32 borrow and initialized exact output layout.
    if unsafe { GetFileInformationByHandle(reference.raw, &mut info) } == 0 {
        return Err(win32_io_error("inspect fresh file-create source"));
    }
    if info.number_of_links != 1
        || snapshot.identity.file_index == 0
        || snapshot.file_attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || snapshot.reparse_tag != 0
        || snapshot.placeholder_state != 0
    {
        return Err(Error::ConfiguredRootChanged);
    }
    Ok((
        snapshot,
        completion_usn(reference.raw, snapshot.identity.file_index)?,
    ))
}
struct Reader<'a, 'owner> {
    source: &'a SourceReference<'owner>,
    offset: u64,
    length: u64,
    eof: bool,
    hash: sha2::Sha256,
    job: &'a crate::StreamedRecoveryJob,
    stopped: &'a dyn Fn() -> bool,
}
impl Read for Reader<'_, '_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        use sha2::Digest;
        if bytes.is_empty() {
            return Ok(0);
        }
        if (self.stopped)() {
            return Err(io::Error::other("file-create capture stopped"));
        }
        let eof = self.offset == self.length;
        let bound = if eof {
            1
        } else {
            bytes
                .len()
                .min(65536)
                .min((self.length - self.offset) as usize)
        };
        let count = native_streamed_io::read_create_at(
            self.source,
            self.offset,
            &mut bytes[..bound],
            eof,
            Some(self.job.cancellation()),
        )
        .map_err(|_| io::Error::other("file-create source unavailable"))?;
        if (self.stopped)() || (eof && count != 0) || (!eof && count == 0) {
            return Err(io::Error::other("file-create source changed"));
        }
        self.eof |= eof;
        self.offset += count as u64;
        self.hash.update(&bytes[..count]);
        Ok(count)
    }
}

#[derive(Default)]
pub(super) struct CreateOwner {
    closed: bool,
    nonce: u64,
    attempt: Option<OwnerAttempt>,
}
struct OwnerAttempt {
    key: Arc<ReplyKey>,
    phase: Phase,
    flight_done: Arc<std::sync::atomic::AtomicBool>,
    backend: Arc<crate::OpenCloudPlaceholderBackend>,
    recovery: Arc<dyn PreparedEditRecovery>,
    tracker: Arc<CloseCaptureAdmission>,
    ticket: OwnedCreateAdmission,
    name: String,
    job: crate::StreamedRecoveryJob,
    current: crate::opencloud::file_create::Current,
    dispatched: Arc<std::sync::atomic::AtomicBool>,
    local: Option<LocalCapture>,
}
enum CaptureResult {
    Busy,
    Incomplete,
    Ready(Box<(LocalCapture, VerifiedFileJoin)>),
}
struct LocalCapture {
    source: SourceOwner,
    _parent: RawOwnedHandle,
    _ancestors: Vec<(RawOwnedHandle, RootSnapshot)>,
    parent_snapshot: RootSnapshot,
    snapshot: RootSnapshot,
    usn: i64,
    expected: PathBuf,
    digest: [u8; 32],
    store: Arc<FileCreateStore>,
    lease: FileCreateLease,
    original_join: StoredFileJoin,
    streamed_key: StreamedRecordKey,
    remote_verified: bool,
}
/// Move-only task. Execute on a joined SDK worker; it carries no native custody.
pub struct FileCreateTask {
    key: Arc<ReplyKey>,
    store: Option<Arc<SnapshotStore>>,
    backend: Arc<crate::OpenCloudPlaceholderBackend>,
    kind: Option<TaskKind>,
    _flight: TaskFlight, // LAST: all owned network/body data drops before done.
}
struct Preparation {
    recovery: Arc<dyn PreparedEditRecovery>,
    job: crate::StreamedRecoveryJob,
    current: crate::opencloud::file_create::Current,
}
enum TaskKind {
    Prepare(Box<Preparation>),
    Send(Box<(Admission, VerifiedFileJoin)>),
    Refresh(Box<(Admission, VerifiedCreateReadback)>),
}
struct Prepared {
    admission: Admission,
    rename: Arc<FileRenameStore>,
}
enum ReplyKind {
    Prepared(Result<Box<Prepared>, BackendError>),
    Sent(Box<(Admission, Result<VerifiedCreateReadback, BackendError>)>),
    Refreshed(Box<(Admission, Result<RefreshedCreateReadback, BackendError>)>),
}
/// Nonserializable original-attempt reply. Public fields/constructors are absent.
pub struct FileCreateReply {
    key: Arc<ReplyKey>,
    store: Option<Arc<SnapshotStore>>,
    kind: ReplyKind,
}
pub enum FileCreateStep {
    Task(FileCreateTask),
    Finished(crate::FreshFileCreateOutcome),
}
impl ReplyKind {
    fn phase(&self) -> Phase {
        match self {
            Self::Prepared(_) => Phase::Prepare,
            Self::Sent(_) => Phase::Send,
            Self::Refreshed(_) => Phase::Refresh,
        }
    }
}
impl FileCreateTask {
    /// No worker is spawned here. Every SDK source worker is joined before return.
    pub fn execute(mut self) -> FileCreateReply {
        let kind = match self.kind.take().expect("private single-use create task") {
            TaskKind::Prepare(prep) => {
                let result = (|| {
                    prep.job.check()?;
                    if !(prep.current)(self.key.authorization)
                        || prep.recovery.has_unresolved()?
                        || prep
                            .recovery
                            .has_unresolved_content_authenticated_legacy()?
                    {
                        return Err(BackendError::Unavailable);
                    }
                    let admission = self.backend.admit_file_create(
                        self.key.root,
                        self.key.authorization,
                        &prep.job,
                        prep.current.clone(),
                    )?;
                    admission.check(&self.backend)?;
                    if prep.recovery.has_unresolved()?
                        || prep
                            .recovery
                            .has_unresolved_content_authenticated_legacy()?
                    {
                        return Err(BackendError::Unavailable);
                    }
                    let rename = prep
                        .recovery
                        .file_rename_store(&admission.parent.scope, self.key.authorization)?
                        .ok_or(BackendError::Unavailable)?;
                    admission.check(&self.backend)?;
                    Ok(Box::new(Prepared { admission, rename }))
                })();
                ReplyKind::Prepared(result)
            }
            TaskKind::Send(pair) => {
                let (mut admission, joined) = *pair;
                let result = admission.send(&self.backend, joined, || Ok(()));
                ReplyKind::Sent(Box::new((admission, result)))
            }
            TaskKind::Refresh(pair) => {
                let (admission, proof) = *pair;
                let result = admission.refresh(&self.backend, proof);
                ReplyKind::Refreshed(Box::new((admission, result)))
            }
        };
        FileCreateReply {
            key: self.key.clone(),
            store: self.store.clone(),
            kind,
        }
    }
}
impl OwnerAttempt {
    fn task(&mut self, phase: Phase, kind: TaskKind) -> FileCreateTask {
        let (done, flight) = TaskFlight::new();
        self.phase = phase;
        self.flight_done = done;
        FileCreateTask {
            key: self.key.clone(),
            store: self
                .local
                .as_ref()
                .map(|local| local.store.snapshot_store().clone()),
            backend: self.backend.clone(),
            kind: Some(kind),
            _flight: flight,
        }
    }
    fn incomplete(&self) -> crate::FreshFileCreateOutcome {
        use crate::FreshFileCreateOutcome::*;
        self.local
            .as_ref()
            .map_or(CapturedLocalIncomplete, |local| {
                if local.remote_verified {
                    RemoteVerifiedLocalIncomplete
                } else {
                    SubmittedUncertain
                }
            })
    }
}

impl ConfiguredRootConnection {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn begin_fresh_personal_file_create(
        &self,
        backend: &Arc<crate::OpenCloudPlaceholderBackend>,
        name: &str,
        authorization: CapturedAuthorization,
        generation: u64,
        job: &crate::StreamedRecoveryJob,
        original_current: crate::opencloud::file_create::Current,
    ) -> Result<FileCreateStep, Error> {
        if !valid_component(name)
            || generation == 0
            || !original_current(authorization)
            || job.is_stopped()
        {
            return Err(Error::InvalidConfiguredRoot);
        }
        let mut slot = self
            .create_owner
            .try_borrow_mut()
            .map_err(|_| Error::ConnectionStateInvalid)?;
        if slot.closed {
            return Err(Error::ProviderUnavailable);
        }
        if slot.attempt.is_some() {
            return Ok(FileCreateStep::Finished(
                crate::FreshFileCreateOutcome::BusyBeforeCapture,
            ));
        }
        let (tracker, recovery) = self.file_rename_guard_context(backend)?;
        let Some(ticket) = tracker.try_begin_create() else {
            return Ok(FileCreateStep::Finished(
                crate::FreshFileCreateOutcome::BusyBeforeCapture,
            ));
        };
        let observation = ticket.observation_probe();
        let dispatch = ticket.dispatch_probe();
        let dispatched = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let started = dispatched.clone();
        let current: crate::opencloud::file_create::Current = Arc::new(move |auth| {
            original_current(auth)
                && observation()
                && (!started.load(Ordering::Acquire) || dispatch())
        });
        let owner = current.clone();
        let original = Arc::downgrade(backend);
        let job = job.with_revocation_check(Arc::new(move || {
            !owner(authorization)
                || original.upgrade().is_none_or(|backend| {
                    backend.recovery_job_revoked()
                        || backend.scope().token_generation() != authorization.token_generation
                })
        }));
        let root = self.root.as_ref().ok_or(Error::ConfiguredRootChanged)?;
        let nonce = slot
            .nonce
            .checked_add(1)
            .ok_or(Error::ConnectionStateInvalid)?;
        slot.nonce = nonce;
        let key = Arc::new(ReplyKey {
            nonce,
            context: self.context_key,
            root: crate::ConfiguredRootIdentity {
                volume_serial: root.identity.volume_serial,
                file_index: root.identity.file_index,
            },
            generation,
            authorization,
        });
        let mut attempt = OwnerAttempt {
            key,
            phase: Phase::Prepare,
            flight_done: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            backend: backend.clone(),
            recovery: recovery.clone(),
            tracker,
            ticket,
            name: name.into(),
            job: job.clone(),
            current: current.clone(),
            dispatched,
            local: None,
        };
        self.check_create_attempt(&attempt)?;
        let task = attempt.task(
            Phase::Prepare,
            TaskKind::Prepare(Box::new(Preparation {
                recovery,
                job,
                current,
            })),
        );
        slot.attempt = Some(attempt);
        Ok(FileCreateStep::Task(task))
    }
    fn check_create_attempt(&self, attempt: &OwnerAttempt) -> Result<(), Error> {
        if !self.connected
            || self.namespace_observation_closed
            || self.context_key != attempt.key.context
            || !attempt.ticket.is_current()
            || attempt.job.is_stopped()
            || !(attempt.current)(attempt.key.authorization)
            || attempt.key.generation == 0
            || attempt.key.nonce == 0
        {
            return Err(Error::ProviderUnavailable);
        }
        let root = self.root.as_ref().ok_or(Error::ConfiguredRootChanged)?;
        if root.identity.volume_serial != attempt.key.root.volume_serial
            || root.identity.file_index != attempt.key.root.file_index
        {
            return Err(Error::ConfiguredRootChanged);
        }
        let (tracker, recovery) = self.file_rename_guard_context(&attempt.backend)?;
        if !Arc::ptr_eq(&tracker, &attempt.tracker) || !Arc::ptr_eq(&recovery, &attempt.recovery) {
            return Err(Error::ProviderUnavailable);
        }
        Ok(())
    }
    pub(crate) fn advance_fresh_personal_file_create(
        &self,
        reply: FileCreateReply,
    ) -> Result<FileCreateStep, Error> {
        let mut slot = self
            .create_owner
            .try_borrow_mut()
            .map_err(|_| Error::ConnectionStateInvalid)?;
        let expected = slot.attempt.as_ref().ok_or(Error::ConnectionStateInvalid)?;
        let disposition = ReplyKey::disposition(
            &expected.key,
            &reply.key,
            expected.phase,
            reply.kind.phase(),
            expected.flight_done.load(Ordering::Acquire),
            expected.job.is_stopped(),
            slot.closed,
        );
        if disposition == ReplyDisposition::Wrong
            || match (&expected.local, &reply.store) {
                (None, None) => false,
                (Some(local), Some(store)) => !Arc::ptr_eq(local.store.snapshot_store(), store),
                _ => true,
            }
        {
            return Err(Error::ConnectionStateInvalid);
        }
        let mut attempt = slot.attempt.take().ok_or(Error::ConnectionStateInvalid)?;
        if disposition == ReplyDisposition::Retire || self.check_create_attempt(&attempt).is_err() {
            attempt.job.cancel();
            if attempt.local.is_none() {
                return Err(Error::ProviderUnavailable);
            }
            return Ok(FileCreateStep::Finished(attempt.incomplete()));
        }
        match reply.kind {
            ReplyKind::Prepared(result) => {
                let prepared = result.map_err(|_| Error::EditRecoveryUnavailable)?;
                let expected = self
                    .file_rename_store(
                        &attempt.backend,
                        &prepared.admission.parent.scope,
                        attempt.key.authorization,
                    )?
                    .ok_or(Error::EditRecoveryUnavailable)?;
                if !prepared
                    .rename
                    .same_admitted_binding(&expected)
                    .map_err(|_| Error::EditRecoveryUnavailable)?
                {
                    return Err(Error::EditRecoveryUnavailable);
                }
                let (mut local, joined) = match self.capture_create_local(
                    &attempt,
                    &prepared.admission,
                    &prepared.rename,
                )? {
                    CaptureResult::Busy => {
                        return Ok(FileCreateStep::Finished(
                            crate::FreshFileCreateOutcome::BusyBeforeCapture,
                        ));
                    }
                    CaptureResult::Incomplete => {
                        return Ok(FileCreateStep::Finished(
                            crate::FreshFileCreateOutcome::CapturedLocalIncomplete,
                        ));
                    }
                    CaptureResult::Ready(captured) => *captured,
                };
                if self.check_create_attempt(&attempt).is_err()
                    || local.lease.mark_submitted().is_err()
                {
                    return Ok(FileCreateStep::Finished(
                        crate::FreshFileCreateOutcome::CapturedLocalIncomplete,
                    ));
                }
                if !attempt.ticket.claim_dispatch() {
                    return Ok(FileCreateStep::Finished(
                        crate::FreshFileCreateOutcome::CapturedLocalIncomplete,
                    ));
                }
                attempt.dispatched.store(true, Ordering::Release);
                attempt.local = Some(local);
                let task = attempt.task(
                    Phase::Send,
                    TaskKind::Send(Box::new((prepared.admission, joined))),
                );
                slot.attempt = Some(attempt);
                Ok(FileCreateStep::Task(task))
            }
            ReplyKind::Sent(pair) => {
                let (admission, proof) = *pair;
                let local = attempt
                    .local
                    .as_mut()
                    .ok_or(Error::ConnectionStateInvalid)?;
                let proof = match proof {
                    Ok(proof) => proof,
                    Err(_) => {
                        let _ = local.lease.record_attention(
                            crate::namespace_intent::NamespaceAttention::Uncertain,
                        );
                        return Ok(FileCreateStep::Finished(
                            crate::FreshFileCreateOutcome::SubmittedUncertain,
                        ));
                    }
                };
                if admission
                    .persist(&attempt.backend, &mut local.lease, &proof)
                    .is_err()
                {
                    return Ok(FileCreateStep::Finished(
                        crate::FreshFileCreateOutcome::SubmittedUncertain,
                    ));
                }
                local.remote_verified = true;
                if self.check_create_attempt(&attempt).is_err() {
                    return Ok(FileCreateStep::Finished(
                        crate::FreshFileCreateOutcome::RemoteVerifiedLocalIncomplete,
                    ));
                }
                let task = attempt.task(
                    Phase::Refresh,
                    TaskKind::Refresh(Box::new((admission, proof))),
                );
                slot.attempt = Some(attempt);
                Ok(FileCreateStep::Task(task))
            }
            ReplyKind::Refreshed(pair) => {
                let (admission, refreshed) = *pair;
                let refreshed = match refreshed {
                    Ok(proof) => proof,
                    Err(_) => {
                        return Ok(FileCreateStep::Finished(
                            crate::FreshFileCreateOutcome::RemoteVerifiedLocalIncomplete,
                        ));
                    }
                };
                let local = attempt.local.take().ok_or(Error::ConnectionStateInvalid)?;
                self.finish_create_local(&mut attempt, local, admission, refreshed)
                    .map(FileCreateStep::Finished)
            }
        }
    }
    /// Close admission/cancel originals. False means task-owned SDK data has not
    /// drained yet; the root must remain connected until caller joins/drains it.
    pub(crate) fn close_fresh_personal_file_create(&self) -> bool {
        let Ok(mut slot) = self.create_owner.try_borrow_mut() else {
            return false;
        };
        slot.closed = true;
        if let Some(attempt) = slot.attempt.as_ref() {
            attempt.job.cancel();
            if !attempt.flight_done.load(Ordering::Acquire) {
                return false;
            }
        }
        slot.attempt.take();
        true
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn reconcile_fresh_personal_file_create(
        &self,
        backend: &Arc<crate::OpenCloudPlaceholderBackend>,
        name: &str,
        authorization: CapturedAuthorization,
        generation: u64,
        job: &crate::StreamedRecoveryJob,
        current: crate::opencloud::file_create::Current,
    ) -> Result<crate::FreshFileCreateOutcome, Error> {
        let mut step = self.begin_fresh_personal_file_create(
            backend,
            name,
            authorization,
            generation,
            job,
            current,
        )?;
        loop {
            step = match step {
                FileCreateStep::Finished(outcome) => return Ok(outcome),
                FileCreateStep::Task(task) => {
                    self.advance_fresh_personal_file_create(task.execute())?
                }
            };
        }
    }
    fn capture_create_local(
        &self,
        attempt: &OwnerAttempt,
        admission: &Admission,
        rename: &Arc<FileRenameStore>,
    ) -> Result<CaptureResult, Error> {
        use sha2::Digest;
        self.check_create_attempt(attempt)?;
        let backend = &attempt.backend;
        let authorization = attempt.key.authorization;
        let generation = attempt.key.generation;
        let name = attempt.name.as_str();
        let current = &attempt.current;
        let capture_job = admission.capture_job();
        let root = self.root.as_ref().ok_or(Error::ConfiguredRootChanged)?;
        let physical = attempt.key.root;
        let captured = &admission.parent;
        let (parent, parent_snapshot, _ancestors) =
            native_namespace_directory::pin_namespace_parent(
                root,
                &captured.route,
                captured.identity,
                &["Personal"],
                FILE_READ_ATTRIBUTES,
            )?;
        let path = root.path.join("Personal").join(name);
        let wide = wide_path(&path)?;
        // SAFETY: bounded no-follow metadata probe, no data or DELETE access.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            return Err(win32_io_error("probe fresh file-create source"));
        }
        let probe = RawOwnedHandle(raw);
        let before = root_snapshot(probe.0)?;
        if before.file_attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
            || before.reparse_tag != 0
            || before.placeholder_state != 0
        {
            return Err(Error::ConfiguredRootChanged);
        }
        let source = match SourceOwner::open(&wide) {
            Ok(value) => value,
            Err(Error::Native { hresult, .. }) if hresult as u32 == 0x80070020 => {
                return Ok(CaptureResult::Busy);
            }
            Err(error) => return Err(error),
        };
        let reference = source.reference()?;
        let (snapshot, usn) = plain(&reference)?;
        if !same_edit_snapshot(before, snapshot)
            || snapshot.identity.volume_serial != physical.volume_serial
            || snapshot.identity == parent_snapshot.identity
        {
            return Err(Error::ConfiguredRootChanged);
        }
        let parent_path =
            final_path_for_handle(parent.0).map_err(|_| Error::ConfiguredRootChanged)?;
        let expected = parent_path.join(name);
        if !windows_paths_equal(
            &final_path_for_handle(reference.raw).map_err(|_| Error::ConfiguredRootChanged)?,
            &expected,
        ) {
            return Err(Error::ConfiguredRootChanged);
        }
        drop(probe); // No leaf share restriction remains during network phases.
        let verify = || -> Result<(), Error> {
            if !attempt.ticket.is_current() {
                return Err(Error::EditRecoveryUnavailable);
            }
            admission
                .check(backend)
                .map_err(|_| Error::ProviderUnavailable)?;
            root.verify_identity(true)?;
            root.verify_registered()?;
            let now = plain(&reference)?;
            let (_, checked_parent, _pins) = native_namespace_directory::pin_namespace_parent(
                root,
                &captured.route,
                captured.identity,
                &["Personal"],
                FILE_READ_ATTRIBUTES,
            )?;
            if !same_edit_snapshot(snapshot, now.0)
                || now.1 != usn
                || checked_parent.identity != parent_snapshot.identity
                || !windows_paths_equal(
                    &final_path_for_handle(reference.raw)
                        .map_err(|_| Error::ConfiguredRootChanged)?,
                    &expected,
                )
            {
                return Err(Error::ConfiguredRootChanged);
            }
            Ok(())
        };
        verify()?;
        let store = FileCreateStore::new(rename.snapshot_store().clone())
            .map_err(|_| Error::EditRecoveryUnavailable)?;
        let local_file = LocalFileIdentity {
            volume_serial: snapshot.identity.volume_serial,
            file_index: snapshot.identity.file_index,
        };
        let entry = LocalNamespaceEntry {
            parent: NamespaceParent {
                scope: captured.scope.clone(),
                authorization,
                classification: StorageClassification::Ordinary,
                local_file: LocalFileIdentity {
                    volume_serial: parent_snapshot.identity.volume_serial,
                    file_index: parent_snapshot.identity.file_index,
                },
                local_components: vec!["Personal".into()],
                remote: captured.remote.clone(),
            },
            name: name.into(),
            local_file,
            object_kind: NamespaceObjectKind::File,
        };
        self.check_create_attempt(attempt)?;
        let reservation = store
            .snapshot_store()
            .try_begin_capture(SnapshotBinding {
                record_id: String::new(),
                scope: captured.scope.clone(),
                generation,
                local_file,
                relative_path: name.into(),
                remote: None,
                content_len: snapshot.file_size,
            })
            .map_err(|_| Error::EditRecoveryUnavailable)?;
        let stopped = || {
            capture_job.is_stopped()
                || !current(authorization)
                || backend.is_revoked()
                || !attempt.ticket.is_current()
        };
        let mut reader = Reader {
            source: &reference,
            offset: 0,
            length: snapshot.file_size,
            eof: false,
            hash: sha2::Sha256::new(),
            job: &capture_job,
            stopped: &stopped,
        };
        let stage = reservation
            .capture(&mut reader, &mut || stopped())
            .map_err(|_| Error::EditRecoveryUnavailable)?;
        if !reader.eof || reader.offset != snapshot.file_size {
            return Err(Error::EditRecoveryUnavailable);
        }
        let digest: [u8; 32] = reader.hash.finalize().into();
        verify()?;
        let committed = stage
            .verify_and_commit(&mut || stopped())
            .map_err(|_| Error::EditRecoveryUnavailable)?;
        if committed.manifest().content_sha256() != &digest {
            return Err(Error::EditRecoveryUnavailable);
        }
        verify()?;
        let joined = store
            .publish_fresh(
                NamespaceIntent {
                    schema_version: 1,
                    record_id: "0".repeat(32),
                    record_generation: generation,
                    operation: NamespaceOperation::CreateFile {
                        destination: entry,
                        content: NamespaceFileContent {
                            byte_len: snapshot.file_size,
                            sha256: digest.iter().map(|b| format!("{b:02x}")).collect(),
                        },
                    },
                },
                committed,
                CapturedCreatePath::new(vec!["Personal".into(), name.into()], name.into())
                    .map_err(|_| Error::EditRecoveryUnavailable)?,
                &mut || stopped(),
            )
            .map_err(|_| Error::EditRecoveryUnavailable)?;
        if verify().is_err() {
            return Ok(CaptureResult::Incomplete);
        }
        drop(reference); // SAME opaque source owner survives, but no network-long ref.

        let lease = match store.acquire_dispatch(joined.record().key()) {
            Ok(lease) => lease,
            Err(_) => return Ok(CaptureResult::Incomplete),
        };
        let original_join = joined.record().clone();
        let streamed_key = store
            .snapshot_store()
            .record_key(original_join.snapshot_id())
            .map_err(|_| Error::EditRecoveryUnavailable)?;
        Ok(CaptureResult::Ready(Box::new((
            LocalCapture {
                source,
                _parent: parent,
                _ancestors,
                parent_snapshot,
                snapshot,
                usn,
                expected,
                digest,
                store,
                lease,
                original_join,
                streamed_key,
                remote_verified: false,
            },
            joined.into_verified(),
        ))))
    }
    fn finish_create_local(
        &self,
        attempt: &mut OwnerAttempt,
        local: LocalCapture,
        admission: Admission,
        proof: RefreshedCreateReadback,
    ) -> Result<crate::FreshFileCreateOutcome, Error> {
        use crate::FreshFileCreateOutcome::*;
        self.check_create_attempt(attempt)?;
        let ticket = &mut attempt.ticket;
        let backend = &attempt.backend;
        let authorization = attempt.key.authorization;
        let current = attempt.current.clone();
        let recovery = attempt.recovery.clone();
        let tracker = attempt.tracker.clone();
        let capture_job = admission.capture_job();
        let root = self.root.as_ref().ok_or(Error::ConfiguredRootChanged)?;
        let LocalCapture {
            source,
            _parent,
            _ancestors,
            parent_snapshot,
            snapshot,
            usn,
            expected,
            digest,
            store,
            mut lease,
            original_join,
            streamed_key,
            ..
        } = local;
        // Own Pending snapshot is covered by initialclean0 + same retained owned
        // ticket/observation. Never rescan it as unrelated pending content.
        let after_publication = || {
            current(authorization)
                && self
                    .file_rename_guard_context(backend)
                    .is_ok_and(|(actual_tracker, actual)| {
                        Arc::ptr_eq(&actual, &recovery) && Arc::ptr_eq(&actual_tracker, &tracker)
                    })
        };
        // Full original context/recovery checks occur outside backend.state.
        if !after_publication() {
            return Ok(RemoteVerifiedLocalIncomplete);
        }
        let inside_publication = || {
            current(authorization)
                && self.connected
                && !self.namespace_observation_closed
                && self.state.readiness.load(Ordering::Acquire) == CALLBACK_READY
                && !backend.is_revoked()
                && self
                    .state
                    .unverifiable_placeholder_closes
                    .load(Ordering::Acquire)
                    == 0
        };
        let complete = |final_reference: &SourceReference<'_>| -> Result<(), Error> {
            if !inside_publication() {
                return Err(Error::EditRecoveryUnavailable);
            }
            admission
                .check(backend)
                .map_err(|_| Error::ProviderUnavailable)?;
            root.verify_identity(true)?;
            root.verify_registered()?;
            let (now, current_usn) = plain(final_reference)?;
            if !same_edit_snapshot(snapshot, now) || current_usn != usn {
                return Err(Error::ConfiguredRootChanged);
            }
            let (_, actual_parent, _pins) = native_namespace_directory::pin_namespace_parent(
                root,
                &admission.parent.route,
                admission.parent.identity,
                &["Personal"],
                FILE_READ_ATTRIBUTES,
            )?;
            if actual_parent.identity != parent_snapshot.identity
                || !windows_paths_equal(
                    &final_path_for_handle(final_reference.raw)
                        .map_err(|_| Error::ConfiguredRootChanged)?,
                    &expected,
                )
            {
                return Err(Error::ConfiguredRootChanged);
            }
            hash_source(final_reference, snapshot.file_size, &capture_job, &digest)?;
            let after = plain(final_reference)?;
            if !same_edit_snapshot(snapshot, after.0) || after.1 != usn {
                return Err(Error::ConfiguredRootChanged);
            }
            Ok(())
        };
        let result = admission.publish_and_complete(backend, &proof, |identity| {
            // Metadata HTTP has finished. Re-reference only this SAME owner;
            // a foreground break refuses completion, never reopen/rebase.
            let final_reference = source.reference()?;
            complete(&final_reference)?;
            let mut converted_usn = 0i64;
            // SAFETY: referenced WRITE_ACCESS Win32 borrow; synchronous NONE
            // conversion retains all bytes, with a live 16-byte identity.
            let hr = unsafe {
                CfConvertToPlaceholder(
                    final_reference.raw,
                    identity.as_ptr().cast(),
                    16,
                    0,
                    &mut converted_usn,
                    null_mut(),
                )
            };
            if hr < 0 {
                return Err(native_error("convert fresh file-create", hr));
            }
            if converted_usn <= 0 {
                return Err(Error::EditRecoveryUnavailable);
            }
            verify_completion_identity(source.0, identity)?;
            hash_source(&final_reference, snapshot.file_size, &capture_job, &digest)?;
            let mut compare_usn =
                completion_usn(final_reference.raw, snapshot.identity.file_index)?;
            if compare_usn <= 0 || compare_usn != converted_usn {
                return Err(Error::ConfiguredRootChanged);
            }
            validate_converted(&final_reference, snapshot, &expected, identity, false)?;
            if !ticket.claim_completion() {
                return Err(Error::EditRecoveryUnavailable);
            }
            // SAFETY: same protected owner and a fresh positive compare USN.
            // Never NULL/zero fallback; a mismatch is retained incomplete.
            let hr = unsafe { CfSetInSyncState(source.0, 1, 0, &mut compare_usn) };
            if hr < 0 {
                return Err(native_error("complete fresh file-create", hr));
            }
            validate_converted(&final_reference, snapshot, &expected, identity, true)?;
            hash_source(&final_reference, snapshot.file_size, &capture_job, &digest)?;
            let after_usn = completion_usn(final_reference.raw, snapshot.identity.file_index)?;
            if compare_usn <= 0 || after_usn != compare_usn {
                return Err(Error::ConfiguredRootChanged);
            }
            root.verify_identity(true)?;
            root.verify_registered()?;
            if !inside_publication() {
                return Err(Error::EditRecoveryUnavailable);
            }
            Ok(final_reference)
        });
        let final_reference = match result {
            Ok(reference) if after_publication() => reference,
            _ => return Ok(RemoteVerifiedLocalIncomplete),
        };
        // Backend state/provider permit are now gone. Keep the SAME source
        // reference while taking record/quota locks for linked custody.
        let completion = NativeFileCreateCompletion {
            _reference: &final_reference,
            store: store.snapshot_store().clone(),
            join: original_join,
            key: streamed_key,
            report: proof
                .report_for(lease.record().intent())
                .map_err(|_| Error::EditRecoveryUnavailable)?,
        };
        let custody = (|| {
            if !after_publication() || admission.check(backend).is_err() {
                return Err(crate::streamed_store::StoreError::Invalid);
            }
            let mut snapshot_lease = store
                .snapshot_store()
                .acquire_dispatch(completion.snapshot().1)?;
            let acknowledged = snapshot_lease.acknowledge_create(&completion)?;
            if !after_publication() || admission.check(backend).is_err() {
                return Err(crate::streamed_store::StoreError::Invalid);
            }
            lease.record_local_completed(&completion, &acknowledged)
        })();
        Ok(if custody.is_ok() {
            LocallyCompleted
        } else {
            RemoteVerifiedLocalIncomplete
        })
    }
}

fn hash_source(
    source: &SourceReference<'_>,
    length: u64,
    job: &crate::StreamedRecoveryJob,
    expected: &[u8; 32],
) -> Result<(), Error> {
    use sha2::Digest;
    let stopped = || job.is_stopped();
    let mut reader = Reader {
        source,
        offset: 0,
        length,
        eof: false,
        hash: sha2::Sha256::new(),
        job,
        stopped: &stopped,
    };
    io::copy(&mut reader, &mut io::sink()).map_err(|_| Error::EditRecoveryUnavailable)?;
    if !reader.eof
        || reader.offset != length
        || <[u8; 32]>::from(reader.hash.finalize()) != *expected
    {
        return Err(Error::ConfiguredRootChanged);
    }
    Ok(())
}
fn validate_converted(
    source: &SourceReference<'_>,
    before: RootSnapshot,
    expected_path: &Path,
    identity: &[u8; 16],
    require_in_sync: bool,
) -> Result<(), Error> {
    let now = root_snapshot(source.raw)?;
    let mut info: ByHandleFileInformation = unsafe { zeroed() };
    if unsafe { GetFileInformationByHandle(source.raw, &mut info) } == 0
        || info.number_of_links != 1
        || now.identity != before.identity
        || now.file_size != before.file_size
        || now.last_write_time != before.last_write_time
        || now.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0
        || now.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
        || !cleanup_cloud_reparse_tag(now.reparse_tag)
        || now.placeholder_state & CF_PLACEHOLDER_STATE_PLACEHOLDER == 0
        || now.placeholder_state
            & (CF_PLACEHOLDER_STATE_PARTIAL | CF_PLACEHOLDER_STATE_PARTIALLY_ON_DISK)
            != 0
        || now.placeholder_state
            & !(CF_PLACEHOLDER_STATE_PLACEHOLDER | 0x4 | CF_PLACEHOLDER_STATE_IN_SYNC)
            != 0
        || (require_in_sync && now.placeholder_state & CF_PLACEHOLDER_STATE_IN_SYNC == 0)
        || !windows_paths_equal(
            &final_path_for_handle(source.raw).map_err(|_| Error::ConfiguredRootChanged)?,
            expected_path,
        )
    {
        return Err(Error::ConfiguredRootChanged);
    }
    verify_completion_identity(source.owner.0, identity)
}

#[cfg(test)]
mod phase_type_tests {
    use super::*;
    #[test]
    fn only_owned_sdk_tasks_and_replies_can_travel() {
        fn send<T: Send>() {}
        send::<FileCreateTask>();
        send::<FileCreateReply>();
        trait AmbiguousIfSend<A> {
            fn check() {}
        }
        impl<T: ?Sized> AmbiguousIfSend<()> for T {}
        impl<T: ?Sized + Send> AmbiguousIfSend<u8> for T {}
        trait AmbiguousIfSync<A> {
            fn check() {}
        }
        impl<T: ?Sized> AmbiguousIfSync<()> for T {}
        impl<T: ?Sized + Sync> AmbiguousIfSync<u8> for T {}
        let _ = <OwnerAttempt as AmbiguousIfSend<_>>::check;
        let _ = <SourceOwner as AmbiguousIfSend<_>>::check;
        let _ = <ConfiguredRootConnection as AmbiguousIfSend<_>>::check;
        let _ = <ConfiguredRootConnection as AmbiguousIfSync<_>>::check;
    }
}
