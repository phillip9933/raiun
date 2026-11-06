//! Explicit same-owner ordinary Personal file create; never recovered replay.
use super::*;
use crate::close_capture_admission::IndependentCreateAdmission;
use crate::creation_preparation::{
    Failure, Stage as PreparationStage, Trace, wait_for_recovery_health,
};
use crate::file_create_completion_diagnostics::{
    Stage as CompletionStage, Trace as CompletionTrace,
};
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

#[path = "native_file_create_continuation.rs"]
mod continuation;
pub(crate) use continuation::NativeFileCreateContinuation;

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
        .map_err(io::Error::other)?;
        if (self.stopped)() || (eof && count != 0) || (!eof && count == 0) {
            return Err(io::Error::other("file-create source changed"));
        }
        self.eof |= eof;
        self.offset += count as u64;
        self.hash.update(&bytes[..count]);
        Ok(count)
    }
}

/// Private same-owner body guard for an admitted replacement. This supplies
/// no remote-create admission: the caller retains the original delete receipt
/// and existing remote baseline through this owner's complete lifetime.
pub(super) struct ReplacementBody {
    source: SourceOwner,
    snapshot: RootSnapshot,
    usn: i64,
    digest: [u8; 32],
    path: PathBuf,
    cloud_identity: Option<[u8; 16]>,
}
impl ReplacementBody {
    pub(super) fn capture<T>(
        path: &Path,
        volume: u32,
        original_file: u64,
        job: &crate::StreamedRecoveryJob,
        stopped: &dyn Fn() -> bool,
        capture: impl FnOnce(&mut dyn Read, RootSnapshot) -> Result<T, Error>,
    ) -> Result<(Self, T), Error> {
        Self::capture_with_usn(
            path,
            volume,
            original_file,
            job,
            stopped,
            |reader, snapshot, _| capture(reader, snapshot),
        )
    }
    pub(super) fn capture_with_usn<T>(
        path: &Path,
        volume: u32,
        original_file: u64,
        job: &crate::StreamedRecoveryJob,
        stopped: &dyn Fn() -> bool,
        capture: impl FnOnce(&mut dyn Read, RootSnapshot, i64) -> Result<T, Error>,
    ) -> Result<(Self, T), Error> {
        Self::capture_with_file_policy(
            path,
            volume,
            original_file,
            false,
            None,
            job,
            stopped,
            capture,
        )
    }

    pub(super) fn capture_same_file_with_usn<T>(
        path: &Path,
        volume: u32,
        original_file: u64,
        job: &crate::StreamedRecoveryJob,
        stopped: &dyn Fn() -> bool,
        capture: impl FnOnce(&mut dyn Read, RootSnapshot, i64) -> Result<T, Error>,
    ) -> Result<(Self, T), Error> {
        Self::capture_with_file_policy(
            path,
            volume,
            original_file,
            true,
            None,
            job,
            stopped,
            capture,
        )
    }

    pub(super) fn capture_continuation_with_usn<T>(
        path: &Path,
        volume: u32,
        original_file: u64,
        cloud_identity: [u8; 16],
        job: &crate::StreamedRecoveryJob,
        stopped: &dyn Fn() -> bool,
        capture: impl FnOnce(&mut dyn Read, RootSnapshot, i64) -> Result<T, Error>,
    ) -> Result<(Self, T), Error> {
        Self::capture_with_file_policy(
            path,
            volume,
            original_file,
            true,
            Some(cloud_identity),
            job,
            stopped,
            capture,
        )
    }

    fn capture_with_file_policy<T>(
        path: &Path,
        volume: u32,
        original_file: u64,
        same_file: bool,
        accepted_cloud_identity: Option<[u8; 16]>,
        job: &crate::StreamedRecoveryJob,
        stopped: &dyn Fn() -> bool,
        capture: impl FnOnce(&mut dyn Read, RootSnapshot, i64) -> Result<T, Error>,
    ) -> Result<(Self, T), Error> {
        use sha2::Digest;
        if stopped() || job.is_stopped() {
            return Err(Error::EditRecoveryUnavailable);
        }
        let source = SourceOwner::open(&wide_path(path)?)?;
        let reference = source.reference()?;
        let initial = root_snapshot(reference.raw)?;
        let cloud_identity = if initial.placeholder_state == 0 {
            None
        } else {
            Some(accepted_cloud_identity.ok_or(Error::ConfiguredRootChanged)?)
        };
        let (snapshot, usn) = Self::observe(&reference, initial, path, cloud_identity)?;
        if snapshot.identity.volume_serial != volume
            || (snapshot.identity.file_index == original_file) != same_file
            || usn <= 0
            || !windows_paths_equal(
                &final_path_for_handle(reference.raw).map_err(|_| Error::ConfiguredRootChanged)?,
                path,
            )
        {
            return Err(Error::ConfiguredRootChanged);
        }
        let mut reader = Reader {
            source: &reference,
            offset: 0,
            length: snapshot.file_size,
            eof: false,
            hash: sha2::Sha256::new(),
            job,
            stopped,
        };
        let value = capture(&mut reader, snapshot, usn)?;
        if !reader.eof || reader.offset != snapshot.file_size {
            return Err(Error::EditRecoveryUnavailable);
        }
        let digest: [u8; 32] = reader.hash.finalize().into();
        let after = Self::observe(&reference, snapshot, path, cloud_identity)?;
        if !same_edit_snapshot(snapshot, after.0) || after.1 != usn || stopped() {
            return Err(Error::ConfiguredRootChanged);
        }
        drop(reference);
        let body = Self {
            source,
            snapshot,
            usn,
            digest,
            path: path.to_owned(),
            cloud_identity,
        };
        body.check(job, stopped)?;
        Ok((body, value))
    }
    fn observe(
        reference: &SourceReference<'_>,
        expected: RootSnapshot,
        path: &Path,
        cloud_identity: Option<[u8; 16]>,
    ) -> Result<(RootSnapshot, i64), Error> {
        if let Some(identity) = cloud_identity {
            // validate_converted also requires exactly one hard link and the
            // full, nonpartial cloud body at this exact file and path.
            validate_converted(reference, expected, path, &identity, false)?;
            Ok((
                root_snapshot(reference.raw)?,
                completion_usn(reference.raw, expected.identity.file_index)?,
            ))
        } else {
            plain(reference)
        }
    }
    pub(super) fn len(&self) -> u64 {
        self.snapshot.file_size
    }
    pub(super) fn sha256(&self) -> [u8; 32] {
        self.digest
    }
    pub(super) fn usn(&self) -> i64 {
        self.usn
    }
    pub(super) fn completed_usn(&self, identity: &[u8; 16]) -> Result<i64, Error> {
        let reference = self.source.reference()?;
        validate_converted(&reference, self.snapshot, &self.path, identity, true)?;
        completion_usn(reference.raw, self.snapshot.identity.file_index)
    }
    pub(super) fn local_file(&self) -> LocalFileIdentity {
        LocalFileIdentity {
            volume_serial: self.snapshot.identity.volume_serial,
            file_index: self.snapshot.identity.file_index,
        }
    }
    pub(super) fn check(
        &self,
        job: &crate::StreamedRecoveryJob,
        stopped: &dyn Fn() -> bool,
    ) -> Result<(), Error> {
        if stopped() || job.is_stopped() {
            return Err(Error::EditRecoveryUnavailable);
        }
        let reference = self.source.reference()?;
        let now = Self::observe(&reference, self.snapshot, &self.path, self.cloud_identity)?;
        if !same_edit_snapshot(self.snapshot, now.0)
            || now.1 != self.usn
            || !windows_paths_equal(
                &final_path_for_handle(reference.raw).map_err(|_| Error::ConfiguredRootChanged)?,
                &self.path,
            )
        {
            return Err(Error::ConfiguredRootChanged);
        }
        hash_source(&reference, self.snapshot.file_size, job, &self.digest)?;
        let after = Self::observe(&reference, self.snapshot, &self.path, self.cloud_identity)?;
        if stopped() || !same_edit_snapshot(self.snapshot, after.0) || after.1 != self.usn {
            return Err(Error::ConfiguredRootChanged);
        }
        Ok(())
    }
    pub(super) fn convert(
        &self,
        identity: &[u8; 16],
        job: &crate::StreamedRecoveryJob,
        stopped: &dyn Fn() -> bool,
        claim: impl FnOnce() -> bool,
    ) -> Result<(), Error> {
        self.convert_with_phase(identity, job, stopped, claim, || {})
    }
    pub(super) fn convert_with_phase(
        &self,
        identity: &[u8; 16],
        job: &crate::StreamedRecoveryJob,
        stopped: &dyn Fn() -> bool,
        claim: impl FnOnce() -> bool,
        after_sync: impl FnOnce(),
    ) -> Result<(), Error> {
        self.check(job, stopped)?;
        let reference = self.source.reference()?;
        if let Some(expected) = self.cloud_identity {
            if expected != *identity || !claim() {
                return Err(Error::EditRecoveryUnavailable);
            }
            validate_converted(&reference, self.snapshot, &self.path, identity, false)?;
            let mut usn = completion_usn(reference.raw, self.snapshot.identity.file_index)?;
            if usn != self.usn || usn <= 0 || stopped() {
                return Err(Error::ConfiguredRootChanged);
            }
            if self.snapshot.placeholder_state & CF_PLACEHOLDER_STATE_IN_SYNC == 0 {
                let hr = unsafe { CfSetInSyncState(self.source.0, 1, 0, &mut usn) };
                if hr < 0 {
                    return Err(native_error("complete held file-create continuation", hr));
                }
            }
            after_sync();
            validate_converted(&reference, self.snapshot, &self.path, identity, true)?;
            hash_source(&reference, self.snapshot.file_size, job, &self.digest)?;
            if stopped() || completion_usn(reference.raw, self.snapshot.identity.file_index)? != usn
            {
                return Err(Error::ConfiguredRootChanged);
            }
            return Ok(());
        }
        let mut converted_usn = 0i64;
        // Same protected WRITE_ACCESS owner and synchronous NONE conversion
        // used by the ordinary create path. No re-open or fallback handle.
        let hr = unsafe {
            CfConvertToPlaceholder(
                reference.raw,
                identity.as_ptr().cast(),
                16,
                0,
                &mut converted_usn,
                null_mut(),
            )
        };
        if hr != 0 {
            return Err(native_error("convert admitted replacement", hr));
        }
        if converted_usn < 0 {
            return Err(Error::EditRecoveryUnavailable);
        }
        verify_completion_identity(self.source.0, identity)?;
        validate_converted(&reference, self.snapshot, &self.path, identity, false)?;
        hash_source(&reference, self.snapshot.file_size, job, &self.digest)?;
        let observed_usn = completion_usn(reference.raw, self.snapshot.identity.file_index)?;
        if observed_usn <= 0
            || (converted_usn > 0 && observed_usn != converted_usn)
            || stopped()
            || job.is_stopped()
        {
            return Err(Error::ConfiguredRootChanged);
        }
        let mut usn = journal_converted_usn(&reference, self.snapshot.identity.file_index)?;
        hash_source(&reference, self.snapshot.file_size, job, &self.digest)?;
        validate_converted(&reference, self.snapshot, &self.path, identity, false)?;
        if stopped()
            || job.is_stopped()
            || completion_usn(reference.raw, self.snapshot.identity.file_index)? != usn
        {
            return Err(Error::ConfiguredRootChanged);
        }
        if !claim() {
            return Err(Error::EditRecoveryUnavailable);
        }
        let hr = unsafe { CfSetInSyncState(self.source.0, 1, 0, &mut usn) };
        if hr < 0 {
            return Err(native_error("complete admitted replacement", hr));
        }
        after_sync();
        validate_converted(&reference, self.snapshot, &self.path, identity, true)?;
        hash_source(&reference, self.snapshot.file_size, job, &self.digest)?;
        if stopped() || completion_usn(reference.raw, self.snapshot.identity.file_index)? != usn {
            return Err(Error::ConfiguredRootChanged);
        }
        Ok(())
    }
}

#[derive(Default)]
pub(super) struct CreateOwner {
    closed: bool,
    nonce: u64,
    attempts: Vec<OwnerAttempt>,
}
struct OwnerAttempt {
    key: Arc<ReplyKey>,
    completion_trace: Arc<CompletionTrace>,
    phase: Phase,
    flight_done: Arc<std::sync::atomic::AtomicBool>,
    backend: Arc<crate::OpenCloudPlaceholderBackend>,
    recovery: Arc<dyn PreparedEditRecovery>,
    tracker: Arc<CloseCaptureAdmission>,
    ticket: IndependentCreateAdmission,
    name: String,
    parent_components: Vec<String>,
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
    completion_trace: Arc<CompletionTrace>,
    store: Option<Arc<SnapshotStore>>,
    backend: Arc<crate::OpenCloudPlaceholderBackend>,
    kind: Option<TaskKind>,
    _flight: TaskFlight, // LAST: all owned network/body data drops before done.
}
struct Preparation {
    parent_components: Vec<String>,
    name: String,
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
    Prepared(Result<Box<Prepared>, Failure>),
    Sent(Box<(Admission, Result<VerifiedCreateReadback, BackendError>)>),
    Refreshed(Box<(Admission, Result<RefreshedCreateReadback, BackendError>)>),
}
/// Nonserializable original-attempt reply. Public fields/constructors are absent.
pub struct FileCreateReply {
    key: Arc<ReplyKey>,
    completion_trace: Arc<CompletionTrace>,
    store: Option<Arc<SnapshotStore>>,
    kind: ReplyKind,
}
impl FileCreateReply {
    /// Fixed failure boundary only; never exposes paths, credentials or server text.
    pub fn failure_context(&self) -> &'static str {
        match &self.kind {
            ReplyKind::Prepared(Err(failure)) => failure.message("File"),
            ReplyKind::Prepared(Ok(_)) => {
                "File creation paused: local source admission or protected capture failed. Recovery files have been kept."
            }
            ReplyKind::Sent(pair) => match &pair.1 {
                Err(_) => {
                    "File creation paused: original upload send or readback returned no verified result. Recovery files have been kept."
                }
                Ok(_) => {
                    "File creation paused: verified readback returned, but the original attempt or result recording was held or refused. Recovery files have been kept."
                }
            },
            ReplyKind::Refreshed(pair) => match &pair.1 {
                Err(_) => {
                    "File creation paused: verified cloud metadata refresh failed. Recovery files have been kept."
                }
                Ok(_) => {
                    "File creation paused: verified file publication or native completion failed. Recovery files have been kept."
                }
            },
        }
    }
    /// Read after consuming this reply on its original owner. The retained
    /// invocation trace contains only fixed stages and grants no authority.
    pub fn failure_context_after_advance(
        &self,
    ) -> impl Fn() -> &'static str + Send + 'static + use<> {
        let trace = Arc::clone(&self.completion_trace);
        let fallback = self.failure_context();
        move || trace.failure_context().unwrap_or(fallback)
    }
    /// The original invocation's native HRESULT only, read after advance.
    pub fn failure_hresult_after_advance(
        &self,
    ) -> impl Fn() -> Option<u32> + Send + 'static + use<> {
        let trace = Arc::clone(&self.completion_trace);
        move || trace.failure_hresult()
    }
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
                let trace = Arc::new(Trace::new());
                let result = (|| {
                    let mut health_wait = None;
                    trace.enter(PreparationStage::Job);
                    prep.job.check()?;
                    trace.enter(PreparationStage::Current);
                    if !(prep.current)(self.key.authorization) {
                        return Err(BackendError::Unavailable);
                    }
                    let parent_components: Vec<_> =
                        prep.parent_components.iter().map(String::as_str).collect();
                    let admission = self.backend.admit_file_create_traced(
                        &parent_components,
                        self.key.root,
                        self.key.authorization,
                        &prep.job,
                        prep.current.clone(),
                        &trace,
                    )?;
                    trace.enter(PreparationStage::Current);
                    admission.check(&self.backend)?;
                    let space = admission
                        .fresh_create_space_for_child(&self.backend, &prep.name)?
                        .with_preparation_trace(Arc::clone(&trace));
                    if wait_for_recovery_health(&prep.job, &trace, &mut health_wait, || {
                        trace.enter(PreparationStage::Job);
                        prep.job.check()?;
                        trace.enter(PreparationStage::Current);
                        if !(prep.current)(self.key.authorization) {
                            return Err(BackendError::Unavailable);
                        }
                        admission.check(&self.backend)?;
                        trace.enter(PreparationStage::RecoveryBefore);
                        prep.recovery
                            .has_unresolved_for_fresh_create_in_space(&space)
                    })? {
                        return Err(BackendError::Unavailable);
                    }
                    trace.enter(PreparationStage::Current);
                    admission.check(&self.backend)?;
                    trace.enter(PreparationStage::RecoveryStore);
                    let rename = prep
                        .recovery
                        .file_rename_store(&admission.parent.scope, self.key.authorization)?
                        .ok_or(BackendError::Unavailable)?;
                    trace.enter(PreparationStage::Current);
                    admission.check(&self.backend)?;
                    if wait_for_recovery_health(&prep.job, &trace, &mut health_wait, || {
                        trace.enter(PreparationStage::Job);
                        prep.job.check()?;
                        trace.enter(PreparationStage::Current);
                        if !(prep.current)(self.key.authorization) {
                            return Err(BackendError::Unavailable);
                        }
                        admission.check(&self.backend)?;
                        trace.enter(PreparationStage::RecoveryAfter);
                        prep.recovery
                            .has_unresolved_for_fresh_create_in_space(&space)
                    })? {
                        return Err(BackendError::Unavailable);
                    }
                    trace.enter(PreparationStage::Current);
                    admission.check(&self.backend)?;
                    Ok(Box::new(Prepared { admission, rename }))
                })()
                .map_err(|error| {
                    trace.backend(error);
                    trace.failure()
                });
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
            completion_trace: Arc::clone(&self.completion_trace),
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
            completion_trace: Arc::clone(&self.completion_trace),
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
        self.begin_fresh_personal_file_create_in_parent(
            backend,
            &["Personal"],
            name,
            authorization,
            generation,
            job,
            original_current,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn begin_fresh_personal_file_create_in_parent(
        &self,
        backend: &Arc<crate::OpenCloudPlaceholderBackend>,
        parent_components: &[&str],
        name: &str,
        authorization: CapturedAuthorization,
        generation: u64,
        job: &crate::StreamedRecoveryJob,
        original_current: crate::opencloud::file_create::Current,
    ) -> Result<FileCreateStep, Error> {
        if crate::personal_create_relative(parent_components, name).is_none()
            || parent_components.iter().any(|part| !valid_component(part))
            || !valid_component(name)
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
        if slot.attempts.len() >= 4
            || slot.attempts.iter().any(|attempt| {
                let parts = attempt
                    .parent_components
                    .iter()
                    .chain(std::iter::once(&attempt.name));
                let incoming = parent_components
                    .iter()
                    .copied()
                    .chain(std::iter::once(name));
                parts.zip(incoming).all(|(a, b)| a.eq_ignore_ascii_case(b))
            })
        {
            return Ok(FileCreateStep::Finished(
                crate::FreshFileCreateOutcome::BusyBeforeCapture,
            ));
        }
        let (tracker, recovery) = self.file_create_guard_context(backend)?;
        let Some(ticket) = tracker.try_begin_independent_create(
            parent_components
                .iter()
                .map(|part| (*part).to_owned())
                .chain(std::iter::once(name.to_owned()))
                .collect(),
        ) else {
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
            completion_trace: Arc::new(CompletionTrace::new()),
            phase: Phase::Prepare,
            flight_done: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            backend: backend.clone(),
            recovery: recovery.clone(),
            tracker,
            ticket,
            name: name.into(),
            parent_components: parent_components
                .iter()
                .map(|part| (*part).to_owned())
                .collect(),
            job: job.clone(),
            current: current.clone(),
            dispatched,
            local: None,
        };
        self.check_create_attempt(&attempt)?;
        let task = attempt.task(
            Phase::Prepare,
            TaskKind::Prepare(Box::new(Preparation {
                parent_components: attempt.parent_components.clone(),
                name: attempt.name.clone(),
                recovery,
                job,
                current,
            })),
        );
        slot.attempts.push(attempt);
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
        let (tracker, recovery) = self.file_create_guard_context(&attempt.backend)?;
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
        let index = slot
            .attempts
            .iter()
            .position(|attempt| Arc::ptr_eq(&attempt.key, &reply.key))
            .ok_or(Error::ConnectionStateInvalid)?;
        let expected = &slot.attempts[index];
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
        let mut attempt = slot.attempts.remove(index);
        if disposition == ReplyDisposition::Retire || self.check_create_attempt(&attempt).is_err() {
            attempt
                .completion_trace
                .fail_at(CompletionStage::OriginalContext);
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
                    &slot.attempts,
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
                if self.check_create_attempt(&attempt).is_err() {
                    attempt
                        .completion_trace
                        .fail_at(CompletionStage::OriginalContext);
                    return Ok(FileCreateStep::Finished(
                        crate::FreshFileCreateOutcome::CapturedLocalIncomplete,
                    ));
                }
                // Claim the original live ticket before writing Submitted. A
                // refused claim has no send and must retain a pending capture.
                if !attempt.ticket.claim_dispatch() {
                    return Ok(FileCreateStep::Finished(
                        crate::FreshFileCreateOutcome::CapturedLocalIncomplete,
                    ));
                }
                attempt.dispatched.store(true, Ordering::Release);
                // Write-ahead history still precedes construction of any Send
                // task; a persistence refusal cannot dispatch the body.
                if local.lease.mark_submitted().is_err() {
                    return Ok(FileCreateStep::Finished(
                        crate::FreshFileCreateOutcome::CapturedLocalIncomplete,
                    ));
                }
                attempt.local = Some(local);
                let task = attempt.task(
                    Phase::Send,
                    TaskKind::Send(Box::new((prepared.admission, joined))),
                );
                slot.attempts.push(attempt);
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
                    attempt
                        .completion_trace
                        .fail_at(CompletionStage::OriginalContext);
                    return Ok(FileCreateStep::Finished(
                        crate::FreshFileCreateOutcome::RemoteVerifiedLocalIncomplete,
                    ));
                }
                let task = attempt.task(
                    Phase::Refresh,
                    TaskKind::Refresh(Box::new((admission, proof))),
                );
                slot.attempts.push(attempt);
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
        for attempt in &slot.attempts {
            attempt.job.cancel();
        }
        // Keep every original native capture until its actual SDK/body flight
        // has disposed; no one result can release a sibling claim.
        slot.attempts
            .retain(|attempt| !attempt.flight_done.load(Ordering::Acquire));
        slot.attempts.is_empty()
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
        siblings: &[OwnerAttempt],
    ) -> Result<CaptureResult, Error> {
        use sha2::Digest;
        self.check_create_attempt(attempt)?;
        let backend = &attempt.backend;
        let authorization = attempt.key.authorization;
        let generation = attempt.key.generation;
        let name = attempt.name.as_str();
        let components: Vec<_> = attempt
            .parent_components
            .iter()
            .map(String::as_str)
            .collect();
        let relative_path = crate::personal_create_relative(&components, name)
            .ok_or(Error::InvalidConfiguredRoot)?;
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
                &components,
                FILE_READ_ATTRIBUTES,
            )?;
        let path = attempt
            .parent_components
            .iter()
            .fold(root.path.clone(), |path, part| path.join(part))
            .join(name);
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
        if before.identity != snapshot.identity
            || before.file_attributes != snapshot.file_attributes
            || before.reparse_tag != snapshot.reparse_tag
            || before.placeholder_state != snapshot.placeholder_state
            || snapshot.identity.volume_serial != physical.volume_serial
            || snapshot.identity == parent_snapshot.identity
            || siblings.iter().any(|sibling| {
                sibling
                    .local
                    .as_ref()
                    .is_some_and(|local| local.snapshot.identity == snapshot.identity)
            })
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
        // Explorer may finish its last write between the metadata probe and
        // the exclusive source open. No body, intent or dispatch exists yet.
        // Keep the original candidate/deadline and reacquire all admission on
        // the next turn; identity, shape, link and path mismatches above hold.
        if before.file_size != snapshot.file_size
            || before.last_write_time != snapshot.last_write_time
        {
            return Ok(CaptureResult::Busy);
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
                &components,
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
                local_components: attempt.parent_components.clone(),
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
                relative_path: relative_path.clone(),
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
                CapturedCreatePath::new(
                    attempt
                        .parent_components
                        .iter()
                        .cloned()
                        .chain(std::iter::once(name.into()))
                        .collect(),
                    relative_path,
                )
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
        let trace = Arc::clone(&attempt.completion_trace);
        trace.enter(CompletionStage::OriginalContext);
        let result = self.finish_create_local_traced(attempt, local, admission, proof, &trace);
        if let Err(error) = &result {
            trace.fail_error(error);
        }
        result
    }
    fn finish_create_local_traced(
        &self,
        attempt: &mut OwnerAttempt,
        local: LocalCapture,
        admission: Admission,
        proof: RefreshedCreateReadback,
        trace: &CompletionTrace,
    ) -> Result<crate::FreshFileCreateOutcome, Error> {
        use crate::FreshFileCreateOutcome::*;
        self.check_create_attempt(attempt)?;
        let components: Vec<_> = attempt
            .parent_components
            .iter()
            .map(String::as_str)
            .collect();
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
                    .file_create_guard_context(backend)
                    .is_ok_and(|(actual_tracker, actual)| {
                        Arc::ptr_eq(&actual, &recovery) && Arc::ptr_eq(&actual_tracker, &tracker)
                    })
        };
        // Full original context/recovery checks occur outside backend.state.
        if !after_publication() {
            trace.fail();
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
                    .observed_unverifiable_closes
                    .load(Ordering::Acquire)
                    == 0
        };
        let complete = |final_reference: &SourceReference<'_>| -> Result<(), Error> {
            trace.enter(CompletionStage::OriginalContext);
            if !inside_publication() {
                return Err(Error::EditRecoveryUnavailable);
            }
            admission
                .check(backend)
                .map_err(|_| Error::ProviderUnavailable)?;
            trace.enter(CompletionStage::RootIdentity);
            root.verify_identity(true)?;
            trace.enter(CompletionStage::RootRegistration);
            root.verify_registered()?;
            trace.enter(CompletionStage::SourceSnapshot);
            let (now, current_usn) = plain(final_reference)?;
            if !same_edit_snapshot(snapshot, now) || current_usn != usn {
                return Err(Error::ConfiguredRootChanged);
            }
            trace.enter(CompletionStage::ParentIdentity);
            let (_, actual_parent, _pins) = native_namespace_directory::pin_namespace_parent(
                root,
                &admission.parent.route,
                admission.parent.identity,
                &components,
                FILE_READ_ATTRIBUTES,
            )?;
            if actual_parent.identity != parent_snapshot.identity {
                return Err(Error::ConfiguredRootChanged);
            }
            trace.enter(CompletionStage::SourcePath);
            if !windows_paths_equal(
                &final_path_for_handle(final_reference.raw)
                    .map_err(|_| Error::ConfiguredRootChanged)?,
                &expected,
            ) {
                return Err(Error::ConfiguredRootChanged);
            }
            trace.enter(CompletionStage::SourceHashBeforeConvert);
            hash_source(final_reference, snapshot.file_size, &capture_job, &digest)?;
            trace.enter(CompletionStage::SourceSnapshotAfterHash);
            let after = plain(final_reference)?;
            if !same_edit_snapshot(snapshot, after.0) || after.1 != usn {
                return Err(Error::ConfiguredRootChanged);
            }
            Ok(())
        };
        trace.enter(CompletionStage::Publication);
        let result = admission.publish_and_complete(backend, &proof, |identity| {
            // Metadata HTTP has finished. Re-reference only this SAME owner;
            // a foreground break refuses completion, never reopen/rebase.
            trace.enter(CompletionStage::SourceReference);
            let final_reference = source.reference()?;
            complete(&final_reference)?;
            let mut converted_usn = 0i64;
            // SAFETY: referenced WRITE_ACCESS Win32 borrow; synchronous NONE
            // conversion retains all bytes, with a live 16-byte identity.
            trace.enter(CompletionStage::Convert);
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
            if hr != 0 {
                return Err(native_error("convert fresh file-create", hr));
            }
            trace.enter(CompletionStage::ConvertedUsn);
            if converted_usn < 0 {
                return Err(Error::EditRecoveryUnavailable);
            }
            trace.enter(CompletionStage::PlaceholderIdentity);
            verify_completion_identity(source.0, identity)?;
            trace.enter(CompletionStage::ConvertedShape);
            validate_converted(&final_reference, snapshot, &expected, identity, false)?;
            trace.enter(CompletionStage::SourceHashAfterConvert);
            hash_source(&final_reference, snapshot.file_size, &capture_job, &digest)?;
            trace.enter(CompletionStage::ConvertedUsnRead);
            let observed_usn = completion_usn(final_reference.raw, snapshot.identity.file_index)?;
            trace.enter(CompletionStage::ConvertedUsnCompare);
            if observed_usn <= 0 || (converted_usn > 0 && observed_usn != converted_usn) {
                return Err(Error::ConfiguredRootChanged);
            }
            trace.enter(CompletionStage::OriginalContext);
            admission
                .check(backend)
                .map_err(|_| Error::ProviderUnavailable)?;
            trace.enter(CompletionStage::RootIdentity);
            root.verify_identity(true)?;
            trace.enter(CompletionStage::RootRegistration);
            root.verify_registered()?;
            trace.enter(CompletionStage::OriginalContext);
            if !inside_publication() {
                return Err(Error::EditRecoveryUnavailable);
            }
            trace.enter(CompletionStage::ConversionJournal);
            let mut compare_usn =
                journal_converted_usn(&final_reference, snapshot.identity.file_index)?;
            trace.enter(CompletionStage::ConversionJournalStable);
            hash_source(&final_reference, snapshot.file_size, &capture_job, &digest)?;
            validate_converted(&final_reference, snapshot, &expected, identity, false)?;
            admission
                .check(backend)
                .map_err(|_| Error::ProviderUnavailable)?;
            root.verify_identity(true)?;
            root.verify_registered()?;
            if !inside_publication() {
                return Err(Error::EditRecoveryUnavailable);
            }
            if completion_usn(final_reference.raw, snapshot.identity.file_index)? != compare_usn {
                return Err(Error::ConfiguredRootChanged);
            }
            trace.enter(CompletionStage::CompletionClaim);
            if !ticket.claim_completion() {
                return Err(Error::EditRecoveryUnavailable);
            }
            // SAFETY: same protected owner and a fresh positive compare USN.
            // Never NULL/zero fallback; a mismatch is retained incomplete.
            trace.enter(CompletionStage::SetInSync);
            let hr = unsafe { CfSetInSyncState(source.0, 1, 0, &mut compare_usn) };
            if hr < 0 {
                return Err(native_error("complete fresh file-create", hr));
            }
            trace.enter(CompletionStage::InSyncShape);
            validate_converted(&final_reference, snapshot, &expected, identity, true)?;
            trace.enter(CompletionStage::SourceHashAfterSync);
            hash_source(&final_reference, snapshot.file_size, &capture_job, &digest)?;
            trace.enter(CompletionStage::InSyncUsnRead);
            let after_usn = completion_usn(final_reference.raw, snapshot.identity.file_index)?;
            trace.enter(CompletionStage::InSyncUsnCompare);
            if compare_usn <= 0 || after_usn != compare_usn {
                return Err(Error::ConfiguredRootChanged);
            }
            trace.enter(CompletionStage::FinalRootIdentity);
            root.verify_identity(true)?;
            trace.enter(CompletionStage::FinalRootRegistration);
            root.verify_registered()?;
            trace.enter(CompletionStage::FinalCurrent);
            if !inside_publication() {
                return Err(Error::EditRecoveryUnavailable);
            }
            trace.enter(CompletionStage::Publication);
            Ok(final_reference)
        });
        let final_reference = match result {
            Ok(reference) => {
                trace.enter(CompletionStage::PostPublicationCurrent);
                if !after_publication() {
                    trace.fail();
                    return Ok(RemoteVerifiedLocalIncomplete);
                }
                reference
            }
            Err(error) => {
                trace.fail_error(&error);
                return Ok(RemoteVerifiedLocalIncomplete);
            }
        };
        // Backend state/provider permit are now gone. Keep the SAME source
        // reference while taking record/quota locks for linked custody.
        trace.enter(CompletionStage::CompletionReport);
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
            trace.enter(CompletionStage::CustodyCurrent);
            if !after_publication() || admission.check(backend).is_err() {
                return Err(crate::streamed_store::StoreError::Invalid);
            }
            trace.enter(CompletionStage::SnapshotLease);
            let mut snapshot_lease = store
                .snapshot_store()
                .acquire_dispatch(completion.snapshot().1)?;
            trace.enter(CompletionStage::SnapshotAck);
            let acknowledged = snapshot_lease.acknowledge_create(&completion)?;
            trace.enter(CompletionStage::CustodyCurrent);
            if !after_publication() || admission.check(backend).is_err() {
                return Err(crate::streamed_store::StoreError::Invalid);
            }
            trace.enter(CompletionStage::JoinCompletion);
            lease.record_local_completed(&completion, &acknowledged)
        })();
        Ok(if custody.is_ok() {
            LocallyCompleted
        } else {
            trace.fail();
            RemoteVerifiedLocalIncomplete
        })
    }
}

// One journal phase for an already verified conversion on the SAME referenced
// exclusive owner. Never repeat it to rebase a refused comparison or update.
// The journal record is no data flush or writer fence: authority remains the
// retained owner, exact metadata/content/current checks and positive USN CAS.
fn journal_converted_usn(
    source: &SourceReference<'_>,
    expected_file_id: u64,
) -> Result<i64, Error> {
    const FSCTL_WRITE_USN_CLOSE_RECORD: u32 = 0x0009_00ef;
    let mut usn = 0_i64;
    let mut io = CompletionIo::new()?;
    // SAFETY: the original referenced raw handle, exact aligned output and
    // owned OVERLAPPED/event remain live until definitive I/O completion.
    // This appends a close record without changing file data or permissions.
    let result = unsafe {
        DeviceIoControl(
            source.raw,
            FSCTL_WRITE_USN_CLOSE_RECORD,
            null(),
            0,
            (&mut usn as *mut i64).cast(),
            size_of::<i64>() as u32,
            null_mut(),
            (&mut io.overlapped as *mut CompletionOverlapped).cast(),
        )
    };
    if io.finish(source.raw, result)? != size_of::<i64>() as u32
        || usn <= 0
        || completion_usn(source.raw, expected_file_id)? != usn
    {
        return Err(Error::EditRecoveryUnavailable);
    }
    Ok(usn)
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
    io::copy(&mut reader, &mut io::sink()).map_err(|error| {
        error
            .get_ref()
            .and_then(|source| source.downcast_ref::<Error>())
            .copied()
            .unwrap_or(Error::EditRecoveryUnavailable)
    })?;
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
