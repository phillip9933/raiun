//! Explicit same-owner ordinary Personal file create; never recovered replay.
use super::*;
use crate::namespace_intent::{
    CapturedAuthorization, LocalNamespaceEntry, NamespaceFileContent, NamespaceIntent,
    NamespaceObjectKind, NamespaceOperation, NamespaceParent, StorageClassification,
};
use crate::streamed_snapshot::SnapshotBinding;
use crate::streamed_store::namespace_file_store::{CapturedCreatePath, FileCreateStore};
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
impl ConfiguredRootConnection {
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
        use crate::FreshFileCreateOutcome::*;
        use sha2::Digest;
        if !valid_component(name) || generation == 0 {
            return Err(Error::InvalidConfiguredRoot);
        }
        let (tracker, recovery) = self.file_rename_guard_context(backend)?;
        let Some(ticket) = tracker.try_begin_rename() else {
            return Ok(BusyBeforeCapture);
        };
        let (dispatch_probe, lifetime) = ticket
            .dispatch_probe(tracker.clone())
            .ok_or(Error::EditRecoveryUnavailable)?;
        let guard = crate::save_rename_admission::SaveRenameAdmission::new(ticket);
        let _probe_lifetime = lifetime; // Drop before guard retires the original ticket.
        let observation = _probe_lifetime.observation_probe();
        let dispatched = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let started = dispatched.clone();
        let original_current = current;
        let current: crate::opencloud::file_create::Current = Arc::new(move |auth| {
            original_current(auth)
                && observation()
                && (!started.load(Ordering::Acquire) || dispatch_probe())
        });
        let health = |whole: bool| {
            guard.probe_clean(|| -> Result<bool, crate::BackendError> {
                let (_, actual) = self
                    .file_rename_guard_context(backend)
                    .map_err(|_| crate::BackendError::Unavailable)?;
                if !Arc::ptr_eq(&actual, &recovery) {
                    return Err(crate::BackendError::Unavailable);
                }
                if whole && recovery.has_unresolved()? {
                    return Ok(true);
                }
                recovery.has_unresolved_content_authenticated_legacy()
            })
        };
        // Our own snapshot is Pending. The authenticated initial clean scan,
        // retained ticket and no-intervening-close observation cover all normal
        // content producers through their durable initial-queue handoff.
        let after_publication = || {
            guard.check().is_ok()
                && current(authorization)
                && self
                    .file_rename_guard_context(backend)
                    .is_ok_and(|(_, actual)| Arc::ptr_eq(&actual, &recovery))
        };
        if !health(true) {
            return Err(Error::EditRecoveryUnavailable);
        }
        if !self.connected
            || self.namespace_observation_closed
            || backend.is_revoked()
            || self.state.readiness.load(Ordering::Acquire) != CALLBACK_READY
        {
            return Err(Error::ProviderUnavailable);
        }
        let original: Arc<dyn PlaceholderBackend> = backend.clone();
        if !Arc::ptr_eq(&original, &self.state.backend) {
            return Err(Error::ProviderUnavailable);
        }
        let root = self.root.as_ref().ok_or(Error::ConfiguredRootChanged)?;
        root.verify_identity(true)?;
        root.verify_registered()?;
        let physical = crate::ConfiguredRootIdentity {
            volume_serial: root.identity.volume_serial,
            file_index: root.identity.file_index,
        };
        let mut admission = backend
            .admit_file_create(physical, authorization, job, current.clone())
            .map_err(|_| Error::EditRecoveryUnavailable)?;
        let capture_job = admission.capture_job();
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
                return Ok(BusyBeforeCapture);
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
            guard.check().map_err(|_| Error::EditRecoveryUnavailable)?;
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
        let rename = self
            .file_rename_store(backend, &captured.scope, authorization)?
            .ok_or(Error::EditRecoveryUnavailable)?;
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
        if !health(true) {
            return Err(Error::EditRecoveryUnavailable);
        }
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
                || guard.check().is_err()
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
            return Ok(CapturedLocalIncomplete);
        }
        drop(reference); // SAME opaque source owner survives, but no network-long ref.
        let mut lease = match store.acquire_dispatch(joined.record().key()) {
            Ok(value) => value,
            Err(_) => return Ok(CapturedLocalIncomplete),
        };
        if !after_publication()
            || admission.check(backend).is_err()
            || lease.mark_submitted().is_err()
        {
            return Ok(CapturedLocalIncomplete);
        }
        let original_join = joined.record().clone();
        let streamed_key = store
            .snapshot_store()
            .record_key(original_join.snapshot_id())
            .map_err(|_| Error::EditRecoveryUnavailable)?;
        match admission.send(backend, joined.into_verified(), || {
            if !after_publication() {
                return Err(crate::BackendError::Unavailable);
            }
            guard
                .claim_send()
                .map_err(|_| crate::BackendError::Unavailable)?;
            if !_probe_lifetime.arm_after_dispatch() {
                return Err(crate::BackendError::Unavailable);
            }
            dispatched.store(true, Ordering::Release);
            Ok(())
        }) {
            Ok(proof) => {
                if admission.persist(backend, &mut lease, &proof).is_err() {
                    return Ok(SubmittedUncertain);
                }
                // Full original context/recovery checks occur outside backend.state.
                if !after_publication() {
                    return Ok(RemoteVerifiedLocalIncomplete);
                }
                let inside_publication = || {
                    guard.check().is_ok()
                        && current(authorization)
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
                    let (_, actual_parent, _pins) =
                        native_namespace_directory::pin_namespace_parent(
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
                    guard
                        .claim_completion()
                        .map_err(|_| Error::EditRecoveryUnavailable)?;
                    // SAFETY: same protected owner and a fresh positive compare USN.
                    // Never NULL/zero fallback; a mismatch is retained incomplete.
                    let hr = unsafe { CfSetInSyncState(source.0, 1, 0, &mut compare_usn) };
                    if hr < 0 {
                        return Err(native_error("complete fresh file-create", hr));
                    }
                    validate_converted(&final_reference, snapshot, &expected, identity, true)?;
                    hash_source(&final_reference, snapshot.file_size, &capture_job, &digest)?;
                    let after_usn =
                        completion_usn(final_reference.raw, snapshot.identity.file_index)?;
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
            Err(_) => {
                // Submitted remains factual even if this best-effort attention append fails.
                let _ =
                    lease.record_attention(crate::namespace_intent::NamespaceAttention::Uncertain);
                Ok(SubmittedUncertain)
            }
        }
        // source/parent/ancestor ownership ends only after SDK source-worker join.
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
