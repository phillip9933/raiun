//! Explicit capture/send foundation only: never conversion, clean or completion.
use super::*;
use crate::namespace_intent::{
    CapturedAuthorization, LocalNamespaceEntry, NamespaceFileContent, NamespaceIntent,
    NamespaceObjectKind, NamespaceOperation, NamespaceParent, StorageClassification,
};
use crate::streamed_snapshot::SnapshotBinding;
use crate::streamed_store::namespace_file_store::{CapturedCreatePath, FileCreateStore};
use std::io::{self, Read};

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
                if admission.persist(backend, &mut lease, &proof).is_ok() {
                    Ok(RemoteVerifiedLocalIncomplete)
                } else {
                    Ok(SubmittedUncertain)
                }
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
