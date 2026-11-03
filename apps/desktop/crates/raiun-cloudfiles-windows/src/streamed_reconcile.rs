//! Bounded ordinary v2 reconciliation. Durable local evidence survives every
//! outcome. A readback proof is separate from native clean-state/retirement.
use crate::{
    EditJournalScope, ExplicitRecoveryApproval, ReconciliationIssue, ReconciliationOutcome,
    RecoveryRemoteVersion, RemoteEditBaseline,
    streamed_snapshot::SnapshotManifest,
    streamed_store::{
        SnapshotStore, StoreError, StreamedAttemptOutcome, StreamedAttemptState,
        StreamedDispatchLease, StreamedRecordKey, VerifiedPinnedSnapshot,
    },
};
use raiun_core::backend::{CloudError, ErrorKind};
use std::{io::Read, sync::Arc};

/// Full independent revision-conditioned GET evidence, not an upload response.
/// The reconciler validates every field against its authenticated snapshot.
pub struct StreamedRemoteDigest {
    pub version: RecoveryRemoteVersion,
    pub bytes: u64,
    pub sha256: [u8; 32],
}

/// Methods must route beneath the exact trusted account/Space/root and enforce
/// authorization during HTTP as well as on entry. There is deliberately no
/// test-friendly default authorization. The caller retains its provider lease.
pub trait StreamedRecoveryRemote: Send + Sync {
    fn server_origin(&self) -> &str;
    fn ensure_authorized(
        &self,
        scope: &EditJournalScope,
        generation: u64,
    ) -> Result<(), CloudError>;
    fn stat(
        &self,
        scope: &EditJournalScope,
        relative_path: &str,
    ) -> Result<RecoveryRemoteVersion, CloudError>;
    /// Conditional PUT of the original baseline, followed by full independent
    /// GET/hash. The owned immutable source/pin must survive that readback and
    /// be joined/released before success is returned; no unconditional writes.
    fn conditional_upload(
        &self,
        scope: &EditJournalScope,
        relative_path: &str,
        source: Box<dyn Read + Send>,
        baseline: &RemoteEditBaseline,
        content_len: u64,
        sha256: [u8; 32],
    ) -> Result<StreamedRemoteDigest, CloudError>;
    fn read_digest(
        &self,
        scope: &EditJournalScope,
        relative_path: &str,
        resource_id: &str,
        etag: &str,
        content_len: u64,
        sha256: [u8; 32],
    ) -> Result<StreamedRemoteDigest, CloudError>;
}

/// Crate-only admission. Only a prepared instance's fresh nonpersistable
/// receipt may select Fresh. Disk discovery must use ExplicitRecovered.
pub(crate) enum StreamedAdmission {
    Fresh,
    ExplicitRecovered(ExplicitRecoveryApproval),
}

/// Current exact local commitment plus complete remote verification. Neither
/// serializable nor cloneable, and not sufficient native acknowledgement
/// authority. The master body pin and record dispatch lock remain owned.
pub struct VerifiedStreamedReadback {
    key: StreamedRecordKey,
    snapshot: VerifiedPinnedSnapshot,
    version: RecoveryRemoteVersion,
    _lease: StreamedDispatchLease,
}
impl VerifiedStreamedReadback {
    pub fn key(&self) -> &StreamedRecordKey {
        &self.key
    }
    pub fn manifest(&self) -> &SnapshotManifest {
        self.snapshot.manifest()
    }
    pub fn remote_version(&self) -> &RecoveryRemoteVersion {
        &self.version
    }
    pub(crate) fn metadata_view(&self) -> crate::LocalEditMetadata {
        let binding = self.manifest().binding();
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let content_sha256 = self
            .manifest()
            .content_sha256()
            .iter()
            .flat_map(|byte| {
                [
                    HEX[(byte >> 4) as usize] as char,
                    HEX[(byte & 15) as usize] as char,
                ]
            })
            .collect();
        crate::LocalEditMetadata {
            record_id: binding.record_id.clone(),
            generation: binding.generation,
            scope: binding.scope.clone(),
            local_file: binding.local_file,
            relative_path: binding.relative_path.clone(),
            remote: binding.remote.clone(),
            content_len: binding.content_len,
            content_sha256,
            state: crate::LocalEditState::Dirty,
        }
    }
    pub(crate) fn verify_pin(&self) -> Result<(), StoreError> {
        self.snapshot.verify_pin()
    }

    /// Called only with an opaque completion minted AFTER guarded native
    /// in-sync success. Getters never lock its backing, avoiding recursion when
    /// the caller already holds this proof's backing mutex.
    pub(crate) fn acknowledge_native(
        &mut self,
        completion: &crate::CompletedLocalEdit,
    ) -> Result<(), StoreError> {
        if completion.streamed_key() != Some(&self.key)
            || completion.metadata() != &self.metadata_view()
        {
            return Err(StoreError::Invalid);
        }
        self.snapshot.verify_pin()?;
        self._lease.acknowledge_native(completion)
    }
}
impl std::fmt::Debug for VerifiedStreamedReadback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedStreamedReadback([BOUND])")
    }
}
pub struct StreamedReconciliationResult {
    pub outcome: ReconciliationOutcome,
    pub verified: Option<VerifiedStreamedReadback>,
}

/// Explicit recovery never reconstructs a fresh initial-dispatch receipt.
pub fn reconcile_recovered_streamed_edit(
    store: &Arc<SnapshotStore>,
    key: &StreamedRecordKey,
    expected_scope: &EditJournalScope,
    remote: &dyn StreamedRecoveryRemote,
    approval: ExplicitRecoveryApproval,
    cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
) -> Result<StreamedReconciliationResult, StoreError> {
    reconcile_streamed_edit(
        store,
        key,
        expected_scope,
        remote,
        StreamedAdmission::ExplicitRecovered(approval),
        cancelled,
    )
}

/// Reverify an already acknowledged successor without uploading or rewriting
/// its history. Historical acknowledgement alone grants no fresh authority.
#[cfg(windows)]
pub(crate) fn verify_acknowledged_streamed_edit(
    store: &Arc<SnapshotStore>,
    key: &StreamedRecordKey,
    remote: &dyn StreamedRecoveryRemote,
    cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
) -> Result<VerifiedStreamedReadback, StoreError> {
    let lease = store.acquire_dispatch(key)?;
    if !matches!(
        lease.current_state()?,
        StreamedAttemptState::LocallyAcknowledged { .. }
    ) {
        return Err(StoreError::Invalid);
    }
    let snapshot = store.open_verified_key(key, &mut || cancelled())?;
    let manifest = snapshot.manifest();
    let baseline = manifest
        .binding()
        .remote
        .as_ref()
        .filter(|baseline| strong_etag(&baseline.etag))
        .ok_or(StoreError::Invalid)?;
    if !authorized(remote, key, &cancelled) {
        return Err(StoreError::Invalid);
    }
    let current = remote
        .stat(key.scope(), &manifest.binding().relative_path)
        .map_err(|_| StoreError::Invalid)?;
    if version_issue(&current, &baseline.resource_id).is_some() {
        return Err(StoreError::Invalid);
    }
    let (outcome, version) = readback(remote, key, manifest, baseline, &current, &cancelled, 0);
    if !matches!(outcome, ReconciliationOutcome::VerifiedApplied { .. })
        || !authorized(remote, key, &cancelled)
    {
        return Err(StoreError::Invalid);
    }
    snapshot.verify_pin()?;
    Ok(VerifiedStreamedReadback {
        key: key.clone(),
        snapshot,
        version: version.ok_or(StoreError::Invalid)?,
        _lease: lease,
    })
}

pub(crate) fn reconcile_streamed_edit(
    store: &Arc<SnapshotStore>,
    key: &StreamedRecordKey,
    expected_scope: &EditJournalScope,
    remote: &dyn StreamedRecoveryRemote,
    admission: StreamedAdmission,
    cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
) -> Result<StreamedReconciliationResult, StoreError> {
    if key.scope() != expected_scope || key.generation() == 0 {
        return Err(StoreError::Invalid);
    }
    let mut lease = store.acquire_dispatch(key)?;
    let prior = lease.current_state()?;
    if matches!(
        prior,
        StreamedAttemptState::LocallyAcknowledged { .. } | StreamedAttemptState::Superseded { .. }
    ) || (matches!(admission, StreamedAdmission::Fresh)
        && prior != StreamedAttemptState::NotAttempted)
    {
        return Err(StoreError::Invalid);
    }
    // Authenticate complete body BEFORE the first remote request. Keep this
    // master pin across all attempts/readbacks and into a successful proof.
    let snapshot = store.open_verified_key(key, &mut || cancelled())?;
    let manifest = snapshot.manifest();
    if manifest.binding().scope != *expected_scope
        || manifest.binding().generation != key.generation()
        || manifest.binding().record_id != key.record_id()
    {
        return Err(StoreError::Invalid);
    }
    let mut attempts = 0u8;
    let mut attempt_id = prior.attempt_id();
    let (outcome, version) = run(
        store,
        key,
        manifest,
        remote,
        &cancelled,
        &mut lease,
        prior,
        &mut attempts,
        &mut attempt_id,
    )?;
    let event = match outcome {
        ReconciliationOutcome::VerifiedApplied { .. } => StreamedAttemptOutcome::VerifiedApplied,
        ReconciliationOutcome::Conflict(_) => StreamedAttemptOutcome::Conflict,
        ReconciliationOutcome::Ambiguous => StreamedAttemptOutcome::Ambiguous,
        ReconciliationOutcome::Deferred => StreamedAttemptOutcome::Deferred,
    };
    // A failed current re-verification cannot erase historical applied
    // evidence. It returns attention/no proof while keeping that receipt.
    if !matches!(prior, StreamedAttemptState::VerifiedApplied { .. })
        || matches!(outcome, ReconciliationOutcome::VerifiedApplied { .. })
    {
        lease.finish_outcome(attempt_id, attempts, event)?;
    }
    let verified = if let Some(version) = version {
        if !authorized(remote, key, &cancelled) {
            return Ok(StreamedReconciliationResult {
                outcome: ReconciliationOutcome::Deferred,
                verified: None,
            });
        }
        snapshot.verify_pin()?;
        Some(VerifiedStreamedReadback {
            key: key.clone(),
            snapshot,
            version,
            _lease: lease,
        })
    } else {
        None
    };
    Ok(StreamedReconciliationResult { outcome, verified })
}

fn authorized(
    remote: &dyn StreamedRecoveryRemote,
    key: &StreamedRecordKey,
    cancelled: &Arc<dyn Fn() -> bool + Send + Sync>,
) -> bool {
    !cancelled()
        && remote.server_origin() == key.scope().server_origin
        && remote
            .ensure_authorized(key.scope(), key.generation())
            .is_ok()
        && !cancelled()
}
type Decision = (ReconciliationOutcome, Option<RecoveryRemoteVersion>);
fn decision(outcome: ReconciliationOutcome) -> Decision {
    (outcome, None)
}
fn conflict(issue: ReconciliationIssue) -> Decision {
    decision(ReconciliationOutcome::Conflict(issue))
}
fn version_issue(version: &RecoveryRemoteVersion, id: &str) -> Option<ReconciliationIssue> {
    if version.resource_id != id || !strong_etag(&version.etag) {
        Some(ReconciliationIssue::RemoteObjectChanged)
    } else if version.is_directory || version.encrypted || !version.writable {
        Some(ReconciliationIssue::RemoteNotWritable)
    } else {
        None
    }
}
fn strong_etag(etag: &str) -> bool {
    etag.len() >= 3
        && etag.len() <= 4096
        && etag.starts_with('"')
        && etag.ends_with('"')
        && !etag[1..etag.len() - 1]
            .bytes()
            .any(|b| b == b'"' || b < 0x21 || b == 0x7f)
}
fn same_base(version: &RecoveryRemoteVersion, baseline: &RemoteEditBaseline) -> bool {
    version.resource_id == baseline.resource_id
        && version.etag == baseline.etag
        && version.size == baseline.byte_len
}
fn check_digest(
    evidence: StreamedRemoteDigest,
    manifest: &SnapshotManifest,
    baseline: &RemoteEditBaseline,
    expected: Option<&RecoveryRemoteVersion>,
    attempts: u8,
) -> Decision {
    if let Some(issue) = version_issue(&evidence.version, &baseline.resource_id) {
        return conflict(issue);
    }
    if expected.is_some_and(|expected| expected != &evidence.version) {
        return conflict(ReconciliationIssue::ResponseInconsistent);
    }
    if evidence.version.size != evidence.bytes {
        return decision(ReconciliationOutcome::Ambiguous);
    }
    if evidence.bytes == manifest.binding().content_len
        && evidence.sha256 == *manifest.content_sha256()
    {
        return (
            ReconciliationOutcome::VerifiedApplied { attempts },
            Some(evidence.version),
        );
    }
    if same_base(&evidence.version, baseline) {
        decision(ReconciliationOutcome::Ambiguous)
    } else {
        conflict(ReconciliationIssue::ContentMismatch)
    }
}
fn readback(
    remote: &dyn StreamedRecoveryRemote,
    key: &StreamedRecordKey,
    manifest: &SnapshotManifest,
    baseline: &RemoteEditBaseline,
    current: &RecoveryRemoteVersion,
    cancelled: &Arc<dyn Fn() -> bool + Send + Sync>,
    attempts: u8,
) -> Decision {
    if !authorized(remote, key, cancelled) {
        return decision(ReconciliationOutcome::Deferred);
    }
    let result = remote.read_digest(
        key.scope(),
        &manifest.binding().relative_path,
        &baseline.resource_id,
        &current.etag,
        current.size,
        *manifest.content_sha256(),
    );
    if !authorized(remote, key, cancelled) {
        return decision(ReconciliationOutcome::Deferred);
    }
    match result {
        Ok(proof) => check_digest(proof, manifest, baseline, Some(current), attempts),
        Err(_) => decision(ReconciliationOutcome::Ambiguous),
    }
}
#[allow(clippy::too_many_arguments)]
fn run(
    store: &Arc<SnapshotStore>,
    key: &StreamedRecordKey,
    manifest: &SnapshotManifest,
    remote: &dyn StreamedRecoveryRemote,
    cancelled: &Arc<dyn Fn() -> bool + Send + Sync>,
    lease: &mut StreamedDispatchLease,
    prior: StreamedAttemptState,
    attempts: &mut u8,
    attempt_id: &mut u64,
) -> Result<Decision, StoreError> {
    let Some(baseline) = manifest
        .binding()
        .remote
        .as_ref()
        .filter(|b| !b.resource_id.is_empty() && strong_etag(&b.etag))
    else {
        return Ok(conflict(ReconciliationIssue::MissingStrongBaseline));
    };
    if !authorized(remote, key, cancelled) {
        return Ok(decision(ReconciliationOutcome::Deferred));
    }
    let path = &manifest.binding().relative_path;
    let current = match remote.stat(key.scope(), path) {
        Ok(v) => v,
        Err(error) if error.kind == ErrorKind::NotFound => {
            return Ok(conflict(ReconciliationIssue::RemoteObjectMissing));
        }
        Err(_) => return Ok(decision(ReconciliationOutcome::Deferred)),
    };
    if !authorized(remote, key, cancelled) {
        return Ok(decision(ReconciliationOutcome::Deferred));
    }
    if let Some(issue) = version_issue(&current, &baseline.resource_id) {
        return Ok(conflict(issue));
    }
    if matches!(prior, StreamedAttemptState::VerifiedApplied { .. })
        || !same_base(&current, baseline)
    {
        return Ok(readback(
            remote, key, manifest, baseline, &current, cancelled, *attempts,
        ));
    }
    while *attempts < 2 {
        if !authorized(remote, key, cancelled) {
            return Ok(decision(ReconciliationOutcome::Deferred));
        }
        // Reopen only the exact committed key while the master immutable pin
        // remains held. Body/manifest checks cannot be skipped by a retry.
        let source = store
            .open_verified_key(key, &mut || cancelled())?
            .into_reader(Arc::clone(cancelled))?;
        if !authorized(remote, key, cancelled) {
            return Ok(decision(ReconciliationOutcome::Deferred));
        }
        *attempt_id = lease.begin_attempt()?;
        *attempts += 1;
        // From this point an early error leaves durable uncertain evidence.
        if !authorized(remote, key, cancelled) {
            return Ok(decision(ReconciliationOutcome::Deferred));
        }
        let uploaded = remote.conditional_upload(
            key.scope(),
            path,
            Box::new(source),
            baseline,
            manifest.binding().content_len,
            *manifest.content_sha256(),
        );
        if !authorized(remote, key, cancelled) {
            return Ok(decision(ReconciliationOutcome::Deferred));
        }
        match uploaded {
            Ok(proof) => return Ok(check_digest(proof, manifest, baseline, None, *attempts)),
            Err(error) => {
                let current = match remote.stat(key.scope(), path) {
                    Ok(v) => v,
                    Err(_) => return Ok(decision(ReconciliationOutcome::Ambiguous)),
                };
                if !authorized(remote, key, cancelled) {
                    return Ok(decision(ReconciliationOutcome::Deferred));
                }
                if let Some(issue) = version_issue(&current, &baseline.resource_id) {
                    return Ok(conflict(issue));
                }
                if same_base(&current, baseline) {
                    if matches!(error.kind, ErrorKind::Offline | ErrorKind::Io) && *attempts < 2 {
                        continue;
                    }
                    return Ok(decision(ReconciliationOutcome::Deferred));
                }
                return Ok(readback(
                    remote, key, manifest, baseline, &current, cancelled, *attempts,
                ));
            }
        }
    }
    Ok(decision(ReconciliationOutcome::Deferred))
}

#[path = "streamed_reconcile_opencloud.rs"]
mod opencloud;
pub use opencloud::OpenCloudStreamedRecoveryRemote;
#[cfg(all(test, unix))]
pub(crate) mod tests {
    include!("streamed_reconcile_tests.rs");

    pub(crate) fn bridge_fixture() -> (
        tempfile::TempDir,
        Arc<SnapshotStore>,
        StreamedRecordKey,
        VerifiedStreamedReadback,
    ) {
        let (directory, store) = synthetic_test_store(policy());
        let key = capture(&store, 3, 3);
        let remote = Remote::new(&store, &key, &[Behavior::Apply]);
        let proof = recovered(&store, &key, &remote).unwrap().verified.unwrap();
        (directory, store, key, proof)
    }

    #[test]
    fn bridged_proof_completion_retains_pin_and_lock_and_requires_exact_native_token() {
        let (_directory, store, key, proof) = bridge_fixture();
        let bridged = crate::VerifiedEditReadback::from_streamed(proof).unwrap();
        assert!(bridged.is_streamed());
        let weak = Arc::downgrade(bridged.streamed_backing().unwrap());
        let completion =
            crate::CompletedLocalEdit::from_verified_native_completion(&bridged).unwrap();
        drop(bridged);
        assert!(matches!(
            store.acquire_dispatch(&key),
            Err(StoreError::Busy)
        ));
        let backing = weak.upgrade().unwrap();
        let (_other_directory, _other_store, _other_key, other_proof) = bridge_fixture();
        let other_bridged = crate::VerifiedEditReadback::from_streamed(other_proof).unwrap();
        let other_completion =
            crate::CompletedLocalEdit::from_verified_native_completion(&other_bridged).unwrap();
        assert_eq!(
            backing
                .lock()
                .unwrap()
                .acknowledge_native(&other_completion),
            Err(StoreError::Invalid)
        );
        backing
            .lock()
            .unwrap()
            .acknowledge_native(&completion)
            .unwrap();
        assert!(matches!(
            store.discover_records().unwrap()[0].state,
            StreamedAttemptState::LocallyAcknowledged { .. }
        ));
        drop(backing);
        assert!(weak.upgrade().is_some());
        drop(completion);
        assert!(weak.upgrade().is_none());
        assert!(store.acquire_dispatch(&key).is_ok());
        // This invokes the opaque native constructor synthetically. It is NOT
        // execution/acceptance of the Windows in-sync guard or Cloud Files API.
    }
}
