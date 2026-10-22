//! Bounded reconciliation for encrypted Cloud Files edit snapshots.
//!
//! This module deliberately does not mutate or acknowledge the durable edit
//! journal. It verifies the exact captured account/root/object validator,
//! makes conditional writes through a narrow adapter, and verifies ambiguous
//! outcomes with a bounded readback. Every outcome leaves the original
//! recovery record available for review.

use sha2::{Digest, Sha256};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

use crate::{
    EditJournal, EditJournalScope, ExplicitRecoveryApproval, JournalError, LocalEditRecord,
    RecoveryAttemptOutcome, RecoveryAttemptState,
};
use raiun_core::backend::{CloudBackend, CloudError, ErrorKind, WriteCondition};
use raiun_opencloud::{OpenCloudClient, RangeReadContext};

/// Maximum recovered body size accepted by this reconciliation path.
pub const MAX_RECOVERY_UPLOAD_BYTES: usize = 16 * 1024 * 1024;
/// One initial attempt and at most one retry after a confirmed unchanged base.
pub const MAX_RECOVERY_UPLOAD_ATTEMPTS: u8 = 2;

/// Remote object metadata returned by an adapter after it has routed the
/// request through the exact scope/root/path arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryRemoteVersion {
    pub resource_id: String,
    pub etag: String,
    pub size: u64,
    pub is_directory: bool,
    pub encrypted: bool,
    pub writable: bool,
}

/// Content returned by a bounded remote readback. The buffer is zeroized when
/// dropped and must not be logged or serialized.
pub struct RecoveryRemoteBody {
    pub version: RecoveryRemoteVersion,
    content: Zeroizing<Vec<u8>>,
}

impl RecoveryRemoteBody {
    pub fn new(version: RecoveryRemoteVersion, content: Vec<u8>) -> Self {
        Self::from_zeroizing(version, Zeroizing::new(content))
    }

    pub fn from_zeroizing(version: RecoveryRemoteVersion, content: Zeroizing<Vec<u8>>) -> Self {
        Self { version, content }
    }

    pub fn content(&self) -> &[u8] {
        self.content.as_slice()
    }
}

/// Narrow adapter for reconciling one protected edit against its exact remote
/// object. Implementations must resolve `relative_path` beneath the supplied
/// root resource in `scope.space_id`, reject any scope mismatch, and bound
/// their network operations. `readback` must return the body for that exact
/// target, optionally conditioned on `expected_etag`.
pub trait RecoveryRemote: Send + Sync {
    fn server_origin(&self) -> Option<&str>;

    /// Verify the caller's serialized active-session/root generation. The
    /// default is suitable only for test remotes; production adapters should
    /// check their provider manager's revocation generation here and in the
    /// conditional-upload method itself.
    fn ensure_authorized(&self, _scope: &EditJournalScope) -> Result<(), CloudError> {
        Ok(())
    }

    fn stat(
        &self,
        scope: &EditJournalScope,
        relative_path: &str,
    ) -> Result<RecoveryRemoteVersion, CloudError>;

    fn conditional_upload(
        &self,
        scope: &EditJournalScope,
        relative_path: &str,
        content: &[u8],
        expected_resource_id: &str,
        condition: WriteCondition,
        expected_size: u64,
    ) -> Result<RecoveryRemoteVersion, CloudError>;

    fn readback(
        &self,
        scope: &EditJournalScope,
        relative_path: &str,
        expected_resource_id: &str,
        expected_etag: Option<&str>,
        max_bytes: usize,
    ) -> Result<RecoveryRemoteBody, CloudError>;
}

/// Production adapter for one exact Cloud Files edit scope. It is intentionally
/// constructed from a trusted remote-root path and captured token generation;
/// recovery records and callback data cannot select a server, Space, or URL.
/// The caller must retain its profile/root revocation lease for the adapter's
/// full dispatch lifetime. Each OpenCloud request independently enforces the
/// captured bearer generation and same-origin/no-redirect policy.
pub struct OpenCloudRecoveryRemote {
    client: Arc<OpenCloudClient>,
    scope: EditJournalScope,
    remote_root_path: String,
    token_generation: u64,
    server_origin: String,
    dispatch_deadline: Option<Instant>,
}

impl OpenCloudRecoveryRemote {
    pub fn new(
        client: Arc<OpenCloudClient>,
        scope: EditJournalScope,
        remote_root_path: String,
        token_generation: u64,
    ) -> Result<Self, CloudError> {
        let origin = client.server_origin().ok_or_else(|| {
            CloudError::new(ErrorKind::Unauthorized, "provider scope is unavailable")
        })?;
        if origin != scope.server_origin
            || client.token_generation() != token_generation
            || token_generation == 0
            || !valid_remote_root_path(&remote_root_path)
        {
            return Err(CloudError::new(
                ErrorKind::Unauthorized,
                "recovery provider scope or generation is invalid",
            ));
        }
        Ok(Self {
            client,
            scope,
            remote_root_path,
            token_generation,
            server_origin: origin,
            dispatch_deadline: None,
        })
    }

    pub(crate) fn with_dispatch_deadline(mut self, deadline: Instant) -> Self {
        self.dispatch_deadline = Some(deadline);
        self
    }

    fn context(&self) -> Result<RangeReadContext, CloudError> {
        if self.client.token_generation() != self.token_generation {
            return Err(CloudError::new(
                ErrorKind::Unauthorized,
                "authenticated provider generation changed",
            ));
        }
        Ok(RangeReadContext {
            deadline: self
                .dispatch_deadline
                .unwrap_or_else(|| Instant::now() + Duration::from_secs(5 * 60)),
            token_generation: self.token_generation,
        })
    }

    fn check_scope(&self, scope: &EditJournalScope) -> Result<(), CloudError> {
        if scope != &self.scope {
            return Err(CloudError::new(
                ErrorKind::Unauthorized,
                "recovery record belongs to another provider scope",
            ));
        }
        if self.client.token_generation() != self.token_generation {
            return Err(CloudError::new(
                ErrorKind::Unauthorized,
                "authenticated provider generation changed",
            ));
        }
        Ok(())
    }
}

impl RecoveryRemote for OpenCloudRecoveryRemote {
    fn server_origin(&self) -> Option<&str> {
        Some(&self.server_origin)
    }

    fn ensure_authorized(&self, scope: &EditJournalScope) -> Result<(), CloudError> {
        self.check_scope(scope)
    }

    fn stat(
        &self,
        scope: &EditJournalScope,
        relative_path: &str,
    ) -> Result<RecoveryRemoteVersion, CloudError> {
        self.check_scope(scope)?;
        let entry = self.client.recovery_stat_with_context(
            &scope.space_id,
            &self.remote_root_path,
            &scope.root_resource_id,
            relative_path,
            self.context()?,
        )?;
        Ok(recovery_version(entry))
    }

    fn conditional_upload(
        &self,
        scope: &EditJournalScope,
        relative_path: &str,
        content: &[u8],
        expected_resource_id: &str,
        condition: WriteCondition,
        expected_size: u64,
    ) -> Result<RecoveryRemoteVersion, CloudError> {
        self.check_scope(scope)?;
        let etag = match condition {
            WriteCondition::Match(etag) => etag,
            WriteCondition::Absent => {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "recovery upload requires a captured conditional validator",
                ));
            }
        };
        let entry = self.client.recovery_upload_bytes_with_context(
            &scope.space_id,
            &self.remote_root_path,
            &scope.root_resource_id,
            relative_path,
            expected_resource_id,
            &etag,
            expected_size,
            content,
            self.context()?,
        )?;
        Ok(recovery_version(entry))
    }

    fn readback(
        &self,
        scope: &EditJournalScope,
        relative_path: &str,
        expected_resource_id: &str,
        expected_etag: Option<&str>,
        max_bytes: usize,
    ) -> Result<RecoveryRemoteBody, CloudError> {
        self.check_scope(scope)?;
        let etag = expected_etag.ok_or_else(|| {
            CloudError::new(
                ErrorKind::Conflict,
                "recovery readback requires an exact revision",
            )
        })?;
        let (entry, bytes) = self.client.recovery_read_bytes_with_context(
            &scope.space_id,
            &self.remote_root_path,
            &scope.root_resource_id,
            relative_path,
            expected_resource_id,
            etag,
            max_bytes,
            self.context()?,
        )?;
        Ok(RecoveryRemoteBody::from_zeroizing(
            recovery_version(entry),
            bytes,
        ))
    }
}

fn recovery_version(entry: raiun_core::backend::RemoteEntry) -> RecoveryRemoteVersion {
    RecoveryRemoteVersion {
        resource_id: entry.id,
        etag: entry.etag,
        size: entry.size,
        is_directory: entry.directory,
        encrypted: entry.encrypted,
        writable: entry.writable,
    }
}

fn valid_remote_root_path(path: &str) -> bool {
    !path.is_empty()
        && path.starts_with('/')
        && path.len() <= 32 * 1024
        && !path.contains('\\')
        && !path.contains('?')
        && !path.contains('#')
        && !path.chars().any(char::is_control)
        && !path.split('/').any(|part| matches!(part, "." | ".."))
}

/// Why a recovered edit was not verified as applied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconciliationIssue {
    InvalidRecord,
    ScopeMismatch,
    MissingStrongBaseline,
    RemoteObjectMissing,
    RemoteObjectChanged,
    RemoteNotWritable,
    ContentMismatch,
    ResponseInconsistent,
}

/// Fresh read-only proof that one exact protected edit matches its remote
/// object/version. Fields are private so an upload outcome alone cannot mint
/// acknowledgement authority. This value is not serializable or cloneable.
/// It is not sufficient acknowledgement authority by itself: the current
/// prepared backend/lease and exact journal record must also match. It does not
/// acknowledge a local placeholder or retire a recovery record.
pub struct VerifiedEditReadback {
    metadata: crate::LocalEditMetadata,
    version: RecoveryRemoteVersion,
}

impl VerifiedEditReadback {
    pub fn metadata(&self) -> &crate::LocalEditMetadata {
        &self.metadata
    }

    pub fn remote_version(&self) -> &RecoveryRemoteVersion {
        &self.version
    }
}

impl std::fmt::Debug for VerifiedEditReadback {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VerifiedEditReadback([BOUND])")
    }
}

/// Verify the current remote version without uploading or changing the journal.
/// The caller must retain the active account/root lease through verification
/// and subsequent local acknowledgement. Native acknowledgement must separately
/// reopen the captured local file and prove its identity and content unchanged.
pub fn verify_edit_readback(
    record: &LocalEditRecord,
    expected_scope: &EditJournalScope,
    remote: &dyn RecoveryRemote,
) -> Result<VerifiedEditReadback, ReconciliationOutcome> {
    if !valid_record_for_scope(record, expected_scope)
        || record.metadata.local_file.volume_serial != expected_scope.root_volume_serial
        || record.metadata.local_file.file_index == 0
    {
        return Err(ReconciliationOutcome::Conflict(
            ReconciliationIssue::InvalidRecord,
        ));
    }
    if remote.server_origin() != Some(expected_scope.server_origin.as_str()) {
        return Err(ReconciliationOutcome::Conflict(
            ReconciliationIssue::ScopeMismatch,
        ));
    }
    if remote.ensure_authorized(expected_scope).is_err() {
        return Err(ReconciliationOutcome::Deferred);
    }
    let baseline = record
        .metadata
        .remote
        .as_ref()
        .filter(|baseline| !baseline.resource_id.is_empty() && valid_strong_etag(&baseline.etag))
        .ok_or(ReconciliationOutcome::Conflict(
            ReconciliationIssue::MissingStrongBaseline,
        ))?;
    let path = record.metadata.relative_path.as_str();
    let before = remote.stat(expected_scope, path).map_err(|error| {
        if error.kind == ErrorKind::NotFound {
            ReconciliationOutcome::Conflict(ReconciliationIssue::RemoteObjectMissing)
        } else {
            ReconciliationOutcome::Deferred
        }
    })?;
    match validate_version(&before, &baseline.resource_id) {
        VersionCheck::WrongObject => {
            return Err(ReconciliationOutcome::Conflict(
                ReconciliationIssue::RemoteObjectChanged,
            ));
        }
        VersionCheck::NotWritable => {
            return Err(ReconciliationOutcome::Conflict(
                ReconciliationIssue::RemoteNotWritable,
            ));
        }
        VersionCheck::Valid => {}
    }
    if before.size != record.metadata.content_len {
        return Err(ReconciliationOutcome::Conflict(
            ReconciliationIssue::ContentMismatch,
        ));
    }
    let body = remote
        .readback(
            expected_scope,
            path,
            &baseline.resource_id,
            Some(&before.etag),
            MAX_RECOVERY_UPLOAD_BYTES,
        )
        .map_err(|_| ReconciliationOutcome::Ambiguous)?;
    if body.version != before || body.content().len() as u64 != before.size {
        return Err(ReconciliationOutcome::Conflict(
            ReconciliationIssue::ResponseInconsistent,
        ));
    }
    if body.content().len() > MAX_RECOVERY_UPLOAD_BYTES
        || digest_hex(body.content()) != record.metadata.content_sha256
    {
        return Err(ReconciliationOutcome::Conflict(
            ReconciliationIssue::ContentMismatch,
        ));
    }
    if remote.ensure_authorized(expected_scope).is_err() {
        return Err(ReconciliationOutcome::Deferred);
    }
    Ok(VerifiedEditReadback {
        metadata: record.metadata.clone(),
        version: body.version.clone(),
    })
}

/// Safe result of one bounded reconciliation invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconciliationOutcome {
    /// Exact remote readback matched the protected local body. The journal
    /// record remains retained until a separate reviewed retirement action.
    VerifiedApplied { attempts: u8 },
    /// The exact target no longer matches the captured resource/validator.
    Conflict(ReconciliationIssue),
    /// No safe conclusion was possible; preserve the snapshot for later review.
    Ambiguous,
    /// No mutation was attempted because the exact remote target could not be
    /// read, or bounded retries did not resolve the transport failure.
    Deferred,
}

/// Reconcile one recovered immutable record. This function never deletes,
/// rewrites, or acknowledges `record`; callers must preserve it for every
/// outcome and may only retire it through a separate explicit reviewed path.
///
/// A retry is permitted only when the first upload failed with a transient
/// transport error and a fresh stat proves the exact resource, strong ETag,
/// and size remain byte-for-byte at the captured baseline. All accepted writes
/// use `If-Match` with that captured ETag. Ambiguous responses are resolved by
/// comparing a bounded exact-target readback to the protected body.
#[cfg(test)]
fn reconcile_recovered_edit(
    record: &LocalEditRecord,
    expected_scope: &EditJournalScope,
    remote: &dyn RecoveryRemote,
) -> ReconciliationOutcome {
    reconcile_recovered_edit_with_hook(record, expected_scope, remote, || true)
}

/// Explicit, durable recovery dispatch for one immutable journal record.
/// Callers must invoke this only from a user-reviewed action while holding the
/// active profile/root lease. The journal writes and syncs an Attempting event
/// immediately before every conditional PUT, then appends a terminal receipt.
/// If receipt persistence fails, the durable Attempting state remains
/// uncertain. The snapshot body is never deleted or replaced.
pub fn dispatch_recovered_edit(
    journal: &EditJournal,
    record_id: &str,
    generation: u64,
    expected_scope: &EditJournalScope,
    remote: &dyn RecoveryRemote,
    approval: ExplicitRecoveryApproval,
) -> Result<ReconciliationOutcome, JournalError> {
    dispatch_edit(
        journal,
        record_id,
        generation,
        expected_scope,
        remote,
        Some(approval),
    )
}

/// Dispatch a never-attempted snapshot while the caller holds its current
/// account/root generation lease. This does not enable provider activation or
/// schedule any background work. Every previous terminal or uncertain state
/// requires explicit recovery instead. Only this invocation may perform the
/// bounded transient retry after reserving its own first attempt.
///
/// The immutable snapshot remains retained on every outcome, including a
/// failure to persist the terminal receipt.
pub(crate) fn dispatch_initial_edit(
    journal: &EditJournal,
    record_id: &str,
    generation: u64,
    expected_scope: &EditJournalScope,
    remote: &dyn RecoveryRemote,
) -> Result<ReconciliationOutcome, JournalError> {
    dispatch_edit(journal, record_id, generation, expected_scope, remote, None)
}

fn dispatch_edit(
    journal: &EditJournal,
    record_id: &str,
    generation: u64,
    expected_scope: &EditJournalScope,
    remote: &dyn RecoveryRemote,
    approval: Option<ExplicitRecoveryApproval>,
) -> Result<ReconciliationOutcome, JournalError> {
    let lease = crate::edit_journal::trace_journal_stage(
        "dispatch_acquire_lease",
        journal.acquire_dispatch_lease(record_id),
    )?;
    let snapshot = crate::edit_journal::trace_journal_stage(
        "dispatch_initial_recover",
        journal.recover_all(),
    )?;
    let record = snapshot
        .records
        .into_iter()
        .find(|record| {
            record.metadata.record_id == record_id
                && record.metadata.generation == generation
                && record.metadata.scope == *expected_scope
        })
        .ok_or(JournalError::ScopeMismatch)?;
    let prior_state = snapshot
        .recovery_states
        .get(record_id)
        .copied()
        .unwrap_or(RecoveryAttemptState::NotAttempted);
    if approval.is_none() && prior_state != RecoveryAttemptState::NotAttempted {
        return Err(JournalError::InvalidState);
    }
    if matches!(prior_state, RecoveryAttemptState::VerifiedApplied { .. }) {
        return Ok(ReconciliationOutcome::VerifiedApplied { attempts: 0 });
    }
    let mut active_attempt_id = recovery_attempt_id(prior_state);
    let mut attempt_count = 0u8;
    let mut journal_error = None;
    let outcome = reconcile_recovered_edit_with_hook(&record, expected_scope, remote, || {
        let reservation = match approval {
            Some(approval) => journal.begin_attempt(&lease, record_id, generation, approval),
            None => journal.begin_admitted_attempt(
                &lease,
                record_id,
                generation,
                crate::edit_journal::AttemptAdmission::Initial {
                    previous_attempt: (attempt_count > 0).then_some(active_attempt_id),
                },
            ),
        };
        match reservation {
            Ok(attempt_id) => {
                active_attempt_id = attempt_id;
                attempt_count = attempt_count.saturating_add(1);
                true
            }
            Err(error) => {
                journal_error = Some(error);
                false
            }
        }
    });
    if let Some(error) = journal_error {
        return Err(error);
    }
    journal.record_outcome(
        &lease,
        record_id,
        generation,
        active_attempt_id,
        attempt_count,
        match outcome {
            ReconciliationOutcome::VerifiedApplied { .. } => {
                RecoveryAttemptOutcome::VerifiedApplied
            }
            ReconciliationOutcome::Conflict(_) => RecoveryAttemptOutcome::Conflict,
            ReconciliationOutcome::Ambiguous => RecoveryAttemptOutcome::Ambiguous,
            ReconciliationOutcome::Deferred => RecoveryAttemptOutcome::Deferred,
        },
    )?;
    Ok(outcome)
}

fn recovery_attempt_id(state: RecoveryAttemptState) -> u64 {
    match state {
        RecoveryAttemptState::NotAttempted => 0,
        RecoveryAttemptState::Uncertain { attempt_id }
        | RecoveryAttemptState::VerifiedApplied { attempt_id, .. }
        | RecoveryAttemptState::Conflict { attempt_id, .. }
        | RecoveryAttemptState::Ambiguous { attempt_id, .. }
        | RecoveryAttemptState::Deferred { attempt_id, .. } => attempt_id,
    }
}

fn reconcile_recovered_edit_with_hook(
    record: &LocalEditRecord,
    expected_scope: &EditJournalScope,
    remote: &dyn RecoveryRemote,
    mut before_upload: impl FnMut() -> bool,
) -> ReconciliationOutcome {
    if !valid_record_for_scope(record, expected_scope) {
        return ReconciliationOutcome::Conflict(ReconciliationIssue::InvalidRecord);
    }
    if remote.server_origin() != Some(expected_scope.server_origin.as_str()) {
        return ReconciliationOutcome::Conflict(ReconciliationIssue::ScopeMismatch);
    }
    if remote.ensure_authorized(expected_scope).is_err() {
        return ReconciliationOutcome::Deferred;
    }
    let Some(baseline) = record.metadata.remote.as_ref() else {
        return ReconciliationOutcome::Conflict(ReconciliationIssue::MissingStrongBaseline);
    };
    if !valid_strong_etag(&baseline.etag) || baseline.resource_id.is_empty() {
        return ReconciliationOutcome::Conflict(ReconciliationIssue::MissingStrongBaseline);
    }

    let path = record.metadata.relative_path.as_str();
    let initial = match remote.stat(expected_scope, path) {
        Ok(version) => version,
        Err(error) if error.kind == ErrorKind::NotFound => {
            return ReconciliationOutcome::Conflict(ReconciliationIssue::RemoteObjectMissing);
        }
        Err(_) => return ReconciliationOutcome::Deferred,
    };
    match validate_version(&initial, baseline.resource_id.as_str()) {
        VersionCheck::Valid
            if initial.etag == baseline.etag && initial.size == baseline.byte_len => {}
        VersionCheck::WrongObject => {
            return ReconciliationOutcome::Conflict(ReconciliationIssue::RemoteObjectChanged);
        }
        VersionCheck::NotWritable => {
            return ReconciliationOutcome::Conflict(ReconciliationIssue::RemoteNotWritable);
        }
        VersionCheck::Valid => {
            // A previous invocation may have completed remotely but lost its
            // acknowledgement. Reconcile the changed validator before any
            // further write so repeated recovery remains idempotent.
            return verify_readback(
                remote,
                expected_scope,
                path,
                baseline.resource_id.as_str(),
                Some(initial.etag.as_str()),
                record,
                0,
            );
        }
    }

    for attempt in 1..=MAX_RECOVERY_UPLOAD_ATTEMPTS {
        if remote.ensure_authorized(expected_scope).is_err() {
            return ReconciliationOutcome::Deferred;
        }
        if !before_upload() {
            return ReconciliationOutcome::Deferred;
        }
        let upload = remote.conditional_upload(
            expected_scope,
            path,
            &record.content,
            &baseline.resource_id,
            WriteCondition::Match(baseline.etag.clone()),
            baseline.byte_len,
        );
        match upload {
            Ok(response) => {
                if !same_target(&response, baseline.resource_id.as_str())
                    || !valid_strong_etag(&response.etag)
                    || response.size != record.metadata.content_len
                {
                    return ReconciliationOutcome::Ambiguous;
                }
                return verify_readback(
                    remote,
                    expected_scope,
                    path,
                    baseline.resource_id.as_str(),
                    Some(response.etag.as_str()),
                    record,
                    attempt,
                );
            }
            Err(error) => {
                let current = match remote.stat(expected_scope, path) {
                    Ok(version) => version,
                    Err(_) => return ReconciliationOutcome::Ambiguous,
                };
                match validate_version(&current, baseline.resource_id.as_str()) {
                    VersionCheck::WrongObject => {
                        return ReconciliationOutcome::Conflict(
                            ReconciliationIssue::RemoteObjectChanged,
                        );
                    }
                    VersionCheck::NotWritable => {
                        return ReconciliationOutcome::Conflict(
                            ReconciliationIssue::RemoteNotWritable,
                        );
                    }
                    VersionCheck::Valid => {}
                }
                if current.etag == baseline.etag && current.size == baseline.byte_len {
                    if is_transient_transport(error.kind) && attempt < MAX_RECOVERY_UPLOAD_ATTEMPTS
                    {
                        continue;
                    }
                    return ReconciliationOutcome::Deferred;
                }
                return verify_readback(
                    remote,
                    expected_scope,
                    path,
                    baseline.resource_id.as_str(),
                    Some(current.etag.as_str()),
                    record,
                    attempt,
                );
            }
        }
    }
    ReconciliationOutcome::Deferred
}

fn verify_readback(
    remote: &dyn RecoveryRemote,
    scope: &EditJournalScope,
    path: &str,
    expected_resource_id: &str,
    expected_etag: Option<&str>,
    record: &LocalEditRecord,
    attempts: u8,
) -> ReconciliationOutcome {
    let body = match remote.readback(
        scope,
        path,
        expected_resource_id,
        expected_etag,
        MAX_RECOVERY_UPLOAD_BYTES,
    ) {
        Ok(body) => body,
        Err(_) => return ReconciliationOutcome::Ambiguous,
    };
    let version = &body.version;
    if !same_target(version, expected_resource_id) || !valid_strong_etag(&version.etag) {
        return ReconciliationOutcome::Conflict(ReconciliationIssue::ResponseInconsistent);
    }
    if version.is_directory || version.encrypted {
        return ReconciliationOutcome::Conflict(ReconciliationIssue::ResponseInconsistent);
    }
    if body.content().len() > MAX_RECOVERY_UPLOAD_BYTES
        || version.size != body.content().len() as u64
    {
        return ReconciliationOutcome::Ambiguous;
    }
    if version.size == record.metadata.content_len
        && digest_hex(body.content()) == record.metadata.content_sha256
    {
        return ReconciliationOutcome::VerifiedApplied { attempts };
    }
    let unchanged_baseline =
        record.metadata.remote.as_ref().is_some_and(|baseline| {
            version.etag == baseline.etag && version.size == baseline.byte_len
        });
    if unchanged_baseline {
        ReconciliationOutcome::Ambiguous
    } else {
        ReconciliationOutcome::Conflict(ReconciliationIssue::ContentMismatch)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VersionCheck {
    Valid,
    WrongObject,
    NotWritable,
}

fn validate_version(version: &RecoveryRemoteVersion, expected_resource_id: &str) -> VersionCheck {
    if !same_target(version, expected_resource_id) || !valid_strong_etag(&version.etag) {
        return VersionCheck::WrongObject;
    }
    if version.is_directory || version.encrypted || !version.writable {
        return VersionCheck::NotWritable;
    }
    VersionCheck::Valid
}

fn same_target(version: &RecoveryRemoteVersion, expected_resource_id: &str) -> bool {
    !expected_resource_id.is_empty() && version.resource_id == expected_resource_id
}

fn is_transient_transport(kind: ErrorKind) -> bool {
    matches!(kind, ErrorKind::Offline | ErrorKind::Io)
}

fn valid_record_for_scope(record: &LocalEditRecord, expected_scope: &EditJournalScope) -> bool {
    &record.metadata.scope == expected_scope
        && valid_scope(expected_scope)
        && record.metadata.generation != 0
        && valid_relative_path(&record.metadata.relative_path)
        && record.metadata.content_len == record.content.len() as u64
        && record.content.len() <= MAX_RECOVERY_UPLOAD_BYTES
        && record.metadata.content_sha256 == digest_hex(&record.content)
}

fn valid_scope(scope: &EditJournalScope) -> bool {
    [
        &scope.profile_id,
        &scope.server_origin,
        &scope.account_subject,
        &scope.space_id,
        &scope.root_resource_id,
    ]
    .into_iter()
    .all(|value| !value.is_empty() && value.len() <= 4096 && !value.chars().any(char::is_control))
        && scope.root_file_index != 0
}

fn valid_relative_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 32 * 1024
        && !path.starts_with('/')
        && !path.ends_with('/')
        && !path.contains('\\')
        && !path.chars().any(char::is_control)
        && !path
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
}

fn valid_strong_etag(etag: &str) -> bool {
    etag.len() >= 2
        && etag.len() <= 4096
        && etag.starts_with('"')
        && etag.ends_with('"')
        && etag != "\"\""
        && !etag[1..etag.len() - 1]
            .bytes()
            .any(|byte| byte == b'"' || byte < 0x21 || byte == 0x7f)
}

fn digest_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    Sha256::digest(bytes)
        .iter()
        .flat_map(|byte| {
            [
                HEX[(byte >> 4) as usize] as char,
                HEX[(byte & 0xf) as usize] as char,
            ]
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::fs;
    use std::sync::Mutex;

    use super::*;
    use crate::{
        EditRecordProtector, LocalEditMetadata, LocalEditState, LocalFileIdentity,
        RemoteEditBaseline,
    };

    const ETAG_BASE: &str = "\"base-v1\"";
    const ETAG_UPDATED: &str = "\"updated-v2\"";

    struct TestProtector;

    impl EditRecordProtector for TestProtector {
        fn seal(&self, associated_data: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, JournalError> {
            let mut bytes: Vec<u8> = plaintext.iter().map(|byte| byte ^ 0x6d).collect();
            let mut hash = Sha256::new();
            hash.update(associated_data);
            hash.update(&bytes);
            bytes.extend_from_slice(&hash.finalize());
            Ok(bytes)
        }

        fn open(&self, associated_data: &[u8], sealed: &[u8]) -> Result<Vec<u8>, JournalError> {
            if sealed.len() < 32 {
                return Err(JournalError::ProtectionFailed);
            }
            let (ciphertext, tag) = sealed.split_at(sealed.len() - 32);
            let mut hash = Sha256::new();
            hash.update(associated_data);
            hash.update(ciphertext);
            if hash.finalize().as_slice() != tag {
                return Err(JournalError::ProtectionFailed);
            }
            Ok(ciphertext.iter().map(|byte| byte ^ 0x6d).collect())
        }
    }

    fn private_tempdir() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        temp
    }

    #[derive(Clone)]
    enum UploadBehavior {
        ApplyAndSucceed,
        ApplyThenEncrypt,
        ApplyThenOffline,
        OfflineWithoutApply,
        RejectConflictUnchanged,
        RejectConflict,
    }

    struct FakeRemote {
        origin: String,
        version: Mutex<RecoveryRemoteVersion>,
        content: Mutex<Vec<u8>>,
        behaviors: Mutex<Vec<UploadBehavior>>,
        calls: Mutex<Vec<&'static str>>,
        fail_readback: bool,
        revoke_after_readback: bool,
        authorization_revoked: std::sync::atomic::AtomicBool,
        readback_etag_override: Option<String>,
    }

    impl FakeRemote {
        fn new(behaviors: Vec<UploadBehavior>, fail_readback: bool) -> Self {
            Self {
                origin: "https://cloud.example".into(),
                version: Mutex::new(RecoveryRemoteVersion {
                    resource_id: "remote-42".into(),
                    etag: ETAG_BASE.into(),
                    size: 4,
                    is_directory: false,
                    encrypted: false,
                    writable: true,
                }),
                content: Mutex::new(b"base".to_vec()),
                behaviors: Mutex::new(behaviors),
                calls: Mutex::new(Vec::new()),
                fail_readback,
                revoke_after_readback: false,
                authorization_revoked: std::sync::atomic::AtomicBool::new(false),
                readback_etag_override: None,
            }
        }

        fn apply(&self, content: &[u8]) {
            *self.content.lock().unwrap() = content.to_vec();
            let mut version = self.version.lock().unwrap();
            version.etag = ETAG_UPDATED.into();
            version.size = content.len() as u64;
        }

        fn calls(&self) -> Vec<&'static str> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl RecoveryRemote for FakeRemote {
        fn server_origin(&self) -> Option<&str> {
            Some(&self.origin)
        }

        fn ensure_authorized(&self, _scope: &EditJournalScope) -> Result<(), CloudError> {
            if self
                .authorization_revoked
                .load(std::sync::atomic::Ordering::Acquire)
            {
                Err(CloudError::new(
                    ErrorKind::Unauthorized,
                    "synthetic revocation",
                ))
            } else {
                Ok(())
            }
        }

        fn stat(
            &self,
            scope: &EditJournalScope,
            relative_path: &str,
        ) -> Result<RecoveryRemoteVersion, CloudError> {
            assert_eq!(scope.space_id, "personal-space");
            assert_eq!(scope.root_resource_id, "root-resource");
            assert_eq!(relative_path, "docs/notes.txt");
            self.calls.lock().unwrap().push("stat");
            Ok(self.version.lock().unwrap().clone())
        }

        fn conditional_upload(
            &self,
            scope: &EditJournalScope,
            relative_path: &str,
            content: &[u8],
            expected_resource_id: &str,
            condition: WriteCondition,
            expected_size: u64,
        ) -> Result<RecoveryRemoteVersion, CloudError> {
            assert_eq!(scope.space_id, "personal-space");
            assert_eq!(scope.root_resource_id, "root-resource");
            assert_eq!(relative_path, "docs/notes.txt");
            assert_eq!(expected_resource_id, "remote-42");
            assert_eq!(condition, WriteCondition::Match(ETAG_BASE.into()));
            assert_eq!(expected_size, 4);
            self.calls.lock().unwrap().push("upload");
            let behavior = {
                let mut behaviors = self.behaviors.lock().unwrap();
                if behaviors.is_empty() {
                    UploadBehavior::OfflineWithoutApply
                } else {
                    behaviors.remove(0)
                }
            };
            match behavior {
                UploadBehavior::ApplyAndSucceed => {
                    self.apply(content);
                    Ok(self.version.lock().unwrap().clone())
                }
                UploadBehavior::ApplyThenEncrypt => {
                    self.apply(content);
                    self.version.lock().unwrap().encrypted = true;
                    Ok(self.version.lock().unwrap().clone())
                }
                UploadBehavior::ApplyThenOffline => {
                    self.apply(content);
                    Err(CloudError::new(ErrorKind::Offline, "synthetic disconnect"))
                }
                UploadBehavior::OfflineWithoutApply => {
                    Err(CloudError::new(ErrorKind::Offline, "synthetic disconnect"))
                }
                UploadBehavior::RejectConflict => {
                    self.apply(b"other body");
                    Err(CloudError::new(ErrorKind::Conflict, "synthetic conflict"))
                }
                UploadBehavior::RejectConflictUnchanged => {
                    Err(CloudError::new(ErrorKind::Conflict, "synthetic conflict"))
                }
            }
        }

        fn readback(
            &self,
            scope: &EditJournalScope,
            relative_path: &str,
            expected_resource_id: &str,
            expected_etag: Option<&str>,
            max_bytes: usize,
        ) -> Result<RecoveryRemoteBody, CloudError> {
            assert_eq!(scope.space_id, "personal-space");
            assert_eq!(scope.root_resource_id, "root-resource");
            assert_eq!(relative_path, "docs/notes.txt");
            assert_eq!(expected_resource_id, "remote-42");
            self.calls.lock().unwrap().push("readback");
            if self.fail_readback {
                return Err(CloudError::new(ErrorKind::Offline, "readback unavailable"));
            }
            let version = self.version.lock().unwrap().clone();
            if expected_etag.is_some_and(|expected| expected != version.etag) {
                return Err(CloudError::new(ErrorKind::Conflict, "validator changed"));
            }
            let content = self.content.lock().unwrap().clone();
            if content.len() > max_bytes {
                return Err(CloudError::new(ErrorKind::InvalidResponse, "too large"));
            }
            if self.revoke_after_readback {
                self.authorization_revoked
                    .store(true, std::sync::atomic::Ordering::Release);
            }
            let mut version = version;
            if let Some(etag) = &self.readback_etag_override {
                version.etag = etag.clone();
            }
            Ok(RecoveryRemoteBody::new(version, content))
        }
    }

    fn test_scope() -> EditJournalScope {
        EditJournalScope {
            profile_id: "default".into(),
            server_origin: "https://cloud.example".into(),
            account_subject: "account-7".into(),
            space_id: "personal-space".into(),
            root_resource_id: "root-resource".into(),
            root_volume_serial: 17,
            root_file_index: 29,
        }
    }

    fn test_record(scope: &EditJournalScope) -> LocalEditRecord {
        let content = b"recovered body".to_vec();
        LocalEditRecord {
            metadata: LocalEditMetadata {
                record_id: "00112233445566778899aabbccddeeff".into(),
                generation: 3,
                scope: scope.clone(),
                local_file: crate::LocalFileIdentity {
                    volume_serial: scope.root_volume_serial,
                    file_index: 101,
                },
                relative_path: "docs/notes.txt".into(),
                remote: Some(RemoteEditBaseline {
                    resource_id: "remote-42".into(),
                    etag: ETAG_BASE.into(),
                    byte_len: 4,
                }),
                content_len: content.len() as u64,
                content_sha256: digest_hex(&content),
                state: LocalEditState::Uncertain,
            },
            content,
        }
    }

    #[test]
    fn readback_proof_binds_exact_record_and_current_remote_without_upload() {
        let scope = test_scope();
        let record = test_record(&scope);
        let remote = FakeRemote::new(Vec::new(), false);
        remote.apply(&record.content);
        let proof = verify_edit_readback(&record, &scope, &remote).unwrap();
        assert_eq!(proof.metadata(), &record.metadata);
        assert_eq!(proof.remote_version().etag, ETAG_UPDATED);
        assert_eq!(proof.remote_version().resource_id, "remote-42");
        assert_eq!(remote.calls(), ["stat", "readback"]);
        assert_eq!(format!("{proof:?}"), "VerifiedEditReadback([BOUND])");
    }

    #[test]
    fn readback_proof_rejects_other_scope_or_changed_local_snapshot() {
        let scope = test_scope();
        let mut record = test_record(&scope);
        let remote = FakeRemote::new(Vec::new(), false);
        let mut other = scope.clone();
        other.account_subject.push('x');
        assert_eq!(
            verify_edit_readback(&record, &other, &remote).unwrap_err(),
            ReconciliationOutcome::Conflict(ReconciliationIssue::InvalidRecord)
        );
        record.content[0] ^= 1;
        assert_eq!(
            verify_edit_readback(&record, &scope, &remote).unwrap_err(),
            ReconciliationOutcome::Conflict(ReconciliationIssue::InvalidRecord)
        );
        assert!(remote.calls().is_empty());
    }

    #[test]
    fn readback_proof_rejects_equal_length_remote_content_change() {
        let scope = test_scope();
        let record = test_record(&scope);
        let remote = FakeRemote::new(Vec::new(), false);
        remote.apply(&vec![b'x'; record.content.len()]);
        assert_eq!(
            verify_edit_readback(&record, &scope, &remote).unwrap_err(),
            ReconciliationOutcome::Conflict(ReconciliationIssue::ContentMismatch)
        );
        assert_eq!(remote.calls(), ["stat", "readback"]);
    }

    #[test]
    fn readback_proof_rejects_revocation_and_inconsistent_version() {
        let scope = test_scope();
        let record = test_record(&scope);
        let mut revoked = FakeRemote::new(Vec::new(), false);
        revoked.apply(&record.content);
        revoked.revoke_after_readback = true;
        assert_eq!(
            verify_edit_readback(&record, &scope, &revoked).unwrap_err(),
            ReconciliationOutcome::Deferred
        );
        let mut inconsistent = FakeRemote::new(Vec::new(), false);
        inconsistent.apply(&record.content);
        inconsistent.readback_etag_override = Some("\"different-version\"".into());
        assert_eq!(
            verify_edit_readback(&record, &scope, &inconsistent).unwrap_err(),
            ReconciliationOutcome::Conflict(ReconciliationIssue::ResponseInconsistent)
        );
    }

    #[test]
    fn conditional_upload_is_verified_by_exact_readback() {
        let scope = test_scope();
        let record = test_record(&scope);
        let remote = FakeRemote::new(vec![UploadBehavior::ApplyAndSucceed], false);
        assert_eq!(
            reconcile_recovered_edit(&record, &scope, &remote),
            ReconciliationOutcome::VerifiedApplied { attempts: 1 }
        );
        assert_eq!(remote.calls(), ["stat", "upload", "readback"]);
        assert_eq!(record.content, b"recovered body");
    }

    #[test]
    fn later_invocation_recognizes_a_previously_applied_snapshot() {
        let scope = test_scope();
        let record = test_record(&scope);
        let remote = FakeRemote::new(Vec::new(), false);
        remote.apply(&record.content);
        assert_eq!(
            reconcile_recovered_edit(&record, &scope, &remote),
            ReconciliationOutcome::VerifiedApplied { attempts: 0 }
        );
        assert_eq!(remote.calls(), ["stat", "readback"]);
    }

    #[test]
    fn ambiguous_upload_is_reconciled_without_duplicate_write() {
        let scope = test_scope();
        let record = test_record(&scope);
        let remote = FakeRemote::new(vec![UploadBehavior::ApplyThenOffline], false);
        assert_eq!(
            reconcile_recovered_edit(&record, &scope, &remote),
            ReconciliationOutcome::VerifiedApplied { attempts: 1 }
        );
        assert_eq!(remote.calls(), ["stat", "upload", "stat", "readback"]);
    }

    #[test]
    fn only_unchanged_baseline_after_transient_error_allows_one_retry() {
        let scope = test_scope();
        let record = test_record(&scope);
        let remote = FakeRemote::new(
            vec![
                UploadBehavior::OfflineWithoutApply,
                UploadBehavior::ApplyAndSucceed,
            ],
            false,
        );
        assert_eq!(
            reconcile_recovered_edit(&record, &scope, &remote),
            ReconciliationOutcome::VerifiedApplied { attempts: 2 }
        );
        assert_eq!(
            remote.calls(),
            ["stat", "upload", "stat", "upload", "readback"]
        );
    }

    fn append_test_edit(journal: &EditJournal, scope: &EditJournalScope) -> LocalEditMetadata {
        let record = test_record(scope);
        journal
            .append_edit(
                record.metadata.generation,
                LocalFileIdentity {
                    volume_serial: scope.root_volume_serial,
                    file_index: 101,
                },
                &record.metadata.relative_path,
                record.metadata.remote.clone(),
                &record.content,
            )
            .unwrap()
    }

    #[test]
    fn initial_dispatch_owns_bounded_retry_and_retains_verified_body() {
        let scope = test_scope();
        let temp = private_tempdir();
        let journal = EditJournal::open(temp.path(), scope.clone(), TestProtector).unwrap();
        let metadata = append_test_edit(&journal, &scope);
        let remote = FakeRemote::new(
            vec![
                UploadBehavior::OfflineWithoutApply,
                UploadBehavior::ApplyAndSucceed,
            ],
            false,
        );
        assert_eq!(
            dispatch_initial_edit(
                &journal,
                &metadata.record_id,
                metadata.generation,
                &scope,
                &remote
            )
            .unwrap(),
            ReconciliationOutcome::VerifiedApplied { attempts: 2 }
        );
        assert_eq!(
            remote.calls(),
            ["stat", "upload", "stat", "upload", "readback"]
        );
        drop(journal);
        let reopened = EditJournal::open(temp.path(), scope.clone(), TestProtector).unwrap();
        let snapshot = reopened.recover_all().unwrap();
        assert_eq!(snapshot.records[0].content, test_record(&scope).content);
        assert_eq!(
            snapshot.recovery_states[&metadata.record_id],
            RecoveryAttemptState::VerifiedApplied {
                attempt_id: 2,
                attempts: 2
            }
        );
        let before = remote.calls();
        assert!(matches!(
            dispatch_initial_edit(
                &reopened,
                &metadata.record_id,
                metadata.generation,
                &scope,
                &remote
            ),
            Err(JournalError::InvalidState)
        ));
        assert_eq!(remote.calls(), before);
    }

    #[test]
    fn initial_dispatch_rejects_every_recovered_attempt_state_before_remote_access() {
        for outcome in [
            None,
            Some(RecoveryAttemptOutcome::Deferred),
            Some(RecoveryAttemptOutcome::Conflict),
            Some(RecoveryAttemptOutcome::Ambiguous),
            Some(RecoveryAttemptOutcome::VerifiedApplied),
        ] {
            let scope = test_scope();
            let temp = private_tempdir();
            let journal = EditJournal::open(temp.path(), scope.clone(), TestProtector).unwrap();
            let metadata = append_test_edit(&journal, &scope);
            let lease = journal.acquire_dispatch_lease(&metadata.record_id).unwrap();
            let attempt = journal
                .begin_admitted_attempt(
                    &lease,
                    &metadata.record_id,
                    metadata.generation,
                    crate::edit_journal::AttemptAdmission::Initial {
                        previous_attempt: None,
                    },
                )
                .unwrap();
            // Reservation is durable before any remote call. Another initial
            // reservation cannot adopt this uncertain attempt, even in-process.
            assert_eq!(
                journal.recover_all().unwrap().recovery_states[&metadata.record_id],
                RecoveryAttemptState::Uncertain { attempt_id: 1 }
            );
            assert!(matches!(
                journal.begin_admitted_attempt(
                    &lease,
                    &metadata.record_id,
                    metadata.generation,
                    crate::edit_journal::AttemptAdmission::Initial {
                        previous_attempt: None,
                    }
                ),
                Err(JournalError::InvalidState)
            ));
            if let Some(outcome) = outcome {
                journal
                    .record_outcome(
                        &lease,
                        &metadata.record_id,
                        metadata.generation,
                        attempt,
                        1,
                        outcome,
                    )
                    .unwrap();
            }
            drop(lease);
            drop(journal);
            let reopened = EditJournal::open(temp.path(), scope.clone(), TestProtector).unwrap();
            let remote = FakeRemote::new(vec![UploadBehavior::ApplyAndSucceed], false);
            assert!(matches!(
                dispatch_initial_edit(
                    &reopened,
                    &metadata.record_id,
                    metadata.generation,
                    &scope,
                    &remote
                ),
                Err(JournalError::InvalidState)
            ));
            assert!(remote.calls().is_empty());
            assert_eq!(
                reopened.recover_all().unwrap().records[0].content,
                test_record(&scope).content
            );
            if outcome != Some(RecoveryAttemptOutcome::VerifiedApplied) {
                assert_eq!(
                    dispatch_recovered_edit(
                        &reopened,
                        &metadata.record_id,
                        metadata.generation,
                        &scope,
                        &remote,
                        ExplicitRecoveryApproval::user_reviewed()
                    )
                    .unwrap(),
                    ReconciliationOutcome::VerifiedApplied { attempts: 1 }
                );
            }
        }
    }

    #[test]
    fn initial_dispatch_without_upload_still_requires_review_on_next_invocation() {
        let scope = test_scope();
        let temp = private_tempdir();
        let journal = EditJournal::open(temp.path(), scope.clone(), TestProtector).unwrap();
        let metadata = append_test_edit(&journal, &scope);
        let remote = FakeRemote::new(vec![UploadBehavior::ApplyAndSucceed], false);
        remote.version.lock().unwrap().resource_id = "replacement".into();
        assert_eq!(
            dispatch_initial_edit(
                &journal,
                &metadata.record_id,
                metadata.generation,
                &scope,
                &remote
            )
            .unwrap(),
            ReconciliationOutcome::Conflict(ReconciliationIssue::RemoteObjectChanged)
        );
        assert_eq!(remote.calls(), ["stat"]);
        assert_eq!(
            journal.recover_all().unwrap().recovery_states[&metadata.record_id],
            RecoveryAttemptState::Conflict {
                attempt_id: 0,
                attempts: 0
            }
        );
        assert!(matches!(
            dispatch_initial_edit(
                &journal,
                &metadata.record_id,
                metadata.generation,
                &scope,
                &remote
            ),
            Err(JournalError::InvalidState)
        ));
        assert_eq!(remote.calls(), ["stat"]);
        assert_eq!(
            journal.recover_all().unwrap().records[0].content,
            test_record(&scope).content
        );
    }

    #[test]
    fn dispatcher_persists_put_count_for_deferred_retry_exhaustion() {
        let scope = test_scope();
        let record = test_record(&scope);
        let temp = private_tempdir();
        let journal = EditJournal::open(temp.path(), scope.clone(), TestProtector).unwrap();
        let metadata = journal
            .append_edit(
                record.metadata.generation,
                LocalFileIdentity {
                    volume_serial: scope.root_volume_serial,
                    file_index: 101,
                },
                &record.metadata.relative_path,
                record.metadata.remote.clone(),
                &record.content,
            )
            .unwrap();
        let remote = FakeRemote::new(
            vec![
                UploadBehavior::OfflineWithoutApply,
                UploadBehavior::OfflineWithoutApply,
            ],
            false,
        );
        assert_eq!(
            dispatch_recovered_edit(
                &journal,
                &metadata.record_id,
                metadata.generation,
                &scope,
                &remote,
                ExplicitRecoveryApproval::user_reviewed(),
            )
            .unwrap(),
            ReconciliationOutcome::Deferred
        );
        let snapshot = journal.recover_all().unwrap();
        assert_eq!(
            snapshot.recovery_states.get(&metadata.record_id),
            Some(&RecoveryAttemptState::Deferred {
                attempt_id: 2,
                attempts: 2,
            })
        );
        assert_eq!(remote.calls(), ["stat", "upload", "stat", "upload", "stat"]);
        assert_eq!(snapshot.records[0].content, record.content);
    }

    #[test]
    fn non_transient_rejection_never_retries_even_if_baseline_is_unchanged() {
        let scope = test_scope();
        let record = test_record(&scope);
        let remote = FakeRemote::new(vec![UploadBehavior::RejectConflictUnchanged], false);
        assert_eq!(
            reconcile_recovered_edit(&record, &scope, &remote),
            ReconciliationOutcome::Deferred
        );
        assert_eq!(remote.calls(), ["stat", "upload", "stat"]);
    }

    #[test]
    fn changed_remote_validator_prevents_upload() {
        let scope = test_scope();
        let record = test_record(&scope);
        let remote = FakeRemote::new(Vec::new(), false);
        remote.version.lock().unwrap().etag = "\"changed\"".into();
        assert_eq!(
            reconcile_recovered_edit(&record, &scope, &remote),
            ReconciliationOutcome::Conflict(ReconciliationIssue::ContentMismatch)
        );
        assert_eq!(remote.calls(), ["stat", "readback"]);
    }

    #[test]
    fn ambiguous_readback_retains_snapshot_and_does_not_retry() {
        let scope = test_scope();
        let record = test_record(&scope);
        let remote = FakeRemote::new(vec![UploadBehavior::ApplyAndSucceed], true);
        assert_eq!(
            reconcile_recovered_edit(&record, &scope, &remote),
            ReconciliationOutcome::Ambiguous
        );
        assert_eq!(remote.calls(), ["stat", "upload", "readback"]);
    }

    #[test]
    fn post_write_readback_rejects_an_encrypted_or_directory_target() {
        let scope = test_scope();
        let record = test_record(&scope);
        let remote = FakeRemote::new(vec![UploadBehavior::ApplyThenEncrypt], false);
        assert_eq!(
            reconcile_recovered_edit(&record, &scope, &remote),
            ReconciliationOutcome::Conflict(ReconciliationIssue::ResponseInconsistent)
        );
        assert_eq!(remote.calls(), ["stat", "upload", "readback"]);
    }

    #[test]
    fn account_scope_mismatch_is_rejected_before_remote_io() {
        let scope = test_scope();
        let record = test_record(&scope);
        let mut other_scope = scope.clone();
        other_scope.account_subject = "another-account".into();
        let remote = FakeRemote::new(Vec::new(), false);
        assert_eq!(
            reconcile_recovered_edit(&record, &other_scope, &remote),
            ReconciliationOutcome::Conflict(ReconciliationIssue::InvalidRecord)
        );
        assert!(remote.calls().is_empty());
    }

    #[test]
    fn failed_upload_with_changed_different_body_is_conflict() {
        let scope = test_scope();
        let record = test_record(&scope);
        let remote = FakeRemote::new(vec![UploadBehavior::RejectConflict], false);
        assert_eq!(
            reconcile_recovered_edit(&record, &scope, &remote),
            ReconciliationOutcome::Conflict(ReconciliationIssue::ContentMismatch)
        );
        assert_eq!(remote.calls(), ["stat", "upload", "stat", "readback"]);
    }
}
