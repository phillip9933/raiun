//! Portable, encrypted-at-rest recovery journal for Windows placeholder edits.
//!
//! This module does not upload, acknowledge, or retire edits. It stores one
//! immutable, authenticated local snapshot per observed edit. A platform
//! protector must encrypt and authenticate the complete record before it is
//! written; Windows production wiring is intentionally a separate step.

use std::{
    collections::HashMap,
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};

#[cfg(not(windows))]
use std::fs::OpenOptions;

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const JOURNAL_DIR: &str = "cloud-files-edit-journal-v1";
const RECORD_MAGIC: &[u8; 8] = b"RAIUNED1";
const MAX_RECORDS: usize = 10_000;
const MAX_RECOVERY_BYTES: u64 = 512 * 1024 * 1024;
const MAX_METADATA_BYTES: usize = 256 * 1024;
const MAX_EDIT_BYTES: usize = 16 * 1024 * 1024;
const MAX_SEALED_BYTES: usize = MAX_METADATA_BYTES + MAX_EDIT_BYTES + 64 * 1024;
const MAX_FIELD_BYTES: usize = 4096;
const MAX_PATH_BYTES: usize = 32 * 1024;
const MAX_RECOVERY_EVENTS_PER_RECORD: u64 = 128;
const MAX_RECOVERY_EVENT_FILES: usize = 100_000;
const MAX_RECOVERY_EVENT_BYTES: usize = 16 * 1024;
const MAX_RECOVERY_SCAN_RETRIES: usize = 3;
const RECOVERY_EVENT_AAD_PREFIX: &[u8] = b"raiun/windows-edit-recovery-event/v1\0";
static RECOVERY_EVENT_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// Aggregate work allowance for read-only discovery, shared across journals.
/// Retries consume the same allowance; exhausted scans return no partial page.
pub(crate) struct MetadataScanBudget {
    pub(crate) entries: usize,
    pub(crate) records: usize,
    pub(crate) read_bytes: u64,
    pub(crate) metadata_bytes: usize,
}

impl Default for MetadataScanBudget {
    fn default() -> Self {
        Self {
            entries: 20_000,
            records: 2_000,
            read_bytes: 64 * 1024 * 1024,
            metadata_bytes: 4 * 1024 * 1024,
        }
    }
}

impl MetadataScanBudget {
    pub(crate) fn charge_read(&mut self, bytes: u64) -> Result<(), JournalError> {
        self.read_bytes = self
            .read_bytes
            .checked_sub(bytes)
            .ok_or(JournalError::ScanLimit)?;
        Ok(())
    }
}

/// Exact authenticated account and selected Cloud Files root binding.
///
/// These values are supplied by the trusted agent, never by Cloud Files
/// callback identity bytes. The opaque account subject is intentionally kept
/// inside the protected record; it is not used in a filename.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EditJournalScope {
    pub profile_id: String,
    pub server_origin: String,
    pub account_subject: String,
    pub space_id: String,
    pub root_resource_id: String,
    pub root_volume_serial: u32,
    pub root_file_index: u64,
}

/// Stable local file identity captured from the validated sync root volume.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalFileIdentity {
    pub volume_serial: u32,
    pub file_index: u64,
}

/// Remote base version captured when the file placeholder was registered.
/// Only a strong ETag can authorize a future conditional upload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteEditBaseline {
    pub resource_id: String,
    /// The exact validator observed when the placeholder was created. Weak or
    /// absent validators may be retained as local evidence but are never
    /// enough to permit a future conditional upload.
    pub etag: String,
    pub byte_len: u64,
}

/// Journal state is local evidence only; none of these states means that a
/// remote write was attempted or completed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalEditState {
    Dirty,
    Uncertain,
}

/// Last durable reconciliation state for an immutable snapshot. A recovered
/// `Attempting` state is deliberately exposed as `Uncertain`; callers must
/// require an explicit review action before beginning another upload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryAttemptState {
    NotAttempted,
    Uncertain { attempt_id: u64 },
    VerifiedApplied { attempt_id: u64, attempts: u8 },
    Conflict { attempt_id: u64, attempts: u8 },
    Ambiguous { attempt_id: u64, attempts: u8 },
    Deferred { attempt_id: u64, attempts: u8 },
}

/// Narrow durable outcome class. It contains no path, body, token, or remote
/// response text; the protected edit snapshot remains the source of truth.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryAttemptOutcome {
    VerifiedApplied,
    Conflict,
    Ambiguous,
    Deferred,
}

/// Marker constructed only at an explicit user-reviewed recovery command.
/// Recovered journal state never creates this marker automatically.
#[derive(Clone, Copy, Debug)]
pub struct ExplicitRecoveryApproval {
    _private: (),
}

impl ExplicitRecoveryApproval {
    pub fn user_reviewed() -> Self {
        Self { _private: () }
    }
}

/// Admission is private to the journal/reconciler. An initial dispatch may
/// continue only its own in-memory attempt chain, never a recovered attempt.
#[derive(Clone, Copy)]
pub(crate) enum AttemptAdmission {
    Explicit(ExplicitRecoveryApproval),
    Initial { previous_attempt: Option<u64> },
}

/// Protected metadata for one retained local copy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalEditMetadata {
    pub record_id: String,
    pub generation: u64,
    pub scope: EditJournalScope,
    pub local_file: LocalFileIdentity,
    /// Slash-separated path relative to the exact configured root. It is
    /// inside the protected record and never used as a host path here.
    pub relative_path: String,
    pub remote: Option<RemoteEditBaseline>,
    pub content_len: u64,
    pub content_sha256: String,
    pub state: LocalEditState,
}

/// A decrypted local recovery item. `remote` is only a captured conditional
/// baseline; callers must revalidate it before any future upload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalEditRecord {
    pub metadata: LocalEditMetadata,
    pub content: Vec<u8>,
}

impl Drop for LocalEditRecord {
    fn drop(&mut self) {
        self.content.zeroize();
    }
}

impl LocalEditRecord {
    /// Whether this record contains enough captured information to consider a
    /// future conditional update. This is not authorization and does not
    /// imply that the remote object or ETag still matches.
    pub fn has_strong_baseline(&self) -> bool {
        self.metadata.remote.as_ref().is_some_and(|baseline| {
            valid_strong_etag(&baseline.etag)
                && !baseline.resource_id.is_empty()
                && baseline.resource_id.len() <= MAX_FIELD_BYTES
        })
    }

    /// Recovered records have no acknowledged server outcome. The caller
    /// should present them as requiring review, even if the last in-process
    /// state was `Dirty`.
    pub fn recovered_state(&self) -> LocalEditState {
        LocalEditState::Uncertain
    }
}

/// Encrypts and authenticates a journal record using platform-owned secret
/// material. `associated_data` binds ciphertext to one exact scope and record
/// filename. Implementations must fail closed on tag or identity mismatch.
pub trait EditRecordProtector: Send + Sync {
    fn seal(&self, associated_data: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, JournalError>;
    fn open(&self, associated_data: &[u8], sealed: &[u8]) -> Result<Vec<u8>, JournalError>;

    /// Tighten platform-specific ACLs on each newly opened journal directory.
    /// Portable test protectors have no OS security policy to apply.
    fn protect_directory(&self, _path: &Path) -> Result<(), JournalError> {
        Ok(())
    }
}

/// Current-user DPAPI implementation for Windows local edit snapshots.
///
/// It is intentionally separate from journal metadata and session persistence:
/// record scope and ID are passed as associated data, while DPAPI binds the
/// protected body to the current Windows user.
#[cfg(windows)]
#[derive(Clone)]
pub struct DpapiEditRecordProtector {
    store: raiun_control_windows::DpapiSessionStore,
}

#[cfg(windows)]
impl DpapiEditRecordProtector {
    pub fn current_user() -> Result<Self, JournalError> {
        let store = raiun_control_windows::DpapiSessionStore::current_user()
            .map_err(|_| JournalError::ProtectionFailed)?;
        Ok(Self { store })
    }

    pub fn local_state_directory(&self) -> &Path {
        self.store.local_edit_state_directory()
    }
}

#[cfg(windows)]
impl EditRecordProtector for DpapiEditRecordProtector {
    fn seal(&self, associated_data: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, JournalError> {
        self.store
            .protect_local_edit_record(associated_data, plaintext)
            .map_err(|_| JournalError::ProtectionFailed)
    }

    fn open(&self, associated_data: &[u8], sealed: &[u8]) -> Result<Vec<u8>, JournalError> {
        self.store
            .unprotect_local_edit_record(associated_data, sealed)
            .map(|plaintext| plaintext.to_vec())
            .map_err(|_| JournalError::ProtectionFailed)
    }

    fn protect_directory(&self, path: &Path) -> Result<(), JournalError> {
        self.store
            .protect_local_edit_directory(path)
            .map_err(|_| JournalError::ProtectionFailed)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalError {
    Io,
    InvalidScope,
    InvalidEdit,
    ScopeMismatch,
    CorruptRecord,
    LimitExceeded,
    ProtectionFailed,
    ScanLimit,
    InvalidState,
}

impl std::fmt::Display for JournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Io => "could not access the local edit recovery journal",
            Self::InvalidScope => "edit recovery scope is invalid",
            Self::InvalidEdit => "local edit metadata is invalid",
            Self::ScopeMismatch => "local edit belongs to another account or root",
            Self::CorruptRecord => "local edit recovery record is incomplete or corrupt",
            Self::LimitExceeded => "local edit exceeds the recovery journal limit",
            Self::ProtectionFailed => "local edit recovery protection failed",
            Self::ScanLimit => "local edit recovery scan exceeded its safety bound",
            Self::InvalidState => "edit recovery state does not permit this operation",
        })
    }
}

impl std::error::Error for JournalError {}

/// Append-only durable local snapshots for one exact account/root scope.
///
/// The caller must pass a private per-user application state directory and a
/// platform protector (Windows: current-user DPAPI). This type never follows
/// a symlink for the journal directory and does not remove records.
pub struct EditJournal {
    directory: PathBuf,
    directory_guard: JournalDirectoryGuard,
    // Keep every ancestor opened without delete sharing so the named
    // journal directory cannot be renamed/replaced while the journal lives.
    _directory_guards: Vec<JournalDirectoryGuard>,
    scope: EditJournalScope,
    protector: Box<dyn EditRecordProtector>,
}

/// RAII ownership of one record's recovery-dispatch lock. This type is not
/// clonable so one holder controls each cross-process attempt sequence.
pub(crate) struct RecoveryDispatchLease {
    record_id: String,
    _file: File,
}

impl RecoveryDispatchLease {
    fn check_record(&self, record_id: &str) -> Result<(), JournalError> {
        if self.record_id == record_id && valid_record_id(record_id) {
            Ok(())
        } else {
            Err(JournalError::InvalidState)
        }
    }
}

impl EditJournal {
    pub fn scope(&self) -> &EditJournalScope {
        &self.scope
    }

    /// Acquire a nonblocking per-record OS lock that spans one full recovery
    /// dispatch. Kernel lock ownership is released on process crash, while
    /// the append-only Attempting event remains for explicit review.
    pub(crate) fn acquire_dispatch_lease(
        &self,
        record_id: &str,
    ) -> Result<RecoveryDispatchLease, JournalError> {
        if !valid_record_id(record_id) {
            return Err(JournalError::InvalidEdit);
        }
        trace_journal_stage(
            "lease_verify_before_open",
            self.directory_guard.verify_path(),
        )?;
        let name = recovery_lock_filename(record_id);
        let (file, _) = match self
            .directory_guard
            .create_new_file(std::ffi::OsStr::new(&name))
        {
            Ok((file, identity)) => {
                trace_journal_stage("lease_set_private", set_private_file(&file))?;
                trace_journal_stage(
                    "lease_sync_file",
                    file.sync_all()
                        .map_err(|error| journal_io_error("lease_file_sync", error)),
                )?;
                trace_journal_stage("lease_sync_directory", sync_directory(&self.directory))?;
                (file, identity)
            }
            Err(_) => trace_journal_stage(
                "lease_open_existing",
                self.directory_guard
                    .open_regular_file(std::ffi::OsStr::new(&name)),
            )?,
        };
        let metadata = trace_journal_stage(
            "lease_file_metadata",
            file.metadata()
                .map_err(|error| journal_io_error("lease_file_metadata", error)),
        )?;
        if metadata.len() != 0 {
            return Err(JournalError::CorruptRecord);
        }
        trace_journal_stage(
            "lease_lock_exclusive",
            file.try_lock_exclusive().map_err(|error| {
                if error.kind() == std::io::ErrorKind::WouldBlock {
                    JournalError::InvalidState
                } else {
                    journal_io_error("lease_lock_exclusive", error)
                }
            }),
        )?;
        trace_journal_stage(
            "lease_verify_after_lock",
            self.directory_guard.verify_path(),
        )?;
        Ok(RecoveryDispatchLease {
            record_id: record_id.to_owned(),
            _file: file,
        })
    }

    pub(crate) fn storage_root(private_state_directory: &Path) -> PathBuf {
        private_state_directory.join(JOURNAL_DIR)
    }

    pub(crate) fn scope_directory_key(scope: &EditJournalScope) -> Result<String, JournalError> {
        Ok(hex(&Sha256::digest(scope_bytes(scope)?)))
    }

    pub fn open(
        private_state_directory: &Path,
        scope: EditJournalScope,
        protector: impl EditRecordProtector + 'static,
    ) -> Result<Self, JournalError> {
        validate_scope(&scope)?;
        let state_guard = ensure_plain_directory(private_state_directory)?;
        protector.protect_directory(private_state_directory)?;
        state_guard.verify_path()?;
        let root_guard = state_guard.create_child_directory(std::ffi::OsStr::new(JOURNAL_DIR))?;
        protector.protect_directory(&root_guard.path)?;
        root_guard.verify_path()?;
        let scope_digest = Self::scope_directory_key(&scope)?;
        let directory_guard =
            root_guard.create_child_directory(std::ffi::OsStr::new(&scope_digest))?;
        protector.protect_directory(&directory_guard.path)?;
        directory_guard.verify_path()?;
        let directory = directory_guard.path.clone();
        Ok(Self {
            directory,
            directory_guard,
            _directory_guards: vec![state_guard, root_guard],
            scope,
            protector: Box::new(protector),
        })
    }

    /// Open existing evidence without creating directories or changing ACLs.
    pub(crate) fn open_existing(
        private_state_directory: &Path,
        scope: EditJournalScope,
        protector: impl EditRecordProtector + 'static,
    ) -> Result<Self, JournalError> {
        validate_scope(&scope)?;
        let state_guard = JournalDirectoryGuard::open(private_state_directory)?;
        let root_guard = JournalDirectoryGuard::open(&Self::storage_root(private_state_directory))?;
        let directory_guard =
            JournalDirectoryGuard::open(&root_guard.path.join(Self::scope_directory_key(&scope)?))?;
        state_guard.verify_path()?;
        root_guard.verify_path()?;
        directory_guard.verify_path()?;
        Ok(Self {
            directory: directory_guard.path.clone(),
            directory_guard,
            _directory_guards: vec![state_guard, root_guard],
            scope,
            protector: Box::new(protector),
        })
    }

    /// Durably append a complete file snapshot. The temporary file is synced,
    /// atomically renamed, and the containing directory is synced before the
    /// method returns. Existing records are never replaced or deleted.
    pub fn append_edit(
        &self,
        generation: u64,
        local_file: LocalFileIdentity,
        relative_path: &str,
        remote: Option<RemoteEditBaseline>,
        content: &[u8],
    ) -> Result<LocalEditMetadata, JournalError> {
        // The agent is the sole writer for a selected profile. Serialize
        // journal appends process-wide so concurrent close callbacks cannot
        // each pass a stale quota scan and overrun the recovery bound.
        static APPEND_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _append_guard = APPEND_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .map_err(|_| JournalError::Io)?;
        validate_edit(
            &self.scope,
            generation,
            local_file,
            relative_path,
            &remote,
            content,
        )?;
        let existing = self.recover_all()?;
        if existing.incomplete_staging_files != 0 {
            // We do not know whether a crashed staging file contains the
            // only copy of an edit, so preserve it and stop appending until
            // recovery has been reviewed.
            return Err(JournalError::ScanLimit);
        }
        if existing.records.len() >= MAX_RECORDS {
            return Err(JournalError::ScanLimit);
        }
        let existing_bytes = existing.records.iter().try_fold(0u64, |total, record| {
            total
                .checked_add(record.metadata.content_len)
                .ok_or(JournalError::LimitExceeded)
        })?;
        let requested_bytes =
            u64::try_from(content.len()).map_err(|_| JournalError::LimitExceeded)?;
        if exceeds_byte_limit(existing_bytes, requested_bytes, MAX_RECOVERY_BYTES) {
            return Err(JournalError::LimitExceeded);
        }
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|_| JournalError::Io)?;
        let record_id = hex(&random);
        let metadata = LocalEditMetadata {
            record_id: record_id.clone(),
            generation,
            scope: self.scope.clone(),
            local_file,
            relative_path: relative_path.to_owned(),
            remote,
            content_len: content.len() as u64,
            content_sha256: hex(&Sha256::digest(content)),
            state: LocalEditState::Dirty,
        };
        let plain = Zeroizing::new(encode_record(&metadata, content)?);
        let associated_data = associated_data(&self.scope, &record_id)?;
        let sealed = self.protector.seal(&associated_data, &plain)?;
        if sealed.is_empty() || sealed.len() > MAX_SEALED_BYTES {
            return Err(JournalError::LimitExceeded);
        }
        let filename = record_filename(&record_id);
        let mut temp_random = [0u8; 8];
        getrandom::fill(&mut temp_random).map_err(|_| JournalError::Io)?;
        let temporary = format!(".stage-{}", hex(&temp_random));
        let write_result = (|| {
            let (mut file, file_identity) = self
                .directory_guard
                .create_new_file(std::ffi::OsStr::new(&temporary))?;
            set_private_file(&file)?;
            file.write_all(&sealed).map_err(|_| JournalError::Io)?;
            file.sync_all().map_err(|_| JournalError::Io)?;
            drop(file);
            // Publish atomically without replacing an existing immutable
            // record if a random ID ever collides.
            self.directory_guard.publish_staged_file(
                std::ffi::OsStr::new(&temporary),
                std::ffi::OsStr::new(&filename),
                file_identity,
            )?;
            #[cfg(not(windows))]
            self.directory_guard
                .remove_file_if_identity(std::ffi::OsStr::new(&temporary), file_identity)?;
            sync_directory(&self.directory)
        })();
        if write_result.is_err() {
            // Only remove the exact unique staging name we created. The final
            // record is append-only and intentionally preserved on errors.
            #[cfg(not(windows))]
            let _ = fs::remove_file(self.directory.join(&temporary));
        }
        write_result?;
        Ok(metadata)
    }

    /// Recover all complete records for the exact open scope. A malformed or
    /// unauthenticated record fails the scan; it is never silently skipped.
    pub fn recover_all(&self) -> Result<RecoverySnapshot, JournalError> {
        self.recover_all_with_entry_hook(|_| {})
    }

    fn recover_all_with_entry_hook(
        &self,
        mut after_entry_name: impl FnMut(&str),
    ) -> Result<RecoverySnapshot, JournalError> {
        for scan_attempt in 0..MAX_RECOVERY_SCAN_RETRIES {
            match self.recover_all_once(&mut after_entry_name, None)? {
                RecoveryScan::Complete(snapshot) => return Ok(snapshot),
                RecoveryScan::Retry => {
                    if scan_attempt + 1 == MAX_RECOVERY_SCAN_RETRIES {
                        return Err(JournalError::Io);
                    }
                }
            }
        }
        Err(JournalError::Io)
    }

    pub(crate) fn recover_metadata_bounded(
        &self,
        budget: &mut MetadataScanBudget,
    ) -> Result<Vec<LocalEditMetadata>, JournalError> {
        for _ in 0..MAX_RECOVERY_SCAN_RETRIES {
            match self.recover_all_once(&mut |_| {}, Some(budget))? {
                RecoveryScan::Retry => continue,
                RecoveryScan::Complete(snapshot) => {
                    if snapshot.incomplete_staging_files != 0 {
                        return Err(JournalError::InvalidState);
                    }
                    return Ok(snapshot
                        .records
                        .iter()
                        .map(|r| r.metadata.clone())
                        .collect());
                }
            }
        }
        Err(JournalError::Io)
    }

    fn recover_all_once(
        &self,
        after_entry_name: &mut impl FnMut(&str),
        mut metadata_budget: Option<&mut MetadataScanBudget>,
    ) -> Result<RecoveryScan, JournalError> {
        let mut records = Vec::new();
        let mut incomplete_staging_files = 0usize;
        let mut recovered_bytes = 0u64;
        let mut recovery_events = Vec::new();
        let mut retry_scan = false;
        self.directory_guard.verify_path()?;
        for (index, entry) in fs::read_dir(&self.directory)
            .map_err(|error| journal_io_error("recover_read_directory", error))?
            .enumerate()
        {
            if index >= MAX_RECORDS * 2 + MAX_RECOVERY_EVENT_FILES {
                return Err(JournalError::ScanLimit);
            }
            if let Some(budget) = metadata_budget.as_deref_mut() {
                budget.entries = budget
                    .entries
                    .checked_sub(1)
                    .ok_or(JournalError::ScanLimit)?;
            }
            let entry = entry.map_err(|error| journal_io_error("recover_read_entry", error))?;
            let name = entry.file_name();
            let name = name.to_str().ok_or(JournalError::CorruptRecord)?;
            after_entry_name(name);
            if name.starts_with(".stage-") {
                // A close callback can publish a staged file while another
                // thread is enumerating the journal. If it disappears after
                // read_dir yielded its name, restart the bounded scan so the
                // immutable destination is observed. A still-present stage
                // remains visible as incomplete evidence and blocks appends.
                match self
                    .directory_guard
                    .open_regular_file(std::ffi::OsStr::new(name))
                {
                    Ok((file, _)) => {
                        let metadata = file
                            .metadata()
                            .map_err(|error| journal_io_error("recover_stage_metadata", error))?;
                        if !metadata.is_file() {
                            return Err(JournalError::CorruptRecord);
                        }
                        incomplete_staging_files = incomplete_staging_files.saturating_add(1);
                    }
                    Err(_) if matches!(fs::symlink_metadata(entry.path()), Err(error) if error.kind() == std::io::ErrorKind::NotFound) =>
                    {
                        retry_scan = true;
                        break;
                    }
                    Err(_) => return Err(JournalError::CorruptRecord),
                }
                continue;
            }
            let (file, _) = self
                .directory_guard
                .open_regular_file(std::ffi::OsStr::new(name))
                .map_err(|_| JournalError::CorruptRecord)?;
            let metadata = file
                .metadata()
                .map_err(|error| journal_io_error("recover_file_metadata", error))?;
            if let Some((event_record_id, event_sequence)) = parse_recovery_event_name(name)? {
                if metadata.len() > MAX_RECOVERY_EVENT_BYTES as u64 {
                    return Err(JournalError::LimitExceeded);
                }
                let read_limit = if let Some(budget) = metadata_budget.as_deref_mut() {
                    let limit = metadata.len().saturating_add(1);
                    budget.charge_read(limit)?;
                    limit
                } else {
                    (MAX_RECOVERY_EVENT_BYTES + 1) as u64
                };
                let mut sealed = Vec::with_capacity(metadata.len() as usize);
                file.take(read_limit)
                    .read_to_end(&mut sealed)
                    .map_err(|error| journal_io_error("recover_event_read", error))?;
                if sealed.len() > MAX_RECOVERY_EVENT_BYTES {
                    return Err(JournalError::LimitExceeded);
                }
                let aad =
                    recovery_event_associated_data(&self.scope, &event_record_id, event_sequence)?;
                let plain = Zeroizing::new(self.protector.open(&aad, &sealed)?);
                let event: RecoveryEvent =
                    serde_json::from_slice(&plain).map_err(|_| JournalError::CorruptRecord)?;
                if event.record_id != event_record_id
                    || event.sequence != event_sequence
                    || event.scope != self.scope
                {
                    return Err(JournalError::ScopeMismatch);
                }
                recovery_events.push(event);
                continue;
            }
            if parse_recovery_lock_name(name)?.is_some() {
                if metadata.len() != 0 {
                    return Err(JournalError::CorruptRecord);
                }
                continue;
            }
            let Some(record_id) = name.strip_suffix(".edit") else {
                return Err(JournalError::CorruptRecord);
            };
            if !valid_record_id(record_id) || metadata.len() > MAX_SEALED_BYTES as u64 {
                return Err(JournalError::CorruptRecord);
            }
            let read_limit = if let Some(budget) = metadata_budget.as_deref_mut() {
                budget.records = budget
                    .records
                    .checked_sub(1)
                    .ok_or(JournalError::ScanLimit)?;
                let limit = metadata.len().saturating_add(1);
                budget.charge_read(limit)?;
                limit
            } else {
                (MAX_SEALED_BYTES + 1) as u64
            };
            let mut sealed = Vec::with_capacity(metadata.len() as usize);
            file.take(read_limit)
                .read_to_end(&mut sealed)
                .map_err(|error| journal_io_error("recover_record_read", error))?;
            if sealed.len() > MAX_SEALED_BYTES {
                return Err(JournalError::LimitExceeded);
            }
            let associated_data = associated_data(&self.scope, record_id)?;
            let plain = Zeroizing::new(self.protector.open(&associated_data, &sealed)?);
            let mut record = decode_record(&plain)?;
            if record.metadata.record_id != record_id || record.metadata.scope != self.scope {
                return Err(JournalError::ScopeMismatch);
            }
            validate_recovered_record(&record)?;
            recovered_bytes = recovered_bytes
                .checked_add(record.metadata.content_len)
                .ok_or(JournalError::LimitExceeded)?;
            if recovered_bytes > MAX_RECOVERY_BYTES {
                return Err(JournalError::LimitExceeded);
            }
            if let Some(budget) = metadata_budget.as_deref_mut() {
                let bytes = serde_json::to_vec(&record.metadata)
                    .map_err(|_| JournalError::CorruptRecord)?
                    .len();
                budget.metadata_bytes = budget
                    .metadata_bytes
                    .checked_sub(bytes)
                    .ok_or(JournalError::ScanLimit)?;
                // Authentication, content hash and scope validation above still
                // cover the full record. Event validation only needs metadata.
                record.content.zeroize();
                record.content = Vec::new();
            }
            records.push(record);
            if records.len() > MAX_RECORDS {
                return Err(JournalError::ScanLimit);
            }
        }
        if retry_scan {
            return Ok(RecoveryScan::Retry);
        }
        records.sort_by(|left, right| left.metadata.record_id.cmp(&right.metadata.record_id));
        let recovery_states = validate_recovery_events(&records, recovery_events)?;
        self.directory_guard.verify_path()?;
        Ok(RecoveryScan::Complete(RecoverySnapshot {
            records,
            incomplete_staging_files,
            recovery_states,
        }))
    }

    /// Durably mark one explicit user-reviewed upload attempt before the
    /// caller performs its conditional remote mutation. The immutable snapshot
    /// and all prior events remain untouched.
    pub(crate) fn begin_attempt(
        &self,
        lease: &RecoveryDispatchLease,
        record_id: &str,
        generation: u64,
        approval: ExplicitRecoveryApproval,
    ) -> Result<u64, JournalError> {
        self.begin_admitted_attempt(
            lease,
            record_id,
            generation,
            AttemptAdmission::Explicit(approval),
        )
    }

    pub(crate) fn begin_admitted_attempt(
        &self,
        lease: &RecoveryDispatchLease,
        record_id: &str,
        generation: u64,
        admission: AttemptAdmission,
    ) -> Result<u64, JournalError> {
        lease.check_record(record_id)?;
        let _guard = trace_journal_stage(
            "begin_attempt_event_lock",
            RECOVERY_EVENT_LOCK
                .get_or_init(|| Mutex::new(()))
                .lock()
                .map_err(|_| JournalError::Io),
        )?;
        let snapshot = trace_journal_stage("begin_attempt_recover", self.recover_all())?;
        let record = snapshot
            .records
            .iter()
            .find(|record| record.metadata.record_id == record_id)
            .filter(|record| record.metadata.generation == generation)
            .ok_or(JournalError::ScopeMismatch)?;
        let prior = snapshot
            .recovery_states
            .get(record_id)
            .copied()
            .unwrap_or(RecoveryAttemptState::NotAttempted);
        if matches!(prior, RecoveryAttemptState::VerifiedApplied { .. }) {
            return Err(JournalError::InvalidState);
        }
        if let AttemptAdmission::Initial { previous_attempt } = admission {
            let expected = previous_attempt
                .map_or(RecoveryAttemptState::NotAttempted, |attempt_id| {
                    RecoveryAttemptState::Uncertain { attempt_id }
                });
            if prior != expected {
                return Err(JournalError::InvalidState);
            }
        }
        let previous_attempt = attempt_id(prior);
        let next_attempt = previous_attempt
            .checked_add(1)
            .filter(|attempt| *attempt <= MAX_RECOVERY_EVENTS_PER_RECORD)
            .ok_or(JournalError::ScanLimit)?;
        let sequence = trace_journal_stage(
            "begin_attempt_next_event_sequence",
            self.next_recovery_sequence(record_id),
        )?;
        trace_journal_stage(
            "begin_attempt_append",
            self.append_recovery_event(RecoveryEvent {
                scope: self.scope.clone(),
                record_id: record_id.to_owned(),
                record_generation: record.metadata.generation,
                sequence,
                attempt_id: next_attempt,
                state: RecoveryEventState::Attempting,
                attempts: 0,
            }),
        )?;
        Ok(next_attempt)
    }

    /// Persist a coarse terminal receipt after bounded verification. Failure
    /// leaves the prior durable Attempting event, which recovers as Uncertain.
    pub(crate) fn record_outcome(
        &self,
        lease: &RecoveryDispatchLease,
        record_id: &str,
        generation: u64,
        expected_attempt_id: u64,
        attempts: u8,
        outcome: RecoveryAttemptOutcome,
    ) -> Result<(), JournalError> {
        lease.check_record(record_id)?;
        let _guard = trace_journal_stage(
            "record_outcome_event_lock",
            RECOVERY_EVENT_LOCK
                .get_or_init(|| Mutex::new(()))
                .lock()
                .map_err(|_| JournalError::Io),
        )?;
        let snapshot = trace_journal_stage("record_outcome_recover", self.recover_all())?;
        let record = snapshot
            .records
            .iter()
            .find(|record| record.metadata.record_id == record_id)
            .filter(|record| record.metadata.generation == generation)
            .ok_or(JournalError::ScopeMismatch)?;
        let state = snapshot
            .recovery_states
            .get(record_id)
            .copied()
            .unwrap_or(RecoveryAttemptState::NotAttempted);
        if expected_attempt_id != attempt_id(state) || attempts > 2 {
            return Err(JournalError::InvalidState);
        }
        let state = match outcome {
            RecoveryAttemptOutcome::VerifiedApplied => RecoveryEventState::VerifiedApplied,
            RecoveryAttemptOutcome::Conflict => RecoveryEventState::Conflict,
            RecoveryAttemptOutcome::Ambiguous => RecoveryEventState::Ambiguous,
            RecoveryAttemptOutcome::Deferred => RecoveryEventState::Deferred,
        };
        let sequence = trace_journal_stage(
            "record_outcome_next_event_sequence",
            self.next_recovery_sequence(record_id),
        )?;
        trace_journal_stage(
            "record_outcome_append",
            self.append_recovery_event(RecoveryEvent {
                scope: self.scope.clone(),
                record_id: record_id.to_owned(),
                record_generation: record.metadata.generation,
                sequence,
                attempt_id: expected_attempt_id,
                state,
                attempts,
            }),
        )
    }

    fn next_recovery_sequence(&self, record_id: &str) -> Result<u64, JournalError> {
        let events = self.read_recovery_events_for(record_id)?;
        let current = events.last().map_or(0, |event| event.sequence);
        current.checked_add(1).ok_or(JournalError::ScanLimit)
    }

    fn read_recovery_events_for(
        &self,
        record_id: &str,
    ) -> Result<Vec<RecoveryEvent>, JournalError> {
        if !valid_record_id(record_id) {
            return Err(JournalError::InvalidEdit);
        }
        let snapshot = self.recover_all()?;
        let mut events = Vec::new();
        let names = recovery_event_names(&self.directory, record_id)?;
        for (name, sequence) in names {
            let (file, _) = self
                .directory_guard
                .open_regular_file(std::ffi::OsStr::new(&name))?;
            let mut sealed = Vec::new();
            file.take((MAX_RECOVERY_EVENT_BYTES + 1) as u64)
                .read_to_end(&mut sealed)
                .map_err(|_| JournalError::Io)?;
            if sealed.len() > MAX_RECOVERY_EVENT_BYTES {
                return Err(JournalError::LimitExceeded);
            }
            let aad = recovery_event_associated_data(&self.scope, record_id, sequence)?;
            let plain = Zeroizing::new(self.protector.open(&aad, &sealed)?);
            let event: RecoveryEvent =
                serde_json::from_slice(&plain).map_err(|_| JournalError::CorruptRecord)?;
            if event.record_id != record_id
                || event.sequence != sequence
                || event.scope != self.scope
                || !snapshot.records.iter().any(|record| {
                    record.metadata.record_id == record_id
                        && record.metadata.generation == event.record_generation
                })
            {
                return Err(JournalError::ScopeMismatch);
            }
            events.push(event);
        }
        events.sort_by_key(|event| event.sequence);
        if !events.is_empty() {
            validate_event_sequence(record_id, &events, &snapshot.records)?;
        }
        Ok(events)
    }

    fn append_recovery_event(&self, event: RecoveryEvent) -> Result<(), JournalError> {
        let body =
            Zeroizing::new(serde_json::to_vec(&event).map_err(|_| JournalError::InvalidEdit)?);
        if body.len() > MAX_RECOVERY_EVENT_BYTES {
            return Err(JournalError::LimitExceeded);
        }
        let aad = recovery_event_associated_data(&self.scope, &event.record_id, event.sequence)?;
        let sealed = self.protector.seal(&aad, &body)?;
        if sealed.is_empty() || sealed.len() > MAX_RECOVERY_EVENT_BYTES {
            return Err(JournalError::LimitExceeded);
        }
        let filename = recovery_event_filename(&event.record_id, event.sequence);
        let mut temp_random = [0u8; 8];
        trace_journal_stage(
            "event_random_name",
            getrandom::fill(&mut temp_random).map_err(|_| JournalError::Io),
        )?;
        let temporary = format!(".stage-recovery-{}", hex(&temp_random));
        let write_result = (|| {
            let (mut file, file_identity) = trace_journal_stage(
                "event_create_stage_file",
                self.directory_guard
                    .create_new_file(std::ffi::OsStr::new(&temporary)),
            )?;
            trace_journal_stage("event_set_private", set_private_file(&file))?;
            trace_journal_stage(
                "event_write_stage_file",
                file.write_all(&sealed)
                    .map_err(|error| journal_io_error("event_stage_write", error)),
            )?;
            trace_journal_stage(
                "event_sync_stage_file",
                file.sync_all()
                    .map_err(|error| journal_io_error("event_stage_sync", error)),
            )?;
            drop(file);
            trace_journal_stage(
                "event_publish_staged_file",
                self.directory_guard.publish_staged_file(
                    std::ffi::OsStr::new(&temporary),
                    std::ffi::OsStr::new(&filename),
                    file_identity,
                ),
            )?;
            #[cfg(not(windows))]
            trace_journal_stage(
                "event_remove_stage_file",
                self.directory_guard
                    .remove_file_if_identity(std::ffi::OsStr::new(&temporary), file_identity)
                    .map(|_| ()),
            )?;
            trace_journal_stage("event_sync_directory", sync_directory(&self.directory))
        })();
        if write_result.is_err() {
            #[cfg(not(windows))]
            let _ = fs::remove_file(self.directory.join(&temporary));
        }
        write_result
    }

    /// Return only the sealed bytes and exact authenticated-data bytes for a
    /// synthetic cross-user DPAPI test. This is deliberately unavailable to
    /// production builds and does not expose decoded journal content.
    #[cfg(all(test, windows))]
    pub(crate) fn sealed_record_for_test(
        &self,
        record_id: &str,
    ) -> Result<(Vec<u8>, Vec<u8>), JournalError> {
        if !valid_record_id(record_id) {
            return Err(JournalError::CorruptRecord);
        }
        let path = self.directory.join(record_filename(record_id));
        let metadata = fs::symlink_metadata(&path).map_err(|_| JournalError::Io)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > MAX_SEALED_BYTES as u64
        {
            return Err(JournalError::CorruptRecord);
        }
        let (file, _) = self
            .directory_guard
            .open_regular_file(std::ffi::OsStr::new(&record_filename(record_id)))?;
        let mut sealed = Vec::with_capacity(metadata.len() as usize);
        file.take((MAX_SEALED_BYTES + 1) as u64)
            .read_to_end(&mut sealed)
            .map_err(|_| JournalError::Io)?;
        if sealed.len() > MAX_SEALED_BYTES {
            return Err(JournalError::LimitExceeded);
        }
        Ok((sealed, associated_data(&self.scope, record_id)?))
    }
}

fn exceeds_byte_limit(existing: u64, requested: u64, limit: u64) -> bool {
    match existing.checked_add(requested) {
        Some(total) => total > limit,
        None => true,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoverySnapshot {
    pub records: Vec<LocalEditRecord>,
    /// A staging file means a crash may have interrupted persistence. It is
    /// retained and surfaced; the journal never deletes or calls it clean.
    pub incomplete_staging_files: usize,
    /// Latest protected reconciliation state by immutable record ID.
    pub recovery_states: HashMap<String, RecoveryAttemptState>,
}

enum RecoveryScan {
    Complete(RecoverySnapshot),
    Retry,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryEvent {
    scope: EditJournalScope,
    record_id: String,
    record_generation: u64,
    sequence: u64,
    attempt_id: u64,
    state: RecoveryEventState,
    attempts: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RecoveryEventState {
    Attempting,
    VerifiedApplied,
    Conflict,
    Ambiguous,
    Deferred,
}

fn validate_recovery_events(
    records: &[LocalEditRecord],
    mut events: Vec<RecoveryEvent>,
) -> Result<HashMap<String, RecoveryAttemptState>, JournalError> {
    if events.len() > MAX_RECOVERY_EVENT_FILES {
        return Err(JournalError::ScanLimit);
    }
    events.sort_by(|left, right| {
        left.record_id
            .cmp(&right.record_id)
            .then_with(|| left.sequence.cmp(&right.sequence))
    });
    let mut states = HashMap::new();
    let mut current_id: Option<String> = None;
    let mut history = Vec::new();
    for event in events {
        if current_id
            .as_deref()
            .is_some_and(|id| id != event.record_id)
        {
            let id = current_id.take().expect("checked above");
            let state = validate_event_sequence(&id, &history, records)?;
            states.insert(id, state);
            history.clear();
        }
        current_id = Some(event.record_id.clone());
        history.push(event);
    }
    if let Some(id) = current_id {
        let state = validate_event_sequence(&id, &history, records)?;
        states.insert(id, state);
    }
    Ok(states)
}

fn validate_event_sequence(
    record_id: &str,
    events: &[RecoveryEvent],
    records: &[LocalEditRecord],
) -> Result<RecoveryAttemptState, JournalError> {
    let record = records
        .iter()
        .find(|record| record.metadata.record_id == record_id)
        .ok_or(JournalError::CorruptRecord)?;
    if events.is_empty() {
        return Err(JournalError::CorruptRecord);
    }
    let mut last_attempt = 0u64;
    let mut active_attempt = false;
    let mut state = RecoveryAttemptState::NotAttempted;
    let mut expected_sequence = 1u64;
    for event in events {
        if event.record_generation != record.metadata.generation
            || event.sequence != expected_sequence
            || event.attempt_id > MAX_RECOVERY_EVENTS_PER_RECORD
        {
            return Err(JournalError::CorruptRecord);
        }
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or(JournalError::ScanLimit)?;
        match event.state {
            RecoveryEventState::Attempting => {
                if event.attempt_id != last_attempt + 1 || event.attempts != 0 {
                    return Err(JournalError::CorruptRecord);
                }
                last_attempt = event.attempt_id;
                active_attempt = true;
                state = RecoveryAttemptState::Uncertain {
                    attempt_id: last_attempt,
                };
            }
            terminal => {
                if event.attempt_id != last_attempt
                    || event.attempts > 2
                    // A zero-PUT terminal receipt is valid after a prior
                    // terminal result: a later explicit review may verify
                    // that the remote already matches without issuing a new
                    // conditional write. Any positive count must belong to
                    // the currently open Attempting event.
                    || (event.attempts != 0 && !active_attempt)
                {
                    return Err(JournalError::CorruptRecord);
                }
                active_attempt = false;
                state = match terminal {
                    RecoveryEventState::VerifiedApplied => RecoveryAttemptState::VerifiedApplied {
                        attempt_id: last_attempt,
                        attempts: event.attempts,
                    },
                    RecoveryEventState::Conflict => RecoveryAttemptState::Conflict {
                        attempt_id: last_attempt,
                        attempts: event.attempts,
                    },
                    RecoveryEventState::Ambiguous => RecoveryAttemptState::Ambiguous {
                        attempt_id: last_attempt,
                        attempts: event.attempts,
                    },
                    RecoveryEventState::Deferred => RecoveryAttemptState::Deferred {
                        attempt_id: last_attempt,
                        attempts: event.attempts,
                    },
                    RecoveryEventState::Attempting => unreachable!(),
                };
            }
        }
    }
    Ok(state)
}

fn attempt_id(state: RecoveryAttemptState) -> u64 {
    match state {
        RecoveryAttemptState::NotAttempted => 0,
        RecoveryAttemptState::Uncertain { attempt_id }
        | RecoveryAttemptState::VerifiedApplied { attempt_id, .. }
        | RecoveryAttemptState::Conflict { attempt_id, .. }
        | RecoveryAttemptState::Ambiguous { attempt_id, .. }
        | RecoveryAttemptState::Deferred { attempt_id, .. } => attempt_id,
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordHeader {
    metadata: LocalEditMetadata,
}

fn encode_record(metadata: &LocalEditMetadata, content: &[u8]) -> Result<Vec<u8>, JournalError> {
    let header = serde_json::to_vec(&RecordHeader {
        metadata: metadata.clone(),
    })
    .map_err(|_| JournalError::InvalidEdit)?;
    if header.len() > MAX_METADATA_BYTES || content.len() > MAX_EDIT_BYTES {
        return Err(JournalError::LimitExceeded);
    }
    let header_len = u32::try_from(header.len()).map_err(|_| JournalError::LimitExceeded)?;
    let content_len = u64::try_from(content.len()).map_err(|_| JournalError::LimitExceeded)?;
    let mut bytes = Vec::with_capacity(RECORD_MAGIC.len() + 12 + header.len() + content.len());
    bytes.extend_from_slice(RECORD_MAGIC);
    bytes.extend_from_slice(&header_len.to_le_bytes());
    bytes.extend_from_slice(&content_len.to_le_bytes());
    bytes.extend_from_slice(&header);
    bytes.extend_from_slice(content);
    Ok(bytes)
}

fn decode_record(bytes: &[u8]) -> Result<LocalEditRecord, JournalError> {
    if bytes.len() < RECORD_MAGIC.len() + 12 || !bytes.starts_with(RECORD_MAGIC) {
        return Err(JournalError::CorruptRecord);
    }
    let header_start = RECORD_MAGIC.len() + 12;
    let header_len = u32::from_le_bytes(
        bytes[RECORD_MAGIC.len()..RECORD_MAGIC.len() + 4]
            .try_into()
            .map_err(|_| JournalError::CorruptRecord)?,
    ) as usize;
    let content_len = u64::from_le_bytes(
        bytes[RECORD_MAGIC.len() + 4..header_start]
            .try_into()
            .map_err(|_| JournalError::CorruptRecord)?,
    );
    if header_len > MAX_METADATA_BYTES || content_len > MAX_EDIT_BYTES as u64 {
        return Err(JournalError::LimitExceeded);
    }
    let content_start = header_start
        .checked_add(header_len)
        .ok_or(JournalError::CorruptRecord)?;
    let content_end = content_start
        .checked_add(usize::try_from(content_len).map_err(|_| JournalError::LimitExceeded)?)
        .ok_or(JournalError::CorruptRecord)?;
    if content_end != bytes.len() {
        return Err(JournalError::CorruptRecord);
    }
    let header: RecordHeader = serde_json::from_slice(&bytes[header_start..content_start])
        .map_err(|_| JournalError::CorruptRecord)?;
    Ok(LocalEditRecord {
        metadata: header.metadata,
        content: bytes[content_start..content_end].to_vec(),
    })
}

fn validate_scope(scope: &EditJournalScope) -> Result<(), JournalError> {
    for value in [
        &scope.profile_id,
        &scope.server_origin,
        &scope.account_subject,
        &scope.space_id,
        &scope.root_resource_id,
    ] {
        if value.is_empty() || value.len() > MAX_FIELD_BYTES || value.chars().any(char::is_control)
        {
            return Err(JournalError::InvalidScope);
        }
    }
    let Some((scheme, authority)) = scope.server_origin.split_once("://") else {
        return Err(JournalError::InvalidScope);
    };
    if !matches!(scheme, "https" | "http")
        || authority.is_empty()
        || authority
            .bytes()
            .any(|byte| matches!(byte, b'/' | b'?' | b'#' | b'@') || byte.is_ascii_whitespace())
        || scope.root_file_index == 0
    {
        return Err(JournalError::InvalidScope);
    }
    Ok(())
}

fn validate_edit(
    scope: &EditJournalScope,
    generation: u64,
    local_file: LocalFileIdentity,
    relative_path: &str,
    remote: &Option<RemoteEditBaseline>,
    content: &[u8],
) -> Result<(), JournalError> {
    if generation == 0
        || local_file.volume_serial != scope.root_volume_serial
        || local_file.file_index == 0
        || relative_path.is_empty()
        || relative_path.len() > MAX_PATH_BYTES
        || relative_path.starts_with('/')
        || relative_path.ends_with('/')
        || relative_path.contains('\\')
        || relative_path
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
        || relative_path.chars().any(char::is_control)
        || content.len() > MAX_EDIT_BYTES
    {
        return Err(if content.len() > MAX_EDIT_BYTES {
            JournalError::LimitExceeded
        } else {
            JournalError::InvalidEdit
        });
    }
    if let Some(remote) = remote {
        if remote.resource_id.is_empty()
            || remote.resource_id.len() > MAX_FIELD_BYTES
            || remote.resource_id.chars().any(char::is_control)
            || remote.etag.len() > MAX_FIELD_BYTES
            || remote.etag.chars().any(char::is_control)
        {
            return Err(JournalError::InvalidEdit);
        }
    }
    Ok(())
}

fn validate_recovered_record(record: &LocalEditRecord) -> Result<(), JournalError> {
    let metadata = &record.metadata;
    validate_scope(&metadata.scope)?;
    validate_edit(
        &metadata.scope,
        metadata.generation,
        metadata.local_file,
        &metadata.relative_path,
        &metadata.remote,
        &record.content,
    )?;
    if metadata.content_len != record.content.len() as u64
        || metadata.content_sha256 != hex(&Sha256::digest(&record.content))
    {
        return Err(JournalError::CorruptRecord);
    }
    Ok(())
}

fn valid_strong_etag(etag: &str) -> bool {
    etag.len() >= 2
        && etag.len() <= MAX_FIELD_BYTES
        && etag.starts_with('"')
        && etag.ends_with('"')
        && !etag.starts_with("W/")
        && etag != "\"\""
        && !etag[1..etag.len() - 1]
            .bytes()
            .any(|byte| byte == b'"' || byte < 0x21 || byte == 0x7f)
}

fn scope_bytes(scope: &EditJournalScope) -> Result<Vec<u8>, JournalError> {
    serde_json::to_vec(scope).map_err(|_| JournalError::InvalidScope)
}

fn associated_data(scope: &EditJournalScope, record_id: &str) -> Result<Vec<u8>, JournalError> {
    let mut bytes = b"raiun/windows-edit-journal/v1\0".to_vec();
    bytes.extend_from_slice(&scope_bytes(scope)?);
    bytes.push(0);
    bytes.extend_from_slice(record_id.as_bytes());
    Ok(bytes)
}

fn record_filename(record_id: &str) -> String {
    format!("{record_id}.edit")
}

fn recovery_event_filename(record_id: &str, sequence: u64) -> String {
    format!(".recovery-{record_id}-{sequence:016x}.evt")
}

fn recovery_lock_filename(record_id: &str) -> String {
    format!(".dispatch-{record_id}.lock")
}

fn parse_recovery_lock_name(name: &str) -> Result<Option<String>, JournalError> {
    if !name.starts_with(".dispatch-") {
        return Ok(None);
    }
    let record_id = name
        .strip_prefix(".dispatch-")
        .and_then(|value| value.strip_suffix(".lock"))
        .ok_or(JournalError::CorruptRecord)?;
    if !valid_record_id(record_id) {
        return Err(JournalError::CorruptRecord);
    }
    Ok(Some(record_id.to_owned()))
}

fn parse_recovery_event_name(name: &str) -> Result<Option<(String, u64)>, JournalError> {
    if !name.starts_with(".recovery-") {
        return Ok(None);
    }
    let rest = name
        .strip_prefix(".recovery-")
        .and_then(|value| value.strip_suffix(".evt"))
        .ok_or(JournalError::CorruptRecord)?;
    let (record_id, sequence) = rest.split_once('-').ok_or(JournalError::CorruptRecord)?;
    if !valid_record_id(record_id) || sequence.len() != 16 {
        return Err(JournalError::CorruptRecord);
    }
    let sequence = u64::from_str_radix(sequence, 16).map_err(|_| JournalError::CorruptRecord)?;
    if sequence == 0 {
        return Err(JournalError::CorruptRecord);
    }
    Ok(Some((record_id.to_owned(), sequence)))
}

fn recovery_event_associated_data(
    scope: &EditJournalScope,
    record_id: &str,
    sequence: u64,
) -> Result<Vec<u8>, JournalError> {
    let mut bytes = RECOVERY_EVENT_AAD_PREFIX.to_vec();
    bytes.extend_from_slice(&scope_bytes(scope)?);
    bytes.push(0);
    bytes.extend_from_slice(record_id.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&sequence.to_le_bytes());
    Ok(bytes)
}

fn recovery_event_names(
    directory: &Path,
    record_id: &str,
) -> Result<Vec<(String, u64)>, JournalError> {
    let mut names = Vec::new();
    for entry in fs::read_dir(directory).map_err(|_| JournalError::Io)? {
        if names.len() >= MAX_RECOVERY_EVENT_FILES {
            return Err(JournalError::ScanLimit);
        }
        let entry = entry.map_err(|_| JournalError::Io)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| JournalError::CorruptRecord)?;
        if let Some((found_id, sequence)) = parse_recovery_event_name(&name)? {
            if found_id == record_id {
                names.push((name, sequence));
            }
        }
    }
    names.sort_by_key(|(_, sequence)| *sequence);
    Ok(names)
}

fn valid_record_id(record_id: &str) -> bool {
    record_id.len() == 32 && record_id.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(not(windows))]
#[derive(Clone, Copy)]
struct JournalFileIdentity;

struct JournalDirectoryGuard {
    path: PathBuf,
    #[cfg(windows)]
    pinned: raiun_control_windows::PinnedDirectory,
}

impl JournalDirectoryGuard {
    fn open(path: &Path) -> Result<Self, JournalError> {
        #[cfg(windows)]
        {
            let pinned =
                raiun_control_windows::PinnedDirectory::open(path).map_err(|_| JournalError::Io)?;
            Ok(Self {
                path: path.to_owned(),
                pinned,
            })
        }
        #[cfg(not(windows))]
        {
            ensure_plain_directory_metadata(path)?;
            Ok(Self {
                path: path.to_owned(),
            })
        }
    }

    fn verify_path(&self) -> Result<(), JournalError> {
        #[cfg(windows)]
        self.pinned
            .verify_path()
            .map_err(|error| journal_io_error("pinned_directory_verify", error))?;
        #[cfg(not(windows))]
        ensure_plain_directory_metadata(&self.path)?;
        Ok(())
    }

    fn create_child_directory(
        &self,
        name: &std::ffi::OsStr,
    ) -> Result<JournalDirectoryGuard, JournalError> {
        self.verify_path()?;
        #[cfg(windows)]
        {
            let pinned = self
                .pinned
                .create_child_directory(name)
                .map_err(|error| journal_io_error("pinned_child_directory_create", error))?;
            Ok(Self {
                path: self.path.join(name),
                pinned,
            })
        }
        #[cfg(not(windows))]
        {
            let child = self.path.join(name);
            match fs::create_dir(&child) {
                Ok(()) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        fs::set_permissions(&child, fs::Permissions::from_mode(0o700))
                            .map_err(|_| JournalError::Io)?;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(JournalError::Io),
            }
            sync_directory(&self.path)?;
            let guard = Self::open(&child)?;
            self.verify_path()?;
            Ok(guard)
        }
    }

    fn create_new_file(
        &self,
        name: &std::ffi::OsStr,
    ) -> Result<(File, JournalFileIdentity), JournalError> {
        self.verify_path()?;
        #[cfg(windows)]
        {
            let (file, identity) = self
                .pinned
                .create_new_file(name)
                .map_err(|error| journal_io_error("pinned_file_create", error))?;
            Ok((file, JournalFileIdentity(identity)))
        }
        #[cfg(not(windows))]
        {
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(self.path.join(name))
                .map_err(|_| JournalError::Io)?;
            Ok((file, JournalFileIdentity))
        }
    }

    fn open_regular_file(
        &self,
        name: &std::ffi::OsStr,
    ) -> Result<(File, JournalFileIdentity), JournalError> {
        self.verify_path()?;
        #[cfg(windows)]
        {
            let (file, identity) = self
                .pinned
                .open_regular_file(name)
                .map_err(|_| JournalError::CorruptRecord)?;
            Ok((file, JournalFileIdentity(identity)))
        }
        #[cfg(not(windows))]
        {
            let file = open_regular_file(&self.path.join(name))?;
            Ok((file, JournalFileIdentity))
        }
    }

    fn publish_staged_file(
        &self,
        source: &std::ffi::OsStr,
        destination: &std::ffi::OsStr,
        expected: JournalFileIdentity,
    ) -> Result<(), JournalError> {
        self.verify_path()?;
        #[cfg(windows)]
        {
            let _ = self
                .pinned
                .publish_staged_file(source, destination, expected.0)
                .map_err(|error| journal_io_error("pinned_rename_publish", error))?;
        }
        #[cfg(not(windows))]
        {
            let _ = expected;
            fs::hard_link(self.path.join(source), self.path.join(destination))
                .map_err(|error| journal_io_error("hard_link", error))?;
        }
        Ok(())
    }

    #[cfg(not(windows))]
    fn remove_file_if_identity(
        &self,
        name: &std::ffi::OsStr,
        _identity: JournalFileIdentity,
    ) -> Result<(), JournalError> {
        self.verify_path()?;
        fs::remove_file(self.path.join(name)).map_err(|_| JournalError::Io)?;
        Ok(())
    }
}

#[cfg(windows)]
#[derive(Clone, Copy)]
struct JournalFileIdentity(raiun_control_windows::PinnedFileIdentity);

fn ensure_plain_directory(path: &Path) -> Result<JournalDirectoryGuard, JournalError> {
    ensure_plain_directory_metadata(path)?;
    JournalDirectoryGuard::open(path)
}

fn ensure_plain_directory_metadata(path: &Path) -> Result<(), JournalError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o077 != 0 {
                    return Err(JournalError::Io);
                }
            }
            Ok(())
        }
        _ => Err(JournalError::Io),
    }
}

#[cfg(not(windows))]
fn open_regular_file(path: &Path) -> Result<File, JournalError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| JournalError::Io)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(JournalError::CorruptRecord);
    }
    File::open(path).map_err(|_| JournalError::Io)
}

fn set_private_file(file: &File) -> Result<(), JournalError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| JournalError::Io)?;
    }
    #[cfg(not(unix))]
    let _ = file;
    Ok(())
}

pub(crate) fn trace_journal_stage<T>(
    stage: &'static str,
    result: Result<T, JournalError>,
) -> Result<T, JournalError> {
    #[cfg(any(test, feature = "synthetic-agent-integration"))]
    if matches!(&result, Err(JournalError::Io)) {
        eprintln!("windows_edit_journal_io_stage={stage}");
    }
    #[cfg(not(test))]
    let _ = stage;
    result
}

fn journal_io_error(stage: &'static str, error: std::io::Error) -> JournalError {
    #[cfg(any(test, feature = "synthetic-agent-integration"))]
    eprintln!(
        "windows_edit_journal_os_error_stage={stage} kind={:?} code={:?}",
        error.kind(),
        error.raw_os_error()
    );
    #[cfg(not(test))]
    let _ = (stage, error);
    JournalError::Io
}

fn sync_directory(path: &Path) -> Result<(), JournalError> {
    #[cfg(unix)]
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| JournalError::Io)?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        sync::atomic::{AtomicBool, Ordering},
    };

    use sha2::{Digest, Sha256};

    use super::{
        EditJournal, EditJournalScope, EditRecordProtector, ExplicitRecoveryApproval, JournalError,
        LocalEditState, LocalFileIdentity, MetadataScanBudget, RecoveryAttemptOutcome,
        RecoveryAttemptState, RemoteEditBaseline, exceeds_byte_limit, record_filename,
    };

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
    struct TestProtector {
        fail_seal: std::sync::Arc<AtomicBool>,
    }

    impl TestProtector {
        fn new() -> Self {
            Self {
                fail_seal: std::sync::Arc::new(AtomicBool::new(false)),
            }
        }

        fn fail_next_seal(&self) {
            self.fail_seal.store(true, Ordering::SeqCst);
        }
    }

    impl EditRecordProtector for TestProtector {
        fn seal(&self, associated_data: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, JournalError> {
            if self.fail_seal.swap(false, Ordering::SeqCst) {
                return Err(JournalError::ProtectionFailed);
            }
            let mut ciphertext = plaintext.iter().map(|byte| byte ^ 0xa7).collect::<Vec<_>>();
            let mut hash = Sha256::new();
            hash.update(associated_data);
            hash.update(&ciphertext);
            ciphertext.extend_from_slice(&hash.finalize());
            Ok(ciphertext)
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
            Ok(ciphertext.iter().map(|byte| byte ^ 0xa7).collect())
        }
    }

    fn scope() -> EditJournalScope {
        EditJournalScope {
            profile_id: "profile-a".into(),
            server_origin: "https://cloud.example.test".into(),
            account_subject: "subject-a".into(),
            space_id: "personal".into(),
            root_resource_id: "root-resource".into(),
            root_volume_serial: 17,
            root_file_index: 88,
        }
    }

    fn baseline() -> RemoteEditBaseline {
        RemoteEditBaseline {
            resource_id: "remote-file-123".into(),
            etag: "\"v1\"".into(),
            byte_len: 4,
        }
    }

    #[test]
    fn metadata_scan_limits_preserve_full_authenticated_bodies() {
        let temp = private_tempdir();
        let journal = EditJournal::open(temp.path(), scope(), TestProtector::new()).unwrap();
        let payload = vec![91; 1024 * 1024];
        let item = journal
            .append_edit(
                1,
                LocalFileIdentity {
                    volume_serial: 17,
                    file_index: 99,
                },
                "retained.txt",
                Some(baseline()),
                &payload,
            )
            .unwrap();
        let record_path = journal.directory.join(format!("{}.edit", item.record_id));
        let sealed = fs::read(&record_path).unwrap();
        let metadata_len = serde_json::to_vec(&item).unwrap().len();
        let allowance = || MetadataScanBudget {
            entries: 1,
            records: 1,
            read_bytes: sealed.len() as u64 + 1,
            metadata_bytes: metadata_len,
        };
        let mut exact = allowance();
        assert_eq!(
            journal.recover_metadata_bounded(&mut exact).unwrap(),
            vec![item]
        );
        assert_eq!(
            (
                exact.entries,
                exact.records,
                exact.read_bytes,
                exact.metadata_bytes
            ),
            (0, 0, 0, 0)
        );
        for dimension in 0..4 {
            let mut budget = allowance();
            match dimension {
                0 => budget.entries -= 1,
                1 => budget.records -= 1,
                2 => budget.read_bytes -= 1,
                _ => budget.metadata_bytes -= 1,
            }
            assert_eq!(
                journal.recover_metadata_bounded(&mut budget),
                Err(JournalError::ScanLimit)
            );
            assert_eq!(fs::read(&record_path).unwrap(), sealed);
        }
        let snapshot = journal.recover_all().unwrap();
        assert_eq!(snapshot.records[0].content, payload);
        fs::write(
            journal.directory.join(".stage-retained"),
            b"incomplete evidence",
        )
        .unwrap();
        assert_eq!(
            journal.recover_metadata_bounded(&mut MetadataScanBudget::default()),
            Err(JournalError::InvalidState)
        );
        assert_eq!(fs::read(&record_path).unwrap(), sealed);
    }

    #[test]
    fn metadata_discovery_authenticates_recovery_events_after_dropping_bodies() {
        let temp = private_tempdir();
        let journal = EditJournal::open(temp.path(), scope(), TestProtector::new()).unwrap();
        let item = journal
            .append_edit(
                1,
                LocalFileIdentity {
                    volume_serial: 17,
                    file_index: 99,
                },
                "retained.txt",
                Some(baseline()),
                b"retained edit",
            )
            .unwrap();
        let lease = journal.acquire_dispatch_lease(&item.record_id).unwrap();
        journal
            .begin_attempt(
                &lease,
                &item.record_id,
                item.generation,
                ExplicitRecoveryApproval::user_reviewed(),
            )
            .unwrap();
        drop(lease);
        assert_eq!(
            journal
                .recover_metadata_bounded(&mut MetadataScanBudget::default())
                .unwrap(),
            vec![item]
        );
        let event = fs::read_dir(&journal.directory)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|e| e == "evt"))
            .unwrap();
        let mut bytes = fs::read(&event).unwrap();
        bytes[0] ^= 1;
        fs::write(&event, &bytes).unwrap();
        assert_eq!(
            journal.recover_metadata_bounded(&mut MetadataScanBudget::default()),
            Err(JournalError::ProtectionFailed)
        );
        assert_eq!(fs::read(&event).unwrap(), bytes);
    }

    #[test]
    fn existing_only_journal_open_never_recreates_missing_evidence() {
        let temp = private_tempdir();
        assert!(EditJournal::open_existing(temp.path(), scope(), TestProtector::new()).is_err());
        assert!(fs::read_dir(temp.path()).unwrap().next().is_none());
        let journal = EditJournal::open(temp.path(), scope(), TestProtector::new()).unwrap();
        let path = journal.directory.clone();
        drop(journal);
        fs::remove_dir(&path).unwrap();
        assert!(EditJournal::open_existing(temp.path(), scope(), TestProtector::new()).is_err());
        assert!(!path.exists());
    }

    #[test]
    fn snapshots_recover_exact_scope_content_and_conditional_base() {
        let temp = private_tempdir();
        let protector = TestProtector::new();
        let journal = EditJournal::open(temp.path(), scope(), TestProtector::new()).unwrap();
        let payload = b"local edit that must survive restart";
        let metadata = journal
            .append_edit(
                1,
                LocalFileIdentity {
                    volume_serial: 17,
                    file_index: 99,
                },
                "Projects/notes.txt",
                Some(baseline()),
                payload,
            )
            .unwrap();
        drop(journal);

        let reopened = EditJournal::open(temp.path(), scope(), protector).unwrap();
        let recovered = reopened.recover_all().unwrap();
        assert_eq!(recovered.incomplete_staging_files, 0);
        assert_eq!(recovered.records.len(), 1);
        let item = &recovered.records[0];
        assert_eq!(item.metadata, metadata);
        assert_eq!(item.content, payload);
        assert!(item.has_strong_baseline());
        assert_eq!(item.recovered_state(), LocalEditState::Uncertain);
    }

    #[test]
    fn recovery_receipt_persists_actual_put_count_and_reopens_uncertain_attempts() {
        let temp = private_tempdir();
        let protector = TestProtector::new();
        let journal = EditJournal::open(temp.path(), scope(), protector.clone()).unwrap();
        let metadata = journal
            .append_edit(
                1,
                LocalFileIdentity {
                    volume_serial: 17,
                    file_index: 99,
                },
                "Projects/notes.txt",
                Some(baseline()),
                b"local edit",
            )
            .unwrap();
        let lease = journal.acquire_dispatch_lease(&metadata.record_id).unwrap();

        let first = journal
            .begin_attempt(
                &lease,
                &metadata.record_id,
                metadata.generation,
                ExplicitRecoveryApproval::user_reviewed(),
            )
            .unwrap();
        assert_eq!(first, 1);
        drop(lease);
        drop(journal);

        // Simulate process restart: the OS lock is released, while the last
        // durable Attempting marker recovers fail-closed as Uncertain.
        let reopened = EditJournal::open(temp.path(), scope(), protector.clone()).unwrap();
        assert_eq!(
            reopened
                .recover_all()
                .unwrap()
                .recovery_states
                .get(&metadata.record_id),
            Some(&RecoveryAttemptState::Uncertain { attempt_id: 1 })
        );

        // A transient unchanged-baseline check led to a second PUT. The
        // terminal class stays coarse, while the durable receipt retains the
        // actual count for this dispatch and the monotonic attempt identity.
        let resumed_lease = reopened
            .acquire_dispatch_lease(&metadata.record_id)
            .unwrap();
        let second = reopened
            .begin_attempt(
                &resumed_lease,
                &metadata.record_id,
                metadata.generation,
                ExplicitRecoveryApproval::user_reviewed(),
            )
            .unwrap();
        assert_eq!(second, 2);
        reopened
            .record_outcome(
                &resumed_lease,
                &metadata.record_id,
                metadata.generation,
                second,
                2,
                RecoveryAttemptOutcome::Deferred,
            )
            .unwrap();
        drop(resumed_lease);
        drop(reopened);

        let reopened = EditJournal::open(temp.path(), scope(), protector).unwrap();
        let snapshot = reopened.recover_all().unwrap();
        assert_eq!(snapshot.records[0].content, b"local edit");
        assert_eq!(
            snapshot.recovery_states.get(&metadata.record_id),
            Some(&RecoveryAttemptState::Deferred {
                attempt_id: 2,
                attempts: 2,
            })
        );
    }

    #[test]
    fn per_record_dispatch_lease_excludes_a_second_journal_handle() {
        let temp = private_tempdir();
        let first = EditJournal::open(temp.path(), scope(), TestProtector::new()).unwrap();
        let metadata = first
            .append_edit(
                1,
                LocalFileIdentity {
                    volume_serial: 17,
                    file_index: 99,
                },
                "Projects/notes.txt",
                Some(baseline()),
                b"local edit",
            )
            .unwrap();
        let second = EditJournal::open(temp.path(), scope(), TestProtector::new()).unwrap();
        let lease = first.acquire_dispatch_lease(&metadata.record_id).unwrap();
        assert!(second.acquire_dispatch_lease(&metadata.record_id).is_err());
        drop(lease);
        assert!(second.acquire_dispatch_lease(&metadata.record_id).is_ok());
    }

    #[test]
    fn journal_bytes_are_protected_and_authentication_is_scope_bound() {
        let temp = private_tempdir();
        let journal = EditJournal::open(temp.path(), scope(), TestProtector::new()).unwrap();
        let payload = b"highly private synthetic edit bytes";
        journal
            .append_edit(
                1,
                LocalFileIdentity {
                    volume_serial: 17,
                    file_index: 99,
                },
                "private.txt",
                Some(baseline()),
                payload,
            )
            .unwrap();
        let mut paths = Vec::new();
        let mut pending = vec![temp.path().join("cloud-files-edit-journal-v1")];
        while let Some(directory) = pending.pop() {
            for entry in fs::read_dir(directory).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_dir() {
                    pending.push(entry.path());
                } else {
                    paths.push(entry.path());
                }
            }
        }
        let bytes = fs::read(&paths[0]).unwrap();
        assert!(!bytes.windows(payload.len()).any(|window| window == payload));

        // A scope-bound protector rejects a copied record before metadata or
        // local content can be recovered. The test protector authenticates AD.
        let isolated = temp.path().join("other-state");
        fs::create_dir(&isolated).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&isolated, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let other_scope = EditJournalScope {
            account_subject: "subject-b".into(),
            ..scope()
        };
        let other = EditJournal::open(&isolated, other_scope, TestProtector::new()).unwrap();
        let dest = other.directory.join(paths[0].file_name().unwrap());
        fs::copy(&paths[0], dest).unwrap();
        assert_eq!(other.recover_all(), Err(JournalError::ProtectionFailed));
    }

    #[test]
    fn missing_or_weak_remote_baseline_is_retained_but_never_upload_eligible() {
        let temp = private_tempdir();
        let journal = EditJournal::open(temp.path(), scope(), TestProtector::new()).unwrap();
        let no_base = journal
            .append_edit(
                1,
                LocalFileIdentity {
                    volume_serial: 17,
                    file_index: 99,
                },
                "orphan.txt",
                None,
                b"keep locally",
            )
            .unwrap();
        let recovered = journal.recover_all().unwrap();
        assert!(!recovered.records[0].has_strong_baseline());
        assert_eq!(recovered.records[0].metadata, no_base);
        let weak = journal
            .append_edit(
                2,
                LocalFileIdentity {
                    volume_serial: 17,
                    file_index: 100,
                },
                "weak.txt",
                Some(RemoteEditBaseline {
                    etag: "W/\"weak\"".into(),
                    ..baseline()
                }),
                b"preserved",
            )
            .unwrap();
        let records = journal.recover_all().unwrap().records;
        assert_eq!(records.len(), 2);
        assert!(
            !records
                .iter()
                .find(|record| record.metadata.record_id == weak.record_id)
                .unwrap()
                .has_strong_baseline()
        );

        let empty = journal
            .append_edit(
                3,
                LocalFileIdentity {
                    volume_serial: 17,
                    file_index: 101,
                },
                "empty.txt",
                Some(baseline()),
                b"",
            )
            .unwrap();
        let records = journal.recover_all().unwrap().records;
        assert!(records.iter().any(
            |record| record.metadata.record_id == empty.record_id && record.content.is_empty()
        ));
    }

    #[test]
    fn a_failed_protection_step_does_not_replace_or_hide_prior_recovery() {
        let temp = private_tempdir();
        let protector = TestProtector::new();
        let journal = EditJournal::open(temp.path(), scope(), protector.clone()).unwrap();
        journal
            .append_edit(
                1,
                LocalFileIdentity {
                    volume_serial: 17,
                    file_index: 99,
                },
                "notes.txt",
                Some(baseline()),
                b"first durable bytes",
            )
            .unwrap();
        protector.fail_next_seal();
        assert_eq!(
            journal.append_edit(
                2,
                LocalFileIdentity {
                    volume_serial: 17,
                    file_index: 99,
                },
                "notes.txt",
                Some(baseline()),
                b"replacement bytes",
            ),
            Err(JournalError::ProtectionFailed)
        );
        let recovered = journal.recover_all().unwrap();
        assert_eq!(recovered.records.len(), 1);
        assert_eq!(recovered.records[0].content, b"first durable bytes");
    }

    #[test]
    fn invalid_paths_and_wrong_volume_are_rejected_before_persistence() {
        let temp = private_tempdir();
        let journal = EditJournal::open(temp.path(), scope(), TestProtector::new()).unwrap();
        for path in ["", "/absolute", "../escape", "a/../b", "a\\b"] {
            assert!(
                journal
                    .append_edit(
                        1,
                        LocalFileIdentity {
                            volume_serial: 17,
                            file_index: 99,
                        },
                        path,
                        Some(baseline()),
                        b"bytes",
                    )
                    .is_err()
            );
        }
        assert!(
            journal
                .append_edit(
                    1,
                    LocalFileIdentity {
                        volume_serial: 18,
                        file_index: 99,
                    },
                    "safe.txt",
                    Some(baseline()),
                    b"bytes",
                )
                .is_err()
        );
        assert!(journal.recover_all().unwrap().records.is_empty());
    }

    #[test]
    fn interrupted_staging_files_are_reported_and_preserved() {
        let temp = private_tempdir();
        let journal = EditJournal::open(temp.path(), scope(), TestProtector::new()).unwrap();
        let partial = journal.directory.join(".stage-interrupted");
        fs::write(&partial, b"partial protected record").unwrap();
        let recovered = journal.recover_all().unwrap();
        assert_eq!(recovered.incomplete_staging_files, 1);
        assert!(partial.exists());
        assert!(recovered.records.is_empty());
        assert_eq!(
            journal.append_edit(
                1,
                LocalFileIdentity {
                    volume_serial: 17,
                    file_index: 123,
                },
                "later.txt",
                Some(baseline()),
                b"do not obscure the interrupted write",
            ),
            Err(JournalError::ScanLimit)
        );
        assert!(partial.exists());
    }

    #[test]
    fn recovery_retries_when_a_listed_stage_is_published_concurrently() {
        let temp = private_tempdir();
        let journal = EditJournal::open(temp.path(), scope(), TestProtector::new()).unwrap();
        let metadata = journal
            .append_edit(
                1,
                LocalFileIdentity {
                    volume_serial: 17,
                    file_index: 124,
                },
                "concurrent-close.txt",
                Some(baseline()),
                b"durable close callback bytes",
            )
            .unwrap();
        let record_name = record_filename(&metadata.record_id);
        let record_path = journal.directory.join(&record_name);
        let staging_name = ".stage-concurrent-publish";
        let staging_path = journal.directory.join(staging_name);
        fs::rename(&record_path, &staging_path).unwrap();

        let mut published = false;
        let recovered = journal
            .recover_all_with_entry_hook(|name| {
                if name == staging_name && !published {
                    // Model a close callback atomically publishing its
                    // immutable record after read_dir yielded the stage name.
                    fs::rename(&staging_path, &record_path).unwrap();
                    published = true;
                }
            })
            .unwrap();

        assert!(published);
        assert_eq!(recovered.incomplete_staging_files, 0);
        assert_eq!(recovered.records.len(), 1);
        assert_eq!(recovered.records[0].metadata.record_id, metadata.record_id);
        assert_eq!(
            recovered.records[0].content.as_slice(),
            b"durable close callback bytes"
        );
    }

    #[test]
    fn recovery_still_fails_closed_when_a_listed_committed_record_disappears() {
        let temp = private_tempdir();
        let journal = EditJournal::open(temp.path(), scope(), TestProtector::new()).unwrap();
        let metadata = journal
            .append_edit(
                1,
                LocalFileIdentity {
                    volume_serial: 17,
                    file_index: 125,
                },
                "missing-committed-record.txt",
                Some(baseline()),
                b"immutable evidence",
            )
            .unwrap();
        let record_name = record_filename(&metadata.record_id);
        let record_path = journal.directory.join(&record_name);
        let mut removed = false;

        let result = journal.recover_all_with_entry_hook(|name| {
            if name == record_name && !removed {
                fs::remove_file(&record_path).unwrap();
                removed = true;
            }
        });

        assert!(removed);
        assert_eq!(result, Err(JournalError::CorruptRecord));
    }

    #[test]
    fn append_quota_check_rejects_overflow_and_exactly_enforces_total_bound() {
        assert!(!exceeds_byte_limit(90, 10, 100));
        assert!(exceeds_byte_limit(90, 11, 100));
        assert!(exceeds_byte_limit(u64::MAX, 1, u64::MAX));
    }

    #[cfg(windows)]
    #[test]
    fn pinned_journal_directory_cannot_be_renamed_while_open() {
        let temp = private_tempdir();
        let journal = EditJournal::open(temp.path(), scope(), TestProtector::new()).unwrap();
        let replacement = journal.directory.with_extension("moved");
        assert!(fs::rename(&journal.directory, &replacement).is_err());
        journal
            .append_edit(
                1,
                LocalFileIdentity {
                    volume_serial: 17,
                    file_index: 99,
                },
                "still-pinned.txt",
                Some(baseline()),
                b"pinned directory content",
            )
            .unwrap();
        assert!(journal.directory.exists());
        assert!(!replacement.exists());
    }

    #[test]
    fn recovery_rejects_a_reparse_record_instead_of_reading_its_target() {
        let temp = private_tempdir();
        let journal = EditJournal::open(temp.path(), scope(), TestProtector::new()).unwrap();
        let record = journal
            .append_edit(
                1,
                LocalFileIdentity {
                    volume_serial: 17,
                    file_index: 99,
                },
                "link-target.txt",
                Some(baseline()),
                b"synthetic original record",
            )
            .unwrap();
        let record_path = journal.directory.join(format!("{}.edit", record.record_id));
        let external_target = temp.path().join("outside-record");
        fs::write(
            &external_target,
            b"must never be opened through a reparse point",
        )
        .unwrap();
        drop(journal);
        fs::remove_file(&record_path).unwrap();

        #[cfg(unix)]
        std::os::unix::fs::symlink(&external_target, &record_path).unwrap();
        #[cfg(windows)]
        {
            match std::os::windows::fs::symlink_file(&external_target, &record_path) {
                Ok(()) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::Unsupported
                    ) =>
                {
                    println!("journal_reparse_record_test=SKIPPED_OS_LINK_CAPABILITY_UNAVAILABLE");
                    return;
                }
                Err(error) => panic!("create synthetic reparse record: {error}"),
            }
        }
        #[cfg(any(unix, windows))]
        println!("journal_reparse_record_test=CREATED");

        let reopened = EditJournal::open(temp.path(), scope(), TestProtector::new()).unwrap();
        assert_eq!(reopened.recover_all(), Err(JournalError::CorruptRecord));
        assert_eq!(
            fs::read(&external_target).unwrap(),
            b"must never be opened through a reparse point"
        );
    }

    #[cfg(windows)]
    #[test]
    fn journal_directory_identity_is_pinned_against_path_swap() {
        let temp = private_tempdir();
        let journal = EditJournal::open(temp.path(), scope(), TestProtector::new()).unwrap();
        let original = journal.directory.clone();
        let moved = original.with_extension("swap-target");
        assert!(fs::rename(&original, &moved).is_err());
        journal
            .append_edit(
                1,
                LocalFileIdentity {
                    volume_serial: 17,
                    file_index: 99,
                },
                "after-swap-attempt.txt",
                Some(baseline()),
                b"still written under the pinned journal directory",
            )
            .unwrap();
        assert!(original.exists());
        assert!(!moved.exists());
        assert_eq!(journal.recover_all().unwrap().records.len(), 1);
    }

    #[cfg(windows)]
    #[test]
    fn opening_a_reparse_private_state_directory_fails_closed() {
        let temp = private_tempdir();
        let target = temp.path().join("ordinary-target");
        fs::create_dir(&target).unwrap();
        let link = temp.path().join("state-link");
        match std::os::windows::fs::symlink_dir(&target, &link) {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::Unsupported
                ) =>
            {
                return;
            }
            Err(error) => panic!("create synthetic reparse directory: {error}"),
        }
        assert!(EditJournal::open(&link, scope(), TestProtector::new()).is_err());
        assert!(fs::read_dir(&target).unwrap().next().is_none());
    }
}
