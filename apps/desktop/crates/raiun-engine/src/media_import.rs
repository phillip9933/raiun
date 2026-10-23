//! Durable, source-preserving media import runs.
//!
//! Job configuration lives in agent Settings. This engine module persists
//! stability observations, upload attempts, and verified receipts. It never
//! deletes or renames a source file, and never treats an ambiguous upload as a
//! receipt.

use crate::{Engine, hash_file, io_error, now_unix};
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt, OpenOptionsMaybeDirExt};
#[cfg(not(windows))]
use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};
use raiun_core::backend::{CloudError, ErrorKind, RemoteEntry, WriteCondition};
use raiun_core::media_scan::{MediaScanOptions, scan_media_dir};
use raiun_core::{
    MediaImportJob, MediaPlanOptions, MediaPlanOutcome, plan_media_import,
    validate_media_import_jobs,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;
#[cfg(not(windows))]
use tempfile::NamedTempFile;
#[cfg(windows)]
#[path = "windows_media_stage.rs"]
mod windows_media_stage;
#[cfg(windows)]
use windows_media_stage::{StageWriter, StagedMedia};

#[cfg(not(windows))]
struct StagedMedia(PathBuf);

#[cfg(not(windows))]
impl StagedMedia {
    fn path(&self) -> &Path {
        &self.0
    }
    fn matches_signature(&mut self, expected: &SourceSignature) -> Result<bool, CloudError> {
        Ok(
            fs::metadata(&self.0).map_err(io_error)?.len() == expected.size
                && hash_file(&self.0)? == expected.sha256,
        )
    }
    fn cleanup(self) -> std::io::Result<()> {
        fs::remove_file(self.0)
    }
}

pub const MEDIA_STABLE_FILE_SECONDS: i64 = 10;
pub const MAX_MEDIA_RECEIPTS_PER_ACCOUNT: i64 = 1_000_000;
pub const MAX_MEDIA_STAGED_FILE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub const MAX_MEDIA_STAGED_TOTAL_BYTES: i64 = 32 * 1024 * 1024 * 1024;
pub const MAX_MEDIA_RECOVERY_PAGE: usize = 100;
#[cfg(windows)]
type MediaSourceRootIdentity = raiun_control_windows::PinnedFileIdentity;
#[cfg(not(windows))]
type MediaSourceRootIdentity = ();

const MEDIA_RUN_CANCELLED: &str = "media job stopped before the next safe processing boundary";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MediaImportReceipt {
    pub job_id: String,
    pub account_id: String,
    pub origin: String,
    pub space_id: String,
    pub source_root: PathBuf,
    pub source_relative_path: String,
    pub destination_path: String,
    pub destination_root_resource_id: String,
    pub source_size: u64,
    pub source_mtime_unix: i64,
    pub source_sha256: String,
    pub remote_resource_id: String,
    pub remote_etag: String,
    pub uploaded_unix: i64,
}

/// Stable, opaque key for the next page of local recovery metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MediaImportRecoveryCursor {
    pub origin: String,
    pub space_id: String,
    pub source_root: String,
    pub source_relative_path: String,
    pub destination_path: String,
}

/// Sanitized local recovery metadata. It never contains staged bytes, hashes,
/// remote IDs, arbitrary provider errors, or a staged-file path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MediaImportRecoveryItem {
    pub origin: String,
    pub space_id: String,
    pub source_root: PathBuf,
    pub source_relative_path: String,
    pub destination_path: String,
    pub state: String,
    /// `None` means this record predates revision binding or was created by a
    /// partial stage operation that has no authenticated attempt row.
    pub configuration_revision: Option<u64>,
    pub attempt_generation: Option<u64>,
    #[serde(default)]
    pub upload_verification_available: bool,
    pub source_size: u64,
    pub updated_unix: Option<i64>,
    pub staged_copy_present: bool,
    pub staged_copy_size: Option<u64>,
    pub stage_generation: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MediaImportRecoveryPage {
    pub items: Vec<MediaImportRecoveryItem>,
    pub has_more: bool,
    pub next_cursor: Option<MediaImportRecoveryCursor>,
    /// Account-level signal only. Unindexed stage names are intentionally not
    /// exposed because there is no authenticated job/path binding for them.
    pub account_has_unindexed_stage: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MediaImportRunStatus {
    pub job_id: String,
    pub generation: u64,
    pub state: String,
    pub scanned: u64,
    pub waiting_for_stability: u64,
    pub uploaded: u64,
    pub unchanged: u64,
    pub conflicts: u64,
    pub needs_attention: u64,
    pub last_error: Option<String>,
    pub updated_unix: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MediaImportRunReport {
    pub job_id: String,
    pub generation: u64,
    pub scanned: u64,
    pub waiting_for_stability: u64,
    pub uploaded: u64,
    pub unchanged: u64,
    pub conflicts: u64,
    pub needs_attention: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SourceSignature {
    size: u64,
    mtime_seconds: i64,
    mtime_nanoseconds: i64,
    sha256: String,
}

impl Engine {
    /// Read durable media status from a known account engine directory without
    /// constructing a live network backend. The caller must derive this path
    /// from the selected profile's persisted account ID, never from a request.
    pub fn media_import_status_at(
        state_dir: &Path,
        job_id: &str,
    ) -> Result<Option<MediaImportRunStatus>, CloudError> {
        validate_media_job_id(job_id)?;
        let Some(db) = open_media_status_db(state_dir)? else {
            return Ok(None);
        };
        db.query_row(
            "SELECT job_id,generation,state,scanned,waiting,uploaded,unchanged,conflicts,attention,last_error,updated_unix FROM media_job_runs WHERE job_id=?1",
            [job_id],
            |row| {
                Ok(MediaImportRunStatus {
                    job_id: row.get(0)?,
                    generation: row.get::<_, i64>(1)?.max(0) as u64,
                    state: row.get(2)?,
                    scanned: row.get::<_, i64>(3)?.max(0) as u64,
                    waiting_for_stability: row.get::<_, i64>(4)?.max(0) as u64,
                    uploaded: row.get::<_, i64>(5)?.max(0) as u64,
                    unchanged: row.get::<_, i64>(6)?.max(0) as u64,
                    conflicts: row.get::<_, i64>(7)?.max(0) as u64,
                    needs_attention: row.get::<_, i64>(8)?.max(0) as u64,
                    last_error: row.get(9)?,
                    updated_unix: row.get(10)?,
                })
            },
        )
        .optional()
        .map_err(crate::db_error)
    }

    /// Persist a scheduler-side block (for example, a source folder that now
    /// overlaps a cloud or recovery root) without scanning the source or
    /// issuing a remote request. The attention state prevents a recurring job
    /// from being silently treated as completed.
    pub fn record_media_import_attention(
        &self,
        job_id: &str,
        message: &str,
    ) -> Result<(), CloudError> {
        validate_media_job_id(job_id)?;
        if message.is_empty() || message.len() > 512 || message.chars().any(char::is_control) {
            return Err(media_error(
                ErrorKind::Unsupported,
                "media attention message is invalid",
            ));
        }
        let now = now_unix();
        let generation = begin_run(self, job_id, now)?;
        finish_run(
            self,
            &MediaImportRunReport {
                job_id: job_id.to_owned(),
                generation,
                ..MediaImportRunReport::default()
            },
            Some(message),
            now,
        )
    }

    /// Read-only unresolved-attempt query for safe configuration removal when
    /// the profile is offline or currently signed into another account.
    pub fn media_import_has_unresolved_at(
        state_dir: &Path,
        job_id: &str,
    ) -> Result<bool, CloudError> {
        validate_media_job_id(job_id)?;
        let Some(db) = open_media_status_db(state_dir)? else {
            return untracked_media_stage_exists(state_dir, None);
        };
        let has_table: bool = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='media_upload_attempts')",
                [],
                |row| row.get(0),
            )
            .map_err(crate::db_error)?;
        if !has_table {
            return untracked_media_stage_exists(state_dir, Some(&db));
        }
        let unresolved: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM media_upload_attempts WHERE job_id=?1 AND state!='uploaded') OR EXISTS(SELECT 1 FROM media_upload_stages WHERE job_id=?1)",
            [job_id],
            |row| row.get(0),
        )
        .map_err(crate::db_error)?;
        Ok(unresolved || untracked_media_stage_exists(state_dir, Some(&db))?)
    }

    /// Read one bounded page of unresolved upload attempts and retained stage
    /// metadata from a profile's account-local engine database. The caller
    /// supplies the expected account ID and job ID from saved profile state;
    /// this method applies both in SQL and never reads staged contents.
    pub fn media_import_recovery_at(
        state_dir: &Path,
        job_id: &str,
        account_id: &str,
        limit: usize,
        cursor: Option<&MediaImportRecoveryCursor>,
    ) -> Result<MediaImportRecoveryPage, CloudError> {
        validate_media_recovery_query(job_id, account_id, limit, cursor)?;
        let Some(db) = open_media_status_db(state_dir)? else {
            return Ok(MediaImportRecoveryPage {
                items: Vec::new(),
                has_more: false,
                next_cursor: None,
                account_has_unindexed_stage: untracked_media_stage_exists(state_dir, None)?,
            });
        };
        media_recovery_page(&db, state_dir, job_id, account_id, limit, cursor)
    }

    /// Read local recovery using this Engine's held database owner. This requires
    /// the exact bound account but deliberately does not require online transport.
    pub fn media_import_recovery(
        &self,
        job_id: &str,
        account_id: &str,
        limit: usize,
        cursor: Option<&MediaImportRecoveryCursor>,
    ) -> Result<MediaImportRecoveryPage, CloudError> {
        validate_media_recovery_query(job_id, account_id, limit, cursor)?;
        if self
            .account_scope
            .as_ref()
            .is_none_or(|scope| scope.account_id != account_id)
        {
            return Err(media_error(
                ErrorKind::Conflict,
                "media recovery account does not match this Engine",
            ));
        }
        let db = self.db()?;
        media_recovery_page(
            &db,
            &self.inner.state_dir,
            job_id,
            account_id,
            limit,
            cursor,
        )
    }

    /// Compare a retained uncertain attempt with the current remote bytes.
    /// This is observation only: no receipts, recovery state or schedules change.
    pub fn verify_media_import_upload(
        &self,
        job: &MediaImportJob,
        attempt_generation: u64,
        source_relative_path: &str,
        destination_path: &str,
    ) -> Result<bool, CloudError> {
        validate_media_import_jobs(std::slice::from_ref(job))
            .map_err(|message| media_error(ErrorKind::Unsupported, message))?;
        let refused = || {
            media_error(
                ErrorKind::Conflict,
                "retained upload cannot be safely verified",
            )
        };
        if attempt_generation == 0
            || attempt_generation > i64::MAX as u64
            || job.revision > i64::MAX as u64
            || !destination_path
                .starts_with(&format!("{}/", job.destination_root.trim_end_matches('/')))
            || destination_path
                .split('/')
                .any(|part| matches!(part, "." | ".."))
        {
            return Err(refused());
        }
        let (account, origin) = self.media_account_scope(job)?;
        let key = scope_key_values(
            job,
            &account,
            &origin,
            source_relative_path,
            destination_path,
        );
        let db = open_media_status_db(&self.inner.state_dir)?.ok_or_else(refused)?;
        // Repeat the exact immutable scope predicate after the remote read, too.
        let read_attempt = || -> Result<(i64, String), CloudError> {
            let running: bool = db.query_row(
                "SELECT EXISTS(SELECT 1 FROM media_job_runs WHERE job_id=?1 AND state='running')",
                [&job.id], |row| row.get(0),
            ).map_err(crate::db_error)?;
            if running {
                return Err(refused());
            }
            db.query_row(
                "SELECT source_size,source_sha256 FROM media_upload_attempts WHERE job_id=?1 AND account_id=?2 AND origin=?3 AND space_id=?4 AND source_root=?5 AND relative_path=?6 AND destination_path=?7 AND generation=?8 AND job_revision=?9 AND destination_root_id=?10 AND state='uncertain'",
                params![key.0,key.1,key.2,key.3,key.4,key.5,key.6,attempt_generation as i64,job.revision as i64,job.destination_root_resource_id],
                |row| Ok((row.get(0)?,row.get(1)?)),
            ).optional().map_err(crate::db_error)?.ok_or_else(refused)
        };
        let attempt = read_attempt()?;
        if attempt.0 < 0
            || attempt.0 as u64 > MAX_MEDIA_STAGED_FILE_BYTES
            || attempt.1.len() != 64
            || !attempt.1.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(refused());
        }
        let check_root = || -> Result<(), CloudError> {
            let root = self.backend.stat(&job.space_id, &job.destination_root)?;
            if root.path != job.destination_root
                || root.id != job.destination_root_resource_id
                || !root.directory
                || root.encrypted
                || !root.writable
            {
                return Err(refused());
            }
            Ok(())
        };
        check_root()?;
        let before = self.backend.stat(&job.space_id, destination_path)?;
        let strong_etag = before.etag.as_bytes();
        if before.path != destination_path
            || before.id.is_empty()
            || before.directory
            || before.encrypted
            || before.size != attempt.0 as u64
            || strong_etag.len() < 2
            || strong_etag.first() != Some(&b'"')
            || strong_etag.last() != Some(&b'"')
            || strong_etag[1..strong_etag.len() - 1]
                .iter()
                .any(|b| !(0x21..=0x7e).contains(b) || *b == b'"')
        {
            return Err(refused());
        }
        // A private disposable directory holds only the conditional remote GET.
        // Never open the source or retained staged copy for this action.
        let directory = tempfile::tempdir().map_err(io_error)?;
        // The real backend atomically publishes a staged file at this name.
        // Keep no empty destination inode open across that replacement.
        let temporary = directory.path().join("uploaded-copy");
        let returned = self.backend.download(
            &job.space_id,
            destination_path,
            Some(&before.etag),
            &temporary,
        )?;
        let after = self.backend.stat(&job.space_id, destination_path)?;
        let same = |entry: &RemoteEntry| {
            entry.id == before.id
                && entry.path == before.path
                && entry.etag == before.etag
                && entry.size == before.size
                && !entry.directory
                && !entry.encrypted
        };
        let matches = same(&returned)
            && same(&after)
            && fs::metadata(&temporary).map_err(io_error)?.len() == attempt.0 as u64
            && hash_file(&temporary)? == attempt.1;
        check_root()?;
        self.media_account_scope(job)?;
        if read_attempt()? != attempt {
            return Err(refused());
        }
        Ok(matches)
    }

    /// Run one recurring media job pass. A candidate must have an unchanged
    /// full-content signature in two scans at least ten seconds apart. This
    /// method performs no source deletion and persists every upload attempt
    /// before issuing a remote mutation.
    pub fn run_media_import_job(
        &self,
        job: &MediaImportJob,
    ) -> Result<MediaImportRunReport, CloudError> {
        self.run_media_import_job_cancellable(job, &|| false)
    }

    /// Run a media pass with a cooperative cancellation check between files
    /// and during large local reads. Cancellation never removes a staged
    /// upload copy or converts an in-flight remote mutation into success.
    pub fn run_media_import_job_cancellable(
        &self,
        job: &MediaImportJob,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<MediaImportRunReport, CloudError> {
        self.run_media_import_job_at_cancellable(job, now_unix(), cancelled)
    }

    /// Read the last durable run summary for one configured job.
    pub fn media_import_status(
        &self,
        job_id: &str,
    ) -> Result<Option<MediaImportRunStatus>, CloudError> {
        if job_id.is_empty() || job_id.len() > 128 {
            return Err(media_error(
                ErrorKind::Unsupported,
                "media job ID is invalid",
            ));
        }
        self.db()?
            .query_row(
                "SELECT job_id,generation,state,scanned,waiting,uploaded,unchanged,conflicts,attention,last_error,updated_unix FROM media_job_runs WHERE job_id=?1",
                [job_id],
                |row| {
                    Ok(MediaImportRunStatus {
                        job_id: row.get(0)?,
                        generation: row.get::<_, i64>(1)?.max(0) as u64,
                        state: row.get(2)?,
                        scanned: row.get::<_, i64>(3)?.max(0) as u64,
                        waiting_for_stability: row.get::<_, i64>(4)?.max(0) as u64,
                        uploaded: row.get::<_, i64>(5)?.max(0) as u64,
                        unchanged: row.get::<_, i64>(6)?.max(0) as u64,
                        conflicts: row.get::<_, i64>(7)?.max(0) as u64,
                        needs_attention: row.get::<_, i64>(8)?.max(0) as u64,
                        last_error: row.get(9)?,
                        updated_unix: row.get(10)?,
                    })
                },
            )
            .optional()
            .map_err(crate::db_error)
    }

    /// Whether a job has an unresolved attempt or a retained staged copy.
    /// Configuration removal is refused while either exists so recovery
    /// remains reachable after an ambiguous upload.
    pub fn media_import_has_unresolved(&self, job_id: &str) -> Result<bool, CloudError> {
        validate_media_job_id(job_id)?;
        let db = self.db()?;
        let unresolved: bool = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM media_upload_attempts WHERE job_id=?1 AND state!='uploaded') OR EXISTS(SELECT 1 FROM media_upload_stages WHERE job_id=?1)",
                [job_id],
                |row| row.get(0),
            )
            .map_err(crate::db_error)?;
        Ok(unresolved || untracked_media_stage_exists(&self.inner.state_dir, Some(&db))?)
    }

    /// Read one receipt by exact source identity. A receipt exists only after
    /// an upload returned a remote entry and full content readback matched.
    pub fn media_import_receipt(
        &self,
        job: &MediaImportJob,
        source_relative_path: &str,
        destination_path: &str,
    ) -> Result<Option<MediaImportReceipt>, CloudError> {
        let (account_id, origin) = self.media_account_scope(job)?;
        load_receipt(
            self,
            job,
            &account_id,
            &origin,
            source_relative_path,
            destination_path,
        )
    }

    #[cfg(test)]
    fn run_media_import_job_at(
        &self,
        job: &MediaImportJob,
        now: i64,
    ) -> Result<MediaImportRunReport, CloudError> {
        self.run_media_import_job_at_cancellable(job, now, &|| false)
    }

    /// Run from the caller's admitted Windows root, retaining its no-delete
    /// ancestor chain and joining its identity to the Engine's opened root.
    #[cfg(windows)]
    pub fn run_media_import_job_from_root_cancellable(
        &self,
        job: &MediaImportJob,
        root: &raiun_control_windows::PinnedDirectory,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<MediaImportRunReport, CloudError> {
        root.verify_path().map_err(io_error)?;
        // The scan joins the opened configured root to this admitted file ID;
        // path spelling is not authority for an independently opened handle.
        let result =
            self.run_media_import_job_with_root(job, now_unix(), cancelled, Some(root.identity()));
        root.verify_path().map_err(io_error)?;
        result
    }

    fn run_media_import_job_at_cancellable(
        &self,
        job: &MediaImportJob,
        now: i64,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<MediaImportRunReport, CloudError> {
        self.run_media_import_job_with_root(job, now, cancelled, None)
    }

    fn run_media_import_job_with_root(
        &self,
        job: &MediaImportJob,
        now: i64,
        cancelled: &dyn Fn() -> bool,
        expected_source_root: Option<MediaSourceRootIdentity>,
    ) -> Result<MediaImportRunReport, CloudError> {
        validate_media_import_jobs(std::slice::from_ref(job))
            .map_err(|message| media_error(ErrorKind::Unsupported, message))?;
        if !job.enabled {
            return Err(media_error(ErrorKind::Unsupported, "media job is disabled"));
        }
        let (account_id, origin) = self.media_account_scope(job)?;
        let generation = begin_run(self, &job.id, now)?;
        let mut report = MediaImportRunReport {
            job_id: job.id.clone(),
            generation,
            ..MediaImportRunReport::default()
        };

        let result = self.run_media_scan(
            job,
            &account_id,
            &origin,
            now,
            &mut report,
            cancelled,
            expected_source_root,
        );
        match result {
            Ok(()) => {
                finish_run(self, &report, None, now)?;
                Ok(report)
            }
            Err(error) => {
                finish_run(self, &report, Some(&error.message), now)?;
                Err(error)
            }
        }
    }

    fn media_account_scope(&self, job: &MediaImportJob) -> Result<(String, String), CloudError> {
        if self.vault_binding.is_some() {
            return Err(media_error(
                ErrorKind::Unsupported,
                "media import requires an ordinary Personal or Space destination",
            ));
        }
        let account = self.account_scope.as_ref().ok_or_else(|| {
            media_error(
                ErrorKind::Unauthorized,
                "media import account is not connected",
            )
        })?;
        if self.backend.server_origin().as_deref() != Some(account.origin.as_str()) {
            return Err(media_error(
                ErrorKind::Conflict,
                "media import account origin changed",
            ));
        }
        if job.account_id != account.account_id {
            return Err(media_error(
                ErrorKind::Unauthorized,
                "media job belongs to a different authenticated account",
            ));
        }
        let space = self
            .backend
            .spaces()?
            .into_iter()
            .find(|space| space.id == job.space_id)
            .ok_or_else(|| {
                media_error(ErrorKind::NotFound, "media destination Space is missing")
            })?;
        if !space.writable || space.encrypted {
            return Err(media_error(
                ErrorKind::Forbidden,
                "media destination must be a writable, unencrypted Space",
            ));
        }
        Ok((account.account_id.clone(), account.origin.clone()))
    }

    #[allow(clippy::too_many_arguments)]
    fn run_media_scan(
        &self,
        job: &MediaImportJob,
        account_id: &str,
        origin: &str,
        now: i64,
        report: &mut MediaImportRunReport,
        cancelled: &dyn Fn() -> bool,
        expected_source_root: Option<MediaSourceRootIdentity>,
    ) -> Result<(), CloudError> {
        check_media_cancelled(cancelled)?;
        #[cfg(not(windows))]
        let _ = expected_source_root;
        // Windows traversal starts from the exact already-open root object;
        // retain the owner and its ancestor pins through scanning and staging.
        #[cfg(windows)]
        let source_root_pin =
            raiun_control_windows::PinnedDirectory::open(&job.source_root).map_err(io_error)?;
        #[cfg(windows)]
        if expected_source_root.is_some_and(|expected| expected != source_root_pin.identity()) {
            return Err(media_error(
                ErrorKind::Conflict,
                "media source root changed after admission",
            ));
        }
        #[cfg(windows)]
        let source_root = Dir::from_std_file(
            source_root_pin
                .try_clone_directory_file()
                .map_err(io_error)?,
        );
        #[cfg(not(windows))]
        let source_root = {
            let source_root = fs::canonicalize(&job.source_root).map_err(io_error)?;
            let root_metadata = fs::symlink_metadata(&job.source_root).map_err(io_error)?;
            if source_root != job.source_root
                || root_metadata.file_type().is_symlink()
                || !root_metadata.is_dir()
            {
                return Err(media_error(
                    ErrorKind::Conflict,
                    "media source folder changed identity",
                ));
            }
            // Retain one opened directory capability for scanning, signature
            // checks, and staging. Reopening the configured string for each file
            // would let an ancestor/root replacement redirect later reads.
            let opened_root =
                Dir::open_ambient_dir(&source_root, ambient_authority()).map_err(io_error)?;
            let opened_metadata = opened_root.dir_metadata().map_err(io_error)?;
            if !opened_metadata.is_dir() {
                return Err(media_error(
                    ErrorKind::Conflict,
                    "media source folder changed identity",
                ));
            }
            #[cfg(unix)]
            {
                if cap_fs_ext::MetadataExt::dev(&opened_metadata)
                    != std::os::unix::fs::MetadataExt::dev(&root_metadata)
                    || cap_fs_ext::MetadataExt::ino(&opened_metadata)
                        != std::os::unix::fs::MetadataExt::ino(&root_metadata)
                {
                    return Err(media_error(
                        ErrorKind::Conflict,
                        "media source folder changed identity",
                    ));
                }
            }
            opened_root
        };
        let scan = scan_media_dir(
            &source_root,
            MediaScanOptions {
                filesystem_mtime_utc: job.filesystem_mtime_utc,
            },
        )
        .map_err(|error| media_error(ErrorKind::Io, error.to_string()))?;
        report.scanned = scan.sources.len() as u64;
        if !scan.complete || scan.truncated {
            report.needs_attention = 1;
            return Err(media_error(
                ErrorKind::Io,
                "media source scan was incomplete; no candidates from this pass were uploaded",
            ));
        }
        let options = MediaPlanOptions {
            destination_root: job.destination_root.clone(),
            filter: job.filter,
            organization: job.organization,
        };
        let plan = plan_media_import(&scan.sources, &options, &[])
            .map_err(|error| media_error(ErrorKind::Unsupported, error.to_string()))?;
        for item in plan {
            check_media_cancelled(cancelled)?;
            match item.outcome {
                MediaPlanOutcome::Planned { destination_path } => {
                    let signature =
                        source_signature(&source_root, &item.source_relative_path, cancelled)?;
                    let readiness = observe_candidate(
                        self,
                        job,
                        account_id,
                        origin,
                        &item.source_relative_path,
                        &destination_path,
                        &signature,
                        now,
                    )?;
                    match readiness {
                        CandidateReadiness::Waiting => {
                            report.waiting_for_stability += 1;
                            continue;
                        }
                        CandidateReadiness::Attention => {
                            report.needs_attention += 1;
                            continue;
                        }
                        CandidateReadiness::Ready => {}
                    }
                    check_media_cancelled(cancelled)?;
                    self.ensure_media_destination_parent(job, &destination_path)?;
                    match self.upload_media_candidate(
                        job,
                        account_id,
                        origin,
                        &item.source_relative_path,
                        &source_root,
                        &destination_path,
                        &signature,
                        report.generation,
                        now,
                        cancelled,
                    )? {
                        CandidateOutcome::Uploaded => report.uploaded += 1,
                        CandidateOutcome::Unchanged => report.unchanged += 1,
                        CandidateOutcome::Conflict => report.conflicts += 1,
                        CandidateOutcome::Attention => report.needs_attention += 1,
                    }
                }
                MediaPlanOutcome::Filtered => {}
                MediaPlanOutcome::Collision { .. } | MediaPlanOutcome::Rejected { .. } => {
                    report.conflicts += 1;
                }
                MediaPlanOutcome::MissingUtcDate => {
                    report.needs_attention += 1;
                }
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn upload_media_candidate(
        &self,
        job: &MediaImportJob,
        account_id: &str,
        origin: &str,
        relative_path: &str,
        source_root: &Dir,
        destination_path: &str,
        signature: &SourceSignature,
        run_generation: u64,
        now: i64,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<CandidateOutcome, CloudError> {
        check_media_cancelled(cancelled)?;
        let current = source_signature(source_root, relative_path, cancelled)?;
        if &current != signature {
            update_candidate_attention(
                self,
                job,
                account_id,
                origin,
                relative_path,
                destination_path,
                "source changed after stability observation",
                now,
            )?;
            return Ok(CandidateOutcome::Attention);
        }
        let _execution = self.execution()?;
        let receipt = load_receipt(
            self,
            job,
            account_id,
            origin,
            relative_path,
            destination_path,
        )?;
        let (base, prior) = match receipt {
            Some(receipt) => {
                if receipt.destination_root_resource_id != job.destination_root_resource_id {
                    mark_candidate_conflict(
                        self,
                        job,
                        account_id,
                        origin,
                        relative_path,
                        destination_path,
                        "destination root identity changed since the verified receipt",
                        now,
                    )?;
                    return Ok(CandidateOutcome::Conflict);
                }
                let remote = self.backend.stat(&job.space_id, destination_path)?;
                if remote.directory
                    || remote.id != receipt.remote_resource_id
                    || remote.etag != receipt.remote_etag
                {
                    mark_candidate_conflict(
                        self,
                        job,
                        account_id,
                        origin,
                        relative_path,
                        destination_path,
                        "destination identity changed since the verified receipt",
                        now,
                    )?;
                    return Ok(CandidateOutcome::Conflict);
                }
                if signature.sha256 == receipt.source_sha256
                    && signature.size == receipt.source_size
                {
                    mark_candidate_uploaded(
                        self,
                        job,
                        account_id,
                        origin,
                        relative_path,
                        destination_path,
                        now,
                    )?;
                    return Ok(CandidateOutcome::Unchanged);
                }
                (
                    WriteCondition::Match(receipt.remote_etag.clone()),
                    Some(receipt),
                )
            }
            None => match self.backend.stat(&job.space_id, destination_path) {
                Ok(_) => {
                    mark_candidate_conflict(
                        self,
                        job,
                        account_id,
                        origin,
                        relative_path,
                        destination_path,
                        "destination already exists without a matching media receipt",
                        now,
                    )?;
                    return Ok(CandidateOutcome::Conflict);
                }
                Err(error) if error.kind == ErrorKind::NotFound => (WriteCondition::Absent, None),
                Err(error) => return Err(error),
            },
        };
        let mut staged = stage_source_file(self, source_root, relative_path, signature, cancelled)?;
        let staged_path = staged.path().to_path_buf();
        if let Err(error) = check_media_cancelled(cancelled) {
            let _ = staged.cleanup();
            return Err(error);
        }
        let attempt = match begin_attempt(
            self,
            job,
            account_id,
            origin,
            relative_path,
            destination_path,
            signature,
            prior.as_ref(),
            run_generation,
            now,
            &staged_path,
        ) {
            Ok(attempt) => attempt,
            Err(error) => {
                // A durable attempt may have committed before an ambiguous
                // database error. Keep the private Windows copy for recovery.
                #[cfg(not(windows))]
                let _ = staged.cleanup();
                return Err(error);
            }
        };
        let staged_path = PathBuf::from(&attempt.staged_path);
        let uploaded = self.upload_inner(None, &job.space_id, destination_path, &staged_path, base);
        match uploaded {
            Ok(remote) => {
                let still_same = staged
                    .matches_signature(signature)
                    .and_then(|staged_same| {
                        if !staged_same {
                            return Ok(false);
                        }
                        source_signature(source_root, relative_path, &|| false)
                            .map(|source_after| &source_after == signature)
                    })
                    .unwrap_or(false);
                if !still_same {
                    finish_attempt(
                        self,
                        &attempt,
                        "uncertain",
                        Some("source changed while upload was running"),
                        now,
                    )?;
                    mark_candidate_attention(
                        self,
                        job,
                        account_id,
                        origin,
                        relative_path,
                        destination_path,
                        "source changed while upload was running",
                        now,
                    )?;
                    return Ok(CandidateOutcome::Attention);
                }
                if let Err(_error) = save_verified_receipt(
                    self,
                    job,
                    account_id,
                    origin,
                    relative_path,
                    destination_path,
                    signature,
                    &remote,
                    &attempt,
                    now,
                ) {
                    finish_attempt(
                        self,
                        &attempt,
                        "uncertain",
                        Some("remote content verified but local receipt could not be committed"),
                        now,
                    )?;
                    mark_candidate_attention(
                        self,
                        job,
                        account_id,
                        origin,
                        relative_path,
                        destination_path,
                        "remote content verified but local receipt could not be committed",
                        now,
                    )?;
                    return Ok(CandidateOutcome::Attention);
                }
                let _ = staged.cleanup();
                Ok(CandidateOutcome::Uploaded)
            }
            Err(error) => {
                let state = if error.kind == ErrorKind::Conflict {
                    "conflict"
                } else {
                    "uncertain"
                };
                finish_attempt(self, &attempt, state, Some(&error.message), now)?;
                update_candidate_attention(
                    self,
                    job,
                    account_id,
                    origin,
                    relative_path,
                    destination_path,
                    &error.message,
                    now,
                )?;
                if state == "conflict" {
                    Ok(CandidateOutcome::Conflict)
                } else {
                    Ok(CandidateOutcome::Attention)
                }
            }
        }
    }

    fn ensure_media_destination_parent(
        &self,
        job: &MediaImportJob,
        destination: &str,
    ) -> Result<(), CloudError> {
        let root = self.backend.stat(&job.space_id, &job.destination_root)?;
        if root.id != job.destination_root_resource_id
            || !root.directory
            || !root.writable
            || root.encrypted
        {
            return Err(media_error(
                ErrorKind::Forbidden,
                "media destination root is not a writable ordinary folder",
            ));
        }
        let parent = destination
            .rsplit_once('/')
            .map(|(parent, _)| parent)
            .ok_or_else(|| {
                media_error(
                    ErrorKind::Unsupported,
                    "planned media destination has no parent",
                )
            })?;
        let relative = parent.strip_prefix(&job.destination_root).ok_or_else(|| {
            media_error(
                ErrorKind::Unsupported,
                "planned media destination escaped its selected folder",
            )
        })?;
        let mut current = job.destination_root.clone();
        for component in relative
            .split('/')
            .filter(|component| !component.is_empty())
        {
            current.push('/');
            current.push_str(component);
            match self.backend.stat(&job.space_id, &current) {
                Ok(entry) if entry.directory && entry.writable && !entry.encrypted => {}
                Ok(_) => {
                    return Err(media_error(
                        ErrorKind::Conflict,
                        "media destination parent is not a writable folder",
                    ));
                }
                Err(error) if error.kind == ErrorKind::NotFound => {
                    match self.backend.mkdir(&job.space_id, &current) {
                        Ok(entry) if entry.directory && entry.writable && !entry.encrypted => {}
                        Ok(_) => {
                            return Err(media_error(
                                ErrorKind::InvalidResponse,
                                "provider created an invalid media folder",
                            ));
                        }
                        Err(create_error) => match self.backend.stat(&job.space_id, &current) {
                            Ok(entry) if entry.directory && entry.writable && !entry.encrypted => {}
                            _ => return Err(create_error),
                        },
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidateOutcome {
    Uploaded,
    Unchanged,
    Conflict,
    Attention,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidateReadiness {
    Waiting,
    Ready,
    Attention,
}

fn media_error(kind: ErrorKind, message: impl Into<String>) -> CloudError {
    CloudError::new(kind, message)
}

fn validate_media_job_id(job_id: &str) -> Result<(), CloudError> {
    if job_id.is_empty()
        || job_id.len() > 128
        || !job_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(media_error(
            ErrorKind::Unsupported,
            "media job ID is invalid",
        ));
    }
    Ok(())
}

fn sanitized_recovery_state(
    state: &str,
    attempt_generation: i64,
    stage_generation: Option<i64>,
) -> String {
    if stage_generation.is_some_and(|generation| generation != attempt_generation) {
        return "stage_mismatch".to_owned();
    }
    match state {
        "uncertain" => "uncertain",
        "conflict" => "conflict",
        "attention" | "failed" => "attention",
        "running" => "interrupted",
        "uploaded" => "stage_cleanup",
        _ => "needs_attention",
    }
    .to_owned()
}

fn validate_media_recovery_query(
    job_id: &str,
    account_id: &str,
    limit: usize,
    cursor: Option<&MediaImportRecoveryCursor>,
) -> Result<(), CloudError> {
    validate_media_job_id(job_id)?;
    if account_id.is_empty()
        || account_id.len() > 256
        || account_id.chars().any(char::is_control)
        || !(1..=MAX_MEDIA_RECOVERY_PAGE).contains(&limit)
    {
        return Err(media_error(
            ErrorKind::Unsupported,
            "media recovery scope or page size is invalid",
        ));
    }
    if let Some(cursor) = cursor {
        for value in [
            &cursor.origin,
            &cursor.space_id,
            &cursor.source_root,
            &cursor.source_relative_path,
            &cursor.destination_path,
        ] {
            if value.is_empty() || value.len() > 4_096 || value.chars().any(char::is_control) {
                return Err(media_error(
                    ErrorKind::Unsupported,
                    "media recovery cursor is invalid",
                ));
            }
        }
    }
    Ok(())
}

// Inputs are validated by both entry points before the database is accessed.
fn media_recovery_page(
    db: &Connection,
    state_dir: &Path,
    job_id: &str,
    account_id: &str,
    limit: usize,
    cursor: Option<&MediaImportRecoveryCursor>,
) -> Result<MediaImportRecoveryPage, CloudError> {
    let has_attempt_table: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='media_upload_attempts')",
            [],
            |row| row.get(0),
        )
        .map_err(crate::db_error)?;
    if !has_attempt_table {
        return Ok(MediaImportRecoveryPage {
            items: Vec::new(),
            has_more: false,
            next_cursor: None,
            account_has_unindexed_stage: untracked_media_stage_exists(state_dir, Some(db))?,
        });
    }
    let has_stage_table: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='media_upload_stages')",
            [],
            |row| row.get(0),
        )
        .map_err(crate::db_error)?;
    if !has_stage_table {
        return Err(media_error(
            ErrorKind::Io,
            "media recovery index is incomplete; retained data was not changed",
        ));
    }
    let after = cursor.map(|cursor| {
        (
            cursor.origin.as_str(),
            cursor.space_id.as_str(),
            cursor.source_root.as_str(),
            cursor.source_relative_path.as_str(),
            cursor.destination_path.as_str(),
        )
    });
    let fetch_limit = (limit + 1) as i64;
    let root_column: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('media_upload_attempts') WHERE name='destination_root_id')",
        [], |row| row.get(0),
    ).map_err(crate::db_error)?;
    let root_expression = if root_column {
        "a.destination_root_id"
    } else {
        "NULL"
    };
    let mut collected = BTreeMap::new();
    let mut statement = db
        .prepare(
            &format!("SELECT a.source_root,a.relative_path,a.destination_path,a.origin,a.space_id,a.generation,a.state,a.source_size,a.updated_unix,s.staged_path,s.staged_size,s.attempt_generation,a.job_revision,{root_expression} FROM media_upload_attempts a LEFT JOIN media_upload_stages s ON s.job_id=a.job_id AND s.account_id=a.account_id AND s.origin=a.origin AND s.space_id=a.space_id AND s.source_root=a.source_root AND s.relative_path=a.relative_path AND s.destination_path=a.destination_path WHERE a.job_id=?1 AND a.account_id=?2 AND (a.state!='uploaded' OR s.job_id IS NOT NULL) AND (?3 IS NULL OR (a.origin,a.space_id,a.source_root,a.relative_path,a.destination_path)>(?3,?4,?5,?6,?7)) ORDER BY a.origin,a.space_id,a.source_root,a.relative_path,a.destination_path LIMIT ?8"),
        )
        .map_err(crate::db_error)?;
    let rows = statement
        .query_map(
            params![
                job_id,
                account_id,
                after.map(|key| key.0),
                after.map(|key| key.1),
                after.map(|key| key.2),
                after.map(|key| key.3),
                after.map(|key| key.4),
                fetch_limit
            ],
            |row| {
                let source_root: String = row.get(0)?;
                let relative_path: String = row.get(1)?;
                let destination_path: String = row.get(2)?;
                let origin: String = row.get(3)?;
                let space_id: String = row.get(4)?;
                let generation: i64 = row.get(5)?;
                let raw_state: String = row.get(6)?;
                let source_size: i64 = row.get(7)?;
                let updated_unix: i64 = row.get(8)?;
                let staged_path: Option<String> = row.get(9)?;
                let staged_size: Option<i64> = row.get(10)?;
                let stage_generation: Option<i64> = row.get(11)?;
                let configuration_revision: i64 = row.get(12)?;
                let destination_root: Option<String> = row.get(13)?;
                let stage_size = staged_size
                    .filter(|size| *size >= 0)
                    .map(|size| size as u64);
                let stage_present = staged_path
                    .as_deref()
                    .zip(stage_size)
                    .is_some_and(|(path, size)| media_stage_file_matches(state_dir, path, size));
                let state = sanitized_recovery_state(&raw_state, generation, stage_generation);
                Ok((
                    (
                        origin.clone(),
                        space_id.clone(),
                        source_root.clone(),
                        relative_path.clone(),
                        destination_path.clone(),
                    ),
                    MediaImportRecoveryItem {
                        origin,
                        space_id,
                        source_root: PathBuf::from(source_root),
                        source_relative_path: relative_path,
                        destination_path,
                        upload_verification_available: state == "uncertain"
                            && generation > 0
                            && configuration_revision > 0
                            && destination_root.is_some_and(|root| !root.is_empty()),
                        state,
                        configuration_revision: u64::try_from(configuration_revision)
                            .ok()
                            .filter(|revision| *revision > 0),
                        attempt_generation: u64::try_from(generation).ok(),
                        source_size: source_size.max(0) as u64,
                        updated_unix: Some(updated_unix),
                        staged_copy_present: stage_present,
                        staged_copy_size: stage_size,
                        stage_generation: stage_generation
                            .and_then(|generation| u64::try_from(generation).ok()),
                    },
                ))
            },
        )
        .map_err(crate::db_error)?;
    for row in rows {
        let (key, item) = row.map_err(crate::db_error)?;
        collected.insert(key, item);
    }
    drop(statement);

    let mut statement = db
        .prepare(
            "SELECT s.source_root,s.relative_path,s.destination_path,s.origin,s.space_id,s.attempt_generation,s.staged_path,s.staged_size FROM media_upload_stages s WHERE s.job_id=?1 AND s.account_id=?2 AND NOT EXISTS (SELECT 1 FROM media_upload_attempts a WHERE a.job_id=s.job_id AND a.account_id=s.account_id AND a.origin=s.origin AND a.space_id=s.space_id AND a.source_root=s.source_root AND a.relative_path=s.relative_path AND a.destination_path=s.destination_path) AND (?3 IS NULL OR (s.origin,s.space_id,s.source_root,s.relative_path,s.destination_path)>(?3,?4,?5,?6,?7)) ORDER BY s.origin,s.space_id,s.source_root,s.relative_path,s.destination_path LIMIT ?8",
        )
        .map_err(crate::db_error)?;
    let rows = statement
        .query_map(
            params![
                job_id,
                account_id,
                after.map(|key| key.0),
                after.map(|key| key.1),
                after.map(|key| key.2),
                after.map(|key| key.3),
                after.map(|key| key.4),
                fetch_limit
            ],
            |row| {
                let source_root: String = row.get(0)?;
                let relative_path: String = row.get(1)?;
                let destination_path: String = row.get(2)?;
                let origin: String = row.get(3)?;
                let space_id: String = row.get(4)?;
                let stage_generation: i64 = row.get(5)?;
                let staged_path: String = row.get(6)?;
                let staged_size: i64 = row.get(7)?;
                let stage_size = u64::try_from(staged_size).ok();
                let stage_present = stage_size
                    .is_some_and(|size| media_stage_file_matches(state_dir, &staged_path, size));
                Ok((
                    (
                        origin.clone(),
                        space_id.clone(),
                        source_root.clone(),
                        relative_path.clone(),
                        destination_path.clone(),
                    ),
                    MediaImportRecoveryItem {
                        origin,
                        space_id,
                        source_root: PathBuf::from(source_root),
                        source_relative_path: relative_path,
                        destination_path,
                        state: "stage_only".to_owned(),
                        configuration_revision: None,
                        upload_verification_available: false,
                        attempt_generation: None,
                        source_size: stage_size.unwrap_or_default(),
                        updated_unix: None,
                        staged_copy_present: stage_present,
                        staged_copy_size: stage_size,
                        stage_generation: u64::try_from(stage_generation).ok(),
                    },
                ))
            },
        )
        .map_err(crate::db_error)?;
    for row in rows {
        let (key, item) = row.map_err(crate::db_error)?;
        collected.entry(key).or_insert(item);
    }
    drop(statement);

    let mut rows: Vec<_> = collected.into_iter().collect();
    rows.sort_by(|left, right| left.0.cmp(&right.0));
    let has_more = rows.len() > limit;
    rows.truncate(limit);
    let next_cursor = if has_more {
        rows.last().map(|(key, _)| MediaImportRecoveryCursor {
            origin: key.0.clone(),
            space_id: key.1.clone(),
            source_root: key.2.clone(),
            source_relative_path: key.3.clone(),
            destination_path: key.4.clone(),
        })
    } else {
        None
    };
    Ok(MediaImportRecoveryPage {
        items: rows.into_iter().map(|(_, item)| item).collect(),
        has_more,
        next_cursor,
        account_has_unindexed_stage: untracked_media_stage_exists(state_dir, Some(db))?,
    })
}

#[cfg(windows)]
fn media_stage_file_matches(state_dir: &Path, stored_path: &str, expected_size: u64) -> bool {
    let Ok(Some(directory)) = windows_media_stage::existing_directory(state_dir) else {
        return false;
    };
    let candidate = Path::new(stored_path);
    if candidate.parent() != Some(directory.path()) {
        return false;
    }
    let Some(name) = candidate.file_name() else {
        return false;
    };
    let Ok(reader) = directory.open_owned_immutable_file(name) else {
        return false;
    };
    reader
        .metadata()
        .is_ok_and(|metadata| metadata.is_file() && metadata.len() == expected_size)
}

#[cfg(not(windows))]
fn media_stage_file_matches(state_dir: &Path, stored_path: &str, expected_size: u64) -> bool {
    let staging_dir = state_dir.join("media-staging");
    let Ok(directory_metadata) = fs::symlink_metadata(&staging_dir) else {
        return false;
    };
    if !directory_metadata.is_dir() || directory_metadata.file_type().is_symlink() {
        return false;
    }
    let Ok(staging_dir) = fs::canonicalize(staging_dir) else {
        return false;
    };
    let candidate = Path::new(stored_path);
    if candidate.parent() != Some(staging_dir.as_path()) {
        return false;
    }
    let Ok(file_metadata) = fs::symlink_metadata(candidate) else {
        return false;
    };
    file_metadata.is_file()
        && !file_metadata.file_type().is_symlink()
        && file_metadata.len() == expected_size
}

fn open_media_status_db(state_dir: &Path) -> Result<Option<Connection>, CloudError> {
    let directory = match fs::symlink_metadata(state_dir) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => metadata,
        Ok(_) => {
            return Err(media_error(
                ErrorKind::Unsupported,
                "media account state directory is unsafe",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error(error)),
    };
    let _ = directory;
    let path = state_dir.join("engine.sqlite3");
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => metadata,
        Ok(_) => {
            return Err(media_error(
                ErrorKind::Unsupported,
                "media account database is unsafe",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error(error)),
    };
    let _ = metadata;
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map(Some)
    .map_err(crate::db_error)
}

fn check_media_cancelled(cancelled: &dyn Fn() -> bool) -> Result<(), CloudError> {
    if cancelled() {
        Err(media_error(ErrorKind::Offline, MEDIA_RUN_CANCELLED))
    } else {
        Ok(())
    }
}

fn source_signature(
    root: &Dir,
    relative: &str,
    cancelled: &dyn Fn() -> bool,
) -> Result<SourceSignature, CloudError> {
    let mut file = open_source_file(root, relative)?;
    let before = file.metadata().map_err(io_error)?;
    if !before.is_file() {
        return Err(media_error(
            ErrorKind::Unsupported,
            "media source must be a regular non-symlink file",
        ));
    }
    let sha256 = hash_reader(&mut file, cancelled)?;
    let after = file.metadata().map_err(io_error)?;
    if before.len() != after.len() || before.modified().ok() != after.modified().ok() {
        return Err(media_error(
            ErrorKind::Conflict,
            "media source changed while checking its signature",
        ));
    }
    let modified = after.modified().map_err(io_error)?;
    let duration = modified
        .into_std()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    Ok(SourceSignature {
        size: after.len(),
        mtime_seconds: duration.as_secs().min(i64::MAX as u64) as i64,
        mtime_nanoseconds: duration.subsec_nanos() as i64,
        sha256,
    })
}

fn media_reparse_point(metadata: &cap_std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use cap_std::fs::MetadataExt;
        metadata.file_attributes() & 0x0000_0400 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

fn open_source_file(root: &Dir, relative: &str) -> Result<cap_std::fs::File, CloudError> {
    let mut directory = root.try_clone().map_err(io_error)?;
    let mut components = relative.split('/').peekable();
    while let Some(component) = components.next() {
        if component.is_empty() || matches!(component, "." | "..") {
            return Err(media_error(
                ErrorKind::Unsupported,
                "media relative path is invalid",
            ));
        }
        if components.peek().is_some() {
            let mut options = OpenOptions::new();
            options
                .read(true)
                .follow(FollowSymlinks::No)
                .maybe_dir(true);
            #[cfg(unix)]
            {
                use cap_std::fs::OpenOptionsExt;
                options.custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32);
            }
            #[cfg(windows)]
            {
                use cap_std::fs::OpenOptionsExt;
                // Retain directory identity without preventing ordinary writes.
                options.share_mode(0x0000_0001 | 0x0000_0002);
            }
            let handle = directory.open_with(component, &options).map_err(io_error)?;
            let metadata = handle.metadata().map_err(io_error)?;
            if !metadata.is_dir() || media_reparse_point(&metadata) {
                return Err(media_error(
                    ErrorKind::Conflict,
                    "media source parent changed identity",
                ));
            }
            directory = Dir::from_std_file(handle.into_std());
            continue;
        }
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            options.custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32);
        }
        #[cfg(windows)]
        {
            use cap_std::fs::OpenOptionsExt;
            // FILE_SHARE_READ alone excludes writers and deletion during reads.
            options.share_mode(0x0000_0001);
        }
        let file = directory.open_with(component, &options).map_err(io_error)?;
        let metadata = file.metadata().map_err(io_error)?;
        if !metadata.is_file() || media_reparse_point(&metadata) {
            return Err(media_error(
                ErrorKind::Unsupported,
                "media source must be a regular non-symlink file",
            ));
        }
        return Ok(file);
    }
    Err(media_error(
        ErrorKind::Unsupported,
        "media relative path is empty",
    ))
}

fn hash_reader(reader: &mut impl Read, cancelled: &dyn Fn() -> bool) -> Result<String, CloudError> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 128 * 1024];
    loop {
        check_media_cancelled(cancelled)?;
        let count = reader.read(&mut buffer).map_err(io_error)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn stage_source_file(
    engine: &Engine,
    root: &Dir,
    relative: &str,
    expected: &SourceSignature,
    cancelled: &dyn Fn() -> bool,
) -> Result<StagedMedia, CloudError> {
    if expected.size > MAX_MEDIA_STAGED_FILE_BYTES {
        return Err(media_error(
            ErrorKind::Unsupported,
            "media file exceeds the staging size limit",
        ));
    }
    let mut staged = new_stage_writer(engine, expected.size)?;
    let mut source = open_source_file(root, relative)?;
    let before = source.metadata().map_err(io_error)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 128 * 1024];
    let mut size = 0u64;
    loop {
        check_media_cancelled(cancelled)?;
        let count = source.read(&mut buffer).map_err(io_error)?;
        if count == 0 {
            break;
        }
        size = size
            .checked_add(count as u64)
            .ok_or_else(|| media_error(ErrorKind::Io, "media file size overflow"))?;
        if size > MAX_MEDIA_STAGED_FILE_BYTES {
            return Err(media_error(
                ErrorKind::Unsupported,
                "media file exceeds the staging size limit",
            ));
        }
        staged.write_all(&buffer[..count]).map_err(io_error)?;
        hasher.update(&buffer[..count]);
    }
    staged.as_file().sync_all().map_err(io_error)?;
    let after = source.metadata().map_err(io_error)?;
    let duration = after
        .modified()
        .map_err(io_error)?
        .into_std()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let actual = SourceSignature {
        size,
        mtime_seconds: duration.as_secs().min(i64::MAX as u64) as i64,
        mtime_nanoseconds: duration.subsec_nanos() as i64,
        sha256: format!("{:x}", hasher.finalize()),
    };
    if !before.is_file()
        || !after.is_file()
        || before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
        || &actual != expected
    {
        return Err(media_error(
            ErrorKind::Conflict,
            "source changed while preparing its immutable upload copy",
        ));
    }
    finish_staged_file(staged, expected)
}

#[cfg(not(windows))]
fn new_stage_writer(engine: &Engine, size: u64) -> Result<NamedTempFile, CloudError> {
    let staging_dir = engine.inner.state_dir.join("media-staging");
    let staging_existed = fs::symlink_metadata(&staging_dir).is_ok();
    fs::create_dir_all(&staging_dir).map_err(io_error)?;
    let staging_metadata = fs::symlink_metadata(&staging_dir).map_err(io_error)?;
    if staging_metadata.file_type().is_symlink() || !staging_metadata.is_dir() {
        return Err(media_error(
            ErrorKind::Unsupported,
            "media staging directory must be a private real directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&staging_dir, fs::Permissions::from_mode(0o700)).map_err(io_error)?;
    }
    if !staging_existed {
        sync_media_directory(&engine.inner.state_dir)?;
    }
    let staged_total = staging_directory_bytes(&staging_dir)?;
    if staged_total.saturating_add(size) > MAX_MEDIA_STAGED_TOTAL_BYTES as u64 {
        return Err(media_error(
            ErrorKind::Io,
            "media staging quota is full; unresolved copies were preserved",
        ));
    }
    NamedTempFile::new_in(&staging_dir).map_err(io_error)
}

#[cfg(windows)]
fn new_stage_writer(engine: &Engine, size: u64) -> Result<StageWriter, CloudError> {
    if windows_media_stage::directory_bytes(engine)?.saturating_add(size)
        > MAX_MEDIA_STAGED_TOTAL_BYTES as u64
    {
        return Err(media_error(
            ErrorKind::Io,
            "media staging quota is full; unresolved copies were preserved",
        ));
    }
    StageWriter::create(engine)
}

#[cfg(not(windows))]
fn finish_staged_file(
    staged: NamedTempFile,
    _expected: &SourceSignature,
) -> Result<StagedMedia, CloudError> {
    let (_, path) = staged.keep().map_err(|error| io_error(error.error))?;
    sync_media_directory(path.parent().expect("media stage parent"))?;
    Ok(StagedMedia(path))
}

#[cfg(windows)]
fn finish_staged_file(
    staged: StageWriter,
    expected: &SourceSignature,
) -> Result<StagedMedia, CloudError> {
    staged.finish(expected)
}

#[cfg(any(not(windows), test))]
fn staging_directory_bytes(path: &Path) -> Result<u64, CloudError> {
    let mut total = 0u64;
    let mut entries = 0usize;
    for entry in fs::read_dir(path).map_err(io_error)? {
        entries += 1;
        if entries > 100_000 {
            return Err(media_error(
                ErrorKind::Io,
                "media staging directory exceeds the bounded entry limit",
            ));
        }
        let entry = entry.map_err(io_error)?;
        let kind = entry.file_type().map_err(io_error)?;
        if !kind.is_file() {
            return Err(media_error(
                ErrorKind::Unsupported,
                "media staging contains an unresolved non-file entry",
            ));
        }
        total = total
            .checked_add(entry.metadata().map_err(io_error)?.len())
            .ok_or_else(|| media_error(ErrorKind::Io, "media staging size overflow"))?;
    }
    Ok(total)
}

fn untracked_media_stage_exists(
    state_dir: &Path,
    db: Option<&Connection>,
) -> Result<bool, CloudError> {
    #[cfg(windows)]
    let private_directory =
        match windows_media_stage::existing_directory(state_dir).map_err(io_error)? {
            Some(directory) => directory,
            None => return Ok(false),
        };
    let staging_dir = state_dir.join("media-staging");
    let metadata = match fs::symlink_metadata(&staging_dir) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => metadata,
        Ok(_) => {
            return Err(media_error(
                ErrorKind::Unsupported,
                "media staging directory is unsafe",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(io_error(error)),
    };
    let _ = metadata;
    let known_paths = if let Some(db) = db {
        let has_table: bool = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='media_upload_stages')",
                [],
                |row| row.get(0),
            )
            .map_err(crate::db_error)?;
        if has_table {
            let mut statement = db
                .prepare("SELECT staged_path FROM media_upload_stages")
                .map_err(crate::db_error)?;
            let rows = statement
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(crate::db_error)?;
            let mut paths = BTreeSet::new();
            for path in rows {
                if paths.len() >= 100_000 {
                    return Err(media_error(
                        ErrorKind::Io,
                        "media stage index exceeds the bounded entry limit",
                    ));
                }
                paths.insert(path.map_err(crate::db_error)?);
            }
            paths
        } else {
            BTreeSet::new()
        }
    } else {
        BTreeSet::new()
    };
    let mut entries = 0usize;
    for entry in fs::read_dir(&staging_dir).map_err(io_error)? {
        entries += 1;
        if entries > 100_000 {
            return Err(media_error(
                ErrorKind::Io,
                "media staging directory exceeds the bounded entry limit",
            ));
        }
        let entry = entry.map_err(io_error)?;
        // Every enumerated child must still satisfy the protected private-file
        // policy; a pathname or generic regular-file attribute is insufficient.
        #[cfg(windows)]
        let _reader = private_directory
            .open_owned_immutable_file(&entry.file_name())
            .map_err(io_error)?;
        if !entry.file_type().map_err(io_error)?.is_file() {
            return Err(media_error(
                ErrorKind::Unsupported,
                "media staging contains an unresolved non-file entry",
            ));
        }
        let path = entry.path().into_os_string().into_string().map_err(|_| {
            media_error(
                ErrorKind::Unsupported,
                "media stage path is not valid UTF-8",
            )
        })?;
        if !known_paths.contains(&path) {
            return Ok(true);
        }
    }
    #[cfg(windows)]
    private_directory.verify_path().map_err(io_error)?;
    Ok(false)
}

#[cfg(unix)]
fn sync_media_directory(path: &Path) -> Result<(), CloudError> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(io_error)
}

#[cfg(all(not(unix), not(windows)))]
fn sync_media_directory(_path: &Path) -> Result<(), CloudError> {
    Ok(())
}

fn begin_run(engine: &Engine, job_id: &str, now: i64) -> Result<u64, CloudError> {
    let _execution = engine.execution()?;
    let mut db = engine.db()?;
    let tx = db.transaction().map_err(crate::db_error)?;
    let existing: Option<(i64, String)> = tx
        .query_row(
            "SELECT generation,state FROM media_job_runs WHERE job_id=?1",
            [job_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(crate::db_error)?;
    let generation = if let Some((generation, state)) = existing {
        if state == "running" {
            return Err(media_error(
                ErrorKind::Conflict,
                "media job is already running",
            ));
        }
        generation
            .checked_add(1)
            .filter(|next| *next > 0)
            .ok_or_else(|| media_error(ErrorKind::Io, "media job generation exhausted"))?
    } else {
        1
    };
    tx.execute(
        "INSERT INTO media_job_runs(job_id,generation,state,scanned,waiting,uploaded,unchanged,conflicts,attention,last_error,updated_unix) VALUES(?1,?2,'running',0,0,0,0,0,0,NULL,?3) ON CONFLICT(job_id) DO UPDATE SET generation=excluded.generation,state='running',scanned=0,waiting=0,uploaded=0,unchanged=0,conflicts=0,attention=0,last_error=NULL,updated_unix=excluded.updated_unix",
        params![job_id, generation, now],
    )
    .map_err(crate::db_error)?;
    tx.commit().map_err(crate::db_error)?;
    Ok(generation as u64)
}

fn finish_run(
    engine: &Engine,
    report: &MediaImportRunReport,
    error: Option<&str>,
    now: i64,
) -> Result<(), CloudError> {
    let state = if error == Some(MEDIA_RUN_CANCELLED) {
        "interrupted"
    } else if error.is_some() || report.conflicts > 0 || report.needs_attention > 0 {
        "attention"
    } else {
        "completed"
    };
    engine
        .db()?
        .execute(
            "UPDATE media_job_runs SET state=?1,scanned=?2,waiting=?3,uploaded=?4,unchanged=?5,conflicts=?6,attention=?7,last_error=?8,updated_unix=?9 WHERE job_id=?10 AND generation=?11 AND state='running'",
            params![state, report.scanned as i64, report.waiting_for_stability as i64, report.uploaded as i64, report.unchanged as i64, report.conflicts as i64, report.needs_attention as i64, error, now, report.job_id, report.generation as i64],
        )
        .map_err(crate::db_error)?;
    Ok(())
}

fn scope_key_values(
    job: &MediaImportJob,
    account_id: &str,
    origin: &str,
    relative_path: &str,
    destination_path: &str,
) -> (String, String, String, String, String, String, String) {
    (
        job.id.clone(),
        account_id.to_owned(),
        origin.to_owned(),
        job.space_id.clone(),
        job.source_root.to_string_lossy().into_owned(),
        relative_path.to_owned(),
        destination_path.to_owned(),
    )
}

// These arguments are the exact durable scope key; keeping them explicit at
// the SQLite boundary makes every predicate visible to review.
#[allow(clippy::too_many_arguments)]
fn observe_candidate(
    engine: &Engine,
    job: &MediaImportJob,
    account_id: &str,
    origin: &str,
    relative_path: &str,
    destination_path: &str,
    signature: &SourceSignature,
    now: i64,
) -> Result<CandidateReadiness, CloudError> {
    let key = scope_key_values(job, account_id, origin, relative_path, destination_path);
    let db = engine.db()?;
    let previous: Option<(i64, i64, i64, String, i64, String)> = db
        .query_row(
            "SELECT source_size,mtime_seconds,mtime_nanoseconds,source_sha256,first_seen_unix,state FROM media_candidates WHERE job_id=?1 AND account_id=?2 AND origin=?3 AND space_id=?4 AND source_root=?5 AND relative_path=?6 AND destination_path=?7",
            params![key.0,key.1,key.2,key.3,key.4,key.5,key.6],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
        )
        .optional()
        .map_err(crate::db_error)?;
    drop(db);
    if previous.as_ref().is_some_and(|(_, _, _, _, _, state)| {
        matches!(state.as_str(), "uncertain" | "conflict" | "attention")
    }) {
        return Ok(CandidateReadiness::Attention);
    }
    let same = previous
        .as_ref()
        .is_some_and(|(size, mtime, mtime_ns, hash, _, _)| {
            *size == signature.size as i64
                && *mtime == signature.mtime_seconds
                && *mtime_ns == signature.mtime_nanoseconds
                && hash == &signature.sha256
        });
    let first_seen = if same {
        previous.as_ref().map(|row| row.4).unwrap_or(now)
    } else {
        now
    };
    let db = engine.db()?;
    db.execute(
        "INSERT INTO media_candidates(job_id,account_id,origin,space_id,source_root,relative_path,destination_path,source_size,mtime_seconds,mtime_nanoseconds,source_sha256,first_seen_unix,last_seen_unix,state,message) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,'waiting',NULL) ON CONFLICT(job_id,account_id,origin,space_id,source_root,relative_path,destination_path) DO UPDATE SET source_size=excluded.source_size,mtime_seconds=excluded.mtime_seconds,mtime_nanoseconds=excluded.mtime_nanoseconds,source_sha256=excluded.source_sha256,first_seen_unix=?12,last_seen_unix=?13,state='waiting',message=NULL",
        params![key.0,key.1,key.2,key.3,key.4,key.5,key.6,signature.size as i64,signature.mtime_seconds,signature.mtime_nanoseconds,signature.sha256,first_seen,now],
    )
    .map_err(crate::db_error)?;
    Ok(
        if same && now.saturating_sub(first_seen) >= MEDIA_STABLE_FILE_SECONDS {
            CandidateReadiness::Ready
        } else {
            CandidateReadiness::Waiting
        },
    )
}

fn load_receipt(
    engine: &Engine,
    job: &MediaImportJob,
    account_id: &str,
    origin: &str,
    relative_path: &str,
    destination_path: &str,
) -> Result<Option<MediaImportReceipt>, CloudError> {
    let key = scope_key_values(job, account_id, origin, relative_path, destination_path);
    engine
        .db()?
        .query_row(
            "SELECT destination_root_id,source_size,mtime_seconds,source_sha256,remote_resource_id,remote_etag,uploaded_unix FROM media_import_receipts WHERE job_id=?1 AND account_id=?2 AND origin=?3 AND space_id=?4 AND source_root=?5 AND relative_path=?6 AND destination_path=?7",
            params![key.0,key.1,key.2,key.3,key.4,key.5,key.6],
            |row| {
                Ok(MediaImportReceipt {
                    job_id: key.0.clone(),
                    account_id: key.1.clone(),
                    origin: key.2.clone(),
                    space_id: key.3.clone(),
                    source_root: PathBuf::from(&key.4),
                    source_relative_path: key.5.clone(),
                    destination_path: key.6.clone(),
                    destination_root_resource_id: row.get(0)?,
                    source_size: row.get::<_, i64>(1)?.max(0) as u64,
                    source_mtime_unix: row.get(2)?,
                    source_sha256: row.get(3)?,
                    remote_resource_id: row.get(4)?,
                    remote_etag: row.get(5)?,
                    uploaded_unix: row.get(6)?,
                })
            },
        )
        .optional()
        .map_err(crate::db_error)
}

#[derive(Debug, Clone)]
struct AttemptKey {
    scope: (String, String, String, String, String, String, String),
    generation: i64,
    staged_path: String,
}

#[allow(clippy::too_many_arguments)]
fn begin_attempt(
    engine: &Engine,
    job: &MediaImportJob,
    account_id: &str,
    origin: &str,
    relative_path: &str,
    destination_path: &str,
    signature: &SourceSignature,
    prior: Option<&MediaImportReceipt>,
    run_generation: u64,
    now: i64,
    staged_path: &Path,
) -> Result<AttemptKey, CloudError> {
    let job_revision = i64::try_from(job.revision)
        .map_err(|_| media_error(ErrorKind::Io, "media job revision cannot be stored safely"))?;
    let key = scope_key_values(job, account_id, origin, relative_path, destination_path);
    #[cfg(windows)]
    let staged_total = windows_media_stage::directory_bytes(engine)?;
    #[cfg(not(windows))]
    let staged_total = staging_directory_bytes(&engine.inner.state_dir.join("media-staging"))?;
    let staged_size = fs::metadata(staged_path).map_err(io_error)?.len();
    let mut db = engine.db()?;
    let tx = db.transaction().map_err(crate::db_error)?;
    if staged_total > MAX_MEDIA_STAGED_TOTAL_BYTES as u64 {
        return Err(media_error(
            ErrorKind::Io,
            "media staging quota is full; unresolved copies were preserved",
        ));
    }
    let receipt_count: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM media_import_receipts WHERE account_id=?1",
            [&key.1],
            |row| row.get(0),
        )
        .map_err(crate::db_error)?;
    let receipt_exists: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM media_import_receipts WHERE job_id=?1 AND account_id=?2 AND origin=?3 AND space_id=?4 AND source_root=?5 AND relative_path=?6 AND destination_path=?7)",
            params![key.0,key.1,key.2,key.3,key.4,key.5,key.6],
            |row| row.get(0),
        )
        .map_err(crate::db_error)?;
    if receipt_count >= MAX_MEDIA_RECEIPTS_PER_ACCOUNT && !receipt_exists {
        return Err(media_error(
            ErrorKind::Io,
            "media receipt limit reached; existing receipts and source files were preserved",
        ));
    }
    let existing: Option<(i64, String, String)> = tx
        .query_row(
            "SELECT generation,state,source_sha256 FROM media_upload_attempts WHERE job_id=?1 AND account_id=?2 AND origin=?3 AND space_id=?4 AND source_root=?5 AND relative_path=?6 AND destination_path=?7",
            params![key.0,key.1,key.2,key.3,key.4,key.5,key.6],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(crate::db_error)?;
    let generation = match existing {
        Some((_, state, _)) if state != "uploaded" => {
            return Err(media_error(
                ErrorKind::Conflict,
                "media upload has an unresolved previous attempt",
            ));
        }
        Some((generation, _, _)) => generation.checked_add(1).ok_or_else(|| {
            media_error(ErrorKind::Io, "media upload attempt generation exhausted")
        })?,
        None => 1,
    };
    tx.execute(
        "INSERT INTO media_upload_attempts(job_id,account_id,origin,space_id,source_root,relative_path,destination_path,generation,job_revision,run_generation,state,source_size,mtime_seconds,mtime_nanoseconds,source_sha256,base_remote_id,base_etag,message,updated_unix,destination_root_id) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'running',?11,?12,?13,?14,?15,?16,NULL,?17,?18) ON CONFLICT(job_id,account_id,origin,space_id,source_root,relative_path,destination_path) DO UPDATE SET generation=excluded.generation,job_revision=excluded.job_revision,destination_root_id=excluded.destination_root_id,run_generation=excluded.run_generation,state='running',source_size=excluded.source_size,mtime_seconds=excluded.mtime_seconds,mtime_nanoseconds=excluded.mtime_nanoseconds,source_sha256=excluded.source_sha256,base_remote_id=excluded.base_remote_id,base_etag=excluded.base_etag,message=NULL,updated_unix=excluded.updated_unix",
        params![key.0,key.1,key.2,key.3,key.4,key.5,key.6,generation,job_revision,run_generation as i64,signature.size as i64,signature.mtime_seconds,signature.mtime_nanoseconds,signature.sha256,prior.map(|receipt| receipt.remote_resource_id.as_str()),prior.map(|receipt| receipt.remote_etag.as_str()),now,job.destination_root_resource_id],
    )
    .map_err(crate::db_error)?;
    tx.execute(
        "UPDATE media_candidates SET state='uploading',message=NULL,last_seen_unix=?1 WHERE job_id=?2 AND account_id=?3 AND origin=?4 AND space_id=?5 AND source_root=?6 AND relative_path=?7 AND destination_path=?8",
        params![now,key.0,key.1,key.2,key.3,key.4,key.5,key.6],
    )
    .map_err(crate::db_error)?;
    tx.execute(
        "INSERT INTO media_upload_stages(job_id,account_id,origin,space_id,source_root,relative_path,destination_path,attempt_generation,staged_path,staged_size) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10) ON CONFLICT(job_id,account_id,origin,space_id,source_root,relative_path,destination_path) DO UPDATE SET attempt_generation=excluded.attempt_generation,staged_path=excluded.staged_path,staged_size=excluded.staged_size",
        params![key.0,key.1,key.2,key.3,key.4,key.5,key.6,generation,staged_path.to_string_lossy(),staged_size.min(i64::MAX as u64) as i64],
    )
    .map_err(crate::db_error)?;
    tx.commit().map_err(crate::db_error)?;
    Ok(AttemptKey {
        scope: key,
        generation,
        staged_path: staged_path.to_string_lossy().into_owned(),
    })
}

fn finish_attempt(
    engine: &Engine,
    attempt: &AttemptKey,
    state: &str,
    error: Option<&str>,
    now: i64,
) -> Result<(), CloudError> {
    let changed = engine.db()?.execute(
            "UPDATE media_upload_attempts SET state=?1,message=?2,updated_unix=?3 WHERE job_id=?4 AND account_id=?5 AND origin=?6 AND space_id=?7 AND source_root=?8 AND relative_path=?9 AND destination_path=?10 AND generation=?11 AND state='running'",
            params![state,error,now,attempt.scope.0,attempt.scope.1,attempt.scope.2,attempt.scope.3,attempt.scope.4,attempt.scope.5,attempt.scope.6,attempt.generation],
        ).map_err(crate::db_error)?;
    if changed != 1 {
        return Err(media_error(
            ErrorKind::Conflict,
            "media upload attempt state changed before completion",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn save_verified_receipt(
    engine: &Engine,
    job: &MediaImportJob,
    account_id: &str,
    origin: &str,
    relative_path: &str,
    destination_path: &str,
    signature: &SourceSignature,
    remote: &RemoteEntry,
    attempt: &AttemptKey,
    now: i64,
) -> Result<(), CloudError> {
    let key = scope_key_values(job, account_id, origin, relative_path, destination_path);
    let mut db = engine.db()?;
    let tx = db.transaction().map_err(crate::db_error)?;
    let claimed = tx
        .execute(
            "UPDATE media_upload_attempts SET state='uploaded',message=NULL,updated_unix=?1 WHERE job_id=?2 AND account_id=?3 AND origin=?4 AND space_id=?5 AND source_root=?6 AND relative_path=?7 AND destination_path=?8 AND generation=?9 AND state='running'",
            params![now,attempt.scope.0,attempt.scope.1,attempt.scope.2,attempt.scope.3,attempt.scope.4,attempt.scope.5,attempt.scope.6,attempt.generation],
        )
        .map_err(crate::db_error)?;
    if claimed != 1 {
        return Err(media_error(
            ErrorKind::Conflict,
            "media upload attempt was superseded before receipt commit",
        ));
    }
    let count: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM media_import_receipts WHERE account_id=?1",
            [&key.1],
            |row| row.get(0),
        )
        .map_err(crate::db_error)?;
    let exists: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM media_import_receipts WHERE job_id=?1 AND account_id=?2 AND origin=?3 AND space_id=?4 AND source_root=?5 AND relative_path=?6 AND destination_path=?7)",
            params![key.0,key.1,key.2,key.3,key.4,key.5,key.6],
            |row| row.get(0),
        )
        .map_err(crate::db_error)?;
    if count >= MAX_MEDIA_RECEIPTS_PER_ACCOUNT && !exists {
        return Err(media_error(
            ErrorKind::Io,
            "media receipt limit reached; existing receipts and source files were preserved",
        ));
    }
    tx.execute(
        "INSERT INTO media_import_receipts(job_id,account_id,origin,space_id,source_root,relative_path,destination_path,destination_root_id,source_size,mtime_seconds,source_sha256,remote_resource_id,remote_etag,uploaded_unix) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14) ON CONFLICT(job_id,account_id,origin,space_id,source_root,relative_path,destination_path) DO UPDATE SET destination_root_id=excluded.destination_root_id,source_size=excluded.source_size,mtime_seconds=excluded.mtime_seconds,source_sha256=excluded.source_sha256,remote_resource_id=excluded.remote_resource_id,remote_etag=excluded.remote_etag,uploaded_unix=excluded.uploaded_unix",
        params![key.0,key.1,key.2,key.3,key.4,key.5,key.6,job.destination_root_resource_id,signature.size as i64,signature.mtime_seconds,signature.sha256,remote.id,remote.etag,now],
    )
    .map_err(crate::db_error)?;
    tx.execute(
        "UPDATE media_candidates SET state='uploaded',message=NULL,last_seen_unix=?1 WHERE job_id=?2 AND account_id=?3 AND origin=?4 AND space_id=?5 AND source_root=?6 AND relative_path=?7 AND destination_path=?8",
        params![now,key.0,key.1,key.2,key.3,key.4,key.5,key.6],
    )
    .map_err(crate::db_error)?;
    tx.execute(
        "DELETE FROM media_upload_stages WHERE job_id=?1 AND account_id=?2 AND origin=?3 AND space_id=?4 AND source_root=?5 AND relative_path=?6 AND destination_path=?7 AND attempt_generation=?8",
        params![attempt.scope.0,attempt.scope.1,attempt.scope.2,attempt.scope.3,attempt.scope.4,attempt.scope.5,attempt.scope.6,attempt.generation],
    )
    .map_err(crate::db_error)?;
    tx.commit().map_err(crate::db_error)
}

fn mark_candidate_uploaded(
    engine: &Engine,
    job: &MediaImportJob,
    account_id: &str,
    origin: &str,
    relative_path: &str,
    destination_path: &str,
    now: i64,
) -> Result<(), CloudError> {
    set_candidate_state(
        engine,
        job,
        account_id,
        origin,
        relative_path,
        destination_path,
        "uploaded",
        None,
        now,
    )
}

#[allow(clippy::too_many_arguments)]
fn mark_candidate_conflict(
    engine: &Engine,
    job: &MediaImportJob,
    account_id: &str,
    origin: &str,
    relative_path: &str,
    destination_path: &str,
    message: &str,
    now: i64,
) -> Result<(), CloudError> {
    set_candidate_state(
        engine,
        job,
        account_id,
        origin,
        relative_path,
        destination_path,
        "conflict",
        Some(message),
        now,
    )
}

#[allow(clippy::too_many_arguments)]
fn mark_candidate_attention(
    engine: &Engine,
    job: &MediaImportJob,
    account_id: &str,
    origin: &str,
    relative_path: &str,
    destination_path: &str,
    message: &str,
    now: i64,
) -> Result<(), CloudError> {
    set_candidate_state(
        engine,
        job,
        account_id,
        origin,
        relative_path,
        destination_path,
        "attention",
        Some(message),
        now,
    )
}

#[allow(clippy::too_many_arguments)]
fn update_candidate_attention(
    engine: &Engine,
    job: &MediaImportJob,
    account_id: &str,
    origin: &str,
    relative_path: &str,
    destination_path: &str,
    message: &str,
    now: i64,
) -> Result<(), CloudError> {
    mark_candidate_attention(
        engine,
        job,
        account_id,
        origin,
        relative_path,
        destination_path,
        message,
        now,
    )
}

#[allow(clippy::too_many_arguments)]
fn set_candidate_state(
    engine: &Engine,
    job: &MediaImportJob,
    account_id: &str,
    origin: &str,
    relative_path: &str,
    destination_path: &str,
    state: &str,
    message: Option<&str>,
    now: i64,
) -> Result<(), CloudError> {
    let key = scope_key_values(job, account_id, origin, relative_path, destination_path);
    engine.db()?.execute(
        "UPDATE media_candidates SET state=?1,message=?2,last_seen_unix=?3 WHERE job_id=?4 AND account_id=?5 AND origin=?6 AND space_id=?7 AND source_root=?8 AND relative_path=?9 AND destination_path=?10",
        params![state,message,now,key.0,key.1,key.2,key.3,key.4,key.5,key.6],
    ).map_err(crate::db_error)?;
    Ok(())
}

#[cfg(test)]
mod tests;
