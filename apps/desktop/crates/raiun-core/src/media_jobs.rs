//! Bounded configuration contract for recurring, upload-only media imports.
//!
//! This module defines configuration only. The engine owns durable attempts
//! and receipts; it never treats a configured job or queued item as uploaded.

use crate::{
    FolderExclusion, MediaFilter, MediaOrganization, validate_folder_exclusions,
    validate_remote_path,
};
use serde::{Deserialize, Serialize};
use std::path::{Component, PathBuf};

pub const MAX_MEDIA_IMPORT_JOBS: usize = 64;
pub const MAX_MEDIA_JOB_ID_BYTES: usize = 128;
pub const MAX_MEDIA_SOURCE_PATH_BYTES: usize = 4_096;
pub const MIN_MEDIA_SCAN_INTERVAL_SECONDS: u32 = 60;
pub const MAX_MEDIA_SCAN_INTERVAL_SECONDS: u32 = 604_800;
pub const DEFAULT_MEDIA_SCAN_INTERVAL_SECONDS: u32 = 3_600;

/// One opt-in recurring backup job. Upload-only and source-preserving behavior
/// are fixed by this type; there is deliberately no mirror/delete mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaImportJob {
    /// Stable local identifier, limited to ASCII letters, digits, `-`, `_`.
    pub id: String,
    /// Agent-owned configuration revision used to reject stale scheduler and
    /// UI requests. The agent assigns this value on every accepted update.
    #[serde(default = "default_media_job_revision")]
    pub revision: u64,
    /// Stable account identity captured at job creation. Jobs never migrate
    /// implicitly when a profile signs into another server or user.
    #[serde(default)]
    pub account_id: String,
    /// User-selected source folder. It may be unavailable at load time; each
    /// run reports that condition without deleting the job or its receipts.
    pub source_root: PathBuf,
    /// Stable cloud Space identity, not a display name.
    pub space_id: String,
    /// Destination folder within that Space. Root imports are disallowed.
    pub destination_root: String,
    /// Stable provider identity captured when the destination is selected.
    /// A same-path replacement is not silently adopted by an existing job.
    pub destination_root_resource_id: String,
    pub filter: MediaFilter,
    /// Additional typed source exclusions, evaluated before planning.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclusions: Vec<FolderExclusion>,
    pub organization: MediaOrganization,
    /// Filesystem mtime is an explicit UTC organization input; it is never
    /// inferred as capture time and is ignored for `PreserveRelativePath`.
    #[serde(default)]
    pub filesystem_mtime_utc: bool,
    /// Recurring schedule interval. Jobs remain opt-in through `enabled`.
    pub interval_seconds: u32,
    pub enabled: bool,
}

pub fn default_media_scan_interval_seconds() -> u32 {
    DEFAULT_MEDIA_SCAN_INTERVAL_SECONDS
}

pub fn default_media_job_revision() -> u64 {
    1
}

/// Validate a bounded list of media jobs without touching the filesystem or
/// network. Missing volumes and temporary permission failures remain
/// per-run states rather than invalidating a persisted job.
pub fn validate_media_import_jobs(jobs: &[MediaImportJob]) -> Result<(), String> {
    if jobs.len() > MAX_MEDIA_IMPORT_JOBS {
        return Err(format!(
            "at most {MAX_MEDIA_IMPORT_JOBS} media import jobs are allowed"
        ));
    }
    let mut ids = std::collections::BTreeSet::new();
    for job in jobs {
        if !valid_job_id(&job.id) || job.revision == 0 || !ids.insert(job.id.as_str()) {
            return Err("media job IDs must be unique, bounded ASCII identifiers".into());
        }
        if job.account_id.is_empty()
            || job.account_id.len() > 256
            || job.account_id.chars().any(char::is_control)
        {
            return Err(format!(
                "media job '{}' has an invalid account binding",
                job.id
            ));
        }
        if job.space_id.trim().is_empty()
            || job.space_id.len() > 512
            || job.space_id.chars().any(char::is_control)
        {
            return Err(format!("media job '{}' has an invalid Space ID", job.id));
        }
        if job.destination_root_resource_id.trim().is_empty()
            || job.destination_root_resource_id.len() > 4_096
            || job
                .destination_root_resource_id
                .chars()
                .any(char::is_control)
        {
            return Err(format!(
                "media job '{}' has an invalid destination folder identity",
                job.id
            ));
        }
        let Some(source) = job.source_root.to_str() else {
            return Err(format!(
                "media job '{}' source folder must be valid UTF-8",
                job.id
            ));
        };
        if !job.source_root.is_absolute()
            || source.len() > MAX_MEDIA_SOURCE_PATH_BYTES
            || source.chars().any(char::is_control)
            || job
                .source_root
                .components()
                .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
            || !job
                .source_root
                .components()
                .any(|component| matches!(component, Component::Normal(_)))
        {
            return Err(format!(
                "media job '{}' source must be an absolute, bounded folder below the filesystem root",
                job.id
            ));
        }
        validate_remote_path(&job.destination_root)
            .map_err(|_| format!("media job '{}' destination path is invalid", job.id))?;
        let exclusion_errors = validate_folder_exclusions(&job.exclusions);
        if !exclusion_errors.is_empty() {
            return Err(format!(
                "media job '{}' exclusions are invalid: {}",
                job.id,
                exclusion_errors.join("; ")
            ));
        }
        if job.destination_root == "/" {
            return Err(format!(
                "media job '{}' must select a destination folder below the Space root",
                job.id
            ));
        }
        if job.organization == MediaOrganization::UtcYearMonth && !job.filesystem_mtime_utc {
            return Err(format!(
                "media job '{}' UTC year/month organization requires the explicit filesystem-mtime option",
                job.id
            ));
        }
        if !(MIN_MEDIA_SCAN_INTERVAL_SECONDS..=MAX_MEDIA_SCAN_INTERVAL_SECONDS)
            .contains(&job.interval_seconds)
        {
            return Err(format!(
                "media job '{}' interval must be between {MIN_MEDIA_SCAN_INTERVAL_SECONDS} and {MAX_MEDIA_SCAN_INTERVAL_SECONDS} seconds",
                job.id
            ));
        }
    }
    Ok(())
}

fn valid_job_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_MEDIA_JOB_ID_BYTES
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job() -> MediaImportJob {
        MediaImportJob {
            id: "phone-import".into(),
            revision: 1,
            account_id: "account-hash".into(),
            source_root: test_source_root(),
            space_id: "space-1".into(),
            destination_root: "/Personal/Photos".into(),
            destination_root_resource_id: "photos-folder-id".into(),
            filter: MediaFilter::Photos,
            exclusions: Vec::new(),
            organization: MediaOrganization::PreserveRelativePath,
            filesystem_mtime_utc: false,
            interval_seconds: DEFAULT_MEDIA_SCAN_INTERVAL_SECONDS,
            enabled: true,
        }
    }

    #[cfg(unix)]
    fn test_source_root() -> PathBuf {
        PathBuf::from("/home/user/Pictures")
    }

    #[cfg(windows)]
    fn test_source_root() -> PathBuf {
        PathBuf::from(r"C:\Users\user\Pictures")
    }

    #[test]
    fn accepts_bounded_upload_only_job_without_filesystem_access() {
        let mut candidate = job();
        candidate.source_root = if cfg!(windows) {
            PathBuf::from(r"Z:\temporarily-unmounted\Pictures")
        } else {
            PathBuf::from("/Volumes/temporarily-unmounted/Pictures")
        };
        assert!(validate_media_import_jobs(&[candidate]).is_ok());
    }

    #[test]
    fn legacy_media_job_omits_default_exclusions_and_opted_in_rules_round_trip() {
        let candidate = job();
        let mut encoded = serde_json::to_value(&candidate).unwrap();
        assert!(encoded.get("exclusions").is_none());
        encoded["exclusions"] = serde_json::json!([{"kind":"file_type","pattern":"*.tar.gz"}]);
        let decoded: MediaImportJob = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded.exclusions[0].pattern, "*.tar.gz");
        assert_eq!(
            serde_json::from_value::<MediaImportJob>(serde_json::to_value(&decoded).unwrap())
                .unwrap(),
            decoded
        );
    }

    #[test]
    fn rejects_unsafe_identity_paths_and_schedule_bounds() {
        let mut candidate = job();
        candidate.id = "../escape".into();
        assert!(validate_media_import_jobs(&[candidate]).is_err());

        let mut candidate = job();
        candidate.destination_root = "/".into();
        assert!(validate_media_import_jobs(&[candidate]).is_err());

        let mut candidate = job();
        candidate.source_root = if cfg!(windows) {
            PathBuf::from(r"C:\")
        } else {
            PathBuf::from("/")
        };
        assert!(validate_media_import_jobs(&[candidate]).is_err());

        let mut candidate = job();
        candidate.interval_seconds = MIN_MEDIA_SCAN_INTERVAL_SECONDS - 1;
        assert!(validate_media_import_jobs(&[candidate]).is_err());

        let mut candidate = job();
        candidate.organization = MediaOrganization::UtcYearMonth;
        assert!(validate_media_import_jobs(&[candidate]).is_err());
    }

    #[test]
    fn rejects_duplicate_jobs_and_excessive_lists() {
        let candidate = job();
        assert!(validate_media_import_jobs(&[candidate.clone(), candidate]).is_err());
        let jobs = (0..=MAX_MEDIA_IMPORT_JOBS)
            .map(|index| {
                let mut candidate = job();
                candidate.id = format!("job-{index}");
                candidate
            })
            .collect::<Vec<_>>();
        assert!(validate_media_import_jobs(&jobs).is_err());
    }
}
