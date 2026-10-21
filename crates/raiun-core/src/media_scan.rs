//! Bounded, read-only source-folder scanner for the media import preview.
//!
//! The scanner does not wait for a stable-file interval and does not claim that
//! a file will remain unchanged after scanning. It compares metadata immediately
//! before and after a small signature read, and excludes files whose metadata
//! changed during that read. All paths below the selected root are accessed
//! through a directory capability.

use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt, OpenOptionsMaybeDirExt};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};
use cap_std::time::{SystemClock, SystemTime};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::ffi::OsString;
use std::fmt;
use std::io::{self, Read};
use std::path::Path;
use time::OffsetDateTime;

use crate::media_plan::{MediaKind, MediaSource, MediaUtcMonth};

/// Maximum directory depth below the chosen source root.
pub const MAX_MEDIA_SCAN_DEPTH: usize = 64;
/// Maximum number of filesystem entries inspected, including directories.
pub const MAX_MEDIA_SCAN_ENTRIES: usize = 10_000;
/// Maximum combined UTF-8 relative path bytes accepted from a scan.
pub const MAX_MEDIA_SCAN_PATH_BYTES: usize = 8 * 1024 * 1024;
/// Maximum prefix bytes read from each regular file for signature detection.
pub const MAX_MEDIA_SCAN_SNIFF_BYTES: usize = 64 * 1024;
/// Maximum detailed warnings retained in a scan report.
pub const MAX_MEDIA_SCAN_WARNINGS: usize = 256;

/// Scanner choices. Filesystem dates are opt-in and always interpreted as UTC.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MediaScanOptions {
    pub filesystem_mtime_utc: bool,
}

/// Bounded results from a single local folder scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaScanReport {
    pub sources: Vec<MediaSource>,
    pub warnings: Vec<MediaScanWarning>,
    pub warnings_omitted: usize,
    pub entries_scanned: usize,
    pub path_bytes_scanned: usize,
    /// True only when the walk finished without skipped, unreadable, unstable,
    /// or resource-limited entries. Signature warnings do not make the walk
    /// incomplete; unknown files are represented as `MediaKind::Other`.
    pub complete: bool,
    pub truncated: bool,
}

/// A filename-scoped diagnostic. No file contents are included.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaScanWarning {
    pub relative_path: Option<String>,
    pub kind: MediaScanWarningKind,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaScanWarningKind {
    SymlinkSkipped,
    SpecialFileSkipped,
    UnsupportedType,
    Unreadable,
    Unstable,
    InvalidPath,
    DepthLimit,
    EntryLimit,
    PathLimit,
}

#[derive(Debug)]
pub enum MediaScanError {
    SourcePathMustBeAbsolute,
    CannotOpenSource(io::Error),
    SourceIsNotDirectory,
}

impl fmt::Display for MediaScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourcePathMustBeAbsolute => write!(f, "source folder must be an absolute path"),
            Self::CannotOpenSource(error) => write!(f, "cannot open source folder: {error}"),
            Self::SourceIsNotDirectory => write!(f, "source path is not a directory"),
        }
    }
}

impl std::error::Error for MediaScanError {}

/// Scan one explicitly selected folder using bounded, directory-relative reads.
///
/// Names must be valid UTF-8 to enter the portable media manifest. Hidden files
/// are included. Symlinks and special files are skipped; symlinks are never
/// intentionally followed. `cap-std` keeps any raced path resolution beneath
/// the opened source root. The scanner reads at most 64 KiB from each regular
/// file and emits no file content.
pub fn scan_media_folder(
    source_root: &Path,
    options: MediaScanOptions,
) -> Result<MediaScanReport, MediaScanError> {
    if !source_root.is_absolute() {
        return Err(MediaScanError::SourcePathMustBeAbsolute);
    }
    let root = Dir::open_ambient_dir(source_root, ambient_authority())
        .map_err(MediaScanError::CannotOpenSource)?;
    scan_media_dir(&root, options)
}

/// Scan an already-open source directory capability. Callers that need to
/// keep source identity stable across a multi-step operation can hold this
/// capability and use it for both enumeration and later file reads.
pub fn scan_media_dir(
    root: &Dir,
    options: MediaScanOptions,
) -> Result<MediaScanReport, MediaScanError> {
    if !root
        .dir_metadata()
        .map_err(MediaScanError::CannotOpenSource)?
        .is_dir()
    {
        return Err(MediaScanError::SourceIsNotDirectory);
    }

    let mut report = MediaScanReport {
        sources: Vec::new(),
        warnings: Vec::new(),
        warnings_omitted: 0,
        entries_scanned: 0,
        path_bytes_scanned: 0,
        complete: true,
        truncated: false,
    };
    let mut stop = false;
    visit_directory(root, "", 0, options, &mut report, &mut stop);
    report
        .sources
        .sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok(report)
}

// An entry can change to a FIFO between enumeration and open. Nonblocking
// opens let the subsequent handle metadata check reject it without hanging.
fn avoid_blocking_special_file_open(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32);
    }
    #[cfg(not(unix))]
    let _ = options;
}

fn visit_directory(
    dir: &Dir,
    relative_dir: &str,
    depth: usize,
    options: MediaScanOptions,
    report: &mut MediaScanReport,
    stop: &mut bool,
) {
    if *stop {
        return;
    }
    let mut entries = Vec::new();
    let iterator = match dir.entries() {
        Ok(iterator) => iterator,
        Err(_) => {
            warn(
                report,
                nonempty(relative_dir),
                MediaScanWarningKind::Unreadable,
                "Could not list this directory.",
                true,
            );
            return;
        }
    };
    for entry in iterator {
        // Charge entries while discovering them, before retaining them. The
        // shared budget bounds all ancestor vectors, not just one directory.
        if report.entries_scanned >= MAX_MEDIA_SCAN_ENTRIES {
            mark_truncated(
                report,
                nonempty(relative_dir),
                MediaScanWarningKind::EntryLimit,
                "Scan entry limit reached; remaining entries were not scanned.",
            );
            *stop = true;
            return;
        }
        report.entries_scanned += 1;
        match entry {
            Ok(entry) => entries.push(entry),
            Err(_) => warn(
                report,
                nonempty(relative_dir),
                MediaScanWarningKind::Unreadable,
                "A directory entry could not be read.",
                true,
            ),
        }
    }
    entries.sort_by(|a, b| os_string_cmp(&a.file_name(), &b.file_name()));

    for entry in entries {
        if *stop {
            return;
        }
        let name: OsString = entry.file_name();
        let Some(name_utf8) = name.to_str() else {
            warn(
                report,
                None,
                MediaScanWarningKind::InvalidPath,
                "A filename is not UTF-8 and was skipped.",
                true,
            );
            continue;
        };
        // Manifest paths use `/` on every platform. A literal backslash is
        // valid in Unix filenames but cannot be represented without changing
        // source identity, so reject it instead of rewriting it.
        if name_utf8.contains('/') || name_utf8.contains('\\') {
            warn(
                report,
                nonempty(relative_dir),
                MediaScanWarningKind::InvalidPath,
                "Filename cannot be represented as a portable relative path and was skipped.",
                true,
            );
            continue;
        }
        let relative_string = if relative_dir.is_empty() {
            name_utf8.to_string()
        } else {
            format!("{relative_dir}/{name_utf8}")
        };
        let path_size = relative_string.len();
        if path_size > crate::media_plan::MAX_MEDIA_PATH_BYTES
            || report.path_bytes_scanned.saturating_add(path_size) > MAX_MEDIA_SCAN_PATH_BYTES
        {
            mark_truncated(
                report,
                Some(relative_string.clone()),
                MediaScanWarningKind::PathLimit,
                "Relative path byte limit reached; this entry was skipped.",
            );
            continue;
        }
        report.path_bytes_scanned += path_size;

        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => {
                warn(
                    report,
                    Some(relative_string),
                    MediaScanWarningKind::Unreadable,
                    "Could not inspect this entry.",
                    true,
                );
                continue;
            }
        };
        if file_type.is_symlink() {
            warn(
                report,
                Some(relative_string),
                MediaScanWarningKind::SymlinkSkipped,
                "Symbolic link was skipped.",
                true,
            );
            continue;
        }
        if file_type.is_dir() {
            let next_depth = depth + 1;
            if next_depth > MAX_MEDIA_SCAN_DEPTH {
                mark_truncated(
                    report,
                    Some(relative_string),
                    MediaScanWarningKind::DepthLimit,
                    "Directory depth limit reached; this subtree was skipped.",
                );
                continue;
            }
            let mut dir_options = OpenOptions::new();
            dir_options
                .read(true)
                .follow(FollowSymlinks::No)
                .maybe_dir(true);
            avoid_blocking_special_file_open(&mut dir_options);
            let child = dir.open_with(&name, &dir_options).and_then(|file| {
                let metadata = file.metadata()?;
                if !metadata.is_dir() {
                    return Err(io::Error::other("entry changed from directory"));
                }
                Ok(Dir::from_std_file(file.into_std()))
            });
            match child {
                Ok(child) => {
                    visit_directory(&child, &relative_string, next_depth, options, report, stop)
                }
                Err(_) => {
                    let changed_to_symlink = dir
                        .symlink_metadata(&name)
                        .map(|metadata| metadata.file_type().is_symlink())
                        .unwrap_or(false);
                    if changed_to_symlink {
                        warn(
                            report,
                            Some(relative_string),
                            MediaScanWarningKind::SymlinkSkipped,
                            "Symbolic link appeared during scanning and was skipped.",
                            true,
                        );
                    } else {
                        warn(
                            report,
                            Some(relative_string),
                            MediaScanWarningKind::Unreadable,
                            "Could not open this directory.",
                            true,
                        );
                    }
                }
            }
            continue;
        }
        if !file_type.is_file() {
            warn(
                report,
                Some(relative_string),
                MediaScanWarningKind::SpecialFileSkipped,
                "Non-regular filesystem entry was skipped.",
                true,
            );
            continue;
        }

        let mut open_options = OpenOptions::new();
        open_options.read(true).follow(FollowSymlinks::No);
        avoid_blocking_special_file_open(&mut open_options);
        let mut file = match dir.open_with(&name, &open_options) {
            Ok(file) => file,
            Err(_) => {
                let changed_to_symlink = dir
                    .symlink_metadata(&name)
                    .map(|metadata| metadata.file_type().is_symlink())
                    .unwrap_or(false);
                if changed_to_symlink {
                    warn(
                        report,
                        Some(relative_string),
                        MediaScanWarningKind::SymlinkSkipped,
                        "Symbolic link appeared during scanning and was skipped.",
                        true,
                    );
                } else {
                    warn(
                        report,
                        Some(relative_string),
                        MediaScanWarningKind::Unreadable,
                        "Could not open this file for a bounded signature read.",
                        true,
                    );
                }
                continue;
            }
        };
        let before = match file.metadata() {
            Ok(metadata) if metadata.is_file() => metadata,
            _ => {
                warn(
                    report,
                    Some(relative_string),
                    MediaScanWarningKind::Unstable,
                    "Entry changed while it was being opened; skipped.",
                    true,
                );
                continue;
            }
        };
        let before_modified = before.modified().ok();
        let mut prefix = Vec::with_capacity(MAX_MEDIA_SCAN_SNIFF_BYTES);
        if Read::take(&mut file, MAX_MEDIA_SCAN_SNIFF_BYTES as u64)
            .read_to_end(&mut prefix)
            .is_err()
        {
            warn(
                report,
                Some(relative_string),
                MediaScanWarningKind::Unreadable,
                "Could not read a bounded file signature.",
                true,
            );
            continue;
        }
        let after = match file.metadata() {
            Ok(metadata) => metadata,
            Err(_) => {
                warn(
                    report,
                    Some(relative_string),
                    MediaScanWarningKind::Unstable,
                    "Could not recheck file metadata after the signature read; skipped.",
                    true,
                );
                continue;
            }
        };
        let after_modified = after.modified().ok();
        if before.len() != after.len()
            || before_modified.is_none()
            || after_modified.is_none()
            || before_modified != after_modified
        {
            warn(
                report,
                Some(relative_string),
                MediaScanWarningKind::Unstable,
                "File metadata changed or was unavailable during the signature read; skipped.",
                true,
            );
            continue;
        }

        let kind = if infer::is_image(&prefix) {
            MediaKind::Photo
        } else if infer::is_video(&prefix) {
            MediaKind::Video
        } else {
            warn(
                report,
                Some(relative_string.clone()),
                MediaScanWarningKind::UnsupportedType,
                "No supported photo or video signature was recognized; classified as other.",
                false,
            );
            MediaKind::Other
        };
        let utc_date = if options.filesystem_mtime_utc {
            match before_modified.and_then(system_time_unix_seconds) {
                Some(seconds) => match OffsetDateTime::from_unix_timestamp(seconds) {
                    Ok(date) if (1..=9999).contains(&date.year()) => Some(MediaUtcMonth {
                        year: date.year() as u16,
                        month: date.month() as u8,
                    }),
                    _ => {
                        warn(
                            report,
                            Some(relative_string.clone()),
                            MediaScanWarningKind::Unstable,
                            "Filesystem modification time could not be represented as a UTC month.",
                            true,
                        );
                        None
                    }
                },
                None => {
                    warn(
                        report,
                        Some(relative_string.clone()),
                        MediaScanWarningKind::Unstable,
                        "Filesystem modification time is unavailable; no UTC month was assigned.",
                        true,
                    );
                    None
                }
            }
        } else {
            None
        };
        report.sources.push(MediaSource {
            relative_path: relative_string,
            kind,
            utc_date,
        });
    }
}

fn nonempty(path: &str) -> Option<String> {
    (!path.is_empty()).then(|| path.to_string())
}

fn system_time_unix_seconds(value: SystemTime) -> Option<i64> {
    match value.duration_since(SystemClock::UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_secs()).ok(),
        Err(error) => {
            let duration = error.duration();
            let whole = i64::try_from(duration.as_secs()).ok()?;
            whole
                .checked_neg()?
                .checked_sub(i64::from(duration.subsec_nanos() > 0))
        }
    }
}

fn os_string_cmp(left: &OsString, right: &OsString) -> Ordering {
    left.cmp(right)
}

fn warn(
    report: &mut MediaScanReport,
    relative_path: Option<String>,
    kind: MediaScanWarningKind,
    message: &str,
    incomplete: bool,
) {
    if incomplete {
        report.complete = false;
    }
    if report.warnings.len() < MAX_MEDIA_SCAN_WARNINGS {
        report.warnings.push(MediaScanWarning {
            relative_path,
            kind,
            message: message.to_string(),
        });
    } else {
        report.warnings_omitted = report.warnings_omitted.saturating_add(1);
    }
}

fn mark_truncated(
    report: &mut MediaScanReport,
    relative_path: Option<String>,
    kind: MediaScanWarningKind,
    message: &str,
) {
    report.truncated = true;
    warn(report, relative_path, kind, message, true);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn options() -> MediaScanOptions {
        MediaScanOptions::default()
    }

    #[test]
    fn scans_magic_signatures_deterministically_and_does_not_infer_dates_by_default() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        fs::create_dir(root.join("camera")).unwrap();
        fs::write(root.join("camera/first.jpg"), [0xff, 0xd8, 0xff, 0xd9]).unwrap();
        fs::write(root.join("second.mp4"), b"not a video signature").unwrap();

        let first = scan_media_folder(root, options()).unwrap();
        let second = scan_media_folder(root, options()).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.sources.len(), 2);
        assert_eq!(first.sources[0].relative_path, "camera/first.jpg");
        assert_eq!(first.sources[0].kind, MediaKind::Photo);
        assert_eq!(first.sources[0].utc_date, None);
        assert_eq!(first.sources[1].kind, MediaKind::Other);
        assert!(first.warnings.iter().any(|warning| {
            warning.kind == MediaScanWarningKind::UnsupportedType
                && warning.relative_path.as_deref() == Some("second.mp4")
        }));
    }

    #[test]
    fn filesystem_mtime_is_only_added_when_requested() {
        let temp = TempDir::new().unwrap();
        fs::write(temp.path().join("photo.jpg"), [0xff, 0xd8, 0xff, 0xd9]).unwrap();
        let report = scan_media_folder(
            temp.path(),
            MediaScanOptions {
                filesystem_mtime_utc: true,
            },
        )
        .unwrap();
        assert!(report.sources[0].utc_date.is_some());
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_skipped_and_reported() {
        use std::os::unix::fs::symlink;
        let temp = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        fs::write(outside.path().join("outside.jpg"), [0xff, 0xd8, 0xff, 0xd9]).unwrap();
        symlink(
            outside.path().join("outside.jpg"),
            temp.path().join("linked.jpg"),
        )
        .unwrap();
        let report = scan_media_folder(temp.path(), options()).unwrap();
        assert!(report.sources.is_empty());
        assert!(!report.complete);
        assert_eq!(
            report.warnings[0].kind,
            MediaScanWarningKind::SymlinkSkipped
        );
    }

    #[test]
    fn relative_and_nonexistent_roots_are_rejected_safely() {
        assert!(matches!(
            scan_media_folder(Path::new("relative"), options()),
            Err(MediaScanError::SourcePathMustBeAbsolute)
        ));
        let temp = TempDir::new().unwrap();
        assert!(scan_media_folder(&temp.path().join("missing"), options()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn literal_backslash_filename_is_skipped_without_rewriting_its_identity() {
        let temp = TempDir::new().unwrap();
        fs::write(
            temp.path().join("literal\\name.jpg"),
            [0xff, 0xd8, 0xff, 0xd9],
        )
        .unwrap();
        let report = scan_media_folder(temp.path(), options()).unwrap();
        assert!(report.sources.is_empty());
        assert!(!report.complete);
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| { warning.kind == MediaScanWarningKind::InvalidPath })
        );
    }

    #[test]
    fn global_entry_budget_is_charged_before_directory_entries_are_retained() {
        let temp = TempDir::new().unwrap();
        for index in 0..=MAX_MEDIA_SCAN_ENTRIES {
            fs::write(temp.path().join(format!("{index:05}.txt")), b"").unwrap();
        }
        let report = scan_media_folder(temp.path(), options()).unwrap();
        assert_eq!(report.entries_scanned, MAX_MEDIA_SCAN_ENTRIES);
        assert!(report.truncated);
        assert!(!report.complete);
        assert!(report.sources.is_empty());
    }

    #[test]
    fn directories_at_the_depth_limit_are_reported_as_truncated() {
        let temp = TempDir::new().unwrap();
        let mut path = temp.path().to_path_buf();
        for index in 0..=MAX_MEDIA_SCAN_DEPTH {
            path.push(format!("d{index}"));
            fs::create_dir(&path).unwrap();
        }
        let report = scan_media_folder(temp.path(), options()).unwrap();
        assert!(report.truncated);
        assert!(!report.complete);
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.kind == MediaScanWarningKind::DepthLimit)
        );
    }
    #[cfg(unix)]
    #[test]
    fn nonblocking_open_allows_rejecting_an_entry_replaced_by_a_fifo() {
        let temp = tempfile::tempdir().unwrap();
        let fifo = temp.path().join("changed-entry");
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .unwrap();
        let dir = Dir::open_ambient_dir(temp.path(), ambient_authority()).unwrap();
        let mut open_options = OpenOptions::new();
        open_options.read(true).follow(FollowSymlinks::No);
        avoid_blocking_special_file_open(&mut open_options);
        let file = dir.open_with("changed-entry", &open_options).unwrap();
        assert!(!file.metadata().unwrap().is_file());
        let report = scan_media_folder(temp.path(), options()).unwrap();
        assert!(!report.complete);
        assert!(report.sources.is_empty());
    }
}
