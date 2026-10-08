//! Read-only index of durable provider-write copies.
//!
//! A listed item may still be active or may have been retained after an
//! interrupted/failed provider write. The index never reads `.data` contents,
//! uploads, renames, or deletes files.

use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Take};
use std::path::{Path, PathBuf};
use std::{fmt, io};

pub const MAX_RECOVERY_PAGE_SIZE: usize = 100;
pub const MAX_RECOVERY_SCAN_ENTRIES: usize = 10_000;
pub const MAX_RECOVERY_MANIFEST_BYTES: u64 = 16 * 1024;
/// Leaves room below the agent's 1 MiB IPC frame limit for its response wrapper.
pub const MAX_RECOVERY_PAGE_JSON_BYTES: usize = 900 * 1024;
const MAX_SPACE_ID_BYTES: usize = 512;
const MAX_REMOTE_PATH_BYTES: usize = 4_096;
const MAX_EXPOSED_LOCAL_PATH_BYTES: usize = 4_096;

/// Write condition saved when the provider spool was created. The ETag itself
/// is deliberately not exposed by this recovery index.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryConditionKind {
    Absent,
    Match,
}

/// A saved local provider-write copy or an entry that needs attention.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecoveryItem {
    /// Stable 16-character spool filename stem and pagination cursor.
    pub spool_key: String,
    pub space_id: Option<String>,
    pub remote_path: Option<String>,
    /// Path to the saved bytes when its name and file type are safe to expose.
    pub local_data_path: Option<String>,
    /// File size from metadata only. The data body is never read.
    pub bytes: Option<u64>,
    pub condition: Option<RecoveryConditionKind>,
    pub warnings: Vec<RecoveryWarning>,
}

/// Warning attached to a corrupt, incomplete, or unsafe spool entry.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryWarning {
    MissingManifest,
    MissingData,
    UnsafeManifest,
    UnsafeData,
    ManifestTooLarge,
    MalformedManifest,
    ManifestNameMismatch,
    InvalidManifestFields,
    LocalPathUnavailable,
}

/// One bounded page from a read-only spool scan.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPage {
    pub items: Vec<RecoveryItem>,
    /// The last returned spool key when more scanned entries remain.
    pub next_after: Option<String>,
    /// Raw directory entries examined, never greater than the scan limit.
    pub scanned_entries: usize,
    /// Warnings on returned entries plus unrecognized filenames seen in this
    /// scan. Warnings for later pages are counted when those pages are loaded.
    pub warning_count: usize,
    pub unrecognized_entries: usize,
    /// True when the directory scan reached its hard entry bound. The list is
    /// then incomplete and callers should show that state to the user.
    pub truncated: bool,
}

/// Read-only recovery-index errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryError {
    InvalidLimit,
    InvalidCursor,
    UnsafeSpoolDirectory,
    ResponseTooLarge,
    Io,
}

impl fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit => write!(f, "recovery page size must be between 1 and 100"),
            Self::InvalidCursor => write!(f, "recovery page cursor is invalid"),
            Self::UnsafeSpoolDirectory => {
                write!(f, "provider spool must be a real directory")
            }
            Self::ResponseTooLarge => write!(f, "recovery page exceeds the response size limit"),
            Self::Io => write!(f, "could not read provider recovery metadata"),
        }
    }
}

impl std::error::Error for RecoveryError {}

#[derive(Default)]
struct SpoolFiles {
    manifest: Option<PathBuf>,
    data: Option<PathBuf>,
}

/// List saved provider-write copies from an account-scoped spool directory.
///
/// The cursor is the previous page's `spool_key`. Only valid lowercase
/// 16-character hexadecimal stems are paged. Scanning stops after 10,000 raw
/// directory entries, and manifests are read only for the requested page.
/// Missing directories return an empty page. Existing file contents are never
/// opened; only bounded manifest JSON and filesystem metadata are read.
pub fn list_recoveries(
    spool_dir: &Path,
    after: Option<&str>,
    limit: usize,
) -> Result<RecoveryPage, RecoveryError> {
    if !(1..=MAX_RECOVERY_PAGE_SIZE).contains(&limit) {
        return Err(RecoveryError::InvalidLimit);
    }
    if after.is_some_and(|cursor| !valid_spool_key(cursor)) {
        return Err(RecoveryError::InvalidCursor);
    }

    let directory_before = match fs::symlink_metadata(spool_dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(empty_page()),
        Err(_) => return Err(RecoveryError::Io),
    };
    if !directory_before.is_dir() || directory_before.file_type().is_symlink() {
        return Err(RecoveryError::UnsafeSpoolDirectory);
    }

    let read_dir = fs::read_dir(spool_dir).map_err(|_| RecoveryError::Io)?;
    let mut files = BTreeMap::<String, SpoolFiles>::new();
    let mut scanned_entries = 0;
    let mut unrecognized_entries = 0usize;
    let mut truncated = false;
    for result in read_dir {
        if !scan_entry_allowed(scanned_entries, MAX_RECOVERY_SCAN_ENTRIES) {
            truncated = true;
            break;
        }
        let entry = result.map_err(|_| RecoveryError::Io)?;
        scanned_entries += 1;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            unrecognized_entries = unrecognized_entries.saturating_add(1);
            continue;
        };
        if name.starts_with(".provider-manifest-") && name.ends_with(".tmp") {
            continue;
        }
        let (stem, is_manifest) = if let Some(stem) = name.strip_suffix(".meta") {
            (stem, true)
        } else if let Some(stem) = name.strip_suffix(".data") {
            (stem, false)
        } else {
            unrecognized_entries = unrecognized_entries.saturating_add(1);
            continue;
        };
        if !valid_spool_key(stem) {
            unrecognized_entries = unrecognized_entries.saturating_add(1);
            continue;
        }
        let files = files.entry(stem.to_owned()).or_default();
        if is_manifest {
            files.manifest = Some(entry.path());
        } else {
            files.data = Some(entry.path());
        }
    }

    let directory_after = fs::symlink_metadata(spool_dir).map_err(|_| RecoveryError::Io)?;
    if directory_after.file_type().is_symlink()
        || !directory_after.is_dir()
        || !same_identity(&directory_before, &directory_after)
    {
        return Err(RecoveryError::UnsafeSpoolDirectory);
    }

    let keys = files
        .keys()
        .filter(|key| after.is_none_or(|cursor| key.as_str() > cursor))
        .cloned()
        .collect::<Vec<_>>();
    let mut page = RecoveryPage {
        items: Vec::with_capacity(limit),
        next_after: None,
        scanned_entries,
        warning_count: unrecognized_entries,
        unrecognized_entries,
        truncated,
    };
    for (index, key) in keys.iter().take(limit).enumerate() {
        let paths = files.get(key).expect("selected key exists in spool map");
        let mut candidate = page.clone();
        candidate.items.push(read_spool_item(key, paths));
        candidate.warning_count = candidate
            .items
            .iter()
            .map(|item| item.warnings.len())
            .sum::<usize>()
            .saturating_add(unrecognized_entries);
        candidate.next_after = (index + 1 < keys.len() || truncated).then(|| key.clone());

        let encoded_size = serde_json::to_vec(&candidate)
            .map_err(|_| RecoveryError::ResponseTooLarge)?
            .len();
        if encoded_size > MAX_RECOVERY_PAGE_JSON_BYTES {
            if page.items.is_empty() {
                return Err(RecoveryError::ResponseTooLarge);
            }
            break;
        }
        page = candidate;
    }
    Ok(page)
}

fn empty_page() -> RecoveryPage {
    RecoveryPage {
        items: Vec::new(),
        next_after: None,
        scanned_entries: 0,
        warning_count: 0,
        unrecognized_entries: 0,
        truncated: false,
    }
}

fn read_spool_item(key: &str, files: &SpoolFiles) -> RecoveryItem {
    let mut item = RecoveryItem {
        spool_key: key.to_owned(),
        space_id: None,
        remote_path: None,
        local_data_path: None,
        bytes: None,
        condition: None,
        warnings: Vec::new(),
    };

    if let Some(data) = files.data.as_deref() {
        match fs::symlink_metadata(data) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                item.warnings.push(RecoveryWarning::UnsafeData);
            }
            Ok(metadata) => {
                item.bytes = Some(metadata.len());
                match exposed_path(data) {
                    Some(path) => item.local_data_path = Some(path),
                    None => item.warnings.push(RecoveryWarning::LocalPathUnavailable),
                }
                match fs::symlink_metadata(data) {
                    Ok(after)
                        if !after.file_type().is_symlink()
                            && after.is_file()
                            && same_identity(&metadata, &after) => {}
                    _ => {
                        item.local_data_path = None;
                        item.bytes = None;
                        item.warnings.push(RecoveryWarning::UnsafeData);
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                item.warnings.push(RecoveryWarning::MissingData);
            }
            Err(_) => item.warnings.push(RecoveryWarning::UnsafeData),
        }
    } else {
        item.warnings.push(RecoveryWarning::MissingData);
    }

    let Some(manifest) = files.manifest.as_deref() else {
        item.warnings.push(RecoveryWarning::MissingManifest);
        return item;
    };
    match read_bounded_manifest(manifest) {
        Ok(fields) => {
            let [space, remote, condition, etag] = fields;
            if !valid_manifest_fields(&space, &remote, &condition, &etag) {
                item.warnings.push(RecoveryWarning::InvalidManifestFields);
                return item;
            }
            if stable_hash(&format!("{space}\0{remote}"))
                != u64::from_str_radix(key, 16).unwrap_or(0)
            {
                item.warnings.push(RecoveryWarning::ManifestNameMismatch);
                return item;
            }
            item.space_id = Some(space);
            item.remote_path = Some(remote);
            item.condition = Some(if condition == "absent" {
                RecoveryConditionKind::Absent
            } else {
                RecoveryConditionKind::Match
            });
        }
        Err(ManifestReadError::TooLarge) => {
            item.warnings.push(RecoveryWarning::ManifestTooLarge);
        }
        Err(ManifestReadError::Unsafe) => {
            item.warnings.push(RecoveryWarning::UnsafeManifest);
        }
        Err(ManifestReadError::Malformed) => {
            item.warnings.push(RecoveryWarning::MalformedManifest);
        }
    }
    item
}

enum ManifestReadError {
    TooLarge,
    Unsafe,
    Malformed,
}

fn read_bounded_manifest(path: &Path) -> Result<[String; 4], ManifestReadError> {
    let before = fs::symlink_metadata(path).map_err(|_| ManifestReadError::Unsafe)?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(ManifestReadError::Unsafe);
    }
    if before.len() > MAX_RECOVERY_MANIFEST_BYTES {
        return Err(ManifestReadError::TooLarge);
    }
    let mut file = open_manifest_nofollow(path).map_err(|_| ManifestReadError::Unsafe)?;
    let opened = file.metadata().map_err(|_| ManifestReadError::Unsafe)?;
    if opened.file_type().is_symlink() || !opened.is_file() || !same_identity(&before, &opened) {
        return Err(ManifestReadError::Unsafe);
    }
    if opened.len() > MAX_RECOVERY_MANIFEST_BYTES {
        return Err(ManifestReadError::TooLarge);
    }
    let mut body = Vec::with_capacity(opened.len() as usize);
    bounded_take(&mut file)
        .read_to_end(&mut body)
        .map_err(|_| ManifestReadError::Unsafe)?;
    if body.len() as u64 > MAX_RECOVERY_MANIFEST_BYTES {
        return Err(ManifestReadError::TooLarge);
    }
    let after = fs::symlink_metadata(path).map_err(|_| ManifestReadError::Unsafe)?;
    if after.file_type().is_symlink() || !same_identity(&opened, &after) {
        return Err(ManifestReadError::Unsafe);
    }
    serde_json::from_slice::<[String; 4]>(&body).map_err(|_| ManifestReadError::Malformed)
}

fn bounded_take(file: &mut File) -> Take<&mut File> {
    file.take(MAX_RECOVERY_MANIFEST_BYTES + 1)
}

#[cfg(unix)]
fn open_manifest_nofollow(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

#[cfg(not(unix))]
fn open_manifest_nofollow(path: &Path) -> io::Result<File> {
    OpenOptions::new().read(true).open(path)
}

fn valid_manifest_fields(space: &str, remote: &str, kind: &str, etag: &str) -> bool {
    !space.is_empty()
        && space.len() <= MAX_SPACE_ID_BYTES
        && !space.chars().any(char::is_control)
        && valid_remote_path(remote)
        && remote.len() <= MAX_REMOTE_PATH_BYTES
        && match kind {
            "absent" => etag.is_empty(),
            "match" => {
                !etag.is_empty()
                    && etag.len() <= MAX_REMOTE_PATH_BYTES
                    && !etag.chars().any(char::is_control)
            }
            _ => false,
        }
}

fn valid_remote_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= MAX_REMOTE_PATH_BYTES
        && !path.contains('\\')
        && !path.chars().any(char::is_control)
        && path != "/"
        && !path.ends_with('/')
        && path[1..]
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn valid_spool_key(key: &str) -> bool {
    key.len() == 16
        && key
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn exposed_path(path: &Path) -> Option<String> {
    let text = path.to_str()?;
    (text.len() <= MAX_EXPOSED_LOCAL_PATH_BYTES && !text.chars().any(char::is_control))
        .then(|| text.to_owned())
}

fn stable_hash(value: &str) -> u64 {
    value
        .as_bytes()
        .iter()
        .fold(0xcbf29ce484222325, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
        })
}

fn same_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        left.dev() == right.dev() && left.ino() == right.ino()
    }
    #[cfg(not(unix))]
    {
        left.len() == right.len() && left.modified().ok() == right.modified().ok()
    }
}

fn scan_entry_allowed(scanned_entries: usize, maximum: usize) -> bool {
    scanned_entries < maximum
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    fn write_manifest(spool: &Path, space: &str, remote: &str, kind: &str, etag: &str) -> String {
        let stem = format!("{:016x}", stable_hash(&format!("{space}\0{remote}")));
        let manifest = serde_json::to_vec(&[space, remote, kind, etag]).unwrap();
        fs::write(spool.join(format!("{stem}.meta")), manifest).unwrap();
        stem
    }

    #[test]
    fn indexes_saved_upload_copy_without_reading_or_mutating_data() {
        let spool = tempfile::tempdir().unwrap();
        let stem = write_manifest(
            spool.path(),
            "drive",
            "/folder/photo.jpg",
            "match",
            "etag-1",
        );
        let data = spool.path().join(format!("{stem}.data"));
        fs::write(&data, b"private saved bytes").unwrap();
        let before = fs::read(&data).unwrap();

        let page = list_recoveries(spool.path(), None, 100).unwrap();
        assert_eq!(page.scanned_entries, 2);
        assert_eq!(page.items.len(), 1);
        let item = &page.items[0];
        assert_eq!(item.space_id.as_deref(), Some("drive"));
        assert_eq!(item.remote_path.as_deref(), Some("/folder/photo.jpg"));
        assert_eq!(item.bytes, Some(before.len() as u64));
        assert_eq!(item.local_data_path.as_deref(), data.to_str());
        assert_eq!(item.condition, Some(RecoveryConditionKind::Match));
        assert!(item.warnings.is_empty());
        assert_eq!(fs::read(data).unwrap(), before);
    }

    #[test]
    fn indexes_absent_condition_without_exposing_etag() {
        let spool = tempfile::tempdir().unwrap();
        let stem = write_manifest(spool.path(), "personal", "/a.txt", "absent", "");
        fs::write(spool.path().join(format!("{stem}.data")), b"pending").unwrap();
        let page = list_recoveries(spool.path(), None, 1).unwrap();
        assert_eq!(page.items[0].condition, Some(RecoveryConditionKind::Absent));
        let json = serde_json::to_string(&page).unwrap();
        assert!(!json.contains("etag"));
    }

    #[test]
    fn corrupt_or_orphaned_entries_are_reported_without_removal() {
        let spool = tempfile::tempdir().unwrap();
        let malformed_key = "0000000000000001";
        fs::write(
            spool.path().join(format!("{malformed_key}.meta")),
            b"not json",
        )
        .unwrap();
        fs::write(
            spool.path().join(format!("{malformed_key}.data")),
            b"keep me",
        )
        .unwrap();
        fs::write(spool.path().join("0000000000000002.data"), b"orphan").unwrap();

        let page = list_recoveries(spool.path(), None, 100).unwrap();
        assert_eq!(page.items.len(), 2);
        assert!(
            page.items[0]
                .warnings
                .contains(&RecoveryWarning::MalformedManifest)
        );
        assert!(
            page.items[1]
                .warnings
                .contains(&RecoveryWarning::MissingManifest)
        );
        assert_eq!(page.warning_count, 2);
        assert!(spool.path().join(format!("{malformed_key}.data")).exists());
        assert!(spool.path().join(format!("{malformed_key}.meta")).exists());
    }

    #[test]
    fn detects_manifest_stem_mismatch_and_oversized_metadata() {
        let spool = tempfile::tempdir().unwrap();
        fs::write(
            spool.path().join("0000000000000001.meta"),
            serde_json::to_vec(&["drive", "/valid.txt", "absent", ""]).unwrap(),
        )
        .unwrap();
        fs::write(
            spool.path().join("0000000000000002.meta"),
            vec![b'x'; MAX_RECOVERY_MANIFEST_BYTES as usize + 1],
        )
        .unwrap();
        let page = list_recoveries(spool.path(), None, 100).unwrap();
        assert!(
            page.items[0]
                .warnings
                .contains(&RecoveryWarning::ManifestNameMismatch)
        );
        assert!(
            page.items[1]
                .warnings
                .contains(&RecoveryWarning::ManifestTooLarge)
        );
    }

    #[test]
    fn pages_by_sorted_stem_and_rejects_invalid_cursors_or_limits() {
        let spool = tempfile::tempdir().unwrap();
        for remote in ["/c", "/a", "/b"] {
            let stem = write_manifest(spool.path(), "drive", remote, "absent", "");
            fs::write(spool.path().join(format!("{stem}.data")), b"x").unwrap();
        }
        let first = list_recoveries(spool.path(), None, 1).unwrap();
        assert_eq!(first.items.len(), 1);
        let next = first.next_after.as_deref().unwrap();
        let second = list_recoveries(spool.path(), Some(next), 1).unwrap();
        assert!(second.items[0].spool_key.as_str() > next);
        assert!(list_recoveries(spool.path(), Some("../"), 1).is_err());
        assert_eq!(
            list_recoveries(spool.path(), None, MAX_RECOVERY_PAGE_SIZE + 1).unwrap_err(),
            RecoveryError::InvalidLimit
        );
    }

    #[test]
    fn maximum_page_stays_below_agent_ipc_limit() {
        let spool = tempfile::tempdir().unwrap();
        let space = "s".repeat(MAX_SPACE_ID_BYTES);
        for index in 0..MAX_RECOVERY_PAGE_SIZE {
            let remote = format!("/{}-{index:03}", "x".repeat(3_980));
            let stem = write_manifest(spool.path(), &space, &remote, "absent", "");
            fs::write(spool.path().join(format!("{stem}.data")), b"").unwrap();
        }

        let page = list_recoveries(spool.path(), None, MAX_RECOVERY_PAGE_SIZE).unwrap();
        let json = serde_json::to_vec(&page).unwrap();
        assert_eq!(page.items.len(), MAX_RECOVERY_PAGE_SIZE);
        assert!(json.len() <= MAX_RECOVERY_PAGE_JSON_BYTES);
    }

    #[test]
    fn escaped_strings_trim_page_without_losing_pagination() {
        let parent = tempfile::tempdir().unwrap();
        let mut spool_path = parent.path().to_path_buf();
        for _ in 0..18 {
            spool_path.push("\"".repeat(190));
            fs::create_dir(&spool_path).unwrap();
        }
        let space = "\"".repeat(MAX_SPACE_ID_BYTES / 2);
        for index in 0..MAX_RECOVERY_PAGE_SIZE {
            let remote = format!("/{}-{index:03}", "\"".repeat(2_039));
            let stem = write_manifest(&spool_path, &space, &remote, "absent", "");
            fs::write(spool_path.join(format!("{stem}.data")), b"").unwrap();
        }

        let first = list_recoveries(&spool_path, None, MAX_RECOVERY_PAGE_SIZE).unwrap();
        let first_json = serde_json::to_vec(&first).unwrap();
        assert!(first.items.len() < MAX_RECOVERY_PAGE_SIZE);
        assert!(first_json.len() <= MAX_RECOVERY_PAGE_JSON_BYTES);
        let cursor = first.next_after.as_deref().unwrap();
        assert_eq!(cursor, first.items.last().unwrap().spool_key);

        let second = list_recoveries(&spool_path, Some(cursor), MAX_RECOVERY_PAGE_SIZE).unwrap();
        assert!(!second.items.is_empty());
        assert!(second.items[0].spool_key.as_str() > cursor);
    }

    #[test]
    fn rejects_root_and_oversized_values_from_manifest() {
        let spool = tempfile::tempdir().unwrap();
        let key = "0000000000000001";
        fs::write(
            spool.path().join(format!("{key}.meta")),
            serde_json::to_vec(&["drive", "/", "absent", ""]).unwrap(),
        )
        .unwrap();
        let page = list_recoveries(spool.path(), None, 1).unwrap();
        assert!(
            page.items[0]
                .warnings
                .contains(&RecoveryWarning::InvalidManifestFields)
        );
        assert!(page.items[0].remote_path.is_none());
    }

    #[test]
    fn scan_bound_has_explicit_truncation_signal() {
        let spool = tempfile::tempdir().unwrap();
        for index in 0..=MAX_RECOVERY_SCAN_ENTRIES {
            fs::write(spool.path().join(format!("unrecognized-{index}")), b"").unwrap();
        }

        let page = list_recoveries(spool.path(), None, 1).unwrap();
        assert_eq!(page.scanned_entries, MAX_RECOVERY_SCAN_ENTRIES);
        assert_eq!(page.unrecognized_entries, MAX_RECOVERY_SCAN_ENTRIES);
        assert!(page.truncated);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_directory_manifest_and_data() {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir().unwrap();
        let target = parent.path().join("target");
        let spool = parent.path().join("spool");
        fs::create_dir(&target).unwrap();
        fs::create_dir(&spool).unwrap();
        let key = write_manifest(&spool, "drive", "/file.jpg", "absent", "");
        let external_meta = parent.path().join("external.meta");
        fs::write(&external_meta, b"[]").unwrap();
        fs::remove_file(spool.join(format!("{key}.meta"))).unwrap();
        symlink(&external_meta, spool.join(format!("{key}.meta"))).unwrap();
        let external_data = parent.path().join("external.data");
        fs::write(&external_data, b"saved").unwrap();
        symlink(&external_data, spool.join(format!("{key}.data"))).unwrap();
        assert!(matches!(
            list_recoveries(&spool, None, 10).unwrap().items[0]
                .warnings
                .as_slice(),
            [RecoveryWarning::UnsafeData, RecoveryWarning::UnsafeManifest]
                | [RecoveryWarning::UnsafeManifest, RecoveryWarning::UnsafeData]
        ));

        let link = parent.path().join("spool-link");
        symlink(&spool, &link).unwrap();
        assert_eq!(
            list_recoveries(&link, None, 10).unwrap_err(),
            RecoveryError::UnsafeSpoolDirectory
        );
    }

    #[test]
    fn missing_spool_directory_is_an_empty_page() {
        let parent = tempfile::tempdir().unwrap();
        let page = list_recoveries(&parent.path().join("not-created"), None, 10).unwrap();
        assert!(page.items.is_empty());
        assert!(!page.truncated);
    }
}
