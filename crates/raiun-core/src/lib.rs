//! Safe configuration and namespace primitives for Raiun's desktop engine.
//!
//! This crate validates configuration data only. It does not scan folder trees,
//! mount cloud storage, perform network requests, or claim that data has synced.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

pub mod backend;
pub mod media_plan;
pub use media_plan::{
    MediaFilter, MediaKind, MediaOrganization, MediaPlanError, MediaPlanItem, MediaPlanOptions,
    MediaPlanOutcome, MediaPlanRejection, MediaSource, MediaUtcMonth, plan_media_import,
};

/// Current on-disk configuration schema version.
pub const CONFIG_SCHEMA_VERSION: u32 = 1;

/// Application configuration for a single OS-provided cloud root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema_version: u32,
    pub cloud_root: PathBuf,
    pub pairs: Vec<FolderPair>,
}

/// A local folder and its corresponding path in a cloud space.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FolderPair {
    pub id: String,
    pub local_path: PathBuf,
    pub space_id: String,
    pub remote_path: String,
    pub mode: SyncMode,
}

/// Direction in which a future sync engine may reconcile a folder pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncMode {
    TwoWay,
    UploadOnly,
    DownloadOnly,
}

/// Validate a full configuration and return actionable diagnostics.
///
/// Validation is read-only. It checks the cloud root and each pair without
/// walking any directory tree. A missing cloud root is allowed because the OS
/// provider may create or remount it later.
pub fn validate_config(config: &Config) -> Vec<String> {
    let mut errors = Vec::new();
    if config.schema_version != CONFIG_SCHEMA_VERSION {
        errors.push(format!(
            "schema_version {} is unsupported; expected {}",
            config.schema_version, CONFIG_SCHEMA_VERSION
        ));
    }

    if let Err(problem) = validate_cloud_root(&config.cloud_root) {
        errors.push(format!(
            "cloud_root '{}' is invalid: {}",
            config.cloud_root.display(),
            problem
        ));
    }

    let mut seen_ids = BTreeSet::new();
    for pair in &config.pairs {
        if !seen_ids.insert(pair.id.as_str()) {
            errors.push(format!("pair id '{}' is duplicated", pair.id));
        }
        errors.extend(validate_pair(pair, &config.pairs, &config.cloud_root));
    }
    errors
}

/// Validate one folder pair against the other configured pairs and cloud root.
///
/// Paths are compared after canonicalizing existing paths, which catches
/// symlink aliases. For a cloud root that does not exist yet, the nearest
/// existing ancestor is canonicalized and the remaining path is appended.
pub fn validate_pair(pair: &FolderPair, existing: &[FolderPair], cloud_root: &Path) -> Vec<String> {
    let mut errors = Vec::new();
    if pair.id.trim().is_empty() {
        errors.push("pair id must not be blank".to_string());
    }
    if pair.space_id.trim().is_empty() {
        errors.push(format!("pair '{}' space_id must not be blank", pair.id));
    }
    let cloud_path = validate_cloud_root(cloud_root);
    if let Err(problem) = &cloud_path {
        errors.push(format!(
            "pair '{}' cannot be checked against cloud_root '{}': {}",
            pair.id,
            cloud_root.display(),
            problem
        ));
    }
    if !pair.local_path.is_absolute() {
        errors.push(format!("pair '{}' local_path must be absolute", pair.id));
    } else if has_parent_dir_component(&pair.local_path) {
        errors.push(format!(
            "pair '{}' local_path '{}' contains a '..' component; use a path without parent-directory traversal",
            pair.id,
            pair.local_path.display()
        ));
    } else {
        match fs::metadata(&pair.local_path) {
            Ok(metadata) if !metadata.is_dir() => errors.push(format!(
                "pair '{}' local_path '{}' is not a directory",
                pair.id,
                pair.local_path.display()
            )),
            Ok(_) => {
                match fs::canonicalize(&pair.local_path) {
                    Ok(canonical) => {
                        if is_filesystem_root(&canonical) {
                            errors.push(format!(
                                "pair '{}' local_path '{}' must not be a filesystem root",
                                pair.id,
                                pair.local_path.display()
                            ));
                        }
                        if fs::read_dir(&canonical).is_err() {
                            errors.push(format!(
                                "pair '{}' local_path '{}' is not readable",
                                pair.id,
                                pair.local_path.display()
                            ));
                        }
                        match &cloud_path {
                            Ok(cloud) if paths_overlap(&canonical, cloud) => {
                                errors.push(format!(
                                    "pair '{}' local_path '{}' overlaps cloud_root '{}'",
                                    pair.id,
                                    pair.local_path.display(),
                                    cloud_root.display()
                                ));
                            }
                            Ok(_) => {}
                            Err(_) => {}
                        }
        for other in existing.iter().filter(|other| !std::ptr::eq(*other, pair)) {
            if other.id == pair.id {
                errors.push(format!("pair id '{}' is duplicated", pair.id));
            }
            if let Ok(other_path) = fs::canonicalize(&other.local_path) {
                                if paths_overlap(&canonical, &other_path) {
                                    errors.push(format!(
                                        "pair '{}' local_path '{}' overlaps pair '{}' local_path '{}'",
                                        pair.id,
                                        pair.local_path.display(),
                                        other.id,
                                        other.local_path.display()
                                    ));
                                }
                            }
                        }
                    }
                    Err(_) => errors.push(format!(
                        "pair '{}' local_path '{}' cannot be resolved; check that it still exists and is accessible",
                        pair.id,
                        pair.local_path.display()
                    )),
                }
            }
            Err(_) => errors.push(format!(
                "pair '{}' local_path '{}' does not exist or is inaccessible; choose an existing readable directory or remove the pair",
                pair.id,
                pair.local_path.display()
            )),
        }
    }

    if let Err(problem) = validate_remote_path(&pair.remote_path) {
        errors.push(format!(
            "pair '{}' remote_path '{}' is invalid: {}",
            pair.id, pair.remote_path, problem
        ));
    }

    for other in existing.iter().filter(|other| !std::ptr::eq(*other, pair)) {
        if other.id == pair.id {
            errors.push(format!("pair id '{}' is duplicated", pair.id));
        }
        if other.space_id == pair.space_id
            && validate_remote_path(&pair.remote_path).is_ok()
            && validate_remote_path(&other.remote_path).is_ok()
            && remote_paths_overlap(&pair.remote_path, &other.remote_path)
        {
            errors.push(format!(
                "pair '{}' remote_path '{}' overlaps pair '{}' remote_path '{}' in space '{}'",
                pair.id, pair.remote_path, other.id, other.remote_path, pair.space_id
            ));
        }
    }
    errors
}

/// A cloud space with a stable identity and user-facing display name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Space {
    pub id: String,
    pub name: String,
}

/// A space identity paired with its current display location under the cloud root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceEntry {
    pub space_id: String,
    pub relative_path: PathBuf,
}

/// Build deterministic display locations for spaces under `Spaces/`.
///
/// Personal is reserved at the root. Display names are sanitized for common
/// Windows path hazards even when the current host is Unix. Colliding names get
/// an ID-derived stable suffix, so input ordering does not affect assignments.
/// The returned path is a display location only; callers should persist the
/// stable `space_id`, since a user can rename a space and change this path.
///
/// Components are bounded to 240 UTF-16 code units. Collision checks use
/// Unicode lowercase mappings without normalization; final filesystem-specific
/// case and normalization behavior still needs acceptance testing per platform.
pub fn space_entries(spaces: &[Space]) -> Result<Vec<NamespaceEntry>, String> {
    let mut seen_ids = BTreeSet::new();
    for space in spaces {
        if space.id.trim().is_empty() {
            return Err("space id must not be blank".to_string());
        }
        if !seen_ids.insert(space.id.as_str()) {
            return Err(format!("space id '{}' is duplicated", space.id));
        }
    }

    let mut bases = Vec::with_capacity(spaces.len());
    let mut groups: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (index, space) in spaces.iter().enumerate() {
        let base = safe_space_name(&space.name);
        let folded = case_fold_key(&base);
        groups.entry(folded).or_default().push(index);
        bases.push(base);
    }

    let reserved_originals: BTreeSet<_> = bases.iter().map(|name| case_fold_key(name)).collect();
    let mut used = BTreeSet::new();
    let mut names = vec![String::new(); spaces.len()];
    let mut by_id: Vec<_> = (0..spaces.len()).collect();
    by_id.sort_by(|left, right| spaces[*left].id.cmp(&spaces[*right].id));
    for index in by_id {
        let folded_base = case_fold_key(&bases[index]);
        if groups[&folded_base].len() == 1 {
            names[index] = bases[index].clone();
            used.insert(folded_base);
            continue;
        }

        // Keep every original sanitized label available. A generated suffix
        // can never take a name that belongs to another space's display label.
        let mut attempt = 1_u64;
        loop {
            let candidate = suffixed_space_name(&bases[index], &spaces[index].id, attempt);
            let folded = case_fold_key(&candidate);
            if !reserved_originals.contains(&folded) && used.insert(folded) {
                names[index] = candidate;
                break;
            }
            attempt = attempt.saturating_add(1);
        }
    }

    let mut entries: Vec<_> = spaces
        .iter()
        .zip(names)
        .map(|(space, name)| NamespaceEntry {
            space_id: space.id.clone(),
            relative_path: PathBuf::from("Spaces").join(name),
        })
        .collect();
    entries.sort_by(|left, right| left.space_id.cmp(&right.space_id));
    Ok(entries)
}

fn validate_remote_path(path: &str) -> Result<(), &'static str> {
    if path.is_empty() {
        return Err("use '/' for the space root or an absolute slash-separated path");
    }
    if !path.starts_with('/') {
        return Err("path must start with '/'");
    }
    if path != "/" && path.ends_with('/') {
        return Err("trailing slash is allowed only for '/'");
    }
    if path.contains('\\') {
        return Err("backslashes are not allowed; use '/' separators");
    }
    if path.chars().any(char::is_control) {
        return Err("control characters are not allowed");
    }
    if path != "/" {
        for segment in path[1..].split('/') {
            if segment.is_empty() {
                return Err("duplicate slashes are not allowed");
            }
            if segment == "." || segment == ".." {
                return Err("'.' and '..' path segments are not allowed");
            }
        }
    }
    Ok(())
}

fn remote_paths_overlap(left: &str, right: &str) -> bool {
    left == right
        || left == "/"
        || right == "/"
        || left
            .strip_prefix(right)
            .is_some_and(|tail| tail.starts_with('/'))
        || right
            .strip_prefix(left)
            .is_some_and(|tail| tail.starts_with('/'))
}

fn resolve_path_for_comparison(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() || has_parent_dir_component(path) {
        return None;
    }
    let mut ancestor = path;
    let mut suffix = Vec::new();
    loop {
        match fs::symlink_metadata(ancestor) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let name = ancestor.file_name()?;
                suffix.push(name.to_os_string());
                ancestor = ancestor.parent()?;
            }
            Err(_) => return None,
        }
    }
    if !fs::metadata(ancestor).ok()?.is_dir() {
        return None;
    }
    let mut resolved = fs::canonicalize(ancestor).ok()?;
    for name in suffix.iter().rev() {
        resolved.push(name);
    }
    Some(resolved)
}

fn validate_cloud_root(path: &Path) -> Result<PathBuf, &'static str> {
    if !path.is_absolute() {
        return Err("must be an absolute path");
    }
    if has_parent_dir_component(path) {
        return Err("contains a '..' component; use a path without parent-directory traversal");
    }
    let resolved = resolve_path_for_comparison(path).ok_or(
        "cannot be resolved as a directory; check that it and its existing ancestors are accessible directories",
    )?;
    if is_filesystem_root(&resolved) {
        return Err("must not be a filesystem root");
    }
    Ok(resolved)
}

fn has_parent_dir_component(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component, Component::ParentDir))
}

fn is_filesystem_root(path: &Path) -> bool {
    path.parent().is_none()
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    path_starts_with(left, right) || path_starts_with(right, left)
}

fn path_starts_with(path: &Path, ancestor: &Path) -> bool {
    let left: Vec<_> = path.components().collect();
    let right: Vec<_> = ancestor.components().collect();
    left.len() >= right.len()
        && left
            .iter()
            .zip(right.iter())
            .all(|(left, right)| path_component_eq(left, right))
}

#[cfg(windows)]
fn path_component_eq(left: &Component<'_>, right: &Component<'_>) -> bool {
    left.as_os_str()
        .to_string_lossy()
        .eq_ignore_ascii_case(&right.as_os_str().to_string_lossy())
}

#[cfg(not(windows))]
fn path_component_eq(left: &Component<'_>, right: &Component<'_>) -> bool {
    left == right
}

fn safe_space_name(name: &str) -> String {
    let mut safe: String = name
        .chars()
        .map(|ch| {
            if ch.is_control() || matches!(ch, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*')
            {
                '_'
            } else {
                ch
            }
        })
        .collect();
    while safe.ends_with(' ') || safe.ends_with('.') {
        safe.pop();
    }
    if safe.is_empty() || safe == "." || safe == ".." {
        safe = "Space".to_string();
    }
    if is_windows_reserved_name(&safe)
        || safe.eq_ignore_ascii_case("Personal")
        || safe.eq_ignore_ascii_case("Spaces")
    {
        safe.insert(0, '_');
    }
    safe = truncate_component(&safe, MAX_SPACE_COMPONENT_BYTES, MAX_SPACE_COMPONENT_UTF16);
    while safe.ends_with(' ') || safe.ends_with('.') {
        safe.pop();
    }
    if safe.is_empty() {
        "Space".to_string()
    } else {
        safe
    }
}

const MAX_SPACE_COMPONENT_UTF16: usize = 240;
const MAX_SPACE_COMPONENT_BYTES: usize = 240;

fn truncate_component(value: &str, max_bytes: usize, max_utf16_units: usize) -> String {
    let mut bytes = 0;
    let mut units = 0;
    let mut output = String::new();
    for ch in value.chars() {
        let ch_bytes = ch.len_utf8();
        let ch_units = ch.len_utf16();
        if bytes + ch_bytes > max_bytes || units + ch_units > max_utf16_units {
            break;
        }
        output.push(ch);
        bytes += ch_bytes;
        units += ch_units;
    }
    output
}

fn suffixed_space_name(base: &str, id: &str, attempt: u64) -> String {
    let suffix = if attempt == 1 {
        format!("~{:016x}", stable_hash(id.as_bytes()))
    } else {
        format!("~{:016x}-{attempt}", stable_hash(id.as_bytes()))
    };
    let base_byte_limit = MAX_SPACE_COMPONENT_BYTES.saturating_sub(suffix.len());
    let base_utf16_limit = MAX_SPACE_COMPONENT_UTF16.saturating_sub(suffix.encode_utf16().count());
    format!(
        "{}{}",
        truncate_component(base, base_byte_limit, base_utf16_limit),
        suffix
    )
}

fn is_windows_reserved_name(name: &str) -> bool {
    let stem = name
        .split('.')
        .next()
        .unwrap_or(name)
        .trim_end_matches(&[' ', '.'][..]);
    let upper = stem.to_ascii_uppercase();
    matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ["COM", "LPT"].iter().any(|prefix| {
            upper.strip_prefix(prefix).is_some_and(|suffix| {
                matches!(
                    suffix,
                    "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            })
        })
}

fn case_fold_key(value: &str) -> String {
    value.chars().flat_map(char::to_lowercase).collect()
}

fn stable_hash(bytes: &[u8]) -> u64 {
    // FNV-1a 64-bit: deterministic across processes and platforms.
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn pair(id: &str, local_path: PathBuf, space_id: &str, remote_path: &str) -> FolderPair {
        FolderPair {
            id: id.to_string(),
            local_path,
            space_id: space_id.to_string(),
            remote_path: remote_path.to_string(),
            mode: SyncMode::TwoWay,
        }
    }

    #[test]
    fn serde_uses_snake_case_and_rejects_unknown_config_fields() {
        let encoded = serde_json::to_string(&SyncMode::UploadOnly).expect("serialize mode");
        assert_eq!(encoded, "\"upload_only\"");
        let invalid = r#"{"schema_version":1,"cloud_root":"/cloud","pairs":[],"extra":true}"#;
        assert!(serde_json::from_str::<Config>(invalid).is_err());
    }

    #[test]
    fn validates_remote_canonical_form_and_segment_boundaries() {
        let invalid = ["", "relative", "/a/", "/a//b", "/a/../b", "/a\\b", "/a\nb"];
        for value in invalid {
            assert!(validate_remote_path(value).is_err(), "accepted {value:?}");
        }
        assert!(validate_remote_path("/").is_ok());
        assert!(validate_remote_path("/folder/a").is_ok());
        assert!(!remote_paths_overlap("/foo", "/foobar"));
        assert!(remote_paths_overlap("/foo", "/foo/bar"));
    }

    #[test]
    fn validates_missing_cloud_root_and_detects_local_cloud_overlap() {
        let temp = tempfile::tempdir().expect("tempdir");
        let cloud = temp.path().join("provider").join("root");
        let parent = temp.path().join("provider");
        fs::create_dir_all(&parent).expect("create parent");
        let pair = pair("p", parent, "s", "/");
        let errors = validate_pair(&pair, std::slice::from_ref(&pair), &cloud);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("overlaps cloud_root"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_parent_components_before_symlink_based_cloud_overlap_checks() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("tempdir");
        let local = temp.path().join("real");
        let target = local.join("sub");
        fs::create_dir_all(&target).expect("create target");
        symlink(&target, temp.path().join("link")).expect("create symlink");
        let cloud = temp.path().join("link").join("..").join("cloud");
        let candidate = pair("p", local, "s", "/");

        let errors = validate_pair(&candidate, &[], &cloud);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("cloud_root") && error.contains("'..'"))
        );
    }

    #[test]
    fn cloud_root_must_be_a_non_root_directory_or_viable_missing_directory() {
        let temp = tempfile::tempdir().expect("tempdir");
        let local = temp.path().join("local");
        fs::create_dir(&local).expect("create local");
        let candidate = pair("p", local, "s", "/");

        let file = temp.path().join("cloud-file");
        fs::write(&file, b"fixture").expect("create file");
        let missing_below_file = file.join("child");
        for cloud in [file, missing_below_file] {
            let errors = validate_pair(&candidate, &[], &cloud);
            assert!(
                errors
                    .iter()
                    .any(|error| error.contains("cannot be checked against cloud_root"))
            );
        }

        let root = Path::new(std::path::MAIN_SEPARATOR_STR);
        let errors = validate_pair(&candidate, &[], root);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("must not be a filesystem root"))
        );
        let config = Config {
            schema_version: CONFIG_SCHEMA_VERSION,
            cloud_root: root.to_path_buf(),
            pairs: Vec::new(),
        };
        assert!(
            validate_config(&config)
                .iter()
                .any(|error| error.contains("must not be a filesystem root"))
        );

        let viable_missing = temp.path().join("provider").join("mount");
        let errors = validate_pair(&candidate, &[], &viable_missing);
        assert!(
            !errors
                .iter()
                .any(|error| error.contains("cannot be checked against cloud_root"))
        );
        let local_with_parent = pair("traversal", temp.path().join("local").join(".."), "s", "/");
        let errors = validate_pair(&local_with_parent, &[], &viable_missing);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("local_path") && error.contains("'..'"))
        );
    }

    #[test]
    fn detects_pair_overlap_and_duplicate_remote_ancestors() {
        let temp = tempfile::tempdir().expect("tempdir");
        let a = temp.path().join("a");
        let b = a.join("nested");
        fs::create_dir_all(&b).expect("create dirs");
        let first = pair("a", a, "space", "/docs");
        let second = pair("b", b, "space", "/docs/child");
        let errors = validate_pair(&second, &[first], &temp.path().join("cloud"));
        assert!(
            errors
                .iter()
                .any(|error| error.contains("local_path") && error.contains("overlaps"))
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("remote_path") && error.contains("overlaps"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn canonical_paths_detect_symlink_aliases() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("tempdir");
        let real = temp.path().join("real");
        fs::create_dir(&real).expect("create real");
        let alias = temp.path().join("alias");
        symlink(&real, &alias).expect("create symlink");
        let first = pair("a", real, "space", "/one");
        let second = pair("b", alias, "space", "/two");
        let errors = validate_pair(&second, &[first], &temp.path().join("cloud"));
        assert!(
            errors
                .iter()
                .any(|error| error.contains("local_path") && error.contains("overlaps"))
        );
    }

    #[test]
    fn rejects_filesystem_root_as_local_path() {
        let root = Path::new(std::path::MAIN_SEPARATOR_STR);
        let candidate = pair("root", root.to_path_buf(), "space", "/");
        let errors = validate_pair(&candidate, &[], Path::new("/cloud"));
        assert!(errors.iter().any(|error| error.contains("filesystem root")));
    }

    #[test]
    fn namespace_reserves_names_sanitizes_and_stably_disambiguates_collisions() {
        let spaces = vec![
            Space {
                id: "id-b".into(),
                name: "Team".into(),
            },
            Space {
                id: "id-a".into(),
                name: "team".into(),
            },
            Space {
                id: "id-c".into(),
                name: "CON".into(),
            },
            Space {
                id: "id-d".into(),
                name: "Personal".into(),
            },
            Space {
                id: "id-e".into(),
                name: "unsafe/name.".into(),
            },
        ];
        let entries = space_entries(&spaces).expect("entries");
        let reordered =
            space_entries(&spaces.iter().rev().cloned().collect::<Vec<_>>()).expect("reordered");
        assert_eq!(entries, reordered);
        let by_id: BTreeMap<_, _> = entries
            .iter()
            .map(|entry| (entry.space_id.as_str(), &entry.relative_path))
            .collect();
        assert!(by_id["id-a"].to_string_lossy().contains("team~"));
        assert!(by_id["id-b"].to_string_lossy().contains("Team~"));
        assert_eq!(by_id["id-c"], Path::new("Spaces/_CON"));
        assert_eq!(by_id["id-d"], Path::new("Spaces/_Personal"));
        assert_eq!(by_id["id-e"], Path::new("Spaces/unsafe_name"));
    }

    #[test]
    fn namespace_suffixes_cannot_steal_original_labels_and_are_globally_unique() {
        let literal_suffix = format!("Team~{:016x}", stable_hash(b"id-a"));
        let spaces = vec![
            Space {
                id: "id-a".into(),
                name: "Team".into(),
            },
            Space {
                id: "id-b".into(),
                name: "team".into(),
            },
            Space {
                id: "id-c".into(),
                name: literal_suffix.clone(),
            },
        ];
        let entries = space_entries(&spaces).expect("entries");
        let reordered =
            space_entries(&spaces.iter().rev().cloned().collect::<Vec<_>>()).expect("reordered");
        assert_eq!(entries, reordered);

        let by_id: BTreeMap<_, _> = entries
            .iter()
            .map(|entry| {
                (
                    entry.space_id.as_str(),
                    entry
                        .relative_path
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .into_owned(),
                )
            })
            .collect();
        assert_eq!(by_id["id-c"], literal_suffix);
        assert_ne!(case_fold_key(&by_id["id-a"]), case_fold_key(&by_id["id-c"]));
        let names: BTreeSet<_> = by_id.values().map(|name| case_fold_key(name)).collect();
        assert_eq!(names.len(), spaces.len());
    }

    #[test]
    fn namespace_bounds_long_multibyte_components_without_splitting_utf8() {
        let long_name = "🧑".repeat(400);
        let entries = space_entries(&[Space {
            id: "long".into(),
            name: long_name,
        }])
        .expect("entries");
        let name = entries[0]
            .relative_path
            .file_name()
            .unwrap()
            .to_str()
            .expect("valid UTF-8");
        assert!(name.encode_utf16().count() <= MAX_SPACE_COMPONENT_UTF16);
        assert!(name.len() <= MAX_SPACE_COMPONENT_BYTES);
        assert!(name.chars().all(|ch| ch == '🧑'));
    }

    #[test]
    fn namespace_rejects_blank_and_duplicate_identity() {
        assert!(
            space_entries(&[Space {
                id: " ".into(),
                name: "A".into()
            }])
            .is_err()
        );
        let duplicate = vec![
            Space {
                id: "x".into(),
                name: "A".into(),
            },
            Space {
                id: "x".into(),
                name: "B".into(),
            },
        ];
        assert!(
            space_entries(&duplicate)
                .unwrap_err()
                .contains("duplicated")
        );
    }
}
