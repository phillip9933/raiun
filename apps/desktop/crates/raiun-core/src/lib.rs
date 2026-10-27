//! Safe configuration and namespace primitives for Raiun's desktop engine.
//!
//! This crate validates configuration data only. It does not scan folder trees,
//! mount cloud storage, perform network requests, or claim that data has synced.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

pub mod backend;
pub mod folder_policy;
pub mod media_jobs;
pub mod media_plan;
pub mod media_scan;
pub mod windows_compatibility;
pub use folder_policy::{
    FolderExclusion, FolderExclusionKind, folder_path_excluded, folder_path_rule_excluded,
    media_filter_includes_path, validate_folder_exclusions,
};
pub use media_jobs::{
    DEFAULT_MEDIA_SCAN_INTERVAL_SECONDS, MAX_MEDIA_IMPORT_JOBS, MAX_MEDIA_SCAN_INTERVAL_SECONDS,
    MAX_MEDIA_SOURCE_PATH_BYTES, MIN_MEDIA_SCAN_INTERVAL_SECONDS, MediaImportJob,
    default_media_scan_interval_seconds, validate_media_import_jobs,
};
pub use media_plan::{
    MediaFilter, MediaKind, MediaOrganization, MediaPlanError, MediaPlanItem, MediaPlanOptions,
    MediaPlanOutcome, MediaPlanRejection, MediaSource, MediaUtcMonth, plan_media_import,
};
pub use windows_compatibility::{WindowsNameWarning, windows_name_warnings};

/// Current on-disk configuration schema version.
pub const CONFIG_SCHEMA_VERSION: u32 = 1;
/// Maximum number of exact relative paths excluded from one folder pair.
pub const MAX_EXCLUDED_PATHS: usize = 256;
/// Maximum aggregate UTF-8 bytes in one folder pair's exclusion list.
pub const MAX_EXCLUDED_PATH_BYTES: usize = 32 * 1024;
pub const MAX_FOLDER_EXCLUSIONS: usize = 100;
pub const MAX_FOLDER_EXCLUSION_CHARS: usize = 8_192;
const MAX_EXCLUDED_PATH_LENGTH: usize = 4096;

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
    /// Explicit identity for a folder vault. `remote_path` is then interpreted
    /// as a virtual path beneath this root, never as a DAV path.
    #[serde(default)]
    pub vault: Option<VaultBinding>,
    pub remote_path: String,
    pub mode: SyncMode,
    /// Exact pair-relative paths whose local/cloud copies remain untouched.
    /// Directories also exclude descendants at slash-separated boundaries.
    #[serde(default)]
    pub excluded_paths: Vec<String>,
    /// Include all files, supported photos, or supported videos.
    #[serde(default, skip_serializing_if = "MediaFilter::is_all")]
    pub content_filter: MediaFilter,
    /// Typed filename and relative-path patterns. Legacy `excluded_paths`
    /// remains supported independently.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclusions: Vec<FolderExclusion>,
}

impl FolderPair {
    /// Whether an exact pair-relative path is excluded from reconciliation.
    /// Callers should pass normalized `/`-separated paths without a leading
    /// slash; configuration validation enforces this representation.
    pub fn excludes_relative_path(&self, path: &str) -> bool {
        self.excluded_paths.iter().any(|excluded| {
            path == excluded
                || path
                    .strip_prefix(excluded)
                    .is_some_and(|suffix| suffix.starts_with('/'))
        }) || folder_path_rule_excluded(&self.exclusions, path)
    }

    /// Whether a file path is outside the selected content filter or typed /
    /// legacy exclusions. Directories are always eligible for traversal.
    pub fn excludes_file_path(&self, path: &str) -> bool {
        self.excludes_relative_path(path)
            || folder_path_excluded(&self.exclusions, path, false)
            || !media_filter_includes_path(self.content_filter, path, false)
    }

    /// Whether a directory is excluded by an exact legacy path or typed path
    /// glob. File-type rules and media filters never exclude directories.
    pub fn excludes_directory_path(&self, path: &str) -> bool {
        self.excluded_paths.iter().any(|excluded| {
            path == excluded
                || path
                    .strip_prefix(excluded)
                    .is_some_and(|suffix| suffix.starts_with('/'))
        }) || folder_path_excluded(&self.exclusions, path, true)
    }

    /// Validate the bounded canonical representation used by sync engines.
    pub fn validate_exclusions(&self) -> Result<(), String> {
        let mut errors = validate_excluded_paths(&self.excluded_paths);
        errors.extend(validate_folder_exclusions(&self.exclusions));
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

/// Stable location and resource identity for one folder-vault root.
///
/// Passwords and unlocked session material are never stored in configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultBinding {
    /// Absolute logical DAV path within `FolderPair::space_id`.
    pub root_path: String,
    /// Server resource identity, scoped by account, origin, and Space.
    pub root_resource_id: String,
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

    errors.extend(
        validate_excluded_paths(&pair.excluded_paths)
            .into_iter()
            .map(|problem| format!("pair '{}' exclusions are invalid: {problem}", pair.id)),
    );
    errors.extend(
        validate_folder_exclusions(&pair.exclusions)
            .into_iter()
            .map(|problem| format!("pair '{}' typed exclusions are invalid: {problem}", pair.id)),
    );

    if let Some(binding) = &pair.vault {
        if binding.root_path.len() > 32_768 {
            errors.push(format!(
                "pair '{}' vault root_path exceeds 32768 bytes",
                pair.id
            ));
        }
        if let Err(problem) = validate_remote_path(&binding.root_path) {
            errors.push(format!(
                "pair '{}' vault root_path '{}' is invalid: {}",
                pair.id, binding.root_path, problem
            ));
        }
        if binding.root_resource_id.trim().is_empty()
            || binding.root_resource_id.trim() != binding.root_resource_id
            || binding.root_resource_id.len() > 512
            || binding.root_resource_id.chars().any(char::is_control)
        {
            errors.push(format!(
                "pair '{}' vault root_resource_id must be nonempty, at most 512 bytes, and contain no control characters",
                pair.id
            ));
        }
    }

    for other in existing.iter().filter(|other| !std::ptr::eq(*other, pair)) {
        if other.id == pair.id {
            errors.push(format!("pair id '{}' is duplicated", pair.id));
        }
        if other.space_id == pair.space_id {
            if let (Some(left), Some(right)) = (&pair.vault, &other.vault) {
                if left.root_path == right.root_path
                    && left.root_resource_id != right.root_resource_id
                {
                    errors.push(format!(
                        "pairs '{}' and '{}' bind different vault resources at the same root path '{}'",
                        pair.id, other.id, left.root_path
                    ));
                }
                if left.root_resource_id == right.root_resource_id
                    && left.root_path != right.root_path
                {
                    errors.push(format!(
                        "pairs '{}' and '{}' bind the same vault resource at different root paths",
                        pair.id, other.id
                    ));
                }
            }
            if validate_remote_path(&pair.remote_path).is_ok()
                && validate_remote_path(&other.remote_path).is_ok()
                && pair
                    .vault
                    .as_ref()
                    .is_none_or(|binding| validate_remote_path(&binding.root_path).is_ok())
                && other
                    .vault
                    .as_ref()
                    .is_none_or(|binding| validate_remote_path(&binding.root_path).is_ok())
            {
                let same_vault = match (&pair.vault, &other.vault) {
                    (Some(left), Some(right)) => {
                        left.root_path == right.root_path
                            && left.root_resource_id == right.root_resource_id
                    }
                    _ => false,
                };
                let left_path = effective_remote_path(&pair.remote_path, pair.vault.as_ref());
                let right_path = effective_remote_path(&other.remote_path, other.vault.as_ref());
                let overlaps = if same_vault {
                    remote_paths_overlap(&pair.remote_path, &other.remote_path)
                } else {
                    remote_paths_overlap(&left_path, &right_path)
                };
                if overlaps {
                    errors.push(format!(
                        "pair '{}' remote_path '{}' overlaps pair '{}' remote_path '{}' in space '{}'",
                        pair.id, pair.remote_path, other.id, other.remote_path, pair.space_id
                    ));
                }
            }
        }
    }
    errors
}

fn validate_excluded_paths(paths: &[String]) -> Vec<String> {
    let mut errors = Vec::new();
    if paths.len() > MAX_EXCLUDED_PATHS {
        errors.push(format!(
            "at most {MAX_EXCLUDED_PATHS} exact paths are allowed"
        ));
    }
    let total_bytes = paths
        .iter()
        .try_fold(0_usize, |sum, path| sum.checked_add(path.len()));
    if total_bytes.is_none_or(|bytes| bytes > MAX_EXCLUDED_PATH_BYTES) {
        errors.push(format!(
            "the exclusion list exceeds {MAX_EXCLUDED_PATH_BYTES} bytes"
        ));
    }
    let mut seen = BTreeSet::new();
    for path in paths {
        let invalid = path.is_empty()
            || path.len() > MAX_EXCLUDED_PATH_LENGTH
            || path.starts_with('/')
            || path.ends_with('/')
            || path.contains('\\')
            || path.chars().any(char::is_control)
            || path
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..");
        if invalid {
            errors.push(format!(
                "'{path}' must be a bounded, normalized relative path using '/' separators"
            ));
        } else if !seen.insert(path) {
            errors.push(format!("'{path}' is listed more than once"));
        }
    }
    errors
}

fn effective_remote_path(remote_path: &str, vault: Option<&VaultBinding>) -> String {
    // Virtual plaintext components are not DAV components. For mixed bindings
    // conservatively protect the whole vault root; same-vault pairs are
    // compared using their virtual paths by the caller above.
    vault.map_or_else(
        || remote_path.to_owned(),
        |binding| binding.root_path.clone(),
    )
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

pub fn validate_remote_path(path: &str) -> Result<(), &'static str> {
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
            vault: None,
            remote_path: remote_path.to_string(),
            mode: SyncMode::TwoWay,
            excluded_paths: Vec::new(),
            content_filter: MediaFilter::All,
            exclusions: Vec::new(),
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
    fn folder_pair_configuration_remains_backward_compatible_without_vault_binding() {
        let legacy = r#"{"id":"p","local_path":"/local","space_id":"s","remote_path":"/docs","mode":"two_way"}"#;
        let pair: FolderPair = serde_json::from_str(legacy).expect("legacy pair");
        assert!(pair.vault.is_none());
        assert!(pair.excluded_paths.is_empty());
        let serialized = serde_json::to_value(&pair).unwrap();
        assert!(serialized.get("content_filter").is_none());
        assert!(serialized.get("exclusions").is_none());
        assert_eq!(
            serde_json::from_str::<FolderPair>(&serde_json::to_string(&pair).unwrap()).unwrap(),
            pair
        );
        let opted_in = FolderPair {
            content_filter: MediaFilter::Photos,
            exclusions: vec![FolderExclusion {
                kind: FolderExclusionKind::FileType,
                pattern: "*.tar.gz".into(),
            }],
            ..pair
        };
        let opted_in_json = serde_json::to_value(&opted_in).unwrap();
        assert_eq!(opted_in_json["content_filter"], "photos");
        assert_eq!(opted_in_json["exclusions"][0]["pattern"], "*.tar.gz");
        assert_eq!(
            serde_json::from_value::<FolderPair>(opted_in_json).unwrap(),
            opted_in
        );
    }

    #[test]
    fn selective_paths_use_exact_component_boundaries() {
        let mut pair = pair("p", PathBuf::from("/local"), "s", "/docs");
        pair.excluded_paths = vec!["cache".into(), "one/two.txt".into()];
        assert!(pair.excludes_relative_path("cache"));
        assert!(pair.excludes_relative_path("cache/item.bin"));
        assert!(!pair.excludes_relative_path("cache-old/item.bin"));
        assert!(pair.excludes_relative_path("one/two.txt"));
        assert!(!pair.excludes_relative_path("one/two.txt.bak"));
        assert!(!pair.excludes_relative_path("one/three.txt"));
    }

    #[test]
    fn selective_path_validation_rejects_ambiguous_or_unbounded_values() {
        let local = tempfile::tempdir().expect("local root");
        let cloud = tempfile::tempdir().expect("cloud root");
        let mut candidate = pair("p", local.path().into(), "s", "/docs");
        for invalid in [
            "",
            "/absolute",
            "trailing/",
            "a//b",
            "./a",
            "a/../b",
            "a\\b",
            "bad\nname",
        ] {
            candidate.excluded_paths = vec![invalid.into()];
            assert!(
                validate_pair(&candidate, &[], cloud.path())
                    .iter()
                    .any(|error| error.contains("exclusions are invalid")),
                "accepted {invalid:?}"
            );
        }
        candidate.excluded_paths = vec!["same/path".into(), "same/path".into()];
        assert!(
            validate_pair(&candidate, &[], cloud.path())
                .iter()
                .any(|error| error.contains("listed more than once"))
        );

        candidate.excluded_paths = vec!["x".repeat(MAX_EXCLUDED_PATH_LENGTH + 1)];
        assert!(
            validate_pair(&candidate, &[], cloud.path())
                .iter()
                .any(|error| error.contains("normalized relative path"))
        );

        candidate.excluded_paths = vec!["x".into(); MAX_EXCLUDED_PATHS + 1];
        assert!(
            validate_pair(&candidate, &[], cloud.path())
                .iter()
                .any(|error| error.contains("at most 256"))
        );

        candidate.excluded_paths = vec!["x".repeat(MAX_EXCLUDED_PATH_BYTES + 1)];
        assert!(
            validate_pair(&candidate, &[], cloud.path())
                .iter()
                .any(|error| error.contains("exclusion list exceeds"))
        );
    }

    #[test]
    fn validates_explicit_vault_binding_path_and_resource_identity() {
        let temp = tempfile::tempdir().expect("tempdir");
        let local = temp.path().join("local");
        fs::create_dir(&local).expect("create local");
        let cloud = temp.path().join("cloud");
        let mut candidate = pair("vault", local, "s", "/");
        candidate.vault = Some(VaultBinding {
            root_path: "/team.vault".into(),
            root_resource_id: "resource-1".into(),
        });
        assert!(validate_pair(&candidate, &[], &cloud).is_empty());

        for root_path in ["", "relative", "/a/../b", "/a//b", "/a/"] {
            let mut invalid = candidate.clone();
            invalid.vault.as_mut().unwrap().root_path = root_path.into();
            assert!(
                validate_pair(&invalid, &[], &cloud)
                    .iter()
                    .any(|error| error.contains("vault root_path")),
                "accepted {root_path:?}"
            );
        }
        let oversized_id = "x".repeat(513);
        for resource_id in [
            "",
            " \t",
            " leading",
            "trailing ",
            oversized_id.as_str(),
            "bad\nid",
        ] {
            let mut invalid = candidate.clone();
            invalid.vault.as_mut().unwrap().root_resource_id = resource_id.into();
            assert!(
                validate_pair(&invalid, &[], &cloud)
                    .iter()
                    .any(|error| error.contains("root_resource_id")),
                "accepted invalid resource id"
            );
        }
        let mut space_root = candidate;
        space_root.vault.as_mut().unwrap().root_path = "/".into();
        assert!(validate_pair(&space_root, &[], &cloud).is_empty());
    }

    #[test]
    fn vault_remote_overlap_uses_virtual_paths_for_same_root_and_physical_paths_otherwise() {
        let temp = tempfile::tempdir().expect("tempdir");
        let first_local = temp.path().join("first");
        let second_local = temp.path().join("second");
        let third_local = temp.path().join("third");
        fs::create_dir_all(&first_local).expect("first local");
        fs::create_dir_all(&second_local).expect("second local");
        fs::create_dir_all(&third_local).expect("third local");
        let cloud = temp.path().join("cloud");

        let mut ordinary_parent = pair("plain", first_local.clone(), "s", "/vaults");
        let mut nested_vault = pair("vault", second_local.clone(), "s", "/");
        nested_vault.vault = Some(VaultBinding {
            root_path: "/vaults/team.vault".into(),
            root_resource_id: "team-id".into(),
        });
        assert!(
            validate_pair(&nested_vault, &[ordinary_parent.clone()], &cloud)
                .iter()
                .any(|error| error.contains("remote_path") && error.contains("overlaps"))
        );

        ordinary_parent.remote_path = "/elsewhere".into();
        let mut sibling_vault = pair("sibling", third_local.clone(), "s", "/");
        sibling_vault.vault = Some(VaultBinding {
            root_path: "/vaults/other.vault".into(),
            root_resource_id: "other-id".into(),
        });
        assert!(
            !validate_pair(&sibling_vault, &[nested_vault.clone()], &cloud)
                .iter()
                .any(|error| error.contains("remote_path") && error.contains("overlaps"))
        );

        let mut same_root_child = pair("child", third_local, "s", "/photos");
        same_root_child.vault = nested_vault.vault.clone();
        assert!(
            validate_pair(&same_root_child, &[nested_vault], &cloud)
                .iter()
                .any(|error| error.contains("remote_path") && error.contains("overlaps"))
        );
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

        let root = temp.path().ancestors().last().expect("filesystem root");
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
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().ancestors().last().expect("filesystem root");
        let candidate = pair("root", root.to_path_buf(), "space", "/");
        let cloud_root = temp.path().join("cloud");
        let errors = validate_pair(&candidate, &[], &cloud_root);
        assert!(errors.iter().any(|error| error.contains("filesystem root")));
    }

    #[cfg(windows)]
    #[test]
    fn recognizes_windows_volume_and_unc_roots() {
        for root in [
            Path::new(r"C:\"),
            Path::new(r"\\server\share\"),
            Path::new(r"\\?\C:\"),
            Path::new(r"\\?\UNC\server\share\"),
        ] {
            assert!(is_filesystem_root(root), "expected root: {root:?}");
        }
        assert!(!is_filesystem_root(Path::new(r"C:\Users")));
        assert!(!is_filesystem_root(Path::new(r"\\server\share\folder")));
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
