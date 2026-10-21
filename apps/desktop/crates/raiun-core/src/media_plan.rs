//! Pure, bounded preview planning for a future media-import workflow.
//!
//! This module accepts already-classified media and explicit UTC date inputs.
//! It does not inspect files, extract metadata, contact a provider, rename a
//! source, or perform any filesystem or network mutation.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Maximum number of source and existing-destination entries combined in one
/// preview. The result therefore cannot contain more than this many rows.
pub const MAX_MEDIA_PLAN_ENTRIES: usize = 10_000;
/// Per-path byte limit. The planner also limits the combined UTF-8 path data.
pub const MAX_MEDIA_PATH_BYTES: usize = 4_096;
const MAX_MEDIA_PLAN_PATH_BYTES_TOTAL: usize = 8 * 1024 * 1024;

/// A source selected by a caller that has already classified its media type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaSource {
    /// Slash-separated path relative to the selected source folder.
    pub relative_path: String,
    pub kind: MediaKind,
    /// Optional year and month already interpreted in UTC by the caller.
    pub utc_date: Option<MediaUtcMonth>,
}

/// The media classification supplied by the scanner or caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaKind {
    Photo,
    Video,
    Other,
}

/// Explicit UTC calendar month metadata. The planner does not infer or parse it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaUtcMonth {
    pub year: u16,
    pub month: u8,
}

/// The caller's requested media filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaFilter {
    Photos,
    Videos,
    All,
}

/// Optional destination layout. Date layout groups by the explicit UTC month
/// and uses the original filename; it does not guess a timestamp fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaOrganization {
    PreserveRelativePath,
    UtcYearMonth,
}

/// Inputs that affect path planning. `existing_destinations` are existing file
/// paths inside `destination_root`, not directories, and should be scoped to
/// this destination by the caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaPlanOptions {
    pub destination_root: String,
    pub filter: MediaFilter,
    pub organization: MediaOrganization,
}

/// One preview row, sorted by the source-relative path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaPlanItem {
    pub source_relative_path: String,
    pub outcome: MediaPlanOutcome,
}

/// Preview outcome. A collision is never resolved by choosing a winner or
/// inventing a renamed destination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaPlanOutcome {
    Planned {
        destination_path: String,
    },
    Filtered,
    MissingUtcDate,
    Rejected {
        reason: MediaPlanRejection,
    },
    Collision {
        destination_path: String,
        /// An existing file has the same, parent, or child path.
        existing_path_conflict: bool,
        /// Another source maps to the same, parent, or child path.
        source_path_conflict: bool,
        /// Number of sources with this exact lowercase collision key.
        matching_sources: usize,
    },
}

/// Why one source could not be assigned a safe, deterministic destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaPlanRejection {
    PathTooLong,
    UnsafeRelativePath,
    UnsupportedPortableFilename,
    InvalidUtcDate,
    DestinationPathInvalid,
}

/// Request-level errors. Invalid individual source paths remain visible as
/// rejected preview rows; invalid roots and excessive input fail the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaPlanError {
    TooManyEntries,
    PathDataTooLarge,
    InvalidDestinationRoot,
    InvalidExistingDestination,
}

impl fmt::Display for MediaPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyEntries => write!(
                f,
                "media preview exceeds the {MAX_MEDIA_PLAN_ENTRIES}-entry limit"
            ),
            Self::PathDataTooLarge => write!(f, "media preview path data exceeds its size limit"),
            Self::InvalidDestinationRoot => write!(f, "destination root is not a safe remote path"),
            Self::InvalidExistingDestination => {
                write!(
                    f,
                    "existing file destination is invalid or outside the selected root"
                )
            }
        }
    }
}

impl std::error::Error for MediaPlanError {}

/// Build a deterministic preview without reading or changing source files.
///
/// The combined source and existing-file count is capped at 10,000, each path
/// is capped at 4 KiB, and combined path input is capped at 8 MiB. Oversized
/// path input fails the request; bounded unsafe source paths become rejected
/// rows. Existing paths outside the selected root fail the request.
/// Collision comparisons use Unicode lowercase keys while preserving every
/// emitted destination's original spelling. The planner does not normalize
/// or rewrite distinct cloud paths; case-only candidates are surfaced for
/// review. Unicode normalization beyond lowercase is intentionally not
/// performed, and Rust lowercase is not the full Unicode case-fold algorithm.
/// Source names reject common Windows-invalid characters, trailing spaces or
/// dots, and reserved DOS device names. Existing file paths are checked only
/// against supplied file paths; directory inventory and provider-specific
/// name rules are the caller's responsibility.
pub fn plan_media_import(
    sources: &[MediaSource],
    options: &MediaPlanOptions,
    existing_destinations: &[String],
) -> Result<Vec<MediaPlanItem>, MediaPlanError> {
    let entries = sources
        .len()
        .checked_add(existing_destinations.len())
        .ok_or(MediaPlanError::TooManyEntries)?;
    if entries > MAX_MEDIA_PLAN_ENTRIES {
        return Err(MediaPlanError::TooManyEntries);
    }

    let mut input_path_bytes = options.destination_root.len();
    for path in sources
        .iter()
        .map(|source| &source.relative_path)
        .chain(existing_destinations.iter())
    {
        if path.len() > MAX_MEDIA_PATH_BYTES {
            return Err(MediaPlanError::PathDataTooLarge);
        }
        input_path_bytes = input_path_bytes
            .checked_add(path.len())
            .ok_or(MediaPlanError::PathDataTooLarge)?;
        if input_path_bytes > MAX_MEDIA_PLAN_PATH_BYTES_TOTAL {
            return Err(MediaPlanError::PathDataTooLarge);
        }
    }
    if options.destination_root.len() > MAX_MEDIA_PATH_BYTES
        || input_path_bytes > MAX_MEDIA_PLAN_PATH_BYTES_TOTAL
    {
        return Err(MediaPlanError::PathDataTooLarge);
    }
    super::validate_remote_path(&options.destination_root)
        .map_err(|_| MediaPlanError::InvalidDestinationRoot)?;

    let root_key = portable_collision_key(&options.destination_root);
    let root_prefix = if root_key == "/" {
        "/".to_owned()
    } else {
        format!("{root_key}/")
    };
    let mut existing_keys = BTreeSet::new();
    for path in existing_destinations {
        super::validate_remote_path(path)
            .map_err(|_| MediaPlanError::InvalidExistingDestination)?;
        let key = portable_collision_key(path);
        if key == root_key || !key.starts_with(&root_prefix) {
            return Err(MediaPlanError::InvalidExistingDestination);
        }
        existing_keys.insert(key);
    }

    let mut result = Vec::with_capacity(sources.len());
    let mut candidate_keys: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    let mut candidate_paths = Vec::with_capacity(sources.len());

    for source in sources {
        let mut item = MediaPlanItem {
            source_relative_path: source.relative_path.clone(),
            outcome: MediaPlanOutcome::Filtered,
        };
        let basename = match validate_source_path(&source.relative_path) {
            Ok(basename) => basename,
            Err(reason) => {
                item.outcome = MediaPlanOutcome::Rejected { reason };
                result.push(item);
                candidate_paths.push(None);
                continue;
            }
        };
        if !matches_filter(options.filter, source.kind) {
            result.push(item);
            candidate_paths.push(None);
            continue;
        }

        let relative_destination = match options.organization {
            MediaOrganization::PreserveRelativePath => source.relative_path.clone(),
            MediaOrganization::UtcYearMonth => {
                let Some(date) = source.utc_date else {
                    item.outcome = MediaPlanOutcome::MissingUtcDate;
                    result.push(item);
                    candidate_paths.push(None);
                    continue;
                };
                if !(1..=9999).contains(&date.year) || !(1..=12).contains(&date.month) {
                    item.outcome = MediaPlanOutcome::Rejected {
                        reason: MediaPlanRejection::InvalidUtcDate,
                    };
                    result.push(item);
                    candidate_paths.push(None);
                    continue;
                }
                format!("{:04}/{:02}/{basename}", date.year, date.month)
            }
        };
        let destination = append_remote_path(&options.destination_root, &relative_destination);
        if destination.len() > MAX_MEDIA_PATH_BYTES
            || super::validate_remote_path(&destination).is_err()
        {
            item.outcome = MediaPlanOutcome::Rejected {
                reason: if destination.len() > MAX_MEDIA_PATH_BYTES {
                    MediaPlanRejection::PathTooLong
                } else {
                    MediaPlanRejection::DestinationPathInvalid
                },
            };
            result.push(item);
            candidate_paths.push(None);
            continue;
        }
        let key = portable_collision_key(&destination);
        candidate_keys.entry(key).or_default().push(result.len());
        candidate_paths.push(Some(destination));
        result.push(item);
    }

    for (key, indexes) in &candidate_keys {
        let existing_path_conflict = has_path_conflict(&existing_keys, key);
        let source_path_conflict = indexes.len() > 1 || has_prefix_conflict(&candidate_keys, key);
        if !existing_path_conflict && !source_path_conflict {
            let index = indexes[0];
            result[index].outcome = MediaPlanOutcome::Planned {
                destination_path: candidate_paths[index]
                    .take()
                    .expect("candidate path matches grouped index"),
            };
        } else {
            let matching_sources = indexes.len();
            for index in indexes {
                result[*index].outcome = MediaPlanOutcome::Collision {
                    destination_path: candidate_paths[*index]
                        .take()
                        .expect("candidate path matches grouped index"),
                    existing_path_conflict,
                    source_path_conflict,
                    matching_sources,
                };
            }
        }
    }

    result.sort_by(|left, right| left.source_relative_path.cmp(&right.source_relative_path));
    Ok(result)
}

fn matches_filter(filter: MediaFilter, kind: MediaKind) -> bool {
    match filter {
        MediaFilter::Photos => kind == MediaKind::Photo,
        MediaFilter::Videos => kind == MediaKind::Video,
        MediaFilter::All => true,
    }
}

fn append_remote_path(root: &str, relative: &str) -> String {
    if root == "/" {
        format!("/{relative}")
    } else {
        format!("{}/{relative}", root.trim_end_matches('/'))
    }
}

fn portable_collision_key(path: &str) -> String {
    path.chars().flat_map(char::to_lowercase).collect()
}

fn has_path_conflict(paths: &BTreeSet<String>, path: &str) -> bool {
    paths.contains(path)
        || has_ancestor(path, |ancestor| paths.contains(ancestor))
        || has_descendant(path, |prefix| {
            paths
                .range(prefix.to_owned()..)
                .next()
                .is_some_and(|candidate| candidate.starts_with(prefix))
        })
}

fn has_prefix_conflict(paths: &BTreeMap<String, Vec<usize>>, path: &str) -> bool {
    has_ancestor(path, |ancestor| paths.contains_key(ancestor))
        || has_descendant(path, |prefix| {
            paths
                .range(prefix.to_owned()..)
                .next()
                .is_some_and(|(candidate, _)| candidate.starts_with(prefix))
        })
}

fn has_ancestor(path: &str, mut contains: impl FnMut(&str) -> bool) -> bool {
    path.char_indices()
        .filter_map(|(index, ch)| (ch == '/').then_some(index))
        .filter(|index| *index > 0)
        .any(|index| contains(&path[..index]))
}

fn has_descendant(path: &str, has_descendant_of: impl FnOnce(&str) -> bool) -> bool {
    let prefix = format!("{path}/");
    has_descendant_of(&prefix)
}

fn validate_source_path(path: &str) -> Result<&str, MediaPlanRejection> {
    if path.is_empty()
        || path.len() > MAX_MEDIA_PATH_BYTES
        || path.starts_with('/')
        || path.contains('\\')
        || path.chars().any(char::is_control)
    {
        return Err(if path.len() > MAX_MEDIA_PATH_BYTES {
            MediaPlanRejection::PathTooLong
        } else {
            MediaPlanRejection::UnsafeRelativePath
        });
    }
    let mut parts = path.split('/').peekable();
    while let Some(part) = parts.next() {
        if part.is_empty() || part == "." || part == ".." {
            return Err(MediaPlanRejection::UnsafeRelativePath);
        }
        validate_portable_segment(part)?;
        if parts.peek().is_none() {
            return Ok(part);
        }
    }
    Err(MediaPlanRejection::UnsafeRelativePath)
}

fn validate_portable_segment(segment: &str) -> Result<(), MediaPlanRejection> {
    if (segment.ends_with(' ') || segment.ends_with('.'))
        || segment
            .chars()
            .any(|ch| matches!(ch, '<' | '>' | ':' | '"' | '|' | '?' | '*'))
    {
        return Err(MediaPlanRejection::UnsupportedPortableFilename);
    }
    let stem = segment.split('.').next().unwrap_or(segment);
    let upper = stem.to_ascii_uppercase();
    let reserved = matches!(
        upper.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "CONIN$"
            | "CONOUT$"
            | "COM¹"
            | "COM²"
            | "COM³"
            | "LPT¹"
            | "LPT²"
            | "LPT³"
    ) || ["COM", "LPT"].iter().any(|prefix| {
        upper
            .strip_prefix(prefix)
            .is_some_and(|number| number.len() == 1 && matches!(number.as_bytes()[0], b'1'..=b'9'))
    });
    if reserved {
        return Err(MediaPlanRejection::UnsupportedPortableFilename);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(path: &str, kind: MediaKind, date: Option<MediaUtcMonth>) -> MediaSource {
        MediaSource {
            relative_path: path.to_owned(),
            kind,
            utc_date: date,
        }
    }

    fn options(filter: MediaFilter, organization: MediaOrganization) -> MediaPlanOptions {
        MediaPlanOptions {
            destination_root: "/Personal/Media".into(),
            filter,
            organization,
        }
    }

    #[test]
    fn preserves_relative_paths_and_original_names_without_mutation() {
        let inputs = vec![
            source("旅行/IMG 1.jpg", MediaKind::Photo, None),
            source("clip.mp4", MediaKind::Video, None),
        ];
        let before = inputs.clone();
        let planned = plan_media_import(
            &inputs,
            &options(MediaFilter::All, MediaOrganization::PreserveRelativePath),
            &[],
        )
        .unwrap();
        assert_eq!(inputs, before);
        assert_eq!(planned[0].source_relative_path, "clip.mp4");
        assert_eq!(
            planned[0].outcome,
            MediaPlanOutcome::Planned {
                destination_path: "/Personal/Media/clip.mp4".into()
            }
        );
        assert_eq!(
            planned[1].outcome,
            MediaPlanOutcome::Planned {
                destination_path: "/Personal/Media/旅行/IMG 1.jpg".into()
            }
        );
    }

    #[test]
    fn filters_and_uses_only_explicit_valid_utc_months() {
        let planned = plan_media_import(
            &[
                source(
                    "a/photo.jpg",
                    MediaKind::Photo,
                    Some(MediaUtcMonth {
                        year: 2024,
                        month: 2,
                    }),
                ),
                source("b/video.mp4", MediaKind::Video, None),
                source("c/other.dat", MediaKind::Other, None),
                source(
                    "d/bad.jpg",
                    MediaKind::Photo,
                    Some(MediaUtcMonth {
                        year: 2024,
                        month: 13,
                    }),
                ),
            ],
            &options(MediaFilter::Photos, MediaOrganization::UtcYearMonth),
            &[],
        )
        .unwrap();
        assert_eq!(
            planned[0].outcome,
            MediaPlanOutcome::Planned {
                destination_path: "/Personal/Media/2024/02/photo.jpg".into()
            }
        );
        assert_eq!(planned[1].outcome, MediaPlanOutcome::Filtered);
        assert_eq!(planned[2].outcome, MediaPlanOutcome::Filtered);
        assert_eq!(
            planned[3].outcome,
            MediaPlanOutcome::Rejected {
                reason: MediaPlanRejection::InvalidUtcDate
            }
        );
    }

    #[test]
    fn missing_date_is_visible_in_date_layout_and_ignored_in_flat_layout() {
        let item = source("camera/IMG.jpg", MediaKind::Photo, None);
        let by_date = plan_media_import(
            std::slice::from_ref(&item),
            &options(MediaFilter::All, MediaOrganization::UtcYearMonth),
            &[],
        )
        .unwrap();
        assert_eq!(by_date[0].outcome, MediaPlanOutcome::MissingUtcDate);
        let flat = plan_media_import(
            &[item],
            &options(MediaFilter::All, MediaOrganization::PreserveRelativePath),
            &[],
        )
        .unwrap();
        assert_eq!(
            flat[0].outcome,
            MediaPlanOutcome::Planned {
                destination_path: "/Personal/Media/camera/IMG.jpg".into()
            }
        );
    }

    #[test]
    fn collisions_are_case_insensitive_and_never_rewrite_destination_spelling() {
        let existing = vec!["/Personal/Media/IMG.JPG".to_owned()];
        let planned = plan_media_import(
            &[source("img.jpg", MediaKind::Photo, None)],
            &options(MediaFilter::All, MediaOrganization::PreserveRelativePath),
            &existing,
        )
        .unwrap();
        assert_eq!(
            planned[0].outcome,
            MediaPlanOutcome::Collision {
                destination_path: "/Personal/Media/img.jpg".into(),
                existing_path_conflict: true,
                source_path_conflict: false,
                matching_sources: 1,
            }
        );
        assert_eq!(existing[0], "/Personal/Media/IMG.JPG");
    }

    #[test]
    fn date_flattening_reports_every_source_to_source_collision() {
        let date = Some(MediaUtcMonth {
            year: 2026,
            month: 10,
        });
        let planned = plan_media_import(
            &[
                source("camera-a/IMG.jpg", MediaKind::Photo, date),
                source("camera-b/img.JPG", MediaKind::Photo, date),
            ],
            &options(MediaFilter::All, MediaOrganization::UtcYearMonth),
            &[],
        )
        .unwrap();
        assert!(planned.iter().all(|item| matches!(
            item.outcome,
            MediaPlanOutcome::Collision {
                matching_sources: 2,
                existing_path_conflict: false,
                source_path_conflict: true,
                ..
            }
        )));
    }

    #[test]
    fn detects_existing_and_planned_file_ancestor_conflicts() {
        let options = options(MediaFilter::All, MediaOrganization::PreserveRelativePath);
        let existing = vec!["/Personal/Media/a".to_owned()];
        let planned = plan_media_import(
            &[source("a/b.jpg", MediaKind::Photo, None)],
            &options,
            &existing,
        )
        .unwrap();
        assert!(matches!(
            planned[0].outcome,
            MediaPlanOutcome::Collision {
                existing_path_conflict: true,
                source_path_conflict: false,
                ..
            }
        ));

        let existing_descendant = vec!["/Personal/Media/a/b.jpg".to_owned()];
        let planned = plan_media_import(
            &[source("a", MediaKind::Photo, None)],
            &options,
            &existing_descendant,
        )
        .unwrap();
        assert!(matches!(
            planned[0].outcome,
            MediaPlanOutcome::Collision {
                existing_path_conflict: true,
                ..
            }
        ));

        let planned = plan_media_import(
            &[
                source("a.jpg", MediaKind::Photo, None),
                source("a.jpg/child.jpg", MediaKind::Photo, None),
            ],
            &options,
            &[],
        )
        .unwrap();
        assert!(planned.iter().all(|item| matches!(
            item.outcome,
            MediaPlanOutcome::Collision {
                existing_path_conflict: false,
                source_path_conflict: true,
                matching_sources: 1,
                ..
            }
        )));
    }

    #[test]
    fn rejects_traversal_and_nonportable_windows_names_without_renaming() {
        let planned = plan_media_import(
            &[
                source("../escape.jpg", MediaKind::Photo, None),
                source("folder\\escape.jpg", MediaKind::Photo, None),
                source("CON.txt", MediaKind::Photo, None),
                source("trailing. ", MediaKind::Photo, None),
            ],
            &options(MediaFilter::All, MediaOrganization::PreserveRelativePath),
            &[],
        )
        .unwrap();
        assert!(
            planned
                .iter()
                .filter(|item| item.source_relative_path == "CON.txt")
                .all(|item| matches!(
                    item.outcome,
                    MediaPlanOutcome::Rejected {
                        reason: MediaPlanRejection::UnsupportedPortableFilename
                    }
                ))
        );
        assert!(planned.iter().any(|item| matches!(
            item.outcome,
            MediaPlanOutcome::Rejected {
                reason: MediaPlanRejection::UnsafeRelativePath
            }
        )));
        assert!(
            planned
                .iter()
                .filter(|item| item.source_relative_path == "CON.txt"
                    || item.source_relative_path == "trailing. ")
                .all(|item| matches!(
                    item.outcome,
                    MediaPlanOutcome::Rejected {
                        reason: MediaPlanRejection::UnsupportedPortableFilename
                    }
                ))
        );
    }

    #[test]
    fn validates_roots_existing_destinations_and_combined_entry_limit() {
        let mut invalid = options(MediaFilter::All, MediaOrganization::PreserveRelativePath);
        invalid.destination_root = "/a/../b".into();
        assert_eq!(
            plan_media_import(&[], &invalid, &[]),
            Err(MediaPlanError::InvalidDestinationRoot)
        );
        let options = options(MediaFilter::All, MediaOrganization::PreserveRelativePath);
        assert_eq!(
            plan_media_import(&[], &options, &["relative".into()]),
            Err(MediaPlanError::InvalidExistingDestination)
        );
        assert_eq!(
            plan_media_import(&[], &options, &["/Personal/Other/existing.jpg".into()]),
            Err(MediaPlanError::InvalidExistingDestination)
        );
        let too_many = vec![source("x.jpg", MediaKind::Photo, None); MAX_MEDIA_PLAN_ENTRIES];
        assert_eq!(
            plan_media_import(
                &too_many,
                &options,
                &["/Personal/Media/existing.jpg".into()]
            ),
            Err(MediaPlanError::TooManyEntries)
        );
        let too_long = source(
            &format!("{}.jpg", "a".repeat(MAX_MEDIA_PATH_BYTES)),
            MediaKind::Photo,
            None,
        );
        assert_eq!(
            plan_media_import(&[too_long], &options, &[]),
            Err(MediaPlanError::PathDataTooLarge)
        );

        let max_path = "a".repeat(MAX_MEDIA_PATH_BYTES);
        let too_much_path_data = vec![
            source(&max_path, MediaKind::Photo, None);
            MAX_MEDIA_PLAN_PATH_BYTES_TOTAL / MAX_MEDIA_PATH_BYTES + 1
        ];
        assert_eq!(
            plan_media_import(&too_much_path_data, &options, &[]),
            Err(MediaPlanError::PathDataTooLarge)
        );
    }

    #[test]
    fn file_prefix_checks_respect_segment_boundaries() {
        let planned = plan_media_import(
            &[source("ab/child.jpg", MediaKind::Photo, None)],
            &options(MediaFilter::All, MediaOrganization::PreserveRelativePath),
            &["/Personal/Media/a".into()],
        )
        .unwrap();
        assert!(matches!(
            planned[0].outcome,
            MediaPlanOutcome::Planned { .. }
        ));
    }
}
