//! Warning-only diagnostics for names that may not round-trip on Windows.
//!
//! These checks do not validate sync paths and never rewrite names. Collision
//! keys use Rust Unicode lowercase as a practical approximation; they are not
//! a complete model of Windows filesystem case folding or normalization.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::backend::RemoteEntry;

// A common Windows filesystem component limit; unusual filesystems may differ.
const WINDOWS_COMPONENT_UTF16_LIMIT: usize = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsNameWarning {
    UnsupportedCharacter,
    TrailingDotOrSpace,
    ReservedDeviceName,
    CaseCollision,
    ComponentTooLong,
}

/// Analyze one remote sibling listing without changing its entries or names.
///
/// The returned map is keyed by the exact remote path. `case_collision` is
/// attached to each member of a sibling group whose lowercase keys match but
/// whose original spellings differ.
pub fn windows_name_warnings(entries: &[RemoteEntry]) -> BTreeMap<String, Vec<WindowsNameWarning>> {
    let mut warnings = BTreeMap::<String, Vec<WindowsNameWarning>>::new();
    let mut collision_groups = BTreeMap::<(String, String), BTreeSet<String>>::new();

    for entry in entries {
        let Some((parent, name)) = entry.path.rsplit_once('/') else {
            continue;
        };
        if name.is_empty() {
            continue;
        }

        let mut entry_warnings = Vec::new();
        if name.encode_utf16().count() > WINDOWS_COMPONENT_UTF16_LIMIT {
            entry_warnings.push(WindowsNameWarning::ComponentTooLong);
        }
        if name.chars().any(|ch| {
            ch <= '\u{001f}' || matches!(ch, '<' | '>' | ':' | '"' | '\\' | '|' | '?' | '*')
        }) {
            entry_warnings.push(WindowsNameWarning::UnsupportedCharacter);
        }
        if name.ends_with(' ') || name.ends_with('.') {
            entry_warnings.push(WindowsNameWarning::TrailingDotOrSpace);
        }
        if is_reserved_device_name(name) {
            entry_warnings.push(WindowsNameWarning::ReservedDeviceName);
        }
        if !entry_warnings.is_empty() {
            warnings.insert(entry.path.clone(), entry_warnings);
        }

        collision_groups
            .entry((parent.to_owned(), name.to_lowercase()))
            .or_default()
            .insert(name.to_owned());
    }

    for ((parent, _), names) in collision_groups {
        if names.len() < 2 {
            continue;
        }
        for name in names {
            let path = if parent.is_empty() {
                format!("/{name}")
            } else {
                format!("{parent}/{name}")
            };
            let entry_warnings = warnings.entry(path).or_default();
            if !entry_warnings.contains(&WindowsNameWarning::CaseCollision) {
                entry_warnings.push(WindowsNameWarning::CaseCollision);
            }
        }
    }

    warnings
}

fn is_reserved_device_name(name: &str) -> bool {
    // Windows reserves these basenames even when followed by an extension.
    // Trimming trailing spaces/dots here is conservative and also surfaces a
    // separate trailing-character warning for the original spelling.
    let trimmed = name.trim_end_matches([' ', '.']);
    let stem = trimmed
        .split('.')
        .next()
        .unwrap_or(trimmed)
        .trim_end_matches(' ');
    let upper = stem.to_ascii_uppercase();
    matches!(
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str) -> RemoteEntry {
        RemoteEntry {
            id: path.to_owned(),
            path: path.to_owned(),
            directory: false,
            size: 1,
            etag: String::new(),
            modified_unix: 0,
            writable: true,
            encrypted: false,
        }
    }

    #[test]
    fn warns_for_windows_invalid_names_without_rejecting_or_rewriting_them() {
        let entries = [
            entry("/photos/bad<name.jpg"),
            entry("/photos/trailing."),
            entry("/photos/trailing "),
            entry("/photos/CON.txt"),
            entry("/photos/normal Linux name.txt"),
        ];
        let warnings = windows_name_warnings(&entries);

        assert_eq!(
            warnings["/photos/bad<name.jpg"],
            [WindowsNameWarning::UnsupportedCharacter]
        );
        assert_eq!(
            warnings["/photos/trailing."],
            [WindowsNameWarning::TrailingDotOrSpace]
        );
        assert_eq!(
            warnings["/photos/trailing "],
            [WindowsNameWarning::TrailingDotOrSpace]
        );
        assert_eq!(
            warnings["/photos/CON.txt"],
            [WindowsNameWarning::ReservedDeviceName]
        );
        assert!(!warnings.contains_key("/photos/normal Linux name.txt"));
        assert_eq!(entries[0].path, "/photos/bad<name.jpg");
    }

    #[test]
    fn reports_case_only_collisions_for_siblings_not_other_directories() {
        let entries = [
            entry("/photos/Cover.JPG"),
            entry("/photos/cover.jpg"),
            entry("/archive/cover.jpg"),
            entry("/photos/unique.jpg"),
        ];
        let warnings = windows_name_warnings(&entries);

        assert_eq!(
            warnings["/photos/Cover.JPG"],
            [WindowsNameWarning::CaseCollision]
        );
        assert_eq!(
            warnings["/photos/cover.jpg"],
            [WindowsNameWarning::CaseCollision]
        );
        assert!(!warnings.contains_key("/archive/cover.jpg"));
        assert!(!warnings.contains_key("/photos/unique.jpg"));
    }

    #[test]
    fn case_collision_approximation_does_not_collapse_identical_duplicate_names() {
        let entries = [entry("/photos/same.txt"), entry("/photos/same.txt")];
        assert!(windows_name_warnings(&entries).is_empty());
    }

    #[test]
    fn warns_only_above_255_utf16_units_for_ascii_components() {
        let at_limit = format!("/photos/{}", "a".repeat(255));
        let over_limit = format!("/photos/{}", "a".repeat(256));
        let entries = [entry(&at_limit), entry(&over_limit)];

        let warnings = windows_name_warnings(&entries);

        assert!(!warnings.contains_key(&at_limit));
        assert_eq!(
            warnings[&over_limit],
            [WindowsNameWarning::ComponentTooLong]
        );
    }

    #[test]
    fn component_length_counts_supplementary_characters_as_two_utf16_units() {
        let at_limit = format!("/photos/{}a", "😀".repeat(127));
        let over_limit = format!("/photos/{}ab", "😀".repeat(127));
        let entries = [entry(&at_limit), entry(&over_limit)];

        let warnings = windows_name_warnings(&entries);

        assert!(!warnings.contains_key(&at_limit));
        assert_eq!(
            warnings[&over_limit],
            [WindowsNameWarning::ComponentTooLong]
        );
    }
}
