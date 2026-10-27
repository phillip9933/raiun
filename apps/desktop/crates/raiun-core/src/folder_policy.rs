//! Bounded, case-sensitive folder filters and typed exclusions.

use crate::{MediaFilter, MediaKind};
use serde::{Deserialize, Serialize};

use crate::{MAX_FOLDER_EXCLUSION_CHARS, MAX_FOLDER_EXCLUSIONS};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FolderExclusionKind {
    FileType,
    Path,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FolderExclusion {
    pub kind: FolderExclusionKind,
    /// `file_type` patterns use `*.ext`; path patterns follow the Android
    /// backup glob syntax and are relative to the selected folder.
    pub pattern: String,
}

pub fn validate_folder_exclusions(exclusions: &[FolderExclusion]) -> Vec<String> {
    let mut errors = Vec::new();
    if exclusions.len() > MAX_FOLDER_EXCLUSIONS {
        errors.push(format!(
            "at most {MAX_FOLDER_EXCLUSIONS} typed exclusion rules are allowed"
        ));
    }
    let total = exclusions.iter().try_fold(0_usize, |sum, rule| {
        sum.checked_add(rule.pattern.encode_utf16().count())
    });
    if total.is_none_or(|total| total > MAX_FOLDER_EXCLUSION_CHARS) {
        errors.push(format!(
            "typed exclusion rules exceed {MAX_FOLDER_EXCLUSION_CHARS} UTF-16 units"
        ));
    }
    for (index, rule) in exclusions.iter().enumerate() {
        let units = rule.pattern.encode_utf16().count();
        if units == 0 || units > 255 {
            errors.push(format!(
                "rule {} must contain 1 to 255 UTF-16 units",
                index + 1
            ));
            continue;
        }
        if rule.pattern.chars().any(char::is_control) {
            errors.push(format!("rule {} contains a control character", index + 1));
            continue;
        }
        match rule.kind {
            FolderExclusionKind::FileType => {
                let extension = rule.pattern.strip_prefix("*.");
                let valid_extension = extension.is_some_and(|ext| {
                    let bytes = ext.as_bytes();
                    !bytes.is_empty()
                        && bytes[0].is_ascii_alphanumeric()
                        && bytes.iter().all(|byte| {
                            byte.is_ascii_alphanumeric()
                                || matches!(*byte, b'.' | b'_' | b'+' | b'-')
                        })
                        && ext.split('.').all(|part| !part.is_empty())
                });
                if !valid_extension {
                    errors.push(format!(
                        "rule {} must use a `*.ext` file type with ASCII letters, digits, `.`, `_`, `+` or `-`",
                        index + 1
                    ));
                }
            }
            FolderExclusionKind::Path => {
                if rule.pattern.starts_with('/') || rule.pattern.contains('\\') {
                    errors.push(format!(
                        "rule {} must be a relative path using `/` separators",
                        index + 1
                    ));
                }
                let body = rule.pattern.strip_suffix('/').unwrap_or(&rule.pattern);
                if body.is_empty()
                    || body
                        .split('/')
                        .any(|part| part.is_empty() || part == "." || part == "..")
                {
                    errors.push(format!(
                        "rule {} has an empty, `.` or `..` path segment",
                        index + 1
                    ));
                }
            }
        }
    }
    errors
}

/// Match a normalized slash-separated relative path. Directory matches apply
/// to descendants, so callers can test files without depending on walk order.
pub fn folder_path_excluded(
    exclusions: &[FolderExclusion],
    relative_path: &str,
    is_directory: bool,
) -> bool {
    exclusions
        .iter()
        .any(|rule| exclusion_matches(rule, relative_path, is_directory))
}

fn exclusion_matches(rule: &FolderExclusion, relative_path: &str, is_directory: bool) -> bool {
    let parts: Vec<&str> = relative_path
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    if parts.is_empty() {
        return false;
    }
    match rule.kind {
        FolderExclusionKind::FileType => {
            if is_directory {
                return false;
            }
            let suffix = rule.pattern.strip_prefix("*").unwrap_or(&rule.pattern);
            parts.last().is_some_and(|name| name.ends_with(suffix))
        }
        FolderExclusionKind::Path => {
            let directory_only = rule.pattern.ends_with('/');
            let pattern = rule.pattern.strip_suffix('/').unwrap_or(&rule.pattern);
            if !pattern.contains('/') {
                parts.iter().enumerate().any(|(index, part)| {
                    let is_dir = index + 1 < parts.len() || is_directory;
                    (!directory_only || is_dir) && glob_match(pattern, part)
                })
            } else {
                (0..parts.len()).any(|end| {
                    let ancestor_is_dir = end + 1 < parts.len() || is_directory;
                    (!directory_only || ancestor_is_dir)
                        && glob_match(pattern, &parts[..=end].join("/"))
                })
            }
        }
    }
}

/// Match only path-pattern rules when the caller has not yet established
/// whether the named entry is a file or directory.
pub fn folder_path_rule_excluded(exclusions: &[FolderExclusion], relative_path: &str) -> bool {
    exclusions.iter().any(|rule| {
        rule.kind == FolderExclusionKind::Path && exclusion_matches(rule, relative_path, false)
    })
}

/// Classify ordinary sync paths from their extension. Cloud listings do not
/// expose a portable content signature; using the same name rule on both sides
/// avoids downloading a file solely to decide whether it is included.
pub fn media_filter_includes_path(
    filter: MediaFilter,
    relative_path: &str,
    is_directory: bool,
) -> bool {
    if is_directory || filter == MediaFilter::All {
        return true;
    }
    let extension = relative_path
        .rsplit('/')
        .next()
        .unwrap_or(relative_path)
        .rsplit_once('.')
        .map(|(_, ext)| ext.to_ascii_lowercase());
    let kind = match extension.as_deref() {
        Some(
            "jpg" | "jpeg" | "png" | "gif" | "bmp" | "webp" | "tif" | "tiff" | "heic" | "heif"
            | "avif" | "raw" | "dng" | "cr2" | "cr3" | "nef" | "nrw" | "arw" | "srf" | "sr2"
            | "orf" | "rw2" | "pef" | "raf",
        ) => MediaKind::Photo,
        Some(
            "mp4" | "m4v" | "mov" | "avi" | "mkv" | "webm" | "mpg" | "mpeg" | "mpe" | "mpv" | "m2v"
            | "3gp" | "3g2" | "mts" | "m2ts" | "ts" | "wmv" | "flv" | "vob" | "ogv" | "mxf" | "asf",
        ) => MediaKind::Video,
        _ => MediaKind::Other,
    };
    match filter {
        MediaFilter::All => true,
        MediaFilter::Photos => kind == MediaKind::Photo,
        MediaFilter::Videos => kind == MediaKind::Video,
    }
}

fn glob_match(pattern: &str, text: &str) -> bool {
    #[derive(Clone, Copy)]
    enum Token {
        Star,
        DoubleStar,
        DoubleStarSlash,
        Literal(u16),
        Question,
    }
    let mut tokens = Vec::new();
    let chars: Vec<u16> = pattern.encode_utf16().collect();
    let mut at = 0;
    while at < chars.len() {
        if chars[at] == b'*' as u16 && chars.get(at + 1) == Some(&(b'*' as u16)) {
            if chars.get(at + 2) == Some(&(b'/' as u16)) {
                tokens.push(Token::DoubleStarSlash);
                at += 3;
            } else {
                tokens.push(Token::DoubleStar);
                at += 2;
            }
        } else {
            tokens.push(match chars[at] {
                x if x == b'*' as u16 => Token::Star,
                x if x == b'?' as u16 => Token::Question,
                x => Token::Literal(x),
            });
            at += 1;
        }
    }
    let t: Vec<u16> = text.encode_utf16().collect();
    let mut dp = vec![false; t.len() + 1];
    dp[t.len()] = true;
    for &token in tokens.iter().rev() {
        if matches!(token, Token::DoubleStarSlash) {
            let mut next = vec![false; t.len() + 1];
            let mut slash_can_start = false;
            for pos in (0..=t.len()).rev() {
                if pos < t.len() && t[pos] == b'/' as u16 && dp[pos + 1] {
                    slash_can_start = true;
                }
                next[pos] = dp[pos] || slash_can_start;
            }
            dp = next;
        } else if matches!(token, Token::Star | Token::DoubleStar) {
            let mut next = vec![false; t.len() + 1];
            for pos in (0..=t.len()).rev() {
                next[pos] = dp[pos]
                    || (pos < t.len()
                        && (matches!(token, Token::DoubleStar) || t[pos] != b'/' as u16)
                        && next[pos + 1]);
            }
            dp = next;
        } else {
            let mut next = vec![false; t.len() + 1];
            for pos in 0..t.len() {
                next[pos] = (matches!(token, Token::Question) && t[pos] != b'/' as u16
                    || matches!(token, Token::Literal(ch) if ch == t[pos]))
                    && dp[pos + 1];
            }
            dp = next;
        }
    }
    dp[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(kind: FolderExclusionKind, pattern: &str) -> FolderExclusion {
        FolderExclusion {
            kind,
            pattern: pattern.into(),
        }
    }

    #[test]
    fn file_type_is_case_sensitive_and_matches_only_files() {
        let rules = [rule(FolderExclusionKind::FileType, "*.tmp")];
        assert!(folder_path_excluded(&rules, "nested/cache.tmp", false));
        assert!(!folder_path_excluded(&rules, "nested/cache.TMP", false));
        assert!(!folder_path_excluded(&rules, "nested/cache.tmp", true));
    }

    #[test]
    fn path_patterns_match_basename_anywhere_and_globstar_paths() {
        let rules = [
            rule(FolderExclusionKind::Path, "*.cache"),
            rule(FolderExclusionKind::Path, "private/**/secret?.dat"),
        ];
        assert!(folder_path_excluded(&rules, "a/b/x.cache", false));
        assert!(folder_path_excluded(
            &rules,
            "private/a/b/secret1.dat",
            false
        ));
        assert!(folder_path_excluded(&rules, "private/secret2.dat", false));
        assert!(!folder_path_excluded(
            &rules,
            "private/a/b/secret12.dat",
            false
        ));
    }

    #[test]
    fn directory_rules_exclude_descendants_and_validation_rejects_traversal() {
        let rules = [rule(FolderExclusionKind::Path, "cache/")];
        assert!(folder_path_excluded(&rules, "cache", true));
        assert!(folder_path_excluded(&rules, "cache/nested/file", false));
        assert!(
            !validate_folder_exclusions(&[rule(FolderExclusionKind::Path, "../escape")]).is_empty()
        );
        assert!(
            !validate_folder_exclusions(&[rule(FolderExclusionKind::FileType, "*.t*mp")])
                .is_empty()
        );
        assert!(
            validate_folder_exclusions(&[rule(FolderExclusionKind::FileType, "*.tar.gz")])
                .is_empty()
        );
        assert!(
            !validate_folder_exclusions(&[rule(FolderExclusionKind::FileType, "*.tar..gz")])
                .is_empty()
        );
    }

    #[test]
    fn question_mark_uses_android_compatible_utf16_code_units() {
        let two = [rule(FolderExclusionKind::Path, "??.txt")];
        let one = [rule(FolderExclusionKind::Path, "?.txt")];
        assert!(folder_path_excluded(&two, "📷.txt", false));
        assert!(!folder_path_excluded(&one, "📷.txt", false));
        assert!(folder_path_excluded(&two, "a/📷.txt", false));
    }

    #[test]
    fn ordinary_pair_media_filters_use_consistent_case_insensitive_extensions() {
        assert!(media_filter_includes_path(
            MediaFilter::Photos,
            "Trip/IMG.JPG",
            false
        ));
        assert!(!media_filter_includes_path(
            MediaFilter::Photos,
            "Trip/clip.MP4",
            false
        ));
        assert!(media_filter_includes_path(
            MediaFilter::Videos,
            "Trip/clip.MP4",
            false
        ));
        assert!(!media_filter_includes_path(
            MediaFilter::Videos,
            "Trip/unknown.bin",
            false
        ));
        assert!(media_filter_includes_path(
            MediaFilter::Photos,
            "Trip/image.jpg",
            true
        ));
    }
}
