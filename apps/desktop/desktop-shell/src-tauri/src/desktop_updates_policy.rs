//! Pure selection and scheduling policy for public Raiun Desktop releases.
//!
//! Network transport, Tauri's signed updater, persistence, and presentation
//! belong to the application integration layer. This module accepts only
//! bounded GitHub release metadata and never authorizes an unsigned installer.

use semver::Version;
use std::{cmp::Ordering, collections::HashSet};
use url::Url;

pub const RELEASES_API: &str =
    "https://api.github.com/repos/phillip9933/raiun/releases?per_page=100&page=1";
pub const PROJECT_URL: &str = "https://github.com/phillip9933/raiun";
pub const AUTO_CHECK_INTERVAL_SECONDS: u64 = 24 * 60 * 60;

const DESKTOP_TAG_PREFIX: &str = "desktop-v";
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_RELEASES: usize = 100;
const MAX_TAG_BYTES: usize = 128;
const MAX_NOTES_BYTES: usize = 32 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Channel {
    Stable,
    Beta,
}

/// Classify every 0.x release as beta, alongside all SemVer prereleases.
/// This keeps the stable channel closed until the product reaches 1.0.0.
pub fn is_beta_version(version: &Version) -> bool {
    version.major == 0 || !version.pre.is_empty()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseOffer {
    pub tag: String,
    pub version: Version,
    pub release_url: String,
    pub notes: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyError {
    ResponseTooLarge,
    InvalidReleaseList,
    TooManyReleases,
    InvalidReleaseMetadata,
    InvalidInstalledVersion,
    DuplicateDesktopTag,
    AmbiguousVersion,
    InvalidReleaseLink,
}

/// Select the highest strictly newer Desktop version from GitHub's releases
/// list. Android and unrelated tags are ignored even if GitHub marks them as
/// latest. Drafts and metadata whose prerelease flag disagrees with SemVer are
/// never candidates.
pub fn select_release(
    response: &[u8],
    installed_version: &str,
    channel: Channel,
) -> Result<Option<ReleaseOffer>, PolicyError> {
    if response.len() > MAX_RESPONSE_BYTES {
        return Err(PolicyError::ResponseTooLarge);
    }
    let installed =
        Version::parse(installed_version).map_err(|_| PolicyError::InvalidInstalledVersion)?;
    let releases: serde_json::Value =
        serde_json::from_slice(response).map_err(|_| PolicyError::InvalidReleaseList)?;
    let releases = releases.as_array().ok_or(PolicyError::InvalidReleaseList)?;
    if releases.len() > MAX_RELEASES {
        return Err(PolicyError::TooManyReleases);
    }

    let mut seen_tags = HashSet::new();
    let mut best: Option<ReleaseOffer> = None;
    for item in releases {
        let object = item
            .as_object()
            .ok_or(PolicyError::InvalidReleaseMetadata)?;
        let tag = object
            .get("tag_name")
            .and_then(serde_json::Value::as_str)
            .ok_or(PolicyError::InvalidReleaseMetadata)?;

        // The monorepo mixes Android and Desktop tags. Only Desktop tags enter
        // the strict SemVer and metadata checks below.
        let Some(version_text) = tag.strip_prefix(DESKTOP_TAG_PREFIX) else {
            continue;
        };
        if tag.len() > MAX_TAG_BYTES || !seen_tags.insert(tag) {
            return Err(PolicyError::DuplicateDesktopTag);
        }

        let draft = object
            .get("draft")
            .and_then(serde_json::Value::as_bool)
            .ok_or(PolicyError::InvalidReleaseMetadata)?;
        let prerelease = object
            .get("prerelease")
            .and_then(serde_json::Value::as_bool)
            .ok_or(PolicyError::InvalidReleaseMetadata)?;
        let version = match Version::parse(version_text) {
            Ok(version) => version,
            Err(_) => continue,
        };
        // The product's 0.x line is beta-channel even for numeric SemVer
        // tags, so GitHub's flag must agree with that release classification.
        if draft || prerelease != is_beta_version(&version) {
            continue;
        }
        if channel == Channel::Stable && is_beta_version(&version) {
            continue;
        }
        if version.cmp_precedence(&installed) != Ordering::Greater {
            continue;
        }

        let notes = match object.get("body") {
            None | Some(serde_json::Value::Null) => String::new(),
            Some(serde_json::Value::String(value)) if value.len() <= MAX_NOTES_BYTES => {
                value.clone()
            }
            Some(serde_json::Value::String(_)) => {
                return Err(PolicyError::InvalidReleaseMetadata);
            }
            _ => return Err(PolicyError::InvalidReleaseMetadata),
        };
        let offer = ReleaseOffer {
            release_url: release_url(tag)?,
            tag: tag.to_owned(),
            version,
            notes,
        };
        match &best {
            None => best = Some(offer),
            Some(current)
                if offer.version.cmp_precedence(&current.version) == Ordering::Greater =>
            {
                best = Some(offer)
            }
            Some(current) if offer.version.cmp_precedence(&current.version) == Ordering::Equal => {
                return Err(PolicyError::AmbiguousVersion);
            }
            Some(_) => {}
        }
    }
    Ok(best)
}

/// A release dismissal is intentionally a single exact tag, not a version
/// floor. A later release therefore becomes offerable immediately.
pub fn should_offer(offer: &ReleaseOffer, dismissed_tag: Option<&str>) -> bool {
    dismissed_tag != Some(offer.tag.as_str())
}

/// Automatic checks default to enabled. Manual checks are always allowed and
/// bypass both the preference and daily throttle.
pub fn should_check(
    manual: bool,
    automatic_enabled: bool,
    last_automatic_attempt: Option<u64>,
    now: u64,
) -> bool {
    if manual {
        return true;
    }
    if !automatic_enabled {
        return false;
    }
    match last_automatic_attempt {
        None => true,
        Some(last) => now
            .checked_sub(last)
            .is_some_and(|elapsed| elapsed >= AUTO_CHECK_INTERVAL_SECONDS),
    }
}

/// Build a release page URL from the known repository and a validated Desktop
/// tag; never forward an arbitrary URL from GitHub release JSON.
fn release_url(tag: &str) -> Result<String, PolicyError> {
    let mut url = Url::parse(&format!("{PROJECT_URL}/releases/tag"))
        .map_err(|_| PolicyError::InvalidReleaseLink)?;
    url.path_segments_mut()
        .map_err(|_| PolicyError::InvalidReleaseLink)?
        .push(tag);
    if url.scheme() != "https"
        || url.host_str() != Some("github.com")
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(PolicyError::InvalidReleaseLink);
    }
    Ok(url.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(tag: &str, prerelease: bool, draft: bool, body: &str) -> serde_json::Value {
        serde_json::json!({
            "tag_name": tag,
            "prerelease": prerelease,
            "draft": draft,
            "body": body,
            "html_url": "https://attacker.invalid/ignored",
        })
    }

    fn parse(
        releases: Vec<serde_json::Value>,
        installed: &str,
        channel: Channel,
    ) -> Option<ReleaseOffer> {
        select_release(&serde_json::to_vec(&releases).unwrap(), installed, channel).unwrap()
    }

    #[test]
    fn monorepo_android_latest_does_not_mask_newest_desktop_release() {
        assert_eq!(
            RELEASES_API,
            "https://api.github.com/repos/phillip9933/raiun/releases?per_page=100&page=1"
        );
        let selected = parse(
            vec![
                release("android-v9.0.0", false, false, "Android release"),
                release("desktop-v0.8.0-beta.2", true, false, "Beta"),
                release("desktop-v0.7.1", false, false, "Stable"),
            ],
            "0.7.0-beta.1",
            Channel::Beta,
        )
        .unwrap();
        assert_eq!(selected.tag, "desktop-v0.8.0-beta.2");
        assert_eq!(
            selected.release_url,
            "https://github.com/phillip9933/raiun/releases/tag/desktop-v0.8.0-beta.2"
        );
        assert_eq!(selected.notes, "Beta");
    }

    #[test]
    fn channel_and_prerelease_metadata_are_fail_closed() {
        let releases = vec![
            release("desktop-v0.8.0-beta.2", true, false, "Beta"),
            release("desktop-v1.0.1", false, false, "Stable"),
        ];
        assert_eq!(
            parse(releases.clone(), "0.7.0-beta.1", Channel::Stable)
                .unwrap()
                .tag,
            "desktop-v1.0.1"
        );
        assert_eq!(
            parse(releases, "0.7.0-beta.1", Channel::Beta).unwrap().tag,
            "desktop-v1.0.1"
        );
        let mismatch = serde_json::to_vec(&vec![release(
            "desktop-v1.0.0-beta.1",
            false,
            false,
            "bad flag",
        )])
        .unwrap();
        assert_eq!(
            select_release(&mismatch, "0.9.0", Channel::Beta).unwrap(),
            None
        );
    }

    #[test]
    fn numeric_zero_major_versions_are_beta_and_require_github_beta_flag() {
        let numeric_beta = Version::parse("0.7.4").unwrap();
        assert!(is_beta_version(&numeric_beta));
        let correctly_marked = vec![release(
            "desktop-v0.7.4",
            true,
            false,
            "Next numeric beta",
        )];
        assert_eq!(
            parse(correctly_marked, "0.7.0-beta.2", Channel::Beta)
                .unwrap()
                .tag,
            "desktop-v0.7.4"
        );
        let mismarked = vec![release(
            "desktop-v0.7.4",
            false,
            false,
            "Missing GitHub beta flag",
        )];
        assert_eq!(parse(mismarked.clone(), "0.7.0-beta.2", Channel::Beta), None);
        assert_eq!(parse(mismarked, "0.7.0-beta.2", Channel::Stable), None);
        assert_eq!(
            parse(
                vec![release("desktop-v0.7.4", true, false, "Next numeric beta")],
                "0.7.0-beta.2",
                Channel::Stable
            ),
            None
        );
        assert!(numeric_beta > Version::parse("0.7.0-beta.2").unwrap());
    }

    #[test]
    fn stable_channel_accepts_one_x_and_legacy_prerelease_metadata_stays_strict() {
        let stable = Version::parse("1.2.0").unwrap();
        assert!(!is_beta_version(&stable));
        assert_eq!(
            parse(
                vec![release("desktop-v0.7.0-beta.2", true, false, "Legacy beta")],
                "0.7.0-beta.1",
                Channel::Beta
            )
            .unwrap()
            .tag,
            "desktop-v0.7.0-beta.2"
        );
        assert_eq!(
            parse(
                vec![release("desktop-v1.2.0", false, false, "Stable")],
                "1.1.0",
                Channel::Stable
            )
            .unwrap()
            .tag,
            "desktop-v1.2.0"
        );
        for (tag, github_prerelease) in [
            ("desktop-v0.7.0-beta.3", false),
            ("desktop-v1.2.0-beta.1", false),
            ("desktop-v1.2.0", true),
        ] {
            assert_eq!(
                parse(
                    vec![release(tag, github_prerelease, false, "mismatched metadata")],
                    "0.7.0-beta.2",
                    Channel::Beta
                ),
                None,
                "{tag}"
            );
        }
    }

    #[test]
    fn draft_invalid_equal_and_older_versions_never_offer() {
        let releases = vec![
            release("desktop-v2.0.0", false, true, "draft"),
            release("desktop-v1.0.0", false, false, "equal"),
            release("desktop-v0.9.9", false, false, "older"),
            release("desktop-vnot-semver", false, false, "invalid"),
        ];
        assert_eq!(parse(releases, "1.0.0", Channel::Beta), None);
        assert_eq!(
            select_release(b"[]", "not-a-version", Channel::Beta),
            Err(PolicyError::InvalidInstalledVersion)
        );
    }

    #[test]
    fn duplicate_desktop_tags_or_versions_are_rejected() {
        let duplicate_tag = vec![
            release("desktop-v2.0.0", false, false, "one"),
            release("desktop-v2.0.0", false, false, "two"),
        ];
        assert_eq!(
            select_release(
                &serde_json::to_vec(&duplicate_tag).unwrap(),
                "1.0.0",
                Channel::Stable
            ),
            Err(PolicyError::DuplicateDesktopTag)
        );
        let same_precedence = vec![
            release("desktop-v2.0.0+one", false, false, "one"),
            release("desktop-v2.0.0+two", false, false, "two"),
        ];
        assert_eq!(
            select_release(
                &serde_json::to_vec(&same_precedence).unwrap(),
                "1.0.0",
                Channel::Stable
            ),
            Err(PolicyError::AmbiguousVersion)
        );
    }

    #[test]
    fn dismissal_is_per_tag_and_links_ignore_untrusted_html_url() {
        let first = parse(
            vec![release("desktop-v1.1.0", false, false, "")],
            "1.0.0",
            Channel::Stable,
        )
        .unwrap();
        assert!(!should_offer(&first, Some("desktop-v1.1.0")));
        let later = parse(
            vec![release("desktop-v1.2.0", false, false, "")],
            "1.0.0",
            Channel::Stable,
        )
        .unwrap();
        assert!(should_offer(&later, Some("desktop-v1.1.0")));
        assert!(
            first
                .release_url
                .starts_with("https://github.com/phillip9933/raiun/releases/tag/")
        );
        assert!(!first.release_url.contains("attacker.invalid"));
    }

    #[test]
    fn automatic_checks_are_daily_and_manual_checks_bypass_preference() {
        assert!(should_check(false, true, None, 0));
        assert!(!should_check(false, false, None, 10_000));
        assert!(should_check(true, false, Some(10_000), 10_001));
        assert!(!should_check(
            false,
            true,
            Some(10_000),
            10_000 + AUTO_CHECK_INTERVAL_SECONDS - 1
        ));
        assert!(should_check(
            false,
            true,
            Some(10_000),
            10_000 + AUTO_CHECK_INTERVAL_SECONDS
        ));
        assert!(!should_check(false, true, Some(10_000), 9_999));
    }

    #[test]
    fn metadata_shape_and_bounds_are_checked() {
        assert_eq!(
            select_release(b"{}", "1.0.0", Channel::Stable),
            Err(PolicyError::InvalidReleaseList)
        );
        assert_eq!(
            select_release(
                &vec![b' '; MAX_RESPONSE_BYTES + 1],
                "1.0.0",
                Channel::Stable
            ),
            Err(PolicyError::ResponseTooLarge)
        );
        let too_many = vec![release("android-v1.0.0", false, false, ""); MAX_RELEASES + 1];
        assert_eq!(
            select_release(
                &serde_json::to_vec(&too_many).unwrap(),
                "1.0.0",
                Channel::Stable
            ),
            Err(PolicyError::TooManyReleases)
        );
        let bad_type = serde_json::to_vec(&vec![
            serde_json::json!({"tag_name":"desktop-v2.0.0","draft":"false","prerelease":false}),
        ])
        .unwrap();
        assert_eq!(
            select_release(&bad_type, "1.0.0", Channel::Stable),
            Err(PolicyError::InvalidReleaseMetadata)
        );
    }
}
